// SPDX-License-Identifier: Apache-2.0

use std::ffi::{CStr, CString};
use std::fs::{self, File, Permissions};
use std::io::{self, Write};
use std::mem;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::ptr;
use std::slice;

use anyhow::Context;
use nix::fcntl::{OFlag, open};
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use nix::sys::signal::{self, Signal};
use nix::sys::stat::Mode;
use nix::unistd::{self, ForkResult};
use vsock::{VsockAddr, VsockStream};

const VMADDR_CID_HOST: u32 = 2;
const TUN_DEV_MAJOR: u32 = 10;
const TUN_DEV_MINOR: u32 = 200;
const ETH_HEADER_LEN: u32 = 14;

// sin_addr.s_addr is stored in network byte order (NBO = big-endian on wire).
// 172.31.10.83 in network byte order.
const TAP_IP_NBO: u32 = 0xAC1F_0A53u32.to_be();
// 255.255.255.0 in network byte order.
const TAP_NETMASK_NBO: u32 = 0xFFFF_FF00u32.to_be();
const TAP_MAC: [u8; 6] = [0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee];
// Default gateway 172.31.10.83 in network byte order.
const TAP_GATEWAY_NBO: u32 = 0xAC1F_0A53u32.to_be();

pub fn tap_afvsock_init(vsock_port: u32, shutdown_fd: RawFd) -> anyhow::Result<()> {
    tun_init().context("net: init /dev/net/tun")?;
    let (tun_file, tap_name) = tap_alloc().context("net: allocate TAP")?;
    let vsock = VsockStream::connect(&VsockAddr::new(VMADDR_CID_HOST, vsock_port))
        .context("net: vsock connect")?;

    match unsafe { unistd::fork() }.context("net: fork")? {
        ForkResult::Parent { .. } => {
            drop(tun_file);
            Ok(())
        }
        ForkResult::Child => run_tap_proxy(tun_file, vsock, shutdown_fd, &tap_name),
    }
}

fn tun_init() -> anyhow::Result<()> {
    if !Path::new("/dev/net").exists() {
        fs::create_dir("/dev/net").context("mkdir /dev/net")?;
    }
    if !Path::new("/dev/net/tun").exists() {
        let dev = libc::makedev(TUN_DEV_MAJOR, TUN_DEV_MINOR);
        let ret = unsafe { libc::mknod(c"/dev/net/tun".as_ptr(), libc::S_IFCHR | 0o600, dev) };
        if ret < 0 {
            return Err(io::Error::last_os_error()).context("mknod /dev/net/tun");
        }
    }
    fs::set_permissions("/dev/net/tun", Permissions::from_mode(0o666)).context("chmod /dev/net/tun")
}

fn tap_alloc() -> anyhow::Result<(File, String)> {
    let fd = open("/dev/net/tun", OFlag::O_RDWR, Mode::empty()).context("open /dev/net/tun")?;
    let raw = fd.as_raw_fd();

    let mut ifr: libc::ifreq = unsafe {
        let mut ifr: libc::ifreq = mem::zeroed();
        ifr.ifr_ifru.ifru_flags = (libc::IFF_TAP | libc::IFF_NO_PI) as i16;
        ifr
    };
    let name = b"tap0\0";
    ifr.ifr_name[..name.len()].copy_from_slice(unsafe {
        slice::from_raw_parts(name.as_ptr() as *const libc::c_char, name.len())
    });

    // TUNSETIFF = _IOW('T', 202, struct ifreq)
    let tunsetiff = nix::request_code_write!('T', 202, mem::size_of::<libc::ifreq>());
    if unsafe { libc::ioctl(raw, tunsetiff, &mut ifr) } < 0 {
        return Err(io::Error::last_os_error()).context("TUNSETIFF");
    }

    let tap_name = unsafe {
        CStr::from_ptr(ifr.ifr_name.as_ptr())
            .to_string_lossy()
            .into_owned()
    };

    tap_assign_ipaddr(&tap_name).context("net: assign IP/MAC/gateway")?;

    let file = unsafe { File::from_raw_fd(raw) };
    mem::forget(fd);
    Ok((file, tap_name))
}

fn ifreq_named(name: &str) -> libc::ifreq {
    let mut ifr: libc::ifreq = unsafe { mem::zeroed() };
    let bytes = name.as_bytes();
    let len = bytes.len().min(libc::IFNAMSIZ - 1);
    unsafe {
        ptr::copy_nonoverlapping(
            bytes.as_ptr() as *const libc::c_char,
            ifr.ifr_name.as_mut_ptr(),
            len,
        );
    }
    ifr
}

fn make_sockaddr_in(ip_nbo: u32) -> libc::sockaddr_in {
    let mut addr: libc::sockaddr_in = unsafe { mem::zeroed() };
    addr.sin_family = libc::AF_INET as u16;
    addr.sin_addr.s_addr = ip_nbo;
    addr
}

fn tap_assign_ipaddr(name: &str) -> anyhow::Result<()> {
    let sock_fd = {
        let raw = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if raw < 0 {
            return Err(io::Error::last_os_error()).context("socket for IP config");
        }
        unsafe { OwnedFd::from_raw_fd(raw) }
    };
    let sock = sock_fd.as_raw_fd();

    // Set IP address.
    let mut ifr = ifreq_named(name);
    let addr_in = make_sockaddr_in(TAP_IP_NBO);
    unsafe {
        ifr.ifr_ifru.ifru_addr = mem::transmute::<libc::sockaddr_in, libc::sockaddr>(addr_in);
        if libc::ioctl(sock, libc::SIOCSIFADDR as _, &ifr) < 0 {
            return Err(io::Error::last_os_error()).context("SIOCSIFADDR");
        }
    }

    // Set netmask.
    let mut ifr = ifreq_named(name);
    let mask_in = make_sockaddr_in(TAP_NETMASK_NBO);
    unsafe {
        ifr.ifr_ifru.ifru_netmask = mem::transmute::<libc::sockaddr_in, libc::sockaddr>(mask_in);
        if libc::ioctl(sock, libc::SIOCSIFNETMASK as _, &ifr) < 0 {
            return Err(io::Error::last_os_error()).context("SIOCSIFNETMASK");
        }
    }

    // Set MAC address.
    let mut ifr = ifreq_named(name);
    unsafe {
        ifr.ifr_ifru.ifru_hwaddr.sa_family = libc::ARPHRD_ETHER;
        let dst = ifr.ifr_ifru.ifru_hwaddr.sa_data.as_mut_ptr() as *mut u8;
        ptr::copy_nonoverlapping(TAP_MAC.as_ptr(), dst, 6);
        if libc::ioctl(sock, libc::SIOCSIFHWADDR as _, &ifr) < 0 {
            return Err(io::Error::last_os_error()).context("SIOCSIFHWADDR");
        }
    }

    // Set flags UP + RUNNING.
    let mut ifr = ifreq_named(name);
    unsafe {
        if libc::ioctl(sock, libc::SIOCGIFFLAGS as _, &mut ifr) < 0 {
            return Err(io::Error::last_os_error()).context("SIOCGIFFLAGS");
        }
        ifr.ifr_ifru.ifru_flags |= (libc::IFF_UP | libc::IFF_RUNNING) as i16;
        if libc::ioctl(sock, libc::SIOCSIFFLAGS as _, &ifr) < 0 {
            return Err(io::Error::last_os_error()).context("SIOCSIFFLAGS");
        }
    }

    // Set default gateway.
    let mut route: libc::rtentry = unsafe { mem::zeroed() };
    let gw = make_sockaddr_in(TAP_GATEWAY_NBO);
    let dst = make_sockaddr_in(0);
    let mask = make_sockaddr_in(0);
    unsafe {
        route.rt_gateway = mem::transmute::<libc::sockaddr_in, libc::sockaddr>(gw);
        route.rt_dst = mem::transmute::<libc::sockaddr_in, libc::sockaddr>(dst);
        route.rt_genmask = mem::transmute::<libc::sockaddr_in, libc::sockaddr>(mask);
    }
    route.rt_flags = libc::RTF_UP | libc::RTF_GATEWAY;
    let name_c = CString::new(name).unwrap();
    route.rt_dev = name_c.as_ptr() as *mut libc::c_char;
    unsafe {
        if libc::ioctl(sock, libc::SIOCADDRT as _, &route) < 0 {
            return Err(io::Error::last_os_error()).context("SIOCADDRT");
        }
    }

    Ok(())
}

fn get_tap_mtu(tap_name: &str) -> anyhow::Result<u32> {
    let sock_fd = {
        let raw = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if raw < 0 {
            return Err(io::Error::last_os_error()).context("socket for MTU");
        }
        unsafe { OwnedFd::from_raw_fd(raw) }
    };
    let sock = sock_fd.as_raw_fd();

    let mut ifr = ifreq_named(tap_name);
    let ret = unsafe { libc::ioctl(sock, libc::SIOCGIFMTU as _, &mut ifr) };
    let mtu = if ret < 0 {
        1500 // fallback
    } else {
        unsafe { ifr.ifr_ifru.ifru_mtu as u32 }
    };
    Ok(mtu)
}

fn run_tap_proxy(tun_file: File, vsock: VsockStream, shutdown_fd: RawFd, tap_name: &str) -> ! {
    let tun_fd = tun_file.as_raw_fd();
    let vsock_fd = vsock.as_raw_fd();

    let mtu = get_tap_mtu(tap_name).unwrap_or(1500);
    let eth_frame_size = (mtu + ETH_HEADER_LEN) as usize;

    // Tell host our max frame size (big-endian).
    let size_be = (eth_frame_size as u32).to_be_bytes();
    if (&vsock).write_all(&size_be).is_err() {
        std::process::exit(1);
    }

    // Notify parent we're ready.
    let ppid = unistd::getppid();
    let _ = signal::kill(ppid, Signal::SIGUSR1);

    let mut buf = vec![0u8; eth_frame_size];

    let poll_fds = &mut [
        PollFd::new(
            unsafe { BorrowedFd::borrow_raw(vsock_fd) },
            PollFlags::POLLIN,
        ),
        PollFd::new(unsafe { BorrowedFd::borrow_raw(tun_fd) }, PollFlags::POLLIN),
        PollFd::new(
            unsafe { BorrowedFd::borrow_raw(shutdown_fd) },
            PollFlags::POLLIN,
        ),
    ];

    loop {
        match poll(poll_fds, PollTimeout::NONE) {
            Ok(n) if n <= 0 => continue,
            Err(nix::errno::Errno::EINTR) => continue,
            Err(_) => break,
            Ok(_) => {}
        }

        if poll_fds[0]
            .revents()
            .is_some_and(|r| r.contains(PollFlags::POLLIN))
            && !forward_vsock_to_tap(vsock_fd, tun_fd, &mut buf, eth_frame_size)
        {
            break;
        }

        if poll_fds[1]
            .revents()
            .is_some_and(|r| r.contains(PollFlags::POLLIN))
            && !forward_tap_to_vsock(tun_fd, vsock_fd, &mut buf, eth_frame_size)
        {
            break;
        }

        if poll_fds[2]
            .revents()
            .is_some_and(|r| r.contains(PollFlags::POLLIN))
        {
            break;
        }
    }

    drop(tun_file);
    drop(vsock);
    std::process::exit(0);
}

/// Read one length-prefixed frame from `vsock_fd` and write it atomically to `tun_fd`.
/// Returns `true` to continue the loop, `false` to break.
fn forward_vsock_to_tap(vsock_fd: RawFd, tun_fd: RawFd, buf: &mut [u8], max: usize) -> bool {
    let mut len_buf = [0u8; 4];
    if read_exact_raw(vsock_fd, &mut len_buf).is_err() {
        return false;
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > max || read_exact_raw(vsock_fd, &mut buf[..len]).is_err() {
        return false;
    }
    // TAP requires a single atomic frame write; only retry on EINTR.
    let written = loop {
        let r = unsafe { libc::write(tun_fd, buf.as_ptr() as _, len) };
        if r < 0 && nix::errno::Errno::last() == nix::errno::Errno::EINTR {
            continue;
        }
        break r;
    };
    written == len as libc::ssize_t
}

/// Read one frame from `tun_fd` and write it length-prefixed to `vsock_fd`.
/// Returns `true` to continue the loop, `false` to break.
fn forward_tap_to_vsock(tun_fd: RawFd, vsock_fd: RawFd, buf: &mut [u8], max: usize) -> bool {
    // TAP reads deliver one complete frame at a time; only retry on EINTR.
    let nread = loop {
        let r = unsafe { libc::read(tun_fd, buf.as_mut_ptr() as _, max) };
        if r < 0 && nix::errno::Errno::last() == nix::errno::Errno::EINTR {
            continue;
        }
        break r;
    };
    if nread <= 0 {
        return false;
    }
    let nread = nread as usize;
    write_exact_raw(vsock_fd, &(nread as u32).to_be_bytes()).is_ok()
        && write_exact_raw(vsock_fd, &buf[..nread]).is_ok()
}

fn read_exact_raw(fd: RawFd, buf: &mut [u8]) -> io::Result<()> {
    let mut total = 0;
    while total < buf.len() {
        let n = unsafe { libc::read(fd, buf[total..].as_mut_ptr() as _, buf.len() - total) };
        match n {
            0 => return Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
            n if n < 0 => {
                if nix::errno::Errno::last() == nix::errno::Errno::EINTR {
                    continue;
                }
                return Err(io::Error::last_os_error());
            }
            n => total += n as usize,
        }
    }
    Ok(())
}

fn write_exact_raw(fd: RawFd, buf: &[u8]) -> io::Result<()> {
    let mut total = 0;
    while total < buf.len() {
        let n = unsafe { libc::write(fd, buf[total..].as_ptr() as _, buf.len() - total) };
        if n < 0 {
            if nix::errno::Errno::last() == nix::errno::Errno::EINTR {
                continue;
            }
            return Err(io::Error::last_os_error());
        }
        total += n as usize;
    }
    Ok(())
}
