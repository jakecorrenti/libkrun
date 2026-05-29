// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result};
use std::io;

const TUN_DEV_MAJOR: u32 = 10;
const TUN_DEV_MINOR: u32 = 200;

const ETH_HEADER_LEN: u32 = 14;
const PROXY_HEADER_LEN: usize = 4;

// SO_VM_SOCKETS_CONNECT_TIMEOUT is Linux-specific and not in the libc crate.
const SO_VM_SOCKETS_CONNECT_TIMEOUT: libc::c_int = 6;

// TAP device IP/network configuration (matches C implementation).
// Use from_ne_bytes so the bytes land in network order in memory regardless of host endianness.
const TAP_IP_OCTETS: [u8; 4] = [172, 31, 10, 83];
const TAP_NETMASK_OCTETS: [u8; 4] = [255, 255, 255, 0];
const TAP_MAC: [u8; 6] = [0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee];

/// Initialize the TAP device and fork a proxy forwarding network frames
/// between the host vsock and the TAP device.
pub fn init(vsock_port: u32, shutdown_fd: i32) -> Result<()> {
    tun_init().context("init /dev/net/tun")?;

    let mut tap_name = [0u8; libc::IFNAMSIZ];
    tap_name[..4].copy_from_slice(b"tap0");

    let tun_fd = tap_alloc(&mut tap_name).context("allocate TAP device")?;

    let pid = unsafe { libc::fork() };
    match pid {
        -1 => {
            unsafe { libc::close(tun_fd) };
            Err(io::Error::last_os_error()).context("fork network proxy")
        }
        0 => {
            // Child process: run the proxy.
            let vsock_fd = vsock_connect(vsock_port).expect("net proxy: connect vsock");
            proxy_run(tun_fd, vsock_fd, shutdown_fd, &tap_name);
        }
        _ => {
            // Parent closes its copy of the tun_fd — the child owns it.
            unsafe { libc::close(tun_fd) };
            Ok(())
        }
    }
}

fn tun_init() -> Result<()> {
    match std::fs::metadata("/dev/net") {
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            std::fs::create_dir("/dev/net").context("mkdir /dev/net")?;
        }
        Err(e) => return Err(e).context("stat /dev/net"),
        Ok(_) => {}
    }

    match std::fs::metadata("/dev/net/tun") {
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let dev = libc::makedev(TUN_DEV_MAJOR, TUN_DEV_MINOR);
            let ret = unsafe {
                libc::mknod(c"/dev/net/tun".as_ptr(), libc::S_IFCHR | 0o666, dev)
            };
            if ret < 0 {
                return Err(io::Error::last_os_error()).context("mknod /dev/net/tun");
            }
        }
        Err(e) => return Err(e).context("stat /dev/net/tun"),
        Ok(_) => {}
    }

    let ret = unsafe { libc::chmod(c"/dev/net/tun".as_ptr(), 0o666) };
    if ret < 0 {
        return Err(io::Error::last_os_error()).context("chmod /dev/net/tun");
    }

    Ok(())
}

fn tap_alloc(name: &mut [u8; libc::IFNAMSIZ]) -> Result<i32> {
    let fd = unsafe { libc::open(c"/dev/net/tun".as_ptr(), libc::O_RDWR) };
    if fd < 0 {
        return Err(io::Error::last_os_error()).context("open /dev/net/tun");
    }

    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    ifr.ifr_ifru.ifru_flags = (libc::IFF_TAP | libc::IFF_NO_PI) as i16;
    for (dst, &src) in ifr.ifr_name.iter_mut().zip(name.iter()) {
        *dst = src as libc::c_char;
    }

    let ret = unsafe { libc::ioctl(fd, libc::TUNSETIFF as _, &ifr) };
    if ret < 0 {
        unsafe { libc::close(fd) };
        return Err(io::Error::last_os_error()).context("TUNSETIFF");
    }

    // Copy back the actual name assigned.
    for (dst, src) in name.iter_mut().zip(ifr.ifr_name.iter()) {
        *dst = *src as u8;
    }

    tap_assign_ipaddr(name)?;

    Ok(fd)
}

fn tap_assign_ipaddr(name: &[u8; libc::IFNAMSIZ]) -> Result<()> {
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if sock < 0 {
        return Err(io::Error::last_os_error()).context("socket for TAP IP config");
    }
    let result = tap_assign_ipaddr_inner(name, sock);
    unsafe { libc::close(sock) };
    result
}

fn make_ifreq(name: &[u8; libc::IFNAMSIZ]) -> libc::ifreq {
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    for (dst, &src) in ifr.ifr_name.iter_mut().zip(name.iter()) {
        *dst = src as libc::c_char;
    }
    ifr
}

fn tap_assign_ipaddr_inner(name: &[u8; libc::IFNAMSIZ], sock: i32) -> Result<()> {
    // Set IP address.
    {
        let mut ifr = make_ifreq(name);
        let addr = unsafe { &mut *(&mut ifr.ifr_ifru.ifru_addr as *mut _ as *mut libc::sockaddr_in) };
        addr.sin_family = libc::AF_INET as _;
        addr.sin_addr.s_addr = u32::from_ne_bytes(TAP_IP_OCTETS);
        if unsafe { libc::ioctl(sock, libc::SIOCSIFADDR as _, &ifr) } < 0 {
            return Err(io::Error::last_os_error()).context("SIOCSIFADDR");
        }
    }

    // Set netmask.
    {
        let mut ifr = make_ifreq(name);
        let addr = unsafe {
            &mut *(&mut ifr.ifr_ifru.ifru_netmask as *mut _ as *mut libc::sockaddr_in)
        };
        addr.sin_family = libc::AF_INET as _;
        addr.sin_addr.s_addr = u32::from_ne_bytes(TAP_NETMASK_OCTETS);
        if unsafe { libc::ioctl(sock, libc::SIOCSIFNETMASK as _, &ifr) } < 0 {
            return Err(io::Error::last_os_error()).context("SIOCSIFNETMASK");
        }
    }

    // Set MAC address.
    {
        let mut ifr = make_ifreq(name);
        ifr.ifr_ifru.ifru_hwaddr.sa_family = libc::ARPHRD_ETHER as _;
        for (dst, &src) in unsafe { ifr.ifr_ifru.ifru_hwaddr.sa_data.iter_mut() }
            .zip(TAP_MAC.iter())
        {
            *dst = src as libc::c_char;
        }
        if unsafe { libc::ioctl(sock, libc::SIOCSIFHWADDR as _, &ifr) } < 0 {
            return Err(io::Error::last_os_error()).context("SIOCSIFHWADDR");
        }
    }

    // Set flags UP | RUNNING.
    {
        let mut ifr = make_ifreq(name);
        if unsafe { libc::ioctl(sock, libc::SIOCGIFFLAGS as _, &mut ifr) } < 0 {
            return Err(io::Error::last_os_error()).context("SIOCGIFFLAGS");
        }
        unsafe { ifr.ifr_ifru.ifru_flags |= (libc::IFF_UP | libc::IFF_RUNNING) as i16 };
        if unsafe { libc::ioctl(sock, libc::SIOCSIFFLAGS as _, &ifr) } < 0 {
            return Err(io::Error::last_os_error()).context("SIOCSIFFLAGS");
        }
    }

    // Add default route via TAP gateway.
    {
        let mut route: libc::rtentry = unsafe { std::mem::zeroed() };

        let gw = unsafe { &mut *(&mut route.rt_gateway as *mut _ as *mut libc::sockaddr_in) };
        gw.sin_family = libc::AF_INET as _;
        gw.sin_addr.s_addr = u32::from_ne_bytes(TAP_IP_OCTETS);

        let dst = unsafe { &mut *(&mut route.rt_dst as *mut _ as *mut libc::sockaddr_in) };
        dst.sin_family = libc::AF_INET as _;
        dst.sin_addr.s_addr = 0; // INADDR_ANY

        let genmask = unsafe { &mut *(&mut route.rt_genmask as *mut _ as *mut libc::sockaddr_in) };
        genmask.sin_family = libc::AF_INET as _;
        genmask.sin_addr.s_addr = 0; // INADDR_ANY

        route.rt_flags = libc::RTF_UP | libc::RTF_GATEWAY;
        route.rt_dev = name.as_ptr() as *mut libc::c_char;

        if unsafe { libc::ioctl(sock, libc::SIOCADDRT as _, &route) } < 0 {
            return Err(io::Error::last_os_error()).context("SIOCADDRT");
        }
    }

    Ok(())
}

fn vsock_connect(port: u32) -> Result<i32> {
    let sock_fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM, 0) };
    if sock_fd < 0 {
        return Err(io::Error::last_os_error()).context("create net vsock");
    }

    let timeout = libc::timeval { tv_sec: 5, tv_usec: 0 };
    let ret = unsafe {
        libc::setsockopt(
            sock_fd,
            libc::AF_VSOCK,
            SO_VM_SOCKETS_CONNECT_TIMEOUT,
            &timeout as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as _,
        )
    };
    if ret < 0 {
        unsafe { libc::close(sock_fd) };
        return Err(io::Error::last_os_error()).context("set net vsock timeout");
    }

    let mut addr: libc::sockaddr_vm = unsafe { std::mem::zeroed() };
    addr.svm_family = libc::AF_VSOCK as _;
    addr.svm_cid = libc::VMADDR_CID_HOST;
    addr.svm_port = port;

    let ret = unsafe {
        libc::connect(
            sock_fd,
            &addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_vm>() as _,
        )
    };
    if ret < 0 {
        unsafe { libc::close(sock_fd) };
        return Err(io::Error::last_os_error()).context("connect net vsock");
    }

    Ok(sock_fd)
}

/// Read exactly `buf.len()` bytes. Returns `false` on clean EOF at start,
/// `true` on success, errors on partial read or I/O failure.
fn read_exact(fd: i32, buf: &mut [u8]) -> io::Result<bool> {
    let mut total = 0;
    while total < buf.len() {
        let n = unsafe {
            libc::read(
                fd,
                buf[total..].as_mut_ptr() as *mut libc::c_void,
                buf.len() - total,
            )
        };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        if n == 0 {
            return if total == 0 {
                Ok(false) // clean EOF before any bytes
            } else {
                Err(io::Error::new(io::ErrorKind::UnexpectedEof, "partial read"))
            };
        }
        total += n as usize;
    }
    Ok(true)
}

fn write_all(fd: i32, buf: &[u8]) -> io::Result<()> {
    let mut total = 0;
    while total < buf.len() {
        let n = unsafe {
            libc::write(
                fd,
                buf[total..].as_ptr() as *const libc::c_void,
                buf.len() - total,
            )
        };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        total += n as usize;
    }
    Ok(())
}

fn proxy_run(tun_fd: i32, vsock_fd: i32, shutdown_fd: i32, tap_name: &[u8; libc::IFNAMSIZ]) -> ! {
    // Get MTU to size the frame buffer.
    let mtu = get_mtu(tap_name).unwrap_or(1500);
    let eth_frame_size = (mtu + ETH_HEADER_LEN) as usize;
    let mut buf = vec![0u8; eth_frame_size];

    // Tell the host the max ethernet frame size (big-endian u32).
    let frame_size_be = (eth_frame_size as u32).to_be_bytes();
    if write_all(vsock_fd, &frame_size_be).is_err() {
        unsafe { libc::exit(1) };
    }

    // Notify parent that we're ready.
    unsafe { libc::kill(libc::getppid(), libc::SIGUSR1) };

    let mut pfds = [
        libc::pollfd { fd: vsock_fd,    events: libc::POLLIN, revents: 0 },
        libc::pollfd { fd: tun_fd,      events: libc::POLLIN, revents: 0 },
        libc::pollfd { fd: shutdown_fd, events: libc::POLLIN, revents: 0 },
    ];

    'outer: loop {
        let ret = unsafe { libc::poll(pfds.as_mut_ptr(), pfds.len() as _, -1) };
        if ret < 0 {
            if unsafe { *libc::__errno_location() } == libc::EINTR {
                continue;
            }
            break;
        }
        if ret == 0 {
            continue;
        }

        // vsock → TAP: read framed ethernet packet and write to TAP.
        if pfds[0].revents & libc::POLLIN != 0 {
            let mut hdr = [0u8; PROXY_HEADER_LEN];
            match read_exact(vsock_fd, &mut hdr) {
                Ok(false) => break, // clean EOF
                Err(_) => break,
                Ok(true) => {}
            }
            let len = u32::from_be_bytes(hdr) as usize;
            if len > buf.len() {
                break;
            }
            if read_exact(vsock_fd, &mut buf[..len]).is_err() {
                break;
            }
            // Write the full frame to TAP (TAP requires atomic writes).
            let mut written = 0;
            while written < len {
                let n = unsafe {
                    libc::write(tun_fd, buf[written..len].as_ptr() as _, len - written)
                };
                if n <= 0 {
                    break 'outer;
                }
                written += n as usize;
            }
        }

        // TAP → vsock: read ethernet frame and write with 4-byte length header.
        if pfds[1].revents & libc::POLLIN != 0 {
            let n = loop {
                let n = unsafe { libc::read(tun_fd, buf.as_mut_ptr() as _, buf.len()) };
                if n < 0 && unsafe { *libc::__errno_location() } == libc::EINTR {
                    continue;
                }
                break n;
            };
            if n <= 0 {
                break;
            }
            let hdr = (n as u32).to_be_bytes();
            if write_all(vsock_fd, &hdr).is_err()
                || write_all(vsock_fd, &buf[..n as usize]).is_err()
            {
                break;
            }
        }

        // Shutdown event — exit cleanly.
        if pfds[2].revents & libc::POLLIN != 0 {
            break;
        }
    }

    unsafe {
        libc::close(vsock_fd);
        libc::close(tun_fd);
        libc::exit(0);
    }
}

fn get_mtu(tap_name: &[u8; libc::IFNAMSIZ]) -> Option<u32> {
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if sock < 0 {
        return None;
    }
    let mut ifr = make_ifreq(tap_name);
    let ret = unsafe { libc::ioctl(sock, libc::SIOCGIFMTU as _, &mut ifr) };
    unsafe { libc::close(sock) };
    if ret < 0 {
        return None;
    }
    Some(unsafe { ifr.ifr_ifru.ifru_mtu } as u32)
}
