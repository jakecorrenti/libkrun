// SPDX-License-Identifier: Apache-2.0

mod archive;
mod args_reader;
mod device;
mod fs;
mod mods;

use std::ffi::CString;
use std::io::{self, Read, Write};
use std::mem;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

use anyhow::Context;
use aws_nitro_enclaves_nsm_api::api::{Request, Response};
use aws_nitro_enclaves_nsm_api::driver::{nsm_exit, nsm_init, nsm_process_request};
use nix::fcntl::{OFlag, open};
use nix::mount::{self, MsFlags};
use nix::sys::signal::{self, SaFlags, SigAction, SigHandler, SigSet, Signal};
use nix::sys::stat::Mode;
use nix::sys::wait::{self, WaitStatus};
use nix::unistd::{self, ForkResult};
use vsock::VsockStream;

const VSOCK_PORT_OFFSET_ARGS_READER: u32 = 1;
const VSOCK_PORT_OFFSET_NET: u32 = 2;
const VSOCK_PORT_OFFSET_OUTPUT: u32 = 3;
const VSOCK_PORT_OFFSET_APP_RET_CODE: u32 = 4;
const VSOCK_PORT_OFFSET_SIGNAL_HANDLER: u32 = 5;

const NSM_PCR_ROOTFS: u16 = 16;
const NSM_PCR_EXEC_DATA: u16 = 17;
const NSM_PCR_CHUNK_SIZE: usize = 0x800;
const VMADDR_CID_HOST: u32 = 2;

static APP_PID: AtomicI32 = AtomicI32::new(-1);
static SIGTERM_CAUGHT: AtomicBool = AtomicBool::new(false);

extern "C" fn shutdown_sig_handler(sig: libc::c_int) {
    if sig == libc::SIGTERM {
        let pid = APP_PID.load(Ordering::Relaxed);
        if pid > 0 {
            unsafe { libc::kill(pid, libc::SIGTERM) };
            SIGTERM_CAUGHT.store(true, Ordering::Relaxed);
        }
    }
}

fn main() -> anyhow::Result<()> {
    // Block all signals during setup, matching the C implementation's sigfillset.
    let all_signals = SigSet::all();
    signal::sigprocmask(signal::SigmaskHow::SIG_BLOCK, Some(&all_signals), None)
        .context("sigprocmask block all")?;

    // Install SIGUSR1 handler for device proxy ready notification.
    let sigusr1_action = SigAction::new(
        SigHandler::Handler(device::device_proxy_sig_handler),
        SaFlags::empty(),
        SigSet::empty(),
    );
    unsafe { signal::sigaction(Signal::SIGUSR1, &sigusr1_action) }.context("sigaction SIGUSR1")?;

    mods::load().context("mods_load")?;
    fs::console_init().context("console_init")?;

    let cid = cid_fetch().context("cid_fetch")?;

    let args =
        args_reader::read(cid + VSOCK_PORT_OFFSET_ARGS_READER).context("args_reader_read")?;

    let nsm_fd = nsm_init();
    if nsm_fd < 0 {
        anyhow::bail!("unable to open NSM guest module");
    }

    // Ensure NSM fd is closed on any error exit path.
    struct NsmGuard(i32);
    impl Drop for NsmGuard {
        fn drop(&mut self) {
            nsm_exit(self.0);
        }
    }
    let _nsm_guard = NsmGuard(nsm_fd);

    nsm_pcrs_exec_path_extend(nsm_fd, &args.exec_path, &args.exec_argv, &args.exec_envp)
        .context("nsm_pcrs_exec_path_extend")?;

    archive::extract(nsm_fd, &args.rootfs_archive).context("archive_extract")?;

    nsm_lock_pcr(nsm_fd).context("nsm_lock_pcr")?;

    rootfs_mount().context("rootfs_mount")?;

    fs::filesystem_init().context("filesystem_init")?;
    fs::cgroups_init().context("cgroups_init")?;

    let shutdown_fd = unsafe { libc::eventfd(0, 0) };
    if shutdown_fd < 0 {
        return Err(io::Error::last_os_error()).context("eventfd");
    }

    proxies_init(cid, &args, shutdown_fd).context("proxies_init")?;

    // Unblock all signals before forking the application.
    signal::sigprocmask(signal::SigmaskHow::SIG_UNBLOCK, Some(&all_signals), None)
        .context("sigprocmask unblock")?;

    let child_pid = match unsafe { unistd::fork() }.context("fork application")? {
        ForkResult::Child => {
            launch(&args.exec_path, &args.exec_argv, &args.exec_envp)?;
            unreachable!()
        }
        ForkResult::Parent { child } => child,
    };

    APP_PID.store(child_pid.as_raw(), Ordering::Relaxed);

    // Install SIGTERM handler to forward to the app process.
    let sigterm_action = SigAction::new(
        SigHandler::Handler(shutdown_sig_handler),
        SaFlags::empty(),
        SigSet::empty(),
    );
    unsafe { signal::sigaction(Signal::SIGTERM, &sigterm_action) }.context("sigaction SIGTERM")?;

    // Wait for the application to exit.
    let ret_code = loop {
        match wait::waitpid(Some(child_pid), None) {
            Ok(WaitStatus::Exited(_, code)) => break code,
            Ok(WaitStatus::Signaled(_, sig, _)) => break sig as i32 + 128,
            Err(nix::errno::Errno::EINTR) => continue,
            Err(nix::errno::Errno::ECHILD) => break 125,
            _ => continue,
        }
    };

    // If SIGTERM was forwarded to the app, zero the exit code.
    let ret_code = if SIGTERM_CAUGHT.load(Ordering::Relaxed) {
        0
    } else {
        ret_code
    };

    proxies_exit(&args, shutdown_fd).context("proxies_exit")?;
    app_ret_write(ret_code, cid).context("app_ret_write")?;

    Ok(())
}

fn rootfs_mount() -> anyhow::Result<()> {
    mount::mount(
        Some("/rootfs"),
        "/rootfs",
        None::<&str>,
        MsFlags::MS_BIND,
        None::<&str>,
    )
    .context("rootfs bind mount")?;

    unistd::chdir("/rootfs").context("chdir /rootfs")?;
    mount::mount(Some("."), "/", None::<&str>, MsFlags::MS_MOVE, None::<&str>)
        .context("rootfs MS_MOVE")?;
    unistd::chroot(".").context("chroot .")?;
    unistd::chdir("/").context("chdir /")?;

    Ok(())
}

fn launch(path: &str, argv: &[String], envp: &[String]) -> anyhow::Result<()> {
    let _ = unistd::setsid();
    let _ = unistd::setpgid(unistd::Pid::from_raw(0), unistd::Pid::from_raw(0));

    let c_path = CString::new(path).context("launch: path contains null")?;
    let c_argv: Vec<CString> = argv
        .iter()
        .map(|s| CString::new(s.as_str()).context("launch: argv contains null"))
        .collect::<anyhow::Result<_>>()?;
    let c_envp: Vec<CString> = envp
        .iter()
        .map(|s| CString::new(s.as_str()).context("launch: envp contains null"))
        .collect::<anyhow::Result<_>>()?;

    unistd::execvpe(&c_path, &c_argv, &c_envp).with_context(|| format!("execvpe {path}"))?;
    unreachable!()
}

fn nsm_pcrs_exec_path_extend(
    nsm_fd: i32,
    path: &str,
    argv: &[String],
    envp: &[String],
) -> anyhow::Result<()> {
    extend_str(nsm_fd, path)?;
    for s in argv {
        extend_str(nsm_fd, s)?;
    }
    for s in envp {
        extend_str(nsm_fd, s)?;
    }
    Ok(())
}

fn extend_str(nsm_fd: i32, s: &str) -> anyhow::Result<()> {
    for chunk in s.as_bytes().chunks(NSM_PCR_CHUNK_SIZE) {
        let response = nsm_process_request(
            nsm_fd,
            Request::ExtendPCR {
                index: NSM_PCR_EXEC_DATA,
                data: chunk.to_vec(),
            },
        );
        match response {
            Response::ExtendPCR { .. } => {}
            Response::Error(e) => anyhow::bail!("NSM ExtendPCR PCR17 failed: {e:?}"),
            other => anyhow::bail!("NSM ExtendPCR PCR17 unexpected: {other:?}"),
        }
    }
    Ok(())
}

fn nsm_lock_pcr(nsm_fd: i32) -> anyhow::Result<()> {
    // Lock PCR 16 (rootfs measurement) so no further data can be measured into it.
    let response = nsm_process_request(
        nsm_fd,
        Request::LockPCR {
            index: NSM_PCR_ROOTFS,
        },
    );
    match response {
        Response::LockPCR => {}
        Response::Error(e) => anyhow::bail!("NSM LockPCR PCR16 failed: {e:?}"),
        other => anyhow::bail!("NSM LockPCR PCR16 unexpected: {other:?}"),
    }

    // Lock PCR 17 (exec env measurement) so no further data can be measured into it.
    let response = nsm_process_request(
        nsm_fd,
        Request::LockPCR {
            index: NSM_PCR_EXEC_DATA,
        },
    );
    match response {
        Response::LockPCR => {}
        Response::Error(e) => anyhow::bail!("NSM LockPCR PCR17 failed: {e:?}"),
        other => anyhow::bail!("NSM LockPCR PCR17 unexpected: {other:?}"),
    }

    Ok(())
}

fn cid_fetch() -> anyhow::Result<u32> {
    let fd =
        open("/dev/vsock", OFlag::O_RDONLY, Mode::empty()).context("cid_fetch: open /dev/vsock")?;

    let mut cid: u32 = 0;
    // IOCTL_VM_SOCKETS_GET_LOCAL_CID = _IOR(7, 0xb9, unsigned int)
    let ioctl_get_cid = nix::request_code_read!('\x07', 0xb9, mem::size_of::<u32>());

    let ret = unsafe { libc::ioctl(fd.as_raw_fd(), ioctl_get_cid, &mut cid) };
    if ret < 0 {
        return Err(io::Error::last_os_error()).context("cid_fetch: ioctl");
    }
    Ok(cid)
}

fn proxies_init(
    cid: u32,
    args: &args_reader::EnclaveArgs,
    shutdown_fd: RawFd,
) -> anyhow::Result<()> {
    // Unblock SIGUSR1 so device proxy children can signal readiness.
    let mut mask = SigSet::empty();
    mask.add(Signal::SIGUSR1);
    signal::sigprocmask(signal::SigmaskHow::SIG_UNBLOCK, Some(&mask), None)
        .context("unblock SIGUSR1")?;

    if args.app_output {
        device::init(
            device::Device::AppOutputStdio,
            cid + VSOCK_PORT_OFFSET_OUTPUT,
            shutdown_fd,
        )?;
    }

    if args.network_proxy {
        device::init(
            device::Device::NetTapAfVsock,
            cid + VSOCK_PORT_OFFSET_NET,
            shutdown_fd,
        )?;
    }

    device::init(
        device::Device::SignalHandler,
        cid + VSOCK_PORT_OFFSET_SIGNAL_HANDLER,
        shutdown_fd,
    )?;

    Ok(())
}

fn proxies_exit(args: &args_reader::EnclaveArgs, shutdown_fd: RawFd) -> anyhow::Result<()> {
    let val: u64 = 1;
    let write_ret = unsafe {
        libc::write(
            shutdown_fd,
            &val as *const u64 as *const libc::c_void,
            mem::size_of::<u64>(),
        )
    };

    // Always close the stdio output vsock, even if the shutdown write failed.
    // The C implementation does this unconditionally.
    if args.app_output {
        device::stdio::output_close();
    }

    if write_ret < 0 {
        return Err(io::Error::last_os_error()).context("proxies_exit: write shutdown_fd");
    }
    Ok(())
}

fn app_ret_write(code: i32, cid: u32) -> anyhow::Result<()> {
    let port = cid + VSOCK_PORT_OFFSET_APP_RET_CODE;

    // Create the socket, set a 5-second connect timeout, then connect.
    // The host needs to join all device proxy threads before reading the return
    // code; the timeout gives it time to do so (matching the C implementation).
    let mut stream =
        vsock_connect_with_timeout(VMADDR_CID_HOST, port, 5).context("app_ret_write: connect")?;

    stream
        .write_all(&code.to_ne_bytes())
        .context("app_ret_write: write code")?;

    let mut ack = [0u8; 4];
    stream
        .read_exact(&mut ack)
        .context("app_ret_write: read ack")?;

    Ok(())
}

/// Open a vsock stream to (cid, port) with a connect timeout in seconds.
///
/// The vsock crate's `VsockStream::connect` does not expose `setsockopt`
/// before connecting. We create the raw socket, set
/// `SO_VM_SOCKETS_CONNECT_TIMEOUT`, and wrap the fd in a `VsockStream`.
fn vsock_connect_with_timeout(
    cid: u32,
    port: u32,
    timeout_secs: u64,
) -> anyhow::Result<VsockStream> {
    // SO_VM_SOCKETS_CONNECT_TIMEOUT = 6 (from linux/vm_sockets.h)
    const SO_VM_SOCKETS_CONNECT_TIMEOUT: libc::c_int = 6;

    let sock = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM, 0) };
    if sock < 0 {
        return Err(io::Error::last_os_error()).context("vsock_connect_with_timeout: socket");
    }

    let timeval = libc::timeval {
        tv_sec: timeout_secs as libc::time_t,
        tv_usec: 0,
    };
    let ret = unsafe {
        libc::setsockopt(
            sock,
            libc::AF_VSOCK,
            SO_VM_SOCKETS_CONNECT_TIMEOUT,
            &timeval as *const libc::timeval as *const libc::c_void,
            mem::size_of::<libc::timeval>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        unsafe { libc::close(sock) };
        return Err(io::Error::last_os_error())
            .context("vsock_connect_with_timeout: setsockopt timeout");
    }

    let mut svm: libc::sockaddr_vm = unsafe { mem::zeroed() };
    svm.svm_family = libc::AF_VSOCK as libc::sa_family_t;
    svm.svm_cid = cid;
    svm.svm_port = port;
    let ret = unsafe {
        libc::connect(
            sock,
            &svm as *const libc::sockaddr_vm as *const libc::sockaddr,
            mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        unsafe { libc::close(sock) };
        return Err(io::Error::last_os_error()).context("vsock_connect_with_timeout: connect");
    }

    // SAFETY: sock is a valid connected AF_VSOCK SOCK_STREAM fd.
    Ok(unsafe { VsockStream::from_raw_fd(sock) })
}
