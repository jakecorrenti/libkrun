// SPDX-License-Identifier: Apache-2.0

mod archive;
mod args;
mod device;
mod fs;
mod modules;
mod nsm;

use anyhow::{Context, Result};
use device::{
    PORT_OFFSET_APP_RET_CODE, PORT_OFFSET_ARGS_READER,
    proxies_exit, proxies_init,
};
use std::ffi::CString;
use std::io;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

const NSM_PCR_EXEC_DATA: u16 = 17;

const IOCTL_VM_SOCKETS_GET_LOCAL_CID: libc::c_ulong = 0x7b9;
// SO_VM_SOCKETS_CONNECT_TIMEOUT is Linux-specific and not in the libc crate.
const SO_VM_SOCKETS_CONNECT_TIMEOUT: libc::c_int = 6;

/// PID of the application process (set in parent after fork).
static APP_PID: AtomicI32 = AtomicI32::new(-1);
/// Set when SIGTERM is forwarded to the application.
static SIGTERM_CAUGHT: AtomicBool = AtomicBool::new(false);

fn main() {
    if let Err(e) = run() {
        eprintln!("krun-nitro-init: {e:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    // Block all signals while we initialize.
    let mut sigset: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe {
        libc::sigfillset(&mut sigset);
        libc::sigprocmask(libc::SIG_BLOCK, &sigset, std::ptr::null_mut());
    }

    modules::load().context("load kernel modules")?;
    fs::console_init().context("console init")?;

    let cid = cid_fetch().context("fetch enclave CID")?;

    let args = args::read(cid + PORT_OFFSET_ARGS_READER).context("read enclave args")?;

    let nsm = nsm::Nsm::new().context("open NSM")?;

    // Measure execution environment in PCR 17.
    nsm_measure_exec(&nsm, &args).context("measure exec environment")?;

    // Extract rootfs from memory, measuring data in PCR 16.
    std::fs::create_dir_all("/rootfs").context("create /rootfs")?;
    archive::extract(&nsm, &args.rootfs_archive).context("extract rootfs archive")?;

    // Lock PCRs and close NSM handle.
    nsm.lock_pcrs(NSM_PCR_EXEC_DATA + 1).context("lock NSM PCRs")?;
    drop(nsm);

    // Switch root to the extracted rootfs.
    rootfs_mount().context("mount rootfs")?;

    fs::filesystem_init().context("filesystem init")?;
    fs::cgroups_init().context("cgroups init")?;

    // Create shutdown eventfd for device proxy coordination.
    let shutdown_fd = unsafe { libc::eventfd(0, 0) };
    if shutdown_fd < 0 {
        return Err(io::Error::last_os_error()).context("create shutdown eventfd");
    }

    proxies_init(cid, &args, shutdown_fd).context("init device proxies")?;

    // Unblock signals now that proxies are running.
    unsafe { libc::sigprocmask(libc::SIG_UNBLOCK, &sigset, std::ptr::null_mut()) };

    // Fork the application.
    let pid = unsafe { libc::fork() };
    match pid {
        -1 => Err(io::Error::last_os_error()).context("fork application"),
        0 => {
            // Child: exec the workload.
            exec_workload(&args.exec_argv, &args.exec_envp);
        }
        app_pid => {
            APP_PID.store(app_pid, Ordering::SeqCst);

            // Set up SIGTERM forwarding to the application.
            unsafe {
                let mut sa: libc::sigaction = std::mem::zeroed();
                sa.sa_sigaction = sigterm_handler as *const () as libc::sighandler_t;
                libc::sigaction(libc::SIGTERM, &sa, std::ptr::null_mut());
            }

            // Wait for application to exit.
            let mut status: i32 = 0;
            unsafe { libc::waitpid(app_pid, &mut status, 0) };

            // If the app was terminated by our forwarded SIGTERM, report 0.
            let ret_code = if SIGTERM_CAUGHT.load(Ordering::SeqCst) {
                0
            } else {
                status
            };

            proxies_exit(&args, shutdown_fd).context("exit device proxies")?;
            app_ret_write(ret_code, cid).context("write return code to host")?;

            Ok(())
        }
    }
}

/// Bind-mount /rootfs onto / and chroot into it.
fn rootfs_mount() -> Result<()> {
    use nix::mount::{mount, MsFlags};
    use nix::unistd::{chdir, chroot};

    mount(
        Some("/rootfs"),
        "/rootfs",
        None::<&str>,
        MsFlags::MS_BIND,
        None::<&str>,
    )
    .context("bind mount /rootfs")?;

    chdir("/rootfs").context("chdir /rootfs")?;

    mount(
        Some("."),
        "/",
        None::<&str>,
        MsFlags::MS_MOVE,
        None::<&str>,
    )
    .context("MS_MOVE rootfs onto /")?;

    chroot(".").context("chroot .")?;
    chdir("/").context("chdir /")?;

    Ok(())
}

/// Measure the exec path, argv, and envp into NSM PCR 17.
fn nsm_measure_exec(nsm: &nsm::Nsm, args: &args::EnclaveArgs) -> Result<()> {
    nsm.extend_pcr(NSM_PCR_EXEC_DATA, args.exec_path.as_bytes())?;
    for arg in &args.exec_argv {
        nsm.extend_pcr(NSM_PCR_EXEC_DATA, arg.as_bytes())?;
    }
    for env in &args.exec_envp {
        nsm.extend_pcr(NSM_PCR_EXEC_DATA, env.as_bytes())?;
    }
    Ok(())
}

/// Retrieve the enclave's vsock CID.
fn cid_fetch() -> Result<u32> {
    let fd = unsafe { libc::open(c"/dev/vsock".as_ptr(), libc::O_RDONLY) };
    if fd < 0 {
        return Err(io::Error::last_os_error()).context("open /dev/vsock");
    }
    let mut cid: u32 = 0;
    let ret = unsafe { libc::ioctl(fd, IOCTL_VM_SOCKETS_GET_LOCAL_CID, &mut cid) };
    unsafe { libc::close(fd) };
    if ret < 0 {
        return Err(io::Error::last_os_error()).context("IOCTL_VM_SOCKETS_GET_LOCAL_CID");
    }
    Ok(cid)
}

/// Connect to the host's return-code vsock and write the application exit code.
/// Waits for the host to acknowledge before returning.
fn app_ret_write(code: i32, cid: u32) -> Result<()> {
    let sock_fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM, 0) };
    if sock_fd < 0 {
        return Err(io::Error::last_os_error()).context("create ret-code vsock");
    }

    let timeout = libc::timeval { tv_sec: 5, tv_usec: 0 };
    unsafe {
        libc::setsockopt(
            sock_fd,
            libc::AF_VSOCK,
            SO_VM_SOCKETS_CONNECT_TIMEOUT,
            &timeout as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as _,
        )
    };

    let mut addr: libc::sockaddr_vm = unsafe { std::mem::zeroed() };
    addr.svm_family = libc::AF_VSOCK as _;
    addr.svm_cid = libc::VMADDR_CID_HOST;
    addr.svm_port = cid + PORT_OFFSET_APP_RET_CODE;

    let ret = unsafe {
        libc::connect(
            sock_fd,
            &addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_vm>() as _,
        )
    };
    if ret < 0 {
        unsafe { libc::close(sock_fd) };
        return Err(io::Error::last_os_error()).context("connect ret-code vsock");
    }

    // Write the return code.
    let ret = unsafe {
        libc::write(
            sock_fd,
            &code as *const _ as *const libc::c_void,
            std::mem::size_of::<i32>(),
        )
    };
    if ret < std::mem::size_of::<i32>() as libc::ssize_t {
        unsafe { libc::close(sock_fd) };
        return Err(io::Error::last_os_error()).context("write ret-code to vsock");
    }

    // Wait for host acknowledgment before returning so the enclave doesn't
    // exit before the host has read the return code.
    let mut ack: i32 = 0;
    unsafe {
        libc::read(
            sock_fd,
            &mut ack as *mut _ as *mut libc::c_void,
            std::mem::size_of::<i32>(),
        )
    };

    unsafe { libc::close(sock_fd) };
    Ok(())
}

/// SIGTERM handler: forward signal to the application process.
extern "C" fn sigterm_handler(sig: libc::c_int) {
    if sig == libc::SIGTERM {
        let app_pid = APP_PID.load(Ordering::SeqCst);
        if app_pid > 0 {
            unsafe { libc::kill(app_pid, libc::SIGTERM) };
            SIGTERM_CAUGHT.store(true, Ordering::SeqCst);
        }
    }
}

/// Exec the workload in the child process (does not return on success).
fn exec_workload(argv: &[String], envp: &[String]) -> ! {
    unsafe { libc::setsid() };
    unsafe { libc::setpgid(0, 0) };

    // Put the first env entry into the process environment (matches the C
    // putenv(envp[0]) which installs a default PATH).
    if let Some(first) = envp.first() {
        if let Ok(s) = CString::new(first.as_str()) {
            unsafe { libc::putenv(s.into_raw()) };
        }
    }

    let c_argv: Vec<CString> = argv
        .iter()
        .filter_map(|s| CString::new(s.as_str()).ok())
        .collect();
    let c_envp: Vec<CString> = envp
        .iter()
        .filter_map(|s| CString::new(s.as_str()).ok())
        .collect();

    let argv_ptrs: Vec<*const libc::c_char> = c_argv
        .iter()
        .map(|s| s.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();
    let envp_ptrs: Vec<*const libc::c_char> = c_envp
        .iter()
        .map(|s| s.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();

    if let Some(prog) = argv_ptrs.first() {
        unsafe {
            libc::execvpe(
                *prog,
                argv_ptrs.as_ptr(),
                envp_ptrs.as_ptr(),
            )
        };
    }

    eprintln!(
        "krun-nitro-init: exec failed: {}",
        io::Error::last_os_error()
    );
    unsafe { libc::exit(1) }
}
