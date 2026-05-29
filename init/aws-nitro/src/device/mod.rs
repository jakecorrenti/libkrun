// SPDX-License-Identifier: Apache-2.0

pub mod net;
pub mod output;
pub mod signal;

use crate::args::EnclaveArgs;
use anyhow::Result;
use std::io;

// Vsock port offsets from the enclave CID.
pub const PORT_OFFSET_ARGS_READER: u32 = 1;
pub const PORT_OFFSET_NET: u32 = 2;
pub const PORT_OFFSET_OUTPUT: u32 = 3;
pub const PORT_OFFSET_APP_RET_CODE: u32 = 4;
pub const PORT_OFFSET_SIGNAL_HANDLER: u32 = 5;

/// Initialize device proxies.  Blocks per-proxy until each signals readiness
/// via SIGUSR1 (for proxies that fork a child process).
pub fn proxies_init(cid: u32, args: &EnclaveArgs, shutdown_fd: i32) -> Result<()> {
    // Enable SIGUSR1 so forked proxy children can signal readiness.
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = proxy_sigusr1_handler as *const () as libc::sighandler_t;
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaddset(&mut sa.sa_mask, libc::SIGUSR1);
        libc::sigprocmask(libc::SIG_UNBLOCK, &sa.sa_mask, std::ptr::null_mut());
        libc::sigaction(libc::SIGUSR1, &sa, std::ptr::null_mut());
    }

    if args.app_output {
        output::init(cid + PORT_OFFSET_OUTPUT)?;
    }

    if args.network_proxy {
        DEVICE_PROXY_READY.store(0, std::sync::atomic::Ordering::SeqCst);
        net::init(cid + PORT_OFFSET_NET, shutdown_fd)?;
        while DEVICE_PROXY_READY.load(std::sync::atomic::Ordering::SeqCst) == 0 {
            std::hint::spin_loop();
        }
    }

    DEVICE_PROXY_READY.store(0, std::sync::atomic::Ordering::SeqCst);
    signal::init(cid + PORT_OFFSET_SIGNAL_HANDLER, shutdown_fd)?;
    while DEVICE_PROXY_READY.load(std::sync::atomic::Ordering::SeqCst) == 0 {
        std::hint::spin_loop();
    }

    Ok(())
}

/// Signal all proxies to shut down by writing to the eventfd.
pub fn proxies_exit(args: &EnclaveArgs, shutdown_fd: i32) -> Result<()> {
    let val: u64 = 1;
    let ret = unsafe {
        libc::write(
            shutdown_fd,
            &val as *const _ as *const libc::c_void,
            std::mem::size_of::<u64>(),
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error())
            .map_err(|e| anyhow::anyhow!("write shutdown fd: {e}"));
    }

    if args.app_output {
        output::close();
    }

    Ok(())
}

static DEVICE_PROXY_READY: std::sync::atomic::AtomicI32 =
    std::sync::atomic::AtomicI32::new(0);

extern "C" fn proxy_sigusr1_handler(sig: libc::c_int) {
    if sig == libc::SIGUSR1 {
        DEVICE_PROXY_READY.store(1, std::sync::atomic::Ordering::SeqCst);
    }
}
