// SPDX-License-Identifier: Apache-2.0
pub mod net;
pub mod signal;
pub mod stdio;

use std::os::fd::RawFd;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::Context;

/// Set by the SIGUSR1 handler to indicate a device proxy child is ready.
pub static DEVICE_PROXY_READY: AtomicBool = AtomicBool::new(false);

/// Signal handler that sets `DEVICE_PROXY_READY` on SIGUSR1.
///
/// # Safety
/// Must only be called from a signal handler context (registered via sigaction).
pub extern "C" fn device_proxy_sig_handler(sig: libc::c_int) {
    if sig == libc::SIGUSR1 {
        DEVICE_PROXY_READY.store(true, Ordering::Release);
    }
}

/// The set of available device proxies.
pub enum Device {
    SignalHandler,
    AppOutputStdio,
    NetTapAfVsock,
}

/// Initialize the specified device proxy.
///
/// For proxies that fork (`SignalHandler`, `NetTapAfVsock`), this function
/// spins until the child sends SIGUSR1 indicating it is ready.
pub fn init(dev: Device, vsock_port: u32, shutdown_fd: RawFd) -> anyhow::Result<()> {
    DEVICE_PROXY_READY.store(false, Ordering::Relaxed);

    match dev {
        Device::SignalHandler => {
            signal::handler_init(vsock_port, shutdown_fd).context("device::init SignalHandler")?;
            spin_until_ready();
        }
        Device::AppOutputStdio => {
            stdio::output_init(vsock_port).context("device::init AppOutputStdio")?;
            // AppOutputStdio does not fork; no SIGUSR1 wait needed.
        }
        Device::NetTapAfVsock => {
            net::tap_afvsock_init(vsock_port, shutdown_fd).context("device::init NetTapAfVsock")?;
            spin_until_ready();
        }
    }

    Ok(())
}

/// Spin-wait until a device proxy child signals SIGUSR1.
fn spin_until_ready() {
    while !DEVICE_PROXY_READY.load(Ordering::Acquire) {
        std::hint::spin_loop();
    }
}
