// SPDX-License-Identifier: Apache-2.0

use std::os::fd::IntoRawFd;
use std::sync::atomic::{AtomicI32, Ordering};

use anyhow::Context;
use vsock::{VsockAddr, VsockStream};

const VMADDR_CID_HOST: u32 = 2;

static APP_STDIO_OUTPUT_VSOCK_FD: AtomicI32 = AtomicI32::new(-1);

/// Connect to the host's stdio output vsock and redirect stdout/stderr to it.
pub fn output_init(vsock_port: u32) -> anyhow::Result<()> {
    let stream = VsockStream::connect(&VsockAddr::new(VMADDR_CID_HOST, vsock_port))
        .context("stdio: vsock connect")?;
    let sock_fd = stream.into_raw_fd();

    // dup2 the socket over stdout and stderr.
    unsafe {
        if libc::dup2(sock_fd, libc::STDOUT_FILENO) < 0 {
            libc::close(sock_fd);
            return Err(std::io::Error::last_os_error()).context("stdio: dup2 stdout");
        }
        if libc::dup2(sock_fd, libc::STDERR_FILENO) < 0 {
            libc::close(sock_fd);
            return Err(std::io::Error::last_os_error()).context("stdio: dup2 stderr");
        }
    }

    APP_STDIO_OUTPUT_VSOCK_FD.store(sock_fd, Ordering::Relaxed);

    Ok(())
}

/// Close the stdout/stderr file descriptors and the stored vsock fd.
pub fn output_close() {
    unsafe {
        libc::close(libc::STDOUT_FILENO);
        libc::close(libc::STDERR_FILENO);
    }
    let fd = APP_STDIO_OUTPUT_VSOCK_FD.swap(-1, Ordering::Relaxed);
    if fd >= 0 {
        unsafe { libc::close(fd) };
    }
}
