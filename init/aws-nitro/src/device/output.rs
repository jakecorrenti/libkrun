// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result};
use std::io;

// SO_VM_SOCKETS_CONNECT_TIMEOUT is Linux-specific and not in the libc crate.
const SO_VM_SOCKETS_CONNECT_TIMEOUT: libc::c_int = 6;

static mut APP_STDIO_VSOCK_FD: i32 = -1;

/// Connect stdout and stderr to a vsock port on the host, forwarding all
/// application output there.
pub fn init(vsock_port: u32) -> Result<()> {
    let sock_fd = vsock_connect(vsock_port).context("connect app output vsock")?;

    for target in [libc::STDOUT_FILENO, libc::STDERR_FILENO] {
        if sock_fd != target {
            let ret = unsafe { libc::dup2(sock_fd, target) };
            if ret < 0 {
                return Err(io::Error::last_os_error())
                    .with_context(|| format!("dup2 output socket to fd {target}"));
            }
        }
    }

    unsafe { APP_STDIO_VSOCK_FD = sock_fd };
    Ok(())
}

pub fn close() {
    unsafe {
        libc::close(libc::STDOUT_FILENO);
        libc::close(libc::STDERR_FILENO);
        if APP_STDIO_VSOCK_FD >= 0 {
            libc::close(APP_STDIO_VSOCK_FD);
            APP_STDIO_VSOCK_FD = -1;
        }
    }
}

fn vsock_connect(port: u32) -> Result<i32> {
    let sock_fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM, 0) };
    if sock_fd < 0 {
        return Err(io::Error::last_os_error()).context("create output vsock");
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
        return Err(io::Error::last_os_error()).context("set output vsock timeout");
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
        return Err(io::Error::last_os_error()).context("connect output vsock");
    }

    Ok(sock_fd)
}
