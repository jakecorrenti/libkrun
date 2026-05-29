// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result};
use std::io;

// SO_VM_SOCKETS_CONNECT_TIMEOUT is Linux-specific and not in the libc crate.
const SO_VM_SOCKETS_CONNECT_TIMEOUT: libc::c_int = 6;

/// Fork a child process that connects to the host's signal vsock port and
/// forwards signals to the parent process.  Sends SIGUSR1 to the parent once
/// the vsock connection is established.
pub fn init(vsock_port: u32, shutdown_fd: i32) -> Result<()> {
    let pid = unsafe { libc::fork() };
    match pid {
        -1 => Err(io::Error::last_os_error()).context("fork signal handler proxy"),
        0 => {
            // Child process.
            let vsock_fd = vsock_connect(vsock_port)
                .expect("signal handler: connect vsock");
            run(vsock_fd, shutdown_fd);
        }
        _ => Ok(()), // Parent returns immediately.
    }
}

fn run(vsock_fd: i32, shutdown_fd: i32) -> ! {
    // Notify parent that the proxy is ready.
    unsafe { libc::kill(libc::getppid(), libc::SIGUSR1) };

    let mut pfds = [
        libc::pollfd { fd: vsock_fd,    events: libc::POLLIN, revents: 0 },
        libc::pollfd { fd: shutdown_fd, events: libc::POLLIN, revents: 0 },
    ];

    loop {
        let ret = unsafe { libc::poll(pfds.as_mut_ptr(), pfds.len() as _, -1) };
        if ret < 0 {
            let e = unsafe { *libc::__errno_location() };
            if e == libc::EINTR {
                continue;
            }
            break;
        }

        // Signal received on vsock — read and forward to parent.
        if pfds[0].revents & libc::POLLIN != 0 {
            let mut sig: i32 = libc::SIGTERM;
            let n = unsafe {
                libc::read(
                    vsock_fd,
                    &mut sig as *mut _ as *mut libc::c_void,
                    std::mem::size_of::<i32>(),
                )
            };
            if n != std::mem::size_of::<i32>() as libc::ssize_t {
                sig = libc::SIGTERM;
            }
            unsafe { libc::kill(libc::getppid(), sig) };
        }

        // Shutdown event — exit.
        if pfds[1].revents & libc::POLLIN != 0 {
            break;
        }
    }

    unsafe { libc::close(vsock_fd) };
    unsafe { libc::exit(0) };
}

fn vsock_connect(port: u32) -> Result<i32> {
    let sock_fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM, 0) };
    if sock_fd < 0 {
        return Err(io::Error::last_os_error()).context("create signal vsock");
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
        return Err(io::Error::last_os_error()).context("set signal vsock timeout");
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
        return Err(io::Error::last_os_error()).context("connect signal vsock");
    }

    Ok(sock_fd)
}
