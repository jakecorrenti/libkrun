// SPDX-License-Identifier: Apache-2.0

use std::io::Read;
use std::os::fd::{AsRawFd, BorrowedFd, RawFd};

use anyhow::Context;
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use nix::sys::signal::{self, Signal};
use nix::unistd::{self, ForkResult};
use vsock::{VsockAddr, VsockStream};

const VMADDR_CID_HOST: u32 = 2;

/// Fork a child process that proxies signals from the host vsock to the parent.
///
/// The child connects to the host's signal vsock, sends SIGUSR1 to the parent
/// when ready, then polls for signals to forward and exits on shutdown.
pub fn handler_init(vsock_port: u32, shutdown_fd: RawFd) -> anyhow::Result<()> {
    let stream = VsockStream::connect(&VsockAddr::new(VMADDR_CID_HOST, vsock_port))
        .context("signal: vsock connect")?;

    match unsafe { unistd::fork() }.context("signal: fork")? {
        ForkResult::Parent { .. } => Ok(()),
        ForkResult::Child => run_signal_proxy(stream, shutdown_fd),
    }
}

fn run_signal_proxy(stream: VsockStream, shutdown_fd: RawFd) -> ! {
    let vsock_raw = stream.as_raw_fd();
    let ppid = unistd::getppid();

    // Notify parent that initialization is complete.
    let _ = signal::kill(ppid, Signal::SIGUSR1);

    let poll_fds = &mut [
        PollFd::new(
            unsafe { BorrowedFd::borrow_raw(vsock_raw) },
            PollFlags::POLLIN,
        ),
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
        {
            let mut buf = [0u8; 4];
            let sig_num = match (&stream).read(&mut buf) {
                Ok(4) => i32::from_ne_bytes(buf),
                _ => libc::SIGTERM,
            };

            if let Ok(sig) = Signal::try_from(sig_num) {
                let _ = signal::kill(ppid, sig);
            }
        }

        if poll_fds[1]
            .revents()
            .is_some_and(|r| r.contains(PollFlags::POLLIN))
        {
            break;
        }
    }

    drop(stream);
    std::process::exit(0);
}
