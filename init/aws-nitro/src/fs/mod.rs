use std::fs::OpenOptions;
use std::os::fd::AsFd;

use anyhow::Context;
use nix::errno::Errno;
use nix::mount::{self, MsFlags};
use nix::unistd;

/// Initialize /dev/console and redirect std{err, in, out} to it for early debug output.
pub fn console_init() -> anyhow::Result<()> {
    let path = "/dev/console";

    match mount::mount(
        Some("dev"),
        "/dev",
        Some("devtmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
        None::<&str>,
    ) {
        Ok(_) => Ok(()),
        Err(Errno::EBUSY) => Ok(()),
        Err(e) => Err(e),
    }?;

    // Redirect stdin, stdout, and stderr to /dev/console.
    let console_r = OpenOptions::new()
        .read(true)
        .open(path)
        .context("unable to open /dev/console as read-only")?;

    unistd::dup2_stdin(console_r.as_fd()).context("unable to redirect stdin")?;

    let console_w = OpenOptions::new()
        .write(true)
        .open(path)
        .context("unable to open /dev/console as write-only")?;
    let console_w = console_w.as_fd();

    unistd::dup2_stdout(console_w).context("unable to redirect stdout")?;
    unistd::dup2_stderr(console_w).context("unable to redirect stderr")
}
