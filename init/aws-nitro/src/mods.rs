// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::os::fd::AsRawFd;

use anyhow::Context;
use nix::errno::Errno;
use nix::fcntl::{OFlag, open};
use nix::sys::stat::Mode;

const MODS_DIR: &str = "/krun_linux_mods";

/// Load all kernel modules found in `/krun_linux_mods/`.
///
/// Each file is loaded via `finit_module(2)` then unlinked.
/// If the directory does not exist, this is a no-op.
pub fn load() -> anyhow::Result<()> {
    let entries = match fs::read_dir(MODS_DIR) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e).context("mods: open /krun_linux_mods"),
    };

    for entry in entries {
        let entry = entry.context("mods: read directory entry")?;
        let path = entry.path();
        let path_str = path.to_string_lossy();

        // Open the module file.
        let fd = open(&path, OFlag::O_RDONLY | OFlag::O_CLOEXEC, Mode::empty());

        let fd = match fd {
            Ok(fd) => fd,
            Err(Errno::ENOENT) => continue,
            Err(e) => return Err(e).with_context(|| format!("mods: open {path_str}")),
        };

        // Load the module via finit_module(2).
        let ret =
            unsafe { libc::syscall(libc::SYS_finit_module, fd.as_raw_fd(), c"".as_ptr(), 0i32) };

        if ret < 0 {
            let errno = Errno::last();
            if errno != Errno::EEXIST {
                return Err(errno).with_context(|| format!("mods: finit_module {path_str}"));
            }
        }

        drop(fd);

        fs::remove_file(&path).with_context(|| format!("mods: unlink {path_str}"))?;
    }

    Ok(())
}
