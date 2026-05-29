// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;
use std::fs;
use std::os::unix::fs::OpenOptionsExt;

const MODS_DIR: &str = "/krun_linux_mods";

pub fn load() -> Result<()> {
    let dir = match fs::read_dir(MODS_DIR) {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e).map_err(|e| anyhow::anyhow!("open {MODS_DIR}: {e}")),
    };

    for entry in dir {
        let entry = entry?;
        let path = entry.path();

        let file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC)
            .open(&path)
            .map_err(|e| anyhow::anyhow!("open module {}: {e}", path.display()))?;

        let ret = unsafe {
            libc::syscall(
                libc::SYS_finit_module,
                std::os::unix::io::IntoRawFd::into_raw_fd(file),
                c"".as_ptr(),
                0,
            )
        };
        if ret < 0 {
            let e = std::io::Error::last_os_error();
            return Err(anyhow::anyhow!("init module {}: {e}", path.display()));
        }

        fs::remove_file(&path)
            .map_err(|e| anyhow::anyhow!("unlink module {}: {e}", path.display()))?;
    }

    Ok(())
}
