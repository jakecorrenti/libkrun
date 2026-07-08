use anyhow::Context;

mod fs {
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
}

mod kernel_mods {
    use std::fs::{self, OpenOptions};
    use std::io::{self, ErrorKind};
    use std::os::{fd::AsRawFd, unix::fs::OpenOptionsExt};

    use anyhow::{Context, bail};
    use nix::libc as nix_c;
    use nix::unistd;

    const KRUN_LINUX_MODS_DIR_NAME: &str = "/krun_linux_mods";

    /// Load a kernel module.
    fn load_module(path: &str) -> anyhow::Result<()> {
        let file = match OpenOptions::new()
            .read(true)
            .custom_flags(nix_c::O_CLOEXEC)
            .open(path)
        {
            Ok(file) => file,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(()),
            Err(_) => bail!("unable to open kernel module {}", path),
        };

        let ret =
            unsafe { nix_c::syscall(nix_c::SYS_finit_module, file.as_raw_fd(), c"".as_ptr(), 0) };

        if ret < 0 {
            let os_err = io::Error::last_os_error();
            if os_err.kind() != io::ErrorKind::AlreadyExists {
                bail!("failure to init kernel module {}: {}", path, os_err);
            }
        }

        unistd::unlink(path).context("unable to unlink kernel module path")?;

        Ok(())
    }

    /// Load the configured kernel modules.
    pub fn load_modules() -> anyhow::Result<()> {
        let entries = match fs::read_dir(KRUN_LINUX_MODS_DIR_NAME) {
            Ok(entries) => entries,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(()),
            Err(_) => bail!(
                "unable to open kernel module configuration directory {}",
                KRUN_LINUX_MODS_DIR_NAME
            ),
        };
        for entry in entries {
            let entry = entry?;
            // The full path of the module file.
            let path = format!(
                "{}/{}",
                KRUN_LINUX_MODS_DIR_NAME,
                entry
                    .file_name()
                    .to_str()
                    .context("unable to convert kernel module name to a string")?
            );

            load_module(&path)?;
        }

        Ok(())
    }
}

fn main() -> anyhow::Result<()> {
    // Some linux modules, like virtio-mmio, may be required for console output. Load these modules
    // immediately to ensure they are available to the initrd.
    kernel_mods::load_modules().context("unable to load linux kernel modules")?;

    // Initialize early debug output with /dev/console.
    fs::console_init().context("unable to initialize /dev/console")?;

    Ok(())
}
