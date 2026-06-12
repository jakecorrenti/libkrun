// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::io::{BufRead, BufReader};
use std::os::unix::fs as unix_fs;

use anyhow::Context;
use nix::mount::{self, MsFlags};

/// Mount /dev and redirect stdin/stdout/stderr to /dev/console for early debug output.
pub fn console_init() -> anyhow::Result<()> {
    mount_or_busy(
        Some("dev"),
        "/dev",
        Some("devtmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
    )?;

    // Reopen stdin, stdout, stderr on /dev/console.
    let console = "/dev/console";
    unsafe {
        reopen_fd(libc::STDIN_FILENO, console, libc::O_RDONLY)
            .context("console_init: reopen stdin")?;
        reopen_fd(libc::STDOUT_FILENO, console, libc::O_WRONLY)
            .context("console_init: reopen stdout")?;
        reopen_fd(libc::STDERR_FILENO, console, libc::O_WRONLY)
            .context("console_init: reopen stderr")?;
    }

    Ok(())
}

/// Open `path` with `flags`, dup2 it over `target_fd`, then close the new fd.
///
/// # Safety
/// `target_fd` must be a valid fd number. `path` must be a valid null-terminated string.
unsafe fn reopen_fd(target_fd: libc::c_int, path: &str, flags: libc::c_int) -> anyhow::Result<()> {
    let path_c = std::ffi::CString::new(path).unwrap();
    // SAFETY: path_c is a valid null-terminated C string.
    let new_fd = unsafe { libc::open(path_c.as_ptr(), flags) };
    if new_fd < 0 {
        return Err(std::io::Error::last_os_error()).with_context(|| format!("open {path}"));
    }
    // SAFETY: new_fd and target_fd are valid file descriptors.
    if unsafe { libc::dup2(new_fd, target_fd) } < 0 {
        unsafe { libc::close(new_fd) };
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("dup2 -> fd {target_fd}"));
    }
    unsafe { libc::close(new_fd) };
    Ok(())
}

/// Initialize the root filesystem with ephemeral file systems.
///
/// Creates /dev, /proc, /run, /sys, /tmp and mounts devtmpfs, proc, sysfs,
/// tmpfs on the appropriate paths. Also creates /dev/shm, /dev/pts and
/// /dev/fd symlinks.
pub fn filesystem_init() -> anyhow::Result<()> {
    let sys_dirs = ["/dev", "/proc", "/run", "/sys", "/tmp"];
    for dir in &sys_dirs {
        fs::create_dir(dir).with_context(|| format!("mkdir {dir}"))?;
    }

    mount_or_busy(
        Some("/dev"),
        "/dev",
        Some("devtmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
    )?;

    let dev_dirs = ["/dev/shm", "/dev/pts"];
    for dir in &dev_dirs {
        fs::create_dir(dir).with_context(|| format!("mkdir {dir}"))?;
    }

    mount::mount(
        Some("shm"),
        "/dev/shm",
        Some("tmpfs"),
        MsFlags::MS_NODEV | MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
        None::<&str>,
    )
    .context("mount /dev/shm")?;

    mount::mount(
        Some("devpts"),
        "/dev/pts",
        Some("devpts"),
        MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
        None::<&str>,
    )
    .context("mount /dev/pts")?;

    mount::mount(
        Some("/proc"),
        "/proc",
        Some("proc"),
        MsFlags::MS_NODEV | MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
        None::<&str>,
    )
    .context("mount /proc")?;

    unix_fs::symlink("/proc/self/fd", "/dev/fd").context("symlink /dev/fd")?;
    unix_fs::symlink("/proc/self/fd/0", "/dev/stdin").context("symlink /dev/stdin")?;
    unix_fs::symlink("/proc/self/fd/1", "/dev/stdout").context("symlink /dev/stdout")?;
    unix_fs::symlink("/proc/self/fd/2", "/dev/stderr").context("symlink /dev/stderr")?;

    mount::mount(
        Some("tmpfs"),
        "/run",
        Some("tmpfs"),
        MsFlags::MS_NODEV | MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
        Some("mode=0755"),
    )
    .context("mount /run")?;

    mount::mount(
        Some("tmpfs"),
        "/tmp",
        Some("tmpfs"),
        MsFlags::MS_NODEV | MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
        None::<&str>,
    )
    .context("mount /tmp")?;

    mount::mount(
        Some("sysfs"),
        "/sys",
        Some("sysfs"),
        MsFlags::MS_NODEV | MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
        None::<&str>,
    )
    .context("mount /sys")?;

    mount::mount(
        Some("cgroup_root"),
        "/sys/fs/cgroup",
        Some("tmpfs"),
        MsFlags::MS_NODEV | MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
        Some("mode=0755"),
    )
    .context("mount /sys/fs/cgroup")?;

    Ok(())
}

/// Read `/proc/cgroups` and mount each enabled cgroup under `/sys/fs/cgroup/<name>`.
pub fn cgroups_init() -> anyhow::Result<()> {
    let f = std::fs::File::open("/proc/cgroups").context("cgroups_init: open /proc/cgroups")?;
    let reader = BufReader::new(f);
    let mut lines = reader.lines();

    // Skip the header line.
    lines.next();

    for line in lines {
        let line = line.context("cgroups_init: read /proc/cgroups")?;
        let mut parts = line.split_whitespace();

        let name = match parts.next() {
            Some(n) => n.to_string(),
            None => continue,
        };
        let _hier = parts.next();
        let _groups = parts.next();
        let enabled: i32 = match parts.next() {
            Some(e) => e.parse().unwrap_or(0),
            None => continue,
        };

        if enabled != 0 {
            let path = format!("/sys/fs/cgroup/{name}");
            fs::create_dir(&path).with_context(|| format!("cgroups_init: mkdir {path}"))?;

            mount::mount(
                Some(name.as_str()),
                path.as_str(),
                Some("cgroup"),
                MsFlags::MS_NODEV | MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
                Some(name.as_str()),
            )
            .with_context(|| format!("cgroups_init: mount {path}"))?;
        }
    }

    Ok(())
}

/// Mount, treating `EBUSY` (already mounted) as success.
fn mount_or_busy(
    src: Option<&str>,
    target: &str,
    fstype: Option<&str>,
    flags: MsFlags,
) -> anyhow::Result<()> {
    match mount::mount(src, target, fstype, flags, None::<&str>) {
        Ok(()) => Ok(()),
        Err(nix::errno::Errno::EBUSY) => Ok(()),
        Err(e) => Err(e).with_context(|| format!("mount {target}")),
    }
}
