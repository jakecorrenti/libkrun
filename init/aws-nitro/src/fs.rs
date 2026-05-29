// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result};
use nix::mount::{mount, MsFlags};
use std::fs;
use std::io::BufRead;

const NONE: Option<&str> = None;

pub fn console_init() -> Result<()> {
    match mount(
        Some("dev"),
        "/dev",
        Some("devtmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
        NONE,
    ) {
        Ok(()) | Err(nix::errno::Errno::EBUSY) => {}
        Err(e) => return Err(e).context("mount /dev"),
    }

    // Redirect stdin/stdout/stderr to /dev/console using raw fd dup2.
    let rfd = unsafe { libc::open(c"/dev/console".as_ptr(), libc::O_RDONLY) };
    if rfd < 0 {
        return Err(std::io::Error::last_os_error()).context("open /dev/console for reading");
    }
    if rfd != libc::STDIN_FILENO {
        unsafe { libc::dup2(rfd, libc::STDIN_FILENO) };
        unsafe { libc::close(rfd) };
    }

    let wfd = unsafe { libc::open(c"/dev/console".as_ptr(), libc::O_WRONLY) };
    if wfd < 0 {
        return Err(std::io::Error::last_os_error()).context("open /dev/console for writing");
    }
    for target in [libc::STDOUT_FILENO, libc::STDERR_FILENO] {
        if wfd != target {
            unsafe { libc::dup2(wfd, target) };
        }
    }
    if wfd != libc::STDOUT_FILENO && wfd != libc::STDERR_FILENO {
        unsafe { libc::close(wfd) };
    }

    Ok(())
}

pub fn filesystem_init() -> Result<()> {
    for dir in ["/dev", "/proc", "/run", "/sys", "/tmp"] {
        fs::create_dir(dir).with_context(|| format!("mkdir {dir}"))?;
    }

    match mount(
        Some("/dev"),
        "/dev",
        Some("devtmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
        NONE,
    ) {
        Ok(()) | Err(nix::errno::Errno::EBUSY) => {}
        Err(e) => return Err(e).context("mount /dev"),
    }

    for dir in ["/dev/shm", "/dev/pts"] {
        fs::create_dir(dir).with_context(|| format!("mkdir {dir}"))?;
    }

    mount(
        Some("shm"),
        "/dev/shm",
        Some("tmpfs"),
        MsFlags::MS_NODEV | MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
        NONE,
    )
    .context("mount /dev/shm")?;

    mount(
        Some("devpts"),
        "/dev/pts",
        Some("devpts"),
        MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
        NONE,
    )
    .context("mount /dev/pts")?;

    mount(
        Some("/proc"),
        "/proc",
        Some("proc"),
        MsFlags::MS_NODEV | MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
        NONE,
    )
    .context("mount /proc")?;

    std::os::unix::fs::symlink("/proc/self/fd", "/dev/fd").context("symlink /dev/fd")?;
    std::os::unix::fs::symlink("/proc/self/fd/0", "/dev/stdin").context("symlink /dev/stdin")?;
    std::os::unix::fs::symlink("/proc/self/fd/1", "/dev/stdout").context("symlink /dev/stdout")?;
    std::os::unix::fs::symlink("/proc/self/fd/2", "/dev/stderr").context("symlink /dev/stderr")?;

    mount(
        Some("tmpfs"),
        "/run",
        Some("tmpfs"),
        MsFlags::MS_NODEV | MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
        Some("mode=0755"),
    )
    .context("mount /run")?;

    mount(
        Some("tmpfs"),
        "/tmp",
        Some("tmpfs"),
        MsFlags::MS_NODEV | MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
        NONE,
    )
    .context("mount /tmp")?;

    mount(
        Some("sysfs"),
        "/sys",
        Some("sysfs"),
        MsFlags::MS_NODEV | MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
        NONE,
    )
    .context("mount /sys")?;

    mount(
        Some("cgroup_root"),
        "/sys/fs/cgroup",
        Some("tmpfs"),
        MsFlags::MS_NODEV | MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
        Some("mode=0755"),
    )
    .context("mount /sys/fs/cgroup")?;

    Ok(())
}

pub fn cgroups_init() -> Result<()> {
    let f = fs::File::open("/proc/cgroups").context("open /proc/cgroups")?;
    let mut lines = std::io::BufReader::new(f).lines();

    // Skip header line.
    lines.next();

    for line in lines {
        let line = line.context("read /proc/cgroups")?;
        let mut parts = line.split_whitespace();
        let name = match parts.next() {
            Some(n) => n.to_string(),
            None => continue,
        };
        let _heir: i32 = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
        let _groups: i32 = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
        let enabled: i32 = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);

        if enabled == 0 {
            continue;
        }

        let path = format!("/sys/fs/cgroup/{name}");
        fs::create_dir(&path).with_context(|| format!("mkdir {path}"))?;

        mount(
            Some(name.as_str()),
            path.as_str(),
            Some("cgroup"),
            MsFlags::MS_NODEV | MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
            Some(name.as_str()),
        )
        .with_context(|| format!("mount cgroup {name}"))?;
    }

    Ok(())
}
