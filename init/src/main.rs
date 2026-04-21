use std::ffi::CStr;
use std::fs::DirBuilder;
use std::io::ErrorKind;
use std::os::unix::fs::DirBuilderExt;

use anyhow::Context;
use rustix::io::Errno;
use rustix::mount::{self, MountFlags};

#[cfg(target_os = "linux")]
fn mkdir_if_missing(path: &str) -> anyhow::Result<()> {
    match DirBuilder::new().mode(0o755).create(path) {
        Err(e) if e.kind() == ErrorKind::AlreadyExists => Ok(()),
        res => res.with_context(|| format!("creating directory {path}")),
    }
}

#[cfg(target_os = "linux")]
fn do_mount(source: &str, target: &str, fstype: &str, flags: MountFlags) -> anyhow::Result<()> {
    match mount::mount(source, target, fstype, flags, None::<&CStr>) {
        Err(Errno::BUSY) => Ok(()),
        res => res.with_context(|| format!("mounting {target}")),
    }
}

#[cfg(target_os = "linux")]
fn mount_filesystems() -> anyhow::Result<()> {
    let base_flags = MountFlags::NOEXEC | MountFlags::NOSUID | MountFlags::RELATIME;

    for dir in &["/dev", "/proc", "/sys"] {
        mkdir_if_missing(dir)?;
    }

    do_mount("devtmpfs", "/dev", "devtmpfs", MountFlags::RELATIME)?;
    do_mount("proc", "/proc", "proc", base_flags | MountFlags::NODEV)?;
    do_mount("sysfs", "/sys", "sysfs", base_flags | MountFlags::NODEV)?;

    mkdir_if_missing("/sys/fs/cgroup")?;
    do_mount(
        "cgroup2",
        "/sys/fs/cgroup",
        "cgroup2",
        base_flags | MountFlags::NODEV,
    )?;

    for dir in &["/dev/pts", "/dev/shm"] {
        mkdir_if_missing(dir)?;
    }

    do_mount("devpts", "/dev/pts", "devpts", base_flags)?;
    do_mount("tmpfs", "/dev/shm", "tmpfs", base_flags)?;

    // May fail if the symlink already exists.
    let _ = rustix::fs::symlink("/proc/self/fd", "/dev/fd");

    Ok(())
}

fn main() -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    mount_filesystems()?;
    Ok(())
}
