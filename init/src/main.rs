use std::env;
use std::ffi::{CStr, CString};
use std::fs::{self, DirBuilder};
use std::io::ErrorKind;
use std::os::unix::fs::DirBuilderExt;

use anyhow::{Context, anyhow};

use rustix::fs::{self as rustix_fs, Mode, OFlags};
use rustix::io::Errno;
use rustix::ioctl::{self, NoArg, Opcode};
use rustix::mount::{self, MountFlags, MountPropagationFlags};
use rustix::process;

const KRUN_REMOVE_ROOT_DIR_IOCTL: Opcode = 0x7603;

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
    let _ = rustix_fs::symlink("/proc/self/fd", "/dev/fd");

    Ok(())
}

/// Read `/proc/filesystems`, skip "nodev" entries, and attempt each filesystem type in turn until
/// one succeeds.
#[cfg(target_os = "linux")]
fn probe_mount(source: &str, target: &str, data: Option<&CStr>) -> anyhow::Result<()> {
    let content = fs::read_to_string("/proc/filesystems").context("opening /proc/filesystems")?;

    for line in content.lines() {
        if line.starts_with("nodev") {
            continue;
        }
        let fstype = line.trim();
        if fstype.is_empty() {
            continue;
        }
        if mount::mount(source, target, fstype, MountFlags::empty(), data).is_ok() {
            return Ok(());
        }
    }
    Err(anyhow!(
        "no filesystem in /proc/filesystems could mount {source} onto {target}"
    ))
}

/// Mount `source` onto `target` using `fstype` when provided, or probe `/proc/filesystems` when
/// `fstype` is empty.
#[cfg(target_os = "linux")]
fn mount_block_device(
    source: &str,
    target: &str,
    fstype: &str,
    data: Option<&CStr>,
) -> anyhow::Result<()> {
    if !fstype.is_empty() {
        mount::mount(source, target, fstype, MountFlags::empty(), data)
            .with_context(|| format!("mounting {source} onto {target} as {fstype}"))
    } else {
        probe_mount(source, target, data)
    }
}

/// Handles optional block-root pivoting and sets shared propagation on the
/// root mount.
#[cfg(target_os = "linux")]
fn setup_block_root() -> anyhow::Result<()> {
    if let Ok(krun_root) = env::var("KRUN_BLOCK_ROOT_DEVICE") {
        let newroot = "/newroot";
        let fstype = env::var("KRUN_BLOCK_ROOT_FSTYPE").unwrap_or_default();
        let options = env::var("KRUN_BLOCK_ROOT_OPTIONS").unwrap_or_default();

        mkdir_if_missing(newroot)?;

        let options_cstr = (!options.is_empty())
            .then(|| CString::new(options).context("KRUN_BLOCK_ROOT_OPTIONS contains a null byte"))
            .transpose()?;
        let data = options_cstr.as_deref();

        mount_block_device(&krun_root, newroot, &fstype, data)?;
        env::set_current_dir(newroot).context("chdir to {newroot}")?;

        let fd =
            rustix_fs::open("/", OFlags::RDONLY, Mode::empty()).context("opening / for ioctl")?;
        if let Err(e) = unsafe { ioctl::ioctl(&fd, NoArg::<KRUN_REMOVE_ROOT_DIR_IOCTL>::new()) } {
            eprintln!("Error removing temporary root directory: {e}");
        }

        mount::mount_move(".", "/").context("mount_move . -> /")?;
        process::chroot(".").context("chroot .")?;

        // Filesystems must be remounted after the chroot.
        mount_filesystems()?;
    }

    mount::mount_change(
        "/",
        MountPropagationFlags::REC | MountPropagationFlags::SHARED,
    )
    .context("setting shared propagation on /")
}

fn main() -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    mount_filesystems()?;

    #[cfg(target_os = "linux")]
    setup_block_root()?;

    // Start a new session and attach the terminal.
    process::setsid().ok();
    process::ioctl_tiocsctty(rustix::stdio::stdin()).ok();

    Ok(())
}
