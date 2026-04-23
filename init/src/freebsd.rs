//! FreeBSD-specific init helpers.
use std::ffi::{CStr, CString};
use std::fs;
use std::io;
use std::os::fd::IntoRawFd;

use anyhow::{self, Context};
use rustix::fs::{self as rustix_fs, Mode, OFlags};
use rustix::stdio;

/// Reads a variable from the FreeBSD kernel environment (`kenv(2)`).
/// Used as a drop-in for `getenv` on FreeBSD where process environment
/// variables are not available in early init.
pub fn get_kenv(name: &str) -> Option<String> {
    // KENV_MVALLEN from <kenv.h> is 128 on FreeBSD.
    const KENV_MVALLEN: usize = 128;
    const KENV_GET: libc::c_int = 0;

    let key = CString::new(name).ok()?;
    let mut buf = [0u8; KENV_MVALLEN + 1];

    let ret = unsafe {
        libc::kenv(
            KENV_GET,
            key.as_ptr(),
            buf.as_mut_ptr().cast::<libc::c_char>(),
            (KENV_MVALLEN + 1) as libc::c_int,
        )
    };

    if ret < 0 {
        return None;
    }

    std::str::from_utf8(&buf[..ret as usize])
        .ok()
        .map(str::to_owned)
}

/// Returns the value of `name` from the kernel environment, falling back to
/// the process environment.
pub fn getenv(name: &str) -> Option<String> {
    get_kenv(name).or_else(|| std::env::var(name).ok())
}

const PATH_CONSOLE: &CStr = c"/dev/console";
const PATH_DEVNULL: &CStr = c"/dev/null";
const PATH_INITLOG: &CStr = c"/init.log";

/// Opens `/dev/console` and makes it the controlling terminal for this
/// process, falling back to `/dev/null` + `/init.log` on failure.
/// Called in the child process before exec on FreeBSD.
pub fn open_console() {
    // Revoke any existing access to the console device.
    // SAFETY: PATH_CONSOLE is a valid NUL-terminated path.
    unsafe { libc::revoke(PATH_CONSOLE.as_ptr()) };

    if let Ok(fd) = rustix_fs::open(PATH_CONSOLE, OFlags::RDWR | OFlags::NONBLOCK, Mode::empty()) {
        // Clear O_NONBLOCK now that we have the fd.
        if let Ok(flags) = rustix_fs::fcntl_getfl(&fd) {
            let _ = rustix_fs::fcntl_setfl(&fd, flags & !OFlags::NONBLOCK);
        }

        // login_tty(3) makes fd the controlling terminal, sets up the
        // session, and dups it onto stdin/stdout/stderr.
        // SAFETY: `fd` is a valid open file descriptor.
        let raw = fd.into_raw_fd();
        if unsafe { libc::login_tty(raw) } == 0 {
            return;
        }
        // login_tty failed; fd was already consumed by into_raw_fd so close manually.
        unsafe { libc::close(raw) };
    }

    // Fallback: stdin → /dev/null, stdout/stderr → /init.log.
    let Ok(null_fd) = rustix_fs::open(PATH_DEVNULL, OFlags::RDWR, Mode::empty()) else {
        unsafe { libc::_exit(1) };
    };
    let _ = stdio::dup2_stdin(&null_fd);

    match rustix_fs::open(
        PATH_INITLOG,
        OFlags::WRONLY | OFlags::APPEND | OFlags::CREATE,
        Mode::from_raw_mode(0o644),
    ) {
        Ok(log_fd) => {
            let _ = stdio::dup2_stdout(&log_fd);
        }
        Err(_) => {
            let _ = stdio::dup2_stdout(&null_fd);
        }
    }
    let _ = stdio::dup2_stderr(stdio::stdout());
}

const KRUN_CONFIG_ISO_DEV: &str = "/dev/iso9660/KRUN_CONFIG";
const ISO_CONFIG_FILE_PATH: &str = "/mnt/krun_config.json";

/// Attempts to mount a cd9660 ISO at `/mnt` and returns the path to the
/// config file inside it, or `Ok(None)` if the mount itself fails.
/// Returns `Err` only if a prerequisite step (e.g. creating `/mnt`) fails.
pub fn config_file_from_iso() -> anyhow::Result<Option<String>> {
    // Ensure /mnt exists (may already be present on a read-only rootfs).
    fs::create_dir("/mnt")
        .or_else(|e| {
            if e.kind() == io::ErrorKind::AlreadyExists {
                Ok(())
            } else {
                Err(e)
            }
        })
        .context("mkdir(/mnt)")?;

    // Build the iovec pairs for nmount(2):
    //   fstype=cd9660  fspath=/mnt  from=<device>
    let pairs: &[(&str, &str)] = &[
        ("fstype", "cd9660"),
        ("fspath", "/mnt"),
        ("from", KRUN_CONFIG_ISO_DEV),
    ];

    let cstrings: Vec<(CString, CString)> = pairs
        .iter()
        .map(|(k, v)| {
            (
                CString::new(*k).expect("nmount key contains no nul bytes"),
                CString::new(*v).expect("nmount value contains no nul bytes"),
            )
        })
        .collect();

    let mut iovs: Vec<libc::iovec> = Vec::with_capacity(cstrings.len() * 2);
    for (k, v) in &cstrings {
        let kb = k.as_bytes_with_nul();
        let vb = v.as_bytes_with_nul();
        iovs.push(libc::iovec {
            iov_base: kb.as_ptr().cast_mut().cast(),
            iov_len: kb.len(),
        });
        iovs.push(libc::iovec {
            iov_base: vb.as_ptr().cast_mut().cast(),
            iov_len: vb.len(),
        });
    }

    let ret = unsafe {
        libc::nmount(
            iovs.as_mut_ptr(),
            iovs.len() as libc::c_uint,
            libc::MNT_RDONLY,
        )
    };

    if ret < 0 {
        return Ok(None);
    }
    Ok(Some(ISO_CONFIG_FILE_PATH.to_owned()))
}

/// Unmounts the config ISO previously mounted by `config_file_from_iso`.
pub fn unmount_config_iso() {
    unsafe { libc::unmount(c"/mnt".as_ptr(), 0) };
}

/// Sets the login name of the current session to "root".
/// Called after `setsid()` on FreeBSD.
pub fn setlogin_root() {
    unsafe { libc::setlogin(c"root".as_ptr()) };
}
