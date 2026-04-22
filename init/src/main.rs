#[cfg(target_os = "linux")]
mod dhcp;

use std::env;
use std::ffi::{CStr, CString};
use std::fs::{self, DirBuilder};
use std::io::{Error as IoError, ErrorKind};
use std::mem;
use std::os::unix::fs::DirBuilderExt;
use std::process;

use anyhow::{Context, anyhow};

use rustix::fs::{self as rustix_fs, Mode, OFlags};
use rustix::io::{self as rustix_io, Errno};
use rustix::ioctl::{self, IntegerSetter, NoArg, Opcode, Updater};
use rustix::mount::{self, MountFlags, MountPropagationFlags};
use rustix::net::{self, AddressFamily, SocketType};
use rustix::process::{self as rustix_process, Pid, WaitOptions};
use rustix::stdio;

use libc::{IFF_UP, ifreq};

const KRUN_REMOVE_ROOT_DIR_IOCTL: Opcode = 0x7603;
const KRUN_EXIT_CODE_IOCTL: Opcode = 0x7602;
const SIOCGIFFLAGS: Opcode = 0x8913;
const SIOCSIFFLAGS: Opcode = 0x8914;

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
        rustix_process::chroot(".").context("chroot .")?;

        // Filesystems must be remounted after the chroot.
        mount_filesystems()?;
    }

    mount::mount_change(
        "/",
        MountPropagationFlags::REC | MountPropagationFlags::SHARED,
    )
    .context("setting shared propagation on /")
}

#[cfg(target_os = "linux")]
fn ifreq_with_name(name: &[u8]) -> ifreq {
    let mut ifr: ifreq = unsafe { mem::zeroed() };
    for (dst, src) in ifr.ifr_name.iter_mut().zip(name) {
        *dst = *src as libc::c_char;
    }
    ifr
}

/// Brings up `lo` unconditionally, then optionally brings up `eth0` and runs
/// DHCP on it when `KRUN_DHCP=1`. Mirrors lines 1296–1320 of init.c.
#[cfg(target_os = "linux")]
fn setup_network() {
    let Ok(sock) = net::socket(AddressFamily::INET, SocketType::DGRAM, None) else {
        return;
    };

    // Bring up lo.
    let mut ifr = ifreq_with_name(b"lo\0");
    unsafe {
        ifr.ifr_ifru.ifru_flags |= IFF_UP as libc::c_short;
        ioctl::ioctl(&sock, Updater::<SIOCSIFFLAGS, ifreq>::new(&mut ifr)).ok();
    }

    if env::var("KRUN_DHCP").as_deref() != Ok("1") {
        return;
    }
    // Check whether eth0 exists via SIOCGIFFLAGS.
    let mut ifr = ifreq_with_name(b"eth0\0");
    unsafe {
        if ioctl::ioctl(&sock, Updater::<SIOCGIFFLAGS, ifreq>::new(&mut ifr)).is_ok() {
            // eth0 exists — bring it up.
            ifr.ifr_ifru.ifru_flags |= IFF_UP as libc::c_short;
            ioctl::ioctl(&sock, Updater::<SIOCSIFFLAGS, ifreq>::new(&mut ifr)).ok();
        }
    }
    if let Err(e) = dhcp::do_dhcp("eth0") {
        eprintln!("Warning: DHCP configuration for eth0 failed: {e}");
    }
}

/// Holds the parsed values produced by `config_parse_file`.
/// Mirrors the `config_argv` / `config_workdir` locals in main().
#[derive(Default)]
struct Config {
    argv: Option<Vec<String>>,
    workdir: Option<String>,
}

/// Parses env vars out of a JSON array value and calls `std::env::set_var`.
/// Mirrors `config_parse_env()` in init.c.
/// HOME and TERM always overwrite; all other vars are set only if not already present.
fn config_parse_env(arr: &serde_json::Value) {
    let Some(entries) = arr.as_array() else {
        return;
    };
    for entry in entries {
        let Some(s) = entry.as_str() else { continue };
        let Some((key, val)) = s.split_once('=') else {
            continue;
        };
        if key == "HOME" || key == "TERM" || env::var_os(key).is_none() {
            // SAFETY: init runs single-threaded at this point; no concurrent
            // threads can observe the environment change.
            unsafe { env::set_var(key, val) };
        }
    }
}

/// Parses a JSON array of strings into a `Vec<String>`.
/// Returns `None` when the array is empty (mirrors the C returning NULL for 0 args).
/// Mirrors `config_parse_args()` in init.c.
fn config_parse_args(arr: &serde_json::Value) -> Option<Vec<String>> {
    let entries: Vec<String> = arr
        .as_array()?
        .iter()
        .filter_map(|v| v.as_str().map(str::to_owned))
        .collect();
    (!entries.is_empty()).then_some(entries)
}

/// Case-insensitive key lookup
///
/// Find a key in the JSON object that matches any of the provided keys and return the value
/// associated with it.
fn get_config_val<'a>(
    obj: &'a serde_json::Map<String, serde_json::Value>,
    keys: &[&str],
) -> Option<&'a serde_json::Value> {
    obj.iter()
        .find(|(k, _)| keys.iter().any(|&q| k.eq_ignore_ascii_case(q)))
        .map(|(_, v)| v)
}

/// Reads, parses, and extracts fields from a krun JSON config file.
///
/// Recognised top-level keys (all case-insensitive via serde_json's string matching):
///   "Env"        – array of "KEY=VALUE" strings → set as environment variables
///   "args" / "Cmd"        – array of strings → argv
///   "Entrypoint"          – array of strings → prepended to argv
///   "WorkingDir" / "Cwd"  – string → working directory
fn parse_config(path: &str) -> Option<Config> {
    let text = fs::read_to_string(path).ok()?;

    let root: serde_json::Value = serde_json::from_str(&text)
        .map_err(|e| eprintln!("Error parsing config file: {e}"))
        .ok()?;

    let obj = root
        .as_object()
        .ok_or_else(|| eprintln!("Couldn't find object in config file"))
        .ok()?;

    if let Some(env) = get_config_val(obj, &["Env"]) {
        config_parse_env(env);
    }

    let cmd_argv = get_config_val(obj, &["args", "Cmd"]).and_then(config_parse_args);
    let entrypoint = get_config_val(obj, &["Entrypoint"]).and_then(config_parse_args);

    // Concatenate the entrypoint first, then the cmd args.
    let argv = match (entrypoint, cmd_argv) {
        (Some(mut ep), Some(cmd)) => {
            ep.extend(cmd);
            Some(ep)
        }
        (Some(ep), None) => Some(ep),
        (None, cmd) => cmd,
    };

    // Get the workdir and convert it to an owned String if it's not empty
    let workdir = get_config_val(obj, &["WorkingDir", "Cwd"])
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_owned);

    Some(Config { argv, workdir })
}

/// Redirects stdin/stdout/stderr to named virtio-console ports when present.
/// Scans `/sys/class/virtio-ports/*/name` for `krun-stdin`, `krun-stdout`,
/// `krun-stderr` and `dup2`s the matching `/dev/<port>` onto the standard fds.
/// Mirrors `setup_redirects()` + `reopen_fd()` in init.c.
#[cfg(target_os = "linux")]
fn setup_redirects() -> anyhow::Result<()> {
    let ports_dir =
        fs::read_dir("/sys/class/virtio-ports").context("Unable to open ports directory")?;

    for entry in ports_dir.flatten() {
        let name_path = entry.path().join("name");
        let Ok(port_name) = fs::read_to_string(&name_path) else {
            continue;
        };

        let dev_path = format!("/dev/{}", entry.file_name().to_string_lossy());

        let trimmed = port_name.trim();
        let (flags, dup2_fn): (OFlags, fn(rustix::fd::OwnedFd) -> rustix_io::Result<()>) =
            match trimmed {
                "krun-stdin" => (OFlags::RDONLY, stdio::dup2_stdin),
                "krun-stdout" => (OFlags::WRONLY, stdio::dup2_stdout),
                "krun-stderr" => (OFlags::WRONLY, stdio::dup2_stderr),
                _ => continue,
            };

        let result: anyhow::Result<()> = (|| {
            let fd = rustix_fs::open(&dev_path, flags, Mode::empty())
                .with_context(|| format!("opening '{dev_path}'"))?;
            dup2_fn(fd).with_context(|| format!("dup2 onto {trimmed}"))?;
            Ok(())
        })();
        if let Err(e) = result {
            eprintln!("{e:#}");
        }
    }

    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn setup_redirects() -> anyhow::Result<()> {
    Ok(())
}

/// Reports the workload exit code back to the hypervisor via a virtiofs ioctl,
/// but only when `/` is on a virtiofs mount.
/// Mirrors `set_exit_code()` in init.c.
fn set_exit_code(code: libc::c_int) {
    if let Err(e) = try_set_exit_code(code) {
        eprintln!("Warning: failed to report exit code: {e:#}");
    }
}

fn try_set_exit_code(code: libc::c_int) -> anyhow::Result<()> {
    const VIRTIOFS_MAGIC: rustix_fs::FsWord = 0x6573_5546;

    let statfs = rustix_fs::statfs("/").context("could not determine filesystem type for root")?;

    if statfs.f_type != VIRTIOFS_MAGIC {
        return Ok(());
    }

    let fd = rustix_fs::open("/", OFlags::RDONLY, Mode::empty())
        .context("couldn't open root filesystem to report exit code")?;

    // SAFETY: `IntegerSetter` encodes the exit code as a plain integer ioctl argument.
    unsafe {
        ioctl::ioctl(
            &fd,
            IntegerSetter::<KRUN_EXIT_CODE_IOCTL>::new_usize(code as usize),
        )
    }
    .context("ioctl to set exit code failed")?;

    Ok(())
}

/// `execvp`s into `argv[0]` with `argv` as the argument list.
/// Prints a diagnostic and exits with 126/127 on failure (matching podman/chroot).
/// Never returns on success.
fn do_exec(argv: &[String]) -> ! {
    let c_args: Vec<CString> = argv
        .iter()
        .enumerate()
        .map(|(i, a)| {
            CString::new(a.as_bytes()).unwrap_or_else(|_| {
                eprintln!("argv[{i}] contains a null byte");
                set_exit_code(126);
                process::exit(126);
            })
        })
        .collect();

    let mut ptrs: Vec<*const libc::c_char> = c_args.iter().map(|s| s.as_ptr()).collect();
    ptrs.push(std::ptr::null());

    unsafe {
        libc::execvp(ptrs[0], ptrs.as_ptr());
    }
    // execvp only returns on failure; read errno immediately.
    let err = IoError::last_os_error();
    eprintln!("Couldn't execute '{}' inside the vm: {err}", argv[0]);
    let code = if Errno::from_io_error(&err) == Some(Errno::NOENT) {
        127
    } else {
        126
    };
    set_exit_code(code);
    process::exit(code);
}

/// Parses and applies a comma-separated list of rlimit triplets.
/// Format: `<id>=<soft>:<hard>[,<id>=<soft>:<hard>...]`
/// Mirrors `set_rlimits()` in init.c.
fn set_rlimits(spec: &str) {
    for item in spec.split(',') {
        // Split on '=' first to separate the resource ID from "soft:hard",
        // then split the remainder on ':'. This matches the format produced
        // by krun_set_rlimits() and documented in libkrun.h.
        let Some((id_str, limits_str)) = item.split_once('=') else {
            eprintln!("Invalid rlimit entry: {item}");
            continue;
        };
        let Some((cur_str, max_str)) = limits_str.split_once(':') else {
            eprintln!("Invalid rlimit entry: {item}");
            continue;
        };
        let Some((id, cur, max)) = (|| -> Option<_> {
            Some((
                id_str.trim().parse::<libc::__rlimit_resource_t>().ok()?,
                cur_str.trim().parse::<libc::rlim_t>().ok()?,
                max_str.trim().parse::<libc::rlim_t>().ok()?,
            ))
        })() else {
            eprintln!("Invalid rlimit values: {item}");
            continue;
        };
        let rlim = libc::rlimit {
            rlim_cur: cur,
            rlim_max: max,
        };
        // SAFETY: `rlim` is a valid, stack-allocated `rlimit`.
        if unsafe { libc::setrlimit(id, &rlim) } != 0 {
            eprintln!("Error setting rlimit for ID={id}");
        }
    }
}

fn main() -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    mount_filesystems()?;

    #[cfg(target_os = "linux")]
    setup_block_root()?;

    // Start a new session and attach the terminal.
    rustix_process::setsid().ok();
    rustix_process::ioctl_tiocsctty(stdio::stdin()).ok();

    #[cfg(target_os = "linux")]
    setup_network();

    let path = env::var("KRUN_CONFIG").unwrap_or_else(|_| String::from("/.krun_config.json"));
    let config = parse_config(&path).unwrap_or_default();

    // Lines 1345-1353: KRUN_HOME / KRUN_TERM override env vars.
    if let Ok(krun_home) = env::var("KRUN_HOME") {
        // SAFETY: init runs single-threaded at this point; no concurrent
        // threads can observe the environment change.
        unsafe { env::set_var("HOME", krun_home) };
    }
    if let Ok(krun_term) = env::var("KRUN_TERM") {
        // SAFETY: same as above.
        unsafe { env::set_var("TERM", krun_term) };
    }

    // Lines 1355-1360: set hostname, defaulting to "localhost".
    let name = env::var("HOSTNAME").unwrap_or_else(|_| "localhost".to_owned());
    if let Err(e) = rustix::system::sethostname(name.as_bytes()) {
        eprintln!("Warning: sethostname failed: {e}");
    }

    // Lines 1362-1365: parse and apply rlimits from KRUN_RLIMITS.
    if let Ok(rlimits) = env::var("KRUN_RLIMITS") {
        set_rlimits(&rlimits);
    }

    // Lines 1367-1372: choose working directory (env overrides config).
    let workdir = env::var("KRUN_WORKDIR").ok().or(config.workdir);
    if let Some(ref dir) = workdir
        && let Err(e) = env::set_current_dir(dir)
    {
        eprintln!("chdir({dir}): {e}");
    }

    // Lines 1374-1388: resolve the argv to exec and whether to run as PID 1.
    let exec_argv: Vec<String> = if let Ok(krun_init) = env::var("KRUN_INIT") {
        // KRUN_INIT overrides everything: use it as the sole executable.
        vec![krun_init]
    } else if let Some(cfg_argv) = config.argv {
        cfg_argv
    } else {
        vec!["/bin/sh".to_owned()]
    };

    let init_pid1 = env::var("KRUN_INIT_PID1").as_deref() == Ok("1");

    // Lines 1396-1444: fork (unless PID 1 mode), redirect stdio to virtio-console
    // ports, exec the workload, and forward its exit code.
    if init_pid1 {
        // Running as PID 1: exec directly in this process.
        setup_redirects()?;
        do_exec(&exec_argv);
    } else {
        // Fork so that PID 1 (us) can reap children and forward the exit code.
        // SAFETY: standard fork precautions apply; we exec or exit in the child.
        let child_pid = match Pid::from_raw(unsafe { libc::fork() }) {
            None => {
                // Child process (fork returned 0): redirect stdio then exec.
                setup_redirects()?;
                do_exec(&exec_argv);
            }
            Some(pid) if pid.as_raw_nonzero().get() > 0 => pid,
            _ => {
                let err = IoError::last_os_error();
                eprintln!("fork: {err}");
                set_exit_code(125);
                process::exit(125);
            }
        };

        // Parent: reap children until we see our direct child exit.
        let code = loop {
            match rustix_process::waitpid(None, WaitOptions::empty()) {
                Ok(Some((pid, status))) if pid == child_pid => {
                    break if let Some(exit_code) = status.exit_status() {
                        exit_code
                    } else if let Some(signal) = status.terminating_signal() {
                        signal + 128
                    } else {
                        0
                    };
                }
                Ok(_) => continue,
                Err(e) => {
                    eprintln!("waitpid: {e}");
                    break 0;
                }
            }
        };

        set_exit_code(code);
    }

    Ok(())
}
