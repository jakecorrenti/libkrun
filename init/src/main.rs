#[cfg(target_os = "linux")]
mod dhcp;

#[cfg(target_os = "freebsd")]
mod freebsd;

#[cfg(feature = "timesync")]
mod timesync;

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
#[cfg(target_os = "linux")]
use rustix::system::{RebootCommand, reboot};

use libc::{AF_INET, IFF_UP, ifreq, sockaddr_in};

const KRUN_EXIT_CODE_IOCTL: Opcode = 0x7602;
const SIOCGIFFLAGS: Opcode = 0x8913;
const SIOCSIFFLAGS: Opcode = 0x8914;
#[cfg(target_os = "linux")]
const SIOCSIFADDR: Opcode = 0x8916;
#[cfg(target_os = "linux")]
const SIOCSIFNETMASK: Opcode = 0x891c;

#[cfg(all(feature = "tdx", feature = "sev"))]
fn setup_root() -> anyhow::Result<()> {
    mkdir_if_missing("/tmp")?;
    mkdir_if_missing("/tmp/vda")?;

    do_mount("/dev/vda", "/tmp/vda", "ext4", MountFlags::RELATIME)?;
    rustix_process::chdir("/tmp/vda").context("chdir(/tmp/vda)")?;

    mount::mount_move(".", "/").context("mount(MS_MOVE . -> /)")?;
    rustix_process::chroot(".").context("chroot(.)")?;

    Ok(())
}

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

/// Returns true if `tsi_hijack` appears in the kernel command line before any
/// `--` delimiter. Mirrors `tsi_enabled()` in init.c.
#[cfg(target_os = "linux")]
fn tsi_enabled() -> bool {
    let Ok(cmdline) = fs::read_to_string("/proc/cmdline") else {
        return false;
    };
    cmdline
        .split_whitespace()
        .take_while(|tok| *tok != "--")
        .any(|tok| tok == "tsi_hijack")
}

/// Brings up the `dummy0` interface and assigns it 10.0.0.1/8 so that
/// applications probing for network availability see a configured interface
/// when TSI is in use. Silently succeeds when the dummy driver is absent.
/// Mirrors `enable_dummy_interface()` in init.c.
#[cfg(target_os = "linux")]
fn enable_dummy_interface() -> anyhow::Result<()> {
    use std::net::Ipv4Addr;

    let sock = net::socket(AddressFamily::INET, SocketType::DGRAM, None)
        .context("dummy interface socket")?;

    let mut ifr = ifreq_with_name(b"dummy0\0");

    // Bring the interface up; silently succeed if the device doesn't exist.
    ifr.ifr_ifru.ifru_flags = IFF_UP as libc::c_short;
    let up_result = unsafe {
        ioctl::ioctl(&sock, Updater::<SIOCSIFFLAGS, ifreq>::new(&mut ifr))
    };
    if let Err(e) = up_result {
        if e == Errno::NODEV {
            return Ok(());
        }
        return Err(e).context("dummy interface up");
    }

    // Set IP address to 10.0.0.1.
    let addr_bytes = Ipv4Addr::new(10, 0, 0, 1).octets();
    let mut sin: sockaddr_in = unsafe { mem::zeroed() };
    sin.sin_family = AF_INET as libc::sa_family_t;
    sin.sin_addr.s_addr = u32::from_ne_bytes(addr_bytes);
    unsafe {
        ifr.ifr_ifru.ifru_addr = mem::transmute(sin);
        ioctl::ioctl(&sock, Updater::<SIOCSIFADDR, ifreq>::new(&mut ifr))
            .context("dummy interface address")?;
    }

    // Set netmask to 255.0.0.0.
    let mask_bytes = Ipv4Addr::new(255, 0, 0, 0).octets();
    let mut sin: sockaddr_in = unsafe { mem::zeroed() };
    sin.sin_family = AF_INET as libc::sa_family_t;
    sin.sin_addr.s_addr = u32::from_ne_bytes(mask_bytes);
    unsafe {
        ifr.ifr_ifru.ifru_netmask = mem::transmute(sin);
        ioctl::ioctl(&sock, Updater::<SIOCSIFNETMASK, ifreq>::new(&mut ifr))
            .context("dummy interface mask")?;
    }

    Ok(())
}

/// Holds the parsed values produced by `config_parse_file`.
/// Mirrors the `config_argv` / `config_workdir` locals in main().
#[derive(Default)]
struct Config {
    argv: Option<Vec<String>>,
    workdir: Option<String>,
    #[cfg(target_os = "linux")]
    tmpfs: Option<String>,
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

/// Checks whether `path` is already listed as a mount point in `/proc/mounts`.
/// Uses `/proc/mounts` rather than stat/lstat to avoid triggering Podman's
/// automount mechanism, which would cause the host tmpfs to be mounted.
#[cfg(target_os = "linux")]
fn is_mount_point(path: &str) -> bool {
    let Ok(mounts) = fs::read_to_string("/proc/mounts") else {
        return false;
    };
    mounts.lines().any(|line| {
        line.split_whitespace()
            .nth(1)
            .map_or(false, |mp| mp == path)
    })
}

/// Parses the `mounts` JSON array and returns the destination path of the
/// first tmpfs entry that is not already mounted.
/// Mirrors `config_parse_mounts()` in init.c.
#[cfg(target_os = "linux")]
fn config_parse_mounts(arr: &serde_json::Value) -> Option<String> {
    for entry in arr.as_array()? {
        let obj = entry.as_object()?;
        let destination = obj.get("destination").and_then(|v| v.as_str())?;
        let fstype = obj.get("type").and_then(|v| v.as_str()).unwrap_or("");
        let source = obj.get("source").and_then(|v| v.as_str()).unwrap_or("");
        if fstype == "tmpfs" && source == "tmpfs" && !is_mount_point(destination) {
            return Some(destination.to_owned());
        }
    }
    None
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

    #[cfg(target_os = "linux")]
    let tmpfs = get_config_val(obj, &["mounts"]).and_then(config_parse_mounts);

    Some(Config {
        argv,
        workdir,
        #[cfg(target_os = "linux")]
        tmpfs,
    })
}

/// Resolves the config file path and parses it.
/// Falls back to a cd9660 ISO mount when KRUN_CONFIG is unset.
/// Mirrors lines 1322–1343 of init.c.
#[cfg(target_os = "freebsd")]
fn load_config() -> Config {
    if let Ok(path) = env::var("KRUN_CONFIG") {
        return parse_config(&path);
    }
    // Try mounting the KRUN_CONFIG ISO; fall back to the default path.
    let iso = freebsd::config_file_from_iso().unwrap_or_else(|e| {
        eprintln!("Warning: config ISO setup failed: {e:#}");
        None
    });
    let (path, mounted) = iso
        .map(|p| (p, true))
        .unwrap_or_else(|| (CONFIG_FILE_PATH.to_owned(), false));
    let cfg = parse_config(&path);
    if mounted {
        freebsd::unmount_config_iso();
    }
    cfg
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

/// Dispatches to the platform-appropriate stdio redirect implementation.
/// On Linux: scans virtio-ports. On FreeBSD: opens /dev/console via login_tty.
fn redirect_stdio() -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    setup_redirects()?;
    #[cfg(target_os = "freebsd")]
    freebsd::open_console();

    Ok(())
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
    // Line 1202: FreeBSD opens the controlling console before anything else.
    #[cfg(target_os = "freebsd")]
    freebsd::open_console();

    #[cfg(target_os = "linux")]
    mount_filesystems()?;

    // Lines 1205-1225: mount /dev/vda as ext4, pivot and chroot into it.
    #[cfg(all(feature = "tdx", feature = "sev"))]
    setup_root().context("TEE root setup failed")?;

    #[cfg(target_os = "linux")]
    setup_block_root()?;

    // Start a new session and attach the terminal.
    rustix_process::setsid().ok();
    rustix_process::ioctl_tiocsctty(stdio::stdin()).ok();

    // Line 1293: FreeBSD sets the login name for the session.
    #[cfg(target_os = "freebsd")]
    freebsd::setlogin_root();

    #[cfg(target_os = "linux")]
    setup_network();

    #[cfg(target_os = "linux")]
    if tsi_enabled() {
        if let Err(e) = enable_dummy_interface() {
            eprintln!("Warning: Couldn't enable dummy interface: {e:#}");
        }
    }

    let path = env::var("KRUN_CONFIG").unwrap_or_else(|_| String::from("/.krun_config.json"));
    #[cfg(target_os = "linux")]
    let config = parse_config(&path).unwrap_or_default();
    #[cfg(target_os = "freebsd")]
    let config = load_config();

    // Mount a tmpfs at the directory requested by the config (e.g. from Podman's
    // --tmpfs). TODO: honour tmpcopyup and other mount flags from the config.
    #[cfg(target_os = "linux")]
    if let Some(ref path) = config.tmpfs {
        let flags = MountFlags::NOEXEC | MountFlags::NOSUID | MountFlags::NODEV | MountFlags::RELATIME;
        if let Err(e) = do_mount("tmpfs", path, "tmpfs", flags) {
            eprintln!("mount for tmpfs: {e:#}");
            process::exit(-1);
        }
    }

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

    // Lines 1389-1393: fork a detached child to keep the guest clock in sync.
    #[cfg(feature = "timesync")]
    timesync::spawn();

    // Lines 1396-1444: fork (unless PID 1 mode), redirect stdio to virtio-console
    // ports, exec the workload, and forward its exit code.
    if init_pid1 {
        // Running as PID 1: exec directly in this process.
        redirect_stdio()?;
        do_exec(&exec_argv);
    } else {
        // Fork so that PID 1 (us) can reap children and forward the exit code.
        // SAFETY: standard fork precautions apply; we exec or exit in the child.
        let child_pid = match Pid::from_raw(unsafe { libc::fork() }) {
            None => {
                // Child process (fork returned 0): redirect stdio then exec.
                redirect_stdio()?;
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

        rustix_fs::sync();
        #[cfg(target_os = "linux")]
        let _ = reboot(RebootCommand::Restart);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    // ── config_parse_args ─────────────────────────────────────────────────────

    #[test]
    fn parse_args_returns_vec_for_non_empty_array() {
        let v = serde_json::json!(["sh", "-c", "echo hi"]);
        let result = config_parse_args(&v);
        assert_eq!(result, Some(vec!["sh".to_owned(), "-c".to_owned(), "echo hi".to_owned()]));
    }

    #[test]
    fn parse_args_returns_none_for_empty_array() {
        let v = serde_json::json!([]);
        assert_eq!(config_parse_args(&v), None);
    }

    #[test]
    fn parse_args_returns_none_for_non_array() {
        let v = serde_json::json!("not an array");
        assert_eq!(config_parse_args(&v), None);
    }

    #[test]
    fn parse_args_skips_non_string_elements() {
        let v = serde_json::json!(["cmd", 42, null, "arg"]);
        let result = config_parse_args(&v);
        assert_eq!(result, Some(vec!["cmd".to_owned(), "arg".to_owned()]));
    }

    // ── try_parse_config / config_parse_file ──────────────────────────────────

    fn write_temp_json(content: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().expect("temp file");
        f.write_all(content.as_bytes()).expect("write");
        f
    }

    #[test]
    fn parse_config_cmd_only() {
        let f = write_temp_json(r#"{"Cmd": ["/bin/sh", "-l"]}"#);
        let cfg = config_parse_file(f.path().to_str().unwrap());
        assert_eq!(cfg.argv, Some(vec!["/bin/sh".to_owned(), "-l".to_owned()]));
        assert_eq!(cfg.workdir, None);
    }

    #[test]
    fn parse_config_entrypoint_prepended_to_cmd() {
        let f = write_temp_json(r#"{"Entrypoint": ["/ep"], "Cmd": ["arg1", "arg2"]}"#);
        let cfg = config_parse_file(f.path().to_str().unwrap());
        assert_eq!(
            cfg.argv,
            Some(vec!["/ep".to_owned(), "arg1".to_owned(), "arg2".to_owned()])
        );
    }

    #[test]
    fn parse_config_entrypoint_only() {
        let f = write_temp_json(r#"{"Entrypoint": ["/sbin/init"]}"#);
        let cfg = config_parse_file(f.path().to_str().unwrap());
        assert_eq!(cfg.argv, Some(vec!["/sbin/init".to_owned()]));
    }

    #[test]
    fn parse_config_workdir_from_working_dir_key() {
        let f = write_temp_json(r#"{"Cmd": ["/bin/sh"], "WorkingDir": "/app"}"#);
        let cfg = config_parse_file(f.path().to_str().unwrap());
        assert_eq!(cfg.workdir, Some("/app".to_owned()));
    }

    #[test]
    fn parse_config_workdir_from_cwd_key() {
        let f = write_temp_json(r#"{"Cwd": "/var/run"}"#);
        let cfg = config_parse_file(f.path().to_str().unwrap());
        assert_eq!(cfg.workdir, Some("/var/run".to_owned()));
    }

    #[test]
    fn parse_config_empty_workdir_treated_as_none() {
        let f = write_temp_json(r#"{"WorkingDir": "", "Cmd": ["/bin/sh"]}"#);
        let cfg = config_parse_file(f.path().to_str().unwrap());
        assert_eq!(cfg.workdir, None);
    }

    #[test]
    fn parse_config_key_lookup_is_case_insensitive() {
        // lowercase "cmd" and "workingdir" should still be matched.
        let f = write_temp_json(r#"{"cmd": ["/bin/bash"], "workingdir": "/home"}"#);
        let cfg = config_parse_file(f.path().to_str().unwrap());
        assert_eq!(cfg.argv, Some(vec!["/bin/bash".to_owned()]));
        assert_eq!(cfg.workdir, Some("/home".to_owned()));
    }

    #[test]
    fn parse_config_missing_file_returns_default() {
        let cfg = config_parse_file("/nonexistent/path/to/config.json");
        assert_eq!(cfg.argv, None);
        assert_eq!(cfg.workdir, None);
    }

    #[test]
    fn parse_config_invalid_json_returns_default() {
        let f = write_temp_json("not json at all {{{");
        let cfg = config_parse_file(f.path().to_str().unwrap());
        assert_eq!(cfg.argv, None);
        assert_eq!(cfg.workdir, None);
    }

    #[test]
    fn parse_config_json_array_root_returns_default() {
        // Root must be an object, not an array.
        let f = write_temp_json(r#"["/bin/sh"]"#);
        let cfg = config_parse_file(f.path().to_str().unwrap());
        assert_eq!(cfg.argv, None);
    }

    // ── set_rlimits ───────────────────────────────────────────────────────────

    #[test]
    fn set_rlimits_valid_single_entry() {
        // RLIMIT_NOFILE is resource 7 on Linux. Set soft=64 hard=128 — low
        // values that are always permissible and don't affect test runners.
        set_rlimits("7=64:128");
        // If no panic/abort occurred, parsing succeeded.
    }

    #[test]
    fn set_rlimits_multiple_entries() {
        // RLIMIT_NOFILE (7)=64:128 and RLIMIT_NPROC (6)=32:64 on Linux.
        set_rlimits("7=64:128,6=32:64");
    }

    #[test]
    fn set_rlimits_invalid_entries_do_not_panic() {
        // Malformed entries should log but not panic.
        set_rlimits("bad");
        set_rlimits("7=notanumber:128");
        set_rlimits("7=64");
        set_rlimits("");
    }
}
