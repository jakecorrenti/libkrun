// Rust port of the resource-audit driver: run any launcher under the full
// measurement pipeline (console captured, /proc/<pid> sampled from outside,
// article-style reports written to the results directory). Behavioral
// duplicate of scripts/resource-audit/run-audit.sh, which stays untouched
// as the reference; the function names mirror the bash ones so the two can
// be compared side by side.

mod procfs;
mod report;
mod runner;

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, exit};
use std::time::SystemTime;

use crate::report::Builds;
use crate::runner::run_wrap;

const PROG: &str = "run-audit-rs";

/// Everything run_wrap and the report writers need, resolved once.
pub struct Config {
    /// The directory holding the helpers (parse-smaps.awk,
    /// annotate-maps.py, the C sources) plus build/ and results/.
    pub home: PathBuf,
    pub cc: String,
    pub libdir: String,
    pub extra_ld: Option<String>,
    pub label_shim: PathBuf,
    pub phase_hook: PathBuf,
    pub vma_probe: PathBuf,
    pub clk_tck: i64,
    pub results_dir: PathBuf,
    pub name: String,
    pub cmd: Vec<String>,
    pub labels: bool,
    pub rebuild: bool,
    pub knobs: Knobs,
}

/// Timing and sizing knobs, parsed for the arithmetic. `raw` keeps the
/// values as given: bash echoes them verbatim into cmd.txt, metrics.txt
/// and meta.txt, so "8" must not become "8.0".
#[derive(Debug)]
pub struct Knobs {
    pub settle: f64,
    pub duration: u64,
    pub interval: u64,
    pub ram_mib: u64,
    pub phase_pause: u64,
    pub raw: RawKnobs,
}

#[derive(Debug)]
pub struct RawKnobs {
    pub settle: String,
    pub duration: String,
    pub interval: String,
    pub ram_mib: String,
    pub phase_pause: String,
}

/// Raw command line after option parsing, before validation.
pub struct ParsedArgs {
    pub name: Option<String>,
    pub ram_mib: String,
    pub phase_pause: String,
    pub settle: String,
    pub duration: String,
    pub interval: String,
    pub results_dir: Option<String>,
    pub labels: bool,
    pub rebuild: bool,
    pub cmd: Vec<String>,
}

/// What option parsing decided to do.
pub enum Cli {
    Run(ParsedArgs),
    /// -h/--help: usage on stdout, exit 0
    Help,
    /// exit 1 with this message on stderr, plus the usage text when bash
    /// printed it too
    Fail {
        msg: String,
        usage: bool,
    },
}

const USAGE: &str = "\
Usage: run-audit-rs [OPTIONS] COMMAND [ARGS...]

Measures COMMAND (a VM launcher or any process) from outside: console
captured, /proc/<pid> sampled, article-style reports written to the
results directory.

Options:
  --name NAME        test name for outputs (default: COMMAND basename)
  --ram-mib N        guest RAM in MiB for exact guest-RAM matching (optional;
                     without it the multi-region method applies)
  --phase-pause S    seconds the phase hook holds libkrun launchers at
                     krun_vmm_run() (default 10)
  --settle S         max wait for the readiness marker (default 10)
  --duration S       sampling duration once ready (default 10)
  --interval S       sampling interval in seconds (default 1)
  --results DIR      output directory (default results/<timestamp>)
  --no-labels        don't preload the mmap/malloc label shim
  --rebuild          rebuild the shims even if up to date
  -h, --help         show this help

The first non-option argument starts COMMAND; everything after it belongs
to the command and is passed through untouched (so sh -c '...' and other
dash-args work). A literal -- immediately before COMMAND is also accepted
and skipped, as is a leading --wrap (both for compatibility with earlier
invocations). A command that itself starts with a dash needs the -- form.

Environment:
  KRUN_AUDIT_CC             C compiler (default: cc)
  KRUN_AUDIT_PREFIX         installation prefix of libkrun (default: /usr/local,
                            libraries are expected in $PREFIX/lib64)
  KRUN_AUDIT_EXTRA_LD_PATH  extra LD_LIBRARY_PATH entries placed in front of
                            the prefix libdir — put a directory holding an
                            alternative libkrunfw.so.5 here to audit a
                            different guest kernel build
  KRUN_AUDIT_MALLOC_LABEL_KIB
                            malloc-labeling threshold in KiB (default 128),
                            read by the shim itself
";

pub fn die(msg: &str) -> ! {
    eprintln!("{PROG}: {msg}");
    exit(1);
}

/// Write a file or die trying — bash's bare redirects under set -e.
pub fn put(path: &Path, content: impl AsRef<[u8]>) {
    fs::write(path, content)
        .unwrap_or_else(|e| die(&format!("cannot write {}: {e}", path.display())));
}

/// bash's basename(1), for the name default and the launcher fragment.
pub fn basename(path: &str) -> String {
    let trimmed = path.trim_end_matches('/');
    match trimmed.rsplit_once('/') {
        Some((_, last)) => last.to_string(),
        None => trimmed.to_string(),
    }
}

fn main() {
    // Pick up the ambient locale like bash does: GNU sort's tie-breaks (the
    // top-mapping orders, the lib list) collate with strcoll, which under
    // e.g. en_US.UTF-8 ignores punctuation and is not byte order.
    unsafe { libc::setlocale(libc::LC_ALL, c"".as_ptr()) };

    let args: Vec<String> = env::args().skip(1).collect();
    let parsed = match parse_cli(&args) {
        Cli::Run(parsed) => parsed,
        Cli::Help => {
            print!("{USAGE}");
            exit(0);
        }
        Cli::Fail { msg, usage } => {
            eprintln!("{msg}");
            if usage {
                eprint!("{USAGE}");
            }
            exit(1);
        }
    };

    let cfg = build_config(&parsed);
    runner::install_signal_handlers();

    let builds = build_binaries(&cfg);
    report::write_meta(&cfg, &builds);

    println!("=== measuring: {} ===", cfg.name);
    let completed = vec![cfg.name.clone()];
    let ok = run_wrap(&cfg);
    report::write_run_summary(&cfg, &completed);

    if ok {
        println!("all tests passed");
        exit(0);
    }
    exit(1);
}

/// Option parsing, mirroring the bash case statement: the first
/// non-option argument starts the command, `--` skips ahead to it.
fn parse_cli(args: &[String]) -> Cli {
    let mut parsed = ParsedArgs {
        name: None,
        ram_mib: "0".to_string(),
        phase_pause: "10".to_string(),
        settle: "10".to_string(),
        duration: "10".to_string(),
        interval: "1".to_string(),
        results_dir: None,
        labels: true,
        rebuild: false,
        cmd: Vec::new(),
    };

    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();
        match arg {
            "--no-labels" => {
                parsed.labels = false;
                i += 1;
            }
            "--rebuild" => {
                parsed.rebuild = true;
                i += 1;
            }
            // compatibility with earlier invocations
            "--wrap" => i += 1,
            "-h" | "--help" => return Cli::Help,
            "--" => {
                // the command follows; everything after belongs to it
                parsed.cmd = args[i + 1..].to_vec();
                return Cli::Run(parsed);
            }
            _ if matches_opt(arg, "--name") => match take_value(args, &mut i, "--name") {
                Ok(value) => parsed.name = Some(value),
                Err(msg) => return Cli::Fail { msg, usage: false },
            },
            _ if matches_opt(arg, "--ram-mib") => match take_value(args, &mut i, "--ram-mib") {
                Ok(value) => parsed.ram_mib = value,
                Err(msg) => return Cli::Fail { msg, usage: false },
            },
            _ if matches_opt(arg, "--phase-pause") => {
                match take_value(args, &mut i, "--phase-pause") {
                    Ok(value) => parsed.phase_pause = value,
                    Err(msg) => return Cli::Fail { msg, usage: false },
                }
            }
            _ if matches_opt(arg, "--settle") => match take_value(args, &mut i, "--settle") {
                Ok(value) => parsed.settle = value,
                Err(msg) => return Cli::Fail { msg, usage: false },
            },
            _ if matches_opt(arg, "--duration") => match take_value(args, &mut i, "--duration") {
                Ok(value) => parsed.duration = value,
                Err(msg) => return Cli::Fail { msg, usage: false },
            },
            _ if matches_opt(arg, "--interval") => match take_value(args, &mut i, "--interval") {
                Ok(value) => parsed.interval = value,
                Err(msg) => return Cli::Fail { msg, usage: false },
            },
            _ if matches_opt(arg, "--results") => match take_value(args, &mut i, "--results") {
                Ok(value) => parsed.results_dir = Some(value),
                Err(msg) => return Cli::Fail { msg, usage: false },
            },
            _ if arg.starts_with('-') => {
                return Cli::Fail {
                    msg: format!(
                        "unknown option: {arg} (a command starting with a dash needs an explicit -- before it)"
                    ),
                    usage: true,
                };
            }
            _ => {
                // the first non-option argument starts the command; the
                // rest of the line is passed through untouched
                parsed.cmd = args[i..].to_vec();
                return Cli::Run(parsed);
            }
        }
    }
    Cli::Run(parsed)
}

/// "--opt" or "--opt=..."
fn matches_opt(arg: &str, opt: &str) -> bool {
    arg == opt || arg.starts_with(&format!("{opt}="))
}

/// Value of "--opt VALUE" / "--opt=VALUE", advancing past it.
fn take_value(args: &[String], i: &mut usize, opt: &str) -> Result<String, String> {
    if let Some(value) = args[*i].strip_prefix(&format!("{opt}=")) {
        *i += 1;
        return Ok(value.to_string());
    }
    if *i + 1 >= args.len() {
        return Err(format!("option {opt} requires a value"));
    }
    let value = args[*i + 1].clone();
    *i += 2;
    Ok(value)
}

impl ParsedArgs {
    /// bash's checks, in the same order and with the same messages.
    fn validate(&self) -> Result<(Knobs, String), String> {
        let settle = if is_seconds(&self.settle) {
            self.settle.parse().unwrap_or(0.0)
        } else {
            return Err("--settle must be a number of seconds".to_string());
        };
        let duration = parse_uint(&self.duration)
            .ok_or_else(|| "--duration must be an integer number of seconds".to_string())?;
        let interval = parse_uint(&self.interval)
            .ok_or_else(|| "--interval must be an integer number of seconds".to_string())?;
        if interval < 1 {
            return Err("--interval must be at least 1 second".to_string());
        }
        if self.cmd.is_empty() {
            return Err("no command given (pass it after the options)".to_string());
        }
        let ram_mib =
            parse_uint(&self.ram_mib).ok_or_else(|| "--ram-mib must be a number".to_string())?;
        let phase_pause = parse_uint(&self.phase_pause)
            .ok_or_else(|| "--phase-pause must be a number of seconds".to_string())?;

        let name = match &self.name {
            Some(name) if !name.is_empty() => name.clone(),
            _ => basename(&self.cmd[0]),
        };
        if name.contains('/') || name.contains("..") {
            return Err(format!("invalid --name '{name}'"));
        }

        let knobs = Knobs {
            settle,
            duration,
            interval,
            ram_mib,
            phase_pause,
            raw: RawKnobs {
                settle: self.settle.clone(),
                duration: self.duration.clone(),
                interval: self.interval.clone(),
                ram_mib: self.ram_mib.clone(),
                phase_pause: self.phase_pause.clone(),
            },
        };
        Ok((knobs, name))
    }
}

/// bash's ^[0-9]+([.][0-9]+)?$
fn is_seconds(s: &str) -> bool {
    match s.split_once('.') {
        Some((int, frac)) => is_uint(int) && is_uint(frac),
        None => is_uint(s),
    }
}

fn is_uint(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

/// A validated all-digit string, or None when it is not one / overflows.
fn parse_uint(s: &str) -> Option<u64> {
    is_uint(s).then(|| s.parse().ok()).flatten()
}

fn build_config(parsed: &ParsedArgs) -> Config {
    let (knobs, name) = parsed.validate().unwrap_or_else(|msg| die(&msg));

    let home = resolve_home();
    let cc = env::var("KRUN_AUDIT_CC").unwrap_or_else(|_| "cc".to_string());
    let prefix = env::var("KRUN_AUDIT_PREFIX").unwrap_or_else(|_| "/usr/local".to_string());
    let libdir = format!("{prefix}/lib64");
    let extra_ld = env::var("KRUN_AUDIT_EXTRA_LD_PATH")
        .ok()
        .filter(|p| !p.is_empty());

    let results_dir = match parsed.results_dir.as_deref().filter(|dir| !dir.is_empty()) {
        Some(dir) => PathBuf::from(dir),
        None => home.join("results").join(local_timestamp()),
    };
    if dir_exists_nonempty(&results_dir) {
        die(&format!(
            "results directory {} exists and is not empty (use --results DIR)",
            results_dir.display()
        ));
    }
    fs::create_dir_all(&results_dir)
        .unwrap_or_else(|e| die(&format!("cannot create {}: {e}", results_dir.display())));

    let build = home.join("build");
    Config {
        label_shim: build.join("mmap-label.so"),
        phase_hook: build.join("phase-hook.so"),
        vma_probe: build.join("vma-probe"),
        clk_tck: unsafe { libc::sysconf(libc::_SC_CLK_TCK) },
        home,
        cc,
        libdir,
        extra_ld,
        results_dir,
        name,
        cmd: parsed.cmd.clone(),
        labels: parsed.labels,
        rebuild: parsed.rebuild,
        knobs,
    }
}

/// The audit home: bash used SCRIPT_DIR; a compiled binary can live
/// anywhere, so $KRUN_AUDIT_HOME wins, then the directory containing the
/// binary, then the cwd — each walked upwards until both helper files
/// show up.
fn resolve_home() -> PathBuf {
    if let Ok(home) = env::var("KRUN_AUDIT_HOME") {
        return PathBuf::from(home);
    }
    let exe = env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf));
    let cwd = env::current_dir().ok();
    for start in exe.into_iter().chain(cwd) {
        let mut dir = Some(start.as_path());
        while let Some(d) = dir {
            if d.join("parse-smaps.awk").is_file() && d.join("annotate-maps.py").is_file() {
                return d.to_path_buf();
            }
            dir = d.parent();
        }
    }
    die(
        "cannot locate the audit home (a directory containing parse-smaps.awk and \
         annotate-maps.py); set KRUN_AUDIT_HOME",
    )
}

fn dir_exists_nonempty(dir: &Path) -> bool {
    dir.exists() && fs::read_dir(dir).is_ok_and(|mut entries| entries.next().is_some())
}

/// date +%Y%m%d-%H%M%S in local time.
fn local_timestamp() -> String {
    unsafe {
        let now = libc::time(std::ptr::null_mut());
        let mut tm: libc::tm = std::mem::zeroed();
        if libc::localtime_r(&now, &mut tm).is_null() {
            return "19700101-000000".to_string();
        }
        format!(
            "{:04}{:02}{:02}-{:02}{:02}{:02}",
            tm.tm_year + 1900,
            tm.tm_mon + 1,
            tm.tm_mday,
            tm.tm_hour,
            tm.tm_min,
            tm.tm_sec
        )
    }
}

/// Build the shims and the probe. Returns the build commands meta.txt
/// records ("cached from previous run" when nothing was rebuilt).
fn build_binaries(cfg: &Config) -> Builds {
    let build = cfg.home.join("build");
    fs::create_dir_all(&build)
        .unwrap_or_else(|e| die(&format!("cannot create {}: {e}", build.display())));

    let mut builds = Builds::default();

    if stale(cfg, "mmap-label.c", &cfg.label_shim) {
        cc(
            cfg,
            &["-O2", "-shared", "-fPIC"],
            &cfg.label_shim,
            "mmap-label.c",
            &["-ldl"],
        );
        builds.label_shim = Some(format!(
            "{} -O2 -shared -fPIC -o build/mmap-label.so mmap-label.c -ldl",
            cfg.cc
        ));
    }
    if stale(cfg, "phase-hook.c", &cfg.phase_hook) {
        cc(
            cfg,
            &["-O2", "-shared", "-fPIC"],
            &cfg.phase_hook,
            "phase-hook.c",
            &["-ldl"],
        );
        builds.phase_hook = Some(format!(
            "{} -O2 -shared -fPIC -o build/phase-hook.so phase-hook.c -ldl",
            cfg.cc
        ));
    }
    if stale(cfg, "vma-probe.c", &cfg.vma_probe) {
        cc(cfg, &["-O2"], &cfg.vma_probe, "vma-probe.c", &[]);
        builds.vma_probe = Some(format!("{} -O2 -o build/vma-probe vma-probe.c", cfg.cc));
    }

    builds
}

/// bash's rebuild test: artifact missing, source newer than it, or --rebuild.
fn stale(cfg: &Config, src: &str, artifact: &Path) -> bool {
    cfg.rebuild || !artifact.is_file() || mtime(&cfg.home.join(src)) > mtime(artifact)
}

fn mtime(path: &Path) -> SystemTime {
    fs::metadata(path)
        .and_then(|m| m.modified())
        .unwrap_or(SystemTime::UNIX_EPOCH)
}

/// $CC <flags> -o <artifact> <home>/<src> <trailing>. A failure kills the
/// run, like bash's set -e around the compiler.
fn cc(cfg: &Config, flags: &[&str], artifact: &Path, src: &str, trailing: &[&str]) {
    let status = Command::new(&cfg.cc)
        .args(flags)
        .arg("-o")
        .arg(artifact)
        .arg(cfg.home.join(src))
        .args(trailing)
        .status()
        .unwrap_or_else(|e| die(&format!("cannot run {}: {e}", cfg.cc)));
    if !status.success() {
        die(&format!("failed to build {src} ({status})"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn first_non_option_starts_the_command() {
        let cli = parse_cli(&args(&["--settle", "3", "sh", "-c", "echo hi"]));
        let Cli::Run(parsed) = cli else {
            panic!("expected a run");
        };
        assert_eq!(parsed.cmd, vec!["sh", "-c", "echo hi"]);
        assert_eq!(parsed.settle, "3");
    }

    #[test]
    fn double_dash_allows_a_dash_leading_command() {
        let cli = parse_cli(&args(&["--", "--weird", "-x"]));
        let Cli::Run(parsed) = cli else {
            panic!("expected a run");
        };
        assert_eq!(parsed.cmd, vec!["--weird", "-x"]);
    }

    #[test]
    fn double_dash_alone_is_no_command() {
        let cli = parse_cli(&args(&["--"]));
        let Cli::Run(parsed) = cli else {
            panic!("expected a run");
        };
        assert!(parsed.cmd.is_empty());
        assert_eq!(
            parsed.validate().unwrap_err(),
            "no command given (pass it after the options)"
        );
    }

    #[test]
    fn equals_form_and_missing_value() {
        let cli = parse_cli(&args(&["--name=x", "--", "ls"]));
        let Cli::Run(parsed) = cli else {
            panic!("expected a run");
        };
        assert_eq!(parsed.name.as_deref(), Some("x"));

        let cli = parse_cli(&args(&["--name"]));
        let Cli::Fail { msg, usage } = cli else {
            panic!("expected a failure");
        };
        assert_eq!(msg, "option --name requires a value");
        assert!(!usage);
    }

    #[test]
    fn wrap_is_skipped_for_compatibility() {
        let cli = parse_cli(&args(&["--wrap", "--", "ls"]));
        let Cli::Run(parsed) = cli else {
            panic!("expected a run");
        };
        assert_eq!(parsed.cmd, vec!["ls"]);
    }

    #[test]
    fn unknown_option_is_an_error_with_usage() {
        let cli = parse_cli(&args(&["--bogus"]));
        let Cli::Fail { msg, usage } = cli else {
            panic!("expected a failure");
        };
        assert_eq!(
            msg,
            "unknown option: --bogus (a command starting with a dash needs an explicit -- before it)"
        );
        assert!(usage);
    }

    #[test]
    fn validation_messages_and_order() {
        let base = |settle: &str, duration: &str, interval: &str, ram_mib: &str| ParsedArgs {
            name: None,
            ram_mib: ram_mib.to_string(),
            phase_pause: "10".to_string(),
            settle: settle.to_string(),
            duration: duration.to_string(),
            interval: interval.to_string(),
            results_dir: None,
            labels: true,
            rebuild: false,
            cmd: vec!["ls".to_string()],
        };
        // settle comes first even with other bad values present
        assert_eq!(
            base("x", "y", "z", "w").validate().unwrap_err(),
            "--settle must be a number of seconds"
        );
        assert_eq!(
            base("1.5", "y", "z", "w").validate().unwrap_err(),
            "--duration must be an integer number of seconds"
        );
        assert_eq!(
            base("1.5", "1", "z", "w").validate().unwrap_err(),
            "--interval must be an integer number of seconds"
        );
        assert_eq!(
            base("1.5", "1", "0", "w").validate().unwrap_err(),
            "--interval must be at least 1 second"
        );
        assert_eq!(
            base("1.5", "1", "1", "w").validate().unwrap_err(),
            "--ram-mib must be a number"
        );
        // a decimal settle is fine
        let (knobs, name) = base("1.5", "1", "1", "0").validate().unwrap();
        assert_eq!(knobs.settle, 1.5);
        assert_eq!(name, "ls");
    }

    #[test]
    fn settle_number_shapes() {
        assert!(is_seconds("10"));
        assert!(is_seconds("3.5"));
        assert!(!is_seconds("3."));
        assert!(!is_seconds(".5"));
        assert!(!is_seconds("1.2.3"));
        assert!(!is_seconds(""));
        assert!(!is_seconds("-1"));
    }

    #[test]
    fn invalid_name_is_rejected() {
        let parsed = ParsedArgs {
            name: Some("a/b".to_string()),
            ram_mib: "0".to_string(),
            phase_pause: "10".to_string(),
            settle: "1".to_string(),
            duration: "1".to_string(),
            interval: "1".to_string(),
            results_dir: None,
            labels: true,
            rebuild: false,
            cmd: vec!["ls".to_string()],
        };
        assert_eq!(parsed.validate().unwrap_err(), "invalid --name 'a/b'");
    }

    #[test]
    fn basename_matches_the_shell_one() {
        assert_eq!(basename("/usr/bin/sh"), "sh");
        assert_eq!(basename("sh"), "sh");
        assert_eq!(basename("./chroot_vm"), "chroot_vm");
        assert_eq!(basename("dir/"), "dir");
    }
}
