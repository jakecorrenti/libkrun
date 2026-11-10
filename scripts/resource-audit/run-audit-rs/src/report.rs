//! The report writers: per-run summary.txt / metrics.txt / libs.txt /
//! cmd.txt, the run-level summary.md and meta.txt, and the awk / python3
//! helper invocations. Wording, spacing and section order are
//! byte-compatible with run-audit.sh — only values may differ.

use std::env;
use std::fmt::Write as _;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::procfs::{field, read_file};
use crate::{Config, basename, put};

/// Build commands for meta.txt; None means "cached from previous run".
#[derive(Default)]
pub struct Builds {
    pub label_shim: Option<String>,
    pub phase_hook: Option<String>,
    pub vma_probe: Option<String>,
}

/// bash's printf ' %q' record in cmd.txt, approximated: tokens made only
/// of shell-safe characters stay raw, everything else is single-quoted
/// with the usual '\'' escaping. The only programmatic consumer
/// (annotate-maps.py) reads the first whitespace token after "cmdline:",
/// strips the quotes and takes the basename.
fn shell_quote(token: &str) -> String {
    let safe = !token.is_empty()
        && token.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'_' | b'+' | b'.' | b',' | b':' | b'@' | b'%' | b'/' | b'=' | b'-'
                )
        });
    if safe {
        token.to_string()
    } else {
        format!("'{}'", token.replace('\'', r"'\''"))
    }
}

/// cmd.txt: the exact environment and knobs the child ran with, written
/// before the spawn so a mid-run crash still leaves the provenance behind.
pub fn write_cmd_txt(cfg: &Config, test_dir: &Path, ld_path: &str, preload: &str) {
    let mut out = String::new();
    writeln!(out, "# environment").unwrap();
    writeln!(out, "LD_LIBRARY_PATH={ld_path}").unwrap();
    writeln!(out, "GLIBC_TUNABLES=glibc.mem.decorate_maps=1").unwrap();
    writeln!(out, "LD_PRELOAD={preload}").unwrap();
    writeln!(out, "KRUN_AUDIT_PHASE_PAUSE={}", cfg.knobs.raw.phase_pause).unwrap();
    writeln!(out, "# knobs").unwrap();
    writeln!(out, "label_mmap={}", cfg.labels as i32).unwrap();
    writeln!(out, "phase_pause={}", cfg.knobs.raw.phase_pause).unwrap();
    writeln!(out, "ram_mib={}", cfg.knobs.raw.ram_mib).unwrap();
    writeln!(out, "# launched from the caller's cwd").unwrap();
    out.push_str("cmdline:");
    for arg in &cfg.cmd {
        out.push_str(&format!(" {}", shell_quote(arg)));
    }
    out.push('\n');
    put(&test_dir.join("cmd.txt"), &out);
}

/// bash's write_libs_txt: ldd output for the binary, then the libkrun
/// libraries actually mapped (from the snapshot's maps), each resolved.
pub fn write_libs_txt(binary: &str, maps_file: &Path, subject: &str, dir: &Path, ld_path: &str) {
    let mut out = String::new();

    // ldd resolves the way the launcher itself did — wrapped commands have
    // no rpath, so without the library path their libs report "not found".
    if let Ok(output) = Command::new("ldd")
        .arg(binary)
        .env("LD_LIBRARY_PATH", ld_path)
        .output()
    {
        out.push_str(&String::from_utf8_lossy(&output.stdout));
    }
    out.push('\n');
    writeln!(
        out,
        "krun libraries actually mapped by {subject} (from {}):",
        basename(&maps_file.to_string_lossy())
    )
    .unwrap();

    let mut libs = Vec::new();
    if let Ok(maps) = fs::read_to_string(maps_file) {
        for line in maps.lines() {
            for token in line.split_whitespace().skip(5) {
                if is_krun_lib(token) {
                    libs.push(token.to_string());
                }
            }
        }
    }
    libs.sort_by(|a, b| coll_cmp(a, b));
    libs.dedup();
    for lib in libs {
        writeln!(out, "  {lib} -> {}", readlink_f(&lib)).unwrap();
    }
    put(&dir.join("libs.txt"), &out);
}

/// awk's /\/libkrun[^/]*\.so/ match on a maps field: a "/libkrun"
/// followed by ".so" before the next slash. Every occurrence counts, not
/// just the first.
fn is_krun_lib(token: &str) -> bool {
    let mut search_from = 0;
    while let Some(rel) = token[search_from..].find("/libkrun") {
        let after_slash = search_from + rel + 1;
        let rest = &token[after_slash..];
        let until_slash = rest.find('/').unwrap_or(rest.len());
        if rest[..until_slash].contains(".so") {
            return true;
        }
        search_from = after_slash;
    }
    false
}

/// readlink -f, with "" when it fails (a missing target resolves to
/// nothing, exactly like the command substitution bash used).
fn readlink_f(path: &str) -> String {
    match Command::new("readlink").arg("-f").arg(path).output() {
        Ok(output) if output.status.success() => {
            String::from_utf8_lossy(&output.stdout).trim().to_string()
        }
        _ => String::new(),
    }
}

/// bash's classify_fds: "total=N, class=cnt, ..." — the classes and the
/// total sorted by name (every class name sorts before "total").
pub fn classify_fds(content: &str) -> String {
    let mut classes: Vec<(String, u64)> = Vec::new();
    let mut total = 0;
    for line in content.lines() {
        // awk's $2: the target, truncated at whitespace like the original
        let target = line.split_whitespace().nth(1).unwrap_or("");
        total += 1;
        let class = fd_class(target);
        match classes.iter_mut().find(|(c, _)| *c == class) {
            Some((_, count)) => *count += 1,
            None => classes.push((class, 1)),
        }
    }
    classes.push(("total".to_string(), total));
    classes.sort_by(|a, b| coll_cmp(&a.0, &b.0));
    classes
        .iter()
        .map(|(class, count)| format!("{class}={count}"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn fd_class(target: &str) -> String {
    if target == "/dev/kvm" {
        "/dev/kvm".to_string()
    } else if target.starts_with("anon_inode:kvm") {
        "anon_inode:kvm-*".to_string()
    } else if target.starts_with("/memfd:") {
        "memfd".to_string()
    } else if target.starts_with("pipe:") {
        "pipe".to_string()
    } else if target.starts_with("socket:") {
        "socket".to_string()
    } else if let Some(rest) = target.strip_prefix("anon_inode:") {
        format!("anon_inode:{}", rest.replace(['[', ']'], ""))
    } else if target.starts_with('/') {
        "file".to_string()
    } else {
        "other".to_string()
    }
}

/// bash's signed_kib: "+N" or "-N", never "+-N".
fn signed_kib(delta: i64) -> String {
    format!("{delta:+}")
}

/// bash arithmetic: a non-numeric string evaluates as 0.
fn num(s: &str) -> i64 {
    s.parse().unwrap_or(0)
}

/// GNU sort's line comparison under the ambient locale: strcoll, with a
/// byte-order fallback when the collation calls the lines equal (matching
/// coreutils). Byte order alone would be wrong: strcoll ignores
/// punctuation at the primary level, so "[anon:4k]" sorts before
/// "/usr/lib/...".
fn coll_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    match (std::ffi::CString::new(a), std::ffi::CString::new(b)) {
        (Ok(ca), Ok(cb)) => {
            let r = unsafe { libc::strcoll(ca.as_ptr(), cb.as_ptr()) };
            if r == 0 { a.cmp(b) } else { r.cmp(&0) }
        }
        _ => a.cmp(b),
    }
}

fn num_f(s: &str) -> f64 {
    s.parse().unwrap_or(0.0)
}

/// bash's ${var:-0}: an empty value prints as 0.
fn nz(s: &str) -> &str {
    if s.is_empty() { "0" } else { s }
}

/// bash's write_summary: summary.txt and metrics.txt from the run's
/// artifacts, then the annotate-maps.py appendix. The appendix is
/// assembled into the same buffer: bash appended it after writing, and
/// annotate-maps.py never reads summary.txt, so the bytes come out
/// identical.
pub fn write_summary(
    cfg: &Config,
    test_dir: &Path,
    config_label: &str,
    result_line: &str,
    metrics_lines: &[String],
) {
    let name = &cfg.name;
    let result_word = result_line.split(" (").next().unwrap_or(result_line);

    let status = read_file(&test_dir.join("final-status.txt"));
    let rollup = read_file(&test_dir.join("final-smaps_rollup.txt"));
    let io = read_file(&test_dir.join("final-io.txt"));

    // Pre-boot phase (the phase-hook shim holding krun_vmm_run()):
    // end-of-phase counters come from the last samples-preboot.csv row.
    let mut have_preboot = false;
    let mut pb = Preboot::default();
    if test_dir.join("preboot-smaps.txt").is_file() {
        have_preboot = true;
        let rows = csv_rows(&test_dir.join("samples-preboot.csv"));
        if let Some(last) = rows.last() {
            pb = Preboot {
                vmrss: csv_field(last, 1),
                rss_anon: csv_field(last, 2),
                rss_file: csv_field(last, 3),
                pss: csv_field(last, 4),
                uss: csv_field(last, 5),
                anon: csv_field(last, 6),
                pte: csv_field(last, 7),
                threads: csv_field(last, 8),
                fds: csv_field(last, 9),
                samples: rows.len().to_string(),
                span: csv_field(last, 0),
            };
        }
    }

    let parsed_path = test_dir.join("parsed-smaps.tsv");
    if test_dir.join("final-smaps.txt").is_file() {
        run_parse_smaps(cfg, test_dir, &parsed_path);
    } else {
        put(&parsed_path, "");
    }
    let parsed = parse_smaps_tsv(&read_file(&parsed_path));

    let vmm_private_anon = num(&parsed.total.anon) - num(&parsed.guest_ram.anon);
    let framework_private_anon = vmm_private_anon - parsed.kernel_cow_anon;

    let vmrss = field(&status, "VmRSS:");
    let rss_anon = field(&status, "RssAnon:");
    let rss_file = field(&status, "RssFile:");
    let vmpte = field(&status, "VmPTE:");
    let threads = field(&status, "Threads:");
    let pss = field(&rollup, "Pss:");
    let uss = num(field(&rollup, "Private_Clean:").unwrap_or("0"))
        + num(field(&rollup, "Private_Dirty:").unwrap_or("0"));
    let anon_r = field(&rollup, "Anonymous:");
    let shared = num(field(&rollup, "Shared_Clean:").unwrap_or("0"))
        + num(field(&rollup, "Shared_Dirty:").unwrap_or("0"));
    let swap_pss = field(&rollup, "SwapPss:");

    let samples = read_samples(&test_dir.join("samples.csv"));
    let (du, ds, dg) = if samples.n > 1 {
        let n = (samples.n - 1) as f64;
        (
            format!(
                "{:.3}",
                (num_f(&samples.last_cpu.0) - num_f(&samples.first_cpu.0)) / n
            ),
            format!(
                "{:.3}",
                (num_f(&samples.last_cpu.1) - num_f(&samples.first_cpu.1)) / n
            ),
            format!(
                "{:.3}",
                (num_f(&samples.last_cpu.2) - num_f(&samples.first_cpu.2)) / n
            ),
        )
    } else {
        ("0".to_string(), "0".to_string(), "0".to_string())
    };

    let mut out = String::new();
    writeln!(out, "Test: {name}").unwrap();
    writeln!(out, "Config: {config_label}").unwrap();
    writeln!(out, "Result: {result_line}").unwrap();
    let note = test_dir.join("final-snapshot-note.txt");
    if note.is_file() {
        out.push_str(&read_file(&note));
    }
    writeln!(
        out,
        "Samples: {} over {}s (interval {}s, duration {}s)",
        samples.n,
        nz(&samples.span_s),
        cfg.knobs.raw.interval,
        cfg.knobs.raw.duration
    )
    .unwrap();
    writeln!(out).unwrap();

    if have_preboot {
        writeln!(out, "[Phase: VMM built, before guest start]").unwrap();
        writeln!(
            out,
            "VmRSS: {} KiB  RssAnon: {} KiB  RssFile: {} KiB  PSS: {} KiB  USS: {} KiB",
            nz(&pb.vmrss),
            nz(&pb.rss_anon),
            nz(&pb.rss_file),
            nz(&pb.pss),
            nz(&pb.uss)
        )
        .unwrap();
        writeln!(
            out,
            "VmPTE: {} KiB  Threads: {}  fds: {}   (at end of pre-boot sampling)",
            nz(&pb.pte),
            nz(&pb.threads),
            nz(&pb.fds)
        )
        .unwrap();
        writeln!(
            out,
            "(samples: {} over {}s, annotated map: preboot-maps-annotated.txt)",
            nz(&pb.samples),
            nz(&pb.span)
        )
        .unwrap();
        writeln!(out).unwrap();
    }

    writeln!(out, "[Process counters /proc/PID/status]").unwrap();
    for key in [
        "VmPeak", "VmSize", "VmHWM", "VmRSS", "RssAnon", "RssFile", "RssShmem", "VmPTE", "VmSwap",
    ] {
        let value = field(&status, &format!("{key}:")).unwrap_or("-");
        writeln!(out, "{key}: {value} KiB").unwrap();
    }
    writeln!(
        out,
        "Threads: {}",
        field(&status, "Threads:").unwrap_or("-")
    )
    .unwrap();
    writeln!(
        out,
        "voluntary_ctxt_switches: {}",
        field(&status, "voluntary_ctxt_switches:").unwrap_or("-")
    )
    .unwrap();
    writeln!(
        out,
        "nonvoluntary_ctxt_switches: {}",
        field(&status, "nonvoluntary_ctxt_switches:").unwrap_or("-")
    )
    .unwrap();
    writeln!(out).unwrap();

    writeln!(out, "[Memory breakdown /proc/PID/smaps_rollup]").unwrap();
    writeln!(out, "Rss: {} KiB", field(&rollup, "Rss:").unwrap_or("-")).unwrap();
    writeln!(out, "Pss: {} KiB", pss.unwrap_or("-")).unwrap();
    if pss.is_some() {
        writeln!(out, "USS (Private_Clean+Private_Dirty): {uss} KiB").unwrap();
    } else {
        writeln!(out, "USS (Private_Clean+Private_Dirty): -").unwrap();
    }
    writeln!(out, "Anonymous: {} KiB", anon_r.unwrap_or("-")).unwrap();
    if pss.is_some() {
        writeln!(out, "Shared (Shared_Clean+Shared_Dirty): {shared} KiB").unwrap();
    } else {
        writeln!(out, "Shared (Shared_Clean+Shared_Dirty): -").unwrap();
    }
    writeln!(out, "SwapPss: {} KiB", swap_pss.unwrap_or("-")).unwrap();
    writeln!(out).unwrap();

    writeln!(out, "[Derived]").unwrap();
    if have_preboot && vmrss.is_some() && anon_r.is_some() {
        writeln!(
            out,
            "boot cost: VmRSS {} KiB, Anonymous {} KiB (guest RAM + kernel COW)",
            signed_kib(num(vmrss.unwrap_or("0")) - num(&pb.vmrss)),
            signed_kib(num(anon_r.unwrap_or("0")) - num(&pb.anon))
        )
        .unwrap();
    }
    writeln!(
        out,
        "guest_ram_rss: {} KiB (method: {}, {} region(s))",
        parsed.guest_ram.rss, parsed.guest_ram.method, parsed.guest_ram.n
    )
    .unwrap();
    writeln!(
        out,
        "vmm_private_anon: {vmm_private_anon} KiB   (= Anonymous {} - guest-RAM anon {})",
        parsed.total.anon, parsed.guest_ram.anon
    )
    .unwrap();
    writeln!(
        out,
        "kernel_image_cow: {} KiB   (guest-kernel boot writes inside the libkrunfw mapping)",
        parsed.kernel_cow_anon
    )
    .unwrap();
    writeln!(
        out,
        "framework_private_anon: {framework_private_anon} KiB   (= vmm_private_anon - \
         kernel_image_cow; the VMM library's own per-instance cost)"
    )
    .unwrap();
    writeln!(
        out,
        "file_backed_rss: {} KiB (shareable across instances)",
        rss_file.unwrap_or("-")
    )
    .unwrap();
    writeln!(out).unwrap();

    writeln!(out, "[CPU]").unwrap();
    writeln!(
        out,
        "user: {}s sys: {}s guest: {}s (final sample)",
        samples.last_cpu.0, samples.last_cpu.1, samples.last_cpu.2
    )
    .unwrap();
    writeln!(out, "avg per sample: user {du}s sys {ds}s guest {dg}s").unwrap();
    writeln!(out).unwrap();

    writeln!(out, "[Threads]").unwrap();
    let threads_txt = test_dir.join("threads.txt");
    if fs::metadata(&threads_txt).is_ok_and(|m| m.len() > 0) {
        for line in read_file(&threads_txt).lines() {
            writeln!(out, "  {line}").unwrap();
        }
    } else {
        writeln!(out, "  (not captured)").unwrap();
    }
    writeln!(out).unwrap();

    writeln!(out, "[FDs]").unwrap();
    let fds_txt = test_dir.join("fds.txt");
    if fs::metadata(&fds_txt).is_ok_and(|m| m.len() > 0) {
        writeln!(out, "  {}", classify_fds(&read_file(&fds_txt))).unwrap();
    } else {
        writeln!(out, "  (not captured)").unwrap();
    }
    writeln!(out).unwrap();

    writeln!(out, "[I/O /proc/PID/io]").unwrap();
    for key in ["rchar", "wchar", "read_bytes", "write_bytes"] {
        let value = field(&io, &format!("{key}:")).unwrap_or("-");
        writeln!(out, "{key}: {value}").unwrap();
    }
    writeln!(out).unwrap();

    writeln!(
        out,
        "[Top mappings by RSS]  size_kib rss_kib anon_kib perms label"
    )
    .unwrap();
    let mut by_rss = parsed.maps.clone();
    // sort -k3,3nr: rss descending, ties falling back to the whole line
    // collated ascending (GNU sort's last-resort comparison, unaffected
    // by -r)
    by_rss.sort_by(|a, b| b.rss.cmp(&a.rss).then_with(|| coll_cmp(&a.line, &b.line)));
    for row in by_rss.iter().take(15) {
        writeln!(
            out,
            "  {:>10} {:>10} {:>10}  {:<5}  {}",
            row.size, row.rss, row.anon, row.perms, row.label
        )
        .unwrap();
    }
    writeln!(out).unwrap();

    writeln!(
        out,
        "[Top mappings by Anonymous]  size_kib rss_kib anon_kib perms label"
    )
    .unwrap();
    let mut by_anon = parsed.maps.clone();
    by_anon.sort_by(|a, b| b.anon.cmp(&a.anon).then_with(|| coll_cmp(&a.line, &b.line)));
    for row in by_anon.iter().take(15) {
        writeln!(
            out,
            "  {:>10} {:>10} {:>10}  {:<5}  {}",
            row.size, row.rss, row.anon, row.perms, row.label
        )
        .unwrap();
    }
    writeln!(out).unwrap();

    writeln!(out, "[Category rollup]  rss_kib anon_kib").unwrap();
    for row in &parsed.rollups {
        writeln!(
            out,
            "  {:<14} {:>10} {:>10}",
            row.category, row.rss, row.anon
        )
        .unwrap();
    }

    put(&test_dir.join("summary.txt"), &out);

    let mut metrics = String::new();
    for line in metrics_lines {
        writeln!(metrics, "{line}").unwrap();
    }
    writeln!(metrics, "result={result_word}").unwrap();
    writeln!(metrics, "vmrss_kib={}", vmrss.unwrap_or("-")).unwrap();
    writeln!(metrics, "rss_anon_kib={}", rss_anon.unwrap_or("-")).unwrap();
    if pss.is_some() {
        writeln!(metrics, "uss_kib={uss}").unwrap();
    } else {
        writeln!(metrics, "uss_kib=-").unwrap();
    }
    writeln!(metrics, "pss_kib={}", pss.unwrap_or("-")).unwrap();
    writeln!(metrics, "guest_ram_rss_kib={}", parsed.guest_ram.rss).unwrap();
    writeln!(metrics, "vmm_private_anon_kib={vmm_private_anon}").unwrap();
    writeln!(metrics, "kernel_image_cow_kib={}", parsed.kernel_cow_anon).unwrap();
    writeln!(
        metrics,
        "framework_private_anon_kib={framework_private_anon}"
    )
    .unwrap();
    writeln!(metrics, "vmpte_kib={}", vmpte.unwrap_or("-")).unwrap();
    writeln!(metrics, "threads={}", threads.unwrap_or("-")).unwrap();
    if fs::metadata(&fds_txt).is_ok_and(|m| m.len() > 0) {
        writeln!(metrics, "fds={}", read_file(&fds_txt).lines().count()).unwrap();
    } else {
        writeln!(metrics, "fds=-").unwrap();
    }
    writeln!(metrics, "cpu_user_s={}", samples.last_cpu.0).unwrap();
    writeln!(metrics, "cpu_sys_s={}", samples.last_cpu.1).unwrap();
    writeln!(metrics, "cpu_guest_s={}", samples.last_cpu.2).unwrap();
    put(&test_dir.join("metrics.txt"), &metrics);

    // Verbose annotated memory map, category data and charts.
    if test_dir.join("final-smaps.txt").is_file() {
        if find_in_path("python3").is_some() {
            let totals = Command::new("python3")
                .arg(cfg.home.join("annotate-maps.py"))
                .arg(test_dir)
                .arg("--name")
                .arg(name)
                .arg("--ram-mib")
                .arg(&cfg.knobs.raw.ram_mib)
                .output();
            let totals = totals.ok().filter(|o| o.status.success()).map(|o| {
                String::from_utf8_lossy(&o.stdout)
                    .trim_end_matches('\n')
                    .to_string()
            });
            match totals {
                Some(totals) => {
                    writeln!(out).unwrap();
                    writeln!(out, "[Total memory breakdown]").unwrap();
                    writeln!(out, "{totals}").unwrap();
                    writeln!(out).unwrap();
                    writeln!(
                        out,
                        "Annotated memory map: {}/maps-annotated.txt",
                        test_dir.display()
                    )
                    .unwrap();
                    writeln!(
                        out,
                        "Category data:        {}/categories.csv",
                        test_dir.display()
                    )
                    .unwrap();
                    writeln!(out, "Charts:               {}/charts/", test_dir.display()).unwrap();
                }
                None => {
                    writeln!(
                        out,
                        "(annotate-maps.py failed; run it by hand for the error)"
                    )
                    .unwrap();
                }
            }
            if have_preboot {
                // second pass over the pre-boot snapshot; its stdout totals
                // are already reflected in the phase section above
                let ok = Command::new("python3")
                    .arg(cfg.home.join("annotate-maps.py"))
                    .arg(test_dir)
                    .arg("--name")
                    .arg(format!("{name}-preboot"))
                    .arg("--ram-mib")
                    .arg(&cfg.knobs.raw.ram_mib)
                    .arg("--input-prefix")
                    .arg("preboot-")
                    .arg("--output-prefix")
                    .arg("preboot-")
                    .output()
                    .is_ok_and(|o| o.status.success());
                if !ok {
                    writeln!(
                        out,
                        "(preboot annotate-maps.py failed; run it by hand for the error)"
                    )
                    .unwrap();
                }
            }
        } else {
            writeln!(
                out,
                "(python3 not found — annotated memory map and charts skipped)"
            )
            .unwrap();
        }
        put(&test_dir.join("summary.txt"), &out);
    }
}

/// awk -v ram_kib=... -v launcher=... -f parse-smaps.awk final-smaps.txt
/// → parsed-smaps.tsv. The output file is truncated first: bash's
/// redirect creates it even when awk fails, leaving the partial stdout.
fn run_parse_smaps(cfg: &Config, test_dir: &Path, parsed: &Path) {
    put(parsed, "");
    let output = Command::new("awk")
        .arg("-v")
        .arg(format!("ram_kib={}", cfg.knobs.ram_mib.wrapping_mul(1024)))
        .arg("-v")
        .arg(format!("launcher={}", basename(&cfg.cmd[0])))
        .arg("-f")
        .arg(cfg.home.join("parse-smaps.awk"))
        .arg(test_dir.join("final-smaps.txt"))
        .output();
    if let Ok(output) = output {
        put(parsed, &output.stdout);
    }
}

/// End-of-phase counters printed in the pre-boot block. String fields:
/// they are echoed verbatim, and `${var:-0}` maps empty to 0.
#[derive(Default)]
struct Preboot {
    vmrss: String,
    rss_anon: String,
    rss_file: String,
    pss: String,
    uss: String,
    anon: String,
    pte: String,
    threads: String,
    fds: String,
    samples: String,
    span: String,
}

/// The rows write_summary uses from parse-smaps.awk's output. Fields
/// absent from a line keep the awk-side defaults, like bash's `read`
/// leaving the variables at their initialized values.
#[derive(Default)]
struct ParsedSmaps {
    guest_ram: GuestRam,
    total: Total,
    kernel_cow_anon: i64,
    maps: Vec<MapRow>,
    rollups: Vec<RollupRow>,
}

impl Default for GuestRam {
    fn default() -> Self {
        GuestRam {
            method: "none".to_string(),
            n: "0".to_string(),
            rss: "0".to_string(),
            anon: "0".to_string(),
        }
    }
}

struct GuestRam {
    method: String,
    n: String,
    rss: String,
    anon: String,
}

impl Default for Total {
    fn default() -> Self {
        Total {
            anon: "0".to_string(),
        }
    }
}

/// The TOTAL row of parse-smaps.awk. bash also read its rss/pss/uss/shared
/// columns but never used them; only the anonymous total feeds the
/// vmm_private_anon split.
struct Total {
    anon: String,
}

#[derive(Clone)]
struct MapRow {
    size: i64,
    rss: i64,
    anon: i64,
    perms: String,
    label: String,
    /// whole row: sort's last-resort tiebreak
    line: String,
}

struct RollupRow {
    category: String,
    rss: i64,
    anon: i64,
}

fn parse_smaps_tsv(content: &str) -> ParsedSmaps {
    let mut parsed = ParsedSmaps::default();
    for line in content.lines() {
        let fields: Vec<&str> = line.split('\t').collect();
        let at = |i: usize, default: &str| fields.get(i).copied().unwrap_or(default).to_string();
        match fields.first().copied() {
            Some("MAP") => parsed.maps.push(MapRow {
                size: num(&at(1, "0")),
                rss: num(&at(2, "0")),
                anon: num(&at(3, "0")),
                perms: at(6, ""),
                label: at(7, ""),
                line: line.to_string(),
            }),
            Some("TOTAL") => {
                parsed.total = Total { anon: at(2, "0") };
            }
            Some("GUESTRAM") => {
                parsed.guest_ram = GuestRam {
                    method: at(1, "none"),
                    n: at(2, "0"),
                    rss: at(3, "0"),
                    anon: at(4, "0"),
                }
            }
            Some("KERNELCOW") => parsed.kernel_cow_anon = num(&at(1, "0")),
            Some("ROLLUP") => parsed.rollups.push(RollupRow {
                category: at(1, ""),
                rss: num(&at(2, "0")),
                anon: num(&at(3, "0")),
            }),
            _ => {}
        }
    }
    parsed
}

/// samples.csv body: row count, span (first field of the last row) and
/// the CPU columns of the first and last rows. The no-rows defaults match
/// bash's locals ("0"); a truncated row keeps its empty fields.
struct Samples {
    n: usize,
    span_s: String,
    first_cpu: Cpu,
    last_cpu: Cpu,
}

struct Cpu(String, String, String);

fn read_samples(path: &Path) -> Samples {
    let rows = csv_rows(path);
    match (rows.first(), rows.last()) {
        (Some(first), Some(last)) => Samples {
            n: rows.len(),
            span_s: csv_field(last, 0),
            first_cpu: row_cpu(first),
            last_cpu: row_cpu(last),
        },
        _ => Samples {
            n: 0,
            span_s: "0".to_string(),
            first_cpu: Cpu("0".to_string(), "0".to_string(), "0".to_string()),
            last_cpu: Cpu("0".to_string(), "0".to_string(), "0".to_string()),
        },
    }
}

fn row_cpu(row: &[String]) -> Cpu {
    Cpu(csv_field(row, 10), csv_field(row, 11), csv_field(row, 12))
}

/// Body rows (header skipped) of a samples CSV, split on commas.
fn csv_rows(path: &Path) -> Vec<Vec<String>> {
    read_file(path)
        .lines()
        .skip(1)
        .filter(|line| !line.is_empty())
        .map(|line| line.split(',').map(str::to_string).collect())
        .collect()
}

fn csv_field(row: &[String], i: usize) -> String {
    row.get(i).cloned().unwrap_or_default()
}

/// bash's write_run_summary: the run-level comparison table.
pub fn write_run_summary(cfg: &Config, completed: &[String]) {
    let mut out = String::new();
    writeln!(
        out,
        "# libkrun resource audit — {}",
        basename(&cfg.results_dir.to_string_lossy())
    )
    .unwrap();
    writeln!(out).unwrap();
    writeln!(
        out,
        "Memory values in KiB, CPU in seconds. Per-test details in <test>/summary.txt,"
    )
    .unwrap();
    writeln!(
        out,
        "run metadata in meta.txt, raw samples in <test>/samples.csv."
    )
    .unwrap();
    writeln!(out).unwrap();
    writeln!(
        out,
        "| test | ram | RSS | RssAnon | USS | PSS | guest_ram_rss | vmm_private_anon \
         | framework_private_anon | VmPTE | threads | fds | cpu_user_s | cpu_sys_s \
         | cpu_guest_s | result |"
    )
    .unwrap();
    writeln!(
        out,
        "|------|-----|-----|---------|-----|-----|---------------|------------------|\
         -----------------------|-------|---------|-----|------------|------------|\
         --------------|--------|"
    )
    .unwrap();
    for name in completed {
        let metrics = cfg.results_dir.join(name).join("metrics.txt");
        if metrics.is_file() {
            writeln!(out, "| {name} | {} |", metrics_row(&metrics)).unwrap();
        } else {
            writeln!(
                out,
                "| {name} | - | - | - | - | - | - | - | - | - | - | - | - | - | - | not run |"
            )
            .unwrap();
        }
    }
    let path = cfg.results_dir.join("summary.md");
    put(&path, &out);
    println!("run summary: {}", path.display());
}

/// The 15 metric columns of a summary.md row, read from metrics.txt;
/// missing or empty keys render as "-".
fn metrics_row(metrics: &Path) -> String {
    const KEYS: [&str; 15] = [
        "ram_mib",
        "vmrss_kib",
        "rss_anon_kib",
        "uss_kib",
        "pss_kib",
        "guest_ram_rss_kib",
        "vmm_private_anon_kib",
        "framework_private_anon_kib",
        "vmpte_kib",
        "threads",
        "fds",
        "cpu_user_s",
        "cpu_sys_s",
        "cpu_guest_s",
        "result",
    ];
    let values: Vec<(String, String)> = read_file(metrics)
        .lines()
        .filter_map(|line| {
            line.split_once('=')
                .map(|(k, v)| (k.to_string(), v.to_string()))
        })
        .filter(|(k, _)| KEYS.contains(&k.as_str()))
        .collect();
    let val = |k: &str| -> String {
        for (key, value) in &values {
            if key == k && !value.is_empty() {
                return value.clone();
            }
        }
        "-".to_string()
    };
    KEYS.map(val).join(" | ")
}

/// bash's write_meta: host, resolved library paths, build commands,
/// timing and the kernel-config note.
pub fn write_meta(cfg: &Config, builds: &Builds) {
    let (anon_labels, anon_source) = config_anon_vma_name(cfg);
    let uts = uname();
    let mut out = String::new();
    writeln!(out, "date: {}", date_is()).unwrap();
    writeln!(
        out,
        "host: {} {} ({})",
        uts.sysname, uts.release, uts.machine
    )
    .unwrap();
    writeln!(out, "MemTotal: {}", memtotal()).unwrap();
    writeln!(out, "CLK_TCK: {}", cfg.clk_tck).unwrap();
    writeln!(
        out,
        "libkrun: {}",
        readlink_f(&format!("{}/libkrun.so.2", cfg.libdir))
    )
    .unwrap();
    writeln!(
        out,
        "libkrun_init: {}",
        readlink_f(&format!("{}/libkrun_init.so.0", cfg.libdir))
    )
    .unwrap();
    writeln!(
        out,
        "libkrunfw (dlopened by soname libkrunfw.so.5): {}",
        readlink_f(&format!("{}/libkrunfw.so.5", cfg.libdir))
    )
    .unwrap();
    writeln!(
        out,
        "libkrunfw resolution: LD_LIBRARY_PATH lists KRUN_AUDIT_EXTRA_LD_PATH entries"
    )
    .unwrap();
    writeln!(
        out,
        "  first, then {} — an alternative libkrunfw.so.5 build placed earlier wins.",
        cfg.libdir
    )
    .unwrap();
    let shim = |cmd: &Option<String>| {
        cmd.clone()
            .unwrap_or_else(|| "cached from previous run".to_string())
    };
    writeln!(out, "mmap-label shim: {}", shim(&builds.label_shim)).unwrap();
    writeln!(out, "phase-hook shim: {}", shim(&builds.phase_hook)).unwrap();
    writeln!(
        out,
        "settle={}s duration={}s interval={}s",
        cfg.knobs.raw.settle, cfg.knobs.raw.duration, cfg.knobs.raw.interval
    )
    .unwrap();
    writeln!(
        out,
        "CONFIG_ANON_VMA_NAME: {anon_labels} ({anon_source}) — glibc's"
    )
    .unwrap();
    writeln!(
        out,
        "  GLIBC_TUNABLES=glibc.mem.decorate_maps=1 labels and the label_mmap shim both"
    )
    .unwrap();
    writeln!(
        out,
        "  depend on it; without it anonymous mappings carry no [anon:...] labels in smaps"
    )
    .unwrap();
    writeln!(
        out,
        "  and guest RAM is identified by size only (see parse-smaps.awk)."
    )
    .unwrap();
    writeln!(out, "vma probe build: {}", shim(&builds.vma_probe)).unwrap();
    put(&cfg.results_dir.join("meta.txt"), &out);
}

/// CONFIG_ANON_VMA_NAME determination for meta.txt: functional probe
/// first (neither /boot/config-$(uname -r) nor /proc/config.gz is
/// guaranteed to exist on custom kernels), then the config files.
fn config_anon_vma_name(cfg: &Config) -> (String, String) {
    if executable(&cfg.vma_probe) {
        let ok = Command::new(&cfg.vma_probe)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success());
        return (
            (if ok { "yes" } else { "no" }).to_string(),
            "functional probe".to_string(),
        );
    }
    let kconfig = format!("/boot/config-{}", uname().release);
    if readable(&kconfig) {
        let found = read_file(Path::new(&kconfig))
            .lines()
            .any(|line| line.starts_with("CONFIG_ANON_VMA_NAME=y"));
        return (
            (if found { "yes" } else { "no" }).to_string(),
            "config file".to_string(),
        );
    }
    if readable("/proc/config.gz") {
        // gzip -cd | grep: the pipeline only succeeds when both do
        let found = Command::new("gzip")
            .args(["-cd", "/proc/config.gz"])
            .output()
            .is_ok_and(|o| {
                o.status.success()
                    && String::from_utf8_lossy(&o.stdout)
                        .lines()
                        .any(|line| line.starts_with("CONFIG_ANON_VMA_NAME=y"))
            });
        return (
            (if found { "yes" } else { "no" }).to_string(),
            "config file".to_string(),
        );
    }
    ("unknown".to_string(), "config file".to_string())
}

fn uname() -> Utsname {
    unsafe {
        let mut uts: libc::utsname = std::mem::zeroed();
        if libc::uname(&mut uts) != 0 {
            return Utsname::default();
        }
        let field = |f: &[libc::c_char]| {
            let bytes: Vec<u8> = f
                .iter()
                .take_while(|&&c| c != 0)
                .map(|&c| c as u8)
                .collect();
            String::from_utf8_lossy(&bytes).into_owned()
        };
        Utsname {
            sysname: field(&uts.sysname),
            release: field(&uts.release),
            machine: field(&uts.machine),
        }
    }
}

#[derive(Default)]
struct Utsname {
    sysname: String,
    release: String,
    machine: String,
}

/// date -Is, exactly as the shell formats it.
fn date_is() -> String {
    Command::new("date")
        .arg("-Is")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}

fn memtotal() -> String {
    for line in read_file(Path::new("/proc/meminfo")).lines() {
        if line.starts_with("MemTotal:") {
            let mut fields = line.split_whitespace();
            fields.next();
            return format!(
                "{} {}",
                fields.next().unwrap_or(""),
                fields.next().unwrap_or("")
            );
        }
    }
    String::new()
}

/// command -v: an executable file by that name somewhere on PATH.
fn find_in_path(program: &str) -> Option<PathBuf> {
    let path = env::var("PATH").ok()?;
    for dir in path.split(':') {
        let dir = if dir.is_empty() { "." } else { dir };
        let candidate = Path::new(dir).join(program);
        if let Ok(meta) = fs::metadata(&candidate)
            && meta.is_file()
            && meta.permissions().mode() & 0o111 != 0
        {
            return Some(candidate);
        }
    }
    None
}

/// bash's [[ -x ]]
fn executable(path: &Path) -> bool {
    fs::metadata(path).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

/// bash's [[ -r ]]
fn readable(path: &str) -> bool {
    match std::ffi::CString::new(path) {
        Ok(p) => unsafe { libc::access(p.as_ptr(), libc::R_OK) == 0 },
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_fds_sorts_classes_with_total_last() {
        let fds = "0 /dev/null\n\
                    3 /dev/kvm\n\
                    4 anon_inode:kvm-vcpu:0\n\
                    5 socket:[123]\n\
                    6 pipe:[456]\n\
                    7 /memfd:foo (deleted)\n\
                    8 anon_inode:[io_uring]\n\
                    9 /usr/lib/x.so\n\
                    10 somethingelse\n";
        assert_eq!(
            classify_fds(fds),
            "/dev/kvm=1, anon_inode:io_uring=1, anon_inode:kvm-*=1, file=2, memfd=1, \
             other=1, pipe=1, socket=1, total=9"
        );
    }

    #[test]
    fn classify_fds_empty_input_is_total_zero() {
        assert_eq!(classify_fds(""), "total=0");
    }

    #[test]
    fn quote_safe_tokens_stay_raw_and_others_get_single_quoted() {
        assert_eq!(shell_quote("sh"), "sh");
        assert_eq!(shell_quote("-c"), "-c");
        assert_eq!(
            shell_quote("a+b.c,d:e@f%g/h=i-j_k"),
            "a+b.c,d:e@f%g/h=i-j_k"
        );
        assert_eq!(shell_quote("echo hi"), "'echo hi'");
        assert_eq!(shell_quote("a'b"), "'a'\\''b'");
        assert_eq!(shell_quote(""), "''");
        assert_eq!(shell_quote("hi!"), "'hi!'");
    }

    #[test]
    fn krun_lib_match_spans_later_occurrences_too() {
        assert!(is_krun_lib("/usr/local/lib64/libkrun.so.2"));
        assert!(is_krun_lib("/usr/local/lib64/libkrunfw.so.5"));
        assert!(is_krun_lib("/x/libkruna/y/libkrunb.so"));
        assert!(!is_krun_lib("/usr/lib64/libc.so.6"));
        assert!(!is_krun_lib("/libkrun/sub/dir.so"));
        assert!(!is_krun_lib("libkrun.so"));
    }

    #[test]
    fn signed_kib_never_renders_plus_minus() {
        assert_eq!(signed_kib(5), "+5");
        assert_eq!(signed_kib(0), "+0");
        assert_eq!(signed_kib(-5), "-5");
    }

    #[test]
    fn smaps_tsv_defaults_and_rows() {
        let parsed = parse_smaps_tsv(
            "MAP\t1024\t512\t256\t300\t400\trw-p\t/usr/lib/libkrun.so.2\n\
             MAP\t2048\t512\t100\t1\t1\trw-p\t[anon]\n\
             TOTAL\t1024\t356\t301\t401\t100\n\
             GUESTRAM\texact-size match\t1\t512\t256\n\
             KERNELCOW\t16384\n\
             ROLLUP\tguest-RAM\t512\t256\n\
             ROLLUP\tsystem-libs\t200\t50\n",
        );
        assert_eq!(parsed.total.anon, "356");
        assert_eq!(parsed.guest_ram.method, "exact-size match");
        assert_eq!(parsed.kernel_cow_anon, 16384);
        assert_eq!(parsed.maps.len(), 2);
        assert_eq!(parsed.maps[0].label, "/usr/lib/libkrun.so.2");
        assert_eq!(parsed.maps[1].perms, "rw-p");
        assert_eq!(parsed.rollups.len(), 2);
        assert_eq!(parsed.rollups[0].category, "guest-RAM");

        // top-by-rss: equal rss falls back to the whole line, collated
        let mut by_rss = parsed.maps.clone();
        by_rss.sort_by(|a, b| b.rss.cmp(&a.rss).then_with(|| coll_cmp(&a.line, &b.line)));
        assert_eq!(by_rss[0].label, "/usr/lib/libkrun.so.2");

        let parsed = parse_smaps_tsv("");
        assert_eq!(parsed.guest_ram.method, "none");
        assert_eq!(parsed.guest_ram.rss, "0");
        assert_eq!(parsed.kernel_cow_anon, 0);
    }
}
