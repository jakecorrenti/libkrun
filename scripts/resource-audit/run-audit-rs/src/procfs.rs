//! /proc readers for the measurement core: aliveness, per-interval
//! sampling, fd/thread listings and snapshot copies. Every read is
//! best-effort — the audited process can die at any moment, and all the
//! consumers are prepared for missing data.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

/// kill(pid, 0) succeeds for a zombie too, so the state letter decides: a
/// zombie has no memory left to sample.
pub fn proc_alive(pid: i32) -> bool {
    if unsafe { libc::kill(pid, 0) } != 0 {
        return false;
    }
    let stat = read_file(&proc(pid, "stat"));
    state_letter(&stat).is_some_and(|state| state != "Z")
}

/// State letter of /proc/PID/stat: the first field after the LAST ')' —
/// comm can contain spaces and parentheses.
fn state_letter(stat: &str) -> Option<&str> {
    stat.rsplit_once(')')?.1.split_whitespace().next()
}

/// utime/stime/guest_time (stat fields 14/15/43) converted with CLK_TCK.
/// Parsing happens after the closing parenthesis of comm, which shifts the
/// remaining fields down by two; missing fields count as 0, like awk's
/// uninitialized variables.
fn cpu_seconds(stat: &str, clk_tck: i64) -> (f64, f64, f64) {
    let after_comm = stat.rsplit_once(')').map_or("", |(_, rest)| rest);
    let tick = |i: usize| {
        after_comm
            .split_whitespace()
            .nth(i)
            .and_then(|f| f.parse::<i64>().ok())
            .unwrap_or(0)
    };
    let secs = |ticks: i64| ticks as f64 / clk_tck as f64;
    (secs(tick(11)), secs(tick(12)), secs(tick(40)))
}

fn proc(pid: i32, file: &str) -> PathBuf {
    Path::new("/proc").join(pid.to_string()).join(file)
}

/// File content as lossy text; empty when missing or unreadable — /proc
/// files of a dying process disappear between the checks.
pub fn read_file(path: &Path) -> String {
    fs::read(path)
        .map(|b| String::from_utf8_lossy(&b).into_owned())
        .unwrap_or_default()
}

/// Value from a "Key: value kB" line of a proc file (awk's `$1 == key`):
/// None when absent or empty.
pub fn field<'a>(content: &'a str, key: &str) -> Option<&'a str> {
    content.lines().find_map(|line| {
        let mut fields = line.split_whitespace();
        if fields.next() == Some(key) {
            fields.next()
        } else {
            None
        }
    })
}

/// Entry count of /proc/PID/fd, 0 when unreadable — a plain count
/// tolerates fds appearing or disappearing mid-scan, like bash's find.
pub fn count_fds(pid: i32) -> u64 {
    fs::read_dir(proc(pid, "fd"))
        .map(|entries| entries.filter_map(|e| e.ok()).count() as u64)
        .unwrap_or(0)
}

/// The counters behind one CSV row. A missing VmRSS fails the sample; every
/// other absent field counts as 0, like awk's uninitialized variables.
pub struct ProcSample {
    pub vmrss: u64,
    pub rss_anon: u64,
    pub rss_file: u64,
    pub pss: u64,
    pub uss: u64,
    pub anon: u64,
    pub pte: u64,
    pub threads: u64,
    pub cpu_user_s: f64,
    pub cpu_sys_s: f64,
    pub cpu_guest_s: f64,
}

pub fn read_sample(pid: i32, clk_tck: i64) -> Option<ProcSample> {
    let status = read_file(&proc(pid, "status"));
    let rollup = read_file(&proc(pid, "smaps_rollup"));
    let stat = read_file(&proc(pid, "stat"));
    let (user, sys, guest) = cpu_seconds(&stat, clk_tck);

    // awk fails the sample only when VmRSS is absent
    let vmrss = field(&status, "VmRSS:")?;
    let num = |v: Option<&str>| v.and_then(|s| s.parse().ok()).unwrap_or(0);
    Some(ProcSample {
        vmrss: vmrss.parse().unwrap_or(0),
        rss_anon: num(field(&status, "RssAnon:")),
        rss_file: num(field(&status, "RssFile:")),
        pss: num(field(&rollup, "Pss:")),
        uss: num(field(&rollup, "Private_Clean:")) + num(field(&rollup, "Private_Dirty:")),
        anon: num(field(&rollup, "Anonymous:")),
        pte: num(field(&status, "VmPTE:")),
        threads: num(field(&status, "Threads:")),
        cpu_user_s: user,
        cpu_sys_s: sys,
        cpu_guest_s: guest,
    })
}

/// The CSV row: bash's printf "%.1f,%d,...,%.2f,%.2f,%.2f", with `elapsed`
/// already formatted to one decimal (bash's elapsed_between).
pub fn csv_row(elapsed: &str, sample: &ProcSample, fds: u64) -> String {
    format!(
        "{elapsed},{},{},{},{},{},{},{},{},{},{:.2},{:.2},{:.2}\n",
        sample.vmrss,
        sample.rss_anon,
        sample.rss_file,
        sample.pss,
        sample.uss,
        sample.anon,
        sample.pte,
        sample.threads,
        fds,
        sample.cpu_user_s,
        sample.cpu_sys_s,
        sample.cpu_guest_s
    )
}

/// Writes <prefix>fds.txt, <prefix>threads.txt and <prefix>task-stats.txt.
/// Shared by the live final snapshot and the wrap insurance checkpoint so
/// both paths produce identical listings.
pub fn capture_proc_listings(pid: i32, dir: &Path, prefix: &str) {
    let fd_dir = proc(pid, "fd");
    let mut lines = Vec::new();
    for name in sorted_entries(&fd_dir, |t| t.is_symlink()) {
        let target = fs::read_link(fd_dir.join(&name))
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|_| "(unreadable)".to_string());
        lines.push(format!("{name} {target}"));
    }
    write_lines(&dir.join(format!("{prefix}fds.txt")), &lines);

    let task_dir = proc(pid, "task");
    // threads.txt and task-stats.txt glob /proc/PID/task separately, like
    // the bash's two loops: a thread dying in between shows in one only
    let mut lines = Vec::new();
    for tid in sorted_entries(&task_dir, |t| t.is_dir()) {
        lines.push(format!("{tid} {}", read_comm(&task_dir, &tid)));
    }
    write_lines(&dir.join(format!("{prefix}threads.txt")), &lines);

    let mut lines = Vec::new();
    for tid in sorted_entries(&task_dir, |t| t.is_dir()) {
        // The sp is the user stack pointer from the thread's blocked
        // syscall (/proc/.../syscall, field 8): stat's startstack is
        // mm-wide (the same main-stack value for every thread) and cannot
        // attribute per-thread stacks. Threads not in a syscall report 0.
        let syscall = read_file(&task_dir.join(&tid).join("syscall"));
        let sp = syscall.split_whitespace().nth(7).unwrap_or("0");
        lines.push(format!("{tid} {} {sp}", read_comm(&task_dir, &tid)));
    }
    write_lines(&dir.join(format!("{prefix}task-stats.txt")), &lines);
}

/// Sorted entry names of a /proc directory (bash's glob expansion order),
/// keeping only the wanted entry type.
fn sorted_entries(dir: &Path, want: fn(&fs::FileType) -> bool) -> Vec<String> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut names = Vec::new();
    for entry in entries.flatten() {
        if entry.file_type().is_ok_and(|t| want(&t)) {
            names.push(entry.file_name().to_string_lossy().into_owned());
        }
    }
    names.sort();
    names
}

/// /proc/PID/task/TID/comm with the trailing newlines stripped ($() eats
/// all of them; an unreadable comm becomes empty, leaving a trailing
/// space, exactly like the bash printf).
fn read_comm(task_dir: &Path, tid: &str) -> String {
    read_file(&task_dir.join(tid).join("comm"))
        .trim_end_matches('\n')
        .to_string()
}

/// Create/truncate then write the lines — bash's `: > file` plus appends,
/// so the file exists (possibly empty) even when the process died first.
fn write_lines(path: &Path, lines: &[String]) {
    let mut out = String::new();
    for line in lines {
        out.push_str(line);
        out.push('\n');
    }
    let _ = fs::write(path, out);
}

/// `cat /proc/PID/<file> > dst`: the redirect creates dst first, so it
/// exists (empty) even when the read fails, and whatever the read returned
/// before the process died is kept. The shell-redirect form (not a copy)
/// is deliberate: procfs files are mode 444, and a cp-created copy would
/// inherit that, silently breaking every later write onto it.
pub fn snapshot_proc_file(pid: i32, file: &str, dst: &Path) {
    let mut content = Vec::new();
    if let Ok(mut src) = fs::File::open(proc(pid, file)) {
        let _ = src.read_to_end(&mut content);
    }
    let _ = fs::write(dst, &content);
}

/// `cp /proc/PID/<file> dst`: only created when the source reads, and the
/// copy inherits the source's permission bits (procfs's 444).
fn cp_proc_file(pid: i32, file: &str, dst: &Path) {
    let Ok(content) = fs::read(proc(pid, file)) else {
        return;
    };
    if fs::write(dst, &content).is_err() {
        return;
    }
    if let Ok(mode) = fs::metadata(proc(pid, file)) {
        let _ = fs::set_permissions(dst, mode.permissions());
    }
}

/// bash's take_final_snapshot: the live final-* set, the unprefixed
/// listings and the library report.
pub fn take_final_snapshot(pid: i32, dir: &Path, binary: &str, ld_path: &str) {
    for file in ["status", "smaps", "smaps_rollup", "maps", "io"] {
        cp_proc_file(pid, file, &dir.join(format!("final-{file}.txt")));
    }
    capture_proc_listings(pid, dir, "");
    crate::report::write_libs_txt(
        binary,
        &dir.join("final-maps.txt"),
        "the wrapped launcher",
        dir,
        ld_path,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_reads_key_value_kb_lines() {
        let status = "Name:\tbash\nVmRSS:\t  1234 kB\nRssAnon: 500 kB\nThreads:\t3\n";
        assert_eq!(field(status, "VmRSS:"), Some("1234"));
        assert_eq!(field(status, "RssAnon:"), Some("500"));
        assert_eq!(field(status, "Threads:"), Some("3"));
        assert_eq!(field(status, "VmPeak:"), None);
        assert_eq!(field(status, "Rss:"), None);
    }

    #[test]
    fn state_letter_after_a_comm_full_of_spaces_and_parens() {
        let stat = "42 (a (weird) comm) R 1 2 3";
        assert_eq!(state_letter(stat), Some("R"));
        assert_eq!(state_letter("42 (zombie) Z 1"), Some("Z"));
        assert_eq!(state_letter(""), None);
        assert_eq!(state_letter("no parens at all"), None);
    }

    #[test]
    fn cpu_seconds_skips_the_whole_comm_field() {
        // fields 14/15/43 of stat = 12th/13th/41st after "pid (comm) "
        let tail: Vec<&str> = (1..=41)
            .map(|i| match i {
                12 => "100",
                13 => "200",
                41 => "300",
                _ => "0",
            })
            .collect();
        let stat = format!("42 (a (weird) comm) {}", tail.join(" "));
        assert_eq!(cpu_seconds(&stat, 100), (1.0, 2.0, 3.0));
        // a missing stat file reads as zero CPU, not a failure
        assert_eq!(cpu_seconds("", 100), (0.0, 0.0, 0.0));
    }

    #[test]
    fn csv_row_matches_the_bash_printf() {
        let sample = ProcSample {
            vmrss: 1234,
            rss_anon: 500,
            rss_file: 700,
            pss: 900,
            uss: 800,
            anon: 510,
            pte: 40,
            threads: 3,
            cpu_user_s: 0.01,
            cpu_sys_s: 0.02,
            cpu_guest_s: 0.0,
        };
        assert_eq!(
            csv_row("2.5", &sample, 7),
            "2.5,1234,500,700,900,800,510,40,3,7,0.01,0.02,0.00\n"
        );
    }
}
