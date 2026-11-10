//! The measurement run: spawn the wrapped launcher, poll /proc from outside
//! until it exits, reaches the readiness marker or runs out of budget,
//! capture the peak-RSS insurance checkpoints along the way, then tear it
//! down. The loop structure and ordering follow run-audit.sh exactly —
//! several of the orderings are load-bearing (see the comments).

use std::fs::{self, File};
use std::io::Write;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio, exit};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::procfs;
use crate::report;
use crate::{Config, die, put};

const CSV_HEADER: &str = "elapsed_s,vmrss_kib,rss_anon_kib,rss_file_kib,pss_kib,uss_kib,anon_kib,pte_kib,threads,fds,cpu_user_s,cpu_sys_s,cpu_guest_s";

const PHASE_MARKER: &str = "AUDIT_PHASE_VMM_BUILT";
const READY_MARKER: &str = "AUDIT_GUEST_READY";

/// Set by the SIGINT/SIGTERM handler; the poll loop and the sampling
/// windows check it between iterations and shut the run down.
static TERMINATED: AtomicBool = AtomicBool::new(false);
/// The wrapped launcher's pid, cleared once reaped: the signal path must
/// not kill a pid that may have been recycled (bash cleared CURRENT_PID).
static CHILD_PID: AtomicI32 = AtomicI32::new(0);

extern "C" fn on_signal(_sig: libc::c_int) {
    TERMINATED.store(true, Ordering::Relaxed);
}

pub fn install_signal_handlers() {
    // through a pointer first: a direct fn-item-to-integer cast is warned
    // against by recent compilers
    let handler = on_signal as *const () as libc::sighandler_t;
    unsafe {
        libc::signal(libc::SIGINT, handler);
        libc::signal(libc::SIGTERM, handler);
    }
}

/// bash's signal trap: CONT first (a stopped process pockets TERM), TERM,
/// half a second, KILL — then exit 130 without waiting for the reap.
fn die_from_signal() -> ! {
    let pid = CHILD_PID.load(Ordering::Relaxed);
    if pid != 0 && unsafe { libc::kill(pid, 0) } == 0 {
        unsafe {
            libc::kill(pid, libc::SIGCONT);
            libc::kill(pid, libc::SIGTERM);
        }
        thread::sleep(Duration::from_millis(500));
        unsafe { libc::kill(pid, libc::SIGKILL) };
    }
    exit(130);
}

fn check_terminated() {
    if TERMINATED.load(Ordering::Relaxed) {
        die_from_signal();
    }
}

/// EPOCHREALTIME equivalent: seconds since the epoch as f64.
fn now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

pub fn run_wrap(cfg: &Config) -> bool {
    WrapRun::new(cfg).run()
}

/// State of one measured run. The bash original kept the capture-step
/// variables in globals shared with the poll loop through dynamic scoping;
/// here they are fields of the run.
struct WrapRun<'a> {
    cfg: &'a Config,
    vm_pid: i32,
    child: Option<Child>,
    test_dir: PathBuf,
    console_log: PathBuf,
    launch_time: f64,
    ld_path: String,
    // checkpoint state shared between capture_step and the poll loop
    best_rss: u64,
    best_at: String,
    cp_rss: Option<u64>,
    cp_threads: String,
    list_threads: String,
    list_fds: String,
    sample_rss: u64,
    sample_fds: u64,
}

impl<'a> WrapRun<'a> {
    fn new(cfg: &'a Config) -> WrapRun<'a> {
        let test_dir = cfg.results_dir.join(&cfg.name);
        fs::create_dir_all(&test_dir)
            .unwrap_or_else(|e| die(&format!("cannot create {}: {e}", test_dir.display())));

        let ld_path = match &cfg.extra_ld {
            Some(extra) => format!("{extra}:{}", cfg.libdir),
            None => cfg.libdir.clone(),
        };
        // The phase hook is always preloaded: without KRUN_AUDIT_PHASE_PAUSE
        // it is a pass-through, and launchers that never call krun_vmm_run()
        // skip it.
        let preload = if cfg.labels {
            format!("{}:{}", cfg.phase_hook.display(), cfg.label_shim.display())
        } else {
            cfg.phase_hook.display().to_string()
        };

        report::write_cmd_txt(cfg, &test_dir, &ld_path, &preload);

        let console_log = test_dir.join("guest-console.log");
        // Spawn through env exactly like the bash's `env ... </dev/null
        // >log 2>&1`: env applies the overrides and execs COMMAND, so a
        // missing binary makes env exit 127 with the error on the console
        // instead of failing the driver. No chdir either: the wrapped
        // command's relative paths resolve from the caller's cwd, like a
        // manual invocation.
        let log = File::create(&console_log)
            .unwrap_or_else(|e| die(&format!("cannot create {}: {e}", console_log.display())));
        let log_err = log
            .try_clone()
            .unwrap_or_else(|e| die(&format!("cannot duplicate {}: {e}", console_log.display())));
        let child = Command::new("env")
            .arg(format!("LD_LIBRARY_PATH={ld_path}"))
            .arg("GLIBC_TUNABLES=glibc.mem.decorate_maps=1")
            .arg(format!("LD_PRELOAD={preload}"))
            .arg(format!(
                "KRUN_AUDIT_PHASE_PAUSE={}",
                cfg.knobs.raw.phase_pause
            ))
            .args(&cfg.cmd)
            .stdin(Stdio::null())
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(log_err))
            .spawn()
            .unwrap_or_else(|e| die(&format!("cannot spawn {}: {e}", cfg.cmd[0])));

        let vm_pid = child.id() as i32;
        CHILD_PID.store(vm_pid, Ordering::Relaxed);

        WrapRun {
            cfg,
            vm_pid,
            child: Some(child),
            test_dir,
            console_log,
            launch_time: now(),
            ld_path,
            best_rss: 0,
            best_at: "0".to_string(),
            cp_rss: None,
            cp_threads: String::new(),
            list_threads: String::new(),
            list_fds: String::new(),
            sample_rss: 0,
            sample_fds: 0,
        }
    }

    fn run(mut self) -> bool {
        let samples_csv = self.test_dir.join("samples.csv");
        put(&samples_csv, format!("{CSV_HEADER}\n"));

        // One fast-poll loop covers the whole run: it samples into
        // samples.csv and captures an insurance snapshot set from launch
        // until the readiness marker or process exit. When the VMM-built
        // marker appears (launcher calls krun_vmm_run() through the PLT),
        // sampling switches to samples-preboot.csv for the pause window and
        // comes back afterwards — so launchers that never emit it, or die
        // before emitting it, still get a fully sampled run.
        let run_start = now();
        let mut budget_start = run_start;
        let budget = self.cfg.knobs.settle + self.cfg.knobs.duration as f64;
        let mut ready_after = String::new();
        let mut ready_seen = false;
        let mut exited = false;
        let mut phase_done = false;
        // After the pre-boot phase returns (~1s before the pause ends),
        // poll at tight cadence: the post-pause transition (event loop
        // spin-up, workload peak, teardown, exit) is often a ~30-100ms
        // window that a 0.1s grid can step over entirely. Covers the
        // margin plus the transition itself.
        let mut poll_sleep = 0.1;
        let mut tight_from = 0.0;
        let mut prev_rss = 0;

        loop {
            check_terminated();
            if !procfs::proc_alive(self.vm_pid) {
                exited = true;
                break;
            }
            if self.cfg.knobs.phase_pause > 0 && !phase_done && self.log_contains(PHASE_MARKER) {
                phase_done = true;
                self.sample_preboot_window(&mut exited);
                if exited {
                    break;
                }
                // the guest only starts executing when the pause window
                // closes
                budget_start = now();
                poll_sleep = 0.01;
                tight_from = now();
                continue;
            }
            if self.log_contains(READY_MARKER) {
                ready_seen = true;
                ready_after = format!("{:.1}", now() - self.launch_time);
                break;
            }
            // Capture before sample_once: its /proc walks take ~15ms, and
            // the peak window sits at the very end of short runs — sampling
            // first would risk losing the capture to a mid-sample death.
            self.capture_step();
            self.sample_once(&samples_csv, run_start);

            self.rise_chase(&samples_csv, run_start, phase_done, &mut prev_rss);
            prev_rss = self.cp_rss.unwrap_or(0);
            if now() - budget_start >= budget {
                break;
            }
            if poll_sleep != 0.1 && now() - tight_from >= 2.5 {
                poll_sleep = 0.1;
            }
            thread::sleep(Duration::from_secs_f64(poll_sleep));
        }

        let result_line = if exited {
            self.finish_exited()
        } else if ready_seen {
            self.finish_ready(ready_after, &samples_csv, run_start)
        } else {
            self.finish_no_marker()
        };

        // the scratch and checkpoint sets are per-run
        self.remove_scratch();

        let mut config_label = self.cfg.cmd.join(" ");
        if self.cfg.knobs.ram_mib > 0 {
            config_label.push_str(&format!(" (ram_mib={})", self.cfg.knobs.raw.ram_mib));
        }
        report::write_summary(
            self.cfg,
            &self.test_dir,
            &config_label,
            &result_line,
            &[format!("ram_mib={}", self.cfg.knobs.raw.ram_mib)],
        );

        if result_line.split(" (").next() == Some("OK") {
            println!("  {}: {}/summary.txt", result_line, self.test_dir.display());
            true
        } else {
            let reason = result_line
                .strip_prefix("FAILED (")
                .and_then(|r| r.strip_suffix(')'))
                .unwrap_or(result_line.as_str());
            println!("  FAILED: {reason}");
            false
        }
    }

    /// The pre-boot sampling window: samples-preboot.csv rows at the
    /// interval, then the preboot-* snapshot when the process survives.
    fn sample_preboot_window(&mut self, exited: &mut bool) {
        let preboot_csv = self.test_dir.join("samples-preboot.csv");
        put(&preboot_csv, format!("{CSV_HEADER}\n"));
        let preboot_start = now();
        let n = ((self.cfg.knobs.phase_pause - 1) / self.cfg.knobs.interval).max(1);
        let mut ok = true;
        for i in 0..n {
            check_terminated();
            if !self.sample_once(&preboot_csv, preboot_start) {
                *exited = true;
                ok = false;
                break;
            }
            if i < n - 1 {
                thread::sleep(Duration::from_secs(self.cfg.knobs.interval));
            }
        }
        if ok && procfs::proc_alive(self.vm_pid) {
            for file in ["status", "smaps", "maps", "io"] {
                procfs::snapshot_proc_file(
                    self.vm_pid,
                    file,
                    &self.test_dir.join(format!("preboot-{file}.txt")),
                );
            }
        }
    }

    /// bash's sample_once: append one CSV row, updating sample_rss and
    /// sample_fds (bash's SAMPLE_RSS / SAMPLE_FDS globals) that the chase
    /// and the listing refresh compare against. False when the sample
    /// failed.
    fn sample_once(&mut self, csv: &Path, start: f64) -> bool {
        if !procfs::proc_alive(self.vm_pid) {
            return false;
        }
        let fds = procfs::count_fds(self.vm_pid);
        self.sample_fds = fds;
        let elapsed = format!("{:.1}", now() - start);
        let Some(sample) = procfs::read_sample(self.vm_pid, self.cfg.clk_tck) else {
            return false;
        };
        append(csv, &procfs::csv_row(&elapsed, &sample, fds));
        // the rise-chase compares against this: a rise can start in the
        // ~15ms between the checkpoint capture and this read
        self.sample_rss = sample.vmrss;
        true
    }

    /// Chase a rising RSS at tight cadence: transitions (the event loop
    /// spinning up after the phase pause, a workload's peak) are shorter
    /// than the 0.1s grid and often end in the process exiting, which
    /// would leave the peak uncaptured. Follow the rise until it settles,
    /// drops (teardown) or the process dies. The step cap bounds a long
    /// ramp; the plateau never triggers a chase.
    fn rise_chase(
        &mut self,
        samples_csv: &Path,
        run_start: f64,
        phase_done: bool,
        prev_rss: &mut u64,
    ) {
        let mut chase_steps = 0;
        while procfs::proc_alive(self.vm_pid)
            && self
                .cp_rss
                .is_some_and(|rss| rss > *prev_rss || self.sample_rss > *prev_rss)
            && chase_steps < 100
            && !self.chase_blocked(phase_done)
        {
            if let Some(rss) = self.cp_rss {
                *prev_rss = rss;
            }
            chase_steps += 1;
            // Freeze for the capture: a rising-RSS transition often ends
            // in the process exiting within tens of milliseconds, and
            // even a living process advances between the five file reads
            // (several MB/s of skew during the spin-up). A frozen process
            // can do neither — the checkpoint and its sample row are an
            // exact point-in-time pair. The ~20ms stall is invisible to
            // the metrics (nothing advances while stopped).
            if unsafe { libc::kill(self.vm_pid, libc::SIGSTOP) } != 0 {
                break;
            }
            self.capture_step();
            self.sample_once(samples_csv, run_start);
            unsafe { libc::kill(self.vm_pid, libc::SIGCONT) };
            if !procfs::proc_alive(self.vm_pid) {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    /// The chase is blocked only while the pre-boot phase is still pending
    /// (the marker stays in the log forever, so testing for it alone would
    /// disable the chase for the whole post-marker run).
    fn chase_blocked(&self, phase_done: bool) -> bool {
        !phase_done && self.log_contains(PHASE_MARKER)
    }

    /// bash's wrap_capture_step: one insurance capture. cp-* is the
    /// per-iteration scratch set; best-* is the peak-RSS checkpoint (>=,
    /// so a flat-at-peak run keeps it fresh) promoted to final-* when the
    /// process exits before a live snapshot can be taken.
    fn capture_step(&mut self) {
        // status is written LAST on purpose: the peak iteration is often
        // also the death iteration, and a mid-loop death truncates the
        // files after it. A non-empty cp-status therefore proves the whole
        // set was read from a living process; an empty one makes cp_rss
        // None and the set is never promoted, leaving the previous
        // complete checkpoint in best-*.
        for file in ["smaps", "smaps_rollup", "maps", "io", "status"] {
            procfs::snapshot_proc_file(self.vm_pid, file, &self.cp_path(file));
        }
        let cp_status = procfs::read_file(&self.cp_path("status"));
        self.cp_rss = procfs::field(&cp_status, "VmRSS:").and_then(|v| v.parse().ok());
        self.cp_threads = procfs::field(&cp_status, "Threads:")
            .unwrap_or("")
            .to_string();

        // The fd/thread listings cost ~15ms (a readlink per fd), so
        // refresh them only when something plausibly changed: first
        // iteration, a thread- or fd-count change, or a strict RSS
        // increase. A post-teardown collapse changes the counts too, but
        // its low RSS can never reach the promotion below, so the
        // collapsed listings are simply overwritten scratch.
        let refresh = !self.cp_path("fds").is_file()
            || self.cp_threads != self.list_threads
            || self.sample_fds.to_string() != self.list_fds
            || self.cp_rss.is_some_and(|rss| rss > self.best_rss);
        if refresh {
            procfs::capture_proc_listings(self.vm_pid, &self.test_dir, "cp-");
            self.list_threads = self.cp_threads.clone();
            self.list_fds = self.sample_fds.to_string();
            // A process can die mid-capture (the peak iteration is often
            // the last), leaving truncated listings; the status read that
            // armed this refresh happened before the death. Only a capture
            // of a still-living process may reach best-*, so the previous
            // good listing survives as the near-peak one.
            if !procfs::proc_alive(self.vm_pid) {
                for file in ["fds", "threads", "task-stats"] {
                    let _ = fs::remove_file(self.cp_path(file));
                }
            }
        }

        if self.cp_rss.is_some_and(|rss| rss >= self.best_rss) {
            self.best_rss = self.cp_rss.unwrap_or(0);
            self.best_at = format!("{:.1}", now() - self.launch_time);
            // non-empty files only: never let a truncated read through,
            // even though the status-last ordering already gates the set
            // on completeness
            for file in [
                "status",
                "smaps",
                "smaps_rollup",
                "maps",
                "io",
                "fds",
                "threads",
                "task-stats",
            ] {
                let (src, dst) = (self.cp_path(file), self.best_path(file));
                if fs::metadata(&src).is_ok_and(|m| m.len() > 0) {
                    let _ = fs::write(&dst, fs::read(&src).unwrap_or_default());
                }
            }
        }
    }

    /// Binary-safe marker search over the growing console log, re-read on
    /// every call (bash's grep -aFq). The markers are plain ASCII, which
    /// the lossy decode passes through untouched, so no match can be
    /// invented or destroyed.
    fn log_contains(&self, marker: &str) -> bool {
        match fs::read(&self.console_log) {
            Ok(bytes) => String::from_utf8_lossy(&bytes).contains(marker),
            Err(_) => false,
        }
    }

    /// COMPLETE: the launcher ran to completion; reap it, promote the peak
    /// checkpoint when no live snapshot exists, report its exit code.
    fn finish_exited(&mut self) -> String {
        let exit_code = match self.child.as_mut() {
            Some(child) => match child.wait() {
                // a signal death reports 128+signal, like the shell's $?
                Ok(status) => status
                    .code()
                    .unwrap_or_else(|| 128 + status.signal().unwrap_or(0)),
                Err(_) => 1,
            },
            None => 1,
        };
        CHILD_PID.store(0, Ordering::Relaxed);

        if !self.test_dir.join("final-status.txt").exists() && self.best_path("status").exists() {
            // The process is gone; final-* becomes the peak-RSS
            // checkpoint. write_summary picks up the note so the
            // provenance is visible.
            for file in ["status", "smaps", "smaps_rollup", "maps", "io"] {
                let _ = fs::copy(self.best_path(file), self.final_path(file));
            }
            // The listings keep their unprefixed names: write_summary and
            // annotate-maps.py read fds.txt/threads.txt/task-stats.txt.
            for file in ["fds", "threads", "task-stats"] {
                if self.best_path(file).exists() {
                    let _ = fs::copy(
                        self.best_path(file),
                        self.test_dir.join(format!("{file}.txt")),
                    );
                }
            }
            // ldd needs only the binary and the promoted map, so the
            // library report survives the process.
            if self.test_dir.join("final-maps.txt").exists() {
                report::write_libs_txt(
                    &self.cfg.cmd[0],
                    &self.test_dir.join("final-maps.txt"),
                    "the wrapped launcher",
                    &self.test_dir,
                    &self.ld_path,
                );
            }
            put(
                &self.test_dir.join("final-snapshot-note.txt"),
                format!(
                    "Note: final snapshot is the peak-RSS checkpoint during the run (VmRSS {} \
                     KiB at ~{}s, thread/fd listings captured near the peak) — the process \
                     exited before a live snapshot.\n",
                    self.best_rss, self.best_at
                ),
            );
        }

        let ran = format!("{:.1}", now() - self.launch_time);
        if exit_code == 0 {
            format!("OK (run-to-completion, exit code 0, ran {ran}s)")
        } else {
            format!("FAILED (exit code {exit_code})")
        }
    }

    /// STEADY: marker-gated sampling for the configured duration, a live
    /// final snapshot, teardown.
    fn finish_ready(&mut self, ready_after: String, samples_csv: &Path, run_start: f64) -> String {
        let n = self.cfg.knobs.duration / self.cfg.knobs.interval;
        let mut failure = self
            .sample_window(samples_csv, run_start, n, "launcher exited during sampling")
            .err();
        if procfs::proc_alive(self.vm_pid) {
            procfs::take_final_snapshot(
                self.vm_pid,
                &self.test_dir,
                &self.cfg.cmd[0],
                &self.ld_path,
            );
        } else {
            failure = Some("launcher exited during sampling".to_string());
        }
        self.teardown_launcher();
        match failure {
            None => format!("OK (guest ready after {ready_after}s)"),
            Some(reason) => format!("FAILED ({reason})"),
        }
    }

    /// Neither marker nor exit within the budget: treat like a marker-less
    /// payload — the poll loop already sampled the whole window.
    fn finish_no_marker(&mut self) -> String {
        if procfs::proc_alive(self.vm_pid) {
            procfs::take_final_snapshot(
                self.vm_pid,
                &self.test_dir,
                &self.cfg.cmd[0],
                &self.ld_path,
            );
        }
        self.teardown_launcher();
        "OK (no readiness marker; settle wait completed)".to_string()
    }

    /// bash's sample_window: n samples at the interval; Err carries the
    /// death reason. The signal check runs between samples, where bash's
    /// traps would fire.
    fn sample_window(
        &mut self,
        csv: &Path,
        start: f64,
        n: u64,
        death_reason: &str,
    ) -> Result<(), String> {
        let n = n.max(1);
        for i in 0..n {
            check_terminated();
            if !self.sample_once(csv, start) {
                return Err(death_reason.to_string());
            }
            if i < n - 1 {
                thread::sleep(Duration::from_secs(self.cfg.knobs.interval));
            }
        }
        Ok(())
    }

    /// bash's teardown_launcher: TERM, then KILL, then reap. The bash kept
    /// separate pid/vm_pid values for an older two-process mode; in wrap
    /// mode both are the spawned launcher, so one kill covers both.
    fn teardown_launcher(&mut self) {
        let pid = self.vm_pid;
        // undo a chase freeze: a stopped process pockets TERM until
        // continued
        unsafe { libc::kill(pid, libc::SIGCONT) };
        if procfs::proc_alive(pid) {
            unsafe { libc::kill(pid, libc::SIGTERM) };
            let mut waited = 0;
            while procfs::proc_alive(pid) && waited < 100 {
                thread::sleep(Duration::from_millis(100));
                waited += 1;
            }
            if procfs::proc_alive(pid) {
                unsafe { libc::kill(pid, libc::SIGKILL) };
            }
        }
        if let Some(child) = self.child.as_mut() {
            let _ = child.wait();
        }
        CHILD_PID.store(0, Ordering::Relaxed);
    }

    fn remove_scratch(&self) {
        let Ok(entries) = fs::read_dir(&self.test_dir) else {
            return;
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if (name.starts_with("cp-") || name.starts_with("best-")) && name.ends_with(".txt") {
                let _ = fs::remove_file(entry.path());
            }
        }
    }

    fn cp_path(&self, file: &str) -> PathBuf {
        self.test_dir.join(format!("cp-{file}.txt"))
    }

    fn best_path(&self, file: &str) -> PathBuf {
        self.test_dir.join(format!("best-{file}.txt"))
    }

    fn final_path(&self, file: &str) -> PathBuf {
        self.test_dir.join(format!("final-{file}.txt"))
    }
}

/// >> append; the CSVs are created with their header before the loop.
fn append(path: &Path, row: &str) {
    if let Ok(mut file) = fs::OpenOptions::new().append(true).create(true).open(path) {
        let _ = file.write_all(row.as_bytes());
    }
}
