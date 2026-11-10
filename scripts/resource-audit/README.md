# libkrun guest resource audit (wrap mode)

Runtime resource-usage audit for libkrun-based microVMs. You provide a
launcher binary and its command line; the driver runs it, measures it from
outside (`/proc` plus the captured console), and writes the article-style
reports: per-run summary, annotated memory map, category data and charts.

The methodology mirrors the "Analyzing Runtime Resource Usage" section of
QEMU's resource-audit article — with QEMU replaced by libkrun, and the
article's instrumented QEMU by a pair of LD_PRELOAD shims that work on any
unmodified launcher:

<https://jsnow.gitlab.io/qemu/devel/qemu-resource-audit.html>

## Quick start

A launcher that runs to completion (its exit code is reported):

```sh
./scripts/resource-audit/run-audit.sh --name my-case \
    ./examples/chroot_vm ./examples/rootfs_fedora cat /etc/os-release
```

A steady-state measurement (marker-gated sampling of a quiescent guest —
put `echo AUDIT_GUEST_READY; exec /bin/sleep infinity`, or the equivalent,
in the guest command):

```sh
./scripts/resource-audit/run-audit.sh \
    ./examples/chroot_vm ./examples/rootfs_fedora \
    /bin/sh -c 'echo AUDIT_GUEST_READY; exec /bin/sleep infinity'
```

Anything else — no guest, no libkrun, just the same pipeline:

```sh
./scripts/resource-audit/run-audit.sh --no-labels -- /bin/sh -c 'echo hi'
```

Results land in `results/<name>/` (default name: the command's basename).
Requirements: bash ≥ 5, gcc/cc, awk, python3 (for the annotated memory map
and charts; without it the run still works and says so) and, for real
guests, a usable `/dev/kvm`. libkrun is expected in
`$KRUN_AUDIT_PREFIX/lib64` (default `/usr/local`).

## How it works

The driver measures the launcher **from outside**: it spawns COMMAND from
your cwd with the audit's environment (`LD_LIBRARY_PATH` including any
`KRUN_AUDIT_EXTRA_LD_PATH` entries,
`GLIBC_TUNABLES=glibc.mem.decorate_maps=1`, and
`LD_PRELOAD=phase-hook.so:mmap-label.so`; `--no-labels` drops the label
shim), captures its stdout/stderr to `guest-console.log`, and samples
`/proc/<pid>` until the run ends. Nothing about the launcher is
modified — which is the point: any binary works, statically linked or not,
libkrun or not.

How a run is measured depends on what the launcher does:

- **Pre-boot phase** — launchers that call `krun_vmm_run()` through the
  PLT (dynamically linked against libkrun, like `examples/chroot_vm`) are
  held at that boundary by the `phase-hook` interposer for `--phase-pause`
  seconds (default 10) after printing `AUDIT_PHASE_VMM_BUILT`. This gives
  the article's "prior to main()" split: a `[Phase: VMM built, before
  guest start]` section and a `boot cost` line (VmRSS/anonymous growth
  between the phases) in `summary.txt`. Statically linked launchers or
  non-libkrun hypervisors (e.g. qemu) simply skip this phase.
- **Steady state** — if `AUDIT_GUEST_READY` appears on the console,
  sampling switches to marker-gated `--duration` windows and a full live
  final snapshot is taken before teardown.
- **Run to completion** — if the launcher exits first, its exit code is
  reported (`OK (run-to-completion, exit code 0, ran Xs)`; non-zero is a
  FAILED result). Note the code is the *launcher's*: `chroot_vm` returns 0
  after `krun_vmm_run()` returns regardless of the workload's own status.
  When the process exits before a live final snapshot can be taken,
  `final-*` (plus `fds.txt`/`threads.txt`/`task-stats.txt`) comes from the
  peak-RSS checkpoint captured while fast-polling — during a rising-RSS
  transition the launcher is briefly SIGSTOPped for the capture, so the
  promoted set is an exact point-in-time pair, and the summary note
  records its provenance.
- **No marker, still running** — after `--settle` + `--duration` the run
  finishes like a marker-less payload (`OK (no readiness marker; settle
  wait completed)`).

`--ram-mib N` enables the exact/merged guest-RAM identification; without
it the self-qualifying multi-region method applies (which is what a 4 GiB
`chroot_vm` needs anyway — its RAM is split around the 32-bit PCI gap),
and processes without guest RAM report 0.

To compare configurations (more vCPUs, a different RAM size, an extra
device), wrap differently-configured launchers and diff their summaries.
The parameterized launcher and the config matrices that used to live here
were removed — the supported use case is measuring *your* binary with
*your* command line.

### Swapping the guest kernel

`libkrunfw.so.5` is looked up by soname through `LD_LIBRARY_PATH` at
payload-load time, so a different libkrunfw build — i.e. a different guest
kernel — is selected purely by search-path order:

```sh
mkdir -p ~/fw-alt
ln -s /path/to/alternative/libkrunfw.so.5.x.y ~/fw-alt/libkrunfw.so.5
KRUN_AUDIT_EXTRA_LD_PATH=~/fw-alt ./scripts/resource-audit/run-audit.sh \
    --name with-alt-kernel ./examples/chroot_vm ./examples/rootfs_fedora ...
```

`KRUN_AUDIT_EXTRA_LD_PATH` entries are placed *before* the prefix libdir,
so they win. The kernel actually used is recorded in the run's `libs.txt`
and in `meta.txt` — always check those when comparing kernels. A convenient
source of alternative builds is a libkrunfw checkout (e.g. `~/libkrunfw`),
where `make` drops versioned `libkrunfw.so.5.x.y` files.

## Files

| file | purpose |
|------|---------|
| `run-audit.sh` | the driver: launch, readiness, sampling, reports |
| `run-audit-rs/` | Rust port of the driver (behavioral duplicate of `run-audit.sh`) |
| `phase-hook.c` | LD_PRELOAD shim holding wrapped launchers at krun_vmm_run() |
| `mmap-label.c` | LD_PRELOAD shim naming anonymous mmaps/mallocs after their callers |
| `vma-probe.c` | functional CONFIG_ANON_VMA_NAME probe (feeds meta.txt) |
| `annotate-maps.py` | verbose annotated memory map, category CSV, SVG charts |
| `parse-smaps.awk` | smaps → per-mapping rows, guest-RAM ID, category rollup |

Build artifacts go to `build/`, results to `results/` (both untracked).

### The Rust port of the driver

`run-audit-rs/` is a standalone-crate Rust duplicate of `run-audit.sh`
(same CLI, same outputs, same loop semantics). Build it once with
`cargo build --release` inside the directory and invoke
`run-audit-rs/target/release/run-audit-rs` exactly like the shell script
— including that COMMAND's relative paths resolve from the directory you
invoke the driver from (the examples above assume the repo root); a
launcher that cannot be executed at all fails with exit code 127, with
the reason in `guest-console.log`.
It still requires `awk` and `python3` on PATH — the smaps parser and the
annotator run as the same helper subprocesses — and resolves the audit
home (helpers, `build/`, default `results/`) from `$KRUN_AUDIT_HOME`, the
binary's location or the cwd. The bash script remains the reference
implementation; function names mirror it so the two can be compared side
by side.

## Metrics

All values are read from `/proc` of the launcher process, which for a
libkrun launcher hosts the VMM threads (vcpu, virtio-fs worker, event
loop), the KVM fd, and the guest RAM mapping — so they capture the full
per-VM cost.

- **RSS / RssAnon / RssFile** (`/proc/PID/status`): resident memory split by
  backing. File-backed RSS (libs, the kernel image inside `libkrunfw.so`)
  is *shared* with the page cache and with every other VM using the same
  files; anonymous RSS is private to this instance.
- **PSS** (proportional set size) and **USS** (unique set size,
  `Private_Clean+Private_Dirty`, from `smaps_rollup`): what the instance
  would cost in isolation (USS) or amortized across sharers (PSS).
- **VmPTE**: page-table memory for the process — grows with mapping count
  and THP usage.
- **guest_ram_rss**: RSS of the mapping(s) holding guest RAM. libkrun mmaps
  guest RAM as anonymous regions; see "Limitations" for how they are found.
- **vmm_private_anon** = `Anonymous − guest_ram_anon`: all anonymous memory
  that is not guest RAM. For a libkrunfw payload this is mostly *not*
  library cost — see the next two metrics.
- **kernel_image_cow**: the anonymous part of the `libkrunfw.so` mapping.
  libkrun maps the guest kernel zero-copy out of the library file, so the
  guest kernel's boot-time writes (the relocation pass over the image plus
  `.data`/`.bss` initialization, ~15 MiB) show up as private anonymous
  memory *inside the libkrunfw mapping* — guest memory misattributed to the
  process. External-kernel and firmware payloads copy the kernel into guest
  RAM instead, so they report 0.
- **framework_private_anon** = `vmm_private_anon − kernel_image_cow`: the
  VMM library's own per-instance cost — heaps, thread stacks, device state.
  For external-kernel payloads (`kernel_image_cow` = 0) it equals
  `vmm_private_anon`.
- **cpu_user/sys/guest**: `utime`, `stime`, `guest_time` from
  `/proc/PID/stat` (converted with `getconf CLK_TCK`). `guest_time` is CPU
  burned inside the guest by the vcpu threads.
- **fds / threads**: counts and classifications from `/proc/PID/fd` and
  `/proc/PID/task`.

## Outputs

Per run (`results/<runid>/<name>/`):

| file | content |
|------|---------|
| `guest-console.log` | the launcher's console output (markers, guest boot) |
| `cmd.txt` | exact environment, knobs and command line |
| `samples.csv` | one row per sampling interval (see header) |
| `final-status.txt`, `final-smaps.txt`, `final-smaps_rollup.txt`, `final-maps.txt`, `final-io.txt` | `/proc` snapshot (live, or the promoted peak checkpoint) |
| `fds.txt`, `threads.txt`, `task-stats.txt`, `libs.txt` | fd targets, thread names, per-thread stack pointers, resolved krun libraries |
| `parsed-smaps.tsv` | `parse-smaps.awk` output for the final snapshot |
| `summary.txt` | the per-run report (ends with the `[Total memory breakdown]` block) |
| `metrics.txt` | machine-readable key=value pairs feeding the run table |
| `maps-annotated.txt`, `categories.csv`, `charts/` | verbose annotated map, category data, SVG charts (see below) |
| `samples-preboot.csv`, `preboot-*`, `preboot-maps-annotated.txt`, `preboot-categories.csv`, `charts/<name>-preboot-*.svg` | only for libkrun launchers with a phase pause: the VMM-built phase |

Run-level: `summary.md` (comparison table, one row per measured command)
and `meta.txt` (host, resolved library paths, build commands, timing,
kernel-config notes).

## Annotated memory map, labels and charts

Every run's snapshot also feeds `annotate-maps.py` (stdlib python3, no
dependencies), which produces the article-style *verbose* view that the
coarse `summary.txt` rollup cannot show:

- **`maps-annotated.txt`** — a pymap-style multi-section report. Section 1
  is the full map: every mapping, sorted by address, one row per VMA:
  `size(KB) address_range perm offset dev inode pathname/[label] rss(KB)
  dirty(KB) anon(KB) pss(KB) uss(KB)`, blank lines between groups. Then
  `Segments (excluding empty reservations)` (Rss > 0, address order),
  `Segments with RSS usage` (sorted by RSS), `Segments with Anonymous
  memory` (sorted by anonymous) — each with its own totals footer — and a
  final `Category breakdown` charge table
  (`category | reservation | RO | RW | none | rss | anon`). File-backed rows
  carry ELF segment annotations (`/usr/lib64/libc.so.6 <.text .plt>`); the
  kernel blob inside `libkrunfw.so` shows up as its `.data` section.
  Anonymous and pseudo mappings carry inferred labels: `[guest RAM
  (merged-size match)]`, `[thread stack: fc_vcpu 0]`, `[glibc: malloc
  arena]` / `[glibc: arena reservation]`, `[.bss: libc.so.6]`,
  `[guard page]`, `[anon]` / `[anon] (empty reservation)`. On kernels with
  `CONFIG_ANON_VMA_NAME=y`, kernel-assigned labels are used instead of (or
  augmented by) inference: `[thread stack: fc_vcpu 0 (tid 1234)]`,
  `[anon: glibc: malloc arena]`, `[guest RAM (merged-size match); krun:
  libkrun.so.2+0x116158]`. The section-1 totals are also appended to
  `summary.txt` under `[Total memory breakdown]`.
- **`categories.csv`** — per category: reservation KiB split into
  `ro_res_kib` / `rw_res_kib` / `none_res_kib` (r--p/r-xp vs rw-p vs ---p),
  RSS and anonymous KiB, with percentages of the run's totals. This is the
  data for the article's pie charts; the categories refine the
  `parse-smaps.awk` rollup (keeping the shared names) with
  `libkrun_init.so`, `thread-stacks`, `glibc-arena`, `guard`, `memfd` and
  `vdso`.
- **`charts/`** — hand-written SVGs, no plotting libraries:
  `<name>-reservations-pie.svg` and `<name>-rss-pie.svg` (donut by
  category, top 9 + "other", legend with KiB and %, total in the center)
  and `<name>-reservations-ro-rw.svg` (horizontal stacked bars per
  category: read-only vs read-write vs `---p` reservations).

`annotate-maps.py` can be run by hand on any snapshot:
`annotate-maps.py TEST_DIR --name NAME --ram-mib N [--no-charts]`.

### The three labeling tiers

The QEMU article could name anonymous mappings because its author ran a
kernel built with `CONFIG_ANON_VMA_NAME=y` and instrumented QEMU itself.
This toolset gets as close as possible without patching libkrun:

1. **Inference (default, works everywhere).** What the annotator does on
   every run: ELF program/section headers are parsed directly from the
   mapped files (`struct`, no readelf), thread stacks are located through
   each task's user stack pointer (from `/proc/PID/task/TID/syscall` —
   stat's `startstack` is mm-wide and identical for every thread, so it
   cannot attribute stacks), glibc arenas are recognized by their
   rw-head + `---p`-tail 64 MiB pattern, and guest RAM by size
   (`ram`, `ram+16 MiB` for the merged low-region VMA, else largest anon).
   These passes only run on mappings the kernel left unnamed.
2. **glibc labels.** `GLIBC_TUNABLES=glibc.mem.decorate_maps=1` is exported
   for every run, so on a kernel built with `CONFIG_ANON_VMA_NAME=y` glibc
   names its own allocations in smaps: `[anon: glibc: malloc arena]`,
   `[anon: glibc: pthread stack: <tid>]` (enriched to
   `[thread stack: <comm> (tid <tid>)]` using task-stats.txt),
   `[anon: glibc: .bss /lib64/libc.so.6]`, `[anon: glibc: loader malloc]`,
   and similar. This tier is live on this host's kernel; on kernels without
   the option it is inert. Recipe to enable it elsewhere: build a kernel
   with `CONFIG_ANON_VMA_NAME=y` (a plain bool in mm/Kconfig), install and
   boot it, then re-run the audit — no other change is needed.
3. **VMM allocation attribution.** The `mmap-label` shim (preloaded by
   default; `--no-labels` disables it) names every anonymous `mmap()` after
   its caller — displayed by the kernel as
   `[anon:krun: <soname>: <symbol>+0x123]` or `[anon:krun: <soname>+0x123]`
   — using `dladdr` on the return address. Names must not contain `[`/`]`
   (the kernel reserves those for its own `[heap]`/`[stack]` smaps
   entries), hence the bare `krun:` prefix. On kernels built without
   `CONFIG_ANON_VMA_NAME=y` every `prctl` fails with EINVAL and the shim
   is a harmless no-op. The article instead patched QEMU's allocation call
   sites; the shim gets the same effect without touching libkrun. Note
   that glibc's own mmaps (arenas, stacks) usually keep their `glibc:`
   names because glibc renames them after mapping, so the `krun:` labels
   mostly mark libkrun's direct allocations — the guest RAM region above
   all.

   The shim also interposes `malloc`/`calloc` and names allocations of at
   least `KRUN_AUDIT_MALLOC_LABEL_KIB` KiB (default 128) as
   `[anon:krun: malloc 1024KiB from <soname>+0x3f0]`, but only when the
   containing VMA is still unnamed — arena- and heap-served allocations,
   and chunks glibc already decorated (`glibc: malloc`), are left alone.
   In practice this catches exactly the allocations glibc serves through
   fresh mmaps. Forcing *more* allocations down that path with
   `MALLOC_MMAP_THRESHOLD_` is deliberately left to you: it increases
   label coverage but perturbs allocator behavior, so such runs must not
   be compared against unmodified ones.

Which of tiers 2 and 3 are actually available is recorded in `meta.txt`:
`build/vma-probe` functionally checks `CONFIG_ANON_VMA_NAME` (the config
files are often absent on custom kernels) by naming a page with
`prctl(PR_SET_VMA)` and looking at the return value.

When a kernel label is present it is the base for the annotated map:
passed through verbatim, augmented only where it adds information (thread
stacks get their comm, the guest-RAM region keeps its identification —
e.g. `[guest RAM (merged-size match); krun: libkrun.so.2+0x116158]`), and
categorized by what made the allocation (`krun: libc.so.6+…` counts under
the caller library's category, `glibc: …` under glibc's).

## Interpreting the numbers for density

The interesting split for running many VMs per host:

- **file_backed_rss** (libs, libkrunfw's kernel image) is page-cache
  memory shared by every instance — it scales sub-linearly with VM count.
- **guest_ram_rss** is guest-private by definition, but only the pages the
  guest actually touches are resident (a quiescent 256 MiB guest shows
  ~25 MiB).
- **framework_private_anon** is the per-instance library cost (heaps, thread
  stacks, device state — a few hundred KiB). `vmm_private_anon` above it is
  dominated by `kernel_image_cow` (~15-16 MiB of guest-kernel boot writes
  inside the shared `libkrunfw.so` image) — guest memory, not VMM memory,
  but per-instance and private, so it *does* scale with VM count even
  though the clean image below it is shared.
- **threads/fds/eventfds** are per-instance kernel resources; the summary
  breaks them down (`fc_vcpu`, `fs worker`, event loop, KVM worker threads
  such as `kvm-nx-lpage-re` on recent host kernels).
- **VmPTE** grows with mapping count — relevant when stacking hundreds of
  VMs.

Compare configurations by diffing `summary.md` rows; drill into
`summary.txt` (top mappings, category rollup) to attribute a delta to a
device, a library, or the kernel.

## Acting on the results

Attribution is only half the job; this section translates observations
into levers.

### Symptom → diagnosis → action

| observation | diagnosis | action |
|---|---|---|
| `kernel_image_cow` ≈ 15–16 MiB | the relocatable guest kernel's boot writes (relocation pass + `.data`/`.bss`) COW the zero-copy mapping out of `libkrunfw.so` — guest memory, not library cost | accept it as per-instance guest cost, or boot an external-kernel payload (copies the kernel into guest RAM, reports 0) when you want it inside `guest_ram_rss` instead |
| `guest_ram_rss` ≫ what the workload needs | guest-kernel config: distro kernels can touch nearly all of RAM at boot (page init); workload page cache piles on | trim the guest kernel config, size the VM's RAM down, attach a virtio balloon, or drop caches in-guest before reporting readiness |
| `guest_ram_rss` ≪ RAM | healthy — only touched pages are resident (a quiescent 256 MiB guest shows ~25 MiB) | none |
| `framework_private_anon` grew vs a baseline | VMM-side allocations: per-device state, worker thread stacks, heaps | find the caller in `categories.csv` (top anon rows) and the `krun: malloc` labels in `maps-annotated.txt`; every attached device adds state plus at least one thread |
| `file_backed_rss` large | shared page cache: libraries, the kernel image, guest workload binaries | fine at density — paid once per host; only the first instance carries it |
| fds / threads above a device-less baseline | one eventfd set per virtqueue; one worker per device (`fs worker`, vsock muxer/reaper) | expected scaling with device count — sanity-check against a console-only baseline |
| `VmPTE` climbing with VM count | page-table memory grows with mappings and touched pages | relevant at hundreds of VMs per host; fewer devices and a smaller guest footprint reduce it |
| `cpu_guest_s` ≈ `--phase-pause` | the vCPU thread spins through earliest boot while the phase hook holds the launcher — not idle cost | read the post-marker `samples.csv` rows for idle CPU (≈0.001 s/sample); never quote the total as idle |
| `boot cost` ≈ 0 on a many-vCPU guest | the guest finished booting *during* the pause; the line measures post-pause growth (event loop + workload start) | shorten `--phase-pause` to move the boundary earlier, or accept the semantics — the sum is invariant |
| RSS drifting across `samples.csv` | guest still settling (page cache) or a genuine leak | quiescent runs are byte-stable (std 0–3 KiB); anything else deserves a look at the drift's shape |
| `VmSize` ≫ RSS | glibc arena reservations (several 64 MiB `---p` tails) plus untouched guest RAM | ignore — use RSS/USS/PSS |
| `FAILED (exit code N)` | that's the *launcher's* exit code — `chroot_vm` returns 0 after `krun_vmm_run()` regardless of the workload's status | check `guest-console.log` for the workload's real outcome |

### Trusting a comparison

Measured run-to-run bounds for identical commands (chroot_vm wraps,
repeated five times): quiescent and pre-boot figures repeat within
**±0.12%**, `framework_private_anon` within **±0.12%**, peak VmRSS and
`guest_ram_rss` within **±0.7%**, thread and fd counts exactly. So:

- deltas above ~1% are signal; below that, re-run the same command into
  another `--results` directory and compare before believing them
- for run-to-completion results, check `VmHWM` in `final-status.txt`:
  when it equals the reported peak VmRSS, the true lifetime peak was
  captured (the frozen checkpoint guarantees it on this tool's current
  version)
- the effective sampling grid is ~0.2–0.4 s per row (proc-walk cost per
  iteration); plateaus are exact, sub-100 ms transients are covered by
  the rise-chase but not point-by-point sampled

### The density arithmetic

Per **first** VM on a host, the launcher's RSS is everything at once;
per **additional identical VM**, only the private parts repeat:

```
marginal cost per VM = framework_private_anon      (~0.5 MiB measured)
                     + kernel_image_cow            (~16 MiB, krunfw payload)
                     + guest_ram_rss               (guest-dependent: THE lever)
                     + kernel-side KVM structs     (blind spot — not in /proc)
```

`file_backed_rss` (~8 MiB: libraries and the clean kernel image) is paid
once per host and shared thereafter. Worked example from the chroot_vm
measurements: each additional Fedora-rootfs VM of that shape costs
~0.6 + 16 + ~160 ≈ **177 MiB private**, of which over 90% is the guest's
own memory — which is why the biggest density levers are guest-side
(kernel config, RAM sizing, ballooning), not VMM-side.

### Measuring the library alone

`framework_private_anon` isolates the library's per-instance cost at run
time. To also get its loaded-and-idle footprint, wrap a binary that links
libkrun but never starts a VM:

```c
/* libkrun-loadonly.c — links against libkrun, calls nothing */
#include <stdio.h>
#include <unistd.h>

int main(void)
{
    printf("AUDIT_GUEST_READY\n");
    fflush(stdout);
    for (;;)
        pause();
}
```

```sh
cc -O2 libkrun-loadonly.c -o libkrun-loadonly -L/usr/local/lib64 -lkrun -lkrun_init \
   -Wl,-rpath,/usr/local/lib64
./run-audit.sh --name load-only -- libkrun-loadonly
```

Reference numbers from the measurements that motivated the split: the
loaded-and-idle library costs ~530 KiB RSS (~380 KiB relocation-touched
code + ~150 KiB private data); a running VM adds ~2.5 MiB of shareable
code working set and ~0.5 MiB `framework_private_anon` per instance;
libkrun makes exactly one large direct mmap per VM (guest RAM) and routes
everything else through the allocator into small heap/arena numbers.
Kernel-side KVM allocations (the per-VM `struct kvm`, vcpu structures,
dirty rings) are charged to kernel memory, not to the process — they remain
the audit's blind spot (see Limitations).

## Limitations

- **The launcher must run its VM in the foreground** — a daemonizing
  launcher would leave the driver sampling the wrong process.
- **The phase hook needs a dynamically linked libkrun launcher.** Static
  binaries and non-libkrun hypervisors get everything except the pre-boot
  phase.
- **`[anon:...]` labels depend on the host kernel.** They need
  `CONFIG_ANON_VMA_NAME=y`: with it (this host's current kernel), glibc's
  decorate_maps names and the `mmap-label` shim's `krun:` names appear in
  smaps; without it (e.g. stock Fedora kernels), neither works and the
  annotator falls back to pure inference. `meta.txt` records which state
  the `vma-probe` found, so old and new results are comparable.
- **Guest RAM is identified by size.** `parse-smaps.awk` and
  `annotate-maps.py` first try anonymous rw mappings whose size equals the
  requested RAM (`--ram-mib`; "exact-size match"), then RAM + 16 MiB for
  the merged low-region VMA ("merged-size match"). Guests larger than the
  32-bit PCI gap (3328 MiB) have their RAM split into several mmaps of no
  recognizable size; for those, every anonymous rw mapping of at least
  16 MiB that is not a glibc decoration or a shim-labeled malloc is
  claimed ("multi-region"). The last resort is the largest anonymous
  mapping ("largest-anon fallback"). The method used is printed in every
  summary and annotated map.
- **`vmm_private_anon` overstates library overhead for libkrunfw
  payloads** by `kernel_image_cow` (~15-16 MiB) — that memory belongs to
  the guest. Use `framework_private_anon` for the library's own cost; the
  category rollup separates the same split per mapping.
- **Sampling is external and unprivileged** — one `awk`/`find` pass per
  interval; the perturbation is negligible at 1 Hz but visible in the
  samples if you shrink the interval drastically. During a rising-RSS
  transition the launcher is briefly SIGSTOPped (~20 ms per checkpoint) so
  the capture is atomic; nothing advances while stopped, so no metric is
  distorted.
- **`read_bytes` in `[I/O]`** is block-layer I/O: it is ~0 when the page
  cache is warm from a previous run.
- **TEE variants (TDX/SEV)** use different `libkrun-tdx`/`libkrun-sev`
  libraries; the audit driver itself is launcher-agnostic and needs no
  changes — wrap a TEE-linked launcher the same way.

## Removed: the matrix mode

Earlier versions of this tool shipped a parameterized VM launcher
(`harness.c`), guest workload stubs and editable test matrices
(`tests.conf` & friends). They were removed: the supported use case is
wrapping your own launcher. To compare configurations (vcpus/ram/device
deltas), wrap differently-configured launchers — e.g. small scripts or
`examples/` binaries — and diff their reports.
