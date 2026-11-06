# libkrun guest resource audit

Runtime resource-usage audit for [libkrun](../../README.md) microVMs, using the
*installed* libkrun / libkrunfw / libkrun_init stack. The methodology mirrors
the "Analyzing Runtime Resource Usage" section of QEMU's resource-audit
article:

<https://jsnow.gitlab.io/qemu/devel/qemu-resource-audit.html>

where QEMU is replaced by libkrun, and the article's mbuto-built guest by the
standard libkrun ecosystem: a libkrunfw kernel payload, the `krun-init` guest
init injected through a virtio-fs overlay, and a tiny static workload that
prints a readiness marker and sleeps forever.

## Quick start

```sh
# wrap any launcher (no matrix configuration needed):
./run-audit.sh --wrap -- ./examples/chroot_vm ./examples/rootfs_fedora cat /etc/os-release
```

```sh
cd scripts/resource-audit
./run-audit.sh                 # runs every test in tests.conf
./run-audit.sh minimal         # one test
./run-audit.sh --list          # what's in the matrix
```

Each test boots a real VM through `/dev/kvm`, waits for the guest to report
readiness, samples `/proc/<harness-pid>` for `--duration` seconds, then
tears the VM down and writes a report. Results land in
`results/<YYYYMMDD-HHMMSS>/<test>/`; the run-level comparison table is
`results/<runid>/summary.md`.

### Everything in one command

`tests-full.conf` is the maximal matrix: every axis above plus PCI/ACPI and
the external kernel (when a libkrunfw vmlinux is present), every test
phased and labeled, and a strace attribution run:

```sh
./run-audit.sh --config tests-full.conf
```

Expect a few minutes. The `minimal-strace` row in `summary.md` is
attribution-only — ptrace perturbs timing, so don't diff it against the
untraced rows.

### Realistic guests

`tests-realistic.conf` runs the chroot_vm / crun-krun workload model: a real
distro rootfs (`examples/rootfs_fedora`, regenerate with
`make -C examples rootfs`) served over virtio-fs, a real `/bin/sh` workload
that prints the readiness marker itself, chroot_vm's device and resource
shape (4 vCPUs / 4 GiB with rng, balloon and vsock), a lean 1-vCPU variant,
and a block-I/O variant where the guest mounts and writes to an ext4 image
before going idle:

```sh
./run-audit.sh --config tests-realistic.conf
```

Two artifacts of the realistic setup are worth knowing:

- **Split guest RAM.** x86_64 guests larger than the 32-bit PCI gap
  (3328 MiB — the 4 GiB chroot_vm shape, for example) get their RAM split
  into several host mmaps (below-gap + above-4G), none of which matches the
  requested RAM size. Both parsers handle this with a "multi-region"
  method: every anonymous rw mapping of at least 16 MiB that is not a
  glibc decoration or a shim-labeled malloc is counted as guest RAM.
  Smaller guests keep using the exact/merged-size matches.
- **The podman-exported rootfs carries foreign uids with setuid bits.**
  Executing its `/sbin/mount` (setuid, owned by that foreign uid) flips
  euid away from root even when invoked by root, and libmount's `fsopen()`
  fails with EPERM. The blk test therefore mounts through
  `build/blk-setup`, a static helper doing raw `mount(2)`/`write(2)`, which
  works as euid 0. Fixing the rootfs itself needs host root
  (`sudo chown -R 0:0 examples/rootfs_fedora`); a properly owned or
  non-podman rootfs would let `/sbin/mount` work again.

Requirements: bash ≥ 5, gcc/cc, awk, python3 (for the annotated memory map
and charts; without it the run still works and says so) and a usable
`/dev/kvm`. `strace` is optional (needed only for `strace=1` tests). libkrun
and friends are expected in `$KRUN_AUDIT_PREFIX/lib64` (default
`/usr/local`). The harness is linked with an rpath for
`libkrun.so`/`libkrun_init.so`, but `libkrunfw.so.5` is `dlopen`ed by soname
at payload-load time, so the driver also sets `LD_LIBRARY_PATH` — keep that
in mind when launching the harness by hand.

## How the guest is booted

- **Payload** — `krun_payload_load_krunfw()`: libkrun `dlopen`s
  `libkrunfw.so.5` and boots the embedded kernel. On x86_64 the bundle is a
  flat binary of the vmlinux load segments placed at its link address
  (`CONFIG_PHYSICAL_START` = 16 MiB) and entered directly — no firmware, no
  PVH. The kernel image is *not* copied into guest RAM: `Payload::KernelMmap`
  (`src/libkrun/src/vmm/builder.rs`) inserts `libkrunfw.so`'s file mapping
  itself as a guest memory region, and `arch_memory_regions()`
  (`src/arch/src/x86_64/mod.rs`) punches a matching hole in guest RAM: a
  16 MiB low-memory region at guest physical 0, the kernel hole, then the
  main RAM region. The two anonymous regions usually merge into one host
  VMA of RAM + 16 MiB. See "Interpreting the numbers" for what the
  zero-copy kernel does to the memory breakdown.
- **Guest init** — `krun_init_config_builder()` builds a `KrunInitConfig`
  (workload path, args, workdir) which `krun_init_config_apply()` turns into
  overlay files (`/init.krun` plus its config) and an `init=/init.krun`
  cmdline append. The init binary itself comes from the embedded blob in
  `libkrun_init.so`.
- **Root filesystem** — a virtio-fs device tagged `/dev/root`:
  - `nullfs` (default): an empty `FsDevice` whose entire content is the
    overlay — `/init.krun`, `dev`/`proc`/`sys` mount points, and the workload.
    This is the initramfs-like minimal guest, the closest analog of the
    article's mbuto guest.
  - `dir`: a host directory shared read-write, with the same overlay applied
    on top (the `examples/chroot_vm.c` model).
- **Workload** — `pause.c`, compiled static, `--embed`ed into the overlay from
  a read-only `mmap` of the host file. It writes `AUDIT_GUEST_READY\n` to the
  console and then `pause()`s forever, so the VM is quiescent while being
  sampled. Because it is mapped `PROT_READ|MAP_PRIVATE`, its pages are
  file-backed and shared with the host page cache instead of heap.

The harness (`harness.c`) is a configurable launcher modeled on
`examples/chroot_vm.c`; `run-audit.sh` starts it in the background with
stdio redirected to `guest-console.log` and samples the process from outside.

## Files

| file | purpose |
|------|---------|
| `harness.c` | C VM launcher (payload / rootfs / devices / embed configuration) |
| `pause.c` | static guest workload: print marker, sleep forever |
| `blk-setup.c` | static guest workload for the blk test: mount ext4, write, idle |
| `run-audit.sh` | driver: build, launch, readiness, sampling, reports |
| `tests.conf` | the test matrix — edit this to add configurations |
| `tests-full.conf` | maximal matrix: every axis, phased and labeled, plus strace |
| `tests-realistic.conf` | realistic-guest matrix: chroot_vm model on a real rootfs |
| `parse-smaps.awk` | smaps → per-mapping rows, guest-RAM ID, category rollup |
| `annotate-maps.py` | verbose annotated memory map, category CSV, SVG charts |
| `mmap-label.c` | LD_PRELOAD shim naming anonymous mmaps after their callers |
| `phase-hook.c` | LD_PRELOAD shim holding wrapped launchers at krun_vmm_run() |
| `vma-probe.c` | functional CONFIG_ANON_VMA_NAME probe (feeds meta.txt) |

Build artifacts go to `build/`, results to `results/` (both untracked).

## Metrics

All values are read from `/proc` of the harness process, which hosts the VMM
threads (vcpu, virtio-fs worker, event loop), the KVM fd, and the guest RAM
mapping — so they capture the full per-VM cost.

- **RSS / RssAnon / RssFile** (`/proc/PID/status`): resident memory split by
  backing. File-backed RSS (libs, the embedded workload) is *shared* with the
  page cache and with every other VM using the same files; anonymous RSS is
  private to this instance.
- **PSS** (proportional set size) and **USS** (unique set size,
  `Private_Clean+Private_Dirty`, from `smaps_rollup`): what the instance
  would cost in isolation (USS) or amortized across sharers (PSS).
- **VmPTE**: page-table memory for the process — grows with mapping count
  and THP usage.
- **guest_ram_rss**: RSS of the mapping(s) holding guest RAM. libkrun mmaps
  guest RAM as anonymous regions; see "Limitations" for how they are found.
- **vmm_private_anon** = `Anonymous − guest_ram_anon`: the headline
  "libkrun overhead" number — anonymous memory that is not guest RAM.
- **cpu_user/sys/guest**: `utime`, `stime`, `guest_time` from
  `/proc/PID/stat` (converted with `getconf CLK_TCK`). `guest_time` is CPU
  burned inside the guest by the vcpu threads.
- **fds / threads**: counts and classifications from `/proc/PID/fd` and
  `/proc/PID/task`.

## Outputs

Per test (`results/<runid>/<test>/`):

| file | content |
|------|---------|
| `guest-console.log` | kernel + init + workload console output (the marker) |
| `cmd.txt` | exact environment, knobs and harness command line |
| `samples.csv` | one row per sampling interval (see header) |
| `final-status.txt`, `final-smaps.txt`, `final-smaps_rollup.txt`, `final-maps.txt`, `final-io.txt` | `/proc` snapshot taken right before teardown |
| `fds.txt`, `threads.txt`, `task-stats.txt`, `libs.txt` | fd targets, thread names, per-thread stack pointers, resolved krun libraries |
| `parsed-smaps.tsv` | `parse-smaps.awk` output for the final snapshot |
| `summary.txt` | the per-test report (ends with the `[Total memory breakdown]` block) |
| `metrics.txt` | machine-readable key=value pairs feeding the run table |
| `maps-annotated.txt`, `categories.csv`, `charts/` | verbose annotated map, category data, SVG charts (see below) |
| `strace.log` | only for `strace=1` tests: traced syscalls with callstacks |
| `samples-preboot.csv`, `preboot-*.{txt,smaps,maps,io}`, `preboot-maps-annotated.txt`, `preboot-categories.csv`, `charts/<test>-preboot-*.svg` | only for `pause_before_run` tests: the VMM-built phase (see below) |

Run-level: `summary.md` (comparison table, one row per test) and `meta.txt`
(host, resolved library paths, build commands, timing, kernel-config notes).

## Annotated memory map, labels and charts

Every test's snapshot also feeds `annotate-maps.py` (stdlib python3, no
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
  `<test>-reservations-pie.svg` and `<test>-rss-pie.svg` (donut by category,
  top 9 + "other", legend with KiB and %, total in the center) and
  `<test>-reservations-ro-rw.svg` (horizontal stacked bars per category:
  read-only vs read-write vs `---p` reservations).

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
   for every harness run, so on a kernel built with
   `CONFIG_ANON_VMA_NAME=y` glibc names its own allocations in smaps:
   `[anon: glibc: malloc arena]`, `[anon: glibc: pthread stack: <tid>]`
   (enriched to `[thread stack: <comm> (tid <tid>)]` using
   task-stats.txt), `[anon: glibc: .bss /lib64/libc.so.6]`,
   `[anon: glibc: loader malloc]`, and similar. This tier is live on this
   host's kernel; on kernels without the option it is inert. Recipe to
   enable it elsewhere: build a kernel with `CONFIG_ANON_VMA_NAME=y`
   (a plain bool in mm/Kconfig), install and boot it, then re-run the
   audit — no other change is needed.
3. **VMM allocation attribution.** `label_mmap=1` in a test (or
   `KRUN_AUDIT_LABEL_MMAP=1` in the environment for all tests) adds
   `build/mmap-label.so` to the harness's `LD_PRELOAD` (recorded in
   cmd.txt). The shim names every anonymous `mmap()` after its caller —
   displayed by the kernel as `[anon:krun: <soname>: <symbol>+0x123]` or
   `[anon:krun: <soname>+0x123]` — using `dladdr` on the return address.
   Names must not contain `[`/`]` (the kernel reserves those for its own
   `[heap]`/`[stack]` smaps entries), hence the bare `krun:` prefix. On
   kernels built without `CONFIG_ANON_VMA_NAME=y` every `prctl` fails
   with EINVAL and the shim is a harmless no-op. The article instead
   patched QEMU's allocation call sites; the shim gets the same effect
   without touching libkrun. Note that glibc's own mmaps (arenas,
   stacks) usually keep their `glibc:` names because glibc renames them
   after mapping, so the `krun:` labels mostly mark libkrun's direct
   allocations — the guest RAM region above all.

   The shim also interposes `malloc`/`calloc` and names allocations of at
   least `KRUN_AUDIT_MALLOC_LABEL_KIB` KiB (default 128) as
   `[anon:krun: malloc 1024KiB from <soname>+0x3f0]`, but only when the
   containing VMA is still unnamed — arena- and heap-served allocations,
   and chunks glibc already decorated (`glibc: malloc`), are left alone.
   In practice this catches exactly the allocations glibc serves through
   fresh mmaps. Forcing *more* allocations down that path with
   `MALLOC_MMAP_THRESHOLD_` (via a test's `extra_env`) is deliberately
   left to you: it increases label coverage but perturbs allocator
   behavior, so such runs must not be compared against unmodified ones.

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

### Tracing allocations with strace

`strace=1` in a test (see the commented `test_minimal-strace` in
`tests.conf`) launches the harness under
`strace -f -k -e trace=mmap,mprotect,munmap,open,openat,openat2,prctl -o
strace.log` (`-k` dropped with a note on strace builds without callstack
support). This is how the article's callstack-style labels
(`[qemu: qemu_thread_start > libc: tcache_init]`) were derived: each traced
`mmap()` line in `strace.log` is followed by the stack of its caller, e.g.

    mmap(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7feffc065000
     > /usr/lib64/ld-linux-x86-64.so.2(__mmap+0x2c) [0x2491c]
     > /usr/lib64/ld-linux-x86-64.so.2(__minimal_malloc+0x90) [0xb960]
     ...

To attribute a mapping from `maps-annotated.txt`, take its address range
and size, find the `mmap(…)` line in `strace.log` whose return value and
length match, and read the backtrace beneath it (pair it with
`mprotect`/`munmap` lines that reshape it afterwards). The driver runs
strace as the harness's parent, so `ptrace_scope` is not an issue, and it
asks strace to kill its tracees on exit so teardown stays clean.

strace perturbs the run: boot is slower (raise `settle`, the commented
example uses `settle=30`) and every traced syscall costs time. Keep strace
rows out of performance comparisons — compare them only against each other.
Note that the traced syscall set is deliberately narrow, so a mostly-KVM
guest boots almost as fast as usual; the mapping churn is what gets traced.

## Phased measurement

The article's "prior to main()" split asks how much of the footprint exists
before the workload runs. The libkrun analog is *VMM built* (KVM VM, virtio
devices, guest RAM mapped, kernel inserted — but the guest not yet
executing) versus *guest running*. A test with `pause_before_run=SECS`
(see `test_minimal-phased` in `tests.conf`) makes the harness print
`AUDIT_PHASE_VMM_BUILT` to its stderr and hold the VM for SECS seconds
after `krun_vmm_builder_build()`, before calling `krun_vmm_run()`.

For such tests the driver:

- waits for the phase marker, then samples `samples-preboot.csv` for the
  pause window (stopping one second early — marker detection lags, and the
  guest reaches readiness within ~0.2s of the sleep ending, so sampling
  right up to the boundary would corrupt the split);
- snapshots `preboot-status.txt`, `preboot-smaps.txt`, `preboot-maps.txt`
  and `preboot-io.txt`;
- annotates the pre-boot snapshot separately: `preboot-maps-annotated.txt`,
  `preboot-categories.csv` and `charts/<test>-preboot-*.svg`;
- adds a `[Phase: VMM built, before guest start]` section to `summary.txt`
  and a `boot cost` line to `[Derived]`.

Reading the split: the pre-boot numbers are the pure VMM cost with the
kernel image in place but untouched — the guest RAM region is mapped yet
nearly empty, and `libkrunfw.so`'s kernel blob is still clean file cache.
The `boot cost` line (VmRSS and anonymous growth between the phases) is
what *running* the guest costs on top: the guest kernel decompressing
itself into RAM, populating its structures, and dirtying the shared kernel
image's `.data` (COW). Compare the two `categories.csv` files to see which
categories moved. Expect a much smaller delta between the phases for an
external-kernel payload (the kernel image is copied into guest RAM before
the phase boundary, so it is already counted pre-boot).

## Wrapping your own launcher

`--wrap` runs any VM launcher through the same measurement pipeline as the
matrix — no harness configuration needed:

```sh
./run-audit.sh --wrap --name chroot-vm-osrelease -- \
    ./examples/chroot_vm ./examples/rootfs_fedora cat /etc/os-release \
    --results /tmp/wrap-run
```

The command after `--` runs from your cwd with the audit's environment
(`LD_LIBRARY_PATH` including any `KRUN_AUDIT_EXTRA_LD_PATH` entries,
`GLIBC_TUNABLES=glibc.mem.decorate_maps=1`, and
`LD_PRELOAD=phase-hook.so:mmap-label.so`; `--no-labels` drops the mmap-label
shim). Its stdout/stderr are captured to `guest-console.log`, `/proc/<pid>`
is sampled, and the usual reports (`summary.txt`, `maps-annotated.txt`,
`categories.csv`, `charts/`, `metrics.txt`) land in
`results/<name>/` exactly as for matrix tests.

How a wrapped run is measured depends on what the launcher does:

- **Pre-boot phase** — launchers that call `krun_vmm_run()` through the PLT
  (dynamically linked against libkrun, like `examples/chroot_vm`) are held
  at that boundary by the `phase-hook` LD_PRELOAD interposer for
  `--phase-pause` seconds (default 10) after printing
  `AUDIT_PHASE_VMM_BUILT`, giving the same `[Phase: VMM built …]` section
  and `boot cost` line as the matrix's phased tests. Statically linked
  launchers or non-libkrun hypervisors (e.g. qemu) simply skip this phase.
- **Steady state** — if `AUDIT_GUEST_READY` appears on the console, sampling
  switches to the usual marker-gated `--duration` window. Put
  `echo AUDIT_GUEST_READY; exec /bin/sleep infinity` (or the equivalent) in
  your guest command for a quiescent measurement.
- **Run to completion** — if the launcher exits first, its exit code is
  reported (`OK (run-to-completion, exit code 0, ran Xs)`; a non-zero code
  is a FAILED result). Note the code is the *launcher's*: `chroot_vm`
  returns 0 after `krun_vmm_run()` returns regardless of the workload's
  own status. When the process exits before a live final snapshot can be
  taken, `final-*` (plus `fds.txt`/`threads.txt`/`task-stats.txt`) comes
  from the peak-RSS checkpoint captured while fast-polling — the launcher
  is briefly SIGSTOPped for the capture during a rising-RSS transition, so
  the promoted set is an exact point-in-time pair and the summary note
  records its provenance.
- **No marker, still running** — after `--settle` + `--duration` the run
  finishes like a marker-less payload (`OK (no readiness marker; settle
  wait completed)`).

`--ram-mib N` enables the exact/merged guest-RAM identification; without it
the self-qualifying multi-region method applies (which is what a 4 GiB
`chroot_vm` needs anyway — its RAM is split around the 32-bit PCI gap), and
processes without guest RAM report 0.

Limitations: the launcher must run its VM in the foreground (daemonizing
launchers are unsupported — the driver would sample the wrong process), and
the phase hook needs a dynamically linked libkrun launcher.

## Configuring tests

`tests.conf` is sourced bash. Each test is a `test_<name>()` function that
overrides any of the variables documented at the top of the file (vcpus, ram,
transport, payload, root mode, devices, images, timing, environment, …).
Test functions run with `$TEST_DIR` (their results directory, already
created) and `$SCRIPT_DIR` available, and can assemble per-test artifacts
such as disk images or rootfs trees — see `test_blk` and `test_rootfs-dir`
for examples. Timing and the whole matrix are trivially editable; that is
the point of the tool.

The driver always embeds `build/pause` at the guest workload path for nullfs
tests (unless the test provides its own embed there).

`run-audit.sh` options: `--config`, `--results`, `--settle`, `--duration`,
`--interval`, `--list`, `--dry-run`, `--rebuild`, `--keep-going`. Tests
failing readiness (marker not seen, harness exited) are marked `FAILED` and
by default abort the run; artifacts are kept either way.

## Swapping the guest kernel

`libkrunfw.so.5` is looked up by soname through `LD_LIBRARY_PATH` at
payload-load time, so a different libkrunfw build — i.e. a different guest
kernel — is selected purely by search-path order:

```sh
mkdir -p ~/fw-alt
ln -s /path/to/alternative/libkrunfw.so.5.x.y ~/fw-alt/libkrunfw.so.5
KRUN_AUDIT_EXTRA_LD_PATH=~/fw-alt ./run-audit.sh minimal
```

`KRUN_AUDIT_EXTRA_LD_PATH` entries are placed *before* the prefix libdir, so
they win. The kernel actually used is recorded in the test's `libs.txt` and
in `meta.txt` — always check those when comparing kernels. A convenient
source of alternative builds is a libkrunfw checkout (e.g.
`~/libkrunfw`), where `make` drops versioned `libkrunfw.so.5.x.y` files.
This mechanism was verified on this host: pointing it at `libkrunfw.so.5.5.0`
booted that kernel instead of the installed 5.6.2.

## External kernel payload

`payload=external` boots a kernel image from a file instead of libkrunfw
(`--kernel`, optional `--initrd`, `--cmdline`, `--kernel-format`; ELF
vmlinux is the default on x86_64). The guest still uses krun-init through
the overlay, but the kernel is *copied* into guest RAM rather than mapped
from a shared library — compare `test_external-kernel` (in `tests.conf` as a
commented example) with the krunfw tests to see the difference:

- krunfw: guest RAM holds only what the running kernel touches; the kernel
  image itself stays file-backed in `libkrunfw.so`. Because that mapping *is*
  guest memory, the kernel's early-boot writes — the relocatable-kernel
  relocation pass over the image plus `.data`/`.bss` initialization — COW
  about 16 MiB of it into *private anonymous* memory per VM, attributed to
  the `libkrunfw.so` category.
- external: the whole kernel image is copied into the guest-RAM region
  (guest_ram_rss grows by the kernel size), and `vmm_private_anon` drops to
  the true VMM cost (well under 1 MiB).

The kernel must support virtio-mmio, virtio-fs (FUSE), virtio-console and
virtio-rng; libkrunfw's configs do, distro kernels frequently lack
virtio-mmio.

## Firmware payload

`payload=firmware` boots a raw firmware image (`--firmware`, optional
`--cmdline`) the way `examples/boot_efi.c` does: no init configuration, no
rootfs, no workload — the firmware boots itself. Readiness cannot be
signalled by a workload, so tests using it set `ready_marker=""` and the
driver falls back to a fixed `--settle` wait. Any bootable firmware image
(e.g. a qboot/TDVF-style blob) works; add a device set (blk/net/…) as
needed.

## Interpreting the numbers for density

The interesting split for running many VMs per host:

- **file_backed_rss** (libs, libkrunfw's kernel image, the embedded
  workload) is page-cache memory shared by every instance — it scales
  sub-linearly with VM count.
- **guest_ram_rss** is guest-private by definition, but only the pages the
  guest actually touches are resident (a quiescent 256 MiB guest shows
  ~25 MiB).
- **vmm_private_anon** is the per-instance VMM cost. With the krunfw payload
  it is dominated by the ~16 MiB of dirty kernel-`.data` pages inside
  `libkrunfw.so` (see above); the pure VMM share (heaps, thread stacks,
  device state) is visible in the category rollup and in the
  external-kernel run.
- **threads/fds/eventfds** are per-instance kernel resources; the summary
  breaks them down (`fc_vcpu`, `fs worker`, event loop, KVM worker threads
  such as `kvm-nx-lpage-re` on recent host kernels).
- **VmPTE** grows with mapping count — relevant when stacking hundreds of
  VMs.

Compare configurations by diffing `summary.md` rows; drill into
`summary.txt` (top mappings, category rollup) to attribute a delta to a
device, a library, or the kernel.

## Limitations

- **`[anon:...]` labels depend on the host kernel.** They need
  `CONFIG_ANON_VMA_NAME=y`: with it (this host's current kernel), glibc's
  decorate_maps names and the `label_mmap` shim's `krun:` names appear in
  smaps; without it (e.g. stock Fedora kernels), neither works and the
  annotator falls back to pure inference. `meta.txt` records which state
  the `vma-probe` found, so old and new results are comparable.
- **Guest RAM is identified by size.** `parse-smaps.awk` and
  `annotate-maps.py` first try anonymous rw mappings whose size equals the
  requested RAM ("exact-size match"), then RAM + 16 MiB for the merged
  low-region VMA ("merged-size match"). Guests larger than the 32-bit PCI
  gap (3328 MiB) have their RAM split into several mmaps of no recognizable
  size; for those, every anonymous rw mapping of at least 16 MiB that is
  not a glibc decoration or a shim-labeled malloc is claimed
  ("multi-region"). The last resort is the largest anonymous mapping
  ("largest-anon fallback"). The method used is printed in every summary
  and annotated map.
- **`vmm_private_anon` overstates pure VMM overhead for krunfw payloads** by
  the guest kernel's dirty `.data` inside `libkrunfw.so` (~16 MiB) — that
  memory belongs to the guest, not the VMM. The category rollup separates
  it; an external-kernel run measures the VMM alone.
- **The blk test uses a sparse image** (`truncate -s 2G`): it measures
  queue/metadata cost only, since nothing reads or writes the data. Use a
  populated image in `tests.conf` to measure I/O paths and page cache.
- **Sampling is external and unprivileged** — one `awk`/`find` pass per
  interval; the perturbation is negligible at 1 Hz but visible in the
  samples if you shrink the interval drastically.
- **`read_bytes` in `[I/O]`** is block-layer I/O: it is ~0 when the page
  cache is warm from a previous run.
- **TEE variants (TDX/SEV)** need a differently-linked harness
  (`-lkrun-tdx`/`-lkrun-sev`, plus `krun_payload_load_krunfw_tee()` with a
  TEE config) — the current harness only exercises the standard library.
  The audit driver itself is payload-agnostic and needs no changes.

## Extending

- New test: add a `test_<name>()` function to `tests.conf` and run
  `./run-audit.sh <name>`.
- Different libkrun installation: `KRUN_AUDIT_PREFIX=/opt/krun ./run-audit.sh`.
- Different compiler: `KRUN_AUDIT_CC=clang ./run-audit.sh`.
- The harness can be driven by hand for experiments — see
  `build/krun-harness --help` and the exact command lines recorded in each
  test's `cmd.txt`.
