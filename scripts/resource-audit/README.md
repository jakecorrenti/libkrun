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

Requirements: bash ≥ 5, gcc/cc, awk, and a usable `/dev/kvm`. libkrun and
friends are expected in `$KRUN_AUDIT_PREFIX/lib64` (default `/usr/local`).
The harness is linked with an rpath for `libkrun.so`/`libkrun_init.so`, but
`libkrunfw.so.5` is `dlopen`ed by soname at payload-load time, so the driver
also sets `LD_LIBRARY_PATH` — keep that in mind when launching the harness by
hand.

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
| `run-audit.sh` | driver: build, launch, readiness, sampling, reports |
| `tests.conf` | the test matrix — edit this to add configurations |
| `parse-smaps.awk` | smaps → per-mapping rows, guest-RAM ID, category rollup |

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
| `cmd.txt` | exact environment and harness command line |
| `samples.csv` | one row per sampling interval (see header) |
| `final-status.txt`, `final-smaps.txt`, `final-smaps_rollup.txt`, `final-maps.txt`, `final-io.txt` | `/proc` snapshot taken right before teardown |
| `fds.txt`, `threads.txt`, `libs.txt` | fd targets, thread names, resolved krun libraries |
| `parsed-smaps.tsv` | `parse-smaps.awk` output for the final snapshot |
| `summary.txt` | the per-test report |
| `metrics.txt` | machine-readable key=value pairs feeding the run table |

Run-level: `summary.md` (comparison table, one row per test) and `meta.txt`
(host, resolved library paths, build commands, timing, kernel-config notes).

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

- **No `[anon:...]` labels on this host.** Fedora's kernel is built without
  `CONFIG_ANON_VMA_NAME`, so `GLIBC_TUNABLES=glibc.mem.decorate_maps=1`
  (exported for every harness run, harmless and future-proof) cannot label
  anonymous mappings the way the QEMU article's host does.
- **Guest RAM is identified by size.** `parse-smaps.awk` sums anonymous rw
  mappings whose size equals the requested RAM ("exact-size match"); without
  a match it takes the largest anonymous mapping ("largest-anon fallback").
  With the krunfw payload the low-memory region below the kernel load
  address and the main RAM region usually *merge* into one VMA of
  RAM + 16 MiB, so in practice the fallback is the norm — it is safe because
  guest RAM dwarfs every other anonymous mapping. The small low-memory
  region is included either way; residual ambiguity is well under 1 MiB. The
  method used is printed in every summary.
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
