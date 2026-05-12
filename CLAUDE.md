# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this project is

**libkrun** is a Rust dynamic library that provides virtualization-based process isolation via KVM (Linux) and HVF (macOS). It exposes a C API (`include/libkrun.h`) that lets callers run a process inside a lightweight VM with configurable vCPUs, RAM, virtio devices, and an embedded init binary.

## Build commands

All builds go through the Makefile, which handles feature flags, platform detection, and sysroot management for cross-compilation. Direct `cargo build` skips that plumbing.

```bash
# Release build (minimal — no optional devices)
make

# Release build with common optional devices
make BLK=1 NET=1 GPU=1 SND=1 INPUT=1

# Debug build
make debug

# TEE variants (mutually exclusive with each other and GPU/SND/INPUT)
make SEV=1        # AMD SEV — produces libkrun-sev.so
make TDX=1        # Intel TDX — produces libkrun-tdx.so

# Other optional features
make VHOST_USER=1
make VIRGL_RESOURCE_MAP2=1

# Install to /usr/local (or PREFIX=...)
make install
make PREFIX=$HOME/.local install
```

The Makefile exports `CC_LINUX` for Rust build scripts that compile C code targeting Linux. On macOS it auto-downloads a Debian sysroot; on Linux it uses the host toolchain.

## Lint and format

Clippy is run with `-D warnings` — zero warnings are allowed. The CI checks several feature combinations; you should too when touching device or feature-gated code:

```bash
# Required before every PR — same as CI
touch init/init   # build scripts require this file to exist
cargo clippy --locked -- -D warnings
cargo clippy --locked --features amd-sev -- -D warnings
cargo clippy --locked --features tdx -- -D warnings
cargo clippy --locked --features net,blk,gpu,snd,input -- -D warnings

# Format check
cargo fmt -- --check
```

## Tests

```bash
# Unit tests (requires init/init to exist and KVM access on Linux)
touch init/init
cargo test

# Integration tests (builds and installs the library first)
make test
make test TEST=test_name       # run a single integration test
make test BLK=1                # integration tests with blk feature
```

Integration tests live in `tests/` as a separate Cargo workspace. They require the library to be installed to a local prefix (`test-prefix/`) which `make test` handles automatically.

## Crate architecture

The workspace (`Cargo.toml`) contains these crates under `src/`:

| Crate | Role |
|---|---|
| **libkrun** | C API surface. Manages `KrunContext` instances (one per VM), translates API calls into VMM configuration, and drives startup via `krun_start_enter()`. |
| **vmm** (krun-vmm) | VMM core: builds and runs the VM, owns the vCPU threads, wires devices to memory and IRQs. |
| **devices** (krun-devices) | All virtio device implementations: console, block, fs (virtiofs passthrough + AugmentFs overlay), net, gpu, sound, input, vsock. |
| **init-blob** | Build script that compiles `init/` (the Rust PID-1) as a statically linked musl binary and embeds it as `INIT_BINARY: &[u8]`. The passthrough fs backends inject this binary as a virtual file (`init.krun`) via `AugmentFs`. |
| **arch** (krun-arch) | Platform-specific VM setup: GDT/IDT (x86_64), FDT (aarch64/riscv), boot protocol. |
| **kernel** | Loads the kernel image and sets up the boot parameters passed to the VMM. |
| **hvf** | macOS HVF hypervisor bindings (Linux uses kvm-ioctls directly in vmm). |
| **cpuid** | x86_64 CPUID leaf manipulation for vCPU feature exposure. |
| **rutabaga_gfx** | Wraps virglrenderer for virtio-gpu. |
| **display** / **input** | Host-side display and input backends (used by the gpu feature). |
| **utils**, **polly**, **smbios**, **arch_gen** | Shared utilities, event loop, SMBIOS table generation, architecture codegen. |
| **aws_nitro** | AWS Nitro Enclave support (separate C-based init binary). |

### How a VM starts

1. Caller invokes `krun_create_ctx()` → allocates a `KrunContext`
2. Caller configures it (vCPUs, RAM, disks, network, exec path, etc.)
3. `krun_start_enter()` calls into **vmm**, which:
   - Loads the kernel via **kernel**
   - Instantiates virtio devices from **devices**
   - Starts vCPU threads (KVM ioctls on Linux, HVF on macOS)
   - The guest boots, **init-blob**'s binary runs as PID 1, reads `.krun_config.json` from the virtiofs overlay, and execs the workload

### The virtiofs overlay (`AugmentFs`)

`src/devices/src/virtio/fs/augment_fs.rs` implements a FUSE layer that sits in front of the passthrough backend. It intercepts lookups for virtual inodes (synthetic read-only files backed by `&[u8]` slices). The init binary and optionally `.krun_config.json` are registered as virtual files here — the passthrough backend never sees them on the real filesystem.

### Feature flags

Features are additive and controlled at the `libkrun` crate level. Each device feature (`blk`, `net`, `gpu`, `snd`, `input`) enables the corresponding code in both `devices` and `vmm`. The TEE variants (`amd-sev`, `tdx`) imply `blk` + `tee` and affect the soname of the output library. The `timesync` feature propagates through `devices`, `init-blob`, and down into the `init/` binary build.

## The init binary (`init/`)

`init/` is a separate Cargo workspace (not a member of the root workspace) that builds `krun-init` — the PID-1 that runs inside every guest. It is compiled by `src/init-blob/build.rs` as a musl-linked static binary, then embedded in `init_blob::INIT_BINARY`. Build script automatically finds a musl-capable rustc (checking active toolchain first, then rustup stable toolchains).

FreeBSD guests use a separately cross-compiled binary (`init/init-freebsd`) built by `make BUILD_BSD_INIT=1`.

## Platform support

- **Linux x86_64 / aarch64**: primary targets, full feature support
- **macOS aarch64**: supported (HVF), GPU works, no blk/net/snd/input in typical use
- **FreeBSD**: experimental cross-compilation target, init ported to Rust

## Code Quality

### Commit structure

- Commits should follow the following format: <subsystem>: <commit title>. In other words, if a new `print_text()` function is added to `src/devices/src/virtio/blk/worker.rs` the commit would be formatted: `virtio/blk: add print_text() function`.
- Commits should be self-contained and isolated to individual changes that will compile and pass tests on their own.
- Avoid large commits and break down into multiple smaller commits where possible

### Think Before Coding

**Don't assume. Don't hide confusion. Surface tradeoffs.**

Before implementing:
- State your assumptions explicitly. If uncertain, ask.
- If multiple interpretations exist, present them - don't pick silently.
- If a simpler approach exists, say so. Push back when warranted.
- If something is unclear, stop. Name what's confusing. Ask.

### Simplicity First

**Minimum code that solves the problem. Nothing speculative.**

- No features beyond what was asked.
- No abstractions for single-use code.
- No "flexibility" or "configurability" that wasn't requested.
- No error handling for impossible scenarios.
- If you write 200 lines and it could be 50, rewrite it.

Ask yourself: "Would a senior engineer say this is overcomplicated?" If yes, simplify.

### Surgical Changes

**Touch only what you must. Clean up only your own mess.**

When editing existing code:
- Don't "improve" adjacent code, comments, or formatting.
- Don't refactor things that aren't broken.
- Match existing style, even if you'd do it differently.
- If you notice unrelated dead code, mention it - don't delete it.

When your changes create orphans:
- Remove imports/variables/functions that YOUR changes made unused.
- Don't remove pre-existing dead code unless asked.

The test: Every changed line should trace directly to the user's request.

### Goal-Driven Execution

**Define success criteria. Loop until verified.**

Transform tasks into verifiable goals:
- "Add validation" → "Write tests for invalid inputs, then make them pass"
- "Fix the bug" → "Write a test that reproduces it, then make it pass"
- "Refactor X" → "Ensure tests pass before and after"

For multi-step tasks, state a brief plan:
```
1. [Step] → verify: [check]
2. [Step] → verify: [check]
3. [Step] → verify: [check]
```

Strong success criteria let you loop independently. Weak criteria ("make it work") require constant clarification.
