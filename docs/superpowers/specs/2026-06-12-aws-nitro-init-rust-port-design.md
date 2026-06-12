# AWS Nitro Init: C → Rust Port Design

**Date:** 2026-06-12  
**Branch:** port-init-aws  
**Status:** Approved

## Background

`init/aws-nitro/` currently holds a statically-linked C binary that runs as PID 1 inside an AWS Nitro Enclave VM. It is compiled separately from the main libkrun library (only when `AWS_NITRO=1`) and linked against `libarchive` and `libnsm`. This design covers porting it to idiomatic Rust as a standalone crate.

## Decision: Standalone crate

The Nitro init is a separate binary artifact with no shared logic with the main init (`init/src/`). The two inits differ fundamentally in what they do:

- The main init reads a JSON config from virtiofs, mounts a normal Linux root, and execs a workload.
- The Nitro init reads a binary vsock protocol, measures the rootfs in NSM PCRs, extracts a tar archive from memory, pivot-roots into it, and spins up vsock device proxies.

Keeping them as separate crates avoids growing the main init's dependency graph with Nitro-specific deps (`vsock`, `tar`, `nitro-enclaves`) and is consistent with the existing structure: the Makefile already builds `init/aws-nitro/init` as a distinct artifact, and the host-side code lives in its own crate (`src/aws_nitro/`).

## Module layout (Approach A: 1:1 with C files)

```
init/aws-nitro/
  Cargo.toml
  src/
    main.rs          ← init sequence, rootfs_mount, launch, CID fetch,
                       app return code write, proxy orchestration,
                       SIGTERM handler, APP_PID / SIGTERM_CAUGHT statics
    archive.rs       ← archive_extract (tar crate, NSM PCR 16 measurement)
    args_reader.rs   ← EnclaveArgs struct + vsock binary read protocol
    fs.rs            ← console_init, filesystem_init, cgroups_init
    mods.rs          ← mods_load (finit_module syscall)
    device/
      mod.rs         ← Device enum + device_init dispatch, DEVICE_PROXY_READY atomic
      stdio.rs       ← app_stdio_output / app_stdio_close
      net.rs         ← tap_afvsock_init (TAP device + vsock packet proxy)
      signal.rs      ← sig_handler_init (signal forwarding proxy)
```

Each Rust module maps 1:1 to a C file, making the port reviewable by direct comparison.

## Dependencies

| Crate | Replaces | Purpose |
|---|---|---|
| `anyhow` | — | Consistent with main init; `?`-based error propagation |
| `nix` | — | mount, signal, fork, wait, ioctl, stat (same version as main init) |
| `libc` | — | `finit_module` syscall, `AF_VSOCK` constants, `ioctl` constants nix doesn't expose |
| `vsock` | — | Vsock address types and stream (already used in `src/aws_nitro/`) |
| `tar` | `libarchive` | In-memory tar extraction via `std::io::Cursor` |
| `nitro-enclaves` | `libnsm` | NSM PCR extension and locking |

`libarchive` and `libnsm` C library dependencies are eliminated.

## Public API of each module

### `args_reader`

```rust
pub struct EnclaveArgs {
    pub rootfs_archive: Vec<u8>,
    pub exec_path: String,
    pub exec_argv: Vec<String>,
    pub exec_envp: Vec<String>,
    pub network_proxy: bool,
    pub app_output: bool,
}

pub fn read(vsock_port: u32) -> anyhow::Result<EnclaveArgs>
```

Wire protocol is identical to the C: 1-byte arg ID, 8-byte little-endian length prefix, then payload. The handshake byte (`0xb7`) exchange is preserved for wire-compatibility with the host-side Rust `EnclaveArgsWriter` in `src/aws_nitro/`.

### `archive`

```rust
pub fn extract(nsm_fd: i32, archive: &[u8]) -> anyhow::Result<()>
```

Wraps `archive` in a `std::io::Cursor`, iterates tar entries, reads each file's data into a buffer, measures in 2 KiB NSM PCR 16 chunks (skipping `/etc/hostname` and `/etc/hosts`), writes to disk via `std::fs`. Functionally identical to the C.

### `fs`

```rust
pub fn console_init() -> anyhow::Result<()>
pub fn filesystem_init() -> anyhow::Result<()>
pub fn cgroups_init() -> anyhow::Result<()>
```

Uses `nix::mount` for all mounts, `std::fs` for mkdir/symlink. `console_init` redirects stdin/stdout/stderr to `/dev/console` via `nix::unistd::dup2`.

### `mods`

```rust
pub fn load() -> anyhow::Result<()>
```

Reads `/krun_linux_mods/`, calls `finit_module(2)` via `libc::syscall(libc::SYS_finit_module, ...)` for each file, unlinks it. Missing directory (`ENOENT`) is silently ignored.

### `device`

```rust
pub enum Device {
    SignalHandler,
    AppOutputStdio,
    NetTapAfVsock,
}

pub fn init(dev: Device, vsock_port: u32, shutdown_fd: RawFd) -> anyhow::Result<()>
```

- `device/stdio.rs`: `pub fn output_init(vsock_port: u32) -> anyhow::Result<()>` + `pub fn output_close()` — connects vsock, `dup2` over stdout/stderr, stores fd for later close
- `device/signal.rs`: `pub fn handler_init(vsock_port: u32, shutdown_fd: RawFd) -> anyhow::Result<()>` — forks, child polls vsock + shutdown fd, forwards signals to parent via `kill(getppid())`
- `device/net.rs`: `pub fn tap_afvsock_init(vsock_port: u32, shutdown_fd: RawFd) -> anyhow::Result<()>` — creates `/dev/net/tun`, opens TAP `tap0`, assigns IP/netmask/MAC (`5a:94:ef:e4:0c:ee`)/gateway (`172.31.10.83`), forks, child polls TAP ↔ vsock with 4-byte big-endian length-framed ethernet frames

`DEVICE_PROXY_READY` becomes a `static AtomicBool` (replacing `volatile sig_atomic_t`), set in the `SIGUSR1` handler and spin-polled in `device::init()` for proxies that fork.

## Signal handling

Signal handlers are registered via `libc::sigaction` directly (no additional crate needed). The two process-global statics in `main.rs`:

```rust
static APP_PID: AtomicI32 = AtomicI32::new(-1);
static SIGTERM_CAUGHT: AtomicBool = AtomicBool::new(false);
```

`SIGTERM` handler: if `APP_PID > 0`, forwards to the app process via `kill`, sets `SIGTERM_CAUGHT`. After `waitpid`, if `SIGTERM_CAUGHT` is set, the exit code is zeroed before forwarding to the host — identical to the C behaviour.

## Fork/exec

- `nix::unistd::fork()` → `ForkResult::Parent` / `ForkResult::Child`
- `nix::unistd::execvpe()` for the workload launch in the child
- `nix::sys::wait::waitpid()` in the parent

## tar crate vs libarchive

The `tar` crate reads from any `Read` impl. `&[u8]` wrapped in `std::io::Cursor<&[u8]>` covers the in-memory case. NSM measurement is done per-entry: read the full file data into a `Vec<u8>`, measure in 2 KiB chunks, write to disk. The C libarchive code also buffered through `archive_read_data_block` so the semantics are equivalent.

## Makefile integration

Replace the C compiler rule:

```makefile
# Before
AWS_NITRO_INIT_BINARY= init/aws-nitro/init
$(AWS_NITRO_INIT_BINARY): $(AWS_NITRO_INIT_SRC)
	$(CC) -O2 -static -s -Wall $(AWS_NITRO_INIT_LD_FLAGS) -o $@ $(AWS_NITRO_INIT_SRC) $(AWS_NITRO_INIT_LD_FLAGS)

# After
AWS_NITRO_INIT_BINARY= init/aws-nitro/init
$(AWS_NITRO_INIT_BINARY): init/aws-nitro/Cargo.toml $(shell find init/aws-nitro/src -name '*.rs')
	cargo build --release --manifest-path init/aws-nitro/Cargo.toml
	cp init/aws-nitro/target/release/krun-init-awsnitro $@
```

`AWS_NITRO_INIT_SRC` and `AWS_NITRO_INIT_LD_FLAGS` variables are removed. The C source files are deleted after the port is verified. `init/aws-nitro/Cargo.toml` is **not** added to the workspace `Cargo.toml` — it remains standalone, built only when `AWS_NITRO=1`.

## Testing

No unit tests. The binary runs as PID 1 inside a Nitro enclave — the syscall-heavy code (mounts, fork, NSM ioctls) cannot be meaningfully unit-tested without the full enclave environment. Integration testing is done by running an actual enclave, consistent with the existing `init/src/` stance.

## Out of scope

- Refactoring or reorganizing the logic beyond what is needed for a faithful port
- Sharing code with `init/src/` (the two inits remain independent)
- Any behaviour changes relative to the C original
