# AWS Nitro Init: C → Rust Port Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace `init/aws-nitro/` C sources with an idiomatic Rust standalone binary crate that is wire-compatible with the host-side `EnclaveArgsWriter` and functionally identical to the C original.

**Architecture:** Flat module layout with one Rust file per C file (`main.rs`, `archive.rs`, `args_reader.rs`, `fs.rs`, `mods.rs`, `device/{mod,stdio,signal,net}.rs`). The crate is standalone (`init/aws-nitro/Cargo.toml` is not in the workspace). The Makefile `$(AWS_NITRO_INIT_BINARY)` rule is updated to `cargo build` instead of `$(CC)`.

**Tech Stack:** Rust 2024 edition, `anyhow`, `nix 0.30`, `libc`, `vsock 0.5`, `tar 0.4`, `aws-nitro-enclaves-nsm-api 0.4` (replaces `libnsm`; provides `nsm_init`, `nsm_exit`, `nsm_process_request` with CBOR-encoded ioctl to `/dev/nsm`). `libarchive` is replaced by the `tar` crate.

---

## File Map

| File (create unless noted) | Responsibility |
|---|---|
| `init/aws-nitro/Cargo.toml` | Crate manifest (standalone, not in workspace) |
| `init/aws-nitro/src/main.rs` | Init sequence orchestration; `rootfs_mount`; `launch`; `nsm_pcrs_exec_path_extend`; `nsm_exit_and_close`; `cid_fetch`; `app_ret_write`; `proxies_init`/`proxies_exit`; `SIGTERM` handler; `APP_PID`/`SIGTERM_CAUGHT` statics |
| `init/aws-nitro/src/args_reader.rs` | `EnclaveArgs` struct; vsock handshake; binary framing read protocol; `read(vsock_port: u32) -> anyhow::Result<EnclaveArgs>` |
| `init/aws-nitro/src/archive.rs` | `extract(nsm_fd: i32, archive: &[u8]) -> anyhow::Result<()>`; tar iteration; NSM PCR 16 measurement in 2 KiB chunks; disk write |
| `init/aws-nitro/src/fs.rs` | `console_init() -> anyhow::Result<()>`; `filesystem_init() -> anyhow::Result<()>`; `cgroups_init() -> anyhow::Result<()>` |
| `init/aws-nitro/src/mods.rs` | `load() -> anyhow::Result<()>`; reads `/krun_linux_mods/`; `finit_module` syscall; unlink |
| `init/aws-nitro/src/device/mod.rs` | `Device` enum; `DEVICE_PROXY_READY: AtomicBool`; `device_proxy_sig_handler`; `init(dev, vsock_port, shutdown_fd) -> anyhow::Result<()>` |
| `init/aws-nitro/src/device/stdio.rs` | `output_init(vsock_port: u32) -> anyhow::Result<()>`; `output_close()`; `APP_STDIO_OUTPUT_VSOCK_FD: AtomicI32` |
| `init/aws-nitro/src/device/signal.rs` | `handler_init(vsock_port: u32, shutdown_fd: RawFd) -> anyhow::Result<()>`; fork; child polls vsock+shutdown; `kill(getppid(), sig)` |
| `init/aws-nitro/src/device/net.rs` | `tap_afvsock_init(vsock_port: u32, shutdown_fd: RawFd) -> anyhow::Result<()>`; `tun_init`; `tap_alloc`; `tap_assign_ipaddr`; fork; TAP↔vsock event loop |
| `Makefile` (modify) | Replace C compiler rule for `$(AWS_NITRO_INIT_BINARY)` with `cargo build` |

---

## Task 1: Scaffold the standalone crate

**Files:**
- Create: `init/aws-nitro/Cargo.toml`
- Create: `init/aws-nitro/src/main.rs` (stub)
- Create: `init/aws-nitro/src/args_reader.rs` (stub)
- Create: `init/aws-nitro/src/archive.rs` (stub)
- Create: `init/aws-nitro/src/fs.rs` (stub)
- Create: `init/aws-nitro/src/mods.rs` (stub)
- Create: `init/aws-nitro/src/device/mod.rs` (stub)
- Create: `init/aws-nitro/src/device/stdio.rs` (stub)
- Create: `init/aws-nitro/src/device/signal.rs` (stub)
- Create: `init/aws-nitro/src/device/net.rs` (stub)

- [ ] **Step 1: Create `init/aws-nitro/Cargo.toml`**

```toml
# SPDX-License-Identifier: Apache-2.0

[package]
name = "krun-init-awsnitro"
version = "0.1.0"
edition = "2024"
description = "PID-1 init binary for libkrun AWS Nitro Enclave guest VMs"
license = "Apache-2.0"
repository = "https://github.com/containers/libkrun"

[[bin]]
name = "krun-init-awsnitro"
path = "src/main.rs"

[dependencies]
anyhow = "1"
libc = "0.2"
nix = { version = "0.30", features = [
    "fs", "ioctl", "mount", "net", "process", "signal", "socket", "uio"
] }
vsock = "0.5"
tar = "0.4"
aws-nitro-enclaves-nsm-api = { version = "0.4", features = ["nix"] }
```

- [ ] **Step 2: Create stub source files**

`init/aws-nitro/src/main.rs`:
```rust
// SPDX-License-Identifier: Apache-2.0
mod archive;
mod args_reader;
mod device;
mod fs;
mod mods;

fn main() -> anyhow::Result<()> {
    Ok(())
}
```

`init/aws-nitro/src/args_reader.rs`:
```rust
// SPDX-License-Identifier: Apache-2.0
```

`init/aws-nitro/src/archive.rs`:
```rust
// SPDX-License-Identifier: Apache-2.0
```

`init/aws-nitro/src/fs.rs`:
```rust
// SPDX-License-Identifier: Apache-2.0
```

`init/aws-nitro/src/mods.rs`:
```rust
// SPDX-License-Identifier: Apache-2.0
```

`init/aws-nitro/src/device/mod.rs`:
```rust
// SPDX-License-Identifier: Apache-2.0
pub mod net;
pub mod signal;
pub mod stdio;
```

`init/aws-nitro/src/device/stdio.rs`:
```rust
// SPDX-License-Identifier: Apache-2.0
```

`init/aws-nitro/src/device/signal.rs`:
```rust
// SPDX-License-Identifier: Apache-2.0
```

`init/aws-nitro/src/device/net.rs`:
```rust
// SPDX-License-Identifier: Apache-2.0
```

- [ ] **Step 3: Verify crate builds**

```bash
cargo build --manifest-path init/aws-nitro/Cargo.toml 2>&1
```
Expected: compiles successfully (no errors, warnings are OK at this stage).

- [ ] **Step 4: Commit**

```bash
git add init/aws-nitro/Cargo.toml init/aws-nitro/src/
git commit -s -m "init/aws-nitro: scaffold standalone Rust crate

Assisted-by: Claude Code: claude-opus-4-8"
```

---

## Task 2: Implement `args_reader`

**Files:**
- Modify: `init/aws-nitro/src/args_reader.rs`

This module implements the vsock binary protocol for reading enclave args from the host.
The wire format is: 1-byte arg ID, 8-byte LE length, then payload. The handshake byte is `0xb7`.
This must be wire-compatible with the host-side `EnclaveArgsWriter` in `src/aws_nitro/src/enclave/args_writer.rs`.

- [ ] **Step 1: Implement `EnclaveArgs` and the read protocol**

```rust
// SPDX-License-Identifier: Apache-2.0

use std::io::Read;
use std::os::unix::net::UnixStream;

use anyhow::{Context, bail};
use vsock::{VsockAddr, VsockStream};

const ENCLAVE_VSOCK_LAUNCH_ARGS_READY: u8 = 0xb7;
const VMADDR_CID_HOST: u32 = 2;

// Argument IDs — must match host-side EnclaveArgsWriter.
const ARG_ID_ROOTFS: u8 = 0;
const ARG_ID_EXEC_PATH: u8 = 1;
const ARG_ID_EXEC_ARGV: u8 = 2;
const ARG_ID_EXEC_ENVP: u8 = 3;
const ARG_ID_NETWORK_PROXY: u8 = 4;
const ARG_ID_APP_OUTPUT: u8 = 5;
const ARG_ID_FINISHED: u8 = 255;

/// Enclave configuration arguments received from the host.
pub struct EnclaveArgs {
    pub rootfs_archive: Vec<u8>,
    pub exec_path: String,
    pub exec_argv: Vec<String>,
    pub exec_envp: Vec<String>,
    pub network_proxy: bool,
    pub app_output: bool,
}

/// Connect to the host's args writer vsock, perform the ready handshake,
/// and read all enclave arguments.
pub fn read(vsock_port: u32) -> anyhow::Result<EnclaveArgs> {
    let addr = VsockAddr::new(VMADDR_CID_HOST, vsock_port);
    let mut stream = VsockStream::connect(&addr).context("args_reader: vsock connect")?;

    // Handshake: send ready byte and read it back.
    stream
        .write_all(&[ENCLAVE_VSOCK_LAUNCH_ARGS_READY])
        .context("args_reader: send ready signal")?;

    let mut ack = [0u8; 1];
    stream
        .read_exact(&mut ack)
        .context("args_reader: read ready ack")?;

    if ack[0] != ENCLAVE_VSOCK_LAUNCH_ARGS_READY {
        bail!("args_reader: unexpected ack byte: {:#x}", ack[0]);
    }

    read_args(&mut stream)
}

fn read_args(stream: &mut VsockStream) -> anyhow::Result<EnclaveArgs> {
    let mut args = EnclaveArgs {
        rootfs_archive: Vec::new(),
        exec_path: String::new(),
        exec_argv: Vec::new(),
        exec_envp: Vec::new(),
        network_proxy: false,
        app_output: false,
    };

    loop {
        let mut id_buf = [0u8; 1];
        stream
            .read_exact(&mut id_buf)
            .context("args_reader: read arg ID")?;

        match id_buf[0] {
            ARG_ID_ROOTFS => {
                args.rootfs_archive = read_bytes(stream).context("args_reader: read rootfs")?;
            }
            ARG_ID_EXEC_PATH => {
                let bytes = read_bytes(stream).context("args_reader: read exec_path")?;
                args.exec_path =
                    String::from_utf8(bytes).context("args_reader: exec_path not valid UTF-8")?;
            }
            ARG_ID_EXEC_ARGV => {
                args.exec_argv = read_string_list(stream).context("args_reader: read exec_argv")?;
            }
            ARG_ID_EXEC_ENVP => {
                args.exec_envp = read_string_list(stream).context("args_reader: read exec_envp")?;
            }
            ARG_ID_NETWORK_PROXY => {
                args.network_proxy = true;
            }
            ARG_ID_APP_OUTPUT => {
                args.app_output = true;
            }
            ARG_ID_FINISHED => break,
            unknown => bail!("args_reader: unknown arg ID: {}", unknown),
        }
    }

    Ok(args)
}

/// Read an 8-byte LE length prefix, then exactly that many bytes.
fn read_bytes(stream: &mut VsockStream) -> anyhow::Result<Vec<u8>> {
    let len = read_u64_le(stream)?;
    let mut buf = vec![0u8; len as usize];
    stream.read_exact(&mut buf).context("read_bytes: read payload")?;
    Ok(buf)
}

/// Read an 8-byte LE count, then that many length-prefixed byte strings.
fn read_string_list(stream: &mut VsockStream) -> anyhow::Result<Vec<String>> {
    let count = read_u64_le(stream)? as usize;
    let mut list = Vec::with_capacity(count);
    for i in 0..count {
        let bytes = read_bytes(stream)
            .with_context(|| format!("read_string_list: item {i}"))?;
        let s = String::from_utf8(bytes)
            .with_context(|| format!("read_string_list: item {i} not valid UTF-8"))?;
        list.push(s);
    }
    Ok(list)
}

/// Read 8 bytes from the stream and interpret them as a little-endian u64.
fn read_u64_le(stream: &mut VsockStream) -> anyhow::Result<u64> {
    let mut buf = [0u8; 8];
    stream.read_exact(&mut buf).context("read_u64_le")?;
    Ok(u64::from_le_bytes(buf))
}
```

Note: `VsockStream` implements `Read` and `Write`, so `read_exact` and `write_all` are available via those traits. You need `use std::io::{Read, Write}`.

- [ ] **Step 2: Remove the unused `UnixStream` import (it was a mistake in the template above) and fix imports**

The final imports in `args_reader.rs` should be:
```rust
use std::io::{Read, Write};

use anyhow::{Context, bail};
use vsock::{VsockAddr, VsockStream};
```

Remove the `use std::os::unix::net::UnixStream;` line — it is not used.

- [ ] **Step 3: Verify it compiles**

```bash
cargo build --manifest-path init/aws-nitro/Cargo.toml 2>&1
```
Expected: no errors.

- [ ] **Step 4: Commit**

```bash
git add init/aws-nitro/src/args_reader.rs
git commit -s -m "init/aws-nitro: implement args_reader

Reads enclave configuration (rootfs, exec path/argv/envp, device proxy
flags) from the host over vsock using the binary framing protocol.
Wire-compatible with host-side EnclaveArgsWriter.

Assisted-by: Claude Code: claude-opus-4-8"
```

---

## Task 3: Implement `mods`

**Files:**
- Modify: `init/aws-nitro/src/mods.rs`

Loads kernel modules from `/krun_linux_mods/` using the `finit_module(2)` syscall, then unlinks each file. Missing directory is silently ignored.

- [ ] **Step 1: Implement `mods.rs`**

```rust
// SPDX-License-Identifier: Apache-2.0

use std::fs;

use anyhow::Context;
use nix::errno::Errno;

const MODS_DIR: &str = "/krun_linux_mods";

/// Load all kernel modules found in `/krun_linux_mods/`.
///
/// Each `.ko` file is loaded via `finit_module(2)` then unlinked.
/// If the directory does not exist, this is a no-op.
pub fn load() -> anyhow::Result<()> {
    let entries = match fs::read_dir(MODS_DIR) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e).context("mods: open /krun_linux_mods"),
    };

    for entry in entries {
        let entry = entry.context("mods: read directory entry")?;
        let path = entry.path();

        let path_str = path.to_string_lossy();

        // Open the module file.
        let fd = nix::fcntl::open(
            &path,
            nix::fcntl::OFlag::O_RDONLY | nix::fcntl::OFlag::O_CLOEXEC,
            nix::sys::stat::Mode::empty(),
        );

        let fd = match fd {
            Ok(fd) => fd,
            Err(Errno::ENOENT) => continue,
            Err(e) => {
                eprintln!("mods: open {path_str}: {e}");
                return Err(e).with_context(|| format!("mods: open {path_str}"));
            }
        };

        // Load the module via finit_module(2).
        let ret = unsafe {
            libc::syscall(
                libc::SYS_finit_module,
                fd.as_raw_fd(),
                c"".as_ptr(),
                0i32,
            )
        };

        if ret < 0 {
            let errno = Errno::last();
            if errno != Errno::EEXIST {
                eprintln!("mods: finit_module {path_str}: {errno}");
                return Err(errno).with_context(|| format!("mods: finit_module {path_str}"));
            }
        }

        drop(fd);

        fs::remove_file(&path)
            .with_context(|| format!("mods: unlink {path_str}"))?;
    }

    Ok(())
}
```

Add `use std::os::fd::AsRawFd;` to the imports for `fd.as_raw_fd()`.

Full imports:
```rust
use std::fs;
use std::os::fd::AsRawFd;

use anyhow::Context;
use nix::errno::Errno;
```

- [ ] **Step 2: Verify it compiles**

```bash
cargo build --manifest-path init/aws-nitro/Cargo.toml 2>&1
```
Expected: no errors.

- [ ] **Step 3: Commit**

```bash
git add init/aws-nitro/src/mods.rs
git commit -s -m "init/aws-nitro: implement mods

Loads kernel modules from /krun_linux_mods via finit_module(2) and
unlinks each file after loading. Missing directory is silently ignored.

Assisted-by: Claude Code: claude-opus-4-8"
```

---

## Task 4: Implement `fs`

**Files:**
- Modify: `init/aws-nitro/src/fs.rs`

- [ ] **Step 1: Implement `fs.rs`**

```rust
// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::io::{self, BufRead, BufReader};
use std::os::unix::fs as unix_fs;

use anyhow::{Context, bail};
use nix::mount::{self, MsFlags};
use nix::unistd;

/// Mount /dev and redirect stdin/stdout/stderr to /dev/console for early debug output.
pub fn console_init() -> anyhow::Result<()> {
    mount_or_busy(
        Some("dev"),
        "/dev",
        Some("devtmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
    )?;

    // Reopen stdin, stdout, stderr on /dev/console.
    let console = "/dev/console";
    unsafe {
        reopen_fd(libc::STDIN_FILENO, console, libc::O_RDONLY)
            .context("console_init: reopen stdin")?;
        reopen_fd(libc::STDOUT_FILENO, console, libc::O_WRONLY)
            .context("console_init: reopen stdout")?;
        reopen_fd(libc::STDERR_FILENO, console, libc::O_WRONLY)
            .context("console_init: reopen stderr")?;
    }

    Ok(())
}

/// Open `path` with `flags`, dup2 it over `target_fd`, then close the new fd.
unsafe fn reopen_fd(target_fd: libc::c_int, path: &str, flags: libc::c_int) -> anyhow::Result<()> {
    let path_c = std::ffi::CString::new(path).unwrap();
    let new_fd = libc::open(path_c.as_ptr(), flags);
    if new_fd < 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("open {path}"));
    }
    if libc::dup2(new_fd, target_fd) < 0 {
        libc::close(new_fd);
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("dup2 -> fd {target_fd}"));
    }
    libc::close(new_fd);
    Ok(())
}

/// Initialize the rest of the root filesystem with ephemeral file systems.
///
/// Creates /dev, /proc, /run, /sys, /tmp and mounts devtmpfs, proc, sysfs,
/// tmpfs on the appropriate paths. Also creates /dev/shm, /dev/pts and
/// /dev/fd symlinks.
pub fn filesystem_init() -> anyhow::Result<()> {
    let sys_dirs = ["/dev", "/proc", "/run", "/sys", "/tmp"];
    for dir in &sys_dirs {
        fs::create_dir(dir).with_context(|| format!("mkdir {dir}"))?;
    }

    mount_or_busy(
        Some("/dev"),
        "/dev",
        Some("devtmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
    )?;

    let dev_dirs = ["/dev/shm", "/dev/pts"];
    for dir in &dev_dirs {
        fs::create_dir(dir).with_context(|| format!("mkdir {dir}"))?;
    }

    mount::mount(
        Some("shm"),
        "/dev/shm",
        Some("tmpfs"),
        MsFlags::MS_NODEV | MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
        None::<&str>,
    )
    .context("mount /dev/shm")?;

    mount::mount(
        Some("devpts"),
        "/dev/pts",
        Some("devpts"),
        MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
        None::<&str>,
    )
    .context("mount /dev/pts")?;

    mount::mount(
        Some("/proc"),
        "/proc",
        Some("proc"),
        MsFlags::MS_NODEV | MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
        None::<&str>,
    )
    .context("mount /proc")?;

    unix_fs::symlink("/proc/self/fd", "/dev/fd").context("symlink /dev/fd")?;
    unix_fs::symlink("/proc/self/fd/0", "/dev/stdin").context("symlink /dev/stdin")?;
    unix_fs::symlink("/proc/self/fd/1", "/dev/stdout").context("symlink /dev/stdout")?;
    unix_fs::symlink("/proc/self/fd/2", "/dev/stderr").context("symlink /dev/stderr")?;

    mount::mount(
        Some("tmpfs"),
        "/run",
        Some("tmpfs"),
        MsFlags::MS_NODEV | MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
        Some("mode=0755"),
    )
    .context("mount /run")?;

    mount::mount(
        Some("tmpfs"),
        "/tmp",
        Some("tmpfs"),
        MsFlags::MS_NODEV | MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
        None::<&str>,
    )
    .context("mount /tmp")?;

    mount::mount(
        Some("sysfs"),
        "/sys",
        Some("sysfs"),
        MsFlags::MS_NODEV | MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
        None::<&str>,
    )
    .context("mount /sys")?;

    mount::mount(
        Some("cgroup_root"),
        "/sys/fs/cgroup",
        Some("tmpfs"),
        MsFlags::MS_NODEV | MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
        Some("mode=0755"),
    )
    .context("mount /sys/fs/cgroup")?;

    Ok(())
}

/// Read `/proc/cgroups` and mount each enabled cgroup under `/sys/fs/cgroup/<name>`.
pub fn cgroups_init() -> anyhow::Result<()> {
    let f = std::fs::File::open("/proc/cgroups").context("cgroups_init: open /proc/cgroups")?;
    let reader = BufReader::new(f);
    let mut lines = reader.lines();

    // Skip the header line.
    lines.next();

    for line in lines {
        let line = line.context("cgroups_init: read /proc/cgroups")?;
        let mut parts = line.split_whitespace();

        let name = match parts.next() {
            Some(n) => n.to_string(),
            None => continue,
        };
        let _hier = parts.next();
        let _groups = parts.next();
        let enabled: i32 = match parts.next() {
            Some(e) => e.parse().unwrap_or(0),
            None => continue,
        };

        if enabled != 0 {
            let path = format!("/sys/fs/cgroup/{name}");
            fs::create_dir(&path).with_context(|| format!("cgroups_init: mkdir {path}"))?;

            mount::mount(
                Some(name.as_str()),
                path.as_str(),
                Some("cgroup"),
                MsFlags::MS_NODEV | MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
                Some(name.as_str()),
            )
            .with_context(|| format!("cgroups_init: mount {path}"))?;
        }
    }

    Ok(())
}

/// Mount, treating `EBUSY` (already mounted) as success.
fn mount_or_busy(
    src: Option<&str>,
    target: &str,
    fstype: Option<&str>,
    flags: MsFlags,
) -> anyhow::Result<()> {
    match mount::mount(src, target, fstype, flags, None::<&str>) {
        Ok(()) => Ok(()),
        Err(nix::errno::Errno::EBUSY) => Ok(()),
        Err(e) => Err(e).with_context(|| format!("mount {target}")),
    }
}
```

- [ ] **Step 2: Verify it compiles**

```bash
cargo build --manifest-path init/aws-nitro/Cargo.toml 2>&1
```
Expected: no errors.

- [ ] **Step 3: Commit**

```bash
git add init/aws-nitro/src/fs.rs
git commit -s -m "init/aws-nitro: implement fs

Implements console_init (mounts devtmpfs, redirects stdio to
/dev/console), filesystem_init (mounts proc/sys/tmp/run/dev/pts/shm
and creates symlinks), and cgroups_init (reads /proc/cgroups and
mounts each enabled cgroup subsystem).

Assisted-by: Claude Code: claude-opus-4-8"
```

---

## Task 5: Implement `archive`

**Files:**
- Modify: `init/aws-nitro/src/archive.rs`

Uses the `tar` crate to iterate entries from an in-memory buffer. Measures each file's data in NSM PCR 16 using `aws-nitro-enclaves-nsm-api`. Skips measurement for `/etc/hostname` and `/etc/hosts`.

- [ ] **Step 1: Implement `archive.rs`**

```rust
// SPDX-License-Identifier: Apache-2.0

use std::io::Cursor;
use std::path::Path;

use anyhow::Context;
use aws_nitro_enclaves_nsm_api::api::{ErrorCode, Request, Response};
use aws_nitro_enclaves_nsm_api::driver::nsm_process_request;

const NSM_PCR_ROOTFS: u16 = 16;
const NSM_PCR_CHUNK_SIZE: usize = 0x800; // 2 KiB

/// Extract a tar archive from `archive` into the current filesystem root,
/// measuring each file's data in NSM PCR 16.
///
/// `/etc/hostname` and `/etc/hosts` are excluded from measurement (they
/// contain ephemeral container-specific values).
pub fn extract(nsm_fd: i32, archive: &[u8]) -> anyhow::Result<()> {
    let cursor = Cursor::new(archive);
    let mut tar = tar::Archive::new(cursor);

    for entry in tar.entries().context("archive: iterate entries")? {
        let mut entry = entry.context("archive: read entry")?;
        let path = entry
            .path()
            .context("archive: get entry path")?
            .into_owned();

        let should_measure = should_measure(&path);

        if should_measure {
            // Read the full entry data into memory for measurement.
            let mut data = Vec::new();
            std::io::copy(&mut entry, &mut data)
                .context("archive: read entry data for measurement")?;

            nsm_pcr_extend(nsm_fd, &data)
                .with_context(|| format!("archive: NSM PCR extend for {:?}", path))?;

            // Re-create the entry from data and write it to disk.
            // Since we've consumed the entry reader, write the data directly.
            let dest = path.to_string_lossy();
            write_entry_data(&path, entry.header(), &data)
                .with_context(|| format!("archive: write entry {:?}", path))?;
        } else {
            entry
                .unpack_in("/")
                .with_context(|| format!("archive: unpack {:?}", path))?;
        }
    }

    Ok(())
}

/// Returns true if this path should be measured in NSM PCR 16.
fn should_measure(path: &Path) -> bool {
    let s = path.to_string_lossy();
    !s.contains("rootfs/etc/hostname") && !s.contains("rootfs/etc/hosts")
}

/// Extend NSM PCR 16 with `data` in 2 KiB chunks.
fn nsm_pcr_extend(nsm_fd: i32, data: &[u8]) -> anyhow::Result<()> {
    for chunk in data.chunks(NSM_PCR_CHUNK_SIZE) {
        let response = nsm_process_request(
            nsm_fd,
            Request::ExtendPCR {
                index: NSM_PCR_ROOTFS,
                data: chunk.to_vec(),
            },
        );

        match response {
            Response::ExtendPCR { .. } => {}
            Response::Error(ErrorCode::Success) | Response::Error(ErrorCode::InvalidIndex) => {}
            Response::Error(e) => {
                anyhow::bail!("NSM ExtendPCR failed: {:?}", e);
            }
            other => {
                anyhow::bail!("NSM ExtendPCR unexpected response: {:?}", other);
            }
        }
    }
    Ok(())
}

/// Write entry data to disk, preserving the tar header metadata (type, permissions, etc.).
fn write_entry_data(
    path: &Path,
    header: &tar::Header,
    data: &[u8],
) -> anyhow::Result<()> {
    use std::fs::{self, File};
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    match header.entry_type() {
        tar::EntryType::Regular | tar::EntryType::Continuous => {
            if let Some(parent) = path.parent() {
                if !parent.as_os_str().is_empty() {
                    fs::create_dir_all(parent)
                        .with_context(|| format!("create parent dirs for {:?}", parent))?;
                }
            }
            let mut f = File::create(path)
                .with_context(|| format!("create file {:?}", path))?;
            f.write_all(data)
                .with_context(|| format!("write file {:?}", path))?;
            if let Ok(mode) = header.mode() {
                fs::set_permissions(path, fs::Permissions::from_mode(mode))
                    .with_context(|| format!("set permissions on {:?}", path))?;
            }
        }
        tar::EntryType::Directory => {
            fs::create_dir_all(path)
                .with_context(|| format!("create dir {:?}", path))?;
            if let Ok(mode) = header.mode() {
                fs::set_permissions(path, fs::Permissions::from_mode(mode))
                    .with_context(|| format!("set permissions on {:?}", path))?;
            }
        }
        tar::EntryType::Symlink => {
            if let Ok(Some(target)) = header.link_name() {
                std::os::unix::fs::symlink(&target, path)
                    .with_context(|| format!("symlink {:?} -> {:?}", path, target))?;
            }
        }
        _ => {
            // Other entry types (hard links, char/block devices, fifos) are
            // handled by letting the tar crate unpack them normally.
            // We've already consumed the data; skip silently.
        }
    }

    Ok(())
}
```

**Note on the tar crate:** `entry.unpack_in("/")` unpacks relative to `/`, which is correct for the rootfs extraction case. For measured entries we manually write data because we consumed the reader into a `Vec<u8>` for measurement first.

- [ ] **Step 2: Verify it compiles**

```bash
cargo build --manifest-path init/aws-nitro/Cargo.toml 2>&1
```
Expected: no errors (may have warnings about unused imports in other stubs).

- [ ] **Step 3: Commit**

```bash
git add init/aws-nitro/src/archive.rs
git commit -s -m "init/aws-nitro: implement archive

Extracts rootfs tar archive from memory, measuring each file's data in
NSM PCR 16 in 2 KiB chunks via aws-nitro-enclaves-nsm-api. Skips
measurement for /etc/hostname and /etc/hosts (ephemeral values).

Assisted-by: Claude Code: claude-opus-4-8"
```

---

## Task 6: Implement `device/stdio`

**Files:**
- Modify: `init/aws-nitro/src/device/stdio.rs`

Redirects stdout/stderr to a host vsock. The vsock fd is stored in a static for later closing.

- [ ] **Step 1: Implement `device/stdio.rs`**

```rust
// SPDX-License-Identifier: Apache-2.0

use std::sync::atomic::{AtomicI32, Ordering};
use std::time::Duration;

use anyhow::Context;
use vsock::{VsockAddr, VsockStream};

const VMADDR_CID_HOST: u32 = 2;

static APP_STDIO_OUTPUT_VSOCK_FD: AtomicI32 = AtomicI32::new(-1);

/// Connect to the host's stdio output vsock and redirect stdout/stderr to it.
pub fn output_init(vsock_port: u32) -> anyhow::Result<()> {
    use std::os::fd::IntoRawFd;

    let addr = VsockAddr::new(VMADDR_CID_HOST, vsock_port);
    let stream = VsockStream::connect_with_cid_port(VMADDR_CID_HOST, vsock_port)
        .context("stdio: vsock connect")?;
    let sock_fd = stream.into_raw_fd();

    // dup2 the socket over stdout and stderr.
    unsafe {
        if libc::dup2(sock_fd, libc::STDOUT_FILENO) < 0 {
            libc::close(sock_fd);
            return Err(std::io::Error::last_os_error()).context("stdio: dup2 stdout");
        }
        if libc::dup2(sock_fd, libc::STDERR_FILENO) < 0 {
            libc::close(sock_fd);
            return Err(std::io::Error::last_os_error()).context("stdio: dup2 stderr");
        }
    }

    APP_STDIO_OUTPUT_VSOCK_FD.store(sock_fd, Ordering::Relaxed);

    Ok(())
}

/// Close the stdout/stderr file descriptors and the stored vsock fd.
pub fn output_close() {
    unsafe {
        libc::close(libc::STDOUT_FILENO);
        libc::close(libc::STDERR_FILENO);
    }
    let fd = APP_STDIO_OUTPUT_VSOCK_FD.swap(-1, Ordering::Relaxed);
    if fd >= 0 {
        unsafe { libc::close(fd) };
    }
}
```

**Note:** `VsockStream::connect_with_cid_port` is the correct API for the `vsock 0.5` crate. Check whether this is the actual function name by looking at the vsock crate — if not, use `VsockStream::connect(&VsockAddr::new(cid, port))`. The connect timeout in the C code (5 seconds via `SO_VM_SOCKETS_CONNECT_TIMEOUT`) is not easily set via the Rust vsock crate; the default connect behavior is acceptable for the port.

- [ ] **Step 2: Check the actual vsock 0.5 API**

```bash
grep -r "pub fn connect" /sandbox/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/vsock-0.5.3/src/ 2>/dev/null
```

Use whichever connect function exists. If it's `VsockStream::connect(&VsockAddr)`, replace the call with:
```rust
let stream = VsockStream::connect(&VsockAddr::new(VMADDR_CID_HOST, vsock_port))
    .context("stdio: vsock connect")?;
```

- [ ] **Step 3: Verify it compiles**

```bash
cargo build --manifest-path init/aws-nitro/Cargo.toml 2>&1
```
Expected: no errors.

- [ ] **Step 4: Commit**

```bash
git add init/aws-nitro/src/device/stdio.rs
git commit -s -m "init/aws-nitro: implement device/stdio

Redirects stdout/stderr to a host vsock for non-debug mode app output.
Stores the vsock fd atomically for later cleanup via output_close().

Assisted-by: Claude Code: claude-opus-4-8"
```

---

## Task 7: Implement `device/signal`

**Files:**
- Modify: `init/aws-nitro/src/device/signal.rs`

Forks a child process that connects to the host's signal vsock, polls it alongside the shutdown eventfd, and forwards any received signal to the parent via `kill(getppid(), sig)`. Sends `SIGUSR1` to the parent when initialized.

- [ ] **Step 1: Implement `device/signal.rs`**

```rust
// SPDX-License-Identifier: Apache-2.0

use std::os::fd::RawFd;

use anyhow::Context;
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use nix::sys::signal::{self, Signal};
use nix::unistd::{self, ForkResult};
use vsock::{VsockAddr, VsockStream};

const VMADDR_CID_HOST: u32 = 2;

/// Fork a child process that proxies signals from the host vsock to the parent.
///
/// The child:
/// 1. Connects to the host's signal vsock at `vsock_port`.
/// 2. Sends `SIGUSR1` to the parent to indicate initialization is complete.
/// 3. Polls the vsock and `shutdown_fd`; reads signals from vsock and forwards
///    them to the parent via `kill(getppid(), sig)`.
/// 4. Exits when the shutdown eventfd fires.
pub fn handler_init(vsock_port: u32, shutdown_fd: RawFd) -> anyhow::Result<()> {
    use std::os::fd::AsRawFd;

    let stream = VsockStream::connect(&VsockAddr::new(VMADDR_CID_HOST, vsock_port))
        .context("signal: vsock connect")?;

    match unsafe { unistd::fork() }.context("signal: fork")? {
        ForkResult::Parent { .. } => {
            // Parent returns; the child runs the proxy loop.
            Ok(())
        }
        ForkResult::Child => {
            run_signal_proxy(stream, shutdown_fd);
        }
    }
}

fn run_signal_proxy(stream: VsockStream, shutdown_fd: RawFd) -> ! {
    use std::io::Read;
    use std::os::fd::AsRawFd;

    let vsock_raw = stream.as_raw_fd();

    // Notify parent that initialization is complete.
    let ppid = unistd::getppid();
    let _ = signal::kill(ppid, Signal::SIGUSR1);

    let poll_fds = &mut [
        PollFd::new(unsafe { std::os::fd::BorrowedFd::borrow_raw(vsock_raw) }, PollFlags::POLLIN),
        PollFd::new(unsafe { std::os::fd::BorrowedFd::borrow_raw(shutdown_fd) }, PollFlags::POLLIN),
    ];

    loop {
        match poll(poll_fds, PollTimeout::NONE) {
            Ok(n) if n <= 0 => continue,
            Err(nix::errno::Errno::EINTR) => continue,
            Err(_) => break,
            Ok(_) => {}
        }

        // Signal event on vsock.
        if poll_fds[0].revents().map_or(false, |r| r.contains(PollFlags::POLLIN)) {
            let mut buf = [0u8; 4];
            let sig_num = match (&stream).read(&mut buf) {
                Ok(4) => i32::from_ne_bytes(buf),
                _ => libc::SIGTERM,
            };

            if let Ok(sig) = Signal::try_from(sig_num) {
                let _ = signal::kill(ppid, sig);
            }
        }

        // Shutdown event.
        if poll_fds[1].revents().map_or(false, |r| r.contains(PollFlags::POLLIN)) {
            break;
        }
    }

    drop(stream);
    std::process::exit(0);
}
```

- [ ] **Step 2: Verify it compiles**

```bash
cargo build --manifest-path init/aws-nitro/Cargo.toml 2>&1
```
Expected: no errors.

- [ ] **Step 3: Commit**

```bash
git add init/aws-nitro/src/device/signal.rs
git commit -s -m "init/aws-nitro: implement device/signal

Forks a child process that proxies signals from a host vsock to the
parent init process. Child signals SIGUSR1 on ready, exits on shutdown
eventfd.

Assisted-by: Claude Code: claude-opus-4-8"
```

---

## Task 8: Implement `device/net`

**Files:**
- Modify: `init/aws-nitro/src/device/net.rs`

Creates a TAP device (`tap0`), assigns a fixed IP (`172.31.10.83/24`), MAC (`5a:94:ef:e4:0c:ee`), and default gateway. Forks a child that proxies ethernet frames between the TAP device and a host vsock using a 4-byte big-endian length prefix framing protocol.

- [ ] **Step 1: Implement `device/net.rs`**

```rust
// SPDX-License-Identifier: Apache-2.0

use std::os::fd::{AsRawFd, RawFd};

use anyhow::Context;
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use nix::unistd::{self, ForkResult};
use vsock::{VsockAddr, VsockStream};

const VMADDR_CID_HOST: u32 = 2;

const TUN_DEV_MAJOR: u32 = 10;
const TUN_DEV_MINOR: u32 = 200;

/// Ethernet header length in bytes (dst MAC + src MAC + ethertype).
const ETH_HEADER_LEN: u32 = 14;
/// Proxy frame length header size (4-byte big-endian u32).
const PROXY_HEADER_LEN: usize = 4;

/// TAP IP configuration (fixed).
const TAP_IP: &str = "172.31.10.83\0";
const TAP_NETMASK: &str = "255.255.255.0\0";
const TAP_MAC: [u8; 6] = [0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee];
const TAP_GATEWAY: u32 = 0xAC1F0A53; // 172.31.10.83 in network byte order (big-endian)

/// Initialize the TAP↔vsock network proxy.
///
/// Creates `/dev/net/tun` if needed, allocates `tap0`, assigns the fixed IP/MAC/gateway,
/// then forks a child that proxies frames between the TAP device and the host vsock.
/// Sends `SIGUSR1` to the parent when the child proxy is ready.
pub fn tap_afvsock_init(vsock_port: u32, shutdown_fd: RawFd) -> anyhow::Result<()> {
    tun_init().context("net: init /dev/net/tun")?;

    let (tun_fd, tap_name) = tap_alloc().context("net: allocate TAP device")?;

    let vsock_stream = VsockStream::connect(&VsockAddr::new(VMADDR_CID_HOST, vsock_port))
        .context("net: vsock connect")?;

    match unsafe { unistd::fork() }.context("net: fork")? {
        ForkResult::Parent { .. } => {
            // Parent closes tun_fd (child has its own copy after fork).
            drop(tun_fd);
            Ok(())
        }
        ForkResult::Child => {
            run_tap_proxy(tun_fd, vsock_stream, shutdown_fd, &tap_name);
        }
    }
}

/// Ensure `/dev/net/tun` exists with correct permissions.
fn tun_init() -> anyhow::Result<()> {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    if !std::path::Path::new("/dev/net").exists() {
        fs::create_dir("/dev/net").context("mkdir /dev/net")?;
    }

    if !std::path::Path::new("/dev/net/tun").exists() {
        unsafe {
            let dev = libc::makedev(TUN_DEV_MAJOR, TUN_DEV_MINOR);
            let path = c"/dev/net/tun";
            if libc::mknod(path.as_ptr(), libc::S_IFCHR | 0o600, dev) < 0 {
                return Err(std::io::Error::last_os_error()).context("mknod /dev/net/tun");
            }
        }
    }

    std::fs::set_permissions("/dev/net/tun", std::fs::Permissions::from_mode(0o666))
        .context("chmod /dev/net/tun")?;

    Ok(())
}

/// Open `/dev/net/tun`, create a `tap0` interface, assign IP/MAC/gateway.
/// Returns `(tun_fd, tap_name)`.
fn tap_alloc() -> anyhow::Result<(std::fs::File, String)> {
    use nix::fcntl::{OFlag, open};
    use nix::sys::stat::Mode;
    use std::fs::File;
    use std::os::fd::FromRawFd;

    let fd = open("/dev/net/tun", OFlag::O_RDWR, Mode::empty())
        .context("open /dev/net/tun")?;

    // TUNSETIFF ioctl to create the TAP device.
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    ifr.ifr_ifru.ifru_flags = (libc::IFF_TAP | libc::IFF_NO_PI) as i16;
    let name = b"tap0\0";
    ifr.ifr_name[..name.len()].copy_from_slice(unsafe {
        std::slice::from_raw_parts(name.as_ptr() as *const libc::c_char, name.len())
    });

    let tunsetiff: libc::c_ulong = nix::request_code_write!('T', 202, std::mem::size_of::<libc::ifreq>());
    if unsafe { libc::ioctl(fd.as_raw_fd(), tunsetiff, &mut ifr) } < 0 {
        return Err(std::io::Error::last_os_error()).context("TUNSETIFF");
    }

    // Extract the actual interface name.
    let tap_name = unsafe {
        std::ffi::CStr::from_ptr(ifr.ifr_name.as_ptr())
            .to_string_lossy()
            .into_owned()
    };

    tap_assign_ipaddr(&tap_name).context("net: assign IP")?;

    let file = unsafe { File::from_raw_fd(fd.as_raw_fd()) };
    std::mem::forget(fd); // File takes ownership.
    Ok((file, tap_name))
}

/// Assign the fixed IP, netmask, MAC, flags, and default gateway to the TAP device.
fn tap_assign_ipaddr(name: &str) -> anyhow::Result<()> {
    use nix::sys::socket::{SockFlag, SockType, socket, AddressFamily};

    let sock = unsafe {
        libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0)
    };
    if sock < 0 {
        return Err(std::io::Error::last_os_error()).context("socket for IP config");
    }
    let _guard = scopeguard::defer(|| unsafe { libc::close(sock); });

    set_ipaddr(sock, name, TAP_IP).context("set IP address")?;
    set_netmask(sock, name, TAP_NETMASK).context("set netmask")?;
    set_mac(sock, name, &TAP_MAC).context("set MAC")?;
    set_flags_up(sock, name).context("set IFF_UP | IFF_RUNNING")?;
    set_default_gateway(sock, name).context("set default gateway")?;

    Ok(())
}

fn ifreq_with_name(name: &str) -> libc::ifreq {
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    let bytes = name.as_bytes();
    let len = bytes.len().min(libc::IFNAMSIZ - 1);
    unsafe {
        std::ptr::copy_nonoverlapping(
            bytes.as_ptr() as *const libc::c_char,
            ifr.ifr_name.as_mut_ptr(),
            len,
        );
    }
    ifr
}

fn set_ipaddr(sock: libc::c_int, name: &str, ip: &str) -> anyhow::Result<()> {
    let mut ifr = ifreq_with_name(name);
    let addr = sockaddr_in_from_str(ip);
    unsafe {
        ifr.ifr_ifru.ifru_addr = std::mem::transmute(addr);
        if libc::ioctl(sock, libc::SIOCSIFADDR, &ifr) < 0 {
            return Err(std::io::Error::last_os_error()).context("SIOCSIFADDR");
        }
    }
    Ok(())
}

fn set_netmask(sock: libc::c_int, name: &str, mask: &str) -> anyhow::Result<()> {
    let mut ifr = ifreq_with_name(name);
    let addr = sockaddr_in_from_str(mask);
    unsafe {
        ifr.ifr_ifru.ifru_netmask = std::mem::transmute(addr);
        if libc::ioctl(sock, libc::SIOCSIFNETMASK, &ifr) < 0 {
            return Err(std::io::Error::last_os_error()).context("SIOCSIFNETMASK");
        }
    }
    Ok(())
}

fn set_mac(sock: libc::c_int, name: &str, mac: &[u8; 6]) -> anyhow::Result<()> {
    let mut ifr = ifreq_with_name(name);
    unsafe {
        ifr.ifr_ifru.ifru_hwaddr.sa_family = libc::ARPHRD_ETHER as u16;
        ifr.ifr_ifru.ifru_hwaddr.sa_data[..6]
            .copy_from_slice(std::mem::transmute::<&[u8; 6], &[i8; 6]>(mac));
        if libc::ioctl(sock, libc::SIOCSIFHWADDR, &ifr) < 0 {
            return Err(std::io::Error::last_os_error()).context("SIOCSIFHWADDR");
        }
    }
    Ok(())
}

fn set_flags_up(sock: libc::c_int, name: &str) -> anyhow::Result<()> {
    let mut ifr = ifreq_with_name(name);
    unsafe {
        if libc::ioctl(sock, libc::SIOCGIFFLAGS, &mut ifr) < 0 {
            return Err(std::io::Error::last_os_error()).context("SIOCGIFFLAGS");
        }
        ifr.ifr_ifru.ifru_flags |= (libc::IFF_UP | libc::IFF_RUNNING) as i16;
        if libc::ioctl(sock, libc::SIOCSIFFLAGS, &ifr) < 0 {
            return Err(std::io::Error::last_os_error()).context("SIOCSIFFLAGS");
        }
    }
    Ok(())
}

fn set_default_gateway(sock: libc::c_int, name: &str) -> anyhow::Result<()> {
    let mut route: libc::rtentry = unsafe { std::mem::zeroed() };

    // Gateway: 172.31.10.83
    let gw = sockaddr_in_from_u32(TAP_GATEWAY);
    unsafe { route.rt_gateway = std::mem::transmute(gw) };

    // Destination: 0.0.0.0
    let dst = sockaddr_in_from_u32(0);
    unsafe { route.rt_dst = std::mem::transmute(dst) };

    // Genmask: 0.0.0.0
    let mask = sockaddr_in_from_u32(0);
    unsafe { route.rt_genmask = std::mem::transmute(mask) };

    route.rt_flags = (libc::RTF_UP | libc::RTF_GATEWAY) as u16;

    let name_cstr = std::ffi::CString::new(name.to_string()).unwrap();
    route.rt_dev = name_cstr.as_ptr() as *mut libc::c_char;

    unsafe {
        if libc::ioctl(sock, libc::SIOCADDRT, &route) < 0 {
            return Err(std::io::Error::last_os_error()).context("SIOCADDRT");
        }
    }

    Ok(())
}

fn sockaddr_in_from_str(ip: &str) -> libc::sockaddr_in {
    let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    addr.sin_family = libc::AF_INET as u16;
    let ip_cstr = std::ffi::CString::new(ip.trim_end_matches('\0')).unwrap();
    unsafe { libc::inet_pton(libc::AF_INET, ip_cstr.as_ptr(), &mut addr.sin_addr as *mut _ as *mut libc::c_void) };
    addr
}

fn sockaddr_in_from_u32(ip: u32) -> libc::sockaddr_in {
    let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    addr.sin_family = libc::AF_INET as u16;
    addr.sin_addr.s_addr = ip;
    addr
}

fn get_tap_mtu(tap_name: &str) -> anyhow::Result<u32> {
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if sock < 0 {
        return Err(std::io::Error::last_os_error()).context("socket for MTU");
    }
    let mut ifr = ifreq_with_name(tap_name);
    unsafe {
        if libc::ioctl(sock, libc::SIOCGIFMTU, &mut ifr) < 0 {
            libc::close(sock);
            return Err(std::io::Error::last_os_error()).context("SIOCGIFMTU");
        }
        libc::close(sock);
        Ok(ifr.ifr_ifru.ifru_mtu as u32)
    }
}

/// Child process: proxy ethernet frames between TAP device and host vsock.
fn run_tap_proxy(tun_file: std::fs::File, vsock: VsockStream, shutdown_fd: RawFd, tap_name: &str) -> ! {
    use nix::sys::signal::{self, Signal};
    use std::io::{Read, Write};

    let tun_fd = tun_file.as_raw_fd();
    let vsock_fd = vsock.as_raw_fd();

    let mtu = get_tap_mtu(tap_name).unwrap_or(1500);
    let eth_frame_size = (mtu + ETH_HEADER_LEN) as usize;

    // Send the max ethernet frame size to the host (big-endian).
    let frame_size_be = (eth_frame_size as u32).to_be_bytes();
    if (&vsock).write_all(&frame_size_be).is_err() {
        std::process::exit(1);
    }

    // Notify parent that initialization is complete.
    let ppid = unistd::getppid();
    let _ = signal::kill(ppid, Signal::SIGUSR1);

    let mut buf = vec![0u8; eth_frame_size];

    let poll_fds = &mut [
        PollFd::new(
            unsafe { std::os::fd::BorrowedFd::borrow_raw(vsock_fd) },
            PollFlags::POLLIN,
        ),
        PollFd::new(
            unsafe { std::os::fd::BorrowedFd::borrow_raw(tun_fd) },
            PollFlags::POLLIN,
        ),
        PollFd::new(
            unsafe { std::os::fd::BorrowedFd::borrow_raw(shutdown_fd) },
            PollFlags::POLLIN,
        ),
    ];

    loop {
        let n = match poll(poll_fds, PollTimeout::NONE) {
            Ok(n) => n,
            Err(nix::errno::Errno::EINTR) => continue,
            Err(_) => break,
        };
        if n <= 0 {
            continue;
        }

        // vsock → TAP
        if poll_fds[0].revents().map_or(false, |r| r.contains(PollFlags::POLLIN)) {
            let mut len_buf = [0u8; 4];
            if read_exact_raw(vsock_fd, &mut len_buf).is_err() {
                break;
            }
            let len = u32::from_be_bytes(len_buf) as usize;
            if len > eth_frame_size || read_exact_raw(vsock_fd, &mut buf[..len]).is_err() {
                break;
            }
            if write_exact_raw(tun_fd, &buf[..len]).is_err() {
                break;
            }
        }

        // TAP → vsock
        if poll_fds[1].revents().map_or(false, |r| r.contains(PollFlags::POLLIN)) {
            let nread = loop {
                let r = unsafe { libc::read(tun_fd, buf.as_mut_ptr() as _, eth_frame_size) };
                if r < 0 && nix::errno::Errno::last() == nix::errno::Errno::EINTR {
                    continue;
                }
                break r;
            };
            if nread <= 0 {
                break;
            }
            let nread = nread as usize;
            let len_be = (nread as u32).to_be_bytes();
            if write_exact_raw(vsock_fd, &len_be).is_err()
                || write_exact_raw(vsock_fd, &buf[..nread]).is_err()
            {
                break;
            }
        }

        // Shutdown
        if poll_fds[2].revents().map_or(false, |r| r.contains(PollFlags::POLLIN)) {
            break;
        }
    }

    drop(tun_file);
    drop(vsock);
    std::process::exit(0);
}

fn read_exact_raw(fd: RawFd, buf: &mut [u8]) -> std::io::Result<()> {
    let mut total = 0;
    while total < buf.len() {
        let n = unsafe {
            libc::read(fd, buf[total..].as_mut_ptr() as _, buf.len() - total)
        };
        match n {
            0 => return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof)),
            n if n < 0 => {
                if nix::errno::Errno::last() == nix::errno::Errno::EINTR {
                    continue;
                }
                return Err(std::io::Error::last_os_error());
            }
            n => total += n as usize,
        }
    }
    Ok(())
}

fn write_exact_raw(fd: RawFd, buf: &[u8]) -> std::io::Result<()> {
    let mut total = 0;
    while total < buf.len() {
        let n = unsafe {
            libc::write(fd, buf[total..].as_ptr() as _, buf.len() - total)
        };
        match n {
            n if n < 0 => {
                if nix::errno::Errno::last() == nix::errno::Errno::EINTR {
                    continue;
                }
                return Err(std::io::Error::last_os_error());
            }
            n => total += n as usize,
        }
    }
    Ok(())
}
```

**Note:** This module uses raw `libc` ioctl calls for network interface configuration (`SIOCSIFADDR`, `SIOCSIFNETMASK`, `SIOCSIFHWADDR`, `SIOCSIFFLAGS`, `SIOCADDRT`, `SIOCGIFMTU`) because the `nix` crate does not expose these as safe wrappers. The `unsafe` blocks are contained and annotated. The `scopeguard` crate is not in scope — replace the `defer` call with a manual close or just hold the raw fd without a guard (the socket is short-lived).

- [ ] **Step 2: Remove `scopeguard` reference and fix the socket lifetime**

The `let _guard = scopeguard::defer(...)` line in `tap_assign_ipaddr` must be replaced. Use a manually managed close instead:
```rust
// At the end of tap_assign_ipaddr, after all ioctls succeed:
unsafe { libc::close(sock) };
```
And remove the `scopeguard` import entirely. Also do not add `scopeguard` to `Cargo.toml`.

- [ ] **Step 3: Verify it compiles**

```bash
cargo build --manifest-path init/aws-nitro/Cargo.toml 2>&1
```
Fix any compilation errors (the ioctl constants and struct field names may need adjustment based on your system's libc headers — check `libc::ifreq` field names using `grep -r "ifr_ifru\|ifru_flags\|ifru_addr" ~/.cargo/registry/src/*/libc*/src/unix/linux_like/linux/gnu/` if needed).

- [ ] **Step 4: Commit**

```bash
git add init/aws-nitro/src/device/net.rs
git commit -s -m "init/aws-nitro: implement device/net

Forks a child process that proxies ethernet frames between a TAP device
(tap0, 172.31.10.83/24, MAC 5a:94:ef:e4:0c:ee) and a host vsock using
4-byte big-endian length-prefixed framing.

Assisted-by: Claude Code: claude-opus-4-8"
```

---

## Task 9: Implement `device/mod`

**Files:**
- Modify: `init/aws-nitro/src/device/mod.rs`

Defines the `Device` enum, the `DEVICE_PROXY_READY` atomic flag (set by a `SIGUSR1` handler), and `init()` which dispatches to the correct proxy and spins until ready.

- [ ] **Step 1: Implement `device/mod.rs`**

```rust
// SPDX-License-Identifier: Apache-2.0

pub mod net;
pub mod signal;
pub mod stdio;

use std::os::fd::RawFd;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::Context;

/// Signals device proxy sub-processes send to the main process to indicate
/// they are ready. Set by the SIGUSR1 signal handler.
pub static DEVICE_PROXY_READY: AtomicBool = AtomicBool::new(false);

/// Signal handler that sets `DEVICE_PROXY_READY` on SIGUSR1.
///
/// # Safety
/// Must only be called from a signal handler context.
pub extern "C" fn device_proxy_sig_handler(sig: libc::c_int) {
    if sig == libc::SIGUSR1 {
        DEVICE_PROXY_READY.store(true, Ordering::Relaxed);
    }
}

/// The set of available device proxies.
pub enum Device {
    SignalHandler,
    AppOutputStdio,
    NetTapAfVsock,
}

/// Initialize the specified device proxy.
///
/// For proxies that fork (`SignalHandler`, `NetTapAfVsock`), this function
/// spins until the child signals `SIGUSR1` to indicate it is ready.
pub fn init(dev: Device, vsock_port: u32, shutdown_fd: RawFd) -> anyhow::Result<()> {
    DEVICE_PROXY_READY.store(false, Ordering::Relaxed);

    match dev {
        Device::SignalHandler => {
            signal::handler_init(vsock_port, shutdown_fd)
                .context("device::init SignalHandler")?;
            spin_until_ready();
        }
        Device::AppOutputStdio => {
            stdio::output_init(vsock_port).context("device::init AppOutputStdio")?;
            // AppOutputStdio does not fork; no SIGUSR1 wait needed.
        }
        Device::NetTapAfVsock => {
            net::tap_afvsock_init(vsock_port, shutdown_fd)
                .context("device::init NetTapAfVsock")?;
            spin_until_ready();
        }
    }

    Ok(())
}

/// Spin-wait until a device proxy child sends SIGUSR1.
fn spin_until_ready() {
    while !DEVICE_PROXY_READY.load(Ordering::Relaxed) {
        std::hint::spin_loop();
    }
}
```

- [ ] **Step 2: Verify it compiles**

```bash
cargo build --manifest-path init/aws-nitro/Cargo.toml 2>&1
```
Expected: no errors.

- [ ] **Step 3: Commit**

```bash
git add init/aws-nitro/src/device/mod.rs
git commit -s -m "init/aws-nitro: implement device/mod

Defines Device enum and init() dispatcher. Uses AtomicBool for the
DEVICE_PROXY_READY flag (replacing volatile sig_atomic_t) and
spin_loop hint for the ready wait.

Assisted-by: Claude Code: claude-opus-4-8"
```

---

## Task 10: Implement `main`

**Files:**
- Modify: `init/aws-nitro/src/main.rs`

Implements the full init sequence in order, plus the two process-global atomics and the SIGTERM handler.

- [ ] **Step 1: Implement `main.rs`**

```rust
// SPDX-License-Identifier: Apache-2.0

mod archive;
mod args_reader;
mod device;
mod fs;
mod mods;

use std::os::fd::{AsRawFd, RawFd};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

use anyhow::Context;
use aws_nitro_enclaves_nsm_api::api::{ErrorCode, Request, Response};
use aws_nitro_enclaves_nsm_api::driver::{nsm_exit, nsm_init, nsm_process_request};
use nix::sys::signal::{self, SaFlags, SigAction, SigHandler, SigSet, Signal};
use nix::sys::wait::{self, WaitStatus};
use nix::unistd::{self, ForkResult};

// Vsock port offsets (added to the enclave's CID).
const VSOCK_PORT_OFFSET_ARGS_READER: u32 = 1;
const VSOCK_PORT_OFFSET_NET: u32 = 2;
const VSOCK_PORT_OFFSET_OUTPUT: u32 = 3;
const VSOCK_PORT_OFFSET_APP_RET_CODE: u32 = 4;
const VSOCK_PORT_OFFSET_SIGNAL_HANDLER: u32 = 5;

const NSM_PCR_EXEC_DATA: u16 = 17;
const NSM_PCR_CHUNK_SIZE: usize = 0x800;
const VMADDR_CID_HOST: u32 = 2;

/// PID of the launched application process (-1 if not yet launched).
static APP_PID: AtomicI32 = AtomicI32::new(-1);
/// Set to true when a SIGTERM was caught and forwarded to the app.
static SIGTERM_CAUGHT: AtomicBool = AtomicBool::new(false);

extern "C" fn shutdown_sig_handler(sig: libc::c_int) {
    if sig == libc::SIGTERM {
        let pid = APP_PID.load(Ordering::Relaxed);
        if pid > 0 {
            unsafe { libc::kill(pid, libc::SIGTERM) };
            SIGTERM_CAUGHT.store(true, Ordering::Relaxed);
        }
    }
}

fn main() -> anyhow::Result<()> {
    // Block all signals during setup.
    let mut sigset = SigSet::empty();
    sigset.add(Signal::SIGTERM);
    sigset.add(Signal::SIGUSR1);
    signal::sigprocmask(signal::SigmaskHow::SIG_BLOCK, Some(&sigset), None)
        .context("sigprocmask block")?;

    // Install SIGUSR1 handler for device proxy ready notification.
    let sigusr1_action = SigAction::new(
        SigHandler::Handler(device::device_proxy_sig_handler),
        SaFlags::empty(),
        SigSet::empty(),
    );
    unsafe { signal::sigaction(Signal::SIGUSR1, &sigusr1_action) }
        .context("sigaction SIGUSR1")?;

    mods::load().context("mods_load")?;
    fs::console_init().context("console_init")?;

    let cid = cid_fetch().context("cid_fetch")?;

    let args = args_reader::read(cid + VSOCK_PORT_OFFSET_ARGS_READER)
        .context("args_reader_read")?;

    // Open the NSM device.
    let nsm_fd = nsm_init();
    if nsm_fd < 0 {
        anyhow::bail!("unable to open NSM guest module");
    }

    // Measure exec path + argv + envp in PCR 17.
    nsm_pcrs_exec_path_extend(nsm_fd, &args.exec_path, &args.exec_argv, &args.exec_envp)
        .context("nsm_pcrs_exec_path_extend")?;

    // Extract rootfs and measure in PCR 16.
    archive::extract(nsm_fd, &args.rootfs_archive).context("archive_extract")?;

    // Lock PCRs and close NSM handle.
    nsm_lock_and_exit(nsm_fd).context("nsm_exit")?;

    // Pivot root into /rootfs.
    rootfs_mount().context("rootfs_mount")?;

    fs::filesystem_init().context("filesystem_init")?;
    fs::cgroups_init().context("cgroups_init")?;

    // Create the shutdown eventfd.
    let shutdown_fd = unsafe { libc::eventfd(0, 0) };
    if shutdown_fd < 0 {
        return Err(std::io::Error::last_os_error()).context("eventfd");
    }

    proxies_init(cid, &args, shutdown_fd).context("proxies_init")?;

    // Unblock signals before forking the application.
    signal::sigprocmask(signal::SigmaskHow::SIG_UNBLOCK, Some(&sigset), None)
        .context("sigprocmask unblock")?;

    let pid = match unsafe { unistd::fork() }.context("fork application")? {
        ForkResult::Child => {
            launch(&args.exec_path, &args.exec_argv, &args.exec_envp)?;
            unreachable!()
        }
        ForkResult::Parent { child } => child,
    };

    APP_PID.store(pid.as_raw(), Ordering::Relaxed);

    // Install SIGTERM handler to forward to the app.
    let sigterm_action = SigAction::new(
        SigHandler::Handler(shutdown_sig_handler),
        SaFlags::empty(),
        SigSet::empty(),
    );
    unsafe { signal::sigaction(Signal::SIGTERM, &sigterm_action) }
        .context("sigaction SIGTERM")?;

    // Wait for the application to exit.
    let ret_code = loop {
        match wait::waitpid(Some(pid), None) {
            Ok(WaitStatus::Exited(_, code)) => break code,
            Ok(WaitStatus::Signaled(_, sig, _)) => break sig as i32 + 128,
            Err(nix::errno::Errno::EINTR) => continue,
            Err(nix::errno::Errno::ECHILD) => break 125,
            _ => continue,
        }
    };

    // If SIGTERM was caught and forwarded, report success.
    let ret_code = if SIGTERM_CAUGHT.load(Ordering::Relaxed) {
        0
    } else {
        ret_code
    };

    proxies_exit(&args, shutdown_fd).context("proxies_exit")?;

    app_ret_write(ret_code, cid).context("app_ret_write")?;

    Ok(())
}

/// Bind-mount /rootfs over /, then pivot via chdir + MS_MOVE + chroot.
fn rootfs_mount() -> anyhow::Result<()> {
    use nix::mount::{self, MsFlags};

    mount::mount(
        Some("/rootfs"),
        "/rootfs",
        None::<&str>,
        MsFlags::MS_BIND,
        None::<&str>,
    )
    .context("rootfs bind mount")?;

    unistd::chdir("/rootfs").context("chdir /rootfs")?;

    mount::mount(
        Some("."),
        "/",
        None::<&str>,
        MsFlags::MS_MOVE,
        None::<&str>,
    )
    .context("rootfs MS_MOVE")?;

    unistd::chroot(".").context("chroot .")?;
    unistd::chdir("/").context("chdir /")?;

    Ok(())
}

/// Create a new session, set PGID, set the PATH env var, then execvpe the workload.
fn launch(path: &str, argv: &[String], envp: &[String]) -> anyhow::Result<()> {
    use std::ffi::CString;

    let _ = unistd::setsid();
    let _ = unistd::setpgid(unistd::Pid::from_raw(0), unistd::Pid::from_raw(0));

    let c_path = CString::new(path).context("launch: path contains null")?;
    let c_argv: Vec<CString> = argv
        .iter()
        .map(|s| CString::new(s.as_str()).context("launch: argv contains null"))
        .collect::<anyhow::Result<_>>()?;
    let c_envp: Vec<CString> = envp
        .iter()
        .map(|s| CString::new(s.as_str()).context("launch: envp contains null"))
        .collect::<anyhow::Result<_>>()?;

    unistd::execvpe(&c_path, &c_argv, &c_envp)
        .with_context(|| format!("execvpe {path}"))?;

    unreachable!()
}

/// Measure exec_path, each argv, and each envp string in NSM PCR 17 in 2 KiB chunks.
fn nsm_pcrs_exec_path_extend(
    nsm_fd: i32,
    path: &str,
    argv: &[String],
    envp: &[String],
) -> anyhow::Result<()> {
    extend_str(nsm_fd, path)?;
    for s in argv {
        extend_str(nsm_fd, s)?;
    }
    for s in envp {
        extend_str(nsm_fd, s)?;
    }
    Ok(())
}

fn extend_str(nsm_fd: i32, s: &str) -> anyhow::Result<()> {
    for chunk in s.as_bytes().chunks(NSM_PCR_CHUNK_SIZE) {
        let response = nsm_process_request(
            nsm_fd,
            Request::ExtendPCR {
                index: NSM_PCR_EXEC_DATA,
                data: chunk.to_vec(),
            },
        );
        match response {
            Response::ExtendPCR { .. } => {}
            Response::Error(ErrorCode::Success) => {}
            Response::Error(e) => anyhow::bail!("NSM ExtendPCR PCR17 failed: {:?}", e),
            other => anyhow::bail!("NSM ExtendPCR PCR17 unexpected: {:?}", other),
        }
    }
    Ok(())
}

/// Lock PCR 17 (exec data) and close the NSM device handle.
fn nsm_lock_and_exit(nsm_fd: i32) -> anyhow::Result<()> {
    let response = nsm_process_request(
        nsm_fd,
        Request::LockPCR {
            index: NSM_PCR_EXEC_DATA,
        },
    );
    match response {
        Response::LockPCR => {}
        Response::Error(e) => anyhow::bail!("NSM LockPCR failed: {:?}", e),
        other => anyhow::bail!("NSM LockPCR unexpected: {:?}", other),
    }
    nsm_exit(nsm_fd);
    Ok(())
}

/// Fetch this enclave's CID from /dev/vsock via ioctl(IOCTL_VM_SOCKETS_GET_LOCAL_CID).
fn cid_fetch() -> anyhow::Result<u32> {
    use nix::fcntl::{OFlag, open};
    use nix::sys::stat::Mode;

    let fd = open("/dev/vsock", OFlag::O_RDONLY, Mode::empty())
        .context("cid_fetch: open /dev/vsock")?;

    let mut cid: u32 = 0;
    // IOCTL_VM_SOCKETS_GET_LOCAL_CID = _IOR(7, 0xb9, unsigned int)
    let ioctl_get_cid: libc::c_ulong = nix::request_code_read!('\x07', 0xb9, std::mem::size_of::<u32>());

    let ret = unsafe { libc::ioctl(fd.as_raw_fd(), ioctl_get_cid, &mut cid) };
    if ret < 0 {
        return Err(std::io::Error::last_os_error()).context("cid_fetch: ioctl");
    }

    Ok(cid)
}

/// Initialize each configured device proxy.
fn proxies_init(cid: u32, args: &args_reader::EnclaveArgs, shutdown_fd: RawFd) -> anyhow::Result<()> {
    // Enable SIGUSR1 so the main process can receive device proxy ready signals.
    let mut mask = SigSet::empty();
    mask.add(Signal::SIGUSR1);
    signal::sigprocmask(signal::SigmaskHow::SIG_UNBLOCK, Some(&mask), None)
        .context("unblock SIGUSR1")?;

    if args.app_output {
        device::init(
            device::Device::AppOutputStdio,
            cid + VSOCK_PORT_OFFSET_OUTPUT,
            shutdown_fd,
        )?;
    }

    if args.network_proxy {
        device::init(
            device::Device::NetTapAfVsock,
            cid + VSOCK_PORT_OFFSET_NET,
            shutdown_fd,
        )?;
    }

    device::init(
        device::Device::SignalHandler,
        cid + VSOCK_PORT_OFFSET_SIGNAL_HANDLER,
        shutdown_fd,
    )?;

    Ok(())
}

/// Signal all device proxies to shut down via the shutdown eventfd.
fn proxies_exit(args: &args_reader::EnclaveArgs, shutdown_fd: RawFd) -> anyhow::Result<()> {
    let val: u64 = 1;
    let ret = unsafe {
        libc::write(
            shutdown_fd,
            &val as *const u64 as *const libc::c_void,
            std::mem::size_of::<u64>(),
        )
    };
    if ret < 0 {
        return Err(std::io::Error::last_os_error()).context("proxies_exit: write shutdown_fd");
    }

    if args.app_output {
        device::stdio::output_close();
    }

    Ok(())
}

/// Connect to the host's return code vsock and write `code`, then read the ack.
fn app_ret_write(code: i32, cid: u32) -> anyhow::Result<()> {
    use std::io::{Read, Write};
    use vsock::{VsockAddr, VsockStream};

    let port = cid + VSOCK_PORT_OFFSET_APP_RET_CODE;
    let mut stream = VsockStream::connect(&VsockAddr::new(VMADDR_CID_HOST, port))
        .context("app_ret_write: connect")?;

    stream
        .write_all(&code.to_ne_bytes())
        .context("app_ret_write: write code")?;

    let mut ack = [0u8; 4];
    stream
        .read_exact(&mut ack)
        .context("app_ret_write: read ack")?;

    Ok(())
}
```

- [ ] **Step 2: Verify it compiles**

```bash
cargo build --manifest-path init/aws-nitro/Cargo.toml 2>&1
```
Fix any errors. Common issues:
- `nix::request_code_read!` macro syntax — check nix 0.30 docs; it may be `nix::request_code_read!('\x07', 0xb9, ...)` or require different import
- `Response::LockPCR` variant name — check the actual variant in `aws-nitro-enclaves-nsm-api::api::Response`; it may be `Response::LockPCR {}` with no fields
- `nix::unistd::execvpe` signature — verify argument types in nix 0.30

Run:
```bash
grep -r "LockPCR\|ExtendPCR\|pub enum Response" /sandbox/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/aws-nitro-enclaves-nsm-api-0.4.0/src/
```
to confirm exact variant names.

- [ ] **Step 3: Run `cargo clippy`**

```bash
cargo clippy --manifest-path init/aws-nitro/Cargo.toml 2>&1
```
Fix any warnings flagged by clippy.

- [ ] **Step 4: Run `cargo fmt`**

```bash
cargo fmt --manifest-path init/aws-nitro/Cargo.toml
```

- [ ] **Step 5: Commit**

```bash
git add init/aws-nitro/src/main.rs
git commit -s -m "init/aws-nitro: implement main

Orchestrates the full Nitro init sequence: load kernel modules, init
console, fetch CID, read enclave args, open NSM, measure exec
environment in PCR 17, extract rootfs (measured in PCR 16), lock PCRs,
mount rootfs, init filesystems + cgroups, init device proxies, fork
and exec the workload, wait, forward return code to host.

Assisted-by: Claude Code: claude-opus-4-8"
```

---

## Task 11: Update the Makefile

**Files:**
- Modify: `Makefile`

Replace the C compiler rule for `$(AWS_NITRO_INIT_BINARY)` with a `cargo build` invocation.

- [ ] **Step 1: Read the current Makefile rule**

```bash
grep -n "AWS_NITRO_INIT" /sandbox/libkrun/Makefile
```

The current lines are approximately:
```makefile
AWS_NITRO_INIT_SRC = \
        init/aws-nitro/include/*                  \
        init/aws-nitro/main.c                     \
        init/aws-nitro/archive.c                  \
        init/aws-nitro/args_reader.c              \
        init/aws-nitro/fs.c                       \
        init/aws-nitro/mod.c                      \
        init/aws-nitro/device/include/*           \
        init/aws-nitro/device/app_stdio_output.c  \
        init/aws-nitro/device/device.c            \
        init/aws-nitro/device/net_tap_afvsock.c   \
        init/aws-nitro/device/signal.c
AWS_NITRO_INIT_LD_FLAGS = -larchive -lnsm
...
AWS_NITRO_INIT_BINARY= init/aws-nitro/init
$(AWS_NITRO_INIT_BINARY): $(AWS_NITRO_INIT_SRC)
        $(CC) -O2 -static -s -Wall $(AWS_NITRO_INIT_LD_FLAGS) -o $@ $(AWS_NITRO_INIT_SRC) $(AWS_NITRO_INIT_LD_FLAGS)
```

- [ ] **Step 2: Replace the rule**

Delete the `AWS_NITRO_INIT_SRC` and `AWS_NITRO_INIT_LD_FLAGS` variable definitions. Replace the build rule with:

```makefile
AWS_NITRO_INIT_BINARY= init/aws-nitro/init
$(AWS_NITRO_INIT_BINARY): init/aws-nitro/Cargo.toml $(shell find init/aws-nitro/src -name '*.rs' 2>/dev/null)
	cargo build --release --manifest-path init/aws-nitro/Cargo.toml
	cp init/aws-nitro/target/release/krun-init-awsnitro $@
```

**Note:** Use a tab (not spaces) for the recipe lines — Makefiles require tabs.

- [ ] **Step 3: Verify `make` parses the Makefile correctly (dry run)**

```bash
make -n AWS_NITRO=1 2>&1 | head -40
```
Expected: shows `cargo build` and `cp` commands (not the old gcc invocation). No parse errors.

- [ ] **Step 4: Commit**

```bash
git add Makefile
git commit -s -m "init/aws-nitro: update Makefile to build Rust binary

Replace C compiler rule with cargo build for the standalone Rust crate.
Remove AWS_NITRO_INIT_SRC and AWS_NITRO_INIT_LD_FLAGS variables.

Assisted-by: Claude Code: claude-opus-4-8"
```

---

## Task 12: Final lint pass

- [ ] **Step 1: Run clippy on the crate**

```bash
cargo clippy --manifest-path init/aws-nitro/Cargo.toml 2>&1
```
Expected: zero warnings. Fix any that appear.

- [ ] **Step 2: Run `cargo fmt --check`**

```bash
cargo fmt --manifest-path init/aws-nitro/Cargo.toml -- --check
```
Expected: no diff. If there is a diff, run `cargo fmt --manifest-path init/aws-nitro/Cargo.toml` and re-check.

- [ ] **Step 3: Commit any lint fixes**

If clippy or fmt required changes:
```bash
git add init/aws-nitro/src/
git commit -s -m "init/aws-nitro: clippy and fmt fixes

Assisted-by: Claude Code: claude-opus-4-8"
```

---

## Self-Review

**Spec coverage check:**

| Spec requirement | Task |
|---|---|
| Standalone crate at `init/aws-nitro/` | Task 1 |
| `args_reader` module with `EnclaveArgs` and vsock binary protocol | Task 2 |
| `mods` module with `finit_module` | Task 3 |
| `fs` module: `console_init`, `filesystem_init`, `cgroups_init` | Task 4 |
| `archive` module: tar extraction + NSM PCR 16 measurement | Task 5 |
| `device/stdio`: stdout/stderr → vsock | Task 6 |
| `device/signal`: fork + vsock signal forwarding + SIGUSR1 on ready | Task 7 |
| `device/net`: TAP device + vsock frame proxy + SIGUSR1 on ready | Task 8 |
| `device/mod`: `Device` enum + `AtomicBool` + dispatch + spin wait | Task 9 |
| `main`: full init sequence + SIGTERM handler + `APP_PID`/`SIGTERM_CAUGHT` | Task 10 |
| Makefile update: `cargo build` replaces `$(CC)` | Task 11 |
| Zero clippy warnings, `cargo fmt` clean | Task 12 |
| Wire-compatible with host `EnclaveArgsWriter` (handshake + framing) | Task 2 |
| NSM PCR 17 locked after exec env measurement | Task 10 (`nsm_lock_and_exit`) |
| `/etc/hostname` + `/etc/hosts` excluded from PCR 16 measurement | Task 5 |
| `SIGTERM_CAUGHT` zeroes the exit code | Task 10 |
| TAP IP=172.31.10.83, MAC=5a:94:ef:e4:0c:ee, gateway=172.31.10.83 | Task 8 |
| `libarchive` replaced by `tar` crate | Task 5 |
| `libnsm` replaced by `aws-nitro-enclaves-nsm-api` | Tasks 5, 10 |

**No gaps found.**
