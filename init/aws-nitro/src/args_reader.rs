// SPDX-License-Identifier: Apache-2.0

use std::io::{Read, Write};

use anyhow::{Context, bail};
use vsock::{VsockAddr, VsockStream};

const ENCLAVE_VSOCK_LAUNCH_ARGS_READY: u8 = 0xb7;
const VMADDR_CID_HOST: u32 = 2;

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
                let s =
                    String::from_utf8(bytes).context("args_reader: exec_path not valid UTF-8")?;
                args.exec_path = s.trim_end_matches('\0').to_string();
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
    let mut buf = vec![0u8; usize::try_from(len).context("read_bytes: length exceeds usize")?];
    stream
        .read_exact(&mut buf)
        .context("read_bytes: read payload")?;
    Ok(buf)
}

/// Read an 8-byte LE count, then that many length-prefixed byte strings.
fn read_string_list(stream: &mut VsockStream) -> anyhow::Result<Vec<String>> {
    let count =
        usize::try_from(read_u64_le(stream)?).context("read_string_list: count exceeds usize")?;
    let mut list = Vec::with_capacity(count);
    for i in 0..count {
        let bytes = read_bytes(stream).with_context(|| format!("read_string_list: item {i}"))?;
        let s = String::from_utf8(bytes)
            .with_context(|| format!("read_string_list: item {i} not valid UTF-8"))?;
        list.push(s.trim_end_matches('\0').to_string());
    }
    Ok(list)
}

/// Read 8 bytes from the stream and interpret them as a little-endian u64.
fn read_u64_le(stream: &mut VsockStream) -> anyhow::Result<u64> {
    let mut buf = [0u8; 8];
    stream.read_exact(&mut buf).context("read_u64_le")?;
    Ok(u64::from_le_bytes(buf))
}
