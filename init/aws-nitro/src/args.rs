// SPDX-License-Identifier: Apache-2.0

use anyhow::{bail, Context, Result};
use std::ffi::CStr;
use std::io::{self, Read, Write};

// Matches ENCLAVE_VSOCK_LAUNCH_ARGS_READY in args_reader.c and args_writer.rs.
const ARGS_READY_BYTE: u8 = 0xb7;

const ARG_ID_ROOTFS: u8 = 0;
const ARG_ID_EXEC_PATH: u8 = 1;
const ARG_ID_EXEC_ARGV: u8 = 2;
const ARG_ID_EXEC_ENVP: u8 = 3;
const ARG_ID_NETWORK_PROXY: u8 = 4;
const ARG_ID_APP_OUTPUT: u8 = 5;
const ARG_ID_FINISHED: u8 = 255;

pub struct EnclaveArgs {
    pub rootfs_archive: Vec<u8>,
    pub exec_path: String,
    pub exec_argv: Vec<String>,
    pub exec_envp: Vec<String>,
    pub network_proxy: bool,
    pub app_output: bool,
}

pub fn read(vsock_port: u32) -> Result<EnclaveArgs> {
    let sock_fd = connect_and_handshake(vsock_port)?;
    let mut stream = unsafe { VsockStream::from_raw_fd(sock_fd) };
    read_args(&mut stream)
}

// A thin newtype so we can impl Read/Write over a raw vsock fd.
struct VsockStream(i32);

impl VsockStream {
    unsafe fn from_raw_fd(fd: i32) -> Self {
        Self(fd)
    }
}

impl Drop for VsockStream {
    fn drop(&mut self) {
        unsafe { libc::close(self.0) };
    }
}

impl Read for VsockStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = unsafe {
            libc::read(
                self.0,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
            )
        };
        if n < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(n as usize)
        }
    }
}

impl Write for VsockStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = unsafe {
            libc::write(self.0, buf.as_ptr() as *const libc::c_void, buf.len())
        };
        if n < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(n as usize)
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Open vsock to host, exchange the readiness handshake, return the connected fd.
fn connect_and_handshake(vsock_port: u32) -> Result<i32> {
    let sock_fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM, 0) };
    if sock_fd < 0 {
        return Err(io::Error::last_os_error()).context("create vsock for args reader");
    }

    let mut addr: libc::sockaddr_vm = unsafe { std::mem::zeroed() };
    addr.svm_family = libc::AF_VSOCK as _;
    addr.svm_cid = libc::VMADDR_CID_HOST;
    addr.svm_port = vsock_port;

    let ret = unsafe {
        libc::connect(
            sock_fd,
            &addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_vm>() as _,
        )
    };
    if ret < 0 {
        unsafe { libc::close(sock_fd) };
        return Err(io::Error::last_os_error()).context("connect args reader vsock");
    }

    // Send the ready byte.
    let buf = [ARGS_READY_BYTE];
    let n = unsafe { libc::write(sock_fd, buf.as_ptr() as *const libc::c_void, 1) };
    if n != 1 {
        unsafe { libc::close(sock_fd) };
        bail!("args reader: failed to write ready byte");
    }

    // Read the echo back.
    let mut echo = [0u8; 1];
    let n = unsafe { libc::read(sock_fd, echo.as_mut_ptr() as *mut libc::c_void, 1) };
    if n != 1 || echo[0] != ARGS_READY_BYTE {
        unsafe { libc::close(sock_fd) };
        bail!("args reader: ready handshake failed");
    }

    Ok(sock_fd)
}

fn read_exact(stream: &mut VsockStream, buf: &mut [u8]) -> Result<()> {
    let mut total = 0;
    while total < buf.len() {
        let n = stream.read(&mut buf[total..]).context("vsock read")?;
        if n == 0 {
            bail!("vsock EOF");
        }
        total += n;
    }
    Ok(())
}

fn read_u64(stream: &mut VsockStream) -> Result<u64> {
    let mut buf = [0u8; 8];
    read_exact(stream, &mut buf)?;
    Ok(u64::from_ne_bytes(buf))
}

fn read_bytes(stream: &mut VsockStream) -> Result<Vec<u8>> {
    let len = read_u64(stream)? as usize;
    let mut buf = vec![0u8; len];
    read_exact(stream, &mut buf)?;
    Ok(buf)
}

fn read_string(stream: &mut VsockStream) -> Result<String> {
    let bytes = read_bytes(stream)?;
    // The host sends null-terminated CStrings; strip the trailing null.
    let cstr = CStr::from_bytes_with_nul(&bytes)
        .or_else(|_| CStr::from_bytes_until_nul(&bytes))
        .context("invalid string from vsock")?;
    Ok(cstr.to_string_lossy().into_owned())
}

fn read_string_list(stream: &mut VsockStream) -> Result<Vec<String>> {
    let count = read_u64(stream)? as usize;
    let mut list = Vec::with_capacity(count);
    for _ in 0..count {
        list.push(read_string(stream)?);
    }
    Ok(list)
}

fn read_args(stream: &mut VsockStream) -> Result<EnclaveArgs> {
    let mut rootfs_archive = Vec::new();
    let mut exec_path = String::new();
    let mut exec_argv = Vec::new();
    let mut exec_envp = Vec::new();
    let mut network_proxy = false;
    let mut app_output = false;

    loop {
        let mut id = [0u8; 1];
        read_exact(stream, &mut id)?;

        match id[0] {
            ARG_ID_ROOTFS => rootfs_archive = read_bytes(stream)?,
            ARG_ID_EXEC_PATH => exec_path = read_string(stream)?,
            ARG_ID_EXEC_ARGV => exec_argv = read_string_list(stream)?,
            ARG_ID_EXEC_ENVP => exec_envp = read_string_list(stream)?,
            ARG_ID_NETWORK_PROXY => network_proxy = true,
            ARG_ID_APP_OUTPUT => app_output = true,
            ARG_ID_FINISHED => break,
            unknown => bail!("unknown enclave arg ID: {unknown}"),
        }
    }

    Ok(EnclaveArgs {
        rootfs_archive,
        exec_path,
        exec_argv,
        exec_envp,
        network_proxy,
        app_output,
    })
}
