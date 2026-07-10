use anyhow::Context;

const VSOCK_PORT_OFFSET_ARGS_READER: u32 = 1;

mod fs {
    use std::fs::OpenOptions;
    use std::os::fd::AsFd;

    use anyhow::Context;
    use nix::errno::Errno;
    use nix::mount::{self, MsFlags};
    use nix::unistd;

    /// Initialize /dev/console and redirect std{err, in, out} to it for early debug output.
    pub fn console_init() -> anyhow::Result<()> {
        let path = "/dev/console";

        match mount::mount(
            Some("dev"),
            "/dev",
            Some("devtmpfs"),
            MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
            None::<&str>,
        ) {
            Ok(_) => Ok(()),
            Err(Errno::EBUSY) => Ok(()),
            Err(e) => Err(e),
        }?;

        // Redirect stdin, stdout, and stderr to /dev/console.
        let console_r = OpenOptions::new()
            .read(true)
            .open(path)
            .context("unable to open /dev/console as read-only")?;

        unistd::dup2_stdin(console_r.as_fd()).context("unable to redirect stdin")?;

        let console_w = OpenOptions::new()
            .write(true)
            .open(path)
            .context("unable to open /dev/console as write-only")?;
        let console_w = console_w.as_fd();

        unistd::dup2_stdout(console_w).context("unable to redirect stdout")?;
        unistd::dup2_stderr(console_w).context("unable to redirect stderr")
    }
}

mod kernel_mods {
    use std::fs::{self, OpenOptions};
    use std::io::{self, ErrorKind};
    use std::os::{fd::AsRawFd, unix::fs::OpenOptionsExt};

    use anyhow::{Context, bail};
    use nix::libc as nix_c;
    use nix::unistd;

    const KRUN_LINUX_MODS_DIR_NAME: &str = "/krun_linux_mods";

    /// Load a kernel module.
    fn load_module(path: &str) -> anyhow::Result<()> {
        let file = match OpenOptions::new()
            .read(true)
            .custom_flags(nix_c::O_CLOEXEC)
            .open(path)
        {
            Ok(file) => file,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(()),
            Err(_) => bail!("unable to open kernel module {}", path),
        };

        let ret =
            unsafe { nix_c::syscall(nix_c::SYS_finit_module, file.as_raw_fd(), c"".as_ptr(), 0) };

        if ret < 0 {
            let os_err = io::Error::last_os_error();
            if os_err.kind() != io::ErrorKind::AlreadyExists {
                bail!("failure to init kernel module {}: {}", path, os_err);
            }
        }

        unistd::unlink(path).context("unable to unlink kernel module path")?;

        Ok(())
    }

    /// Load the configured kernel modules.
    pub fn load_modules() -> anyhow::Result<()> {
        let entries = match fs::read_dir(KRUN_LINUX_MODS_DIR_NAME) {
            Ok(entries) => entries,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(()),
            Err(_) => bail!(
                "unable to open kernel module configuration directory {}",
                KRUN_LINUX_MODS_DIR_NAME
            ),
        };
        for entry in entries {
            let entry = entry?;
            // The full path of the module file.
            let path = format!(
                "{}/{}",
                KRUN_LINUX_MODS_DIR_NAME,
                entry
                    .file_name()
                    .to_str()
                    .context("unable to convert kernel module name to a string")?
            );

            load_module(&path)?;
        }

        Ok(())
    }
}

mod args_reader {
    use std::io::{Read, Write};
    use std::mem;

    use anyhow::Context;
    use anyhow::bail;
    use vsock::{VMADDR_CID_HOST, VsockAddr, VsockStream};

    const ENCLAVE_VSOCK_LAUNCH_ARGS_READY: u8 = 0xb7;

    const ENCLAVE_ARG_ID_ROOTFS: u8 = 0;
    const ENCLAVE_ARG_ID_EXEC_PATH: u8 = 1;
    const ENCLAVE_ARG_ID_EXEC_ARGV: u8 = 2;
    const ENCLAVE_ARG_ID_EXEC_ENVP: u8 = 3;
    const ENCLAVE_ARG_ID_NETWORK_PROXY: u8 = 4;
    const ENCLAVE_ARG_ID_APP_OUTPUT: u8 = 5;
    const ENCLAVE_ARGS_FINISHED: u8 = 255;

    /// Enclave configuration arguments written from the host.
    #[derive(Default)]
    pub struct EnclaveArgs {
        /// Rootfs tar archive.
        pub rootfs_archive: Vec<u8>,

        /// Path of execution library.
        pub exec_path: String,

        /// Execution argument vector.
        pub exec_argv: Vec<String>,

        /// Execution environment pointer,
        pub exec_envp: Vec<String>,

        /// Indicate if networking is configured.
        pub network_proxy: bool,

        /// Indicate if running in non-debug mode.
        pub app_output: bool,
    }

    /// Signal to the host that the enclave is ready to receive the enclave arguments.
    fn signal(vsock_port: u32) -> anyhow::Result<VsockStream> {
        let addr = VsockAddr::new(VMADDR_CID_HOST, vsock_port);
        // connect to the host socket.
        let mut stream = VsockStream::connect(&addr).context("unable to connect to host socket")?;

        // Write the heartbeat to the host and read it back to ensure that the communication is
        // established.
        stream
            .write_all(&[ENCLAVE_VSOCK_LAUNCH_ARGS_READY])
            .context("unable to send heartbeat to host")?;

        let mut buf = [0u8; 1];
        stream
            .read_exact(&mut buf)
            .context("unable to read host response")?;
        match buf[0] {
            ENCLAVE_VSOCK_LAUNCH_ARGS_READY => Ok(stream),
            _ => bail!("unable to establish connection to hypervisor"),
        }
    }

    fn read_arg_header(stream: &mut VsockStream) -> anyhow::Result<u64> {
        // Read the length of the object.
        let mut len_buf = [0u8; mem::size_of::<u64>()];
        stream
            .read_exact(&mut len_buf)
            .context("unable to read argument object length")?;
        Ok(u64::from_le_bytes(len_buf))
    }

    /// Read an object from the vsock stream.
    fn recv(stream: &mut VsockStream) -> anyhow::Result<Vec<u8>> {
        // Read the length of the object.
        let len = read_arg_header(stream)?;

        let mut arg_buf = vec![0u8; len as usize];
        stream
            .read_exact(&mut arg_buf)
            .context("unable to read object from stream")?;
        Ok(arg_buf)
    }

    /// Build an array of strings read from the vsock.
    fn recv_list(stream: &mut VsockStream) -> anyhow::Result<Vec<String>> {
        // Read the size of the string array
        let len = read_arg_header(stream).context("unable to read size of arg list")?;
        let mut buf = Vec::with_capacity(len as usize);

        // Read each string in the array, storing them at each index.
        // The host sends null-terminated c-strings, so strip the trailing null.
        for _ in 0..len {
            let mut arr = recv(stream).context("unable to read string in arg list")?;
            if arr.last() == Some(&0) {
                arr.pop();
            }
            let str = String::from_utf8(arr).context("unable to convert bytes to String")?;
            buf.push(str);
        }

        Ok(buf)
    }

    /// Read each enclave argument from the host.
    fn read_args(stream: &mut VsockStream) -> anyhow::Result<EnclaveArgs> {
        let mut args = EnclaveArgs::default();
        loop {
            let mut id = [0u8; 1];
            // read the argument identifier
            stream
                .read_exact(&mut id)
                .context("unable to read argument id")?;

            match id[0] {
                ENCLAVE_ARG_ID_ROOTFS => args.rootfs_archive = recv(stream)?,
                ENCLAVE_ARG_ID_EXEC_PATH => {
                    let mut path = recv(stream).context("unable to read exec path from stream")?;
                    if path.last() == Some(&0) {
                        path.pop();
                    }
                    args.exec_path =
                        String::from_utf8(path).context("unable to convert exec path to String")?;
                }
                ENCLAVE_ARG_ID_EXEC_ARGV => {
                    args.exec_argv = recv_list(stream).context("unable to read exec argv")?
                }
                ENCLAVE_ARG_ID_EXEC_ENVP => {
                    args.exec_envp = recv_list(stream).context("unable to read exec envp")?
                }
                ENCLAVE_ARG_ID_NETWORK_PROXY => {
                    args.network_proxy = true;
                }
                ENCLAVE_ARG_ID_APP_OUTPUT => {
                    args.app_output = true;
                }
                ENCLAVE_ARGS_FINISHED => return Ok(args),
                _ => bail!("invalid enclave argument"),
            }
        }
    }

    /// Establish communication with the host's argument writer and read the enclave configuration
    /// (via the arguments) from it.
    pub fn read(vsock_port: u32) -> anyhow::Result<EnclaveArgs> {
        // Open the arguments reader and signal to the hypervisor that the enclave is booted and
        // ready to read the arguments.
        let mut stream =
            signal(vsock_port).context("unable to signal enclave readiness to hypervisor")?;

        // Read the arguments.
        read_args(&mut stream).context("unable to read arguments")
    }
}

fn main() -> anyhow::Result<()> {
    // Some linux modules, like virtio-mmio, may be required for console output. Load these modules
    // immediately to ensure they are available to the initrd.
    kernel_mods::load_modules().context("unable to load linux kernel modules")?;

    // Initialize early debug output with /dev/console.
    fs::console_init().context("unable to initialize /dev/console")?;

    // Fetch the enclave VM's CID in order to calculate vsock port offsets for host communication.
    let cid = vsock::get_local_cid().context("unable to get enclave VM's CID")?;
    if cid == 0 {
        return Ok(());
    }

    // Read the enclave arguments from the host.
    let args = args_reader::read(cid + VSOCK_PORT_OFFSET_ARGS_READER)?;

    Ok(())
}
