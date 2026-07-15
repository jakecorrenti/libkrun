use anyhow::{Context, bail};

const VSOCK_PORT_OFFSET_ARGS_READER: u32 = 1;

mod fs {
    use std::fs::OpenOptions;
    use std::io::{BufRead, BufReader};
    use std::os::{fd::AsFd, unix::fs as unix_fs};

    use anyhow::Context;
    use nix::errno::Errno;
    use nix::mount::{self, MsFlags};
    use nix::sys::stat::Mode;
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

    /// Mount the extracted rootfs and switch the root directory to it.
    pub fn mount_rootfs() -> anyhow::Result<()> {
        mount::mount(
            Some("/rootfs"),
            "/rootfs",
            None::<&str>,
            MsFlags::MS_BIND,
            None::<&str>,
        )
        .context("unable to mount /rootfs with mount()")?;
        unistd::chdir("/rootfs").context("unable to change current dir to /rootfs")?;

        mount::mount(Some("."), "/", None::<&str>, MsFlags::MS_MOVE, None::<&str>)
            .context("unable to move . to / with mount()")?;
        unistd::chroot(".").context("unable to change root to . ")?;
        unistd::chdir("/").context("unable to change dir to /")?;

        Ok(())
    }

    fn init_dev_filesystem() -> anyhow::Result<()> {
        let sys_dirs = ["/dev", "/proc", "/run", "/sys", "/tmp"];
        let dev_dirs = ["/dev/shm", "/dev/pts"];

        // Create the system directories not provided by the enclave rootfs.
        for dir in sys_dirs {
            unistd::mkdir(dir, Mode::from_bits_truncate(0o755))
                .context(format!("unable to mkdir {}", dir))?;
        }

        // Mount /dev for device files.
        mount::mount(
            Some("/dev"),
            "/dev",
            Some("devtmpfs"),
            MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
            None::<&str>,
        )
        .context("unable to mount /dev")?;

        // Create the initial device files.
        for dir in dev_dirs {
            unistd::mkdir(dir, Mode::from_bits_truncate(0o755))
                .context(format!("unable to mkdir {}", dir))?;
        }

        mount::mount(
            Some("shm"),
            "/dev/shm",
            Some("tmpfs"),
            MsFlags::MS_NODEV | MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
            None::<&str>,
        )
        .context("unable to mount /dev/shm")?;

        mount::mount(
            Some("devpts"),
            "/dev/pts",
            Some("devpts"),
            MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
            None::<&str>,
        )
        .context("unable to mount /dev/pts")?;

        Ok(())
    }

    fn init_proc_filesystem() -> anyhow::Result<()> {
        // Initialize the /proc filesystem for special files representing the current state of the
        // kernel.
        mount::mount(
            Some("/proc"),
            "/proc",
            Some("proc"),
            MsFlags::MS_NODEV | MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
            None::<&str>,
        )
        .context("unable to mount /proc")?;

        unix_fs::symlink("/proc/self/fd", "/dev/fd")
            .context("unable to symlink /dev/fd -> /proc/self/fd")?;
        unix_fs::symlink("/proc/self/fd/0", "/dev/stdin")
            .context("unable to symlink /dev/stdin -> /proc/self/fd/0")?;
        unix_fs::symlink("/proc/self/fd/1", "/dev/stdout")
            .context("unable to symlink /dev/stdout -> /proc/self/fd/1")?;
        unix_fs::symlink("/proc/self/fd/2", "/dev/stderr")
            .context("unable to symlink /dev/stderr -> /proc/self/fd/2")?;

        Ok(())
    }

    /// Initialize the rest of the root filesystem with ephemeral enclave file systems.
    pub fn init_filesystem() -> anyhow::Result<()> {
        init_dev_filesystem().context("unable to initialize /dev")?;
        init_proc_filesystem().context("unable to initialize /proc")?;

        // Mount the /run directory to store volatile runtime data about the system since boot.
        mount::mount(
            Some("tmpfs"),
            "/run",
            Some("tmpfs"),
            MsFlags::MS_NODEV | MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
            Some("mode=0755"),
        )
        .context("unable to mount /run")?;

        // Mount the /tmp directory for temporary files (cleraed on reboot).
        mount::mount(
            Some("tmpfs"),
            "/tmp",
            Some("tmpfs"),
            MsFlags::MS_NODEV | MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
            None::<&str>,
        )
        .context("unable to mount /tmp")?;

        // Mount the sysfs, accessed to set or obtain information about the kernel's view of the
        // system.
        mount::mount(
            Some("sysfs"),
            "/sys",
            Some("sysfs"),
            MsFlags::MS_NODEV | MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
            None::<&str>,
        )
        .context("unable to mount /sys")?;

        // Initialize the cgroup root.
        mount::mount(
            Some("cgroup_root"),
            "/sys/fs/cgroup",
            Some("tmpfs"),
            MsFlags::MS_NODEV | MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
            Some("mode=0755"),
        )
        .context("unable to mount /sys/fs/cgroup")?;

        Ok(())
    }

    /// Initialize the cgroups.
    pub fn init_cgroups() -> anyhow::Result<()> {
        let f = OpenOptions::new()
            .read(true)
            .open("/proc/cgroups")
            .context("unable to open /proc/cgroups")?;

        let buf_reader = BufReader::new(f);
        let mut lines = buf_reader.lines();

        // Skip the first line.
        lines.next();

        for line in lines {
            let line = line.context("unable to read line of /proc/cgroups")?;
            let sysfs_path = "/sys/fs/cgroup/";

            // Cgroup lines have the following format: subsys_name | hierarchy | num_cgroups | enabled
            let mut line = line.split_whitespace();
            let subsys_name = match line.next() {
                Some(l) => l,
                None => continue,
            };

            // Skip hierarchy and num_cgroups
            let mut line = line.skip(2);

            let enabled = match line.next() {
                Some(l) => l.parse().unwrap_or(0),
                None => continue,
            };

            let path = format!("{}{}", sysfs_path, subsys_name);

            if enabled > 0 {
                unistd::mkdir(path.as_str(), Mode::from_bits_truncate(0o755))
                    .context(format!("unable to mkdir {}", path))?;
                mount::mount(
                    Some(subsys_name),
                    path.as_str(),
                    Some("cgroup"),
                    MsFlags::MS_NODEV | MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
                    Some(subsys_name),
                )
                .context(format!("unable to mount {}", path))?;
            }
        }

        Ok(())
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

mod nsm {
    use anyhow::bail;
    use aws_nitro_enclaves_nsm_api::api::{Request, Response};
    use aws_nitro_enclaves_nsm_api::driver as nitro_driver;

    const NSM_PCR_CHUNK_SIZE: usize = 0x800; // 2KiB
    const NSM_PCR_ROOTFS: u16 = 16;
    const NSM_PCR_EXEC_DATA: u16 = 17;

    /// Measure the enclave execution environment {path, argv, envp} in NSM PCR 17.
    ///
    /// NSM PCR 17 contains the measurement of the execution environment (path,
    /// argv, envp).
    pub fn pcr_extend_exec_path(
        nsm_fd: i32,
        path: &str,
        argv: &[String],
        envp: &[String],
    ) -> anyhow::Result<()> {
        // Measure the execution path.
        measure_exec_string(nsm_fd, path)?;

        // Measure each execution argument.
        for arg in argv {
            measure_exec_string(nsm_fd, arg)?;
        }

        // Measure each environment variable.
        for env in envp {
            measure_exec_string(nsm_fd, env)?;
        }

        Ok(())
    }

    fn measure_exec_string(fd: i32, data: &str) -> anyhow::Result<()> {
        let req = Request::ExtendPCR {
            index: NSM_PCR_EXEC_DATA,
            data: data.as_bytes().to_vec(),
        };
        let resp = nitro_driver::nsm_process_request(fd, req);
        match resp {
            Response::ExtendPCR { .. } => Ok(()),
            Response::Error(e) => bail!("failure to extend PCR {}: {:?}", NSM_PCR_EXEC_DATA, e),
            r => bail!("unexpected NSM response: {:?}", r),
        }
    }

    /// Extend the rootfs NSM PCR with a data block from the TAR archive
    pub fn pcr_extend_rootfs(nsm_fd: i32, rootfs: &[u8]) -> anyhow::Result<()> {
        // Measure the root filesystem with NSM PCR 16. NSM PCR extension requests have a data size
        // cap of 4KiB (usually smaller than the rootfs size). Therefore, measure the rootfs in
        // 2KiB chunks.
        for chunk in rootfs.chunks(NSM_PCR_CHUNK_SIZE) {
            let req = Request::ExtendPCR {
                index: NSM_PCR_ROOTFS,
                data: chunk.to_vec(),
            };
            let resp = nitro_driver::nsm_process_request(nsm_fd, req);
            match resp {
                Response::ExtendPCR { .. } => continue,
                Response::Error(e) => bail!("failure to extend PCR {}: {:?}", NSM_PCR_ROOTFS, e),
                r => bail!("unexpected NSM response: {:?}", r),
            }
        }
        Ok(())
    }

    /// Lock PCRs measured by init process and close the NSM handle.
    pub fn lock_and_exit(nsm_fd: i32) -> anyhow::Result<()> {
        // Lock PCRs 16 and 17 so they cannot be extended further. This is to ensure there can be
        // no further data measured other than the rootfs and execution environment.
        for index in [NSM_PCR_ROOTFS, NSM_PCR_EXEC_DATA] {
            let req = Request::LockPCR { index };
            let resp = nitro_driver::nsm_process_request(nsm_fd, req);
            match resp {
                Response::LockPCR => continue,
                Response::Error(e) => bail!("failure to lock PCR {}: {:?}", index, e),
                r => bail!("unexpected NSM response: {:?}", r),
            }
        }

        // Close the NSM device handle.
        nitro_driver::nsm_exit(nsm_fd);
        Ok(())
    }
}

mod archive {
    use std::io::{Cursor, Read};

    use anyhow::Context;

    /// Extract the tarball from the reader (that is, the memory buffer that
    /// read the rootfs archive from the hypervisor vsock) and write it to the
    /// enclave's filesystem.
    pub fn extract(nsm_fd: i32, rootfs_archive: &[u8]) -> anyhow::Result<()> {
        // Measure the rootfs data in NSM PCR 16 before extraction.
        let mut tar = tar::Archive::new(Cursor::new(rootfs_archive));
        for entry in tar.entries().context("unable to read tar entries")? {
            let mut entry = entry.context("unable to read tar entry")?;
            let path = entry.path().context("unable to read entry path")?;

            let ignored_paths = ["rootfs/etc/hostname", "rootfs/etc/hosts"];
            if ignored_paths
                .iter()
                .any(|p| path.to_string_lossy().contains(p))
            {
                continue;
            }

            let mut data = Vec::new();
            entry
                .read_to_end(&mut data)
                .context("unable to read entry data")?;
            if !data.is_empty() {
                super::nsm::pcr_extend_rootfs(nsm_fd, &data)
                    .context("unable to extend pcr with rootfs")?;
            }
        }

        // Extract the archive to the root filesystem.
        let mut tar = tar::Archive::new(Cursor::new(rootfs_archive));
        tar.set_preserve_permissions(true);
        tar.set_preserve_ownerships(true);
        tar.unpack("/").context("unable to extract rootfs archive")
    }
}

mod proxy {
    use std::fs::{self, File, OpenOptions};
    use std::io::{ErrorKind, Read, Write};
    use std::mem;
    use std::net::Ipv4Addr;
    use std::os::fd::{AsRawFd, BorrowedFd, OwnedFd};
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use std::time::Duration;

    use anyhow::{Context, bail};
    use nix::errno::Errno;
    use nix::libc as nix_c;
    use nix::poll::{PollFd, PollFlags, PollTimeout};
    use nix::sys::signal::{self, Signal};
    use nix::sys::socket::{self, AddressFamily, SockFlag, SockType};
    use nix::sys::stat::{self, Mode, SFlag};
    use nix::unistd::{self, ForkResult};
    use vsock::{VMADDR_CID_HOST, VsockAddr, VsockStream};

    const VSOCK_PORT_OFFSET_NET: u32 = 2;
    const VSOCK_PORT_OFFSET_OUTPUT: u32 = 3;
    const VSOCK_PORT_OFFSET_SIGNAL_HANDLER: u32 = 5;

    const TUN_DEV_MAJOR: u64 = 10;
    const TUN_DEV_MINOR: u64 = 200;

    const ETH_HEADER_LEN: i32 = 14;

    /// Redirect std{err, out} output to a vsock connected to the host.
    /// This allows the host to read application output.
    fn init_output_proxy(vsock_port: u32) -> anyhow::Result<()> {
        let addr = VsockAddr::new(VMADDR_CID_HOST, vsock_port);
        let stream = VsockStream::connect(&addr).context("unable to connect to host vsock")?;
        unistd::dup2_stderr(&stream).context("unable to redirect stderr to vsock")?;
        unistd::dup2_stdout(&stream).context("unable to redirect stdout to vsock")
    }

    /// Initialize the enclave TAP device to route all network traffic to the
    /// host.
    fn init_tun() -> anyhow::Result<()> {
        match unistd::mkdir("/dev/net", Mode::from_bits_truncate(0o755)) {
            Ok(_) | Err(Errno::EEXIST) => {}
            Err(e) => bail!("failure to create /dev/net: {}", e),
        }

        match Path::new("/dev/net/tun").try_exists() {
            Ok(false) => {
                let dev = stat::makedev(TUN_DEV_MAJOR, TUN_DEV_MINOR);
                // Allow all users to read/write to /dev/net/tun. Allowing
                // the device to be accessible by non-root users is safe
                // as CAP_NET_ADMIN is required for connecting to network
                // devices not owned by the user in question.
                stat::mknod(
                    "/dev/net/tun",
                    SFlag::S_IFCHR,
                    Mode::from_bits_truncate(0o666),
                    dev,
                )
                .context("unable to create /dev/net/tun device node")?;
            }
            Ok(true) => {
                let path = "/dev/net/tun";
                let mut permissions = fs::metadata(path)
                    .context("unable to get /dev/net/tun metadata")?
                    .permissions();
                permissions.set_mode(0o666);
                fs::set_permissions(path, permissions)
                    .context("unable to set file permissions for /dev/net/tun")?;
            }
            Err(e) => bail!("unable to verify status of /dev/net/tun: {}", e),
        }
        Ok(())
    }

    fn ifr_with_name_and_addr(name: &str, ipaddr: Ipv4Addr) -> nix_c::ifreq {
        let mut ifr = ifr_with_name(name);

        let mut addr = unsafe { mem::zeroed::<nix_c::sockaddr_in>() };
        addr.sin_family = nix_c::AF_INET as u16;
        addr.sin_addr = nix_c::in_addr {
            s_addr: u32::from_ne_bytes(ipaddr.octets()),
        };
        ifr.ifr_ifru.ifru_addr =
            unsafe { mem::transmute::<nix_c::sockaddr_in, nix_c::sockaddr>(addr) };
        ifr
    }

    fn setup_default_tap_gateway(ifr: &mut nix_c::ifreq) -> nix_c::rtentry {
        let mut route = unsafe { mem::zeroed::<nix_c::rtentry>() };

        // Set the gateway IP.
        let mut gateway_sa = unsafe { mem::zeroed::<nix_c::sockaddr_in>() };
        gateway_sa.sin_family = nix_c::AF_INET as u16;
        let ipaddr = Ipv4Addr::new(172, 31, 10, 83);
        gateway_sa.sin_addr.s_addr = u32::from(ipaddr).to_be();
        route.rt_gateway =
            unsafe { mem::transmute::<nix_c::sockaddr_in, nix_c::sockaddr>(gateway_sa) };

        // Set the destination to 0.0.0.0 (default route).
        let mut dest_sa = unsafe { mem::zeroed::<nix_c::sockaddr_in>() };
        dest_sa.sin_family = nix_c::AF_INET as u16;
        dest_sa.sin_addr.s_addr = nix_c::INADDR_ANY;
        route.rt_dst = unsafe { mem::transmute::<nix_c::sockaddr_in, nix_c::sockaddr>(dest_sa) };

        // Set the genmask to 0.0.0.0
        let mut genmask_sa = unsafe { mem::zeroed::<nix_c::sockaddr_in>() };
        genmask_sa.sin_family = nix_c::AF_INET as u16;
        genmask_sa.sin_addr.s_addr = nix_c::INADDR_ANY;
        route.rt_genmask =
            unsafe { mem::transmute::<nix_c::sockaddr_in, nix_c::sockaddr>(genmask_sa) };

        // Set the flags to UP and GATEWAY for default gateway.
        route.rt_flags = nix_c::RTF_UP | nix_c::RTF_GATEWAY;

        // Set the interface.
        route.rt_dev = ifr.ifr_name.as_mut_ptr();

        route
    }

    /// Assign IP data to route enclave network to the TAP device.
    fn assign_tap_ipaddr(name: &str) -> anyhow::Result<()> {
        let sock_fd = socket::socket(
            AddressFamily::Inet,
            SockType::Datagram,
            SockFlag::empty(),
            None,
        )?;

        // Set the IP address
        let ipaddr = Ipv4Addr::new(172, 31, 10, 83);
        let mut ifr = ifr_with_name_and_addr(name, ipaddr);
        nix::ioctl_write_ptr_bad!(siocsifaddr, nix_c::SIOCSIFADDR, nix_c::ifreq);
        unsafe { siocsifaddr(sock_fd.as_raw_fd(), &ifr).context("unable to set TAP IP address")? };

        // Set the netmask.
        let ipaddr = Ipv4Addr::new(255, 255, 255, 0);
        ifr = ifr_with_name_and_addr(name, ipaddr);
        nix::ioctl_write_ptr_bad!(siocsifnetmask, nix_c::SIOCSIFNETMASK, nix_c::ifreq);
        unsafe {
            siocsifnetmask(sock_fd.as_raw_fd(), &ifr).context("unable to set TAP netmask")?;
        }

        // Set the MAC address.
        ifr = ifr_with_name(name);
        ifr.ifr_ifru.ifru_hwaddr.sa_family = nix_c::ARPHRD_ETHER;
        let mac: [u8; 6] = [0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee];
        unsafe {
            ifr.ifr_ifru.ifru_hwaddr.sa_data[..mac.len()]
                .copy_from_slice(&mac.map(|i| i as nix_c::c_char))
        };

        nix::ioctl_write_ptr_bad!(siocsifhwaddr, nix_c::SIOCSIFHWADDR, nix_c::ifreq);
        unsafe {
            siocsifhwaddr(sock_fd.as_raw_fd(), &ifr).context("unable to set TAP MAC address")?
        };

        // Set the flags to UP and RUNNING.
        ifr = ifr_with_name(name);
        nix::ioctl_read_bad!(siocgifflags, nix_c::SIOCGIFFLAGS, nix_c::ifreq);
        nix::ioctl_write_ptr_bad!(siocsifflags, nix_c::SIOCSIFFLAGS, nix_c::ifreq);
        unsafe {
            siocgifflags(sock_fd.as_raw_fd(), &mut ifr).context("unable to get TAP flags")?;
            ifr.ifr_ifru.ifru_flags |= (nix_c::IFF_UP | nix_c::IFF_RUNNING) as i16;
            siocsifflags(sock_fd.as_raw_fd(), &ifr).context("unable to get TAP flags")?;
        }

        // Set the default gateway to the TAP device.
        let route = setup_default_tap_gateway(&mut ifr);
        nix::ioctl_write_ptr_bad!(siocaddrt, nix_c::SIOCADDRT, nix_c::rtentry);
        unsafe {
            siocaddrt(sock_fd.as_raw_fd(), &route)
                .context("unable to set default gateway for TAP device")?;
        }
        Ok(())
    }

    fn ifr_with_name(name: &str) -> nix_c::ifreq {
        let mut ifreq = unsafe { mem::zeroed::<nix_c::ifreq>() };
        let name_bytes: Vec<nix_c::c_char> = name
            .as_bytes()
            .iter()
            .map(|c| *c as nix_c::c_char)
            .collect();
        ifreq.ifr_name[..name_bytes.len()].copy_from_slice(&name_bytes);
        ifreq
    }

    /// Allocate a TAP device for enclave network traffic.
    fn alloc_tap(name: &mut String) -> anyhow::Result<File> {
        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/net/tun")
            .context("unable to open /dev/net/tun")?;

        let mut ifreq = ifr_with_name(name.as_str());
        ifreq.ifr_ifru.ifru_flags = (nix_c::IFF_TAP | nix_c::IFF_NO_PI) as i16;

        // TUNSETIFF = _IOW('T', 202, int)
        nix::ioctl_write_ptr_bad!(tunsetiff, 0x400454ca, nix_c::ifreq);
        unsafe { tunsetiff(f.as_raw_fd(), &ifreq).context("unable to call tunsetiff ioctl")? };

        let len = ifreq
            .ifr_name
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(ifreq.ifr_name.len());
        name.clear();
        name.push_str(&String::from_utf8_lossy(
            #[allow(clippy::unnecessary_cast)]
            &ifreq.ifr_name[..len]
                .iter()
                .map(|&c| c as u8)
                .collect::<Vec<u8>>(),
        ));

        assign_tap_ipaddr(name).context("unable to assign IP data to TAP device")?;
        Ok(f)
    }

    /// Forward ethernet packets to/from the host vsock providing network access
    /// and the guest TAP device routing application network traffic.
    fn forward_network_traffic(
        writep: &OwnedFd,
        shutdown_read: &OwnedFd,
        tap_name: &str,
        stream: &mut VsockStream,
        tun_fd: &mut File,
    ) -> anyhow::Result<()> {
        // Fetch the TAP device's Maximum Transfer Unit (MTU) and allocate a
        // buffer in that size to transfer ethernet frames to/from the host.
        let sock_fd = socket::socket(
            AddressFamily::Inet,
            SockType::Datagram,
            SockFlag::empty(),
            None,
        )
        .context("unable to create INET socket to get TAP MTU")?;
        let mut ifr = ifr_with_name(tap_name);

        nix::ioctl_read_bad!(siocgifmtu, nix_c::SIOCGIFMTU, nix_c::ifreq);
        unsafe {
            siocgifmtu(sock_fd.as_raw_fd(), &mut ifr).context("unable to call siocgifmtu ioctl")?
        };

        drop(sock_fd);

        let eth_frame_size = unsafe { ifr.ifr_ifru.ifru_mtu + ETH_HEADER_LEN };
        let mut buf: Vec<u8> = vec![0; eth_frame_size as usize];

        // Forward the max ethernet frame size to the host for it to allocate a
        // corresponding buffer.
        //
        // To avoid issues where the host endianness and the enclave endianness
        // is different, convert to big endian to pass the max ethernet frame
        // size to the host.
        let eth_frame_size_be = (eth_frame_size as u32).to_be_bytes();
        stream
            .write_all(&eth_frame_size_be)
            .context("unable to forward eth frame size to host")?;

        let stream_borrowed_fd = unsafe { BorrowedFd::borrow_raw(stream.as_raw_fd()) };
        let tun_borrowed_fd = unsafe { BorrowedFd::borrow_raw(tun_fd.as_raw_fd()) };
        let shutdown_borrowed_fd = unsafe { BorrowedFd::borrow_raw(shutdown_read.as_raw_fd()) };

        let mut pfds = [
            PollFd::new(stream_borrowed_fd, PollFlags::POLLIN),
            PollFd::new(tun_borrowed_fd, PollFlags::POLLIN),
            PollFd::new(shutdown_borrowed_fd, PollFlags::POLLIN),
        ];

        //Signal to the parent process that initialization is complete.
        unistd::write(writep, &[1])
            .context("unable to signal parent process network proxy is ready")?;

        loop {
            let nready = nix::poll::poll(&mut pfds, PollTimeout::NONE)?;
            if nready == 0 {
                continue;
            }

            let mut event_found = false;
            // Event on vsock. Read the frame and write it to the TAP device.
            if let Some(vsock_event) = pfds[0].revents()
                && vsock_event.contains(PollFlags::POLLIN)
            {
                let mut size = [0u8; 4];
                stream
                    .read_exact(&mut size)
                    .context("unable to read ethernet frame size")?;
                let len = u32::from_be_bytes(size);
                if len > eth_frame_size as u32 {
                    bail!(
                        "ethernet frame size {} exceeds MTU + header size {}",
                        len,
                        eth_frame_size
                    );
                }

                // Resize the buffer to the size of the ethernet frame.
                stream
                    .read_exact(&mut buf[..len as usize])
                    .context("unable to resize buffer to size of ethernet frame")?;

                // TAP devices are expected to write an entire frame at once
                // and not do partial writes. Only retry if the syscall is
                // interrupted.
                tun_fd
                    .write_all(&buf[..len as usize])
                    .context("unable to write eth frame")?;
                event_found = true;
            }

            // Event on the TAP device. Read the frame and write it to the vsock.
            if let Some(tap_event) = pfds[1].revents()
                && tap_event.contains(PollFlags::POLLIN)
            {
                // TAP devices are expected to read an entire frame at once
                // and not do partial reads. Only retry if the syscall is
                // interrupted.
                let nread = loop {
                    match tun_fd.read(&mut buf) {
                        Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                        Ok(0) | Err(_) => {
                            bail!("failed to read the ethernet frame from the TAP device")
                        }
                        Ok(r) => break r,
                    }
                };

                let size = (nread as u32).to_be_bytes();
                stream
                    .write_all(&size)
                    .context("unable to write eth frame size")?;
                stream
                    .write_all(&buf[..nread])
                    .context("unable to write eth frame")?;
                event_found = true;
            }

            if event_found {
                continue;
            }

            // No events on network proxy sockets, check shutdown FD and shut
            // down if event found.
            if let Some(shutdown_event) = pfds[2].revents()
                && shutdown_event == PollFlags::POLLIN
            {
                break;
            }
        }

        Ok(())
    }

    /// Initialize a TAP device to route network to/from.
    fn init_network_proxy(
        readp: &OwnedFd,
        writep: &OwnedFd,
        shutdown_write: &OwnedFd,
        shutdown_read: &OwnedFd,
        vsock_port: u32,
    ) -> anyhow::Result<()> {
        init_tun()?;

        let mut tap_name = String::from("tap0");
        let mut tun_fd = alloc_tap(&mut tap_name)?;

        match unsafe { unistd::fork().context("unable to fork process for network proxy")? } {
            ForkResult::Parent { .. } => {
                let mut buf = [0u8; 1];
                if let Err(e) = unistd::read(readp, &mut buf) {
                    bail!(
                        "error waiting for network proxy to report ready state: {}",
                        e
                    );
                }
                // We can continue onward with execution and not wait for the
                // child to finish
            }
            ForkResult::Child => {
                // Close the child's copy of the write end so the child sees EOF
                // when the parent drops shutdown_write. Uses raw close because we
                // only have a borrow; process::exit() below prevents double-close.
                // To make this explicit, take shutdown_write by value (OwnedFd)
                // and use drop() instead — but that prevents passing it to other
                // proxies from the caller.
                unistd::close(shutdown_write.as_raw_fd())
                    .context("unable to close shutdown_write pipe")?;

                let addr = VsockAddr::new(VMADDR_CID_HOST, vsock_port);
                let mut stream =
                    VsockStream::connect(&addr).context("unable to connect to host")?;
                stream.set_read_timeout(Some(Duration::from_secs(5)))?;
                stream.set_write_timeout(Some(Duration::from_secs(5)))?;

                match forward_network_traffic(
                    writep,
                    shutdown_read,
                    &tap_name,
                    &mut stream,
                    &mut tun_fd,
                ) {
                    Ok(()) => std::process::exit(0),
                    Err(e) => {
                        println!("failure to forward network traffic: {}", e);
                        std::process::exit(1);
                    }
                }
            }
        }

        Ok(())
    }

    /// Initialize a sign handling proxy to forward signals from the host to the parent process.
    fn init_signal_handler_proxy(
        readp: &OwnedFd,
        writep: &OwnedFd,
        shutdown_write: &OwnedFd,
        shutdown_read: &OwnedFd,
        vsock_port: u32,
    ) -> anyhow::Result<()> {
        match unsafe { unistd::fork()? } {
            ForkResult::Parent { .. } => {
                let mut buf = [0u8; 1];
                if let Err(e) = unistd::read(readp, &mut buf) {
                    bail!(
                        "error waiting for signal handler proxy to report ready state: {}",
                        e
                    );
                }
                // We can continue onward with execution and not wait for the
                // child to finish
            }
            ForkResult::Child => {
                unistd::close(shutdown_write.as_raw_fd())
                    .context("unable to close shutdown write pipe")?;

                let addr = VsockAddr::new(VMADDR_CID_HOST, vsock_port);
                let mut stream =
                    VsockStream::connect(&addr).context("unable to connect to host")?;
                stream.set_write_timeout(Some(Duration::from_secs(5)))?;
                stream.set_read_timeout(Some(Duration::from_secs(5)))?;

                let stream_borrowed_fd = unsafe { BorrowedFd::borrow_raw(stream.as_raw_fd()) };
                let shutdown_read_borrowed_fd =
                    unsafe { BorrowedFd::borrow_raw(shutdown_read.as_raw_fd()) };

                let mut pfds = [
                    PollFd::new(stream_borrowed_fd, PollFlags::POLLIN),
                    PollFd::new(shutdown_read_borrowed_fd, PollFlags::POLLIN),
                ];

                // Signal to the parent process that initialization is complete.
                unistd::write(writep, &[1]).context("unable to write signal handler readiness")?;

                loop {
                    let nready = nix::poll::poll(&mut pfds, PollTimeout::NONE)
                        .context("unable to poll fds")?;
                    if nready == 0 {
                        continue;
                    }

                    // Event on vsock. Read the signal and forward it to the parent process.
                    if let Some(vsock_event) = pfds[0].revents()
                        && vsock_event == PollFlags::POLLIN
                    {
                        let mut sig = [0u8; 4];
                        match stream.read_exact(&mut sig) {
                            Ok(()) => {
                                let sig_int = i32::from_ne_bytes(sig);
                                let sig = Signal::try_from(sig_int).unwrap_or(Signal::SIGTERM);
                                signal::kill(unistd::getppid(), sig)
                                    .context(format!("unable to send {} to parent process", sig))?;
                            }
                            Err(_) => signal::kill(unistd::getppid(), Signal::SIGTERM)
                                .context("unable to send SIGTERM to parent process")?,
                        }
                    }

                    // Event on shutdown FD. Close the vsock and exit.
                    if let Some(shutdown_event) = pfds[1].revents()
                        && shutdown_event == PollFlags::POLLIN
                    {
                        break;
                    }
                }
                std::process::exit(0);
            }
        }
        Ok(())
    }

    pub fn init(cid: u32, args: &super::args_reader::EnclaveArgs) -> anyhow::Result<()> {
        let (readp, writep) = nix::unistd::pipe().context("unable to create readiness pipe")?;
        let (shutdown_read, shutdown_write) =
            nix::unistd::pipe().context("unable to create shutdown pipe")?;

        // If not running in debug mode, initialize the application output proxy.
        // Otherwise, the enclave uses the console (which is already connected)
        // for output.
        if args.app_output {
            init_output_proxy(cid + VSOCK_PORT_OFFSET_OUTPUT)?;
        }

        // Initialize the network proxy if configured.
        if args.network_proxy {
            init_network_proxy(
                &readp,
                &writep,
                &shutdown_write,
                &shutdown_read,
                cid + VSOCK_PORT_OFFSET_NET,
            )?;
        }

        // The signal proxy is always initialized to allow the host to send signals to the enclave.
        init_signal_handler_proxy(
            &readp,
            &writep,
            &shutdown_write,
            &shutdown_read,
            cid + VSOCK_PORT_OFFSET_SIGNAL_HANDLER,
        )?;

        Ok(())
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

    // Create a handle to the NSM.
    let nsm_fd = aws_nitro_enclaves_nsm_api::driver::nsm_init();
    if nsm_fd < 0 {
        bail!("unable to open NSM guest module");
    }

    // Measure the rootfs and execution environment in the NSM PCRs.
    nsm::pcr_extend_exec_path(nsm_fd, &args.exec_path, &args.exec_argv, &args.exec_envp)?;

    // Extract the rootfs from memory and write it to the enclave filesystem.
    archive::extract(nsm_fd, &args.rootfs_archive)?;

    // Lock NSM PCRs 16 and 17 and close NSM handle.
    nsm::lock_and_exit(nsm_fd)?;

    // Mount the root filesystem
    fs::mount_rootfs()?;

    // Initialize the rest of the filesystem.
    fs::init_filesystem()?;

    // Initialize the cgroups.
    fs::init_cgroups()?;

    // Initialize each configured device proxy.
    proxy::init(cid, &args)?;

    Ok(())
}
