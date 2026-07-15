mod archive;
mod args_reader;
mod fs;
mod kernel_mods;
mod nsm;
mod proxy;

use std::mem::size_of;
use std::os::fd::AsRawFd;

use anyhow::{Context, bail};
use nix::errno::Errno;
use nix::libc as nix_c;
use nix::sys::socket::{self, AddressFamily, SockFlag, SockType};
use vsock::{VMADDR_CID_HOST, VsockAddr, VsockStream};

const VSOCK_PORT_OFFSET_ARGS_READER: u32 = 1;
const SO_VM_SOCKETS_CONNECT_TIMEOUT: nix_c::c_int = 6;

fn connect_host(port: u32) -> anyhow::Result<VsockStream> {
    let socket = socket::socket(
        AddressFamily::Vsock,
        SockType::Stream,
        SockFlag::SOCK_CLOEXEC,
        None,
    )
    .context("unable to create host vsock")?;
    let timeout = nix_c::timeval {
        tv_sec: 5,
        tv_usec: 0,
    };
    let ret = unsafe {
        nix_c::setsockopt(
            socket.as_raw_fd(),
            nix_c::AF_VSOCK,
            SO_VM_SOCKETS_CONNECT_TIMEOUT,
            &timeout as *const _ as *const nix_c::c_void,
            size_of::<nix_c::timeval>() as nix_c::socklen_t,
        )
    };
    Errno::result(ret).context("unable to set host vsock connect timeout")?;

    socket::connect(socket.as_raw_fd(), &VsockAddr::new(VMADDR_CID_HOST, port))
        .context("unable to connect to host vsock")?;
    Ok(VsockStream::from(socket))
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

#[cfg(test)]
mod tests {
    use super::*;
    use vsock::{VMADDR_CID_ANY, VsockListener};

    #[test]
    fn host_connection_has_five_second_connect_timeout() {
        let listener =
            VsockListener::bind_with_cid_port(VMADDR_CID_ANY, nix_c::VMADDR_PORT_ANY).unwrap();
        let stream = connect_host(listener.local_addr().unwrap().port()).unwrap();
        let mut timeout = nix_c::timeval {
            tv_sec: 0,
            tv_usec: 0,
        };
        let mut size = size_of::<nix_c::timeval>() as nix_c::socklen_t;
        let ret = unsafe {
            nix_c::getsockopt(
                stream.as_raw_fd(),
                nix_c::AF_VSOCK,
                SO_VM_SOCKETS_CONNECT_TIMEOUT,
                &mut timeout as *mut _ as *mut nix_c::c_void,
                &mut size,
            )
        };
        Errno::result(ret).unwrap();
        assert_eq!(timeout.tv_sec, 5);
        assert_eq!(timeout.tv_usec, 0);
    }
}
