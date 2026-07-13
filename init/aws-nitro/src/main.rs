mod archive;
mod args_reader;
mod fs;
mod kernel_mods;
mod nsm;

use anyhow::{Context, bail};

const VSOCK_PORT_OFFSET_ARGS_READER: u32 = 1;

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

    Ok(())
}
