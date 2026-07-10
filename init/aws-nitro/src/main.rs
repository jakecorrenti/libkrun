mod args_reader;
mod fs;
mod kernel_mods;

use anyhow::Context;

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
    let _args = args_reader::read(cid + VSOCK_PORT_OFFSET_ARGS_READER)?;

    Ok(())
}
