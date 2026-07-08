mod kernel_mods;

use anyhow::Context;

fn main() -> anyhow::Result<()> {
    // Some linux modules, like virtio-mmio, may be required for console output. Load these modules
    // immediately to ensure they are available to the initrd.
    kernel_mods::load_modules().context("unable to load linux kernel modules")?;

    Ok(())
}
