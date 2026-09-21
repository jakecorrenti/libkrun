//! A minimal PCI host bridge at `00:00.0`.
//!
//! Linux's Configuration Mechanism #1 probe ignores ports `0xCF8`/`0xCFC`
//! unless some function looks like a host bridge (PCI class `0x0600`).
//! Slot `00:00.0` answers that check and does nothing else — virtio
//! devices occupy `00:01.0` onward.

#[cfg(target_arch = "x86_64")]
use super::conf1::PciFunction;
use super::config::PciConfigSpace;

/// Vendor/device used by QEMU's i440FX host bridge; any `0x0600` class works.
const HOST_BRIDGE_VENDOR_ID: u16 = 0x8086;
const HOST_BRIDGE_DEVICE_ID: u16 = 0x1237;

/// PCI class code for a host bridge: base `0x06`, sub `0x00`.
const HOST_BRIDGE_BASE_CLASS: u8 = 0x06;
const HOST_BRIDGE_SUB_CLASS: u8 = 0x00;

/// Host bridge configuration space; no BARs, no capabilities.
pub struct PciHostBridge {
    config: PciConfigSpace,
}

impl PciHostBridge {
    pub fn new() -> Self {
        let mut config = PciConfigSpace::new();
        config.set_vendor_id(HOST_BRIDGE_VENDOR_ID);
        config.set_device_id(HOST_BRIDGE_DEVICE_ID);
        config.set_class_code(HOST_BRIDGE_BASE_CLASS, HOST_BRIDGE_SUB_CLASS, 0);
        config.set_header_type(0);
        Self { config }
    }
}

impl Default for PciHostBridge {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_arch = "x86_64")]
impl PciFunction for PciHostBridge {
    fn config_space(&mut self) -> &mut PciConfigSpace {
        &mut self.config
    }
}
