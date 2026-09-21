//! PCI configuration and bus helpers for virtio-pci.
//!
//! A PCI function is discovered through a 256-byte configuration space.
//! Later modules layer Configuration Mechanism #1 (x86 I/O ports) and
//! the virtio-pci capability layout on top of that space.

#[cfg(target_arch = "x86_64")]
mod conf1;
mod config;

#[cfg(target_arch = "x86_64")]
pub use conf1::{PciAddress, PciConfigMechanism1, PciFunction, PciRoot};
pub use config::PciConfigSpace;
