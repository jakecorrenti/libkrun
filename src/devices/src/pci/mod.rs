//! PCI configuration and bus helpers for virtio-pci.
//!
//! A PCI function is discovered through a 256-byte configuration space.
//! Later modules layer Configuration Mechanism #1 (x86 I/O ports) and
//! the virtio-pci capability layout on top of that space.

mod config;

pub use config::PciConfigSpace;
