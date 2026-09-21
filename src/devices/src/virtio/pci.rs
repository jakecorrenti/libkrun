//! Modern (non-transitional) virtio-pci transport layout.
//!
//! Unlike virtio-mmio, virtio-pci has no fixed register map. The driver
//! walks a PCI capability list; each vendor capability names a type
//! (common config, notification, ISR, device-specific config), which
//! BAR holds it, and the offset/length inside that BAR. This module
//! publishes that list and packs all four regions into a single 4 KiB
//! non-prefetchable BAR0.

use crate::pci::PciConfigSpace;

/// Red Hat / OASIS virtio PCI vendor ID.
const VIRTIO_PCI_VENDOR_ID: u16 = 0x1af4;
/// Modern device IDs are `0x1040 + virtio device type`.
const VIRTIO_PCI_DEVICE_ID_BASE: u16 = 0x1040;
/// Revision `1` marks a modern-only (non-transitional) function.
const VIRTIO_PCI_REVISION_MODERN: u8 = 1;

/// PCI capability ID for vendor-specific capabilities.
const PCI_CAP_ID_VNDR: u8 = 0x09;

/// Virtio-pci capability types (virtio spec 4.1.4).
const VIRTIO_PCI_CAP_COMMON_CFG: u8 = 1;
const VIRTIO_PCI_CAP_NOTIFY_CFG: u8 = 2;
const VIRTIO_PCI_CAP_ISR_CFG: u8 = 3;
const VIRTIO_PCI_CAP_DEVICE_CFG: u8 = 4;

/// Total BAR0 size: one page, matching the MMIO transport window.
pub const VIRTIO_PCI_BAR_SIZE: u32 = 0x1000;

/// Offsets of the four virtio regions inside BAR0.
const COMMON_CFG_OFFSET: u32 = 0x0000;
const COMMON_CFG_SIZE: u32 = 0x38;
pub const NOTIFY_OFFSET: u32 = 0x0040;
const NOTIFY_SIZE: u32 = 0x4;
const ISR_OFFSET: u32 = 0x0044;
const ISR_SIZE: u32 = 0x1;
const DEVICE_CFG_OFFSET: u32 = 0x0100;
const DEVICE_CFG_SIZE: u32 = 0x0f00;

/// `notify_off_multiplier == 0`: one notify address; the written value
/// is the queue index (same ioeventfd shape as MMIO's NOTIFY_REG_OFFSET).
const NOTIFY_OFF_MULTIPLIER: u32 = 0;

/// Config-space offset where the capability chain begins (past the header).
const CAP_CHAIN_START: u8 = 0x40;

const VNDR_CAP_LEN: u8 = 16;
const NOTIFY_CAP_LEN: u8 = 20;

/// Build a Type 0 config space for a modern virtio-pci function.
///
/// `device_type` is the virtio device ID (console=3, fs=26, …). Interrupt
/// pin INTA (`1`) is set; the interrupt line is filled in by the VMM when
/// an irqfd is assigned.
pub fn modern_virtio_config_space(device_type: u32) -> PciConfigSpace {
    let mut cfg = PciConfigSpace::new();
    let device_id = VIRTIO_PCI_DEVICE_ID_BASE
        .checked_add(device_type as u16)
        .expect("virtio device type fits in modern PCI device id");

    cfg.set_vendor_id(VIRTIO_PCI_VENDOR_ID);
    cfg.set_device_id(device_id);
    cfg.set_revision_id(VIRTIO_PCI_REVISION_MODERN);
    // Unclassified; modern virtio does not require a specific class.
    cfg.set_class_code(0xff, 0x00, 0x00);
    cfg.set_header_type(0);
    cfg.set_subsystem(VIRTIO_PCI_VENDOR_ID, device_type as u16);
    cfg.set_interrupt_pin(1); // INTA
    cfg.set_bar_memory32(0, VIRTIO_PCI_BAR_SIZE);

    write_capability_chain(&mut cfg);
    cfg
}

fn write_capability_chain(cfg: &mut PciConfigSpace) {
    // Layout in config space:
    //   0x40: common cfg (len 16) -> 0x50
    //   0x50: notify   (len 20) -> 0x64
    //   0x64: isr      (len 16) -> 0x74
    //   0x74: device   (len 16) -> 0
    let common = CAP_CHAIN_START;
    let notify = common + VNDR_CAP_LEN;
    let isr = notify + NOTIFY_CAP_LEN;
    let device = isr + VNDR_CAP_LEN;

    write_virtio_cap(
        cfg,
        common,
        notify,
        VNDR_CAP_LEN,
        VIRTIO_PCI_CAP_COMMON_CFG,
        COMMON_CFG_OFFSET,
        COMMON_CFG_SIZE,
    );
    write_notify_cap(cfg, notify, isr);
    write_virtio_cap(
        cfg,
        isr,
        device,
        VNDR_CAP_LEN,
        VIRTIO_PCI_CAP_ISR_CFG,
        ISR_OFFSET,
        ISR_SIZE,
    );
    write_virtio_cap(
        cfg,
        device,
        0,
        VNDR_CAP_LEN,
        VIRTIO_PCI_CAP_DEVICE_CFG,
        DEVICE_CFG_OFFSET,
        DEVICE_CFG_SIZE,
    );

    cfg.set_capabilities_pointer(common);
}

fn write_virtio_cap(
    cfg: &mut PciConfigSpace,
    offset: u8,
    next: u8,
    cap_len: u8,
    cfg_type: u8,
    bar_offset: u32,
    length: u32,
) {
    let base = offset as usize;
    cfg.write_u8(base, PCI_CAP_ID_VNDR);
    cfg.write_u8(base + 1, next);
    cfg.write_u8(base + 2, cap_len);
    cfg.write_u8(base + 3, cfg_type);
    cfg.write_u32(base + 4, 0); // bar 0, cap id, padding
    cfg.write_u32(base + 8, bar_offset);
    cfg.write_u32(base + 12, length);
}

fn write_notify_cap(cfg: &mut PciConfigSpace, offset: u8, next: u8) {
    write_virtio_cap(
        cfg,
        offset,
        next,
        NOTIFY_CAP_LEN,
        VIRTIO_PCI_CAP_NOTIFY_CFG,
        NOTIFY_OFFSET,
        NOTIFY_SIZE,
    );
    cfg.write_u32(offset as usize + 16, NOTIFY_OFF_MULTIPLIER);
}
