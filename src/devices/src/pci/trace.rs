// Copyright 2026 The libkrun Authors
// SPDX-License-Identifier: Apache-2.0
//
// Targeted virtio-pci bringup tracing. Filter with:
//   RUST_LOG=krun_devices::virtio::pci=debug ...

use utils::byte_order;

use super::PciBdf;

pub(crate) fn ecam_access(bdf: &PciBdf, offset: u16, write: bool, data: &[u8], found: bool) {
    if !found {
        return;
    }

    match offset {
        0 if !write && data.len() >= 4 => {
            let value = byte_order::read_le_u32(data);
            log::debug!(
                target: "krun_devices::virtio::pci",
                "{bdf}: config read vendor/device -> {value:#010x}"
            );
        }
        4 if write && data.len() >= 2 => {
            let cmd = byte_order::read_le_u16(data);
            log::debug!(
                target: "krun_devices::virtio::pci",
                "{bdf}: config write command -> {cmd:#06x}"
            );
        }
        4 if !write && data.len() >= 2 => {
            let cmd = byte_order::read_le_u16(data);
            log::debug!(
                target: "krun_devices::virtio::pci",
                "{bdf}: config read command -> {cmd:#06x}"
            );
        }
        0x10..=0x24 if write => {
            log::debug!(
                target: "krun_devices::virtio::pci",
                "{bdf}: config write BAR offset {offset:#x} data={data:02x?}"
            );
        }
        _ => {}
    }
}
