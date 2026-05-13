// Copyright 2025 Red Hat, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use crate::bus::BusDevice;

const SELECTOR_OFFSET: u64 = 0x0;
const DATA_OFFSET: u64 = 0x1;

const FW_CFG_SIGNATURE: u16 = 0x0000;
const FW_CFG_VERSION: u16 = 0x0001;
const FW_CFG_KERNEL_SIZE: u16 = 0x0008;
const FW_CFG_INITRD_SIZE: u16 = 0x000b;
const FW_CFG_KERNEL_DATA: u16 = 0x0011;
const FW_CFG_INITRD_DATA: u16 = 0x0012;
const FW_CFG_CMDLINE_SIZE: u16 = 0x0014;
const FW_CFG_CMDLINE_DATA: u16 = 0x0015;
const FW_CFG_KERNEL_SETUP_SIZE: u16 = 0x0017;
const FW_CFG_KERNEL_SETUP_DATA: u16 = 0x0018;

pub struct FwCfg {
    items: HashMap<u16, Vec<u8>>,
    selector: u16,
    data_offset: usize,
}

impl FwCfg {
    pub fn new(kernel_data: &[u8], initrd_data: &[u8], cmdline: &str) -> FwCfg {
        let mut items = HashMap::new();

        items.insert(FW_CFG_SIGNATURE, b"QEMU".to_vec());
        items.insert(FW_CFG_VERSION, 1u32.to_le_bytes().to_vec());

        // bzImage: setup_sects at offset 0x1F1
        let setup_sects = kernel_data[0x1F1] as usize;
        let setup_size = (setup_sects + 1) * 512;

        items.insert(
            FW_CFG_KERNEL_SETUP_SIZE,
            (setup_size as u32).to_le_bytes().to_vec(),
        );
        items.insert(FW_CFG_KERNEL_SETUP_DATA, kernel_data[..setup_size].to_vec());

        let kernel_size = kernel_data.len() - setup_size;
        items.insert(
            FW_CFG_KERNEL_SIZE,
            (kernel_size as u32).to_le_bytes().to_vec(),
        );
        items.insert(FW_CFG_KERNEL_DATA, kernel_data[setup_size..].to_vec());

        items.insert(
            FW_CFG_INITRD_SIZE,
            (initrd_data.len() as u32).to_le_bytes().to_vec(),
        );
        items.insert(FW_CFG_INITRD_DATA, initrd_data.to_vec());

        let cmdline_bytes = [cmdline.as_bytes(), &[0]].concat();
        items.insert(
            FW_CFG_CMDLINE_SIZE,
            (cmdline_bytes.len() as u32).to_le_bytes().to_vec(),
        );
        items.insert(FW_CFG_CMDLINE_DATA, cmdline_bytes);

        debug!(
            "fw_cfg: kernel setup_size={setup_size} kernel_size={kernel_size} initrd_size={} cmdline_len={}",
            initrd_data.len(),
            cmdline.len()
        );

        FwCfg {
            items,
            selector: 0,
            data_offset: 0,
        }
    }
}

impl BusDevice for FwCfg {
    fn read(&mut self, _vcpuid: u64, offset: u64, data: &mut [u8]) {
        match offset {
            DATA_OFFSET => {
                for byte in data.iter_mut() {
                    *byte = self
                        .items
                        .get(&self.selector)
                        .and_then(|item| item.get(self.data_offset).copied())
                        .unwrap_or(0);
                    self.data_offset += 1;
                }
            }
            _ => {
                debug!("fw_cfg: unsupported read at offset {offset}");
                for byte in data.iter_mut() {
                    *byte = 0;
                }
            }
        }
    }

    fn write(&mut self, _vcpuid: u64, offset: u64, data: &[u8]) {
        match offset {
            SELECTOR_OFFSET if data.len() >= 2 => {
                self.selector = u16::from_le_bytes([data[0], data[1]]);
                self.data_offset = 0;
                debug!("fw_cfg: select item 0x{:04x}", self.selector);
            }
            _ => {
                debug!(
                    "fw_cfg: unsupported write at offset {offset} len={}",
                    data.len()
                );
            }
        }
    }
}
