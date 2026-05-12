// SPDX-License-Identifier: Apache-2.0

use crate::bus::BusDevice;

const ADDR_OFFSET: u64 = 0x0;
const DATA_OFFSET: u64 = 0x4;

// i440FX host bridge (bus 0, dev 0, fn 0)
const I440FX_VENDOR: u16 = 0x8086;
const I440FX_DEVICE: u16 = 0x1237;
const I440FX_CLASS: u32 = 0x0600_0000;

// PIIX4 ACPI controller (bus 0, dev 1, fn 3)
const PIIX4_VENDOR: u16 = 0x8086;
const PIIX4_DEVICE: u16 = 0x7113;
const PIIX4_CLASS: u32 = 0x0680_0000;
const PIIX4_PMBA_OFFSET: u8 = 0x40;
const PIIX4_PMBA_VALUE: u32 = 0xB001;
const PIIX4_PMREGMISC_OFFSET: u8 = 0x80;
const PIIX4_PMREGMISC_VALUE: u8 = 0x01;

#[derive(Default)]
pub struct PciConfigSpace {
    address: u32,
}

impl PciConfigSpace {
    pub fn new() -> Self {
        Self { address: 0 }
    }

    fn config_read(&self) -> u32 {
        if self.address & 0x8000_0000 == 0 {
            return 0xFFFF_FFFF;
        }

        let bus = (self.address >> 16) & 0xFF;
        let dev = (self.address >> 11) & 0x1F;
        let func = (self.address >> 8) & 0x7;
        let offset = (self.address & 0xFC) as u8;

        if bus != 0 {
            return 0xFFFF_FFFF;
        }

        match (dev, func) {
            (0, 0) => self.host_bridge_read(offset),
            (1, 3) => self.piix4_pm_read(offset),
            _ => 0xFFFF_FFFF,
        }
    }

    fn host_bridge_read(&self, offset: u8) -> u32 {
        match offset {
            0x00 => (I440FX_DEVICE as u32) << 16 | I440FX_VENDOR as u32,
            0x08 => I440FX_CLASS,
            _ => 0,
        }
    }

    fn piix4_pm_read(&self, offset: u8) -> u32 {
        match offset {
            0x00 => (PIIX4_DEVICE as u32) << 16 | PIIX4_VENDOR as u32,
            0x08 => PIIX4_CLASS,
            PIIX4_PMBA_OFFSET => PIIX4_PMBA_VALUE,
            PIIX4_PMREGMISC_OFFSET => PIIX4_PMREGMISC_VALUE as u32,
            _ => 0,
        }
    }
}

impl BusDevice for PciConfigSpace {
    fn read(&mut self, _vcpuid: u64, offset: u64, data: &mut [u8]) {
        match offset {
            ADDR_OFFSET => {
                let bytes = self.address.to_le_bytes();
                let len = data.len().min(4);
                data[..len].copy_from_slice(&bytes[..len]);
            }
            DATA_OFFSET..=0x7 => {
                let val = self.config_read();
                let byte_offset = (offset - DATA_OFFSET) as usize;
                let bytes = val.to_le_bytes();
                for (i, d) in data.iter_mut().enumerate() {
                    let idx = byte_offset + i;
                    *d = if idx < 4 { bytes[idx] } else { 0 };
                }
            }
            _ => {
                for d in data.iter_mut() {
                    *d = 0xFF;
                }
            }
        }
    }

    fn write(&mut self, _vcpuid: u64, offset: u64, data: &[u8]) {
        if offset == ADDR_OFFSET && data.len() == 4 {
            self.address = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        }
    }
}
