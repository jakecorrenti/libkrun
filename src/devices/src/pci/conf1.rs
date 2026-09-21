//! PCI Configuration Mechanism #1 (x86).
//!
//! On PCs without firmware ECAM, the guest reaches configuration space
//! through two I/O ports: it writes an address dword to `0xCF8`
//! (bus/device/function/register plus an enable bit) and then reads or
//! writes the selected dword through `0xCFC`. Empty functions return
//! `0xffff` for the vendor ID so the probe stops. Linux only trusts
//! these ports after it finds a host bridge answering on some slot.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use crate::bus::BusDevice;

use super::config::PciConfigSpace;

/// CONFIG_ADDRESS (`0xCF8`) enable bit — without it, data accesses are ignored.
const CONFIG_ADDRESS_ENABLE: u32 = 1 << 31;

type FunctionMap = BTreeMap<PciAddress, Arc<Mutex<dyn PciFunction>>>;

/// A PCI address in bus/device/function form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PciAddress {
    pub bus: u8,
    pub device: u8,
    pub function: u8,
}

impl PciAddress {
    pub fn new(bus: u8, device: u8, function: u8) -> Self {
        Self {
            bus,
            device,
            function,
        }
    }

    /// Decode the bus/device/function fields of a CONFIG_ADDRESS dword.
    pub fn from_config_address(addr: u32) -> Self {
        Self {
            bus: ((addr >> 16) & 0xff) as u8,
            device: ((addr >> 11) & 0x1f) as u8,
            function: ((addr >> 8) & 0x07) as u8,
        }
    }
}

/// Something that owns a PCI configuration space.
pub trait PciFunction: Send {
    fn config_space(&mut self) -> &mut PciConfigSpace;
}

/// Shared registry of PCI functions on the root bus.
///
/// Held behind `Arc` so the conf1 port device can be cloned into every
/// vCPU's I/O bus while later-attached functions still become visible.
#[derive(Clone, Default)]
pub struct PciRoot {
    functions: Arc<Mutex<FunctionMap>>,
}

impl PciRoot {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_function(&self, address: PciAddress, function: Arc<Mutex<dyn PciFunction>>) {
        self.functions.lock().unwrap().insert(address, function);
    }
}

/// I/O-port device implementing Configuration Mechanism #1 at `0xCF8`/`0xCFC`.
pub struct PciConfigMechanism1 {
    root: PciRoot,
    address_latch: u32,
}

impl PciConfigMechanism1 {
    pub fn new(root: PciRoot) -> Self {
        Self {
            root,
            address_latch: 0,
        }
    }

    fn enabled(&self) -> bool {
        self.address_latch & CONFIG_ADDRESS_ENABLE != 0
    }

    fn register_offset(&self) -> usize {
        (self.address_latch & 0xfc) as usize
    }

    fn with_function_config<R>(&self, f: impl FnOnce(Option<&mut PciConfigSpace>) -> R) -> R {
        if !self.enabled() {
            return f(None);
        }
        let addr = PciAddress::from_config_address(self.address_latch);
        let functions = self.root.functions.lock().unwrap();
        let Some(func) = functions.get(&addr) else {
            return f(None);
        };
        let mut func = func.lock().unwrap();
        f(Some(func.config_space()))
    }
}

impl BusDevice for PciConfigMechanism1 {
    fn read(&mut self, _vcpuid: u64, offset: u64, data: &mut [u8]) {
        match offset {
            0..=3 => {
                let bytes = self.address_latch.to_le_bytes();
                for (slot, src) in data.iter_mut().zip(&bytes[offset as usize..]) {
                    *slot = *src;
                }
            }
            4..=7 => {
                let data_offset = (offset - 4) as usize;
                let reg = self.register_offset() + data_offset;
                self.with_function_config(|cfg| match cfg {
                    Some(cfg) => cfg.read(reg, data),
                    None => data.fill(0xff),
                });
            }
            _ => data.fill(0xff),
        }
    }

    fn write(&mut self, _vcpuid: u64, offset: u64, data: &[u8]) {
        match offset {
            0..=3 => {
                let mut bytes = self.address_latch.to_le_bytes();
                for (slot, src) in bytes[offset as usize..].iter_mut().zip(data) {
                    *slot = *src;
                }
                // Bits 1:0 of CONFIG_ADDRESS are hardwired to zero.
                self.address_latch = u32::from_le_bytes(bytes) & !0x3;
            }
            4..=7 => {
                let data_offset = (offset - 4) as usize;
                let reg = self.register_offset() + data_offset;
                self.with_function_config(|cfg| {
                    if let Some(cfg) = cfg {
                        cfg.write(reg, data);
                    }
                });
            }
            _ => {}
        }
    }
}
