//! A 256-byte PCI configuration space for a single function.
//!
//! Every PCI function exposes this space. The first 64 bytes are the
//! standard Type 0 header: vendor/device IDs so software can recognize
//! the function, a command/status pair that enables decoding, a class
//! code, six Base Address Registers (BARs) that name MMIO or I/O
//! windows, a capability-list pointer, and an interrupt pin. Accesses
//! are little-endian at 1-, 2-, or 4-byte widths, matching what a guest
//! OS issues through Configuration Mechanism #1.

const CONFIG_SPACE_SIZE: usize = 256;

/// Standard Type 0 header offsets.
mod offset {
    pub const VENDOR_ID: usize = 0x00;
    pub const DEVICE_ID: usize = 0x02;
    pub const COMMAND: usize = 0x04;
    pub const STATUS: usize = 0x06;
    pub const REVISION_ID: usize = 0x08;
    pub const CLASS_CODE: usize = 0x09;
    pub const HEADER_TYPE: usize = 0x0e;
    pub const BAR0: usize = 0x10;
    pub const SUBSYSTEM_VENDOR_ID: usize = 0x2c;
    pub const SUBSYSTEM_ID: usize = 0x2e;
    pub const CAPABILITY_POINTER: usize = 0x34;
    pub const INTERRUPT_LINE: usize = 0x3c;
    pub const INTERRUPT_PIN: usize = 0x3d;
}

/// Command register bits the guest may set.
mod command {
    pub const IO_SPACE: u16 = 1 << 0;
    pub const MEMORY_SPACE: u16 = 1 << 1;
    pub const BUS_MASTER: u16 = 1 << 2;
}

/// Status register bits.
mod status {
    /// Set when [`offset::CAPABILITY_POINTER`] is non-zero.
    pub const CAPABILITIES_LIST: u16 = 1 << 4;
}

/// Bits of a BAR the guest may program; the low bits encode type.
const BAR_ADDRESS_MASK: u32 = !0xf;

/// A Type 0 PCI configuration space.
pub struct PciConfigSpace {
    data: [u8; CONFIG_SPACE_SIZE],
    /// Encoded size for each BAR (write `0xffff_ffff`, read this mask).
    bar_sizes: [u32; 6],
}

impl Default for PciConfigSpace {
    fn default() -> Self {
        Self::new()
    }
}

impl PciConfigSpace {
    pub fn new() -> Self {
        Self {
            data: [0; CONFIG_SPACE_SIZE],
            bar_sizes: [0; 6],
        }
    }

    pub(crate) fn write_u8(&mut self, offset: usize, value: u8) {
        if let Some(slot) = self.data.get_mut(offset) {
            *slot = value;
        }
    }

    pub(crate) fn read_u8(&self, offset: usize) -> u8 {
        self.data.get(offset).copied().unwrap_or(0)
    }

    fn write_u16(&mut self, offset: usize, value: u16) {
        if let Some(dst) = self.data.get_mut(offset..offset + 2) {
            dst.copy_from_slice(&value.to_le_bytes());
        }
    }

    pub(crate) fn read_u16(&self, offset: usize) -> u16 {
        u16::from_le_bytes([self.read_u8(offset), self.read_u8(offset + 1)])
    }

    pub(crate) fn write_u32(&mut self, offset: usize, value: u32) {
        if let Some(dst) = self.data.get_mut(offset..offset + 4) {
            dst.copy_from_slice(&value.to_le_bytes());
        }
    }

    fn read_u32(&self, offset: usize) -> u32 {
        u32::from_le_bytes([
            self.read_u8(offset),
            self.read_u8(offset + 1),
            self.read_u8(offset + 2),
            self.read_u8(offset + 3),
        ])
    }

    pub fn set_vendor_id(&mut self, vendor_id: u16) {
        self.write_u16(offset::VENDOR_ID, vendor_id);
    }

    pub fn set_device_id(&mut self, device_id: u16) {
        self.write_u16(offset::DEVICE_ID, device_id);
    }

    pub fn set_revision_id(&mut self, revision_id: u8) {
        self.write_u8(offset::REVISION_ID, revision_id);
    }

    pub fn set_header_type(&mut self, header_type: u8) {
        self.write_u8(offset::HEADER_TYPE, header_type);
    }

    /// Class code as `(base_class, sub_class, prog_if)`.
    pub fn set_class_code(&mut self, base_class: u8, sub_class: u8, prog_if: u8) {
        self.write_u8(offset::CLASS_CODE, prog_if);
        self.write_u8(offset::CLASS_CODE + 1, sub_class);
        self.write_u8(offset::CLASS_CODE + 2, base_class);
    }

    pub fn set_subsystem(&mut self, vendor_id: u16, id: u16) {
        self.write_u16(offset::SUBSYSTEM_VENDOR_ID, vendor_id);
        self.write_u16(offset::SUBSYSTEM_ID, id);
    }

    pub fn set_interrupt_pin(&mut self, pin: u8) {
        self.write_u8(offset::INTERRUPT_PIN, pin);
    }

    pub fn set_interrupt_line(&mut self, line: u8) {
        self.write_u8(offset::INTERRUPT_LINE, line);
    }

    /// Install a capabilities list starting at `cap_offset` and set the
    /// Status.Capabilities List bit so the guest walks it.
    pub fn set_capabilities_pointer(&mut self, cap_offset: u8) {
        self.write_u8(offset::CAPABILITY_POINTER, cap_offset);
        let status = self.read_u16(offset::STATUS) | status::CAPABILITIES_LIST;
        self.write_u16(offset::STATUS, status);
    }

    fn command(&self) -> u16 {
        self.read_u16(offset::COMMAND)
    }

    /// Declare BAR `index` as a 32-bit non-prefetchable memory window of
    /// `size` bytes. `size` must be a power of two and at least 16.
    pub fn set_bar_memory32(&mut self, index: usize, size: u32) {
        assert!(index < 6);
        assert!(size.is_power_of_two() && size >= 16);
        // Size probe returns bits that are writable; lower 4 bits encode
        // "memory, 32-bit, non-prefetchable" (all zero).
        self.bar_sizes[index] = !(size - 1) & BAR_ADDRESS_MASK;
        self.write_u32(offset::BAR0 + index * 4, 0);
    }

    /// Guest-facing config read at `reg_offset` into `data` (1, 2, or 4 bytes).
    pub fn read(&self, reg_offset: usize, data: &mut [u8]) {
        match data.len() {
            1 => data[0] = self.read_u8(reg_offset),
            2 => data.copy_from_slice(&self.read_u16(reg_offset).to_le_bytes()),
            4 => data.copy_from_slice(&self.read_u32(reg_offset).to_le_bytes()),
            _ => data.fill(0xff),
        }
    }

    /// Guest-facing config write at `reg_offset` from `data` (1, 2, or 4 bytes).
    ///
    /// The guest may update the command register, interrupt line, and BARs
    /// (including the all-ones size probe). Everything else is ignored.
    pub fn write(&mut self, reg_offset: usize, data: &[u8]) {
        match data.len() {
            1 => self.write_at(reg_offset, u32::from(data[0]), 0xff),
            2 => {
                let v = u16::from_le_bytes([data[0], data[1]]);
                self.write_at(reg_offset, u32::from(v), 0xffff);
            }
            4 => {
                let v = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
                self.write_at(reg_offset, v, 0xffff_ffff);
            }
            _ => {}
        }
    }

    fn write_command(&mut self, cmd: u16) {
        const ALLOWED: u16 = command::IO_SPACE | command::MEMORY_SPACE | command::BUS_MASTER;
        self.write_u16(offset::COMMAND, cmd & ALLOWED);
    }

    fn write_at(&mut self, reg_offset: usize, value: u32, mask: u32) {
        if reg_offset >= CONFIG_SPACE_SIZE {
            return;
        }

        let bar_off = reg_offset.wrapping_sub(offset::BAR0);
        if mask == 0xffff_ffff && bar_off < 24 && bar_off.is_multiple_of(4) {
            if value == 0xffff_ffff {
                self.write_u32(reg_offset, self.bar_sizes[bar_off / 4]);
            } else {
                let type_bits = self.read_u32(reg_offset) & !BAR_ADDRESS_MASK;
                self.write_u32(reg_offset, (value & BAR_ADDRESS_MASK) | type_bits);
            }
            return;
        }

        match reg_offset {
            offset::COMMAND => {
                let cmd = match mask {
                    0xff => (self.command() & !0xff) | (value as u16 & 0xff),
                    0xffff | 0xffff_ffff => value as u16,
                    _ => return,
                };
                self.write_command(cmd);
            }
            n if n == offset::COMMAND + 1 && mask == 0xff => {
                self.write_command((self.command() & 0xff) | ((value as u16) << 8));
            }
            offset::INTERRUPT_LINE if mask & 0xff != 0 => {
                self.write_u8(offset::INTERRUPT_LINE, value as u8);
            }
            _ => {}
        }
    }
}
