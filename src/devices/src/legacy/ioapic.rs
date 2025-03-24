use std::fmt::Debug;

use crate::legacy::irqchip::IrqChipT;
use crate::Error as DeviceError;
use crate::{bus::BusDevice, virtio::AsAny};

use kvm_bindings::{kvm_enable_cap, KVM_CAP_SPLIT_IRQCHIP};
use kvm_ioctls::{Error, VmFd};
use libc::EFD_NONBLOCK;
use utils::eventfd::EventFd;

pub const IOAPIC_BASE: u32 = 0xfec0_0000;

/// register offsets

/// I/O Register Select (index) D/I#=0
pub const IO_REG_SEL: u64 = 0x00;
/// I/O Window (data) D/I#=1
pub const IO_WIN: u64 = 0x10;

pub const IO_EOI: u64 = 0x40;

/// I/O APIC ID
/// the register contains the 4-bit APIC ID. The APIC bus arbitration ID for the
/// I/O unit is also written during a write to the APICID Register (same data is
/// loaded into both)
pub const IO_APIC_ID: u8 = 0x00;
/// I/O APIC Version
/// identifies the APIC hardware version. Additionally provides the maximum
/// number of entries in the I/O Redirection Table
pub const IO_APIC_VER: u8 = 0x01;
/// I/O APIC Arbitration ID
/// contains the bus arbitration priority for the I/O APIC. This register is
/// loaded when the I/O APIC ID Register is written.
pub const IO_APIC_ARB: u8 = 0x02;

/// 63:56 Destination Field (RW)
/// 55:17 Reserved
/// 16 Interrupt Mask (RW)
/// 15 Trigger Mode (RW)
/// 14 Remote IRR (RO)
/// 13 Interrupt Input Pin Polarity (INTPOL) (RW)
/// 12 Delivery Status (DELIVS) (RO)
/// 11 Destination Mode (DESTMOD) (RW)
/// 10:8 Delivery Mode (DELMOD) (RW)
/// 7:0 Interrupt Vector (INTVEC) (RW)
type RedirectionTableEntry = u64;

/// A 3-bit field that specifies how the APICs listed in the destination field should act upon
/// reception of this signal. Note that certain Delivery Modes only operate as intended when used
#[repr(u8)]
pub enum DeliveryMode {
    /// Deliver the signal on the INTR signal of all processor cores listed in the destination.
    /// Trigger Mode for "fixed". Delivery Mode can be `Edge` or `Level`
    Fixed = 0b000,

    /// Deliver the signal on the INTR signal of the processor core that is executing at the lowest
    /// priority among all the processors listed in the specified destination. Trigger Mode for
    /// "lowest priority". Delivery Mode can be `Edge` or `Level`
    LowestPriority = 0b001,

    /// System Management Interrupt. A delivery mode equal to SMI requires an `Edge` Trigger Mode.
    /// The vector information is ignored but must be programmed to all zeroes for future
    /// compatibility.
    SMI = 0b010,

    Reserved = 0b011,

    /// Deliver the signal on the NMI signal of all processor cores listed in the destination.
    /// Vector information is ignored. NMI is treated as an `Edge` triggered interrupt, even if it
    /// is programmed as a `Level` triggered interrupt. For proper operation, this redirection
    /// table entry must be programmed to `Edge` triggered interrupt.
    NMI = 0b100,

    /// Deliver the signal to all processor cores listed in the destination by asserting the INIT
    /// signal. All addressed local APICs will assume their INIT state. INIT is always treated as
    /// an `Edge` triggered interrupt, even if programmed otherwise. For proper operation, this
    /// redirection table entry must be programmed to `Edge` triggered interrupt.
    INIT = 0b101,

    Reserved2 = 0b110,

    /// Deliver the signal to the INTR signal of all processor cores listed in the destination as
    /// an interrupt that originated in an externally connected (8259A-compatible) interrupt
    /// controller. The INTA cycle that corresponds to this ExtInt delivery is routed to the
    /// external controller that is expected to supply the vector. A Delivery Mode of `ExtInt`
    /// requires an `Edge` Trigger Mode.
    ExtInt = 0b111,
}

/// Determines the interpretation of the Destination field
#[repr(u8)]
pub enum DestinationMode {
    /// A Destination APIC is identified by its ID. Bits 59:56 of the Destination field specify the
    /// 4-bit APIC ID
    Physical = 0,

    /// Destinations are identified by matching on the logical destination under the control of the
    /// Destination Format Register and Logical Destination Register in each Local APIC.
    Logical = 1,
}

/// Contains the current status of the delivery of the interrupt. Read-only and writes to this bit
/// (as part of a 32-bit word) do not effect this bit.
#[repr(u8)]
pub enum DeliveryStatus {
    /// There is currently no activity for this interrupt
    Idle = 0,

    /// The interrupt has been injected but its delivery is temporarily held up due to the APIC bus
    /// being busy or the inability of the receiving APIC unit to accept that interrupt at that
    /// time
    SendPending = 1,
}

/// Specifies the polarity of the interrupt signal
#[repr(u8)]
pub enum PinPolarity {
    High = 0,
    Low = 1,
}

/// The type of signal on the interrupt pin that triggers an interrupt
#[repr(u8)]
pub enum TriggerMode {
    Edge = 0,
    Level = 1,
}

#[derive(Debug, Default)]
pub struct MSIMessage {
    address: u64,
    data: u64,
}

#[derive(Debug, Default)]
pub struct IoApicEntryInfo {
    masked: u8,
    trig_mode: u8,
    dest_idx: u16,
    dest_mode: u8,
    delivery_mode: u8,
    vector: u8,

    addr: u32,
    data: u32,
}

#[derive(Debug)]
pub struct IoApic {
    ioredtbl: [RedirectionTableEntry; 24],
    irq_entries: kvm_bindings::kvm_irq_routing,
    ioregsel: u8,
    id: u8,
    version: u8,
    irq_sender:
        crossbeam_channel::Sender<(u32, u32, Vec<kvm_bindings::kvm_irq_routing_entry>, EventFd)>,
    irq_receiver: crossbeam_channel::Receiver<u32>,
    event_fd: EventFd,
    irr: u32,
    // vm_fd: kvm_ioctls::VmFd,
}

impl IoApic {
    pub fn new(
        vm: &VmFd,
        irq_sender: crossbeam_channel::Sender<(
            u32,
            u32,
            Vec<kvm_bindings::kvm_irq_routing_entry>,
            EventFd,
        )>,
        irq_receiver: crossbeam_channel::Receiver<u32>,
    ) -> Result<Self, Error> {
        let mut cap = kvm_enable_cap {
            cap: KVM_CAP_SPLIT_IRQCHIP,
            ..Default::default()
        };
        cap.args[0] = 24;
        vm.enable_cap(&cap)?;

        vm.set_gsi_routing(&kvm_bindings::kvm_irq_routing::default())?;
        Ok(Self {
            ioredtbl: [RedirectionTableEntry::default(); 24],
            irq_entries: kvm_bindings::kvm_irq_routing::default(),
            ioregsel: 0,
            id: 0,
            version: 0,
            irr: 0,
            irq_sender,
            irq_receiver,
            event_fd: EventFd::new(EFD_NONBLOCK).unwrap(),
            // vm_fd: vm,
        })
    }

    fn parse_entry(&self, &entry: &RedirectionTableEntry) -> IoApicEntryInfo {
        let mut info = IoApicEntryInfo::default();
        info.masked = ((entry >> 16) & 1) as u8;
        info.trig_mode = ((entry >> 15) & 1) as u8;
        info.dest_idx = ((entry >> 48) & 0xffff) as u16;
        info.dest_mode = ((entry >> 11) & 1) as u8;
        info.delivery_mode = ((entry >> 8) & 0x7) as u8;
        if info.delivery_mode == 0x7 {
            debug!("need to read the pic but that isn't supported");
            // info.vector = pic_read_irq();
        } else {
            info.vector = (entry & 0xff) as u8;
        }

        info.addr =
            (0xfec00000u32 | (info.dest_idx << 4) as u32 | (info.dest_mode << 2) as u32) as u32;
        info.data = (info.vector << 0) as u32
            | ((info.trig_mode as u32) << 15u8) as u32
            | ((info.delivery_mode as u32) << 8u8) as u32;

        info
    }

    fn update_kvm_routes(&mut self) {
        for i in 0..24 {
            let entry = self.parse_entry(&self.ioredtbl[i]);
            let mut msg = MSIMessage {
                address: entry.addr as u64,
                data: entry.data as u64,
            };
            if !(entry.masked > 0) {
                // update msi route
                self.update_msi_route(i as u32, &mut msg);
            }
        }

        // equivalent to kvm_irqchip_commit_routes
        let mut entries = Vec::new();
        for entry in unsafe {
            self.irq_entries
                .entries
                .as_slice(self.irq_entries.nr as usize)
                .iter()
        } {
            entries.push(*entry);
        }

        self.irq_sender
            .send((
                self.irq_entries.nr,
                self.irq_entries.flags,
                entries,
                self.event_fd.try_clone().unwrap(),
            ))
            .unwrap();

        loop {
            match self.event_fd.read() {
                Err(e) => {
                    if e.raw_os_error().unwrap() == libc::EAGAIN {
                        continue;
                    } else {
                        error!("error reading irq event fd {:#?}", e);
                        break;
                    }
                }
                Ok(_) => break,
            }
        }
    }

    fn update_msi_route(&mut self, virq: u32, msg: &mut MSIMessage) {
        let mut kroute = kvm_bindings::kvm_irq_routing_entry::default();
        kroute.gsi = virq;
        kroute.type_ = kvm_bindings::KVM_IRQ_ROUTING_MSI;
        kroute.flags = 0;
        kroute.u.msi.address_lo = msg.address as u32;
        kroute.u.msi.address_hi = (msg.address >> 32) as u32;
        kroute.u.msi.data = msg.data as u32;

        // qemu also calls kvm_arch_fixup_msi_route here. not sure if that's completely necessary

        // update the routing entry
        for entry in unsafe {
            self.irq_entries
                .entries
                .as_mut_slice(self.irq_entries.nr as usize)
                .iter_mut()
        } {
            if entry.gsi != kroute.gsi {
                continue;
            }

            debug!("updating msi route");
            *entry = kroute;
        }
    }

    fn service_irq(&mut self) {
        let mut mask = 0;
        let mut entry: RedirectionTableEntry = Default::default();
        let mut info: IoApicEntryInfo = Default::default();
        for i in 0..24 {
            mask = 1 << i;
            if self.irr & mask < 1 {
                continue;
            }

            let mut coalesce = 0;
            entry = self.ioredtbl[i];
            info = self.parse_entry(&entry);
            if !(info.masked > 0) {
                if info.trig_mode == 0 {
                    self.irr &= !mask;
                } else {
                    coalesce = self.ioredtbl[i] & (1 << 14);
                    self.ioredtbl[i] |= 1 << 14;
                }

                if coalesce > 0 {
                    continue;
                }

                if info.trig_mode == 0 {
                    // kvm_set_irq(i, 1)
                    // kvm_set_irq(i, 0)
                } else {
                    // kvm_set_irq(i, 1)
                }
            }
        }
    }
}

impl IrqChipT for IoApic {
    fn get_mmio_addr(&self) -> u64 {
        0xfec00000
    }

    fn get_mmio_size(&self) -> u64 {
        0x1000
    }

    // TODO(jakecorrenti): figure out why this isn't getting called
    fn set_irq(
        &self,
        _irq_line: Option<u32>,
        interrupt_evt: Option<&EventFd>,
    ) -> Result<(), DeviceError> {
        debug!("setting irq for io apic");
        Ok(())
    }
}

impl BusDevice for IoApic {
    fn read(&mut self, vcpuid: u64, offset: u64, data: &mut [u8]) {
        debug!("read data: {:?}", data);
        let mut val = 0u32;
        let mut index = 0;

        match offset {
            IO_REG_SEL => {
                val = self.ioregsel as u32;
                debug!("reading ioregsel with val: 0x{:x}", val);
            }
            IO_WIN => {
                if data.len() != 4 {
                    debug!("bad data read size");
                    return;
                }

                match self.ioregsel {
                    IO_APIC_ID | IO_APIC_ARB => {
                        val = ((self.id as u32) << 24u32) as u32;
                        debug!("reading either id or arb with val: 0x{:x}", val);
                    }
                    IO_APIC_VER => {
                        val = (self.version as u32 | ((24u32 - 1) << 16u32)) as u32;
                        debug!("reading apic ver with val: 0x{:x}", val);
                    }
                    _ => {
                        debug!("reading other register");
                        index = (self.ioregsel - 0x10) >> 1;
                        if index >= 0 && index < 24 {
                            if self.ioregsel & 1 > 0 {
                                val = (self.ioredtbl[index as usize] >> 32) as u32;
                            } else {
                                val = (self.ioredtbl[index as usize] & 0xffffffffu64) as u32;
                            }
                        }
                    }
                }
            }
            _ => unreachable!(),
        }

        // TODO(jakecorrenti): need to set the data to whatever is in val
        let out_arr = val.to_ne_bytes();
        for i in 0..4 {
            if i < data.len() {
                data[i] = out_arr[i];
            }
        }
    }

    // see `ioapic_mem_write` in qemu as reference implementation
    fn write(&mut self, vcpuid: u64, offset: u64, data: &[u8]) {
        const IOAPIC_RO_BITS: u64 = (1 << 14) | (1 << 12);
        const IOAPIC_RW_BITS: u64 = !IOAPIC_RO_BITS;
        debug!("write data: {:?}", data);
        match offset {
            IO_REG_SEL => {
                self.ioregsel = data[0];
                debug!("writing ioregsel with val: 0x{:x}", self.ioregsel);
            }
            IO_WIN => {
                if data.len() != 4 {
                    debug!("bad data write size");
                    return;
                }

                match self.ioregsel {
                    IO_APIC_ID => {
                        self.id = data[0];
                        debug!("writing apic id reg");
                    }
                    IO_APIC_VER | IO_APIC_ARB => {
                        debug!("ignoring write to apic ver and apic arb");
                    }
                    _ => {
                        debug!("writing to default ioregsel");
                        let index = (self.ioregsel - 0x10) >> 1;
                        if index >= 0 && index <= 24 {
                            let ro_bits: u64 = self.ioredtbl[index as usize] & IOAPIC_RO_BITS;
                            if self.ioregsel & 1 > 0 {
                                self.ioredtbl[index as usize] &= 0xffffffffu64;
                                self.ioredtbl[index as usize] |= (data[0] as u64) << 32;
                            } else {
                                self.ioredtbl[index as usize] &= !0xffffffffu64;
                                self.ioredtbl[index as usize] |= data[0] as u64;
                            }
                            // restore RO bits
                            self.ioredtbl[index as usize] &= IOAPIC_RW_BITS;
                            self.ioredtbl[index as usize] |= ro_bits;
                            // TODO: fix_edge_remote_irr
                            fix_edge_remote_irr(&mut self.ioredtbl[index as usize]);
                            // TODO(jakecorrenti): update kvm routes
                            self.update_kvm_routes();
                            // TODO(jakecorrenti): service IRQ
                            self.service_irq();
                        }
                    }
                }
            }
            IO_EOI => {
                if data.len() != 4 && self.version != 0x20 {
                    debug!("Explicit EOI is only supported for IO APIC version 0x20");
                    return;
                }

                // TODO: EOI broadcast
            }
            _ => unreachable!(),
        }
    }
}

fn fix_edge_remote_irr(entry: &mut RedirectionTableEntry) {
    if !(*entry & (1 << 15) > 0) {
        *entry &= !(1 << 14);
    }
}
