use std::fmt::Debug;

use crate::legacy::irqchip::IrqChipT;
use crate::Error as DeviceError;
use crate::{bus::BusDevice, virtio::AsAny};

use kvm_bindings::{kvm_enable_cap, KVM_CAP_SPLIT_IRQCHIP};
use kvm_ioctls::{Error, VmFd};
use libc::EFD_NONBLOCK;
use utils::eventfd::EventFd;

pub const IOAPIC_BASE: u32 = 0xfec0_0000;
pub const APIC_DEFAULT_ADDRESS: u32 = 0xfee0_0000;

pub const MSI_ADDR_DEST_IDX_SHIFT: u64 = 4;
pub const MSI_ADDR_DEST_MODE_SHIFT: u64 = 2;

pub const MSI_DATA_VECTOR_SHIFT: u64 = 0;
pub const MSI_DATA_TRIGGER_SHIFT: u64 = 15;
pub const MSI_DATA_DELIVERY_MODE_SHIFT: u64 = 8;

pub const IOAPIC_TRIGGER_EDGE: u64 = 0;

/// register offsets

/// I/O Register Select (index) D/I#=0
pub const IO_REG_SEL: u64 = 0x00;
/// I/O Window (data) D/I#=1
pub const IO_WIN: u64 = 0x10;

pub const IO_EOI: u64 = 0x40;

pub const IOAPIC_ID_SHIFT: u64 = 24;
pub const IOAPIC_VER_ENTRIES_SHIFT: u64 = 16;
pub const IOAPIC_REG_REDTBL_BASE: u64 = 0x10;

pub const IOAPIC_LVT_REMOTE_IRR_SHIFT: u64 = 14;
pub const IOAPIC_LVT_REMOTE_IRR: u64 = 1 << IOAPIC_LVT_REMOTE_IRR_SHIFT;
pub const IOAPIC_LVT_DELIV_STATUS_SHIFT: u64 = 12;
pub const IOAPIC_LVT_DELIV_STATUS: u64 = 1 << IOAPIC_LVT_DELIV_STATUS_SHIFT;
pub const IOAPIC_RO_BITS: u64 = IOAPIC_LVT_REMOTE_IRR | IOAPIC_LVT_DELIV_STATUS;
pub const IOAPIC_RW_BITS: u64 = !IOAPIC_RO_BITS;
pub const IOAPIC_ID_MASK: u64 = 0xf;

pub const IOAPIC_LVT_TRIGGER_MODE_SHIFT: u64 = 15;
pub const IOAPIC_LVT_TRIGGER_MODE: u64 = 1 << IOAPIC_LVT_TRIGGER_MODE_SHIFT;

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

pub const IOAPIC_LVT_MASKED_SHIFT: u64 = 16;
pub fn interrupt_mask(entry: &RedirectionTableEntry) -> u8 {
    ((entry >> IOAPIC_LVT_MASKED_SHIFT) & 1) as u8
}

pub fn trigger_mode(entry: &RedirectionTableEntry) -> u8 {
    ((entry >> IOAPIC_LVT_TRIGGER_MODE_SHIFT) & 1) as u8
}

pub const IOAPIC_LVT_DEST_IDX_SHIFT: u64 = 48;
pub fn destination_index(entry: &RedirectionTableEntry) -> u16 {
    ((entry >> IOAPIC_LVT_DEST_IDX_SHIFT) & 0xffff) as u16
}

pub const IOAPIC_LVT_DEST_MODE_SHIFT: u64 = 11;
pub fn destination_mode(entry: &RedirectionTableEntry) -> u8 {
    ((entry >> IOAPIC_LVT_DEST_MODE_SHIFT) & 1) as u8
}

pub const IOAPIC_LVT_DELIV_MODE_SHIFT: u64 = 8;
pub const IOAPIC_DM_MASK: u64 = 0x7;
pub fn delivery_mode(entry: &RedirectionTableEntry) -> u8 {
    ((entry >> IOAPIC_LVT_DELIV_MODE_SHIFT) & IOAPIC_DM_MASK) as u8
}

pub const IOAPIC_VECTOR_MASK: u64 = 0xff;
pub const IOAPIC_DM_EXTINT: u64 = 0x7;
pub fn vector(entry: &RedirectionTableEntry) -> u8 {
    (entry >> IOAPIC_VECTOR_MASK) as u8
}

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

#[derive(Debug)]
pub enum IrqWorkerMessage {
    GsiRoute(u32, u32, Vec<kvm_bindings::kvm_irq_routing_entry>),
    IrqLine(u32, bool),
}

const IOAPIC_NUM_PINS: usize = 24;

#[derive(Default)]
pub struct MsiMessage {
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
    id: u8,
    ioregsel: u8,
    irr: u32,
    ioredtbl: [u64; IOAPIC_NUM_PINS],
    version: u8,
    irq_count: [u64; IOAPIC_NUM_PINS],
    irq_level: [i32; IOAPIC_NUM_PINS],
    irq_eoi: [i32; IOAPIC_NUM_PINS],

    irq_routes: kvm_bindings::kvm_irq_routing,
    gsi_count: i32,

    irq_sender: crossbeam_channel::Sender<(IrqWorkerMessage, EventFd)>,
    event_fd: EventFd,
}

impl IoApic {
    pub fn new(
        vm: &VmFd,
        _irq_sender: crossbeam_channel::Sender<(IrqWorkerMessage, EventFd)>,
    ) -> Result<Self, Error> {
        let mut cap = kvm_enable_cap {
            cap: KVM_CAP_SPLIT_IRQCHIP,
            ..Default::default()
        };
        cap.args[0] = 24;
        vm.enable_cap(&cap)?;

        let _gsi_count = vm.check_extension_int(kvm_ioctls::Cap::IrqRouting) - 1;

        let mut entries = Vec::with_capacity(IOAPIC_NUM_PINS);
        for i in 0..IOAPIC_NUM_PINS {
            Self::add_msi_route(i, &mut entries);
        }

        println!("initial entries vec: {:#?}", entries);

        let mut routing = kvm_bindings::kvm_irq_routing::default();
        routing.nr = entries.len() as u32;

        unsafe {
            routing
                .entries
                .as_mut_slice(routing.nr as usize)
                .copy_from_slice(entries.as_slice());
        }

        let event_fd = EventFd::new(EFD_NONBLOCK).unwrap();
        let apic = Self {
            id: 0,
            ioregsel: 0,
            irr: 0,
            ioredtbl: [0; IOAPIC_NUM_PINS],
            version: 0,
            irq_count: [0; IOAPIC_NUM_PINS],
            irq_level: [0; IOAPIC_NUM_PINS],
            irq_eoi: [0; IOAPIC_NUM_PINS],

            irq_routes: routing,
            gsi_count: _gsi_count as i32,

            irq_sender: _irq_sender,
            event_fd,
        };
        Ok(apic)
    }

    fn add_msi_route(virq: usize, entries: &mut Vec<kvm_bindings::kvm_irq_routing_entry>) {
        let msg = MsiMessage::default();
        let mut kroute = kvm_bindings::kvm_irq_routing_entry::default();
        kroute.gsi = virq as u32;
        kroute.type_ = kvm_bindings::KVM_IRQ_ROUTING_MSI;
        kroute.flags = 0;
        kroute.u.msi.address_lo = msg.address as u32;
        kroute.u.msi.address_hi = (msg.address >> 32) as u32;
        kroute.u.msi.data = msg.data as u32;

        // 4095 is the max irq number for kvm
        if entries.len() < 4095 {
            entries.push(kroute);
        } else {
            error!("ioapic: not enough space for irq");
        }
    }

    fn send_irq_worker_message(&self, msg: IrqWorkerMessage) {
        println!("SENDING IRQ WORKER MESSAGE: {:#?}", msg);
        self.irq_sender
            .send((msg, self.event_fd.try_clone().unwrap()))
            .unwrap();

        std::thread::sleep(std::time::Duration::from_millis(100));
        // loop {
        //     match self.event_fd.read() {
        //         Err(e) => {
        //             if e.raw_os_error().unwrap() == libc::EAGAIN {
        //                 println!("GETTING EGAIN");
        //                 continue;
        //             } else {
        //                 error!("error reading irq event fd {:#?}", e);
        //                 break;
        //             }
        //         }
        //         Ok(_) => {
        //             println!("DONE GETTING EVENT READ");
        //             break;
        //         },
        //     }
        // }
        println!("DONE SENDING IRQ WORKER MESSAGE");
    }

    fn fix_edge_remote_irr(&mut self, index: usize) {
        if !(self.ioredtbl[index] & IOAPIC_LVT_TRIGGER_MODE > 0) {
            self.ioredtbl[index] &= !IOAPIC_LVT_REMOTE_IRR;
        }
    }

    fn parse_entry(&self, entry: &RedirectionTableEntry) -> IoApicEntryInfo {
        let mut info = IoApicEntryInfo::default();
        info.masked = interrupt_mask(entry);
        info.trig_mode = trigger_mode(entry);
        info.dest_idx = destination_index(entry);
        info.dest_mode = destination_mode(entry);
        info.delivery_mode = delivery_mode(entry);
        if (info.delivery_mode as u64) == IOAPIC_DM_EXTINT {
            // here we would determine the vector by reading the PIC IRQ
            error!("ioapic: libkrun does not have PIC support");
        } else {
            info.vector = vector(entry);
        }

        info.addr = ((APIC_DEFAULT_ADDRESS as u64)
            | ((info.dest_idx as u64) << MSI_ADDR_DEST_IDX_SHIFT)
            | ((info.dest_mode as u64) << MSI_ADDR_DEST_MODE_SHIFT)) as u32;

        info.data = (((info.vector as u64) << MSI_DATA_VECTOR_SHIFT)
            | ((info.trig_mode as u64) << MSI_DATA_TRIGGER_SHIFT)
            | ((info.delivery_mode as u64) << MSI_DATA_DELIVERY_MODE_SHIFT))
            as u32;

        info
    }

    fn update_msi_route(&mut self, virq: usize, msg: &MsiMessage) {
        let mut kroute = kvm_bindings::kvm_irq_routing_entry::default();
        kroute.gsi = virq as u32;
        kroute.type_ = kvm_bindings::KVM_IRQ_ROUTING_MSI;
        kroute.flags = 0;
        kroute.u.msi.address_lo = msg.address as u32;
        kroute.u.msi.address_hi = (msg.address >> 32) as u32;

        // update the routing entry

        for entry in unsafe {
            self.irq_routes
                .entries
                .as_mut_slice(self.irq_routes.nr as usize)
                .iter_mut()
        } {
            if entry.gsi != kroute.gsi {
                continue;
            }
            debug!("updating msi route");
            *entry = kroute;
        }
    }

    fn update_routes(&mut self) {
        for i in 0..IOAPIC_NUM_PINS {
            let info = self.parse_entry(&self.ioredtbl[i]);
            if !(info.masked > 0) {
                let msg = MsiMessage {
                    address: info.addr as u64,
                    data: info.data as u64,
                };

                // kvm_irqchip_update_msi_route
                self.update_msi_route(i, &msg);
            }
        }

        // kvm_irqchip_commit_routes
        let mut entries = Vec::new();
        for entry in unsafe {
            self.irq_routes
                .entries
                .as_slice(self.irq_routes.nr as usize)
                .iter()
        } {
            entries.push(*entry);
        }

        self.send_irq_worker_message(IrqWorkerMessage::GsiRoute(
            self.irq_routes.nr,
            self.irq_routes.flags,
            entries,
        ));
    }

    fn service(&mut self) {
        for i in 0..IOAPIC_NUM_PINS {
            let mask = 1 << i;

            if self.irr & mask > 0 {
                let mut coalesce = 0;

                let entry = self.ioredtbl[i];
                let info = self.parse_entry(&entry);
                if !(info.masked > 0) {
                    if info.trig_mode as u64 == IOAPIC_TRIGGER_EDGE {
                        self.irr &= !mask;
                    } else {
                        coalesce = self.ioredtbl[i] & IOAPIC_LVT_REMOTE_IRR;
                        self.ioredtbl[i] |= IOAPIC_LVT_REMOTE_IRR;
                    }

                    if coalesce > 0 {
                        continue;
                    }

                    if info.trig_mode as u64 == IOAPIC_TRIGGER_EDGE {
                        self.send_irq_worker_message(IrqWorkerMessage::IrqLine(i as u32, true));
                        self.send_irq_worker_message(IrqWorkerMessage::IrqLine(i as u32, false));
                    } else {
                        self.send_irq_worker_message(IrqWorkerMessage::IrqLine(i as u32, true));
                    }
                }
            }
        }
    }
}

impl IrqChipT for IoApic {
    fn get_mmio_addr(&self) -> u64 {
        IOAPIC_BASE as u64
    }

    fn get_mmio_size(&self) -> u64 {
        0x10000
    }

    fn set_irq(
        &self,
        _irq_line: Option<u32>,
        interrupt_evt: Option<&EventFd>,
    ) -> Result<(), DeviceError> {
        debug!("setting irq for io apic: {:?}", _irq_line);
        if let Some(interrupt_evt) = interrupt_evt {
            if let Err(e) = interrupt_evt.write(1) {
                error!("Failed to signal used queue: {:?}", e);
                return Err(DeviceError::FailedSignalingUsedQueue(e));
            }
        } else {
            error!("EventFd not set up for irq line");
            return Err(DeviceError::FailedSignalingUsedQueue(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "EventFd not set up for irq line",
            )));
        }
        debug!("done setting irq for io apic: IRQLINE: {:?}", _irq_line);
        Ok(())
    }
}

impl BusDevice for IoApic {
    fn read(&mut self, _vcpuid: u64, offset: u64, data: &mut [u8]) {
        let val = match offset {
            IO_REG_SEL => {
                debug!("ioapic: read: ioregsel");
                self.ioregsel as u32
            }
            IO_WIN => {
                if data.len() != 4 {
                    error!("ioapic: bad read size {}", data.len());
                    return;
                }

                match self.ioregsel {
                    IO_APIC_ID | IO_APIC_ARB => {
                        debug!("ioapic: read: IOAPIC ID");
                        ((self.id as u64) << IOAPIC_ID_SHIFT) as u32
                    }
                    IO_APIC_VER => {
                        debug!("ioapic: read: IOAPIC version");
                        (self.version as u32
                            | ((IOAPIC_NUM_PINS as u32 - 1) << IOAPIC_VER_ENTRIES_SHIFT))
                            as u32
                    }
                    _ => {
                        let index = (self.ioregsel as u64 - IOAPIC_REG_REDTBL_BASE) >> 1;
                        debug!("ioapic: read: index {}", index);
                        let mut val = 0u32;
                        if index < IOAPIC_NUM_PINS as u64 {
                            if self.ioregsel & 1 > 0 {
                                // read upper 32 bits
                                val = (self.ioredtbl[index as usize] >> 32) as u32;
                            } else {
                                // read lower 32 bits
                                val = (self.ioredtbl[index as usize] & 0xffff_ffffu64) as u32;
                            }
                        }
                        val as u32
                    }
                }
            }
            _ => unreachable!(),
        };

        let out_arr = val.to_ne_bytes();
        for i in 0..4 {
            if i < data.len() {
                data[i] = out_arr[i];
            }
        }
    }

    // see `ioapic_mem_write` in qemu as reference implementation
    fn write(&mut self, _vcpuid: u64, offset: u64, data: &[u8]) {
        if data.len() != 4 {
            error!("ioapic: bad write size {}", data.len());
            return;
        }
        let arr = [data[0], data[1], data[2], data[3]];
        let val = u32::from_ne_bytes(arr);
        match offset {
            IO_REG_SEL => {
                debug!("ioapic: write: ioregsel");
                self.ioregsel = val as u8
            }
            IO_WIN => {
                match self.ioregsel {
                    IO_APIC_ID => {
                        debug!("ioapic: write: IOAPIC ID");
                        self.id = ((val >> IOAPIC_ID_SHIFT) & (IOAPIC_ID_MASK as u32)) as u8
                    }
                    IO_APIC_VER | IO_APIC_ARB => debug!("ioapic: write: IOAPIC VERSION"),
                    _ => {
                        let index = (self.ioregsel as u64 - IOAPIC_REG_REDTBL_BASE) >> 1;
                        debug!("ioapic: write: index {}", index);
                        if index < IOAPIC_NUM_PINS as u64 {
                            let ro_bits = self.ioredtbl[index as usize] & IOAPIC_RO_BITS;
                            if self.ioregsel & 1 > 0 {
                                self.ioredtbl[index as usize] &= 0xffff_ffff;
                                self.ioredtbl[index as usize] |= (val as u64) << 32;
                            } else {
                                self.ioredtbl[index as usize] &= !0xffff_ffff;
                                self.ioredtbl[index as usize] |= val as u64;
                            }

                            // restore RO bits
                            self.ioredtbl[index as usize] &= IOAPIC_RW_BITS;
                            self.ioredtbl[index as usize] |= ro_bits;
                            self.irq_eoi[index as usize] = 0;

                            self.fix_edge_remote_irr(index as usize);
                            self.update_routes();
                            self.service();
                        }
                    }
                }
            }
            IO_EOI => todo!(),
            _ => (),
        }
    }
}
