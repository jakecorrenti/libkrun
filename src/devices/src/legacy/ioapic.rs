use kvm_bindings::{
    kvm_enable_cap, kvm_irq_routing, kvm_irq_routing_entry, KVM_CAP_SPLIT_IRQCHIP,
    KVM_IRQ_ROUTING_MSI,
};
use kvm_ioctls::{Error, VmFd};

use utils::eventfd::{EventFd, EFD_SEMAPHORE};
use utils::sized_vec;

use crate::bus::BusDevice;

const APIC_DEFAULT_ADDRESS: u32 = 0xfee0_0000;

const MSI_ADDR_DEST_IDX_SHIFT: u64 = 4;
const MSI_ADDR_DEST_MODE_SHIFT: u64 = 2;

const MSI_DATA_VECTOR_SHIFT: u64 = 0;
const MSI_DATA_TRIGGER_SHIFT: u64 = 15;
const MSI_DATA_DELIVERY_MODE_SHIFT: u64 = 8;

/// I/O Register Select (index) D/I#=0
const IO_REGSEL_OFF: u64 = 0x00;
/// I/O Window (data) D/I#=1
const IO_WIN_OFF: u64 = 0x10;
const IO_EOI_OFF: u64 = 0x40;

const IOAPIC_ID: u8 = 0x00;
const IOAPIC_VER: u8 = 0x01;
const IOAPIC_ARB: u8 = 0x02;

const IOAPIC_ID_SHIFT: u64 = 24;
const IOAPIC_VER_ENTRIES_SHIFT: u64 = 16;
const IOAPIC_REG_REDTBL_BASE: u64 = 0x10;

const IOAPIC_NUM_PINS: usize = 24;

const IOAPIC_LVT_MASKED_SHIFT: u64 = 16;

const IOAPIC_LVT_TRIGGER_MODE_SHIFT: u64 = 15;
const IOAPIC_LVT_TRIGGER_MODE: u64 = 1 << IOAPIC_LVT_TRIGGER_MODE_SHIFT;

const IOAPIC_LVT_REMOTE_IRR_SHIFT: u64 = 14;
const IOAPIC_LVT_REMOTE_IRR: u64 = 1 << IOAPIC_LVT_REMOTE_IRR_SHIFT;

const IOAPIC_LVT_DEST_IDX_SHIFT: u64 = 48;

const IOAPIC_LVT_DEST_MODE_SHIFT: u64 = 11;

const IOAPIC_LVT_DELIV_MODE_SHIFT: u64 = 8;
const IOAPIC_DM_MASK: u64 = 0x7;

const IOAPIC_VECTOR_MASK: u64 = 0xff;
const IOAPIC_DM_EXTINT: u64 = 0x7;

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

fn interrupt_mask(entry: &RedirectionTableEntry) -> u8 {
    ((entry >> IOAPIC_LVT_MASKED_SHIFT) & 1) as u8
}

fn trigger_mode(entry: &RedirectionTableEntry) -> u8 {
    ((entry >> IOAPIC_LVT_TRIGGER_MODE_SHIFT) & 1) as u8
}

fn destination_index(entry: &RedirectionTableEntry) -> u16 {
    ((entry >> IOAPIC_LVT_DEST_IDX_SHIFT) & 0xffff) as u16
}

fn destination_mode(entry: &RedirectionTableEntry) -> u8 {
    ((entry >> IOAPIC_LVT_DEST_MODE_SHIFT) & 1) as u8
}

fn delivery_mode(entry: &RedirectionTableEntry) -> u8 {
    ((entry >> IOAPIC_LVT_DELIV_MODE_SHIFT) & IOAPIC_DM_MASK) as u8
}

fn vector(entry: &RedirectionTableEntry) -> u8 {
    (entry & IOAPIC_VECTOR_MASK) as u8
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

#[derive(Debug, Default)]
pub struct MsiMessage {
    address: u64,
    data: u64,
}

#[derive(Debug)]
pub enum IrqWorkerMessage {
    GsiRoute(u32, u32, Vec<kvm_irq_routing_entry>),
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

    irq_routes: Vec<kvm_irq_routing_entry>,

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

        let mut entries = Vec::with_capacity(IOAPIC_NUM_PINS);
        for i in 0..IOAPIC_NUM_PINS {
            Self::add_msi_route(i, &mut entries);
        }

        let mut irq_routing = sized_vec::vec_with_array_field::<
            kvm_irq_routing,
            kvm_irq_routing_entry,
        >(entries.len());
        unsafe {
            let entries_slice: &mut [kvm_irq_routing_entry] =
                irq_routing[0].entries.as_mut_slice(entries.len());
            entries_slice.copy_from_slice(&entries.as_slice());
        }
        vm.set_gsi_routing(&irq_routing[0]).unwrap();

        let event_fd = EventFd::new(EFD_SEMAPHORE).unwrap();
        let apic = Self {
            id: 0,
            ioregsel: 0,
            irr: 0,
            ioredtbl: [1 << IOAPIC_LVT_MASKED_SHIFT; IOAPIC_NUM_PINS],
            version: 0x20,
            irq_count: [0; IOAPIC_NUM_PINS],
            irq_level: [0; IOAPIC_NUM_PINS],
            irq_eoi: [0; IOAPIC_NUM_PINS],

            irq_routes: entries,

            irq_sender: _irq_sender,
            event_fd,
        };
        Ok(apic)
    }

    fn add_msi_route(virq: usize, entries: &mut Vec<kvm_bindings::kvm_irq_routing_entry>) {
        let msg = MsiMessage::default();
        let mut kroute = kvm_irq_routing_entry::default();
        kroute.gsi = virq as u32;
        kroute.type_ = KVM_IRQ_ROUTING_MSI;
        kroute.flags = 0;
        kroute.u.msi.address_lo = msg.address as u32;
        kroute.u.msi.address_hi = (msg.address >> 32) as u32;
        kroute.u.msi.data = msg.data as u32;

        // 4095 is the max irq number for kvm (MAX_IRQ_ROUTES - 1)
        if entries.len() < 4095 {
            entries.push(kroute);
        } else {
            error!("ioapic: not enough space for irq");
        }
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
            panic!("ioapic: libkrun does not have PIC support");
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
        let mut kroute = kvm_irq_routing_entry::default();
        kroute.gsi = virq as u32;
        kroute.type_ = KVM_IRQ_ROUTING_MSI;
        kroute.flags = 0;
        kroute.u.msi.address_lo = msg.address as u32;
        kroute.u.msi.address_hi = (msg.address >> 32) as u32;
        kroute.u.msi.data = msg.data as u32;

        // update the routing entry
        for entry in self.irq_routes.iter_mut() {
            if entry.gsi == kroute.gsi {
                *entry = kroute;
            }
        }
    }

    fn send_irq_worker_message(&self, msg: IrqWorkerMessage) {
        self.irq_sender
            .send((msg, self.event_fd.try_clone().unwrap()))
            .unwrap();

        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    fn update_routes(&mut self) {
        for i in 0..IOAPIC_NUM_PINS {
            let info = self.parse_entry(&self.ioredtbl[i]);
            // When the bit is 1, the interrupt signal is masked.
            // Edge sensitive interrupts signaled on a masked interrupt pin are ignored.
            // Level-asserts or negates occuring on a masked level-sensitive pin are also
            // ignored and have no side effects. When the bit is 0, the interrupt is not masekd.
            // An edge or level on an interrupt pin that is not masked results in the delivery of
            // the interrupt to the destination.

            if !(info.masked > 0) {
                let msg = MsiMessage {
                    address: info.addr as u64,
                    data: info.data as u64,
                };

                // kvm_irqchip_update_msi_route
                self.update_msi_route(i, &msg);
            }
        }

        self.send_irq_worker_message(IrqWorkerMessage::GsiRoute(
            self.irq_routes.len() as u32,
            0,
            self.irq_routes.clone(),
        ));
    }
}

impl BusDevice for IoApic {
    fn read(&mut self, _vcpuid: u64, offset: u64, data: &mut [u8]) {
        let val = match offset {
            IO_REGSEL_OFF => {
                debug!("ioapic: read: ioregsel");
                self.ioregsel as u32
            }
            IO_WIN_OFF => {
                // the data needs to be 32-bits in size
                if data.len() != 4 {
                    error!("ioapic: bad read size {}", data.len());
                    return;
                }

                match self.ioregsel {
                    IOAPIC_ID | IOAPIC_ARB => {
                        debug!("ioapic: read: IOAPIC ID");
                        ((self.id as u64) << IOAPIC_ID_SHIFT) as u32
                    }
                    IOAPIC_VER => {
                        debug!("ioapic: read: IOAPIC version");
                        (self.version as u32
                            | ((IOAPIC_NUM_PINS as u32 - 1) << IOAPIC_VER_ENTRIES_SHIFT))
                            as u32
                    }
                    _ => {
                        let index = (self.ioregsel as u64 - IOAPIC_REG_REDTBL_BASE) >> 1;
                        debug!("ioapic: read: ioredtbl register {}", index);
                        let mut val = 0u32;

                        // we can only read from this register in 32-bit chunks.
                        // Therefore, we need to check if we are reading the
                        // upper 32 bits or the lower
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

        // turn the value into native endian byte order and put that value into `data`
        let out_arr = val.to_ne_bytes();
        for i in 0..4 {
            if i < data.len() {
                data[i] = out_arr[i];
            }
        }
    }

    fn write(&mut self, _vcpuid: u64, offset: u64, data: &[u8]) {
        todo!()
    }
}
