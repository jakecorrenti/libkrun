use kvm_bindings::{
    kvm_enable_cap, kvm_irq_routing, kvm_irq_routing_entry, KVM_CAP_SPLIT_IRQCHIP,
    KVM_IRQ_ROUTING_MSI,
};
use kvm_ioctls::{Error, VmFd};

use utils::eventfd::{EventFd, EFD_SEMAPHORE};
use utils::sized_vec;

use crate::bus::BusDevice;

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

#[derive(Debug, Default)]
pub struct MsiMessage {
    address: u64,
    data: u64,
}

#[derive(Debug)]
pub enum IrqWorkerMessage {}

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
