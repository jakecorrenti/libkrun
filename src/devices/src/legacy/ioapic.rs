use kvm_bindings::{
    kvm_enable_cap, kvm_irq_routing, kvm_irq_routing_entry, KVM_CAP_SPLIT_IRQCHIP,
    KVM_IRQ_ROUTING_MSI,
};
use kvm_ioctls::{Error, VmFd};

use utils::eventfd::{EventFd, EFD_SEMAPHORE};
use utils::sized_vec;

const IOAPIC_NUM_PINS: usize = 24;

const IOAPIC_LVT_MASKED_SHIFT: u64 = 16;

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
}
