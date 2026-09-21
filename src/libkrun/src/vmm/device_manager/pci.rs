//! PCI virtio device attachment for x86_64 KVM.
//!
//! A BAR is a guest-chosen MMIO window advertised in configuration space;
//! we preassign each function's BAR0 inside the existing MMIO hole so the
//! address is visible before the guest runs. An interrupt pin (INTA) names
//! which IOAPIC line the device raises; we wire that line with irqfd.

#![cfg(all(target_arch = "x86_64", target_os = "linux"))]

use std::sync::{Arc, Mutex};

use arch::x86_64::layout::{IRQ_BASE, IRQ_MAX, MMIO_MEM_START};
use devices::virtio::{NOTIFY_OFFSET, VIRTIO_PCI_BAR_SIZE, VirtioPciTransport};
use devices::{PciAddress, PciFunction, PciHostBridge, PciRoot};
use kvm_ioctls::{IoEventAddress, VmFd};

use super::mmio::Error as MmioError;

type Result<T> = std::result::Result<T, MmioError>;

/// Per-VM PCI attachment state shared with the conf1 port device.
pub struct PciAttachState {
    pub root: PciRoot,
    next_slot: u8,
    next_irq: u32,
    /// `(PCI slot, IOAPIC pin)` for MP-table INTSRC entries.
    pub intx_routes: Vec<(u8, u32)>,
}

impl PciAttachState {
    pub fn new(root: PciRoot) -> Self {
        Self {
            root,
            next_slot: 1, // 00:00.0 is the host bridge
            next_irq: IRQ_BASE,
            intx_routes: Vec::new(),
        }
    }

    fn alloc_slot_and_irq(&mut self) -> Result<(u8, u32)> {
        if self.next_slot > 31 || self.next_irq > IRQ_MAX {
            return Err(MmioError::IrqsExhausted);
        }
        let slot = self.next_slot;
        let irq = self.next_irq;
        self.next_slot += 1;
        self.next_irq += 1;
        Ok((slot, irq))
    }
}

/// Register a virtio device as a modern PCI function.
pub fn register_pci_device(
    state: &mut PciAttachState,
    vm: &VmFd,
    mmio_bus: &mut devices::Bus,
    mut transport: VirtioPciTransport,
) -> Result<()> {
    let (slot, irq) = state.alloc_slot_and_irq()?;
    let bar_addr = MMIO_MEM_START + u64::from(slot) * u64::from(VIRTIO_PCI_BAR_SIZE);

    transport.config_space().set_bar_address(0, bar_addr as u32);

    for (i, queue_evt) in transport.queue_evts().iter().enumerate() {
        let io_addr = IoEventAddress::Mmio(bar_addr + u64::from(NOTIFY_OFFSET));
        vm.register_ioevent(queue_evt, &io_addr, i as u32)
            .map_err(MmioError::RegisterIoEvent)?;
    }

    vm.register_irqfd(transport.interrupt_evt(), irq)
        .map_err(MmioError::RegisterIrqFd)?;
    transport.set_irq_line(irq);

    let transport = Arc::new(Mutex::new(transport));
    state
        .root
        .add_function(PciAddress::new(0, slot, 0), transport.clone());
    mmio_bus
        .insert(transport, bar_addr, u64::from(VIRTIO_PCI_BAR_SIZE))
        .map_err(MmioError::BusError)?;

    state.intx_routes.push((slot, irq));
    Ok(())
}

/// Install the host bridge at `00:00.0`.
pub fn add_host_bridge(root: &PciRoot) {
    root.add_function(
        PciAddress::new(0, 0, 0),
        Arc::new(Mutex::new(PciHostBridge::new())),
    );
}
