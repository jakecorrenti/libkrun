//! Modern (non-transitional) virtio-pci transport.
//!
//! Unlike virtio-mmio, virtio-pci has no fixed register map. The driver
//! walks a PCI capability list; each vendor capability names a type
//! (common config, notification, ISR, device-specific config), which
//! BAR holds it, and the offset/length inside that BAR.
//!
//! The runtime below is the same virtio 1.0 setup sequence as MMIO
//! (features, queues, status, activate), addressed at the offsets the
//! capabilities advertise. ISR is read-to-clear (virtio-pci), not
//! acknowledged through a separate register.

use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, MutexGuard};

use utils::byte_order;
use utils::eventfd::{EFD_NONBLOCK, EventFd};
use virtio_bindings::virtio_ring::VIRTIO_RING_F_EVENT_IDX;
use vm_memory::{GuestAddress, GuestMemoryMmap};

use crate::bus::BusDevice;
use crate::legacy::IrqChip;
use crate::pci::PciConfigSpace;
#[cfg(target_arch = "x86_64")]
use crate::pci::PciFunction;

use super::device_status;
use super::mmio::{CreateMmioTransportError, InterruptTransport};
use super::{DeviceQueue, Queue, QueueConfig, VirtioDevice};

/// Red Hat / OASIS virtio PCI vendor ID.
const VIRTIO_PCI_VENDOR_ID: u16 = 0x1af4;
/// Modern device IDs are `0x1040 + virtio device type`.
const VIRTIO_PCI_DEVICE_ID_BASE: u16 = 0x1040;
/// Revision `1` marks a modern-only (non-transitional) function.
const VIRTIO_PCI_REVISION_MODERN: u8 = 1;

/// PCI capability ID for vendor-specific capabilities.
const PCI_CAP_ID_VNDR: u8 = 0x09;

/// Virtio-pci capability types (virtio spec 4.1.4).
const VIRTIO_PCI_CAP_COMMON_CFG: u8 = 1;
const VIRTIO_PCI_CAP_NOTIFY_CFG: u8 = 2;
const VIRTIO_PCI_CAP_ISR_CFG: u8 = 3;
const VIRTIO_PCI_CAP_DEVICE_CFG: u8 = 4;

/// Total BAR0 size: one page, matching the MMIO transport window.
pub const VIRTIO_PCI_BAR_SIZE: u32 = 0x1000;

/// Offsets of the four virtio regions inside BAR0.
const COMMON_CFG_OFFSET: u32 = 0x0000;
const COMMON_CFG_SIZE: u32 = 0x38;
pub const NOTIFY_OFFSET: u32 = 0x0040;
const NOTIFY_SIZE: u32 = 0x4;
const ISR_OFFSET: u32 = 0x0044;
const ISR_SIZE: u32 = 0x1;
const DEVICE_CFG_OFFSET: u32 = 0x0100;
const DEVICE_CFG_SIZE: u32 = 0x0f00;

/// `notify_off_multiplier == 0`: one notify address; the written value
/// is the queue index (same ioeventfd shape as MMIO's NOTIFY_REG_OFFSET).
const NOTIFY_OFF_MULTIPLIER: u32 = 0;

/// No MSI-X vector assigned (we only offer INTx).
const VIRTIO_MSI_NO_VECTOR: u16 = 0xffff;

/// Config-space offset where the capability chain begins (past the header).
const CAP_CHAIN_START: u8 = 0x40;

const VNDR_CAP_LEN: u8 = 16;
const NOTIFY_CAP_LEN: u8 = 20;

/// Build a Type 0 config space for a modern virtio-pci function.
///
/// `device_type` is the virtio device ID (console=3, fs=26, …). Interrupt
/// pin INTA (`1`) is set; the interrupt line is filled in by the VMM when
/// an irqfd is assigned.
fn modern_virtio_config_space(device_type: u32) -> PciConfigSpace {
    let mut cfg = PciConfigSpace::new();
    let device_id = VIRTIO_PCI_DEVICE_ID_BASE
        .checked_add(device_type as u16)
        .expect("virtio device type fits in modern PCI device id");

    cfg.set_vendor_id(VIRTIO_PCI_VENDOR_ID);
    cfg.set_device_id(device_id);
    cfg.set_revision_id(VIRTIO_PCI_REVISION_MODERN);
    // Unclassified; modern virtio does not require a specific class.
    cfg.set_class_code(0xff, 0x00, 0x00);
    cfg.set_header_type(0);
    cfg.set_subsystem(VIRTIO_PCI_VENDOR_ID, device_type as u16);
    cfg.set_interrupt_pin(1); // INTA
    cfg.set_bar_memory32(0, VIRTIO_PCI_BAR_SIZE);

    write_capability_chain(&mut cfg);
    cfg
}

fn write_capability_chain(cfg: &mut PciConfigSpace) {
    // Layout in config space:
    //   0x40: common cfg (len 16) -> 0x50
    //   0x50: notify   (len 20) -> 0x64
    //   0x64: isr      (len 16) -> 0x74
    //   0x74: device   (len 16) -> 0
    let common = CAP_CHAIN_START;
    let notify = common + VNDR_CAP_LEN;
    let isr = notify + NOTIFY_CAP_LEN;
    let device = isr + VNDR_CAP_LEN;

    write_virtio_cap(
        cfg,
        common,
        notify,
        VNDR_CAP_LEN,
        VIRTIO_PCI_CAP_COMMON_CFG,
        COMMON_CFG_OFFSET,
        COMMON_CFG_SIZE,
    );
    write_notify_cap(cfg, notify, isr);
    write_virtio_cap(
        cfg,
        isr,
        device,
        VNDR_CAP_LEN,
        VIRTIO_PCI_CAP_ISR_CFG,
        ISR_OFFSET,
        ISR_SIZE,
    );
    write_virtio_cap(
        cfg,
        device,
        0,
        VNDR_CAP_LEN,
        VIRTIO_PCI_CAP_DEVICE_CFG,
        DEVICE_CFG_OFFSET,
        DEVICE_CFG_SIZE,
    );

    cfg.set_capabilities_pointer(common);
}

fn write_virtio_cap(
    cfg: &mut PciConfigSpace,
    offset: u8,
    next: u8,
    cap_len: u8,
    cfg_type: u8,
    bar_offset: u32,
    length: u32,
) {
    let base = offset as usize;
    cfg.write_u8(base, PCI_CAP_ID_VNDR);
    cfg.write_u8(base + 1, next);
    cfg.write_u8(base + 2, cap_len);
    cfg.write_u8(base + 3, cfg_type);
    cfg.write_u32(base + 4, 0); // bar 0, cap id, padding
    cfg.write_u32(base + 8, bar_offset);
    cfg.write_u32(base + 12, length);
}

fn write_notify_cap(cfg: &mut PciConfigSpace, offset: u8, next: u8) {
    write_virtio_cap(
        cfg,
        offset,
        next,
        NOTIFY_CAP_LEN,
        VIRTIO_PCI_CAP_NOTIFY_CFG,
        NOTIFY_OFFSET,
        NOTIFY_SIZE,
    );
    cfg.write_u32(offset as usize + 16, NOTIFY_OFF_MULTIPLIER);
}

/// Virtio-pci transport wrapping a [`VirtioDevice`].
///
/// Serves PCI config space (via [`PciFunction`]) and BAR0 MMIO (via
/// [`BusDevice`]). The virtio status/queue sequence is copied from the
/// MMIO transport so MMIO remains an unchanged reference.
pub struct VirtioPciTransport {
    device: Arc<Mutex<dyn VirtioDevice>>,
    config: PciConfigSpace,
    features_select: u32,
    acked_features_select: u32,
    queue_select: u16,
    device_status: u32,
    config_generation: u8,
    mem: GuestMemoryMmap,
    queues: Option<Vec<Queue>>,
    queue_evts: Vec<Arc<EventFd>>,
    queue_config: Vec<QueueConfig>,
    interrupt: InterruptTransport,
}

impl VirtioPciTransport {
    pub fn new(
        mem: GuestMemoryMmap,
        intc: IrqChip,
        device: Arc<Mutex<dyn VirtioDevice>>,
    ) -> Result<Self, CreateMmioTransportError> {
        let locked = device
            .try_lock()
            .expect("VirtioDevice lock held during VirtioPciTransport::new");
        let device_type = locked.device_type();
        let debug_log_target = format!("{}[{}]", module_path!(), locked.device_name());
        let queue_config: Vec<QueueConfig> = locked.queue_config().to_vec();
        drop(locked);

        let queues = Self::create_queues(&queue_config);
        let queue_evts = Self::create_queue_evts(queue_config.len())?;

        Ok(Self {
            config: modern_virtio_config_space(device_type),
            interrupt: InterruptTransport::new(intc, debug_log_target)?,
            device,
            features_select: 0,
            acked_features_select: 0,
            queue_select: 0,
            device_status: device_status::INIT,
            config_generation: 0,
            mem,
            queues: Some(queues),
            queue_evts,
            queue_config,
        })
    }

    fn create_queues(queue_config: &[QueueConfig]) -> Vec<Queue> {
        queue_config.iter().map(|c| Queue::new(c.size)).collect()
    }

    fn create_queue_evts(count: usize) -> Result<Vec<Arc<EventFd>>, CreateMmioTransportError> {
        let mut queue_evts = Vec::with_capacity(count);
        for _ in 0..count {
            queue_evts.push(Arc::new(
                EventFd::new(EFD_NONBLOCK)
                    .map_err(CreateMmioTransportError::CreateInterruptEventFd)?,
            ));
        }
        Ok(queue_evts)
    }

    pub fn set_irq_line(&mut self, irq_line: u32) {
        self.interrupt.set_irq_line(irq_line);
        self.config.set_interrupt_line(irq_line as u8);
    }

    pub fn interrupt_evt(&self) -> &EventFd {
        self.interrupt.event()
    }

    pub fn queue_evts(&self) -> &[Arc<EventFd>] {
        &self.queue_evts
    }

    fn locked_device(&self) -> MutexGuard<'_, dyn VirtioDevice + 'static> {
        self.device.lock().expect("Poisoned device lock")
    }

    fn check_device_status(&self, set: u32, clr: u32) -> bool {
        self.device_status & (set | clr) == set
    }

    fn with_queue<U, F>(&self, d: U, f: F) -> U
    where
        F: FnOnce(&Queue) -> U,
    {
        match &self.queues {
            Some(queues) => match queues.get(self.queue_select as usize) {
                Some(queue) => f(queue),
                None => d,
            },
            None => d,
        }
    }

    fn with_queue_mut<F: FnOnce(&mut Queue)>(&mut self, f: F) -> bool {
        match &mut self.queues {
            Some(queues) => {
                if let Some(queue) = queues.get_mut(self.queue_select as usize) {
                    f(queue);
                    true
                } else {
                    false
                }
            }
            None => false,
        }
    }

    fn update_queue_field<F: FnOnce(&mut Queue)>(&mut self, f: F) {
        if self.check_device_status(device_status::FEATURES_OK, device_status::FAILED) {
            self.with_queue_mut(f);
        } else {
            warn!(
                "update virtio queue in invalid state 0x{:x}",
                self.device_status
            );
        }
    }

    fn reset(&mut self) {
        if self.locked_device().is_activated() {
            debug!("reset device while it's still in active state");
        }
        self.features_select = 0;
        self.acked_features_select = 0;
        self.queue_select = 0;
        self.interrupt.status().store(0, Ordering::SeqCst);
        self.device_status = device_status::INIT;
        self.queues = Some(Self::create_queues(&self.queue_config));
    }

    fn activate(&mut self) {
        let Some(queues) = self.queues.take() else {
            return;
        };

        let mut device_queues: Vec<DeviceQueue> = queues
            .into_iter()
            .zip(self.queue_evts.iter().cloned())
            .map(|(queue, event)| DeviceQueue::new(queue, event))
            .collect();

        let mut locked_device = self.locked_device();
        let event_idx_enabled =
            (locked_device.acked_features() & (1 << VIRTIO_RING_F_EVENT_IDX)) != 0;
        for dq in &mut device_queues {
            dq.queue.set_event_idx(event_idx_enabled);
        }
        locked_device
            .activate(self.mem.clone(), self.interrupt.clone(), device_queues)
            .expect("Failed to activate device");
    }

    fn set_device_status(&mut self, status: u32) {
        match !self.device_status & status {
            device_status::ACKNOWLEDGE if self.device_status == device_status::INIT => {
                self.device_status = status;
            }
            device_status::DRIVER if self.device_status == device_status::ACKNOWLEDGE => {
                self.device_status = status;
            }
            device_status::FEATURES_OK
                if self.device_status == (device_status::ACKNOWLEDGE | device_status::DRIVER) =>
            {
                self.device_status = status;
            }
            device_status::DRIVER_OK
                if self.device_status
                    == (device_status::ACKNOWLEDGE
                        | device_status::DRIVER
                        | device_status::FEATURES_OK) =>
            {
                self.device_status = status;
                if !self.locked_device().is_activated() {
                    self.activate();
                }
            }
            _ if (status & device_status::FAILED) != 0 => {
                self.device_status |= device_status::FAILED;
            }
            _ if status == 0 => {
                if self.locked_device().is_activated() && !self.locked_device().reset() {
                    self.device_status |= device_status::FAILED;
                }
                if self.device_status & device_status::FAILED == 0 {
                    self.reset();
                }
            }
            _ => {
                warn!(
                    "invalid virtio driver status transition: 0x{:x} -> 0x{:x}",
                    self.device_status, status
                );
            }
        }
    }

    fn read_common_cfg(&self, offset: u64, data: &mut [u8]) {
        let value: u64 = match offset {
            0x00 if data.len() == 4 => self.features_select.into(),
            0x04 if data.len() == 4 => {
                let mut features = self
                    .locked_device()
                    .avail_features_by_page(self.features_select);
                if self.features_select == 1 {
                    features |= 0x1; // VIRTIO_F_VERSION_1
                }
                features.into()
            }
            0x08 if data.len() == 4 => self.acked_features_select.into(),
            0x0c if data.len() == 4 => {
                self.locked_device()
                    .acked_features()
                    .wrapping_shr(self.acked_features_select * 32) as u32 as u64
            }
            0x10 if data.len() == 2 => u64::from(VIRTIO_MSI_NO_VECTOR),
            0x12 if data.len() == 2 => self.queue_config.len() as u64,
            0x14 if data.len() == 1 => u64::from(self.device_status as u8),
            0x15 if data.len() == 1 => u64::from(self.config_generation),
            0x16 if data.len() == 2 => u64::from(self.queue_select),
            0x18 if data.len() == 2 => u64::from(self.with_queue(0, |q| q.size)),
            0x1a if data.len() == 2 => u64::from(VIRTIO_MSI_NO_VECTOR),
            0x1c if data.len() == 2 => u64::from(self.with_queue(0, |q| q.ready as u16)),
            0x1e if data.len() == 2 => 0, // notify_off: multiplier 0 → all queues share offset 0
            0x20 if data.len() == 4 => self.with_queue(0, |q| q.desc_table.0 as u32).into(),
            0x24 if data.len() == 4 => self.with_queue(0, |q| (q.desc_table.0 >> 32) as u32).into(),
            0x20 if data.len() == 8 => self.with_queue(0, |q| q.desc_table.0),
            0x28 if data.len() == 4 => self.with_queue(0, |q| q.avail_ring.0 as u32).into(),
            0x2c if data.len() == 4 => self.with_queue(0, |q| (q.avail_ring.0 >> 32) as u32).into(),
            0x28 if data.len() == 8 => self.with_queue(0, |q| q.avail_ring.0),
            0x30 if data.len() == 4 => self.with_queue(0, |q| q.used_ring.0 as u32).into(),
            0x34 if data.len() == 4 => self.with_queue(0, |q| (q.used_ring.0 >> 32) as u32).into(),
            0x30 if data.len() == 8 => self.with_queue(0, |q| q.used_ring.0),
            _ => {
                warn!(
                    "virtio-pci common cfg read: offset=0x{offset:x} len={}",
                    data.len()
                );
                data.fill(0);
                return;
            }
        };
        match data.len() {
            1 => data[0] = value as u8,
            2 => byte_order::write_le_u16(data, value as u16),
            4 => byte_order::write_le_u32(data, value as u32),
            8 => {
                byte_order::write_le_u32(&mut data[..4], value as u32);
                byte_order::write_le_u32(&mut data[4..], (value >> 32) as u32);
            }
            _ => data.fill(0),
        }
    }

    fn write_common_cfg(&mut self, offset: u64, data: &[u8]) {
        fn hi(v: &mut GuestAddress, x: u32) {
            *v = (*v & 0xffff_ffff) | (u64::from(x) << 32);
        }
        fn lo(v: &mut GuestAddress, x: u32) {
            *v = (*v & !0xffff_ffff) | u64::from(x);
        }

        match offset {
            0x00 if data.len() == 4 => self.features_select = byte_order::read_le_u32(data),
            0x08 if data.len() == 4 => self.acked_features_select = byte_order::read_le_u32(data),
            0x0c if data.len() == 4 => {
                let v = byte_order::read_le_u32(data);
                if self.check_device_status(
                    device_status::DRIVER,
                    device_status::FEATURES_OK | device_status::FAILED,
                ) {
                    self.locked_device()
                        .ack_features_by_page(self.acked_features_select, v);
                } else {
                    warn!(
                        "ack virtio features in invalid state 0x{:x}",
                        self.device_status
                    );
                }
            }
            0x10 if data.len() == 2 => { /* msix_config ignored */ }
            0x14 if data.len() == 1 => self.set_device_status(u32::from(data[0])),
            0x16 if data.len() == 2 => self.queue_select = byte_order::read_le_u16(data),
            0x18 if data.len() == 2 => {
                let v = byte_order::read_le_u16(data);
                self.update_queue_field(|q| q.size = v);
            }
            0x1a if data.len() == 2 => { /* queue_msix_vector ignored */ }
            0x1c if data.len() == 2 => {
                let v = byte_order::read_le_u16(data);
                self.update_queue_field(|q| q.ready = v == 1);
            }
            0x20 if data.len() == 4 => {
                let v = byte_order::read_le_u32(data);
                self.update_queue_field(|q| lo(&mut q.desc_table, v));
            }
            0x24 if data.len() == 4 => {
                let v = byte_order::read_le_u32(data);
                self.update_queue_field(|q| hi(&mut q.desc_table, v));
            }
            0x20 if data.len() == 8 => {
                let lo_v = byte_order::read_le_u32(&data[..4]);
                let hi_v = byte_order::read_le_u32(&data[4..]);
                self.update_queue_field(|q| {
                    lo(&mut q.desc_table, lo_v);
                    hi(&mut q.desc_table, hi_v);
                });
            }
            0x28 if data.len() == 4 => {
                let v = byte_order::read_le_u32(data);
                self.update_queue_field(|q| lo(&mut q.avail_ring, v));
            }
            0x2c if data.len() == 4 => {
                let v = byte_order::read_le_u32(data);
                self.update_queue_field(|q| hi(&mut q.avail_ring, v));
            }
            0x28 if data.len() == 8 => {
                let lo_v = byte_order::read_le_u32(&data[..4]);
                let hi_v = byte_order::read_le_u32(&data[4..]);
                self.update_queue_field(|q| {
                    lo(&mut q.avail_ring, lo_v);
                    hi(&mut q.avail_ring, hi_v);
                });
            }
            0x30 if data.len() == 4 => {
                let v = byte_order::read_le_u32(data);
                self.update_queue_field(|q| lo(&mut q.used_ring, v));
            }
            0x34 if data.len() == 4 => {
                let v = byte_order::read_le_u32(data);
                self.update_queue_field(|q| hi(&mut q.used_ring, v));
            }
            0x30 if data.len() == 8 => {
                let lo_v = byte_order::read_le_u32(&data[..4]);
                let hi_v = byte_order::read_le_u32(&data[4..]);
                self.update_queue_field(|q| {
                    lo(&mut q.used_ring, lo_v);
                    hi(&mut q.used_ring, hi_v);
                });
            }
            _ => {
                warn!(
                    "virtio-pci common cfg write: offset=0x{offset:x} len={}",
                    data.len()
                );
            }
        }
    }
}

#[cfg(target_arch = "x86_64")]
impl PciFunction for VirtioPciTransport {
    fn config_space(&mut self) -> &mut PciConfigSpace {
        &mut self.config
    }
}

fn bar_rel(offset: u64, start: u32, size: u32) -> Option<u64> {
    let start = u64::from(start);
    (start..start + u64::from(size))
        .contains(&offset)
        .then_some(offset - start)
}

impl BusDevice for VirtioPciTransport {
    fn read(&mut self, _vcpuid: u64, offset: u64, data: &mut [u8]) {
        if let Some(off) = bar_rel(offset, COMMON_CFG_OFFSET, COMMON_CFG_SIZE) {
            self.read_common_cfg(off, data);
        } else if offset == u64::from(ISR_OFFSET) {
            // Virtio-pci ISR is read-to-clear.
            let status = self.interrupt.status().swap(0, Ordering::SeqCst) as u8;
            if let Some((first, rest)) = data.split_first_mut() {
                *first = status;
                rest.fill(0);
            }
        } else if let Some(off) = bar_rel(offset, DEVICE_CFG_OFFSET, DEVICE_CFG_SIZE) {
            self.locked_device().read_config(off, data);
        } else if offset == u64::from(NOTIFY_OFFSET) {
            data.fill(0);
        } else {
            warn!(
                "virtio-pci BAR read: offset=0x{offset:x} len={}",
                data.len()
            );
            data.fill(0);
        }
    }

    fn write(&mut self, _vcpuid: u64, offset: u64, data: &[u8]) {
        if let Some(off) = bar_rel(offset, COMMON_CFG_OFFSET, COMMON_CFG_SIZE) {
            self.write_common_cfg(off, data);
        } else if offset == u64::from(NOTIFY_OFFSET) {
            let queue_index = match data.len() {
                1 => u32::from(data[0]),
                2 => u32::from(byte_order::read_le_u16(data)),
                4 => byte_order::read_le_u32(data),
                _ => {
                    warn!("virtio-pci notify: bad len {}", data.len());
                    return;
                }
            };
            if let Some(eventfd) = self.queue_evts.get(queue_index as usize) {
                eventfd.write(1).unwrap();
            } else {
                warn!("virtio-pci notify: invalid queue {queue_index}");
            }
        } else if offset == u64::from(ISR_OFFSET) {
            // Writes to ISR are ignored (read-to-clear).
        } else if let Some(off) = bar_rel(offset, DEVICE_CFG_OFFSET, DEVICE_CFG_SIZE) {
            if self.check_device_status(device_status::DRIVER, device_status::FAILED) {
                self.locked_device().write_config(off, data);
            } else {
                warn!("virtio-pci device cfg write before DRIVER status");
            }
        } else {
            warn!(
                "virtio-pci BAR write: offset=0x{offset:x} len={}",
                data.len()
            );
        }
    }

    fn interrupt(&self, irq_mask: u32) -> std::io::Result<()> {
        self.interrupt
            .status()
            .fetch_or(irq_mask as usize, Ordering::SeqCst);
        self.interrupt.event().write(1).unwrap();
        Ok(())
    }
}
