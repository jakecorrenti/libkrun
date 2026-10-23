use super::*;

use std::sync::{Arc, RwLock};
use std::time::Duration;

use imago::{DynStorage, FormatAccess, Storage, StorageOpenOptions, file::File, raw::Raw};
use utils::eventfd::EFD_NONBLOCK;
use utils::tempfile::TempFile;
use vm_memory::{Bytes, GuestAddress};

use crate::virtio::device::{InterruptHandler, InterruptType};
use crate::virtio::queue::tests::VirtQueue;

struct TestInterrupt;

impl InterruptHandler for TestInterrupt {
    fn try_signal(&self, _: InterruptType) -> Result<(), crate::Error> {
        Ok(())
    }
}

fn disk(direct: bool) -> (TempFile, DiskProperties) {
    let file = TempFile::new().unwrap();
    file.as_file().set_len(1024).unwrap();
    let storage = File::open(
        StorageOpenOptions::new()
            .filename(file.as_path())
            .write(true)
            .direct(direct),
    )
    .unwrap();
    let raw = Raw::<Box<dyn DynStorage>>::open_image(Box::new(storage), true).unwrap();
    let disk = DiskProperties::new(
        Arc::new(RwLock::new(FormatAccess::new(raw))),
        Vec::new(),
        CacheType::Unsafe,
    )
    .unwrap();
    (file, disk)
}

fn request(
    mem: &GuestMemoryMmap,
    queue: &VirtQueue,
    slot: u16,
    request_type: u32,
    sector: u64,
    data_addr: u64,
    data_len: u32,
) {
    let head = slot * 3;
    let header_addr = 0x1000 + u64::from(slot) * 16;
    mem.write_obj(
        RequestHeader {
            request_type,
            sector,
            ..Default::default()
        },
        GuestAddress(header_addr),
    )
    .unwrap();
    queue.dtable[head as usize].set(header_addr, 16, 1, head + 1);
    if request_type == VIRTIO_BLK_T_OUT {
        queue.dtable[head as usize + 1].set(data_addr, data_len, 1, head + 2);
        queue.dtable[head as usize + 2].set(0x1800 + u64::from(slot), 1, 2, 0);
    } else {
        queue.dtable[head as usize + 1].set(data_addr, data_len + 1, 2, 0);
    }
    queue.avail.ring[slot as usize].set(head);
    queue.avail.idx.set(slot + 1);
}

#[test]
fn pooled_reads_with_overlapping_guest_buffers_and_a_write() {
    let (file, disk) = disk(false);
    file.as_file().write_all(&[0x11; 512]).unwrap();
    file.as_file().write_all(&[0x22; 512]).unwrap();
    let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
    let queue = VirtQueue::new(GuestAddress(0), &mem, 32);
    request(&mem, &queue, 0, VIRTIO_BLK_T_IN, 0, 0x2000, 512);
    request(&mem, &queue, 1, VIRTIO_BLK_T_IN, 1, 0x2000, 512);
    request(&mem, &queue, 2, VIRTIO_BLK_T_OUT, 0, 0x3000, 512);
    request(&mem, &queue, 3, VIRTIO_BLK_T_IN, 0, 0x4000, 512);
    mem.write_slice(&[0x33; 512], GuestAddress(0x3000)).unwrap();
    let mut worker = BlockWorker::new(
        DeviceQueue::new(
            queue.create_queue(),
            Arc::new(EventFd::new(EFD_NONBLOCK).unwrap()),
        ),
        InterruptTransport::from_handler(Arc::new(TestInterrupt)),
        mem.clone(),
        disk,
        EventFd::new(EFD_NONBLOCK).unwrap(),
        true,
        Some(2),
    );

    worker.process_virtio_queues();

    assert_eq!(queue.used.idx.get(), 4);
    let first = queue.used.ring[0].get().id;
    let second = queue.used.ring[1].get().id;
    assert!(matches!((first, second), (0, 3) | (3, 0)));
    assert_eq!(queue.used.ring[2].get().id, 6);
    assert_eq!(queue.used.ring[3].get().id, 9);
    let mut data = [0; 512];
    mem.read_slice(&mut data, GuestAddress(0x2000)).unwrap();
    assert_eq!(data, [if second == 0 { 0x11 } else { 0x22 }; 512]);
    mem.read_slice(&mut data, GuestAddress(0x4000)).unwrap();
    assert_eq!(data, [0x33; 512]);
    for addr in [0x2200, 0x1802, 0x4200] {
        assert_eq!(mem.read_obj::<u8>(GuestAddress(addr)).unwrap(), 0);
    }
}

#[test]
fn read_pool_returns_request_ids_and_data() {
    let (file, disk) = disk(false);
    file.as_file().write_all(&[0x11; 512]).unwrap();
    file.as_file().write_all(&[0x22; 512]).unwrap();
    let pool = ReadPool::new(&disk, 2).unwrap();
    pool.submit(0, 512, 512);
    pool.submit(1, 0, 512);
    let mut results = Vec::new();
    for _ in 0..2 {
        let completion = pool
            .completions
            .recv_timeout(Duration::from_secs(5))
            .unwrap();
        results.push((completion.index, completion.result));
    }
    results.sort_by_key(|(index, _)| *index);
    assert_eq!(results[0].1.as_ref().unwrap(), &[0x22; 512]);
    assert_eq!(results[1].1.as_ref().unwrap(), &[0x11; 512]);
}

#[test]
fn invalid_reads_complete_with_ioerr() {
    for parallel in [false, true] {
        let (_file, disk) = disk(false);
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let queue = VirtQueue::new(GuestAddress(0), &mem, 16);
        request(&mem, &queue, 0, VIRTIO_BLK_T_IN, 0, 0x2000, 511);
        request(&mem, &queue, 1, VIRTIO_BLK_T_IN, u64::MAX, 0x3000, 512);
        request(&mem, &queue, 2, VIRTIO_BLK_T_IN, 0, 0x4000, 512);
        let mut worker = BlockWorker::new(
            DeviceQueue::new(
                queue.create_queue(),
                Arc::new(EventFd::new(EFD_NONBLOCK).unwrap()),
            ),
            InterruptTransport::from_handler(Arc::new(TestInterrupt)),
            mem.clone(),
            disk,
            EventFd::new(EFD_NONBLOCK).unwrap(),
            parallel,
            Some(1),
        );

        worker.process_virtio_queues();

        assert_eq!(queue.used.idx.get(), 3);
        assert_eq!(mem.read_obj::<u8>(GuestAddress(0x2000)).unwrap(), 1);
        assert_eq!(mem.read_obj::<u8>(GuestAddress(0x3000)).unwrap(), 1);
        assert_eq!(mem.read_obj::<u8>(GuestAddress(0x4200)).unwrap(), 0);
    }
}

#[cfg(target_os = "linux")]
#[test]
fn pooled_read_supports_direct_io() {
    let (_file, disk) = disk(true);
    let pool = ReadPool::new(&disk, 1).unwrap();
    pool.submit(0, 0, 512);
    let completion = pool
        .completions
        .recv_timeout(Duration::from_secs(5))
        .unwrap();
    assert_eq!(completion.result.unwrap(), [0; 512]);
}

#[test]
fn read_pool_shutdown_finishes_queued_reads() {
    let (_file, disk) = disk(false);
    let pool = ReadPool::new(&disk, 2).unwrap();
    let completions = pool.completions.clone();
    for index in 0..4 {
        pool.submit(index, 0, 512);
    }

    drop(pool);

    assert_eq!(completions.len(), 4);
    for completion in completions {
        assert_eq!(completion.result.unwrap(), [0; 512]);
    }
}
