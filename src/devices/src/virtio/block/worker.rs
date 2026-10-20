use crate::virtio::descriptor_utils::{Reader, Writer};

use super::super::DeviceQueue;
use super::device::{CacheType, DiskProperties};
use super::read_pool::{ReadJob, ReadPool};

use crate::virtio::InterruptTransport;
use std::io::{self, Write};
#[cfg(unix)]
use std::os::fd::AsRawFd;
use std::result;
use std::thread;
use utils::epoll::{ControlOperation, Epoll, EpollEvent, EventSet};
use utils::eventfd::EventFd;
#[cfg(target_os = "windows")]
use utils::windows::AsRawFd;
use virtio_bindings::virtio_blk::*;
use vm_memory::{ByteValued, GuestMemoryMmap};

#[allow(dead_code)]
#[derive(Debug)]
pub enum RequestError {
    Discarding(io::Error),
    DiscardingToZero(io::Error),
    FlushingToDisk(io::Error),
    InvalidDataLength,
    ReadingFromDescriptor(io::Error),
    WritingToDescriptor(io::Error),
    WritingZeroes(io::Error),
    UnknownRequest,
}

/// The request header represents the mandatory fields of each block device request.
///
/// A request header contains the following fields:
///   * request_type: an u32 value mapping to a read, write or flush operation.
///   * reserved: 32 bits are reserved for future extensions of the Virtio Spec.
///   * sector: an u64 value representing the offset where a read/write is to occur.
///
/// The header simplifies reading the request from memory as all request follow
/// the same memory layout.
#[derive(Copy, Clone, Default)]
#[repr(C)]
pub struct RequestHeader {
    request_type: u32,
    _reserved: u32,
    sector: u64,
}
// Safe because RequestHeader only contains plain data.
unsafe impl ByteValued for RequestHeader {}

#[derive(Copy, Clone, Default)]
#[repr(C)]
pub struct DiscardWriteData {
    sector: u64,
    num_sectors: u32,
    flags: u32,
}
// Safe because DiscardWriteData only contains plain data.
unsafe impl ByteValued for DiscardWriteData {}

pub struct BlockWorker {
    device_queue: DeviceQueue,
    interrupt: InterruptTransport,
    mem: GuestMemoryMmap,
    disk: DiskProperties,
    stop_fd: EventFd,
    read_pool: Option<ReadPool>,
}

impl BlockWorker {
    pub fn new(
        device_queue: DeviceQueue,
        interrupt: InterruptTransport,
        mem: GuestMemoryMmap,
        disk: DiskProperties,
        stop_fd: EventFd,
        read_pool_threads: Option<usize>,
    ) -> io::Result<Self> {
        let read_pool = read_pool_threads
            .map(|threads| ReadPool::new(&disk, threads))
            .transpose()?;
        Ok(Self {
            device_queue,
            interrupt,
            mem,
            disk,
            stop_fd,
            read_pool,
        })
    }

    pub fn run(self) -> thread::JoinHandle<()> {
        thread::Builder::new()
            .name("block worker".into())
            .spawn(|| self.work())
            .unwrap()
    }

    fn work(mut self) {
        let virtq_ev_fd = self.device_queue.event.as_raw_fd();
        let stop_ev_fd = self.stop_fd.as_raw_fd();
        let read_ev_fd = self.read_pool.as_ref().map(|pool| pool.event.as_raw_fd());

        let mut epoll = Epoll::new().unwrap();

        let _ = epoll.ctl(
            ControlOperation::Add,
            virtq_ev_fd,
            &EpollEvent::new(EventSet::IN, virtq_ev_fd as u64),
        );

        let _ = epoll.ctl(
            ControlOperation::Add,
            stop_ev_fd,
            &EpollEvent::new(EventSet::IN, stop_ev_fd as u64),
        );

        if let Some(fd) = read_ev_fd {
            epoll
                .ctl(
                    ControlOperation::Add,
                    fd,
                    &EpollEvent::new(EventSet::IN, fd as u64),
                )
                .unwrap();
        }

        let mut epoll_events = vec![EpollEvent::new(EventSet::empty(), 0); 32];
        loop {
            match epoll.wait(epoll_events.len(), -1, epoll_events.as_mut_slice()) {
                Ok(ev_cnt) => {
                    for event in &epoll_events[0..ev_cnt] {
                        let source = event.fd();
                        let event_set = event.event_set();
                        match event_set {
                            EventSet::IN if source == virtq_ev_fd => {
                                self.process_queue_event();
                            }
                            EventSet::IN if source == stop_ev_fd => {
                                debug!("stopping worker thread");
                                let _ = self.stop_fd.read();
                                self.complete_reads(true);
                                return;
                            }
                            EventSet::IN if Some(source) == read_ev_fd => {
                                let _ = self.read_pool.as_ref().unwrap().event.read();
                                self.complete_reads(false);
                            }
                            _ => {
                                log::warn!(
                                    "Received unknown event: {event_set:?} from fd: {source:?}"
                                );
                            }
                        }
                    }
                }
                Err(e) => {
                    debug!("failed to consume muxer epoll event: {e}");
                }
            }
        }
    }

    fn process_queue_event(&mut self) {
        if let Err(e) = self.device_queue.event.read() {
            error!("Failed to get queue event: {e:?}");
        } else {
            self.process_virtio_queues();
        }
    }

    /// Process device virtio queue(s).
    fn process_virtio_queues(&mut self) {
        let mem = self.mem.clone();
        loop {
            self.device_queue.queue.disable_notification(&mem).unwrap();

            self.process_queue(&mem);

            if !self.device_queue.queue.enable_notification(&mem).unwrap() {
                break;
            }
        }
    }

    fn process_queue(&mut self, mem: &GuestMemoryMmap) {
        while let Some(head) = self.device_queue.queue.pop(mem) {
            let mut reader = match Reader::new(mem, head.clone()) {
                Ok(r) => r,
                Err(e) => {
                    error!("invalid descriptor chain: {e:?}");
                    continue;
                }
            };
            let mut writer = match Writer::new(mem, head.clone()) {
                Ok(r) => r,
                Err(e) => {
                    error!("invalid descriptor chain: {e:?}");
                    continue;
                }
            };
            let request_header: RequestHeader = match reader.read_obj() {
                Ok(h) => h,
                Err(e) => {
                    error!("invalid request header: {e:?}");
                    continue;
                }
            };

            if request_header.request_type == VIRTIO_BLK_T_IN && self.read_pool.is_some() {
                match ReadJob::new(head.clone(), request_header.sector) {
                    Ok(job) if ReadPool::can_buffer(job.data_len) => {
                        drop(reader);
                        drop(writer);
                        while !self.read_pool.as_ref().unwrap().has_capacity(job.data_len) {
                            self.complete_read(true);
                        }
                        self.read_pool.as_mut().unwrap().submit(job);
                        continue;
                    }
                    Ok(_) => {}
                    Err(e) => {
                        error!("invalid block read: {e}");
                        if let Some(data_len) = writer.available_bytes().checked_sub(1)
                            && let Ok(mut status) = writer.split_at(data_len)
                            && let Err(e) = status.write_obj(VIRTIO_BLK_S_IOERR as u8)
                        {
                            error!("Failed to write virtio block status: {e}");
                        }
                        self.add_used(mem, head.index, 0);
                        continue;
                    }
                }
            }

            // Mutations and oversized synchronous reads must observe all prior reads.
            self.complete_reads(true);

            let (status, len): (u8, usize) =
                match self.process_request(request_header, &mut reader, &mut writer) {
                    Ok(l) => (VIRTIO_BLK_S_OK.try_into().unwrap(), l),
                    Err(e) => {
                        error!("error processing request: {e:?}");
                        (VIRTIO_BLK_S_IOERR.try_into().unwrap(), 0)
                    }
                };

            if let Err(e) = writer.write_obj(status) {
                error!("Failed to write virtio block status: {e:?}")
            }

            self.add_used(mem, head.index, len as u32);
        }
    }

    fn add_used(&mut self, mem: &GuestMemoryMmap, head_index: u16, len: u32) {
        if let Err(e) = self.device_queue.queue.add_used(mem, head_index, len) {
            error!("failed to add used elements to the queue: {e:?}");
        }
        if self.device_queue.queue.needs_notification(mem).unwrap()
            && let Err(e) = self.interrupt.try_signal_used_queue()
        {
            error!("error signalling queue: {e:?}");
        }
    }

    fn complete_reads(&mut self, wait: bool) {
        while self.complete_read(wait) {}
    }

    fn complete_read(&mut self, wait: bool) -> bool {
        let Some(pool) = self.read_pool.as_mut() else {
            return false;
        };
        if pool.pending == 0 {
            return false;
        }
        let Some(completion) = pool.complete(wait) else {
            return false;
        };
        let mem = self.mem.clone();
        let (head_index, len) = completion.finish(&mem);
        self.add_used(&mem, head_index, len);
        true
    }

    fn process_request(
        &mut self,
        request_header: RequestHeader,
        reader: &mut Reader,
        writer: &mut Writer,
    ) -> result::Result<usize, RequestError> {
        match request_header.request_type {
            VIRTIO_BLK_T_IN => {
                let data_len = writer
                    .available_bytes()
                    .checked_sub(1)
                    .ok_or(RequestError::InvalidDataLength)?;
                let offset = request_header
                    .sector
                    .checked_mul(512)
                    .ok_or(RequestError::InvalidDataLength)?;
                if !data_len.is_multiple_of(512) {
                    Err(RequestError::InvalidDataLength)
                } else {
                    writer
                        .write_from_at(&self.disk, data_len, offset)
                        .map_err(RequestError::WritingToDescriptor)
                }
            }
            VIRTIO_BLK_T_OUT => {
                let data_len = reader.available_bytes();
                if !data_len.is_multiple_of(512) {
                    Err(RequestError::InvalidDataLength)
                } else {
                    reader
                        .read_to_at(&self.disk, data_len, request_header.sector * 512)
                        .map_err(RequestError::ReadingFromDescriptor)
                }
            }
            VIRTIO_BLK_T_FLUSH => match self.disk.cache_type() {
                CacheType::Writeback => {
                    let diskfile = self.disk.file.write().unwrap();
                    diskfile.flush().map_err(RequestError::FlushingToDisk)?;
                    diskfile.sync().map_err(RequestError::FlushingToDisk)?;
                    Ok(0)
                }
                CacheType::Unsafe => Ok(0),
            },
            VIRTIO_BLK_T_GET_ID => {
                let data_len = writer.available_bytes();
                let disk_id = self.disk.image_id();
                if data_len < disk_id.len() {
                    Err(RequestError::InvalidDataLength)
                } else {
                    writer
                        .write_all(disk_id)
                        .map_err(RequestError::WritingToDescriptor)?;
                    Ok(disk_id.len())
                }
            }
            VIRTIO_BLK_T_DISCARD => {
                let discard_write_data: DiscardWriteData = reader
                    .read_obj()
                    .map_err(RequestError::ReadingFromDescriptor)?;
                self.disk
                    .file
                    .write()
                    .unwrap()
                    .discard_to_any(
                        discard_write_data.sector * 512,
                        discard_write_data.num_sectors as u64 * 512,
                    )
                    .map_err(RequestError::Discarding)?;
                Ok(0)
            }
            VIRTIO_BLK_T_WRITE_ZEROES => {
                let discard_write_data: DiscardWriteData = reader
                    .read_obj()
                    .map_err(RequestError::ReadingFromDescriptor)?;
                let unmap = (discard_write_data.flags & VIRTIO_BLK_WRITE_ZEROES_FLAG_UNMAP) != 0;
                if unmap {
                    self.disk
                        .file
                        .write()
                        .unwrap()
                        .discard_to_zero(
                            discard_write_data.sector * 512,
                            discard_write_data.num_sectors as u64 * 512,
                        )
                        .map_err(RequestError::DiscardingToZero)?;
                } else {
                    self.disk
                        .file
                        .write()
                        .unwrap()
                        .write_zeroes(
                            discard_write_data.sector * 512,
                            discard_write_data.num_sectors as u64 * 512,
                        )
                        .map_err(RequestError::WritingZeroes)?;
                }
                Ok(0)
            }
            _ => Err(RequestError::UnknownRequest),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::virtio::device::{InterruptHandler, InterruptType};
    use crate::virtio::queue::tests::VirtQueue;
    use imago::{
        DynStorage, FormatAccess, Storage, StorageOpenOptions, file::File as ImagoFile, raw::Raw,
    };
    use std::sync::{Arc, RwLock, mpsc};
    use std::time::Duration;
    use utils::eventfd::EFD_NONBLOCK;
    use utils::tempfile::TempFile;
    use vm_memory::{Address, Bytes, GuestAddress};

    struct TestInterrupt;

    impl InterruptHandler for TestInterrupt {
        fn try_signal(&self, _: InterruptType) -> Result<(), crate::Error> {
            Ok(())
        }
    }

    fn worker(mem: &GuestMemoryMmap, queue: &VirtQueue, threads: Option<usize>) -> BlockWorker {
        let backing = TempFile::new().unwrap();
        let mut file = backing.as_file();
        file.write_all(&[0x11; 512]).unwrap();
        file.write_all(&[0x22; 512]).unwrap();
        let file: Box<dyn DynStorage> = Box::new(
            ImagoFile::open(
                StorageOpenOptions::new()
                    .filename(backing.as_path())
                    .write(true),
            )
            .unwrap(),
        );
        let image = FormatAccess::new(Raw::open_image(file, true).unwrap());
        let disk =
            DiskProperties::new(Arc::new(RwLock::new(image)), vec![0; 20], CacheType::Unsafe)
                .unwrap();
        BlockWorker::new(
            DeviceQueue::new(
                queue.create_queue(),
                Arc::new(EventFd::new(EFD_NONBLOCK).unwrap()),
            ),
            InterruptTransport::from_handler(Arc::new(TestInterrupt)),
            mem.clone(),
            disk,
            EventFd::new(EFD_NONBLOCK).unwrap(),
            threads,
        )
        .unwrap()
    }

    fn request(mem: &GuestMemoryMmap, queue: &VirtQueue, kind: u32, sector: u64, buffer: u64) {
        let slot = queue.avail.idx.get() as usize;
        let head = slot * 3;
        let header_addr = GuestAddress(0x1000 + slot as u64 * 16);
        mem.write_obj(
            RequestHeader {
                request_type: kind,
                _reserved: 0,
                sector,
            },
            header_addr,
        )
        .unwrap();
        queue.dtable[head].set(header_addr.raw_value(), 16, 1, (head + 1) as u16);
        let flags = if kind == VIRTIO_BLK_T_OUT { 1 } else { 3 };
        queue.dtable[head + 1].set(buffer, 512, flags, (head + 2) as u16);
        queue.dtable[head + 2].set(buffer + 512, 1, 2, 0);
        queue.avail.ring[slot].set(head as u16);
        queue.avail.idx.set((slot + 1) as u16);
    }

    #[test]
    fn overlapping_reads_only_touch_guest_memory_during_completion() {
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let queue = VirtQueue::new(GuestAddress(0), &mem, 16);
        mem.write_slice(&[0xcc; 769], GuestAddress(0x2000)).unwrap();
        request(&mem, &queue, VIRTIO_BLK_T_IN, 0, 0x2000);
        request(&mem, &queue, VIRTIO_BLK_T_IN, 1, 0x2100);
        let mut worker = worker(&mem, &queue, Some(2));
        worker.process_virtio_queues();
        let pool = worker.read_pool.as_mut().unwrap();
        assert_eq!(pool.pending, 2);
        let completions = [pool.complete(true).unwrap(), pool.complete(true).unwrap()];

        let mut actual = [0; 769];
        mem.read_slice(&mut actual, GuestAddress(0x2000)).unwrap();
        assert_eq!(actual, [0xcc; 769]);
        assert_eq!(queue.used.idx.get(), 0);

        let mut expected = [0xcc; 769];
        for completion in completions {
            let (head, len) = completion.finish(&mem);
            let (offset, byte) = if head == 0 { (0, 0x11) } else { (256, 0x22) };
            expected[offset..offset + 512].fill(byte);
            expected[offset + 512] = VIRTIO_BLK_S_OK as u8;
            assert_eq!(len, 512);
            worker.add_used(&mem, head, len);
        }
        mem.read_slice(&mut actual, GuestAddress(0x2000)).unwrap();
        assert_eq!(actual, expected);
        assert_eq!(queue.used.idx.get(), 2);
    }

    #[test]
    fn writes_wait_for_prior_reads_and_following_reads_see_the_write() {
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let queue = VirtQueue::new(GuestAddress(0), &mem, 16);
        mem.write_slice(&[0x77; 512], GuestAddress(0x4000)).unwrap();
        request(&mem, &queue, VIRTIO_BLK_T_IN, 0, 0x2000);
        request(&mem, &queue, VIRTIO_BLK_T_OUT, 0, 0x4000);
        request(&mem, &queue, VIRTIO_BLK_T_IN, 0, 0x3000);
        let mut worker = worker(&mem, &queue, Some(2));
        worker.process_virtio_queues();
        worker.complete_reads(true);
        let mut data = [0; 512];
        mem.read_slice(&mut data, GuestAddress(0x2000)).unwrap();
        assert_eq!(data, [0x11; 512]);
        mem.read_slice(&mut data, GuestAddress(0x3000)).unwrap();
        assert_eq!(data, [0x77; 512]);
        assert_eq!(queue.used.idx.get(), 3);
    }

    #[test]
    fn descriptor_changes_do_not_redirect_pending_reads() {
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let queue = VirtQueue::new(GuestAddress(0), &mem, 16);
        request(&mem, &queue, VIRTIO_BLK_T_IN, 0, 0x2000);
        let mut worker = worker(&mem, &queue, Some(2));
        worker.process_virtio_queues();
        queue.dtable[1].addr.set(0x3000);
        worker.complete_reads(true);
        let mut data = [0; 512];
        mem.read_slice(&mut data, GuestAddress(0x2000)).unwrap();
        assert_eq!(data, [0x11; 512]);
        mem.read_slice(&mut data, GuestAddress(0x3000)).unwrap();
        assert_eq!(data, [0; 512]);
    }

    #[test]
    fn disabled_parallel_reads_complete_synchronously() {
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let queue = VirtQueue::new(GuestAddress(0), &mem, 16);
        request(&mem, &queue, VIRTIO_BLK_T_IN, 0, 0x2000);
        let mut worker = worker(&mem, &queue, None);
        assert!(worker.read_pool.is_none());
        worker.process_virtio_queues();
        assert_eq!(queue.used.idx.get(), 1);
        assert_eq!(mem.read_obj::<u8>(GuestAddress(0x2000)).unwrap(), 0x11);
    }

    #[test]
    fn stopping_the_worker_drains_pending_reads() {
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let queue = VirtQueue::new(GuestAddress(0), &mem, 16);
        request(&mem, &queue, VIRTIO_BLK_T_IN, 0, 0x2000);
        let mut worker = worker(&mem, &queue, Some(2));
        worker.process_virtio_queues();
        let stop = worker.stop_fd.try_clone().unwrap();
        let worker = worker.run();
        stop.write(1).unwrap();
        worker.join().unwrap();
        assert_eq!(queue.used.idx.get(), 1);
        assert_eq!(mem.read_obj::<u8>(GuestAddress(0x2000)).unwrap(), 0x11);
    }

    #[test]
    fn read_completion_wakes_the_dispatcher_without_another_guest_kick() {
        struct NotifyInterrupt(mpsc::Sender<()>);
        impl InterruptHandler for NotifyInterrupt {
            fn try_signal(&self, _: InterruptType) -> Result<(), crate::Error> {
                let _ = self.0.send(());
                Ok(())
            }
        }

        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let queue = VirtQueue::new(GuestAddress(0), &mem, 16);
        request(&mem, &queue, VIRTIO_BLK_T_IN, 0, 0x2000);
        let mut worker = worker(&mem, &queue, Some(2));
        let (sent, received) = mpsc::channel();
        worker.interrupt = InterruptTransport::from_handler(Arc::new(NotifyInterrupt(sent)));
        let kick = worker.device_queue.event.clone();
        let stop = worker.stop_fd.try_clone().unwrap();
        let worker = worker.run();
        kick.write(1).unwrap();
        let result = received.recv_timeout(Duration::from_secs(5));
        stop.write(1).unwrap();
        worker.join().unwrap();
        result.unwrap();
        assert_eq!(queue.used.idx.get(), 1);
        assert_eq!(mem.read_obj::<u8>(GuestAddress(0x2000)).unwrap(), 0x11);
    }

    #[test]
    fn invalid_read_offset_completes_with_ioerr_without_touching_the_payload() {
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let queue = VirtQueue::new(GuestAddress(0), &mem, 16);
        mem.write_slice(&[0xcc; 513], GuestAddress(0x2000)).unwrap();
        request(&mem, &queue, VIRTIO_BLK_T_IN, u64::MAX, 0x2000);
        let mut worker = worker(&mem, &queue, Some(2));
        worker.process_virtio_queues();
        assert_eq!(queue.used.idx.get(), 1);
        assert_eq!(mem.read_obj::<u8>(GuestAddress(0x2000)).unwrap(), 0xcc);
        assert_eq!(
            mem.read_obj::<u8>(GuestAddress(0x2200)).unwrap(),
            VIRTIO_BLK_S_IOERR as u8
        );
    }
}
