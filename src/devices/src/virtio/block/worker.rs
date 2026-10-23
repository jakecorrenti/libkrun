use crate::virtio::descriptor_utils::{Reader, Writer};

use super::super::DeviceQueue;
use super::QUEUE_SIZE;
use super::device::{CacheType, DiskProperties};
use super::read_pool::{ReadCompletion, ReadPool};

use crate::virtio::InterruptTransport;
use std::collections::HashMap;
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
        parallel_reads: bool,
        read_pool_size: Option<usize>,
    ) -> Self {
        let read_pool = parallel_reads.then(|| {
            let size = read_pool_size
                .unwrap_or_else(|| thread::available_parallelism().map_or(1, usize::from))
                .clamp(1, QUEUE_SIZE as usize);
            ReadPool::new(&disk, size).expect("failed to create block read pool")
        });
        Self {
            device_queue,
            interrupt,
            mem,
            disk,
            stop_fd,
            read_pool,
        }
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
                                return;
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
        let mut pending = HashMap::new();
        while let Some(head) = self.device_queue.queue.pop(mem) {
            if let Some(size) = self.read_pool.as_ref().map(ReadPool::size) {
                while pending.len() == size || pending.contains_key(&head.index) {
                    let completion = self.read_pool.as_ref().unwrap().completions.recv().unwrap();
                    self.complete_read(mem, &mut pending, completion);
                }
                while let Ok(completion) = self.read_pool.as_ref().unwrap().completions.try_recv() {
                    self.complete_read(mem, &mut pending, completion);
                }
            }
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

            if request_header.request_type == VIRTIO_BLK_T_IN
                && let Some(pool) = &self.read_pool
            {
                match Self::read_parameters(request_header, &writer) {
                    Ok((offset, len)) => {
                        pool.submit(head.index, offset, len);
                        pending.insert(head.index, writer);
                    }
                    Err(e) => self.complete_request(mem, head.index, &mut writer, Err(e)),
                }
                continue;
            }

            while !pending.is_empty() {
                let completion = self.read_pool.as_ref().unwrap().completions.recv().unwrap();
                self.complete_read(mem, &mut pending, completion);
            }
            let result = self.process_request(request_header, &mut reader, &mut writer);
            self.complete_request(mem, head.index, &mut writer, result);
        }
        while !pending.is_empty() {
            let completion = self.read_pool.as_ref().unwrap().completions.recv().unwrap();
            self.complete_read(mem, &mut pending, completion);
        }
    }

    fn complete_read(
        &mut self,
        mem: &GuestMemoryMmap,
        pending: &mut HashMap<u16, Writer>,
        completion: ReadCompletion,
    ) {
        let mut writer = pending.remove(&completion.index).unwrap();
        let result = completion
            .result
            .and_then(|data| writer.write_all(&data).map(|()| data.len()))
            .map_err(RequestError::WritingToDescriptor);
        self.complete_request(mem, completion.index, &mut writer, result);
    }

    fn read_parameters(
        header: RequestHeader,
        writer: &Writer,
    ) -> result::Result<(u64, usize), RequestError> {
        let len = writer
            .available_bytes()
            .checked_sub(1)
            .filter(|len| len.is_multiple_of(512))
            .ok_or(RequestError::InvalidDataLength)?;
        let offset = header
            .sector
            .checked_mul(512)
            .filter(|offset| offset.checked_add(len as u64).is_some())
            .ok_or(RequestError::InvalidDataLength)?;
        Ok((offset, len))
    }

    fn complete_request(
        &mut self,
        mem: &GuestMemoryMmap,
        index: u16,
        writer: &mut Writer,
        result: result::Result<usize, RequestError>,
    ) {
        let (status, len): (u8, usize) = match result {
            Ok(len) => (VIRTIO_BLK_S_OK as u8, len),
            Err(e) => {
                error!("error processing request: {e:?}");
                (VIRTIO_BLK_S_IOERR as u8, 0)
            }
        };

        if let Err(e) = writer.write_obj(status) {
            error!("Failed to write virtio block status: {e:?}")
        }

        if let Err(e) = self.device_queue.queue.add_used(mem, index, len as u32) {
            error!("failed to add used elements to the queue: {e:?}");
        }

        if self.device_queue.queue.needs_notification(mem).unwrap()
            && let Err(e) = self.interrupt.try_signal_used_queue()
        {
            error!("error signalling queue: {e:?}");
        }
    }

    fn process_request(
        &mut self,
        request_header: RequestHeader,
        reader: &mut Reader,
        writer: &mut Writer,
    ) -> result::Result<usize, RequestError> {
        match request_header.request_type {
            VIRTIO_BLK_T_IN => {
                let (offset, len) = Self::read_parameters(request_header, writer)?;
                writer
                    .write_from_at(&self.disk, len, offset)
                    .map_err(RequestError::WritingToDescriptor)
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
