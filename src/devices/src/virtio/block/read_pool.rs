#![forbid(unsafe_code)]

use std::io;
use std::sync::Arc;
use std::thread::{self, JoinHandle};

use crossbeam_channel::{Receiver, Sender, unbounded};
use utils::eventfd::{EFD_NONBLOCK, EventFd};
use virtio_bindings::virtio_blk::{VIRTIO_BLK_S_IOERR, VIRTIO_BLK_S_OK};
use vm_memory::{Address, Bytes, GuestAddress, GuestMemoryBackend, GuestMemoryMmap};

use super::device::DiskProperties;
use crate::virtio::DescriptorChain;

const MAX_BUFFERED_READ_BYTES: usize = 64 * 1024 * 1024;

pub(super) struct ReadJob {
    pub head_index: u16,
    pub data_len: usize,
    offset: u64,
    buffers: Vec<(GuestAddress, usize)>,
    status_addr: GuestAddress,
}

impl ReadJob {
    pub fn new(head: DescriptorChain<'_>, sector: u64) -> io::Result<Self> {
        let mut buffers = Vec::new();
        let mut total_len = 0usize;
        let mut status_addr = None;
        for desc in head.clone().into_iter().writable() {
            let len = desc.len as usize;
            if !head.mem.check_range(desc.addr, len) {
                return Err(io::Error::other("invalid block read buffer"));
            }
            total_len = total_len
                .checked_add(len)
                .ok_or_else(|| io::Error::other("block read buffer length overflow"))?;
            if len != 0 {
                status_addr = desc.addr.checked_add((len - 1) as u64);
            }
            buffers.push((desc.addr, len));
        }
        let data_len = total_len
            .checked_sub(1)
            .filter(|len| len.is_multiple_of(512))
            .ok_or_else(|| io::Error::other("invalid block read length"))?;
        let offset = sector
            .checked_mul(512)
            .filter(|offset| offset.checked_add(data_len as u64).is_some())
            .ok_or_else(|| io::Error::other("block read offset overflow"))?;
        Ok(Self {
            head_index: head.index,
            data_len,
            offset,
            buffers,
            status_addr: status_addr
                .ok_or_else(|| io::Error::other("missing block read status"))?,
        })
    }

    fn copy_data(&self, mem: &GuestMemoryMmap, mut data: &[u8]) -> io::Result<()> {
        for &(addr, len) in &self.buffers {
            let count = len.min(data.len());
            mem.write_slice(&data[..count], addr)
                .map_err(io::Error::other)?;
            data = &data[count..];
        }
        Ok(())
    }
}

pub(super) struct ReadCompletion {
    job: ReadJob,
    data: io::Result<Vec<u8>>,
}

impl ReadCompletion {
    pub fn finish(self, mem: &GuestMemoryMmap) -> (u16, u32) {
        let result = self.data.and_then(|data| self.job.copy_data(mem, &data));
        let (status, len) = match result {
            Ok(()) => (VIRTIO_BLK_S_OK as u8, self.job.data_len as u32),
            Err(e) => {
                error!("error processing block read: {e}");
                (VIRTIO_BLK_S_IOERR as u8, 0)
            }
        };
        if let Err(e) = mem.write_obj(status, self.job.status_addr) {
            error!("Failed to write virtio block status: {e}");
        }
        (self.job.head_index, len)
    }
}

pub(super) struct ReadPool {
    sender: Option<Sender<ReadJob>>,
    completions: Receiver<ReadCompletion>,
    pub event: Arc<EventFd>,
    workers: Vec<JoinHandle<()>>,
    pub pending: usize,
    buffered_bytes: usize,
}

impl ReadPool {
    pub fn new(disk: &DiskProperties, threads: usize) -> io::Result<Self> {
        let (sender, jobs) = unbounded::<ReadJob>();
        let (completed, completions) = unbounded();
        let event = Arc::new(EventFd::new(EFD_NONBLOCK)?);
        let mut pool = Self {
            sender: Some(sender),
            completions,
            event,
            workers: Vec::new(),
            pending: 0,
            buffered_bytes: 0,
        };
        for index in 0..threads.max(1) {
            let jobs = jobs.clone();
            let completed = completed.clone();
            let event = pool.event.clone();
            let file = disk.file.clone();
            pool.workers.push(
                thread::Builder::new()
                    .name(format!("block read {index}"))
                    .spawn(move || {
                        while let Ok(job) = jobs.recv() {
                            // Only host-owned buffers enter the pool; guest writes are serialized
                            // by BlockWorker, even when guest descriptors overlap.
                            let mut data = vec![0; job.data_len];
                            let result = file.read().unwrap().read(&mut data[..], job.offset);
                            if completed
                                .send(ReadCompletion {
                                    job,
                                    data: result.map(|()| data),
                                })
                                .is_err()
                            {
                                break;
                            }
                            if let Err(e) = event.write(1) {
                                error!("Failed to signal block read completion: {e}");
                            }
                        }
                    })?,
            );
        }
        Ok(pool)
    }

    pub fn can_buffer(data_len: usize) -> bool {
        data_len <= MAX_BUFFERED_READ_BYTES
    }

    pub fn has_capacity(&self, data_len: usize) -> bool {
        self.pending < self.workers.len()
            && data_len <= MAX_BUFFERED_READ_BYTES - self.buffered_bytes
    }

    pub fn submit(&mut self, job: ReadJob) {
        self.buffered_bytes += job.data_len;
        self.pending += 1;
        self.sender.as_ref().unwrap().send(job).unwrap();
    }

    pub fn complete(&mut self, wait: bool) -> Option<ReadCompletion> {
        let completion = if wait {
            Some(self.completions.recv().expect("block read workers stopped"))
        } else {
            self.completions.try_recv().ok()
        }?;
        self.pending -= 1;
        self.buffered_bytes -= completion.job.data_len;
        Some(completion)
    }
}

impl Drop for ReadPool {
    fn drop(&mut self) {
        self.sender.take();
        for worker in self.workers.drain(..) {
            if let Err(e) = worker.join() {
                error!("error joining block read worker: {e:?}");
            }
        }
    }
}
