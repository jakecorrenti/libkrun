use std::io;
use std::sync::Arc;
use std::thread::{self, JoinHandle};

use crossbeam_channel::{Receiver, Sender, bounded, unbounded};
use imago::io_buffers::IoVectorMut;

use super::device::DiskProperties;

struct ReadJob {
    index: u16,
    offset: u64,
    len: usize,
}

pub(super) struct ReadCompletion {
    pub index: u16,
    pub result: io::Result<Vec<u8>>,
}

pub(super) struct ReadPool {
    jobs: Option<Sender<ReadJob>>,
    pub completions: Receiver<ReadCompletion>,
    threads: Vec<JoinHandle<()>>,
}

impl ReadPool {
    pub fn new(disk: &DiskProperties, size: usize) -> io::Result<Self> {
        let (jobs, receiver) = bounded::<ReadJob>(size);
        let (sender, completions) = unbounded();
        let mut pool = Self {
            jobs: Some(jobs),
            completions,
            threads: Vec::new(),
        };

        for index in 0..size {
            let jobs = receiver.clone();
            let completions = sender.clone();
            let disk = Arc::clone(&disk.file);
            pool.threads.push(
                thread::Builder::new()
                    .name(format!("block read {index}"))
                    .spawn(move || {
                        for job in jobs {
                            // Pool threads never receive guest memory: overlapping guest buffers
                            // must not become aliased Rust references while waiting on a disk lock.
                            let result = (|| {
                                let mut data = vec![0; job.len];
                                disk.read()
                                    .unwrap()
                                    .readv(IoVectorMut::from(&mut data), job.offset)?;
                                Ok(data)
                            })();
                            if completions
                                .send(ReadCompletion {
                                    index: job.index,
                                    result,
                                })
                                .is_err()
                            {
                                break;
                            }
                        }
                    })?,
            );
        }
        Ok(pool)
    }

    pub fn size(&self) -> usize {
        self.threads.len()
    }

    pub fn submit(&self, index: u16, offset: u64, len: usize) {
        self.jobs
            .as_ref()
            .unwrap()
            .send(ReadJob { index, offset, len })
            .unwrap();
    }
}

impl Drop for ReadPool {
    fn drop(&mut self) {
        self.jobs.take();
        for thread in self.threads.drain(..) {
            if let Err(e) = thread.join() {
                error!("error waiting for block read thread: {e:?}");
            }
        }
    }
}
