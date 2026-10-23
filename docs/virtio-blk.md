# Parallel virtio-blk reads

A virtio-blk request describes an operation, a disk sector, and guest-memory
buffers. The guest places requests on an available ring. After processing a
request, libkrun writes its status byte, puts the request on the used ring, and
notifies the guest when needed.

`BlockDevice::set_parallel_reads(true)` enables a persistent read thread pool for
that device. `set_read_pool_size(n)` selects its thread count. Without an explicit
size, the pool uses the host's available parallelism, falling back to one thread.
Sizes are clamped to 1–256, the device's queue capacity. Disabling parallel reads
keeps request processing on the block worker.

## Request flow

1. The block worker parses requests and submits disk offsets and lengths to the
   pool. It keeps at most one outstanding request per pool thread.
2. Pool threads read concurrently under the disk's shared read lock. Each read
   uses a private host buffer; no guest-memory references enter the pool.
3. The block worker receives whichever result arrives first, copies successful
   data into the guest buffers, and completes the request. It alone accesses
   guest memory and updates the queue within this device, including when guest
   buffers overlap.
4. Before processing a non-read request, the worker completes all outstanding
   reads. Writes, flushes, discards, and write-zeroes therefore retain their
   existing serial execution. It also drains reads before returning to its event
   loop. Reset joins the block worker and all pool threads.

[Virtio §5.2.6](https://docs.oasis-open.org/virtio/virtio/v1.3/virtio-v1.3.html)
allows requests to be used “not necessarily in order.” This device does not
advertise `VIRTIO_F_IN_ORDER`, so read completions can be returned out of order.
Draining before non-read requests is an implementation choice that keeps disk
mutation ordering straightforward.

Private buffers cost an allocation and an extra copy per read. They avoid holding
overlapping mutable Rust references to guest memory across threads, even before
a disk lock is acquired. Concurrency bounds the number of outstanding buffers.

## Code map

- `src/devices/src/virtio/block/worker.rs`: parsing, read validation, dispatch,
  guest-memory copies, and the shared request completion path.
- `src/devices/src/virtio/block/read_pool.rs`: host-only read jobs, result channel,
  thread creation, and shutdown.
- `src/devices/src/virtio/block/tests.rs`: overlapping guest buffers, ordering
  around writes, request validation, result identity, and direct I/O.
