use super::super::BlockResult;
use super::super::helpers::cache::{AsyncLruCache, AsyncLruCacheEntry};
use super::IoVectorMut;
use super::super::helpers::{IoBuffer, IoBufferMut, IoVector, FutureJoin};
use super::meta::{
    L1Table, L2Table, Mapping, MappingSource, Qcow2Header, RefBlock, RefTable, Table,
};
use super::super::node::{IoQueue, NodeUser};
use miniz_oxide::inflate::core::{decompress as inflate, DecompressorOxide};
use miniz_oxide::inflate::TINFLStatus;
use std::collections::HashSet;
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::{Mutex as AsyncMutex, RwLock as AsyncRwLock};

type L1Index = usize;
type RefTableIndex = usize;

pub struct Qcow2State {
    hdr: AsyncMutex<Qcow2Header>,
    read_only: bool,

    virtual_size: u64,
    cluster_size: usize,
    l2_entries: usize,
    rb_entries: usize,
    refcount_order: u32,

    in_cluster_offset_mask: usize,
    l2_index_mask: usize,
    cluster_shift: u32,
    l2_index_shift: u32,
    rb_index_mask: usize,
    rb_index_shift: u32,
    free_cluster_offset: AtomicU64,

    l1table: AsyncRwLock<L1Table>,
    l2cache: AsyncLruCache<L1Index, AsyncRwLock<L2Table>>,
    reftable: AsyncRwLock<RefTable>,
    refblock_cache: AsyncLruCache<RefTableIndex, AsyncMutex<RefBlock>>,
    /// Refblocks that must be flushed before flushing any L2 table.  When locking this in
    /// conjunction with an L2 table, you *must* lock the L2 table first (so that both locks are
    /// always taken in the same order and do not trigger a deadlock).
    refblock_dependencies: AsyncMutex<HashSet<RefTableIndex>>,
}

pub struct Qcow2Queue {
    queue: IoQueue,
    backing_queue: Option<IoQueue>,
    file: Arc<Qcow2State>,
}

#[derive(Debug, Clone)]
pub struct SplitGuestOffset {
    pub l1_index: usize,
    pub l2_index: usize,
    pub in_cluster_offset: usize,
}

/// Allocation of clusters, not yet settled.  Must be consumed through `Allocation::use_for()`; if
/// the passed async block returns an error, all allocated clusters are automatically freed again.
struct Allocation<'a> {
    queue: &'a Qcow2Queue,
    start: Option<u64>,
    count: Option<usize>,
}

impl Qcow2State {
    pub async fn new(file: &Arc<NodeUser>, read_only: bool) -> BlockResult<Self> {
        let queue = file.new_queue()?;
        let hdr = Qcow2Header::from(&queue, read_only).await?;

        let virtual_size = hdr.size();
        let cluster_shift = hdr.cluster_bits();
        let cluster_size: usize = 1usize
            .checked_shl(cluster_shift)
            .ok_or_else(|| format!("cluster_bits={} is too large", cluster_shift))?;
        let refcount_order = hdr.refcount_order();

        let table_entries_per_cluster = cluster_size / std::mem::size_of::<u64>();
        let refcounts_per_cluster = cluster_size / std::mem::size_of::<u16>();

        let (l1_offset, l1_entries) = (hdr.l1_table_offset(), hdr.l1_table_entries());
        let (rt_offset, rt_clusters) = (hdr.reftable_offset(), hdr.reftable_clusters());

        let mut qcow2_file = Qcow2State {
            hdr: AsyncMutex::new(hdr),
            read_only,

            virtual_size,
            cluster_size,
            l2_entries: table_entries_per_cluster,
            rb_entries: refcounts_per_cluster,
            refcount_order,

            in_cluster_offset_mask: cluster_size - 1,
            l2_index_mask: table_entries_per_cluster - 1,
            cluster_shift,
            l2_index_shift: table_entries_per_cluster.trailing_zeros(),
            rb_index_mask: refcounts_per_cluster - 1,
            rb_index_shift: refcounts_per_cluster.trailing_zeros(),
            free_cluster_offset: AtomicU64::new(0),

            l1table: AsyncRwLock::new(L1Table::empty()),
            l2cache: AsyncLruCache::new(128),
            reftable: AsyncRwLock::new(RefTable::empty()),
            refblock_cache: AsyncLruCache::new(128),
            refblock_dependencies: AsyncMutex::new(HashSet::new()),
        };

        let l1table = L1Table::load(&qcow2_file, &queue, l1_offset, l1_entries).await?;
        qcow2_file.l1table = AsyncRwLock::new(l1table);

        let reftable = RefTable::load(
            &qcow2_file,
            &queue,
            rt_offset,
            rt_clusters * table_entries_per_cluster,
        )
        .await?;
        qcow2_file.reftable = AsyncRwLock::new(reftable);

        Ok(qcow2_file)
    }

    pub fn virtual_size(&self) -> u64 {
        self.virtual_size
    }

    pub async fn header_backing_filename(&self) -> Option<String> {
        self.hdr.lock().await.backing_filename().cloned()
    }

    pub async fn header_backing_format(&self) -> Option<String> {
        self.hdr.lock().await.backing_format().cloned()
    }

    pub fn new_queue(
        self: &Arc<Self>,
        file: &Arc<NodeUser>,
        backing: &Option<Arc<NodeUser>>,
    ) -> BlockResult<Qcow2Queue> {
        let queue = file.new_queue()?;
        let backing_queue = backing
            .as_ref()
            .map(|backing| backing.new_queue())
            .transpose()?;
        Ok(Qcow2Queue {
            queue,
            backing_queue,
            file: Arc::clone(self),
        })
    }

    fn split_guest_offset(&self, mut guest_offset: u64) -> SplitGuestOffset {
        let in_cluster_offset = guest_offset as usize & self.in_cluster_offset_mask;
        guest_offset >>= self.cluster_shift;

        let l2_index = guest_offset as usize & self.l2_index_mask;
        guest_offset >>= self.l2_index_shift;

        let l1_index: usize = guest_offset.try_into().unwrap();

        SplitGuestOffset {
            l1_index,
            l2_index,
            in_cluster_offset,
        }
    }

    pub fn in_cluster_offset(&self, offset: u64) -> usize {
        offset as usize & self.in_cluster_offset_mask
    }

    pub fn cluster_size(&self) -> usize {
        self.cluster_size
    }

    pub fn refcount_order(&self) -> u32 {
        self.refcount_order
    }

    async fn flush_l2(
        &self,
        l2_table_handle: AsyncLruCacheEntry<AsyncRwLock<L2Table>>,
        queue: &IoQueue,
    ) -> BlockResult<()> {
        // Lock L2 table before `refblock_dependencies`, as is required
        let l2_table = l2_table_handle.value().read().await;

        // Keep this locked throughout L2 flushing, so we do not introduce new dependencies in the
        // meantime
        let mut rb_deps = self.refblock_dependencies.lock().await;
        for rt_index in rb_deps.drain() {
            self.refblock_cache
                .flush_entry(&rt_index, |refblock_handle| {
                    self.flush_refblock(refblock_handle, queue)
                })
                .await?;
        }

        l2_table.write(queue).await
    }

    async fn flush_refblock(
        &self,
        refblock_handle: AsyncLruCacheEntry<AsyncMutex<RefBlock>>,
        queue: &IoQueue,
    ) -> BlockResult<()> {
        let refblock = refblock_handle.value().lock().await;
        refblock.write(queue).await
    }

    pub async fn flush_caches(&self, queue: &IoQueue) -> BlockResult<()> {
        self.refblock_cache
            .flush(|refblock_handle| self.flush_refblock(refblock_handle, queue))
            .await?;

        self.l2cache
            .flush(|l2_table_handle| self.flush_l2(l2_table_handle, queue))
            .await?;

        Ok(())
    }
}

impl Qcow2Queue {
    // Splits off anything beyond the image end and zeroes it
    fn limit_to_image<'a>(&self, cursor: u64, bufv: IoVectorMut<'a>) -> IoVectorMut<'a> {
        let remaining_bytes = self.file.virtual_size().saturating_sub(cursor);
        let (bufv, mut tail) = bufv.split_at(remaining_bytes);
        if !tail.is_empty() {
            tail.fill(0);
        }
        bufv
    }

    async fn get_mapping(&self, virtual_offset: u64) -> BlockResult<Mapping> {
        let split = self.file.split_guest_offset(virtual_offset);
        let l1entry = self.file.l1table.read().await.get(split.l1_index);
        if l1entry.is_zero() {
            return Ok(Mapping {
                source: MappingSource::Backing,
                cluster_offset: Some(virtual_offset - split.in_cluster_offset as u64),
                compressed_length: None,
                copied: false,
            });
        }

        let l2_table_handle = self
            .get_l2_table(split.l1_index, l1entry.l2_offset())
            .await?;
        let l2_table = l2_table_handle.value().read().await;
        Ok(l2_table.get_mapping(&split))
    }

    async fn ensure_refblock_offset(&self, rt_index: usize) -> BlockResult<u64> {
        // Limit the `reftable` read lock guard in scope
        {
            let reftable = self.file.reftable.read().await;
            let rt_entry = reftable.get(rt_index);
            if !rt_entry.is_empty() {
                return Ok(rt_entry.refblock_offset());
            }
        }

        let mut reftable = self.file.reftable.write().await;
        if !reftable.in_bounds(rt_index) {
            let mut grown_reftable = reftable.clone_and_grow(rt_index, self.file.cluster_size);
            let new_reftable_clusters = grown_reftable.cluster_count(&self.file);

            if new_reftable_clusters >= self.file.rb_entries - 1 {
                // 1 entry stays free so we can allocate this refblock by putting its refcount into
                // itself
                // TODO: Implement larger allocations
                return Err(format!(
                    "The reftable needs to grow to {} bytes, but we can allocate only {} -- try \
                     increasing the cluster size",
                    new_reftable_clusters * self.file.cluster_size,
                    (self.file.rb_entries - 1) * self.file.cluster_size,
                )
                .into());
            }

            // Allocate new reftable, put its refcounts in a completely new refblock
            let old_reftable_offset = reftable.get_offset().unwrap();
            let old_reftable_clusters = reftable.cluster_count(&self.file);

            let mut new_refblock = RefBlock::new_cleared(&self.file);

            let refblock_offset =
                (reftable.entries() as u64) << (self.file.rb_index_shift + self.file.cluster_shift);
            new_refblock.set_offset(refblock_offset);
            grown_reftable.set_offset(refblock_offset + self.file.cluster_size as u64);

            // Reference for the refblock
            new_refblock.increment(0).unwrap();
            // References for the reftable
            for i in 1..(new_reftable_clusters + 1) {
                new_refblock.increment(i).unwrap();
            }
            new_refblock.write(&self.queue).await?;

            grown_reftable.set_refblock_offset(reftable.entries(), refblock_offset);
            grown_reftable.write(&self.queue).await?;

            let mut header = self.file.hdr.lock().await;
            header.set_reftable(grown_reftable.get_offset().unwrap(), new_reftable_clusters)?;
            if let Err(err) = header.write(&self.queue).await {
                header
                    .set_reftable(old_reftable_offset, old_reftable_clusters)
                    .unwrap();
                return Err(err);
            }

            *reftable = grown_reftable;
            self.free_clusters(old_reftable_offset, old_reftable_clusters)
                .await;
        }

        // Retry before allocating, maybe something has changed in the meantime
        let rt_entry = reftable.get(rt_index);
        if !rt_entry.is_empty() {
            return Ok(rt_entry.refblock_offset());
        }

        // Refblock must be empty, too, so create one with the first refcount used for
        // itself; this places the refblock at the first address covered by it
        let refblock_offset =
            (rt_index as u64) << (self.file.rb_index_shift + self.file.cluster_shift);

        let mut new_refblock = RefBlock::new_cleared(&self.file);
        new_refblock.set_offset(refblock_offset);

        new_refblock.increment(0).unwrap();
        new_refblock.write(&self.queue).await?;

        reftable.set_refblock_offset(rt_index, refblock_offset);
        if let Err(err) = reftable.write_entry(&self.queue, rt_index).await {
            // Restore previous entry
            reftable.set(rt_index, rt_entry);
            return Err(err);
        }

        Ok(refblock_offset)
    }

    /// Try to allocate `count` clusters starting somewhere at or after `host_cluster`, but in the
    /// same refblock.  This function cannot cross refblock boundaries.
    async fn try_allocate_from(&self, host_cluster: u64, count: usize) -> BlockResult<Option<u64>> {
        assert!(count > 0);

        if count > self.file.rb_entries - 1 {
            // 1 entry stays free so we can always allocate a refblock by putting its refcount into
            // itself
            // TODO: Implement larger allocations
            return Err(format!(
                "Need to allocate {} consecutive bytes of data, but can allocate only {} -- try \
                 increasing the cluster size",
                count * self.file.cluster_size,
                (self.file.rb_entries - 1) * self.file.cluster_size,
            )
            .into());
        }

        let cluster_index = host_cluster >> self.file.cluster_shift;

        let rt_index: usize = (cluster_index >> self.file.rb_index_shift)
            .try_into()
            .unwrap();
        let rb_index = cluster_index as usize & self.file.rb_index_mask;

        if rb_index + count > self.file.rb_entries {
            // Do not cross refblock boundaries; caller should look into the next refblock
            return Ok(None);
        }

        let refblock_offset = self.ensure_refblock_offset(rt_index).await?;

        let rb_handle = self.get_refblock(rt_index, refblock_offset).await?;
        let mut refblock = rb_handle.value().lock().await;

        let mut start_i: Option<usize> = None;
        for i in rb_index..self.file.rb_entries {
            if refblock.is_zero(i) {
                if start_i.is_none() {
                    start_i = Some(i);
                }
                let start_i = start_i.unwrap();
                if i - start_i == count - 1 {
                    for j in start_i..=i {
                        refblock.increment(j).unwrap();
                    }
                    rb_handle.mark_dirty();

                    let cluster_offset = ((rt_index as u64) << self.file.rb_index_shift
                        | start_i as u64)
                        << self.file.cluster_shift;
                    return Ok(Some(cluster_offset));
                }
            } else {
                start_i = None;
            }
        }
        // nothing in this refblock
        Ok(None)
    }

    async fn allocate_clusters(&self, count: usize) -> BlockResult<Allocation<'_>> {
        let mut host_offset = self.file.free_cluster_offset.load(Ordering::Relaxed);

        loop {
            match self.try_allocate_from(host_offset, count).await? {
                Some(offset) => {
                    if count == 1 {
                        // Update the free cluster index only for `count == 1`, because otherwise
                        // (`count > 1`) we might have the index skip holes where single clusters
                        // could still fit
                        self.file
                            .free_cluster_offset
                            .fetch_max(offset + self.file.cluster_size as u64, Ordering::Relaxed);
                    }

                    return Ok(Allocation {
                        queue: self,
                        start: Some(offset),
                        count: Some(count),
                    });
                }

                None => {
                    // Try the next refblock
                    host_offset = (host_offset
                        | ((self.file.rb_index_mask as u64) << self.file.cluster_shift)
                        | (self.file.in_cluster_offset_mask as u64))
                        + 1;
                }
            }
        }
    }

    async fn allocate_cluster(&self) -> BlockResult<Allocation<'_>> {
        self.allocate_clusters(1).await
    }

    /// Any failure in this function is hidden and will only lead to leaked clusters
    async fn free_clusters(&self, host_cluster: u64, mut count: usize) {
        let mut cluster_index = host_cluster >> self.file.cluster_shift;
        let mut first_zero = true;

        while count > 0 {
            let rt_index: usize = (cluster_index >> self.file.rb_index_shift)
                .try_into()
                .unwrap();
            let mut rb_index = cluster_index as usize & self.file.rb_index_mask;

            let refblock_offset = {
                let reftable = self.file.reftable.read().await;
                let rt_entry = reftable.get(rt_index);
                assert!(!rt_entry.is_empty());
                rt_entry.refblock_offset()
            };

            let rb_handle = match self.get_refblock(rt_index, refblock_offset).await {
                Ok(handle) => handle,
                Err(_) => {
                    // Ignore errors, skip this refblock
                    let skip_count = self.file.rb_entries - rb_index;
                    if count <= skip_count {
                        break;
                    }
                    cluster_index += skip_count as u64;
                    count -= skip_count;
                    continue;
                }
            };

            let mut refblock = rb_handle.value().lock().await;
            while count > 0 && rb_index < self.file.rb_entries {
                refblock.decrement(rb_index).unwrap();
                if refblock.is_zero(rb_index) && first_zero {
                    self.file
                        .free_cluster_offset
                        .fetch_min(cluster_index << self.file.cluster_shift, Ordering::Relaxed);
                    first_zero = false;
                }
                rb_index += 1;
                cluster_index += 1;
                count -= 1;
            }
            rb_handle.mark_dirty();
        }
    }

    async fn ensure_l2_offset(&self, l1_index: usize) -> BlockResult<u64> {
        // Limit the `l1_table` read lock guard in scope
        {
            let l1_table = self.file.l1table.read().await;
            let l1_entry = l1_table.get(l1_index);
            if !l1_entry.is_zero() {
                return Ok(l1_entry.l2_offset());
            }
        }

        let mut l1_table = self.file.l1table.write().await;
        if !l1_table.in_bounds(l1_index) {
            let old_l1_offset = l1_table.get_offset().unwrap();
            let old_l1_clusters = l1_table.cluster_count(&self.file);
            let old_l1_size = l1_table.entries();

            let mut grown_l1_table = l1_table.clone_and_grow(l1_index, self.file.cluster_size);

            let grown_l1_table = self
                .allocate_clusters(grown_l1_table.cluster_count(&self.file))
                .await?
                .flush_refblocks() // must write refblocks before adjusting the image header
                .await?
                .use_for(|new_l1_offset, _clusters| async move {
                    grown_l1_table.set_offset(new_l1_offset);
                    grown_l1_table.write(&self.queue).await?;

                    let mut header = self.file.hdr.lock().await;
                    header.set_l1_table(new_l1_offset, grown_l1_table.entries())?;
                    if let Err(err) = header.write(&self.queue).await {
                        header.set_l1_table(old_l1_offset, old_l1_size).unwrap();
                        return Err(err);
                    }

                    // Return table after moving it into this async block
                    Ok(grown_l1_table)
                })
                .await?;

            *l1_table = grown_l1_table;
            self.free_clusters(old_l1_offset, old_l1_clusters).await;
        }

        // Retry before allocating, maybe something has changed in the meantime
        let l1_entry = l1_table.get(l1_index);
        if !l1_entry.is_zero() {
            return Ok(l1_entry.l2_offset());
        }

        self.allocate_cluster()
            .await?
            .flush_refblocks() // must write refblocks before adjusting the image header
            .await?
            .use_for(|l2_offset, _clusters| async move {
                let mut zero_buf = IoBuffer::new(self.file.cluster_size, self.queue.mem_align())?;
                zero_buf.as_mut().into_slice().fill(0);
                self.queue.grow_write(zero_buf.as_ref(), l2_offset).await?;

                l1_table.map_l2_offset(l1_index, l2_offset);
                if let Err(err) = l1_table.write_entry(&self.queue, l1_index).await {
                    // Restore previous entry
                    l1_table.set(l1_index, l1_entry);
                    return Err(err);
                }

                Ok(l2_offset)
            })
            .await
    }

    fn do_read<'a>(
        &'a self,
        mapping: Mapping,
        in_cluster_offset: usize,
        mut head_bufv: IoVectorMut<'a>,
        tail_bufv: Option<IoVectorMut<'a>>,
        tail_ofs: Option<usize>,
        req_futs: &mut FutureJoin<'a>,
    ) -> BlockResult<()> {
        let source_queue = match mapping.source {
            MappingSource::DataFile => &self.queue,
            MappingSource::Backing => match self.backing_queue.as_ref() {
                Some(backing) => backing,
                None => {
                    head_bufv.fill(0);
                    if let Some(mut tail_bufv) = tail_bufv {
                        tail_bufv.fill(0);
                    }
                    return Ok(());
                }
            },
            MappingSource::Zero => {
                head_bufv.fill(0);
                if let Some(mut tail_bufv) = tail_bufv {
                    tail_bufv.fill(0);
                }
                return Ok(());
            }
            MappingSource::Compressed => {
                let fut = Box::pin(async move {
                    let compressed_offset = mapping.cluster_offset.unwrap();
                    let compressed_length = mapping.compressed_length.unwrap();

                    let mut compressed_data = vec![0; compressed_length];
                    let mut uncompressed_data = vec![0; self.file.cluster_size];

                    self.queue
                        .read(
                            IoBufferMut::from_slice(&mut compressed_data),
                            compressed_offset,
                        )
                        .await?;

                    let mut dec_ox = DecompressorOxide::new();
                    let (status, _read, written) =
                        inflate(&mut dec_ox, &compressed_data, &mut uncompressed_data, 0, 0);
                    // Because `compressed_length` will generally exceed the actual length,
                    // `HasMoreOutput` is expected and can be ignored
                    if status != TINFLStatus::Done && status != TINFLStatus::HasMoreOutput {
                        return Err(format!(
                            "Failed to decompress cluster (host offset 0x{:x}+{}): {:?}",
                            compressed_offset, compressed_length, status
                        )
                        .into());
                    }
                    if written < self.file.cluster_size {
                        return Err(format!("Failed to decompress cluster (host offset 0x{:x}+{}): Decompressed {} bytes, expected {}",
                        compressed_offset, compressed_length,
                                written, self.file.cluster_size).into());
                    }

                    if !head_bufv.is_empty() {
                        let head_ofs = in_cluster_offset;
                        let head_range = head_ofs..(head_ofs + head_bufv.len() as usize);
                        head_bufv.copy_from_slice(&uncompressed_data[head_range]);
                    }
                    if let Some(mut tail_bufv) = tail_bufv {
                        if !tail_bufv.is_empty() {
                            let tail_ofs = tail_ofs.unwrap();
                            let tail_range = tail_ofs..(tail_ofs + tail_bufv.len() as usize);
                            tail_bufv.copy_from_slice(&uncompressed_data[tail_range]);
                        }
                    }

                    Ok(())
                });
                req_futs.push(fut);
                return Ok(());
            }
        };

        if !head_bufv.is_empty() {
            let head_ofs = mapping.cluster_offset.unwrap() + in_cluster_offset as u64;
            req_futs.push(source_queue.readv(head_bufv, head_ofs));
        }
        if let Some(tail_bufv) = tail_bufv {
            if !tail_bufv.is_empty() {
                let tail_ofs = mapping.cluster_offset.unwrap() + tail_ofs.unwrap() as u64;
                req_futs.push(source_queue.readv(tail_bufv, tail_ofs));
            }
        }
        Ok(())
    }

    async fn get_l2_table(
        &self,
        l1_index: L1Index,
        l2_offset: u64,
    ) -> BlockResult<AsyncLruCacheEntry<AsyncRwLock<L2Table>>> {
        self.file
            .l2cache
            .get_or_insert(
                l1_index,
                async {
                    let table =
                        L2Table::load(&self.file, &self.queue, l2_offset, self.file.l2_entries)
                            .await?;
                    Ok(AsyncRwLock::new(table))
                },
                |l2_table_handle| self.file.flush_l2(l2_table_handle, &self.queue),
            )
            .await
    }

    async fn get_refblock(
        &self,
        rt_index: RefTableIndex,
        rb_offset: u64,
    ) -> BlockResult<AsyncLruCacheEntry<AsyncMutex<RefBlock>>> {
        self.file
            .refblock_cache
            .get_or_insert(
                rt_index,
                async {
                    let refblock = RefBlock::load(&self.file, &self.queue, rb_offset).await?;
                    Ok(AsyncMutex::new(refblock))
                },
                |refblock_handle| self.file.flush_refblock(refblock_handle, &self.queue),
            )
            .await
    }

    fn reftable_index_range(
        &self,
        host_offset: u64,
        cluster_count: usize,
    ) -> std::ops::RangeInclusive<usize> {
        let shift = self.file.rb_index_shift + self.file.cluster_shift;

        let start_rt_index: usize = (host_offset >> shift).try_into().unwrap();
        let end_rt_index: usize =
            ((host_offset + ((cluster_count as u64 - 1) << self.file.cluster_shift)) >> shift)
                .try_into()
                .unwrap();

        start_rt_index..=end_rt_index
    }

    /// Creates a new data cluster mapping in the L2 table for the given cluster (at the virtual
    /// (guest) offset `virtual_cluster_offset`), using the given buffer as initial data.
    async fn do_write<'a>(
        &'a self,
        guest_offset: u64,
        cluster_bufv: IoVector<'a>,
        req_futs: &mut FutureJoin<'a>,
    ) -> BlockResult<()> {
        let split = self.file.split_guest_offset(guest_offset);

        let mapping = self.get_mapping(guest_offset).await?;
        if let Some(ofs) = mapping.plain_offset(split.in_cluster_offset) {
            req_futs.push(self.queue.grow_writev(cluster_bufv, ofs));
            return Ok(());
        }

        // Cluster allocations are done one by one, while keeping the affected L2 table locked;
        // this way, we only ever need to keep one L2 cache entry up during the operation.
        // TODO: We can optimize by doing all cluster allocations that affect a single L2 table
        // first, then do the I/O, then update the L2 table.

        let l2_offset = self.ensure_l2_offset(split.l1_index).await?;
        let l2_handle = self.get_l2_table(split.l1_index, l2_offset).await?;
        let mut l2_table = l2_handle.value().write().await;

        // Check if a concurrent writer has allocated the cluster
        let mapping = l2_table.get_mapping(&split);
        if let Some(ofs) = mapping.plain_offset(split.in_cluster_offset) {
            req_futs.push(self.queue.grow_writev(cluster_bufv, ofs));
            return Ok(());
        }

        let mut bounce_buf = IoBuffer::new(self.file.cluster_size, self.queue.mem_align())?;
        let mut cow_read_requests = FutureJoin::new();

        let bounce_buf_ref = bounce_buf.as_mut().into_slice();
        let (bounce_head, bounce_tail) = bounce_buf_ref.split_at_mut(split.in_cluster_offset);
        let (_bounce_mid, bounce_tail) = bounce_tail.split_at_mut(cluster_bufv.len() as usize);

        self.do_read(
            mapping.clone(),
            0,
            bounce_head.into(),
            Some(bounce_tail.into()),
            Some(split.in_cluster_offset + cluster_bufv.len() as usize),
            &mut cow_read_requests,
        )?;

        let mut bounce_buf_vec = IoVector::with_capacity(2 + cluster_bufv.buffer_count());

        cow_read_requests.await?;

        if !bounce_head.is_empty() {
            bounce_buf_vec.push(bounce_head);
        }
        bounce_buf_vec.append(cluster_bufv);
        if !bounce_tail.is_empty() {
            bounce_buf_vec.push(bounce_tail);
        }

        debug_assert!(bounce_buf_vec.len() == self.file.cluster_size as u64);

        // Is the cluster already COPIED, i.e. can we reuse its allocation?  If so, no need to
        // allocate anything new.
        if mapping.copied {
            let host_cluster = mapping.cluster_offset.unwrap();
            self.queue.grow_writev(bounce_buf_vec, host_cluster).await?;
            let leaked = l2_table.map_cluster(split.l2_index, host_cluster);
            // Reusing the allocation, so `leaked` should be `None`
            assert!(leaked.is_none());
            l2_handle.mark_dirty();
            return Ok(());
        }

        let leaked = self
            .allocate_cluster()
            .await?
            .use_for(|host_cluster, count| async move {
                self.queue.grow_writev(bounce_buf_vec, host_cluster).await?;

                {
                    let mut rb_deps = self.file.refblock_dependencies.lock().await;
                    rb_deps.extend(self.reftable_index_range(host_cluster, count));
                }

                // Return potentially leaked clusters
                Ok(l2_table.map_cluster(split.l2_index, host_cluster))
            })
            .await?;

        // Cannot be done in the `use_for()` closure, because then both `l2_handle` and `l2_table`
        // would need to be moved simultaneously, which the compiler does not like (`l2_table` is
        // derived from a reference to `l2_handle`) -- given that this would be the last thing we
        // do in the closure anyway (and `use_for()` does nothing after the closure on success),
        // there is no harm in doing it here
        l2_handle.mark_dirty();

        if let Some((leaked_offset, leaked_count)) = leaked {
            self.free_clusters(leaked_offset, leaked_count).await;
        }

        Ok(())
    }

    pub async fn read_at<'a>(&self, bufv: IoVectorMut<'a>, mut offset: u64) -> BlockResult<()> {
        let mut bufv = self.limit_to_image(offset, bufv);
        let mut requests = FutureJoin::new();

        while !bufv.is_empty() {
            let in_cluster_offset = offset as usize & self.file.in_cluster_offset_mask;
            let in_cluster_remaining = self.file.cluster_size - in_cluster_offset;
            let (cluster_bufv, tail_bufv) = bufv.split_at(in_cluster_remaining as u64);
            bufv = tail_bufv;

            let mapping = self.get_mapping(offset).await?;
            self.do_read(
                mapping,
                in_cluster_offset,
                cluster_bufv,
                None,
                None,
                &mut requests,
            )?;

            offset += in_cluster_remaining as u64;
        }

        requests.await
    }

    pub async fn write_at<'a>(&self, mut bufv: IoVector<'a>, mut offset: u64) -> BlockResult<()> {
        if self.file.read_only {
            return Err("qcow2 node is read-only".into());
        }

        if offset
            .checked_add(bufv.len())
            .map(|end| end > self.file.virtual_size())
            != Some(false)
        {
            return Err("Cannot write beyond the end of a qcow2 image".into());
        }

        let mut requests = FutureJoin::new();

        while !bufv.is_empty() {
            let in_cluster_offset = offset as usize & self.file.in_cluster_offset_mask;
            let in_cluster_remaining = self.file.cluster_size - in_cluster_offset;

            let (cluster_bufv, tail_bufv) = bufv.split_at(in_cluster_remaining as u64);
            bufv = tail_bufv;

            self.do_write(offset, cluster_bufv, &mut requests).await?;

            offset += in_cluster_remaining as u64;
        }

        requests.await
    }

    pub async fn flush(&self) -> BlockResult<()> {
        self.file.flush_caches(&self.queue).await
    }
}

impl<'a> Allocation<'a> {
    /// Make use of this allocation; if the future (async block) returns an error, all allocated
    /// clusters are freed again.
    async fn use_for<R, F: Future<Output = BlockResult<R>>, G: FnOnce(u64, usize) -> F>(
        mut self,
        gen_fut: G,
    ) -> BlockResult<R> {
        let start = self.start.take().unwrap();
        let count = self.count.take().unwrap();

        match gen_fut(start, count).await {
            Ok(ret) => Ok(ret),
            Err(err) => {
                self.queue.free_clusters(start, count).await;
                Err(err)
            }
        }
    }

    async fn flush_refblocks(self) -> BlockResult<Allocation<'a>> {
        for rt_index in self
            .queue
            .reftable_index_range(self.start.unwrap(), self.count.unwrap())
        {
            self.queue
                .file
                .refblock_cache
                .flush_entry(&rt_index, |refblock_handle| {
                    self.queue
                        .file
                        .flush_refblock(refblock_handle, &self.queue.queue)
                })
                .await?;
        }

        Ok(self)
    }
}

impl<'a> Drop for Allocation<'a> {
    fn drop(&mut self) {
        // Must have been used through `use_for()`
        assert!(self.start.is_none() && self.count.is_none());
    }
}

impl SplitGuestOffset {
    pub fn cluster_offset(&self, cluster_bits: u32) -> u64 {
        (((self.l1_index as u64) << (cluster_bits - 3)) + self.l2_index as u64) << cluster_bits
    }
}
