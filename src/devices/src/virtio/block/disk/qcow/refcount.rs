use super::vec_cache::{CacheMap, Cacheable, VecCache};
use crate::virtio::block::disk::qcow::qcow_raw_file::QcowRawFile;
use std::io;

#[derive(Debug)]
pub enum Error {
    EvictingRefCounts(io::Error),
    InvalidIndex,
    NeedCluster(u64),
    NeedNewCluster,
    ReadingRefCounts(io::Error),
}

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub struct RefCount {
    ref_table: VecCache<u64>,
    refcount_table_offset: u64,
    refblock_cache: CacheMap<VecCache<u16>>,
    refcount_block_entries: u64, // number of refcounts in a cluster.
    cluster_size: u64,
    max_valid_cluster_offset: u64,
}

impl RefCount {
    /// Creates a `RefCount` from `file`, reading the refcount table from `refcount_table_offset`.
    /// `refcount_table_entries` specifies the number of refcount blocks used by this image.
    /// `refcount_block_entries` indicates the number of refcounts in each refcount block.
    /// Each refcount table entry points to a refcount block.
    pub fn new(
        raw_file: &mut super::qcow_raw_file::QcowRawFile,
        refcount_table_offset: u64,
        refcount_table_entries: u64,
        refcount_block_entries: u64,
        cluster_size: u64,
    ) -> io::Result<RefCount> {
        let ref_table = VecCache::from_vec(raw_file.read_pointer_table(
            refcount_table_offset,
            refcount_table_entries,
            None,
        )?);
        let max_valid_cluster_index = (ref_table.len() as u64) * refcount_block_entries - 1;
        let max_valid_cluster_offset = max_valid_cluster_index * cluster_size;
        Ok(RefCount {
            ref_table,
            refcount_table_offset,
            refblock_cache: CacheMap::new(50),
            refcount_block_entries,
            cluster_size,
            max_valid_cluster_offset,
        })
    }

    /// Returns the number of refcounts per block.
    pub fn refcounts_per_block(&self) -> u64 {
        self.refcount_block_entries
    }

    /// Returns the maximum valid cluster offset in the raw file for this refcount table.
    pub fn max_valid_cluster_offset(&self) -> u64 {
        self.max_valid_cluster_offset
    }

    /// Returns `NeedNewCluster` if a new cluster needs to be allocated for refcounts. If an
    /// existing cluster needs to be read, `NeedCluster(addr)` is returned. The Caller should
    /// allocate a cluster or read the required one and call this function again with the cluster.
    /// On success, an optional address of a dropped cluster is returned. The dropped cluster can
    /// be reused for other purposes.
    pub fn set_cluster_refcount(
        &mut self,
        raw_file: &mut QcowRawFile,
        cluster_address: u64,
        refcount: u16,
        mut new_cluster: Option<(u64, VecCache<u16>)>,
    ) -> Result<Option<u64>> {
        let (table_index, block_index) = self.get_refcount_index(cluster_address);

        let block_addr_disk = *self.ref_table.get(table_index).ok_or(Error::InvalidIndex)?;

        // Fill the cache if this block isn't yet there.
        if !self.refblock_cache.contains_key(&table_index) {
            // Need a new cluster
            if let Some((addr, table)) = new_cluster.take() {
                self.ref_table[table_index] = addr;
                let ref_table = &self.ref_table;
                self.refblock_cache
                    .insert(table_index, table, |index, evicted| {
                        raw_file.write_refcount_block(ref_table[index], evicted.get_values())
                    })
                    .map_err(Error::EvictingRefCounts)?;
            } else {
                if block_addr_disk == 0 {
                    return Err(Error::NeedNewCluster);
                }
                return Err(Error::NeedCluster(block_addr_disk));
            }
        }

        // Unwrap is safe here as the entry was filled directly above.
        let dropped_cluster = if !self.refblock_cache.get(&table_index).unwrap().dirty() {
            // Free the previously used block and use a new one. Writing modified counts to new
            // blocks keeps the on-disk state consistent even if it's out of date.
            if let Some((addr, _)) = new_cluster.take() {
                self.ref_table[table_index] = addr;
                Some(block_addr_disk)
            } else {
                return Err(Error::NeedNewCluster);
            }
        } else {
            None
        };

        self.refblock_cache.get_mut(&table_index).unwrap()[block_index] = refcount;
        Ok(dropped_cluster)
    }

    /// Flush the dirty refcount blocks. This must be done before flushing the table that points to
    /// the blocks.
    pub fn flush_blocks(&mut self, raw_file: &mut QcowRawFile) -> io::Result<()> {
        // Write out all dirty L2 tables.
        for (table_index, block) in self.refblock_cache.iter_mut().filter(|(_k, v)| v.dirty()) {
            let addr = self.ref_table[*table_index];
            if addr != 0 {
                raw_file.write_refcount_block(addr, block.get_values())?;
            } else {
                return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
            }
            block.mark_clean();
        }
        Ok(())
    }

    /// Flush the refcount table that keeps the address of the refcounts blocks.
    /// Returns true if the table changed since the previous `flush_table()` call.
    pub fn flush_table(&mut self, raw_file: &mut QcowRawFile) -> io::Result<bool> {
        if self.ref_table.dirty() {
            raw_file.write_pointer_table(
                self.refcount_table_offset,
                self.ref_table.get_values(),
                0,
            )?;
            self.ref_table.mark_clean();
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Gets the refcount for a cluster with the given address.
    pub fn get_cluster_refcount(
        &mut self,
        raw_file: &mut super::qcow_raw_file::QcowRawFile,
        address: u64,
    ) -> Result<u16> {
        let (table_index, block_index) = self.get_refcount_index(address);
        let block_addr_disk = *self.ref_table.get(table_index).ok_or(Error::InvalidIndex)?;
        if block_addr_disk == 0 {
            return Ok(0);
        }
        if !self.refblock_cache.contains_key(&table_index) {
            let table = VecCache::from_vec(
                raw_file
                    .read_refcount_block(block_addr_disk)
                    .map_err(Error::ReadingRefCounts)?,
            );
            let ref_table = &self.ref_table;
            self.refblock_cache
                .insert(table_index, table, |index, evicted| {
                    raw_file.write_refcount_block(ref_table[index], evicted.get_values())
                })
                .map_err(Error::EvictingRefCounts)?;
        }
        Ok(self.refblock_cache.get(&table_index).unwrap()[block_index])
    }

    // Gets the address of the refcount block and the index into the block for the given address.
    fn get_refcount_index(&self, address: u64) -> (usize, usize) {
        let block_index = (address / self.cluster_size) % self.refcount_block_entries;
        let refcount_table_index = (address / self.cluster_size) / self.refcount_block_entries;
        (refcount_table_index as usize, block_index as usize)
    }
}
