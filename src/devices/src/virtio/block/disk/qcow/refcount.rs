use super::vec_cache::{CacheMap, VecCache};
use std::io;

#[derive(Debug)]
pub enum Error {
    EvictingRefCounts(io::Error),
    InvalidIndex,
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
