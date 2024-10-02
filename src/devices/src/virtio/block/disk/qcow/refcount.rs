use super::vec_cache::{CacheMap, VecCache};

#[derive(Debug)]
pub struct RefCount {
    ref_table: VecCache<u64>,
    refcount_table_offset: u64,
    refblock_cache: CacheMap<VecCache<u16>>,
    refcount_block_entries: u64, // number of refcounts in a cluster.
    cluster_size: u64,
    max_valid_cluster_offset: u64,
}
