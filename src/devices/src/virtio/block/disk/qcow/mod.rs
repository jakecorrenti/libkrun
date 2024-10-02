mod qcow_raw_file;
mod refcount;
mod vec_cache;

use std::sync::Mutex;

use qcow_raw_file::QcowRawFile;
use refcount::RefCount;
use vec_cache::{CacheMap, VecCache};

// QCOW magic constant that starts the header.
pub const QCOW_MAGIC: u32 = 0x5146_49fb;

#[derive(Debug)]
pub struct QcowFile {
    inner: Mutex<QcowFileInner>,
    // Copy of `inner.header.size` outside the mutex.
    virtual_size: u64,
}

#[derive(Debug)]
struct QcowFileInner {
    raw_file: QcowRawFile,
    header: QcowHeader,
    l1_table: VecCache<u64>,
    l2_entries: u64,
    l2_cache: CacheMap<VecCache<u64>>,
    refcounts: RefCount,
    current_offset: u64,
    unref_clusters: Vec<u64>, // List of freshly unreferenced clusters.
    // List of unreferenced clusters available to be used. unref clusters become available once the
    // removal of references to them have been synced to disk.
    avail_clusters: Vec<u64>,
    backing_file: Option<Box<dyn super::DiskFile>>,
}

#[derive(Clone, Debug)]
pub struct QcowHeader {
    pub magic: u32,
    pub version: u32,

    pub backing_file_offset: u64,
    pub backing_file_size: u32,

    pub cluster_bits: u32,
    pub size: u64,
    pub crypt_method: u32,

    pub l1_size: u32,
    pub l1_table_offset: u64,

    pub refcount_table_offset: u64,
    pub refcount_table_clusters: u32,

    pub nb_snapshots: u32,
    pub snapshots_offset: u64,

    // v3 entries
    pub incompatible_features: u64,
    pub compatible_features: u64,
    pub autoclear_features: u64,
    pub refcount_order: u32,
    pub header_size: u32,

    // Post-header entries
    pub backing_file_path: Option<String>,
}
