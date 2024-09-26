use std::sync::atomic::{AtomicU64, AtomicUsize, AtomicBool};
use std::collections::{HashSet, HashMap, LinkedList};
use std::sync::{self, Arc, Mutex};
use std::hash::Hash;
use std::task::Walker;

use tokio::sync::{Mutex as AsyncMutex, RwLock as AsyncRwLock};
use serde::{Serialize, Deserialize};

// QCOW magic constant that starts the header.
pub const QCOW_MAGIC: u32 = 0x5146_49fb;

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
}

pub struct NodeInner {
    pub name: String,

    driver: Box<dyn NodeDriverData + Send + Sync>,

    opts: Mutex<NodeConfig>,
    pre_reopen_opts: Mutex<Option<NodeConfig>>,

    limits: NodeLimits,
    pre_reopen_limits: Mutex<Option<NodeLimits>>,

    users: Mutex<Vec<sync::Weak<NodeUser>>>,
    queue_handles: Mutex<Vec<IoQueueHandle>>,
    bitmaps: Mutex<HashMap<String, Arc<Mutex<DirtyBitmap>>>>,

    quiesce_count: Arc<AtomicUsize>,
    driver_quiesce_count: AtomicUsize,
    in_flight: Arc<AtomicUsize>,

    /// Writes that all other writes must await when intersecting
    serializing_writes: RwLock<Vec<Arc<InFlightWrite>>>,
    /// Only serializing writes need to await these writes
    nonserializing_writes: RwLock<Vec<Arc<InFlightWrite>>>,

    quiesce_waiters: Mutex<LinkedList<Waker>>,
    quiesced_queues: Mutex<LinkedList<Waker>>,
}

pub type Node = SendOnDrop<NodeInner>;

/// Parents of nodes do not own those nodes directly, but through `NodeUser` objects.  These
/// describe the parent and the permissions the parent uses and blocks.
pub struct NodeUser {
    node: Arc<Node>,
    parent: NodeParent,

    /// List of permissions the parent has taken and blocked
    permissions: Arc<IntMutNodePermPair>,
    /// During a reopen, this captures the pre-reopen permissions so we can roll back to them if
    /// needed
    roll_back_permissions: Mutex<Option<NodePermPair>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct NodeConfig {
    pub node_name: String,

    pub read_only: Option<bool>,
    pub auto_read_only: Option<bool>,

    #[serde(default)]
    pub cache: NodeCacheConfig,

    #[serde(flatten)]
    driver: NodeDriverConfig,
}

/// Pair of permissions, i.e. those that have been taken, and those that have been blocked
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NodePermPair {
    /// Permissions for things this user can do with the node
    taken: NodePerms,
    /// Things other users are not allowed to do with the node
    blocked: NodePerms,
}

/// Same as `NodePermPair`, but provides interior mutability
#[derive(Debug, Default)]
struct IntMutNodePermPair {
    taken: IntMutNodePerms,
    blocked: IntMutNodePerms,
}

/// Represent any combination of permissions
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NodePerms(u64);

/// Same as `NodePerms`, but with interior mutability
#[derive(Debug, Default)]
pub struct IntMutNodePerms(AtomicU64);

/// Describes a node's parent node
#[derive(Clone, Debug)]
struct NodeParent {
    node_name: String,
    child_name: String,
}

pub struct Qcow2Header {
    raw: Qcow2RawHeader,
    backing_filename: Option<String>,
    extensions: Vec<Qcow2HeaderExtension>,
}

#[derive(Debug, Clone)]
pub enum Qcow2HeaderExtension {
    BackingFileFormat(String),
    FeatureNameTable(HashMap<(Qcow2FeatureType, u8), String>),
    Unknown { extension_type: u32, data: Vec<u8> },
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, Hash)]
pub enum Qcow2FeatureType {
    Incompatible ,
    Compatible,
    Autoclear,
}

#[derive(Default, Deserialize, Serialize)]
#[repr(packed)]
struct Qcow2RawHeader {
    /// QCOW magic string ("QFI\xfb")
    magic: u32,

    /// Version number (valid values are 2 and 3)
    version: u32,

    /// Offset into the image file at which the backing file name
    /// is stored (NB: The string is not null terminated). 0 if the
    /// image doesn't have a backing file.
    ///
    /// Note: backing files are incompatible with raw external data
    /// files (auto-clear feature bit 1).
    backing_file_offset: u64,

    /// Length of the backing file name in bytes. Must not be
    /// longer than 1023 bytes. Undefined if the image doesn't have
    /// a backing file.
    backing_file_size: u32,

    /// Number of bits that are used for addressing an offset
    /// within a cluster (1 << cluster_bits is the cluster size).
    /// Must not be less than 9 (i.e. 512 byte clusters).
    ///
    /// Note: qemu as of today has an implementation limit of 2 MB
    /// as the maximum cluster size and won't be able to open images
    /// with larger cluster sizes.
    ///
    /// Note: if the image has Extended L2 Entries then cluster_bits
    /// must be at least 14 (i.e. 16384 byte clusters).
    cluster_bits: u32,

    /// Virtual disk size in bytes.
    ///
    /// Note: qemu has an implementation limit of 32 MB as
    /// the maximum L1 table size.  With a 2 MB cluster
    /// size, it is unable to populate a virtual cluster
    /// beyond 2 EB (61 bits); with a 512 byte cluster
    /// size, it is unable to populate a virtual size
    /// larger than 128 GB (37 bits).  Meanwhile, L1/L2
    /// table layouts limit an image to no more than 64 PB
    /// (56 bits) of populated clusters, and an image may
    /// hit other limits first (such as a file system's
    /// maximum size).
    size: u64,

    /// 0 for no encryption
    /// 1 for AES encryption
    /// 2 for LUKS encryption
    crypt_method: u32,

    /// Number of entries in the active L1 table
    l1_size: u32,

    /// Offset into the image file at which the active L1 table
    /// starts. Must be aligned to a cluster boundary.
    l1_table_offset: u64,

    /// Offset into the image file at which the refcount table
    /// starts. Must be aligned to a cluster boundary.
    refcount_table_offset: u64,

    /// Number of clusters that the refcount table occupies
    refcount_table_clusters: u32,

    /// Number of snapshots contained in the image
    nb_snapshots: u32,

    /// Offset into the image file at which the snapshot table
    /// starts. Must be aligned to a cluster boundary.
    snapshots_offset: u64,

    // The following fields are only valid for version >= 3
    /// Bitmask of incompatible features. An implementation must
    /// fail to open an image if an unknown bit is set.
    ///
    /// Bit 0:      Dirty bit.  If this bit is set then refcounts
    /// may be inconsistent, make sure to scan L1/L2
    /// tables to repair refcounts before accessing the
    /// image.
    ///
    /// Bit 1:      Corrupt bit.  If this bit is set then any data
    /// structure may be corrupt and the image must not
    /// be written to (unless for regaining
    /// consistency).
    ///
    /// Bit 2:      External data file bit.  If this bit is set, an
    /// external data file is used. Guest clusters are
    /// then stored in the external data file. For such
    /// images, clusters in the external data file are
    /// not refcounted. The offset field in the
    /// Standard Cluster Descriptor must match the
    /// guest offset and neither compressed clusters
    /// nor internal snapshots are supported.
    ///
    /// An External Data File Name header extension may
    /// be present if this bit is set.
    ///
    /// Bit 3:      Compression type bit.  If this bit is set,
    /// a non-default compression is used for compressed
    /// clusters. The compression_type field must be
    /// present and not zero.
    ///
    /// Bit 4:      Extended L2 Entries.  If this bit is set then
    /// L2 table entries use an extended format that
    /// allows subcluster-based allocation. See the
    /// Extended L2 Entries section for more details.
    ///
    /// Bits 5-63:  Reserved (set to 0)
    incompatible_features: u64,

    /// Bitmask of compatible features. An implementation can
    /// safely ignore any unknown bits that are set.
    ///
    /// Bit 0:      Lazy refcounts bit.  If this bit is set then
    /// lazy refcount updates can be used.  This means
    /// marking the image file dirty and postponing
    /// refcount metadata updates.
    ///
    /// Bits 1-63:  Reserved (set to 0)
    compatible_features: u64,

    /// Bitmask of auto-clear features. An implementation may only
    /// write to an image with unknown auto-clear features if it
    /// clears the respective bits from this field first.
    ///
    /// Bit 0:      Bitmaps extension bit
    /// This bit indicates consistency for the bitmaps
    /// extension data.
    ///
    /// It is an error if this bit is set without the
    /// bitmaps extension present.
    ///
    /// If the bitmaps extension is present but this
    /// bit is unset, the bitmaps extension data must be
    /// considered inconsistent.
    ///
    /// Bit 1:      Raw external data bit
    /// If this bit is set, the external data file can
    /// be read as a consistent standalone raw image
    /// without looking at the qcow2 metadata.
    ///
    /// Setting this bit has a performance impact for
    /// some operations on the image (e.g. writing
    /// zeros requires writing to the data file instead
    /// of only setting the zero flag in the L2 table
    /// entry) and conflicts with backing files.
    ///
    /// This bit may only be set if the External Data
    /// File bit (incompatible feature bit 1) is also
    /// set.
    ///
    /// Bits 2-63:  Reserved (set to 0)
    autoclear_features: u64,

    /// Describes the width of a reference count block entry (width
    /// in bits: refcount_bits = 1 << refcount_order). For version 2
    /// images, the order is always assumed to be 4
    /// (i.e. refcount_bits = 16).
    /// This value may not exceed 6 (i.e. refcount_bits = 64).
    refcount_order: u32,

    /// Length of the header structure in bytes. For version 2
    /// images, the length is always assumed to be 72 bytes.
    /// For version 3 it's at least 104 bytes and must be a multiple
    /// of 8.
    header_length: u32,

    /// Additional fields
    compression_type: u8,
}

pub struct AsyncLruCache<K: Clone + PartialEq + Eq + Hash, V> {
    map: AsyncRwLock<HashMap<K, Arc<AsyncLruCacheEntryInner<V>>>>,
    lru_timer: AtomicUsize,
    limit: usize,
}

pub struct AsyncLruCacheEntryInner<V> {
    value: V,
    last_used: AtomicUsize,
    dirty: AtomicBool,
}

#[derive(Debug, Clone)]
pub struct RefTable {
    offset: Option<u64>,
    data: Box<[RefTableEntry]>,
}

#[derive(Copy, Clone, Default, Debug)]
pub struct RefTableEntry(u64);

pub struct RefBlock {
    offset: Option<u64>,
    raw_data: Box<[u8]>,
    refcount_order: u32,
}

#[derive(Debug, Clone)]
pub struct L1Table {
    offset: Option<u64>,
    data: Box<[L1Entry]>,
}

#[derive(Copy, Clone, Default, Debug)]
pub struct L1Entry(u64);

type L1Index = usize;
type RefTableIndex = usize;

#[derive(Debug, Clone)]
pub struct L2Table {
    offset: Option<u64>,
    cluster_bits: u32,
    data: Box<[L2Entry]>,
}

#[derive(Copy, Clone, Default, Debug)]
pub struct L2Entry(u64);
