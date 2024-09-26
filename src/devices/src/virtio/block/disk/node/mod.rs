use super::{BlockError, BlockResult};
use super::helpers::threads::{ThreadBound};
use super::helpers::{
    BlockFutureResult, BoxedFuture, InfallibleFuture, IoBuffer, IoBufferMut, IoBufferRef, IoVector,
    IoVectorMut, IteratorExtensions, Overlaps, SendOnDrop, WeakAutoDeleteIterator,
};
// use crate::monitor::{self, broadcast_event, qmp};
// use crate::server::ServerNode;
use crate::{numerical_enum, splittable_enum};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::cell::{Cell, RefCell, UnsafeCell};
use std::collections::{hash_map, HashMap, HashSet, LinkedList};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{self, Arc, Mutex, RwLock};
use std::task::{Context, Poll, Waker};
use tokio::sync::oneshot;

// pub mod exports;

// pub mod bench_export;
// pub mod copy;
use super::qcow2::file;
// pub mod nbd_export;
// pub mod null;
use super::qcow2;
// pub mod raw;

pub struct DirtyBitmap {
    layers: Vec<FlatBitmap>,
    enabled: bool,

    dirty_notifiers: Vec<oneshot::Sender<()>>,
}

const GRANULARITY_STEP: u32 = usize::BITS.trailing_zeros();

impl DirtyBitmap {
    pub fn new(length: u64, mut granularity: u64, enabled: bool) -> BlockResult<DirtyBitmap> {
        let mut layers: Vec<FlatBitmap> = Vec::new();
        layers.push(FlatBitmap::new(length, granularity)?);

        while layers.last().unwrap().data.len() >= 8 {
            granularity = match granularity.checked_shl(GRANULARITY_STEP) {
                Some(g) => g,
                None => break,
            };

            layers.push(FlatBitmap::new(length, granularity)?);
        }

        Ok(DirtyBitmap {
            layers,
            enabled,
            dirty_notifiers: Vec::new(),
        })
    }

    pub fn len(&self) -> u64 {
        self.layers[0].length
    }

    pub fn set_enabled(&mut self, enable: bool) {
        self.enabled = enable;
    }

    pub fn dirty(&mut self, start: u64, length: u64) {
        if !self.enabled {
            return;
        }

        for notifier in self.dirty_notifiers.drain(..) {
            let _: Result<(), _> = notifier.send(());
        }

        for layer in &mut self.layers {
            if !layer.dirty(start, length) {
                break;
            }
        }
    }

    pub fn clear(&mut self, start: u64, length: u64) {
        for layer in &mut self.layers {
            if !layer.clear(start, length) {
                break;
            }
        }
    }

    pub fn full_clear(&mut self) {
        for layer in &mut self.layers {
            layer.full_clear();
        }
    }

    pub fn add_dirty_notifier(&mut self) -> oneshot::Receiver<()> {
        let (notifier, notifiee) = oneshot::channel();
        self.dirty_notifiers.push(notifier);
        notifiee
    }

    pub fn merge(&mut self, other: &Self) {
        for layer in &mut self.layers {
            layer.merge(&other.layers[0])
        }
    }

    pub fn granularity(&self) -> u64 {
        1u64 << self.layers[0].ld_granularity
    }

    pub fn dirty_count(&self) -> u64 {
        self.layers[0].dirty_count
    }

    pub fn dirty_bytes(&self) -> u64 {
        self.dirty_count() << self.layers[0].ld_granularity
    }

    pub fn is_empty(&self) -> bool {
        self.layers[0].dirty_count == 0
    }

    pub fn dirty_in_range(&self, offset: u64, length: u64) -> bool {
        let clean_length = self.layers[0].get_clean_area(offset, length);
        // If `offset + clean_length == self.layers[0].length`, `length` just exceeds the length of
        // the bitmap, but we ignore everything past its end, so let that area count as clean here
        clean_length < length && offset + clean_length < self.layers[0].length
    }

    pub fn clean_in_range(&self, offset: u64, length: u64) -> bool {
        let dirty_length = self.layers[0].get_dirty_area(offset, length);
        // If `offset + dirty_length == self.layers[0].length`, `length` just exceeds the length of
        // the bitmap, but we ignore everything past its end, so let that area count as dirty here
        dirty_length < length && offset + dirty_length < self.layers[0].length
    }

    pub fn get_clean_area(&self, offset: u64, length: u64) -> u64 {
        self.layers[0].get_clean_area(offset, length)
    }

    pub fn get_dirty_area(&self, offset: u64, length: u64) -> u64 {
        self.layers[0].get_dirty_area(offset, length)
    }
}


struct FlatBitmap {
    data: Vec<usize>,
    length: u64,
    dirty_count: u64,

    ld_granularity: u32,
    shift_to_usize: u32,
    in_usize_mask: usize,
}

macro_rules! bitmap_get_area {
    ($name:ident, $check_usize:ident, $in_condition_bit_count:ident) => {
        fn $name(&self, offset: u64, max_len: u64) -> u64 {
            let max_len = std::cmp::min(max_len, self.length - offset);

            let bit_index = (offset >> self.ld_granularity) as usize;

            let mut in_usize_index = (bit_index & self.in_usize_mask) as u32;
            let mut usize_index = bit_index >> self.shift_to_usize;
            let mut len = 0u64;
            let len_per_usize = 1u64 << (self.ld_granularity + self.shift_to_usize);

            while len < max_len {
                if let Some(partial) = self.$check_usize(usize_index, in_usize_index) {
                    len += (partial as u64) << self.ld_granularity;
                    break;
                }

                usize_index += 1;
                if in_usize_index == 0 {
                    len += len_per_usize;
                } else {
                    len += (usize::BITS as u64 - in_usize_index as u64) << self.ld_granularity;
                    in_usize_index = 0;
                }
            }

            std::cmp::min(len, max_len)
        }
    };
}

macro_rules! bitmap_operation {
    ($name:ident, $element_operation:ident, $dirty:literal) => {
        fn $name(&mut self, start: u64, length: u64) -> bool {
            if length == 0 {
                return false;
            }

            assert!(start < self.length);
            let end = start.checked_add(length).unwrap();
            // End must either be less than the bitmap length, or be aligned exactly to the length
            // rounded up to match the granularity
            assert!(
                end <= self.length
                    || end
                        == (self.length + (1 << self.ld_granularity) - 1)
                            & !((1 << self.ld_granularity) - 1)
            );

            let (start_bit, end_bit): (usize, usize) = if $dirty {
                // Round up if dirtying
                (
                    (start >> self.ld_granularity) as usize,
                    ((start + length - 1) >> self.ld_granularity) as usize,
                )
            } else {
                // Round down if clearing
                let gran_size = 1u64 << self.ld_granularity;
                let start_bit = ((start + gran_size - 1) >> self.ld_granularity) as usize;
                let end_bit = if start + length == self.length {
                    ((self.length - 1) >> self.ld_granularity) as usize
                } else {
                    match (start + length).checked_sub(gran_size) {
                        Some(x) => (x >> self.ld_granularity) as usize,
                        None => return false,
                    }
                };
                if start_bit > end_bit {
                    return false;
                }

                (start_bit, end_bit)
            };

            let start_usize = start_bit >> self.shift_to_usize;
            let end_usize = end_bit >> self.shift_to_usize;

            let mut modified = 0;

            if start_usize == end_usize {
                let start_bit = (start_bit & self.in_usize_mask) as u32;
                let end_bit = (end_bit & self.in_usize_mask) as u32;

                let mask =
                    2usize.wrapping_shl(end_bit).wrapping_sub(1) & !((1usize << start_bit) - 1);

                modified += self.$element_operation(start_usize, mask);
            } else {
                let start_bit = (start_bit & self.in_usize_mask) as u32;
                let mask = usize::MAX & !((1usize << start_bit) - 1);

                modified += self.$element_operation(start_usize, mask);

                for usize_i in (start_usize + 1)..end_usize {
                    modified += self.$element_operation(usize_i, usize::MAX);
                }

                let end_bit = (end_bit & self.in_usize_mask) as u32;
                let mask = 2usize.wrapping_shl(end_bit).wrapping_sub(1);

                modified += self.$element_operation(end_usize, mask);
            }

            if $dirty {
                self.dirty_count += modified;
            } else {
                self.dirty_count -= modified;
            }
            modified != 0
        }
    };
}

impl FlatBitmap {
    bitmap_operation!(dirty, usize_dirty, true);

    bitmap_operation!(clear, usize_clear, false);

    bitmap_get_area!(get_clean_area, get_clean_area_single_usize, trailing_zeros);

    bitmap_get_area!(get_dirty_area, get_dirty_area_single_usize, trailing_ones);

    fn new(length: u64, granularity: u64) -> BlockResult<FlatBitmap> {
        if !granularity.is_power_of_two() {
            return Err(format!(
                "Bitmap granularity must be a power of two; {} is not",
                granularity
            )
                .into());
        }

        let ld_granularity = granularity.trailing_zeros();
        let bit_count = (length.checked_add(granularity).ok_or_else(|| {
            format!(
                "Bitmap size ({}) must not exceed u64::MAX - granularity ({})",
                length,
                u64::MAX - granularity
            )
        })? - 1)
            >> ld_granularity;

        if bit_count > usize::MAX as u64 {
            return Err(format!(
                "Bitmap size ({}) divided by granularity ({}), rounded up, must not exceed \
                 usize::MAX ({}); try a bigger granularity",
                length,
                granularity,
                usize::MAX
            )
                .into());
        }

        let shift_to_usize = usize::BITS.trailing_zeros();
        let in_usize_mask: usize = (usize::BITS - 1).try_into().unwrap();

        let usize_count = (bit_count + usize::BITS as u64 - 1) >> shift_to_usize;

        let mut data = Vec::new();
        data.resize_with(usize_count.try_into().unwrap(), Default::default);

        Ok(FlatBitmap {
            data,
            length,
            dirty_count: 0,
            ld_granularity,
            shift_to_usize,
            in_usize_mask,
        })
    }

    fn usize_dirty(&mut self, index: usize, mask: usize) -> u64 {
        let to_set = !self.data[index] & mask;
        if to_set != 0 {
            self.data[index] |= mask;
            to_set.count_ones() as u64
        } else {
            0
        }
    }

    fn usize_clear(&mut self, index: usize, mask: usize) -> u64 {
        let to_clear = self.data[index] & mask;
        if to_clear != 0 {
            self.data[index] &= !mask;
            to_clear.count_ones() as u64
        } else {
            0
        }
    }

    fn get_dirty_area_single_usize(&self, usize_index: usize, in_usize_index: u32) -> Option<u32> {
        let lower_set: usize = (1usize << in_usize_index) - 1;
        let masked = self.data[usize_index] | lower_set;
        if masked != usize::MAX {
            Some(masked.trailing_ones() - in_usize_index)
        } else {
            None
        }
    }

    fn get_clean_area_single_usize(&self, usize_index: usize, in_usize_index: u32) -> Option<u32> {
        let lower_cleared: usize = !((1usize << in_usize_index) - 1);
        let masked = self.data[usize_index] & lower_cleared;
        if masked != 0 {
            Some(masked.trailing_zeros() - in_usize_index)
        } else {
            None
        }
    }

    fn full_clear(&mut self) {
        self.data.fill(0);
        self.dirty_count = 0;
    }

    fn merge(&mut self, other: &Self) {
        match other.ld_granularity.cmp(&self.ld_granularity) {
            std::cmp::Ordering::Equal => self.merge_same_granularity(other),
            std::cmp::Ordering::Less => self.merge_smaller_granularity(other),
            std::cmp::Ordering::Greater => self.merge_greater_granularity(other),
        }

        self.clean_tail();
        self.recalc_dirty_count();
    }

    fn clean_tail(&mut self) {
        if self.length == 0 {
            assert!(self.data.is_empty());
            return;
        }

        let past_last_bit_index = ((self.length - 1) >> self.ld_granularity) + 1;
        let past_last_usize = past_last_bit_index >> self.shift_to_usize;
        if past_last_usize >= self.data.len() as u64 {
            return;
        }

        // Keep all bits excluding `past_last_bit_index`, clean the rest
        let mask = (1usize
            .wrapping_shl((past_last_bit_index & (self.in_usize_mask as u64)) as u32))
            .wrapping_sub(1);
        self.data[past_last_usize as usize] &= mask;
    }

    fn recalc_dirty_count(&mut self) {
        self.dirty_count = 0;
        for word in self.data.iter() {
            self.dirty_count += word.count_ones() as u64;
        }
    }

    fn merge_same_granularity(&mut self, other: &Self) {
        assert!(self.ld_granularity == other.ld_granularity);
        let len = std::cmp::min(self.data.len(), other.data.len());
        for i in 0..len {
            self.data[i] |= other.data[i];
        }
    }

    fn merge_smaller_granularity(&mut self, other: &Self) {
        assert!(self.ld_granularity > other.ld_granularity);

        // Area covered by a single bit in `self`
        let self_bit_area_length = 1u64 << self.ld_granularity;

        let mut i = 0;
        while i < other.data.len() {
            let mut word = other.data[i];
            if word == 0 {
                i += 1;
                continue;
            }

            let mut j = 0;
            while j < usize::BITS {
                if word & (1usize << j) != 0 {
                    let offset =
                        (((i as u64) << other.shift_to_usize) | j as u64) << other.ld_granularity;

                    let offset_rounded_down = offset & !((1u64 << self.ld_granularity) - 1);
                    if offset_rounded_down >= self.length {
                        return;
                    }
                    // `self` has a greater granularity, so anything in `1..=self_bit_area_length`
                    // has the same effect (but this does not need to be checked against
                    // `self.length`)
                    self.dirty(offset_rounded_down, 1);

                    let next_offset = offset_rounded_down + self_bit_area_length;
                    j = ((next_offset >> other.ld_granularity) & (other.in_usize_mask as u64))
                        as u32;
                    i = (next_offset >> (other.ld_granularity + other.shift_to_usize)) as usize;

                    if i >= other.data.len() {
                        return;
                    }
                    word = other.data[i];
                    if word == 0 {
                        break;
                    }
                } else {
                    j += 1;
                }
            }

            i += 1;
        }
    }

    fn merge_greater_granularity(&mut self, other: &Self) {
        assert!(self.ld_granularity < other.ld_granularity);

        // Area covered by a single bit in `other`
        let other_bit_area_length = 1u64 << other.ld_granularity;

        for i in 0..other.data.len() {
            let word = other.data[i];
            if word == 0 {
                continue;
            }

            for j in 0..usize::BITS {
                if word & (1usize << j) != 0 {
                    let offset =
                        (((i as u64) << other.shift_to_usize) | j as u64) << other.ld_granularity;
                    if offset >= self.length {
                        return;
                    }
                    self.dirty(
                        offset,
                        std::cmp::min(other_bit_area_length, self.length - offset),
                    );
                }
            }
        }
    }
}


pub struct DirtyBitmapIterator {
    bitmap: Arc<Mutex<DirtyBitmap>>,
    offset: u64,
    max_area_length: u64,
    clear: bool,
}

pub struct DirtyBitmapArea {
    pub offset: u64,
    pub length: u64,
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

/// Pollable nodes that are bound to servers announce this via creating this struct, which, on
/// drop, will automatically detach the node from the server
pub struct ServerNode {
    node_name: String,
    server: String,

    _main_thread: super::helpers::threads::MainThreadOnlyMarker,
}

pub struct PollableNode {
    node: Arc<Node>,
    future: BoxedFuture<'static, BackgroundOpResult>,

    /// This is just here so when this object is dropped, the node is removed from its server
    _server: Option<ServerNode>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PollableNodeStopMode {
    /// Exit only if there are no active connections
    #[default]
    Safe,
    /// Exit now, closing all active connections
    Hard,
    /// Copy node: Settle everything, then switch over or not
    CopyComplete {
        #[serde(rename = "switch-over")]
        switch_over: bool,
    },
}

/// Node that should be closed automatically once all users are gone.  To ensure all users are
/// gone, the node is (optionally) replaced by one of its children first of all.
pub struct FadingNode {
    fut: BoxedFuture<'static, Result<(), (BlockError, Arc<Node>)>>,
    node_name: String,
}

/// Helper object to construct a `NodeUser`
#[derive(Clone)]
pub struct NodeUserBuilder {
    parent: NodeParent,
    permissions: NodePermPair,
}

/// Describes a node's parent node
#[derive(Clone, Debug)]
struct NodeParent {
    node_name: String,
    child_name: String,
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

numerical_enum! {
    /// Permissions that can be taken/blocked on a node
    pub enum NodePerm as u64 {
        /// Guarantees that data read from the node represents a complete and self-consistent view
        /// of it
        ConsistentRead = 0x1,
        /// Allows writing
        Write = 0x2,
        /// Allows writing data such that the data read from the node will not change
        WriteUnchanged = 0x4,
        /// Allows changing the node's size
        Resize = 0x8,
    }
}

/// Represent any combination of permissions
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NodePerms(u64);

/// Same as `NodePerms`, but with interior mutability
#[derive(Debug, Default)]
pub struct IntMutNodePerms(AtomicU64);

type QueueBitmapList = RefCell<Vec<Arc<Mutex<DirtyBitmap>>>>;

pub struct IoQueue {
    // Reachable also thorugh `node_user.node`, but this is quicker
    node: Arc<Node>,
    node_user: Arc<NodeUser>,
    inner: Arc<IoQueueMut>,

    quiesce_count: Arc<AtomicUsize>,
    node_in_flight: Arc<AtomicUsize>,
    queue_in_flight: Cell<usize>,
}

struct IoQueueMut {
    driver: UnsafeCell<Box<dyn IoQueueDriverData>>,
    bitmaps: QueueBitmapList,
    request_alignment: Cell<usize>,
    memory_alignment: Cell<usize>,
    enforced_memory_alignment: Cell<usize>,
}

/// Handle on an `IoQueue` for the purpose of accessing it externally
struct IoQueueHandle {
    inner: ThreadBound<sync::Weak<IoQueueMut>>,

    /// Whether the queue was successfully reopened (i.e. whether `reopen_do()` was successful).
    /// If not, `reopen_roll_back()` will not be called.
    did_reopen: bool,
}

pub struct NodeLimits {
    pub size: AtomicU64,
    pub request_alignment: AtomicUsize,
    /// Somewhere down the node graph, some node will enforce this limit, but not necessarily this
    /// one.  Parents are well-advised to adhere to this limit, but it will not be enforced by the
    /// common node code.
    pub memory_alignment: AtomicUsize,
    /// In contrast to `memory_alignment`, this limit is enforced by the common node code.
    /// Requests whose buffers are not aligned to this value will be amended (which involves an
    /// allocation and a memcpy) to match it.
    pub enforced_memory_alignment: AtomicUsize,
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
    pub driver: NodeDriverConfig,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct NodeCacheConfig {
    #[serde(default)]
    direct: bool,
}

splittable_enum! {
    #[derive(Clone, Debug, Deserialize, Serialize)]
    #[serde(tag = "driver", rename_all = "kebab-case")]
    pub enum NodeDriverConfig {
        // BenchExport(bench_export::Config),
        // Copy(copy::Config),
        // File(file::Config),
        // NbdExport(nbd_export::Config),
        // Null(null::Config),
        Qcow2(qcow2::Config),
        // Raw(raw::Config),
        // #[cfg(feature = "vhost-user-blk")]
        // VhostUserBlkExport(vhost_user_blk_export::Config),
    }
}

/// For use in block drivers to denote a reference to a child node (in their `NodeDriverConfig`
/// variant).
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum NodeConfigOrReference {
    Reference(String),
    // Not a `NodeConfig` so there is no recursive definition (which the compiler would not like)
    Config(serde_json::Map<String, serde_json::Value>),
}

pub struct NodeBasicInfo {
    pub limits: NodeLimits,
}

mod qmp {
    #[derive(Clone, Copy, Debug, Eq, PartialEq, super::Deserialize, super::Serialize)]
    #[serde(rename_all = "kebab-case")]
    pub enum JobType {
        Backup,
        Mirror,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq, super::Deserialize, super::Serialize)]
    #[serde(rename_all = "kebab-case")]
    pub enum JobStatus {
        Undefined,
        Created,
        Running,
        Paused,
        Ready,
        Standby,
        Pending,
        Aborting,
        Concluded,
        Null,
    }
}

#[derive(Clone)]
pub struct JobInfo {
    pub job_type: qmp::JobType,
    pub status: qmp::JobStatus,
    pub id: String,
    pub done: u64,
    pub remaining: u64,
    pub busy: bool,
    pub auto_finalize: bool,
    pub auto_dismiss: bool,
    pub error: Option<String>,
}

pub struct QuiesceWaiter<'a> {
    waiting: bool,

    in_flight: &'a AtomicUsize,
    quiesce_waiters: &'a Mutex<LinkedList<Waker>>,
}

pub struct QuiescedQueueWaiter<'a> {
    waiting: bool,

    queue: &'a IoQueue,
    request: Option<Request<'a>>,
    future: Option<BlockFutureResult<'a, ()>>,
}

enum Request<'a> {
    Readv {
        bufv: IoVectorMut<'a>,
        offset: u64,
        allow_post_eof: bool,
    },
    Writev {
        bufv: IoVector<'a>,
        offset: u64,
        allow_grow: bool,
    },
    Flush,
}

/// When performing a reopen action on an `IoQueue`, this specifies which action to take.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IoQueueReopenAction {
    Do,
    Clean,
    RollBack,
}

/// To reopen nodes, collect them in an object of this type (via `ReopenQueue::push()`) and then
/// call `ReopenQueue::reopen()`.
pub struct ReopenQueue {
    params: HashMap<NodeId, ReopenParams>,
    pre_reopen_order: Vec<NodeId>,
    post_reopen_order: Vec<NodeId>,
}

/// Parameters for reopening a single node.
struct ReopenParams {
    opts: Option<NodeConfig>,
    node: Arc<Node>,
    begun_reopen: bool,
    quiesced: bool,
}

#[derive(Debug)]
struct InFlightWrite {
    range: std::ops::Range<u64>,
    waiters: Mutex<Vec<oneshot::Sender<()>>>,

    // Index in its containing write list (so that the element can be removed when the write is
    // done)
    index: AtomicUsize,
}

/// Representation of write serialization: Some writes (at least read-modify-write cycles) require
/// all other intersecting writes to be serialized around them.  They will therefore install a
/// blocker (referenced by the `.handle` field), and all other writes will need to await them.
/// So while `.handle` may or may not be set, depending on whether this write is serializing, all
/// writes must await intersecting serializing writes: That is the `.intersecting_blockers` field,
/// which will contain a future to await those requests if there are any.  If it is set
/// (`.must_await()` returns true), the object owner (the write) must await it before submitting
/// their own write (`.await_intersecting().await`).
struct InFlightWriteBlocker<F: Future<Output = ()>> {
    node: Arc<Node>,
    // Wrapped in `Option<>` so `drop()` can `take()` this and `Arc::try_unwrap()` it
    handle: Option<Arc<InFlightWrite>>,

    serializing: bool,

    // If there are intersecting serializing writes, this must be awaited before submitting the
    // write this blocker is for
    intersecting_blockers: Option<F>,
}

/// Result that a background operation returns when it settles
pub struct BackgroundOpResult {
    /// The actual result
    pub result: BlockResult<()>,
    /// Whether the corresponding node should immediately fade
    pub auto_fade: bool,
}

/// Identifies a node without having to resort to the node-name (which is a string, and thus more
/// costly)
pub type NodeId = usize;

#[async_trait]
pub trait NodeDriverData {
    /// Get basic information about this node
    async fn get_basic_info(&self) -> BlockResult<NodeBasicInfo>;

    /// Drivers that need to run a background operation (like a block job) implement this function
    /// and have it return a respective future that can be polled.  If the node is bound to a
    /// server, it must also return a `ServerNode`.
    #[allow(clippy::type_complexity)]
    fn background_operation(
        &self,
    ) -> Option<(BoxedFuture<'static, BackgroundOpResult>, Option<ServerNode>)> {
        None
    }

    /// If qemu would consider this node to be a block job filter node, return job info
    fn block_job_info(&self) -> Option<JobInfo> {
        None
    }

    /// Return the node which is to succeed this node (e.g. for job-finalize)
    fn get_successor(&self) -> Option<Arc<Node>> {
        None
    }

    /// Finish all remaining async operations so the node can be dropped
    fn drain_caches(&mut self) -> InfallibleFuture {
        Box::pin(async {})
    }

    /// Create a new I/O queue (called from the thread where the queue is to be used)
    fn new_queue(&self) -> BlockResult<Box<dyn IoQueueDriverData>>;

    /// Return all children this node has
    fn get_children(&self) -> Vec<Arc<Node>>;

    /// Return all children this node would have after a successful reopen with the given options
    fn get_children_after_reopen(&self, opts: &NodeConfig) -> BlockResult<Vec<Arc<Node>>>;

    /// If this is a pollable node, quiesce that background operation.  Called only once before
    /// `unquiesce()` is invoked.
    fn quiesce(&self) -> InfallibleFuture {
        Box::pin(async {})
    }

    /// If this is a pollable node, resume background operation.
    fn unquiesce(&self) {}

    /// If this is a pollable node, stop the background operation altogether (how to stop and
    /// whether to actually stop it at all depends on the `mode` parameter).
    fn stop<'a>(&self, _mode: PollableNodeStopMode) -> BlockFutureResult<'a, ()> {
        Box::pin(async { Err("This node does not support background operations".into()) })
    }

    /// Preparatory step during the reopen process.  Change the graph as necessary, i.e. add new
    /// child nodes (using `Node::add_user_in_reopen_change_graph()`) and take/relinquish
    /// permissions on child nodes (using `NodeUser::set_perms_in_reopen_change_graph()`).
    /// `step` tells whether to take or relinquish permissions, both must be done separately.
    /// This operation may need to be rolled back (without error), so the driver must retain the
    /// old state until `reopen_clean()` or `reopen_roll_back()` are called.
    /// Not marked async because the compiler does not like that for some reason.
    fn reopen_change_graph<'a>(
        &'a self,
        _opts: &'a NodeConfig,
        _perms: NodePermPair,
        _read_only: bool,
        _step: ChangeGraphStep,
    ) -> BlockFutureResult<'a, ()> {
        Box::pin(async { Ok(()) })
    }
    /// Reopen the node.  The driver has to check that `opts` matches its type.  This operation may
    /// need to be rolled back (without error), so the driver must retain the old state until
    /// `reopen_clean()` or `reopen_roll_back()` are called.
    /// Not marked async because the compiler does not like that for some reason.
    fn reopen_do(
        &self,
        opts: NodeConfig,
        perms: NodePermPair,
        read_only: bool,
    ) -> BlockFutureResult<()>;
    /// Clean up potentially retained old state after a reopen.
    fn reopen_clean(&self) {
        // Either this or `reopen_clean_async()` must be implemented
        todo!()
    }
    /// Async version of `reopen_clean()` for pollable nodes that need to send and await messages
    /// to their background operations.
    fn reopen_clean_async(&self) -> InfallibleFuture {
        self.reopen_clean();
        Box::pin(async {})
    }
    /// Roll back to the old state after a failed reopen attempt (only called after this node's
    /// `reopen_change_graph()` has returned success).
    fn reopen_roll_back(&self) {
        // Either this or `reopen_clean_async()` must be implemented
        todo!()
    }
    /// Async version of `reopen_roll_back()` for pollable nodes that need to send and await
    /// messages to their background operations.
    fn reopen_roll_back_async(&self) -> InfallibleFuture {
        self.reopen_roll_back();
        Box::pin(async {})
    }
}

pub trait IoQueueDriverData {
    /// Read data from the given offset into the given buffer vector (length `bufv.len()`)
    fn readv<'a>(&'a self, bufv: IoVectorMut<'a>, offset: u64) -> BlockFutureResult<'a, ()>;
    /// Write data from the given buffer vector to the given offset (length `bufv.len()`)
    fn writev<'a>(&'a self, bufv: IoVector<'a>, offset: u64) -> BlockFutureResult<'a, ()>;
    /// Flush the device
    fn flush(&self) -> BlockFutureResult<'_, ()>;

    /// Update queue data after the node has been reopened
    fn reopen_do(&mut self) -> BlockResult<()>;
    /// Clean up potentially retained old state after a reopen
    fn reopen_clean(&mut self);
    /// Roll back to the old state after a failed reopen attempt (not called when this queue's
    /// `reopen_do()` did not return success, only if it was another queue or node that failed).
    fn reopen_roll_back(&mut self);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChangeGraphStep {
    Release,
    Acquire,
}

impl NodeConfig {
    /// Splits a tree-form `NodeConfig` into one configuration per node.  The list is sorted such
    /// that child nodes always appear before their parents.
    pub fn split_tree(mut self, vec: &mut Vec<NodeConfig>) -> BlockResult<()> {
        match &mut self.driver {
            // NodeDriverConfig::BenchExport(o) => o.split_tree(vec)?,
            // NodeDriverConfig::Copy(o) => o.split_tree(vec)?,
            // NodeDriverConfig::File(o) => o.split_tree(vec)?,
            // NodeDriverConfig::NbdExport(o) => o.split_tree(vec)?,
            // NodeDriverConfig::Null(o) => o.split_tree(vec)?,
            NodeDriverConfig::Qcow2(o) => o.split_tree(vec)?,
            // NodeDriverConfig::Raw(o) => o.split_tree(vec)?,
            // #[cfg(feature = "vhost-user-blk")]
            // NodeDriverConfig::VhostUserBlkExport(o) => o.split_tree(vec)?,
        }

        vec.push(self);
        Ok(())
    }
}

pub async fn new(opts: NodeConfig) -> BlockResult<(Arc<Node>, Option<PollableNode>)> {
    let cloned_opts = opts.clone();
    let name = opts.node_name;

    // Nodes are always created without parents at first, so if auto-read-only is set, it is
    // read-only
    let read_only = opts.read_only.unwrap_or(false) || opts.auto_read_only.unwrap_or(false);

    let mut driver: Box<dyn NodeDriverData + Send + Sync> = match opts.driver {
        // NodeDriverConfig::BenchExport(o) => {
        //     bench_export::Data::new(&name, o, read_only, &opts.cache).await?
        // }
        // NodeDriverConfig::Copy(o) => copy::Data::new(&name, o, read_only, &opts.cache).await?,
        // NodeDriverConfig::File(o) => file::Data::new(&name, o, read_only, &opts.cache).await?,
        // NodeDriverConfig::NbdExport(o) => {
        //     nbd_export::Data::new(&name, o, read_only, &opts.cache).await?
        // }
        // NodeDriverConfig::Null(o) => null::Data::new(&name, o, read_only, &opts.cache).await?,
        NodeDriverConfig::Qcow2(o) => qcow2::Data::new(&name, o, read_only, &opts.cache).await?,
        // NodeDriverConfig::Raw(o) => raw::Data::new(&name, o, read_only, &opts.cache).await?,
        // #[cfg(feature = "vhost-user-blk")]
        // NodeDriverConfig::VhostUserBlkExport(o) => {
        //     vhost_user_blk_export::Data::new(&name, o, read_only, &opts.cache).await?
        // }
    };

    let basic_info = match driver
        .get_basic_info()
        .await
        .and_then(NodeBasicInfo::check_validity)
    {
        Ok(info) => info,
        Err(err) => {
            driver.drain_caches().await;
            return Err(err);
        }
    };

    let node = NodeInner {
        name,
        driver,
        opts: Mutex::new(cloned_opts),
        pre_reopen_opts: Mutex::new(None),
        limits: basic_info.limits,
        pre_reopen_limits: Default::default(),
        users: Default::default(),
        queue_handles: Default::default(),
        bitmaps: Default::default(),
        quiesce_count: Arc::new(AtomicUsize::new(0)),
        driver_quiesce_count: AtomicUsize::new(0),
        in_flight: Arc::new(AtomicUsize::new(0)),
        serializing_writes: Default::default(),
        nonserializing_writes: Default::default(),
        quiesce_waiters: Default::default(),
        quiesced_queues: Default::default(),
    };

    let node = Arc::new(SendOnDrop::new(node));

    let pollable_node = node
        .driver
        .background_operation()
        .map(|(future, server)| PollableNode {
            node: Arc::clone(&node),
            future,
            _server: server,
        });

    Ok((node, pollable_node))
}

impl Node {
    /// Add a new `NodeUser` to this node.  Must only be called from a
    /// `NodeDriverData::reopen_change_graph()` implementation, because it does not communicate the
    /// permission changes to the node.  The subsequent reopen process is expected to take care of
    /// this.
    pub fn add_user_in_reopen_change_graph(
        self: &Arc<Self>,
        user: NodeUserBuilder,
    ) -> BlockResult<Arc<NodeUser>> {
        let user = Arc::new(NodeUser {
            node: Arc::clone(self),
            parent: user.parent,

            permissions: Arc::new(user.permissions.into()),
            roll_back_permissions: Default::default(),
        });

        self.check_perm_conflicts(&user)?;
        self.users.lock().unwrap().push(Arc::downgrade(&user));

        Ok(user)
    }

    /// Add a new `NodeUser` to this node.  Must not be called during reopen, use
    /// `add_user_in_reopen_change_graph()` instead.
    pub async fn add_user(self: &Arc<Self>, user: NodeUserBuilder) -> BlockResult<Arc<NodeUser>> {
        let user = self.add_user_in_reopen_change_graph(user)?;

        let mut reopen_queue = ReopenQueue::new();
        let opts = self.opts.lock().unwrap().clone();
        reopen_queue.push(Arc::clone(self), opts)?;
        reopen_queue.reopen().await?;

        Ok(user)
    }
}

impl NodeInner {
    pub fn id(&self) -> NodeId {
        self as *const NodeInner as usize
    }

    pub fn get_opts(&self) -> NodeConfig {
        self.opts.lock().unwrap().clone()
    }

    pub fn size(&self) -> u64 {
        self.limits.size.load(Ordering::Relaxed)
    }

    pub fn request_align(&self) -> usize {
        self.limits.request_alignment.load(Ordering::Relaxed)
    }

    pub fn mem_align(&self) -> usize {
        self.limits.memory_alignment.load(Ordering::Relaxed)
    }

    pub fn enforced_mem_align(&self) -> usize {
        self.limits
            .enforced_memory_alignment
            .load(Ordering::Relaxed)
    }

    /// Check whether adding the given user `new_user` to this node would lead to conflicts.  If
    /// so, return an error.
    /// `new_user` may be an existing user on this node, in which case it is checked against all
    /// other users for conflicts.  This can be used to change an existing user's permissions.
    fn check_perm_conflicts(&self, new_user: &NodeUser) -> BlockResult<()> {
        let mut users = self.users.lock().unwrap();
        let mut errors: Vec<String> = Vec::new();

        let new_perms: NodePermPair = new_user.permissions.as_ref().into();

        for user in WeakAutoDeleteIterator::from_vec(&mut users, sync::Weak::upgrade) {
            // Check if `new_user` already exists in the list, if so, skip it.
            // This happens when trying to change an existing user's permissions.
            if std::ptr::eq(user.as_ref() as *const _, new_user as *const _) {
                continue;
            }

            let existing_perms: NodePermPair = user.permissions.as_ref().into();

            let overlap = existing_perms.taken.overlap_with(new_perms.blocked);
            if !overlap.is_empty() {
                errors.push(format!(
                    "block permissions already taken by {}: {}",
                    user.parent, overlap
                ));
            }

            let overlap = existing_perms.blocked.overlap_with(new_perms.taken);
            if !overlap.is_empty() {
                errors.push(format!(
                    "take permissions already blocked by {}: {}",
                    user.parent, overlap
                ));
            }
        }

        if errors.is_empty() {
            Ok(())
        } else if errors.len() == 1 {
            Err(format!(
                "New parent {} of node \"{}\" would {}",
                new_user.parent, self.name, errors[0]
            )
                .into())
        } else {
            Err(format!(
                "New parent {} of node \"{}\" would: {}",
                new_user.parent,
                self.name,
                errors.join("; ")
            )
                .into())
        }
    }

    /// Calculate the cumulative permissions taken by all users on this node.
    fn get_perms(&self) -> NodePermPair {
        let mut users = self.users.lock().unwrap();
        let mut perms = NodePermPair::default();

        for user in WeakAutoDeleteIterator::from_vec(&mut users, sync::Weak::upgrade) {
            perms.taken.add(&user.permissions.taken);
            perms.blocked.add(&user.permissions.blocked);
        }

        perms
    }

    /// Return all children this node has
    fn get_children(&self) -> Vec<Arc<Node>> {
        self.driver.get_children()
    }

    /// Return all children this node would have after a successful reopen with the given options
    fn get_children_after_reopen(&self, opts: &NodeConfig) -> BlockResult<Vec<Arc<Node>>> {
        self.driver
            .get_children_after_reopen(opts)
            .map_err(|err| err.prepend(&format!("Node \"{}\"", self.name)))
    }

    /// Check whether `self` has any of the nodes in `other` as children
    fn has_any_as_child(&self, other: &HashSet<NodeId>) -> bool {
        self.get_children()
            .into_iter()
            .any(|child| other.contains(&child.id()))
    }

    /// Check whether `self` will have any of the nodes in `other` as children once a reopen with
    /// the given parameteters has been done
    fn has_any_as_child_after_reopen(
        &self,
        other: &HashSet<NodeId>,
        reopen_params: &HashMap<NodeId, ReopenParams>,
    ) -> BlockResult<bool> {
        let children =
            if let Some(opts) = reopen_params.get(&self.id()).and_then(|p| p.opts.as_ref()) {
                self.get_children_after_reopen(opts)?
            } else {
                self.get_children()
            };

        Ok(children
            .into_iter()
            .any(|child| other.contains(&child.id())))
    }

    /// Check whether the subtree below `self` will have any nodes that are present in `other` once
    /// a reopen with the given parameters has been done.  This subtree does not include `self`.
    fn has_any_in_exclusive_subtree_after_reopen(
        &self,
        other: &HashSet<NodeId>,
        reopen_params: &HashMap<NodeId, ReopenParams>,
    ) -> BlockResult<bool> {
        let children =
            if let Some(opts) = reopen_params.get(&self.id()).and_then(|p| p.opts.as_ref()) {
                self.get_children_after_reopen(opts)?
            } else {
                self.get_children()
            };

        children
            .into_iter()
            .try_any(|child| child.has_any_in_inclusive_subtree_after_reopen(other, reopen_params))
    }

    /// Same as `has_any_in_exclusive_subtree_after_reopen()`, but the subtree does include `self`.
    fn has_any_in_inclusive_subtree_after_reopen(
        &self,
        other: &HashSet<NodeId>,
        reopen_params: &HashMap<NodeId, ReopenParams>,
    ) -> BlockResult<bool> {
        if other.contains(&self.id()) {
            return Ok(true);
        }

        self.has_any_in_exclusive_subtree_after_reopen(other, reopen_params)
    }

    pub fn drain_caches(mut self) -> InfallibleFuture<'static> {
        Box::pin(async move { self.driver.drain_caches().await })
    }

    /// Quiesce the node: Stop background operations and pause all IoQueues, waiting for current
    /// in-flight operations to settle.
    fn quiesce(&self) -> impl Future<Output = ()> + '_ {
        let driver_quiesce = self.quiesce_background();

        self.quiesce_count.fetch_add(1, Ordering::SeqCst);

        let queue_quiesce = QuiesceWaiter {
            waiting: false,
            in_flight: self.in_flight.as_ref(),
            quiesce_waiters: &self.quiesce_waiters,
        };

        async move {
            let ((), ()) = futures::join!(driver_quiesce, queue_quiesce);
        }
    }

    /// Stop background operations on the node, but keep IoQueues running.
    pub fn quiesce_background(&self) -> InfallibleFuture {
        if self.driver_quiesce_count.fetch_add(1, Ordering::SeqCst) == 0 {
            self.driver.quiesce()
        } else {
            Box::pin(async {})
        }
    }

    /// Pairs with `quiesce()`.  Tell the node that background operations and IoQueue operations
    /// may be resumed.
    fn unquiesce(&self) {
        if self.quiesce_count.fetch_sub(1, Ordering::SeqCst) == 1 {
            let mut list = self.quiesced_queues.lock().unwrap();
            while let Some(waker) = list.pop_front() {
                waker.wake();
            }
        }

        self.unquiesce_background();
    }

    /// Pairs with `quiesce_background()`.  Tell the node that background operations may be
    /// resumed.
    pub fn unquiesce_background(&self) {
        if self.driver_quiesce_count.fetch_sub(1, Ordering::SeqCst) == 1 {
            self.driver.unquiesce();
        }
    }

    pub fn stop<'a>(&self, mode: PollableNodeStopMode) -> BlockFutureResult<'a, ()> {
        self.driver.stop(mode)
    }

    /// Run this before doing any reopen operations on any queue that belongs to this node.
    fn queue_reopen_prepare(&self) {
        for handle in self.queue_handles.lock().unwrap().iter_mut() {
            handle.did_reopen = false;
        }
    }

    /// Run the given reopen action on all queues.
    /// Holding the lock on `self.queue_handles` across `thread.owned_run()` is:
    /// - Necessary, because we need the `handle` reference to live for the whole lifetime of
    ///   `thread.owned_run()`
    /// - Safe, because the code we run in the other threads (which we are awaiting) will not
    ///   attempt to take the same lock on `self.queue_handles`
    #[allow(clippy::await_holding_lock)]
    async fn queue_reopen_action(&self, action: IoQueueReopenAction) -> BlockResult<()> {
        // let mon = monitor::monitor();
        let mut queue_handles = self.queue_handles.lock().unwrap();
        let mut i = 0;
        while i < queue_handles.len() {
            let handle = &mut queue_handles[i];
            // let queue_alive = match mon.lookup_thread_by_id(handle.inner.thread_id()) {
            //     Ok(thread) => {
            //         thread
            //             .owned_run(|| Box::pin(async move { handle.reopen_action(action) }))
            //             .await?
            //     }
            //
            //     // Failed to find the thread, which means the queue must have been dropped
            //     Err(_) => false,
            // };

            // if queue_alive {
            //     i += 1;
            // } else {
            //     queue_handles.swap_remove(i);
            // }
        }

        Ok(())
    }

    /// Have all queues update their cached limits from the node's `NodeLimits`.
    /// Holding the lock on `self.queue_handles` across `thread.owned_run()` is:
    /// - Necessary, because we need the `handle` reference to live for the whole lifetime of
    ///   `thread.owned_run()`
    /// - Safe, because the code we run in the other threads (which we are awaiting) will not
    ///   attempt to take the same lock on `self.queue_handles`
    #[allow(clippy::await_holding_lock)]
    async fn queue_update_limits(&self) {
        // let mon = monitor::monitor();
        let mut queue_handles = self.queue_handles.lock().unwrap();
        let mut i = 0;
        while i < queue_handles.len() {
            let handle = &mut queue_handles[i];
            // let queue_alive = match mon.lookup_thread_by_id(handle.inner.thread_id()) {
            //     Ok(thread) => {
            //         thread
            //             .owned_run(|| Box::pin(async move { handle.update_limits(self) }))
            //             .await
            //     }
            //
            //     // Failed to find the thread, which means the queue must have been dropped
            //     Err(_) => false,
            // };
            //
            // if queue_alive {
            //     i += 1;
            // } else {
            //     queue_handles.swap_remove(i);
            // }
        }
    }

    async fn reopen_change_graph(
        &self,
        opts: Option<NodeConfig>,
        step: ChangeGraphStep,
    ) -> BlockResult<()> {
        assert!(
            self.in_flight.load(Ordering::Relaxed) == 0
                && self.quiesce_count.load(Ordering::Relaxed) > 0
        );

        if let Some(opts) = opts.as_ref() {
            assert!(opts.node_name == self.name);
        }

        if opts.is_some() {
            self.queue_reopen_prepare();
        }

        let perms = self.get_perms();

        if let Some(opts) = opts {
            debug_assert!(step == ChangeGraphStep::Release);

            let ask_write = perms.has(NodePerm::Write) || perms.has(NodePerm::WriteUnchanged);
            let read_only = opts.read_only.unwrap_or(false)
                || (opts.auto_read_only.unwrap_or(false) && !ask_write);

            if read_only && ask_write {
                return Err(format!("Node \"{}\" is read-only", self.name).into());
            }

            self.driver
                .reopen_change_graph(&opts, perms, read_only, step)
                .await?;

            let old_opts = std::mem::replace(&mut *self.opts.lock().unwrap(), opts);
            let existing = self.pre_reopen_opts.lock().unwrap().replace(old_opts);
            assert!(existing.is_none());
        } else {
            debug_assert!(step == ChangeGraphStep::Acquire);
            // Clone `opts` so we do not have to hold the lock across `await`
            let opts = self.opts.lock().unwrap().clone();

            let ask_write = perms.has(NodePerm::Write) || perms.has(NodePerm::WriteUnchanged);
            let read_only = opts.read_only.unwrap_or(false)
                || (opts.auto_read_only.unwrap_or(false) && !ask_write);

            if read_only && ask_write {
                return Err(format!("Node \"{}\" is read-only", self.name).into());
            }

            self.driver
                .reopen_change_graph(&opts, perms, read_only, step)
                .await?;
        }

        Ok(())
    }

    async fn reopen_do(&self) -> BlockResult<()> {
        assert!(
            self.in_flight.load(Ordering::Relaxed) == 0
                && self.quiesce_count.load(Ordering::Relaxed) > 0
        );

        let opts = self.opts.lock().unwrap().clone();
        let perms = self.get_perms();

        let ask_write = perms.has(NodePerm::Write) || perms.has(NodePerm::WriteUnchanged);
        let read_only =
            opts.read_only.unwrap_or(false) || (opts.auto_read_only.unwrap_or(false) && !ask_write);

        if read_only && ask_write {
            return Err(format!("Node \"{}\" is read-only", self.name).into());
        }

        self.driver.reopen_do(opts, perms, read_only).await?;

        if let Err(err) = self.queue_reopen_action(IoQueueReopenAction::Do).await {
            self.reopen_roll_back().await;
            return Err(err);
        }

        let new_info = match self
            .driver
            .get_basic_info()
            .await
            .and_then(NodeBasicInfo::check_validity)
        {
            Ok(info) => info,
            Err(err) => {
                self.reopen_roll_back().await;
                return Err(err);
            }
        };

        let old_limits = self.limits.clone();
        self.pre_reopen_limits.lock().unwrap().replace(old_limits);

        self.update_limits_from(new_info.limits).await;

        Ok(())
    }

    async fn reopen_clean(&self) {
        self.queue_reopen_action(IoQueueReopenAction::Clean)
            .await
            .unwrap();

        self.driver.reopen_clean_async().await;

        self.pre_reopen_opts.lock().unwrap().take();
        self.pre_reopen_limits.lock().unwrap().take();

        let mut users = self.users.lock().unwrap();
        for user in WeakAutoDeleteIterator::from_vec(&mut users, sync::Weak::upgrade) {
            user.clean_reopen_perms();
        }
    }

    async fn reopen_roll_back(&self) {
        assert!(
            self.in_flight.load(Ordering::Relaxed) == 0
                && self.quiesce_count.load(Ordering::Relaxed) > 0
        );

        if let Some(old_opts) = self.pre_reopen_opts.lock().unwrap().take() {
            *self.opts.lock().unwrap() = old_opts;
        }

        self.queue_reopen_action(IoQueueReopenAction::RollBack)
            .await
            .unwrap();

        self.driver.reopen_roll_back_async().await;

        // May be unset if called from `self.reopen_do()`
        let old_limits = { self.pre_reopen_limits.lock().unwrap().take() };
        if let Some(old_limits) = old_limits {
            self.update_limits_from(old_limits).await;
        }

        let mut users = self.users.lock().unwrap();
        for user in WeakAutoDeleteIterator::from_vec(&mut users, sync::Weak::upgrade) {
            user.roll_back_reopen_perms();
        }
    }

    async fn update_limits_from(&self, new_limits: NodeLimits) {
        self.limits
            .size
            .store(new_limits.size.load(Ordering::Relaxed), Ordering::Relaxed);
        self.limits.request_alignment.store(
            new_limits.request_alignment.load(Ordering::Relaxed),
            Ordering::Relaxed,
        );
        self.limits.memory_alignment.store(
            new_limits.memory_alignment.load(Ordering::Relaxed),
            Ordering::Relaxed,
        );
        self.limits.enforced_memory_alignment.store(
            new_limits.enforced_memory_alignment.load(Ordering::Relaxed),
            Ordering::Relaxed,
        );

        self.queue_update_limits().await;
    }

    pub async fn add_dirty_bitmap(
        &self,
        name: &str,
        granularity: u64,
        enabled: bool,
    ) -> BlockResult<()> {
        let bitmap = DirtyBitmap::new(
            self.limits.size.load(Ordering::Relaxed),
            granularity,
            enabled,
        )?;
        if let hash_map::Entry::Vacant(entry) =
            self.bitmaps.lock().unwrap().entry(String::from(name))
        {
            entry.insert(Arc::new(Mutex::new(bitmap)));
        } else {
            return Err(format!(
                "Bitmap name \"{}\" already in use on node \"{}\"",
                name, self.name
            )
                .into());
        }

        self.update_queues_bitmap_list().await;
        Ok(())
    }

    pub async fn remove_dirty_bitmap(&self, name: &str) -> BlockResult<()> {
        self.bitmaps.lock().unwrap().remove(name).ok_or_else(|| {
            format!(
                "No bitmap with name \"{}\" found on node \"{}\"",
                name, self.name
            )
        })?;

        self.update_queues_bitmap_list().await;
        Ok(())
    }

    /// Keeps locks on `self.bitmaps` and `self.queue_handles` across `.await` points.  That is OK
    /// because the futures we await will not access those fields (i.e. no deadlock possible).
    /// Also, we want all queues to have the exact same list of bitmaps, which makes it desirable
    /// to block concurrent updates to the list of bitmaps while we distribute it to the queues.
    #[allow(clippy::await_holding_lock)]
    async fn update_queues_bitmap_list(&self) {
        let bitmaps = self.bitmaps.lock().unwrap();
        let bitmap_vec: Vec<_> = bitmaps.values().cloned().collect();
        let mut queue_handles = self.queue_handles.lock().unwrap();
        // let mon = monitor::monitor();
        let mut i = 0;

        while i < queue_handles.len() {
            let handle = &mut queue_handles[i];
            // let queue_alive = match mon.lookup_thread_by_id(handle.inner.thread_id()) {
            //     Ok(thread) => {
            //         let bitmap_vec = bitmap_vec.clone();
            //         thread
            //             .owned_run(|| -> BlockFutureResult<_> {
            //                 Box::pin(async move {
            //                     if let Some(inner) = sync::Weak::upgrade(handle.inner.as_mut()) {
            //                         *inner.bitmaps.borrow_mut() = bitmap_vec;
            //                         Ok(true)
            //                     } else {
            //                         Ok(false)
            //                     }
            //                 })
            //             })
            //             .await
            //             .unwrap()
            //     }
            //
            //     // Failed to find the thread, which means the queue must have been dropped
            //     Err(_) => false,
            // };
            //
            // if queue_alive {
            //     i += 1;
            // } else {
            //     queue_handles.swap_remove(i);
            // }
        }
    }

    pub fn get_dirty_bitmap(&self, name: &str) -> BlockResult<Arc<Mutex<DirtyBitmap>>> {
        self.bitmaps
            .lock()
            .unwrap()
            .get(name)
            .cloned()
            .ok_or_else(|| {
                format!(
                    "No bitmap with name \"{}\" found on node \"{}\"",
                    name, self.name
                )
                    .into()
            })
    }

    /// If qemu would consider this node to be a block job filter node, return job info
    pub fn block_job_info(&self) -> Option<JobInfo> {
        self.driver.block_job_info()
    }

    /// Return the node which is to succeed this node (e.g. for job-finalize)
    pub fn get_successor(&self) -> Option<Arc<Node>> {
        self.driver.get_successor()
    }
}

impl std::fmt::Debug for NodeInner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Node")
            .field("name", &self.name)
            .field("quiesce_count", &self.quiesce_count)
            .field("in_flight", &self.in_flight)
            .finish()
    }
}

impl Drop for NodeInner {
    fn drop(&mut self) {
        assert!(self.in_flight.load(Ordering::Relaxed) == 0);
    }
}

impl PollableNode {
    pub fn node(&self) -> &Arc<Node> {
        &self.node
    }

    pub fn poll(&mut self, cx: &mut Context<'_>) -> Poll<BackgroundOpResult> {
        Future::poll(self.future.as_mut(), cx)
    }
}

impl FadingNode {
    // pub fn new(
    //     node: Arc<Node>,
    //     successor: Arc<Node>,
    //     event: Option<qmp::Events>,
    // ) -> Result<Self, (BlockError, Arc<Node>)> {
    //     let node_name = node.name.clone();
    //     Ok(FadingNode {
    //         fut: Box::pin(Self::fade(node, successor, event)),
    //         node_name,
    //     })
    // }

    pub fn node_name(&self) -> &String {
        &self.node_name
    }

    /// Actual function that (1) replaces the node by its successor, (2) waits until all remaining
    /// references to it are dropped, and (3) drains its caches.
    // async fn fade(
    //     node: Arc<Node>,
    //     successor: Arc<Node>,
    //     mut qmp_event: Option<qmp::Events>,
    // ) -> Result<(), (BlockError, Arc<Node>)> {
    //     let mut block_job_info = node.block_job_info();
    //
    //     // This function may miss parents that are added after it has started, but since a
    //     // `FadingNode` is created after the node is removed from the monitor's node list, no new
    //     // parents can be attached anymore.
    //     let reopen_result = match ReopenQueue::replace_node(&node, &successor.name) {
    //         Ok(queue) => queue.reopen().await,
    //         Err(err) => Err(err),
    //     };
    //     if let Some(info) = block_job_info.take() {
    //         info.complete(
    //             reopen_result
    //                 .as_ref()
    //                 .err()
    //                 .map(|err| err.clone().into_description()),
    //         );
    //     }
    //     if let Err(err) = reopen_result {
    //         return Err((err, node));
    //     }
    //
    //     // Node is now replaced by its successor, wait for it to be dropped by all remaining users
    //     let node_inner = SendOnDrop::into_receiver(node).unwrap().await.unwrap();
    //
    //     // And drain it before dropping it
    //     node_inner.drain_caches().await;
    //
    //     if let Some(event) = qmp_event.take() {
    //         broadcast_event(qmp::Event::new(event));
    //     }
    //
    //     Ok(())
    // }

    pub fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), (BlockError, Arc<Node>)>> {
        Future::poll(self.fut.as_mut(), cx)
    }
}

impl Future for QuiesceWaiter<'_> {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            if self.in_flight.load(Ordering::Relaxed) == 0 {
                return Poll::Ready(());
            }

            if self.waiting {
                return Poll::Pending;
            } else {
                self.quiesce_waiters
                    .lock()
                    .unwrap()
                    .push_back(cx.waker().clone());

                self.waiting = true;
            }
        }
    }
}

impl IoQueue {
    pub fn size(&self) -> u64 {
        self.node.limits.size.load(Ordering::Relaxed)
    }

    pub fn request_align(&self) -> usize {
        self.inner.request_alignment.get()
    }

    pub fn mem_align(&self) -> usize {
        self.inner.memory_alignment.get()
    }

    pub fn enforced_mem_align(&self) -> usize {
        self.inner.enforced_memory_alignment.get()
    }

    pub fn node(&self) -> &Arc<Node> {
        &self.node
    }

    pub fn node_user(&self) -> &Arc<NodeUser> {
        &self.node_user
    }

    fn check_request(&self, offset: u64, len: u64, allow_post_eof: bool) -> BlockResult<()> {
        if !allow_post_eof && offset + len > self.size() {
            return Err(BlockError::from_desc(format!(
                "Access [0x{:x}, 0x{:x}) is beyond the end of \"{}\" (size: 0x{:x})",
                offset,
                len,
                self.node.name,
                self.size()
            )));
        }

        Ok(())
    }

    /// Check whether the node is quiesced.
    /// If so, the queue cannot be used at this point.  `self.quiesce_self()` produces a future
    /// that can be awaited to re-run the request when the queue becomes available again.
    /// If it is not quiesced, a reference to the driver data is returned, which is safe to access
    /// until `self.settle_request()` is called (when the request is settled, it is generally
    /// assumed that there are absolutely no references to the queue's driver).
    fn check_quiesced(&self) -> Option<&dyn IoQueueDriverData> {
        if self.quiesce_count.load(Ordering::Acquire) == 0 {
            self.node_in_flight.fetch_add(1, Ordering::Acquire);
            self.queue_in_flight.replace(self.queue_in_flight.get() + 1);

            let driver = self.inner.driver.get();
            // Safe because `self.quiesce_count` is 0, so no mutable operations are going on right
            // now.  `self.node_in_flight` is now greater than 0, so no mutable operations will be
            // started until `Self::settle_request()` is invoked.
            Some(unsafe { &**driver })
        } else {
            None
        }
    }

    fn quiesce_self<'a>(&'a self, req: Request<'a>) -> BlockFutureResult<'a, ()> {
        Box::pin(QuiescedQueueWaiter {
            waiting: false,
            queue: self,
            request: Some(req),
            future: None,
        })
    }

    fn settle_request(&self) {
        self.queue_in_flight.replace(self.queue_in_flight.get() - 1);

        if self.node_in_flight.fetch_sub(1, Ordering::Release) == 1
            && self.quiesce_count.load(Ordering::Acquire) > 0
        {
            let mut waiters = self.node.quiesce_waiters.lock().unwrap();
            while let Some(waker) = waiters.pop_front() {
                waker.wake();
            }
        }
    }

    fn check_iovec_io_alignment(&self, offset: u64, len: u64) -> bool {
        let req_mask = (self.request_align() - 1) as u64;

        offset & req_mask == 0 && len & req_mask == 0
    }

    fn do_read<'a>(
        &'a self,
        buf: IoBufferMut<'a>,
        offset: u64,
        allow_post_eof: bool,
    ) -> BlockFutureResult<'a, ()> {
        self.do_readv(buf.into(), offset, allow_post_eof)
    }

    fn do_readv_inner<'a, 'b>(
        &'a self,
        driver: &'a dyn IoQueueDriverData,
        bufv: IoVectorMut<'a>,
        offset: u64,
        allow_post_eof: bool,
    ) -> BlockResult<BlockFutureResult<'a, ()>>
    where
        'a: 'b,
    {
        self.check_request(offset, bufv.len(), allow_post_eof)?;

        // Always return 0 post-EOF; shield the driver from such requests
        let bufv = if allow_post_eof {
            let req_end = offset + bufv.len();
            let size = self.size();
            if req_end > size {
                let head_len = bufv.len() - (req_end - size);
                let (head, mut tail) = bufv.split_at(head_len);
                tail.fill(0);
                head
            } else {
                bufv
            }
        } else {
            bufv
        };

        let enforced_mem_align = self.enforced_mem_align();
        let req_align = self.request_align();
        if self.check_iovec_io_alignment(offset, bufv.len())
            && bufv.is_aligned(enforced_mem_align, req_align)
        {
            let fut = driver.readv(bufv, offset);
            Ok(Box::pin(async move {
                let result = fut.await;
                self.settle_request();
                result
            }))
        } else {
            let req_align = req_align as u64;
            let unpadded_end = offset + bufv.len();
            let padded_offset = offset & !(req_align - 1);
            let padded_end = (unpadded_end + req_align - 1) & !(req_align - 1);

            let mem_align = self.mem_align();

            let pad_head_len = (offset - padded_offset) as usize;
            let mut head_buf = (pad_head_len > 0)
                .then(|| IoBuffer::new(pad_head_len, mem_align))
                .transpose()?;

            let pad_tail_len = (padded_end - unpadded_end) as usize;
            let mut tail_buf = (pad_tail_len > 0)
                .then(|| IoBuffer::new(pad_tail_len, mem_align))
                .transpose()?;

            Ok(Box::pin(async move {
                let bufv = if let Some(head_buf) = head_buf.as_mut() {
                    bufv.with_inserted(0, head_buf.as_mut().into_slice())
                } else {
                    bufv
                };

                let bufv = if let Some(tail_buf) = tail_buf.as_mut() {
                    bufv.with_pushed(tail_buf.as_mut().into_slice())
                } else {
                    bufv
                };

                let mut bounce = super::helpers::IoVectorBounceBuffers::default();
                let bufv = bufv.enforce_alignment_for_read(
                    self.enforced_mem_align(),
                    self.request_align(),
                    &mut bounce,
                )?;
                // There is no await before this, so in theory we could create the Future outside
                // of this async block (compare commit e52d10612a).  In practice, that gives
                // ownership problems with `head_buf`, `tail_buf`, and `bounce`, which would need
                // to live at least as long as the future, which is difficult to do strictly.
                // Note specifically that the compiler will consider the `async move` block to
                // move them, so you cannot create the future depending on those objects before
                // `async move` and await it in the block, when those objects are moved into the
                // block.  Maybe something can be done with `Pin`, which should be able to solve
                // that movement problem.
                // Re-aligning breaks performance anyway, so accept this as-is for now.
                let result = driver.readv(bufv, padded_offset).await;
                self.settle_request();
                result
            }))
        }
    }

    fn do_readv<'a>(
        &'a self,
        bufv: IoVectorMut<'a>,
        offset: u64,
        allow_post_eof: bool,
    ) -> BlockFutureResult<'a, ()> {
        let driver = match self.check_quiesced() {
            Some(driver) => driver,
            None => {
                return self.quiesce_self(Request::Readv {
                    bufv,
                    offset,
                    allow_post_eof,
                });
            }
        };

        match self.do_readv_inner(driver, bufv, offset, allow_post_eof) {
            // Request will be settled in the returned future
            Ok(fut) => fut,
            Err(err) => {
                self.settle_request();
                Box::pin(async move { Err(err) })
            }
        }
    }

    pub fn read<'a>(&'a self, buf: IoBufferMut<'a>, offset: u64) -> BlockFutureResult<'a, ()> {
        self.do_read(buf, offset, false)
    }

    pub fn readv<'a>(&'a self, bufv: IoVectorMut<'a>, offset: u64) -> BlockFutureResult<'a, ()> {
        self.do_readv(bufv, offset, false)
    }

    /// Searches the list for writes intersecting the given range, creates a waiter (oneshot
    /// channel) for each of them, and returns an iterator over the awaitable (receiving) end
    fn await_intersecting_in_write_list<
        'a,
        G: std::ops::Deref<Target = Vec<Arc<InFlightWrite>>>,
    >(
        &'a self,
        writes: &'a G,
        range: &'a std::ops::Range<u64>,
    ) -> impl Iterator<Item = oneshot::Receiver<()>> + 'a {
        writes.iter().filter(|w| w.range.overlaps(range)).map(|w| {
            let (s, r) = oneshot::channel();
            w.waiters.lock().unwrap().push(s);
            r
        })
    }

    /// Serialize intersecting blocking writes; if `serialize` is true, block all other
    /// intersecting writes until the returned object is dropped.
    /// The returned `InFlightWriteBlocker` needs to be awaited (`await_intersecting()`) before
    /// submitting this write to await all intersecting writes, unless `must_await()` returns
    /// `false`.
    ///
    /// It would be much simpler to just have this be an `async` function that already awaits
    /// intersecting writes, but doing it this way allows us to potentially invoke `driver.write()`
    /// in the synchronous path, outside of any `async` block (when there are no intersecting
    /// writes).  This then allows request batching, because requests can thus be enqueued by the
    /// driver before they are polled for the first time (polling requires submission to the
    /// kernel).
    fn serialize_intersecting_writes(
        &self,
        range: std::ops::Range<u64>,
        serialize: bool,
    ) -> InFlightWriteBlocker<impl Future<Output = ()>> {
        let write = Arc::new(InFlightWrite {
            range: range.clone(),
            waiters: Mutex::new(Vec::new()),
            index: AtomicUsize::new(0),
        });

        let intersecting_blockers = {
            let mut intersecting = Vec::<oneshot::Receiver<()>>::new();

            // We must lock `serializing_writes` and `nonserializing_writes` in the same order to
            // prevent deadlocks.
            // Also, one of the locks must be kept throughout the entire branch to fully serialize
            // the two branches between requests of different kinds.  Otherwise, this can happen
            // (consider one serializing request S, which intersects with a non-serializing request
            // NS):
            // - Request S looks into the NS list, finds nothing, drops the NS lock.  Request NS
            //   (in any order) looks into the S list, finds nothing, and enters itself into the NS
            //   list.  Request S enters itself into the S list.  NS and S are submitted
            //   concurrently, which is not allowed.
            // - Request S enters itself into the S list, drops the S lock.  Request NS (in any
            //   order) looks into the S list, notes to await request S, then enters itself into
            //   the NS list.  Request S looks into the NS list, notes to await NS.  S and NS will
            //   await each other, resulting in a deadlock.
            //
            // By locking `serializing_writes` first in each branch and keeping the lock
            // throughout, we can prevent these problems.  We choose to lock `serializing_writes`
            // (over `nonserializing_writes`) because this keeps the write-lock section in the
            // common branch (non-serializing write) minimal.

            if serialize {
                let mut serializing_writes = self.node.serializing_writes.write().unwrap();
                // Serializing requests must await all other requests
                intersecting
                    .extend(self.await_intersecting_in_write_list(&serializing_writes, &range));

                write
                    .index
                    .store(serializing_writes.len(), Ordering::Relaxed);
                serializing_writes.push(Arc::clone(&write));

                let nonserializing_writes = self.node.nonserializing_writes.read().unwrap();
                // Serializing requests must await all other requests
                intersecting
                    .extend(self.await_intersecting_in_write_list(&nonserializing_writes, &range));
            } else {
                let serializing_writes = self.node.serializing_writes.read().unwrap();
                // Non-serializing requests must await serializing requests
                intersecting
                    .extend(self.await_intersecting_in_write_list(&serializing_writes, &range));

                let mut nonserializing_writes = self.node.nonserializing_writes.write().unwrap();
                // Non-serializing requests need not await other non-serializing requests

                write
                    .index
                    .store(nonserializing_writes.len(), Ordering::Relaxed);
                nonserializing_writes.push(Arc::clone(&write));
            }

            // Not sure if `async move {}` is really zero-cost -- on the other hand,
            // `!intersecting.is_empty()` should be rare, so the potential overhead of evaluating
            // the closure is negligible
            #[allow(clippy::unnecessary_lazy_evaluations)]
            (!intersecting.is_empty()).then(|| async move {
                // Wait on all preceding writes, but not on any that are entered into the list
                // after we have entered this request here.  All of those succeeding requests must
                // be waiting on this one here.
                for i in intersecting {
                    let _: Result<(), _> = i.await;
                }
            })
        };

        InFlightWriteBlocker {
            node: Arc::clone(&self.node),
            handle: Some(write),
            serializing: serialize,
            intersecting_blockers,
        }
    }

    fn do_write<'a>(
        &'a self,
        buf: IoBufferRef<'a>,
        offset: u64,
        allow_grow: bool,
    ) -> BlockFutureResult<'a, ()> {
        self.do_writev(buf.into(), offset, allow_grow)
    }

    fn do_writev_inner<'a>(
        &'a self,
        driver: &'a dyn IoQueueDriverData,
        bufv: IoVector<'a>,
        offset: u64,
        allow_grow: bool,
    ) -> BlockResult<BlockFutureResult<'a, ()>> {
        debug_assert!(
            self.node_user.permissions.has(NodePerm::Write)
                && (!allow_grow || self.node_user.permissions.has(NodePerm::Resize))
        );

        self.check_request(offset, bufv.len(), allow_grow)?;
        self.mark_dirty(offset, bufv.len());

        let enforced_mem_align = self.enforced_mem_align();
        let req_align = self.request_align();
        if self.check_iovec_io_alignment(offset, bufv.len())
            && bufv.is_aligned(enforced_mem_align, req_align)
        {
            let end = offset + bufv.len();
            let mut serializing_blocker = self.serialize_intersecting_writes(offset..end, false);

            // This combined object helps the compiler see that we only use `bufv` in the `async`
            // block if it has not been moved into the future already
            enum FutOrBufv<'a> {
                Fut(BlockFutureResult<'a, ()>),
                Bufv(IoVector<'a>),
            }

            let fut_or_bufv = if serializing_blocker.must_await() {
                FutOrBufv::Bufv(bufv)
            } else {
                FutOrBufv::Fut(driver.writev(bufv, offset))
            };

            Ok(Box::pin(async move {
                let result = match fut_or_bufv {
                    FutOrBufv::Fut(fut) => fut.await,
                    FutOrBufv::Bufv(bufv) => {
                        serializing_blocker.await_intersecting().await;
                        driver.writev(bufv, offset).await
                    }
                };

                if allow_grow && result.is_ok() {
                    self.node.limits.size.fetch_max(end, Ordering::Relaxed);
                }
                self.settle_request();
                result
            }))
        } else {
            let req_align_mask = !((req_align - 1) as u64);
            let unpadded_end = offset + bufv.len();
            let padded_offset = offset & req_align_mask;
            let padded_end = (unpadded_end + req_align as u64 - 1) & req_align_mask;

            let mem_align = self.mem_align();

            let pad_head_len = (offset - padded_offset) as usize;
            debug_assert!(pad_head_len < req_align);
            let mut head_buf = (pad_head_len > 0)
                .then(|| IoBuffer::new(req_align, mem_align))
                .transpose()?;

            let pad_tail_len = (padded_end - unpadded_end) as usize;
            debug_assert!(pad_tail_len < req_align);
            let mut tail_buf = (pad_tail_len > 0)
                .then(|| IoBuffer::new(req_align, mem_align))
                .transpose()?;

            Ok(Box::pin(async move {
                {
                    let mut serializing_blocker =
                        self.serialize_intersecting_writes(padded_offset..padded_end, true);

                    serializing_blocker.await_intersecting().await;

                    let head_fut = head_buf
                        .as_mut()
                        .map(|head_ref| self.do_read(head_ref.as_mut(), padded_offset, true))
                        .unwrap_or_else(|| Box::pin(async { Ok(()) }));

                    let tail_fut = tail_buf
                        .as_mut()
                        .map(|tail_ref| {
                            self.do_read(tail_ref.as_mut(), padded_end - req_align as u64, true)
                        })
                        .unwrap_or_else(|| Box::pin(async { Ok(()) }));

                    let (head, tail) = futures::join!(head_fut, tail_fut);
                    head.or(tail)?;
                }

                let bufv = if let Some(head_buf) = head_buf.as_ref() {
                    let slice: &[u8] = head_buf.as_ref().into_slice();
                    bufv.with_inserted(0, &slice[0..pad_head_len])
                } else {
                    bufv
                };

                let bufv = if let Some(tail_buf) = tail_buf.as_ref() {
                    let slice: &[u8] = tail_buf.as_ref().into_slice();
                    bufv.with_pushed(&slice[(req_align - pad_tail_len)..req_align])
                } else {
                    bufv
                };

                let mut bounce = super::helpers::IoVectorBounceBuffers::default();
                let bufv = bufv.enforce_alignment_for_write(
                    self.enforced_mem_align(),
                    self.request_align(),
                    &mut bounce,
                )?;
                let result = driver.writev(bufv, padded_offset).await;
                if allow_grow && result.is_ok() {
                    self.node
                        .limits
                        .size
                        .fetch_max(padded_end, Ordering::Relaxed);
                }
                self.settle_request();
                result
            }))
        }
    }

    fn do_writev<'a>(
        &'a self,
        bufv: IoVector<'a>,
        offset: u64,
        allow_grow: bool,
    ) -> BlockFutureResult<'a, ()> {
        let driver = match self.check_quiesced() {
            Some(driver) => driver,
            None => {
                return self.quiesce_self(Request::Writev {
                    bufv,
                    offset,
                    allow_grow,
                })
            }
        };

        match self.do_writev_inner(driver, bufv, offset, allow_grow) {
            // Request will be settled in the returned future
            Ok(fut) => fut,
            Err(err) => {
                self.settle_request();
                Box::pin(async move { Err(err) })
            }
        }
    }

    pub fn write<'a>(&'a self, buf: IoBufferRef<'a>, offset: u64) -> BlockFutureResult<'a, ()> {
        self.do_write(buf, offset, false)
    }

    pub fn grow_write<'a>(
        &'a self,
        buf: IoBufferRef<'a>,
        offset: u64,
    ) -> BlockFutureResult<'a, ()> {
        self.do_write(buf, offset, true)
    }

    pub fn writev<'a>(&'a self, bufv: IoVector<'a>, offset: u64) -> BlockFutureResult<'a, ()> {
        self.do_writev(bufv, offset, false)
    }

    pub fn grow_writev<'a>(&'a self, bufv: IoVector<'a>, offset: u64) -> BlockFutureResult<'a, ()> {
        self.do_writev(bufv, offset, true)
    }

    pub fn flush(&self) -> BlockFutureResult<'_, ()> {
        let driver = match self.check_quiesced() {
            Some(driver) => driver,
            None => return self.quiesce_self(Request::Flush),
        };

        let fut = driver.flush();

        Box::pin(async move {
            let result = fut.await;
            self.settle_request();
            result
        })
    }

    fn mark_dirty(&self, offset: u64, length: u64) {
        let bitmaps = self.inner.bitmaps.borrow();

        for bitmap in bitmaps.iter() {
            bitmap.lock().unwrap().dirty(offset, length);
        }
    }
}

impl Drop for IoQueue {
    fn drop(&mut self) {
        // Dropping the queue means cancelling all requests, so reduce the node's in-flight count
        // accordingly
        self.node_in_flight
            .fetch_sub(self.queue_in_flight.get(), Ordering::Relaxed);
        self.queue_in_flight.replace(0);
    }
}

impl<'a> Future for QuiescedQueueWaiter<'a> {
    type Output = BlockResult<()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if let Some(fut) = self.future.as_mut() {
            return Future::poll(fut.as_mut(), cx);
        }

        loop {
            if self.queue.quiesce_count.load(Ordering::Acquire) == 0 {
                let fut = match self.request.take().unwrap() {
                    Request::Readv {
                        bufv,
                        offset,
                        allow_post_eof,
                    } => self.queue.do_readv(bufv, offset, allow_post_eof),
                    Request::Writev {
                        bufv,
                        offset,
                        allow_grow,
                    } => self.queue.do_writev(bufv, offset, allow_grow),
                    Request::Flush => self.queue.flush(),
                };
                self.future.replace(fut);

                return Future::poll(self.future.as_mut().unwrap().as_mut(), cx);
            }

            if self.waiting {
                return Poll::Pending;
            } else {
                self.queue
                    .node
                    .quiesced_queues
                    .lock()
                    .unwrap()
                    .push_back(cx.waker().clone());

                self.waiting = true;
            }
        }
    }
}

impl IoQueueHandle {
    /// Issue an `IoQueueReopenAction` on the corresponding `IoQueue`.
    /// *Must* be run in the `IoQueue`'s thread (or will panic).
    /// Return whether the queue is still alive.  If not, this handle should be dropped from the
    /// list of handles.
    fn reopen_action(&mut self, action: IoQueueReopenAction) -> BlockResult<bool> {
        let driver = match sync::Weak::upgrade(self.inner.as_mut()) {
            Some(inner) => inner.driver.get(),
            None => return Ok(false),
        };

        // Safe because we (and our callers) block waiting for this to settle, while no requests
        // are in flight.  (We have checked `in_flight` to be 0, and we have set `quiesce_count` to
        // announce that mutable operations can occur.)
        let driver = unsafe { &mut *driver };

        match action {
            IoQueueReopenAction::Do => {
                driver.reopen_do()?;
                self.did_reopen = true;
            }

            IoQueueReopenAction::Clean => {
                // If the queue was created during the reopen transaction (i.e. by a higher-level
                // node after this node here was already fully reopened), it will not have received
                // the `Do` action, but it will already be in post-reopen state, which is correct.
                // It will not have any pre-reopen state (because it was not present before the
                // reopen), so there is nothing to clean up either.
                if self.did_reopen {
                    driver.reopen_clean();
                }
            }

            IoQueueReopenAction::RollBack => {
                // Two possibilities:
                // 1. Queue was created during reopen (like explained above in `Clean`).  It will
                //    be dropped on roll-back (by the higher level node), so not rolling back
                //    anything here is fine.
                // 2. Queue existed before reopen, but `reopen_do()` was not invoked because
                //    something else during the reopen process failed.  The queue is still in
                //    pre-reopen state, so there is nothing to roll back.
                if self.did_reopen {
                    driver.reopen_roll_back();
                }
            }
        }

        Ok(true)
    }

    fn update_limits(&mut self, from: &NodeInner) -> bool {
        let inner = match sync::Weak::upgrade(self.inner.as_mut()) {
            Some(inner) => inner,
            None => return false,
        };

        inner.request_alignment.set(from.request_align());
        inner.memory_alignment.set(from.mem_align());
        inner
            .enforced_memory_alignment
            .set(from.enforced_mem_align());

        true
    }
}

impl Clone for NodeLimits {
    fn clone(&self) -> Self {
        NodeLimits {
            size: self.size.load(Ordering::Relaxed).into(),
            request_alignment: self.request_alignment.load(Ordering::Relaxed).into(),
            memory_alignment: self.memory_alignment.load(Ordering::Relaxed).into(),
            enforced_memory_alignment: self
                .enforced_memory_alignment
                .load(Ordering::Relaxed)
                .into(),
        }
    }
}

impl NodeConfigOrReference {
    /// If the object is a reference (by string), keep it.  If it is a configuration structure,
    /// split it off as a new `NodeConfig` object, and replace it by a string reference.
    /// To be called by a driver's `NodeDriverConfig` variant's `.split_tree()` implementation.
    pub fn split_tree(&mut self, vec: &mut Vec<NodeConfig>) -> BlockResult<()> {
        match self {
            NodeConfigOrReference::Reference(_) => Ok(()),
            NodeConfigOrReference::Config(conf) => {
                let conf: serde_json::Value = std::mem::take(conf).into();
                let conf = NodeConfig::deserialize(conf)?;
                let name = conf.node_name.clone();
                *self = NodeConfigOrReference::Reference(name);
                conf.split_tree(vec)
            }
        }
    }

    pub fn lookup(&self) -> BlockResult<Arc<Node>> {
        // let mon = monitor::monitor();
        // match self {
        //     NodeConfigOrReference::Reference(name) => mon.lookup_node(name),
        //     NodeConfigOrReference::Config(_) => unreachable!(),
        // }

        Err(BlockError::from("lookup not implemented"))
    }
}

impl ReopenQueue {
    pub fn new() -> Self {
        ReopenQueue {
            params: HashMap::new(),
            pre_reopen_order: Vec::new(),
            post_reopen_order: Vec::new(),
        }
    }

    /// Create a queue that will replace `to_replace` by `replace_by` (i.e. reopen all parents of
    /// `to_replace` to point to `replace_by` where they currently point to `to_replace`).  Note
    /// that any new parents added once this function is invoked may not be affected.
    pub fn replace_node(to_replace: &Node, replace_by: &str) -> BlockResult<Self> {
        let mut queue = Self::new();
        // let mon = monitor::monitor();

        // Iterate only once, which may miss parents added after this point.  That's the caveat
        // noted in the doc comment.
        let users = to_replace.users.lock().unwrap().clone();
        for user in users {
            if let Some(user) = sync::Weak::upgrade(&user) {
                if user.parent.node_name == replace_by {
                    // `replace_by` may be a parent of `to_replace`, and then it should stay so
                    // (generally when we want to insert it between `to_replace` and its parents).
                    // Not skipping it would also mean creating a loop (`replace_by` pointing to
                    // itself), which must not happen.
                    continue;
                }

                // Need to set parent.opts.{child_name} to the successor’s node name,
                // but we can only do that by going through JSON

                // let parent = mon.lookup_node(&user.parent.node_name)?;
                // let parent_opts = parent.opts.lock().unwrap().clone();
                // let mut parent_opts_json = match serde_json::to_value(parent_opts).unwrap() {
                //     serde_json::Value::Object(obj) => obj,
                //     _ => {
                //         return Err(
                //             format!("Node \"{}\"'s options are not an object", parent.name).into(),
                //         )
                //     }
                // };
                // let existing = parent_opts_json.insert(
                //     user.parent.child_name.clone(),
                //     serde_json::Value::String(String::from(replace_by)),
                // );
                // Nodes can only be moved via reopen in the main thread, this function
                // is a synchronous function in the main thread, so concurrent reopen
                // is impossible
                // assert!(existing.unwrap() == to_replace.name);
                // let parent_opts =
                //     serde_json::from_value(serde_json::Value::Object(parent_opts_json)).unwrap();
                // if let Err(err) = queue.push(parent, parent_opts) {
                //     return Err(
                //         format!(
                //             "Cannot reopen parent \"{}\" to have \"{}\" fade out and be replaced by \"{}\": {}",
                //             user.parent.node_name,
                //             to_replace.name,
                //             replace_by,
                //             err
                //         ).into()
                //     );
                // }
            }
        }

        Ok(queue)
    }

    pub fn push(&mut self, node: Arc<Node>, opts: NodeConfig) -> BlockResult<()> {
        assert!(self.pre_reopen_order.is_empty());
        assert!(self.post_reopen_order.is_empty());

        let params = ReopenParams {
            opts: Some(opts),
            node,
            begun_reopen: false,
            quiesced: false,
        };

        let existing = self.params.insert(params.node.id(), params);
        if let Some(existing) = existing {
            let name = existing.opts.unwrap().node_name;
            return Err(format!("Node \"{}\" specified twice", name).into());
        }

        Ok(())
    }

    /// Get a reference to a `NodeConfig` already present in the queue for the given node, or
    /// insert the one given if none is present so far, and then returns a reference to the
    /// now-inserted configuration.
    pub fn get_mut_or_push(
        &mut self,
        node: Arc<Node>,
        opts: NodeConfig,
    ) -> BlockResult<&mut NodeConfig> {
        assert!(self.pre_reopen_order.is_empty());
        assert!(self.post_reopen_order.is_empty());

        let node_id = node.id();

        if !self.params.contains_key(&node_id) {
            self.push(node, opts)?;
        }

        Ok(self
            .params
            .get_mut(&node_id)
            .unwrap()
            .opts
            .as_mut()
            .unwrap())
    }

    /// Ensure that the reopen queue contains a complete graph by inserting all recursive children
    /// of all elements in the queue (reopening with their current options).  This is important so
    /// that permission changes are propagated across all potentially affected nodes.
    fn fill(&mut self) -> BlockResult<()> {
        let mut queue: Vec<NodeId> = self.params.keys().copied().collect();

        while let Some(id) = queue.pop() {
            let p = self.params.get(&id).unwrap();
            let mut children = p.node.get_children();
            let mut new_children = p.node.get_children_after_reopen(p.opts.as_ref().unwrap())?;
            children.append(&mut new_children);

            for child in children {
                if let hash_map::Entry::Vacant(entry) = self.params.entry(child.id()) {
                    entry.insert(ReopenParams {
                        opts: Some(child.opts.lock().unwrap().clone()),
                        node: Arc::clone(&child),
                        begun_reopen: false,
                        quiesced: false,
                    });
                    queue.push(child.id());
                }
            }
        }

        Ok(())
    }

    /// Topologically sort the given vector of nodes, returning them sorted from bottom to top.
    /// `has_any_as_child(node, hash_set)` must return whether any of the nodes in `hash_set` is a
    /// child of `node`.
    /// The caller must have ensure there are no cycles before invoking this function.
    /// `queue` must be complete, i.e. for any given node in it, all children (as per
    /// `has_any_as_child()`) must be present in it, too.
    fn sort_by<F: Fn(&Arc<Node>, &HashSet<NodeId>) -> BlockResult<bool>>(
        mut queue: Vec<Arc<Node>>,
        has_any_as_child: F,
    ) -> BlockResult<Vec<NodeId>> {
        let mut new_queue: Vec<NodeId> = Vec::with_capacity(queue.len());
        let mut set: HashSet<NodeId> = queue.iter().map(|n| n.id()).collect();

        // We have a graph: `queue` are the nodes, `has_any_as_child` implicitly defines edges.
        // To sort topologically, we need to repeatedly pull out the leaf nodes.  To do this, we
        // iterate over the nodes, and pull out those that have no outgoing edges
        // (`has_any_as_child() == false` when given all remaining nodes), until the list of nodes
        // is empty.
        while !queue.is_empty() {
            let mut i = 0;
            while i < queue.len() {
                if !has_any_as_child(&queue[i], &set)? {
                    let element = queue.swap_remove(i);
                    set.remove(&element.id());
                    new_queue.push(element.id());
                } else {
                    i += 1;
                }
            }
        }

        Ok(new_queue)
    }

    /// Topologically sort the reopen queue from bottom to top, both in the pre-reopen and the
    /// post-reopen order.
    fn sort(&mut self) -> BlockResult<()> {
        assert!(self.pre_reopen_order.is_empty());
        assert!(self.post_reopen_order.is_empty());

        let queue: Vec<Arc<Node>> = self.params.values().map(|v| Arc::clone(&v.node)).collect();

        // Check for loops first
        for node in &queue {
            let mut node_set = HashSet::new();
            node_set.insert(node.id());

            if node.has_any_in_exclusive_subtree_after_reopen(&node_set, &self.params)? {
                return Err(
                    format!("This reopen would create a cycle through \"{}\"", node.name).into(),
                );
            }
        }

        self.pre_reopen_order = Self::sort_by(queue.clone(), |node: &Arc<Node>, other| {
            Ok(node.has_any_as_child(other))
        })?;

        self.post_reopen_order = Self::sort_by(queue, |node: &Arc<Node>, other| {
            node.has_any_as_child_after_reopen(other, &self.params)
        })?;

        Ok(())
    }

    /// Try to reopen all nodes in the queue.  On error, the reopen is automatically rolled back.
    pub async fn reopen(mut self) -> BlockResult<()> {
        self.fill()?;
        self.sort()?;

        let result = self.reopen_do().await;
        if result.is_err() {
            self.roll_back().await;
        } else {
            self.clean().await;
        }
        result
    }

    /// Try to reopen all nodes in the queue.  On error, the caller must invoke
    /// `blockdev_reopen_roll_back()`, on success `blockdev_reopen_clean()`.
    async fn reopen_do(&mut self) -> BlockResult<()> {
        // Quiesce from top to bottom in pre-reopen order
        for node_id in self.pre_reopen_order.iter().rev() {
            let element = self.params.get_mut(node_id).unwrap();
            element.node.quiesce().await;
            element.quiesced = true;
        }

        // Change the graph and permissions from top to bottom: Permission changes are announced
        // via the `*_in_reopen_change_graph()` functions, which only announce them, but require
        // this reopen process to actually carry them out (i.e. run them by the affected child
        // node).  Because this always affects child nodes, we need this to go from top to bottom.

        // First, release permissions in pre-reopen order: Permissions are released on nodes that
        // are currently child nodes, but might not be after the reopen.  We need to go from
        // parents to children, so we need to use the pre-reopen order.
        for node_id in self.pre_reopen_order.iter().rev() {
            let element = self.params.get_mut(node_id).unwrap();
            element
                .node
                .reopen_change_graph(Some(element.opts.take().unwrap()), ChangeGraphStep::Release)
                .await
                .map_err(|err| err.prepend(&format!("Reopening node \"{}\"", element.node.name)))?;
            element.begun_reopen = true;
        }

        // Second, acquire permissions in post-reopen order: Permissions are acquired on nodes that
        // will be child nodes after the reopen, but might not have been before.  We need to go
        // from parents to children, so we need to use the post-reopen order.
        for node_id in self.post_reopen_order.iter().rev() {
            let element = self.params.get(node_id).unwrap();
            element
                .node
                .reopen_change_graph(None, ChangeGraphStep::Acquire)
                .await
                .map_err(|err| err.prepend(&format!("Reopening node \"{}\"", element.node.name)))?;
        }

        // Reopen from bottom to top in post-reopen order: When invoking `reopen_do()`, nodes
        // expect their subgraph to already be in the post-reopen state.  Therefore, we need to run
        // this in post-reopen order.
        for node_id in self.post_reopen_order.iter() {
            let element = self.params.get_mut(node_id).unwrap();
            element
                .node
                .reopen_do()
                .await
                .map_err(|err| err.prepend(&format!("Reopening node \"{}\"", element.node.name)))?;
            element.node.unquiesce();
            element.quiesced = false;
        }

        Ok(())
    }

    /// Clean up reopen state after a successful reopen
    async fn clean(self) {
        // Cleaning up from bottom to top in post-reopen order: The order probably does not really
        // matter, but using the same order as `reopen_do()` seems most natural.
        for node_id in self.post_reopen_order.iter() {
            let element = self.params.get(node_id).unwrap();
            assert!(element.begun_reopen && !element.quiesced);
            element.node.reopen_clean().await;
        }
    }

    /// Roll back already reopened nodes after a failed reopen
    async fn roll_back(mut self) {
        // All nodes that have already been reopened need to be re-quiesced so we can roll them
        // back.  We do this top to bottom in post-reopen order, because that is the order in which
        // the nodes we quiesce here are.
        for node_id in self.post_reopen_order.iter().rev() {
            let element = self.params.get_mut(node_id).unwrap();
            if !element.quiesced {
                element.node.quiesce().await;
                element.quiesced = true;
            }
        }

        // Roll back from bottom to top in pre-reopen order: Rolling back is basically an
        // infallible variant of `reopen_do()` to the pre-reopen state, consequentially, we should
        // apply the same measure and use the post-roll-back order, which is the pre-reopen order.
        for node_id in self.pre_reopen_order.iter() {
            let element = self.params.get_mut(node_id).unwrap();
            assert!(element.quiesced);
            if element.begun_reopen {
                element.node.reopen_roll_back().await;
            }
            element.node.unquiesce();
            element.quiesced = false;
        }
    }
}

impl NodeUser {
    pub fn builder(parent_node_name: &str, child_name: &str) -> NodeUserBuilder {
        let parent = NodeParent {
            node_name: String::from(parent_node_name),
            child_name: String::from(child_name),
        };

        NodeUserBuilder {
            parent,
            permissions: Default::default(),
        }
    }

    pub fn parent_name(&self) -> &String {
        &self.parent.node_name
    }
}

impl NodePerms {
    pub fn is_empty(&self) -> bool {
        self.0 == 0
    }

    pub fn overlap_with(&self, perms: impl Into<NodePerms>) -> NodePerms {
        NodePerms(self.0 & perms.into().0)
    }

    pub fn add(&mut self, perms: impl Into<NodePerms>) {
        self.0 |= perms.into().0
    }

    pub fn remove(&mut self, perms: impl Into<NodePerms>) {
        self.0 &= !perms.into().0
    }
}

impl NodePermPair {
    pub fn has(&self, perm: NodePerm) -> bool {
        self.taken.0 & (perm as u64) != 0
    }

    pub fn has_any(&self) -> bool {
        self.taken.0 != 0
    }

    pub fn blocks(&self, perm: NodePerm) -> bool {
        self.blocked.0 & (perm as u64) != 0
    }
}

impl IntMutNodePermPair {
    pub fn set(&self, other: impl Into<NodePermPair>) {
        let other = other.into();
        self.taken.0.store(other.taken.0, Ordering::Relaxed);
        self.blocked.0.store(other.blocked.0, Ordering::Relaxed);
    }

    pub fn has(&self, perm: NodePerm) -> bool {
        self.taken.0.load(Ordering::Relaxed) & (perm as u64) != 0
    }
}

impl From<NodePerms> for IntMutNodePerms {
    fn from(perms: NodePerms) -> Self {
        IntMutNodePerms(AtomicU64::new(perms.0))
    }
}

impl From<NodePermPair> for IntMutNodePermPair {
    fn from(perms: NodePermPair) -> Self {
        IntMutNodePermPair {
            taken: perms.taken.into(),
            blocked: perms.blocked.into(),
        }
    }
}

impl From<NodePerm> for NodePerms {
    fn from(perm: NodePerm) -> Self {
        NodePerms(perm as u64)
    }
}

impl From<&IntMutNodePerms> for NodePerms {
    fn from(perm: &IntMutNodePerms) -> Self {
        NodePerms(perm.0.load(Ordering::Relaxed))
    }
}

impl From<&IntMutNodePermPair> for NodePermPair {
    fn from(pair: &IntMutNodePermPair) -> Self {
        NodePermPair {
            taken: (&pair.taken).into(),
            blocked: (&pair.blocked).into(),
        }
    }
}

impl NodeUserBuilder {
    pub fn require(mut self, permissions: impl Into<NodePerms>) -> Self {
        self.permissions.taken.add(permissions);
        self
    }

    pub fn block(mut self, permissions: impl Into<NodePerms>) -> Self {
        self.permissions.blocked.add(permissions);
        self
    }

    pub fn unrequire(mut self, permissions: impl Into<NodePerms>) -> Self {
        self.permissions.taken.remove(permissions);
        self
    }

    pub fn set_perms(mut self, permissions: impl Into<NodePermPair>) -> Self {
        self.permissions = permissions.into();
        self
    }
}

impl From<&NodeUser> for NodeUserBuilder {
    fn from(user: &NodeUser) -> Self {
        NodeUserBuilder {
            parent: user.parent.clone(),
            permissions: user.permissions.as_ref().into(),
        }
    }
}

impl NodeUser {
    pub fn node(&self) -> &Arc<Node> {
        &self.node
    }

    pub fn new_queue(self: &Arc<Self>) -> BlockResult<IoQueue> {
        let queue_driver = UnsafeCell::new(self.node.driver.new_queue()?);

        // clippy reports that since `IoQueueMut` is neither `Send` nor `Sync`, we should be using
        // `Rc` instead of `Arc`.  However, that does not work: Through `IoQueueHandle`, we want to
        // be able to send `ThreadBound::new(downgrade(&inner))` to other threads.  For this,
        // whatever type is returned by `downgrade()` must be droppable from any thread (as
        // indicated by the `SendDrop` trait).  This is not true for `rc::Weak` (`sync::Weak`'s
        // `SendDrop` documentation explains why), and therefore we must use `Arc` instead of `Rc`
        // here.
        #[allow(clippy::arc_with_non_send_sync)]
        let inner = Arc::new(IoQueueMut {
            driver: queue_driver,
            bitmaps: Default::default(),
            request_alignment: Cell::new(self.node.request_align()),
            memory_alignment: Cell::new(self.node.mem_align()),
            enforced_memory_alignment: Cell::new(self.node.enforced_mem_align()),
        });

        let queue = IoQueue {
            node: Arc::clone(&self.node),
            node_user: Arc::clone(self),
            inner,
            quiesce_count: Arc::clone(&self.node.quiesce_count),
            node_in_flight: Arc::clone(&self.node.in_flight),
            queue_in_flight: Cell::new(0),
        };

        let queue_handle = IoQueueHandle {
            inner: ThreadBound::new(Arc::downgrade(&queue.inner)),
            did_reopen: false,
        };

        self.node.queue_handles.lock().unwrap().push(queue_handle);

        Ok(queue)
    }

    /// Change this `NodeUser`'s permissions.  Must only be called from a
    /// `NodeDriverData::reopen_change_graph()` implementation, because it does not communicate the
    /// permission changes to the node.  The subsequent reopen process is expected to take care of
    /// this.
    /// When the reopen fails, the permissions are automatically reverted to the original state.
    pub fn set_perms_in_reopen_change_graph(&self, perms: NodePermPair) -> BlockResult<()> {
        if perms == self.permissions.as_ref().into() {
            return Ok(());
        }

        self.roll_back_permissions
            .lock()
            .unwrap()
            .replace(self.permissions.as_ref().into());
        self.permissions.set(perms);

        if let Err(err) = self.node.check_perm_conflicts(self) {
            self.roll_back_reopen_perms();
            return Err(err);
        }

        Ok(())
    }

    /// Clean up potential `set_perms_in_reopen_change_graph()` state.  Call from `reopen_clean()`.
    fn clean_reopen_perms(&self) {
        self.roll_back_permissions.lock().unwrap().take();
    }

    /// Roll back a `set_perms_in_reopen_change_graph()`.  Call from `reopen_roll_back()`.
    fn roll_back_reopen_perms(&self) {
        if let Some(old_perm) = self.roll_back_permissions.lock().unwrap().take() {
            self.permissions.set(old_perm);
        }
    }
}

impl std::fmt::Debug for NodeUser {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeUser")
            .field("node", &self.node)
            .field("parent", &self.parent)
            .field("permissions", &self.permissions)
            .finish()
    }
}

impl std::fmt::Display for NodeParent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "node \"{}\" (as child \"{}\")",
            self.node_name, self.child_name
        )
    }
}

impl std::fmt::Display for NodePerms {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (known_perm_bits, mut names): (u64, Vec<String>) = [
            (NodePerm::ConsistentRead, "consistent-read"),
            (NodePerm::Write, "write"),
            (NodePerm::WriteUnchanged, "write-unchanged"),
            (NodePerm::Resize, "resize"),
        ]
            .into_iter()
            .filter(|(perm_bit, _perm_name)| self.0 & (*perm_bit as u64) != 0)
            .fold(
                (0, Vec::new()),
                |(known_perm_bits, mut names), (perm_bit, perm_name)| {
                    names.push(perm_name.to_string());
                    (known_perm_bits | (perm_bit as u64), names)
                },
            );

        if (self.0 & !known_perm_bits) != 0 {
            names.push(format!("unknown(0x{:x})", self.0 & !known_perm_bits));
        }

        write!(f, "{}", names.join(", "))
    }
}

impl NodeBasicInfo {
    fn check_validity(self) -> BlockResult<Self> {
        let size = self.limits.size.load(Ordering::Relaxed);
        let req_align = self.limits.request_alignment.load(Ordering::Relaxed);
        let soft_mem_align = self.limits.memory_alignment.load(Ordering::Relaxed);
        let mem_align = self
            .limits
            .enforced_memory_alignment
            .load(Ordering::Relaxed);

        if size % req_align as u64 != 0 {
            return Err(format!(
                "Size ({}) is not aligned to minimum I/O request alignment ({})",
                size, req_align
            )
                .into());
        }

        if size % mem_align as u64 != 0 {
            return Err(format!(
                "Size ({}) is not aligned to minimum memory buffer alignment ({})",
                size, mem_align
            )
                .into());
        }

        if soft_mem_align % mem_align != 0 {
            return Err(format!(
                "Advisory memory buffer alignment ({}) is not a multiple of the mandatory memory buffer alignment ({})",
                soft_mem_align, mem_align
            )
                .into());
        }

        Ok(self)
    }
}

impl JobInfo {
    /// Broadcast completion of this job.  Optionally, a new fatal error can be specified that
    /// happened during completion.
    fn complete(mut self, new_error: Option<String>) {
        if let Some(error) = self.error.take() {
            // broadcast_event(qmp::Event::new(qmp::Events::BlockJobCancelled {
            //     job_type: self.job_type,
            //     device: self.id.clone(),
            //     len: self.done + self.remaining,
            //     offset: self.done,
            //     speed: 0,
            //     error: new_error.unwrap_or(error),
            // }));
        } else {
            // broadcast_event(qmp::Event::new(qmp::Events::BlockJobCompleted {
            //     job_type: self.job_type,
            //     device: self.id.clone(),
            //     len: self.done + self.remaining,
            //     offset: self.done,
            //     speed: 0,
            //     error: new_error,
            // }));
        }
    }
}

impl<F: Future<Output = ()>> InFlightWriteBlocker<F> {
    fn must_await(&self) -> bool {
        self.intersecting_blockers.is_some()
    }

    async fn await_intersecting(&mut self) {
        if let Some(fut) = self.intersecting_blockers.take() {
            fut.await;
        }
    }
}

impl<F: Future<Output = ()>> Drop for InFlightWriteBlocker<F> {
    fn drop(&mut self) {
        // Must have been awaited
        assert!(self.intersecting_blockers.is_none());

        if let Some(this_write) = self.handle.take() {
            {
                let list = if self.serializing {
                    &self.node.serializing_writes
                } else {
                    &self.node.nonserializing_writes
                };

                let mut list_locked = list.write().unwrap();

                let index = this_write.index.load(Ordering::Relaxed);
                let removed = list_locked.swap_remove(index);

                debug_assert!(std::ptr::eq(
                    Arc::as_ptr(&removed),
                    Arc::as_ptr(&this_write)
                ));

                // Fix index stored in the swapped element
                if index < list_locked.len() {
                    list_locked[index].index.store(index, Ordering::Relaxed);
                }
            }

            let owned = Arc::try_unwrap(this_write).unwrap();
            let waiters = owned.waiters.into_inner().unwrap();
            for waiter in waiters {
                let _: Result<(), _> = waiter.send(());
            }
        }
    }
}