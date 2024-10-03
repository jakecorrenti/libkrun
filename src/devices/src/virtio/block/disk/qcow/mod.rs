mod qcow_raw_file;
mod refcount;
mod vec_cache;

use crate::virtio::block::disk::base::descriptor::{
    AsRawDescriptor, AsRawDescriptors, RawDescriptor,
};
use crate::virtio::block::disk::base::{PunchHole, WriteZeroesAt};
use crate::virtio::block::disk::qcow::vec_cache::Cacheable;
use crate::virtio::block::disk::{DiskFile, DiskGetLen};
use crate::virtio::file_traits::{FileAllocate, FileReadWriteAtVolatile, FileSetLen, FileSync};
use crate::virtio::AsAny;
use qcow_raw_file::QcowRawFile;
use refcount::RefCount;
use std::cmp::{max, min};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::sync::Mutex;
use vec_cache::{CacheMap, VecCache};
use vm_memory::{VolatileMemory, VolatileSlice};

// QCOW magic constant that starts the header.
pub const QCOW_MAGIC: u32 = 0x5146_49fb;

// The L1 and RefCount table are kept in RAM, only handle files that require less than 35M entries.
// This easily covers 1 TB files. When support for bigger files is needed the assumptions made to
// keep these tables in RAM needs to be thrown out.
const MAX_RAM_POINTER_TABLE_SIZE: u64 = 35_000_000;

// Limit clusters to reasonable sizes. Choose the same limits as qemu. Making the clusters smaller
// increases the amount of overhead for book keeping.
const MIN_CLUSTER_BITS: u32 = 9;
const MAX_CLUSTER_BITS: u32 = 21;

// Maximum data size supported.
const MAX_QCOW_FILE_SIZE: u64 = 0x01 << 44; // 16 TB.
                                            //
                                            // Flags
const COMPRESSED_FLAG: u64 = 1 << 62;
const CLUSTER_USED_FLAG: u64 = 1 << 63;
const COMPATIBLE_FEATURES_LAZY_REFCOUNTS: u64 = 1 << 0;

// bits 0-8 and 56-63 are reserved.
const L1_TABLE_OFFSET_MASK: u64 = 0x00ff_ffff_ffff_fe00;
const L2_TABLE_OFFSET_MASK: u64 = 0x00ff_ffff_ffff_fe00;

// Defined by the specification
const MAX_BACKING_FILE_SIZE: u32 = 1023;

#[derive(Debug)]
pub enum Error {
    BackingFileOpen(Box<super::Error>),
    BackingFileTooLong(usize),
    FileTooBig(u64),
    GettingFileSize(io::Error),
    GettingRefcount(refcount::Error),
    InvalidBackingFileName(std::str::Utf8Error),
    InvalidClusterIndex,
    InvalidClusterSize,
    InvalidIndex,
    InvalidL1TableOffset,
    InvalidL1TableSize(u32),
    InvalidMagic,
    InvalidOffset(u64),
    InvalidRefcountTableSize(u64),
    InvalidRefcountTableOffset,
    NoRefcountClusters,
    NotEnoughSpaceForRefcounts,
    ReadingHeader(io::Error),
    ReadingPointers(io::Error),
    ReadingRefCounts(io::Error),
    RefcountTableOffEnd,
    RefcountTableTooLarge,
    SeekingFile(io::Error),
    TooManyL1Entries(u64),
    TooManyRefcounts(u64),
    UnsupportedRefcountOrder,
    UnsupportedVersion(u32),
    WritingHeader(io::Error),
}

type Result<T> = std::result::Result<T, Error>;

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

impl QcowFile {
    /// Creates a QcowFile from `file`. File must be a valid qcow2 image.
    pub fn from(mut file: File, params: super::DiskFileParams) -> Result<QcowFile> {
        let header = QcowHeader::new(&mut file)?;

        // Only v3 files are supported.
        if header.version != 3 {
            return Err(Error::UnsupportedVersion(header.version));
        }

        // Make sure that the L1 table fits in RAM.
        if u64::from(header.l1_size) > MAX_RAM_POINTER_TABLE_SIZE {
            return Err(Error::InvalidL1TableSize(header.l1_size));
        }

        let cluster_bits: u32 = header.cluster_bits;
        if !(MIN_CLUSTER_BITS..=MAX_CLUSTER_BITS).contains(&cluster_bits) {
            return Err(Error::InvalidClusterSize);
        }
        let cluster_size = 0x01u64 << cluster_bits;

        // Limit the total size of the disk.
        if header.size > MAX_QCOW_FILE_SIZE {
            return Err(Error::FileTooBig(header.size));
        }

        let backing_file = if let Some(backing_file_path) = header.backing_file_path.as_ref() {
            let backing_file = super::open_disk_file(super::DiskFileParams {
                path: std::path::PathBuf::from(backing_file_path),
                // The backing file is only read from.
                is_read_only: true,
                // Sparse isn't meaningful for read only files.
                is_sparse_file: false,
                // TODO: Should pass `params.is_overlapped` through here. Needs testing.
                is_overlapped: false,
                is_direct: params.is_direct,
                lock: params.lock,
                depth: params.depth + 1,
            })
            .map_err(|e| Error::BackingFileOpen(Box::new(e)))?;
            Some(backing_file)
        } else {
            None
        };

        // Only support two byte refcounts.
        let refcount_bits: u64 = 0x01u64
            .checked_shl(header.refcount_order)
            .ok_or(Error::UnsupportedRefcountOrder)?;
        if refcount_bits != 16 {
            return Err(Error::UnsupportedRefcountOrder);
        }
        let refcount_bytes = (refcount_bits + 7) / 8;

        // Need at least one refcount cluster
        if header.refcount_table_clusters == 0 {
            return Err(Error::NoRefcountClusters);
        }
        offset_is_cluster_boundary(header.l1_table_offset, header.cluster_bits)?;
        offset_is_cluster_boundary(header.snapshots_offset, header.cluster_bits)?;
        // refcount table must be a cluster boundary, and within the file's virtual or actual size.
        offset_is_cluster_boundary(header.refcount_table_offset, header.cluster_bits)?;
        let file_size = file.metadata().map_err(Error::GettingFileSize)?.len();
        if header.refcount_table_offset > max(file_size, header.size) {
            return Err(Error::RefcountTableOffEnd);
        }

        // The first cluster should always have a non-zero refcount, so if it is 0,
        // this is an old file with broken refcounts, which requires a rebuild.
        let mut refcount_rebuild_required = true;
        file.seek(SeekFrom::Start(header.refcount_table_offset))
            .map_err(Error::SeekingFile)?;
        let first_refblock_addr = read_u64_from_file(&file)?;
        if first_refblock_addr != 0 {
            file.seek(SeekFrom::Start(first_refblock_addr))
                .map_err(Error::SeekingFile)?;
            let first_cluster_refcount = read_u16_from_file(&file)?;
            if first_cluster_refcount != 0 {
                refcount_rebuild_required = false;
            }
        }

        if (header.compatible_features & COMPATIBLE_FEATURES_LAZY_REFCOUNTS) != 0 {
            refcount_rebuild_required = true;
        }

        let mut raw_file =
            QcowRawFile::from(file, cluster_size).ok_or(Error::InvalidClusterSize)?;
        if refcount_rebuild_required {
            QcowFileInner::rebuild_refcounts(&mut raw_file, header.clone())?;
        }

        let l2_size = cluster_size / size_of::<u64>() as u64;
        let num_clusters = header.size.div_ceil(cluster_size);
        let num_l2_clusters = num_clusters.div_ceil(l2_size);
        let l1_clusters = num_l2_clusters.div_ceil(cluster_size);
        let header_clusters = (size_of::<QcowHeader>() as u64).div_ceil(cluster_size);
        if num_l2_clusters > MAX_RAM_POINTER_TABLE_SIZE {
            return Err(Error::TooManyL1Entries(num_l2_clusters));
        }
        let l1_table = VecCache::from_vec(
            raw_file
                .read_pointer_table(
                    header.l1_table_offset,
                    num_l2_clusters,
                    Some(L1_TABLE_OFFSET_MASK),
                )
                .map_err(Error::ReadingHeader)?,
        );

        let num_clusters = header.size.div_ceil(cluster_size);
        let refcount_clusters = max_refcount_clusters(
            header.refcount_order,
            cluster_size as u32,
            (num_clusters + l1_clusters + num_l2_clusters + header_clusters) as u32,
        );
        // Check that the given header doesn't have a suspiciously sized refcount table.
        if u64::from(header.refcount_table_clusters) > 2 * refcount_clusters {
            return Err(Error::RefcountTableTooLarge);
        }
        if l1_clusters + refcount_clusters > MAX_RAM_POINTER_TABLE_SIZE {
            return Err(Error::TooManyRefcounts(refcount_clusters));
        }
        let refcount_block_entries = cluster_size / refcount_bytes;
        let refcounts = RefCount::new(
            &mut raw_file,
            header.refcount_table_offset,
            refcount_clusters,
            refcount_block_entries,
            cluster_size,
        )
        .map_err(Error::ReadingRefCounts)?;

        let l2_entries = cluster_size / size_of::<u64>() as u64;

        let mut inner = QcowFileInner {
            raw_file,
            header,
            l1_table,
            l2_entries,
            l2_cache: CacheMap::new(100),
            refcounts,
            current_offset: 0,
            unref_clusters: Vec::new(),
            avail_clusters: Vec::new(),
            backing_file,
        };

        // Check that the L1 and refcount tables fit in a 64bit address space.
        inner
            .header
            .l1_table_offset
            .checked_add(inner.l1_address_offset(inner.virtual_size()))
            .ok_or(Error::InvalidL1TableOffset)?;
        inner
            .header
            .refcount_table_offset
            .checked_add(u64::from(inner.header.refcount_table_clusters) * cluster_size)
            .ok_or(Error::InvalidRefcountTableOffset)?;

        inner.find_avail_clusters()?;

        let virtual_size = inner.virtual_size();
        Ok(QcowFile {
            inner: Mutex::new(inner),
            virtual_size,
        })
    }
}

// Reads the next u16 from the file.
fn read_u16_from_file(mut f: &File) -> Result<u16> {
    let mut value = [0u8; 2];
    (&mut f)
        .read_exact(&mut value)
        .map_err(Error::ReadingHeader)?;
    Ok(u16::from_be_bytes(value))
}

// Reads the next u32 from the file.
fn read_u32_from_file(mut f: &File) -> Result<u32> {
    let mut value = [0u8; 4];
    (&mut f)
        .read_exact(&mut value)
        .map_err(Error::ReadingHeader)?;
    Ok(u32::from_be_bytes(value))
}

// Reads the next u64 from the file.
fn read_u64_from_file(mut f: &File) -> Result<u64> {
    let mut value = [0u8; 8];
    (&mut f)
        .read_exact(&mut value)
        .map_err(Error::ReadingHeader)?;
    Ok(u64::from_be_bytes(value))
}

// Returns an Error if the given offset doesn't align to a cluster boundary.
fn offset_is_cluster_boundary(offset: u64, cluster_bits: u32) -> Result<()> {
    if offset & ((0x01 << cluster_bits) - 1) != 0 {
        return Err(Error::InvalidOffset(offset));
    }
    Ok(())
}

fn max_refcount_clusters(refcount_order: u32, cluster_size: u32, num_clusters: u32) -> u64 {
    // Use u64 as the product of the u32 inputs can overflow.
    let refcount_bytes = (0x01 << refcount_order as u64) / 8;
    let for_data = (u64::from(num_clusters) * refcount_bytes).div_ceil(u64::from(cluster_size));
    let for_refcounts = (for_data * refcount_bytes).div_ceil(u64::from(cluster_size));
    for_data + for_refcounts
}

impl QcowHeader {
    /// Creates a QcowHeader from a reference to a file.
    pub fn new(f: &mut File) -> Result<QcowHeader> {
        f.seek(SeekFrom::Start(0)).map_err(Error::ReadingHeader)?;

        let magic = read_u32_from_file(f)?;
        if magic != QCOW_MAGIC {
            return Err(Error::InvalidMagic);
        }

        let mut header = QcowHeader {
            magic,
            version: read_u32_from_file(f)?,
            backing_file_offset: read_u64_from_file(f)?,
            backing_file_size: read_u32_from_file(f)?,
            cluster_bits: read_u32_from_file(f)?,
            size: read_u64_from_file(f)?,
            crypt_method: read_u32_from_file(f)?,
            l1_size: read_u32_from_file(f)?,
            l1_table_offset: read_u64_from_file(f)?,
            refcount_table_offset: read_u64_from_file(f)?,
            refcount_table_clusters: read_u32_from_file(f)?,
            nb_snapshots: read_u32_from_file(f)?,
            snapshots_offset: read_u64_from_file(f)?,
            incompatible_features: read_u64_from_file(f)?,
            compatible_features: read_u64_from_file(f)?,
            autoclear_features: read_u64_from_file(f)?,
            refcount_order: read_u32_from_file(f)?,
            header_size: read_u32_from_file(f)?,
            backing_file_path: None,
        };
        if header.backing_file_size > MAX_BACKING_FILE_SIZE {
            return Err(Error::BackingFileTooLong(header.backing_file_size as usize));
        }
        if header.backing_file_offset != 0 {
            f.seek(SeekFrom::Start(header.backing_file_offset))
                .map_err(Error::ReadingHeader)?;
            let mut backing_file_name_bytes = vec![0u8; header.backing_file_size as usize];
            f.read_exact(&mut backing_file_name_bytes)
                .map_err(Error::ReadingHeader)?;
            header.backing_file_path = Some(
                String::from_utf8(backing_file_name_bytes)
                    .map_err(|err| Error::InvalidBackingFileName(err.utf8_error()))?,
            );
        }
        Ok(header)
    }

    /// Write the header to `file`.
    pub fn write_to<F: Write + Seek>(&self, file: &mut F) -> Result<()> {
        // Writes the next u32 to the file.
        fn write_u32_to_file<F: Write>(f: &mut F, value: u32) -> Result<()> {
            f.write_all(&value.to_be_bytes())
                .map_err(Error::WritingHeader)
        }

        // Writes the next u64 to the file.
        fn write_u64_to_file<F: Write>(f: &mut F, value: u64) -> Result<()> {
            f.write_all(&value.to_be_bytes())
                .map_err(Error::WritingHeader)
        }

        write_u32_to_file(file, self.magic)?;
        write_u32_to_file(file, self.version)?;
        write_u64_to_file(file, self.backing_file_offset)?;
        write_u32_to_file(file, self.backing_file_size)?;
        write_u32_to_file(file, self.cluster_bits)?;
        write_u64_to_file(file, self.size)?;
        write_u32_to_file(file, self.crypt_method)?;
        write_u32_to_file(file, self.l1_size)?;
        write_u64_to_file(file, self.l1_table_offset)?;
        write_u64_to_file(file, self.refcount_table_offset)?;
        write_u32_to_file(file, self.refcount_table_clusters)?;
        write_u32_to_file(file, self.nb_snapshots)?;
        write_u64_to_file(file, self.snapshots_offset)?;
        write_u64_to_file(file, self.incompatible_features)?;
        write_u64_to_file(file, self.compatible_features)?;
        write_u64_to_file(file, self.autoclear_features)?;
        write_u32_to_file(file, self.refcount_order)?;
        write_u32_to_file(file, self.header_size)?;
        write_u32_to_file(file, 0)?; // header extension type: end of header extension area
        write_u32_to_file(file, 0)?; // length of header extension data: 0
        if let Some(backing_file_path) = self.backing_file_path.as_ref() {
            write!(file, "{}", backing_file_path).map_err(Error::WritingHeader)?;
        }

        // Set the file length by seeking and writing a zero to the last byte. This avoids needing
        // a `File` instead of anything that implements seek as the `file` argument.
        // Zeros out the l1 and refcount table clusters.
        let cluster_size = 0x01u64 << self.cluster_bits;
        let refcount_blocks_size = u64::from(self.refcount_table_clusters) * cluster_size;
        file.seek(SeekFrom::Start(
            self.refcount_table_offset + refcount_blocks_size - 2,
        ))
        .map_err(Error::WritingHeader)?;
        file.write(&[0u8]).map_err(Error::WritingHeader)?;

        Ok(())
    }
}

impl QcowFileInner {
    // Fill a range of `length` bytes starting at `address` with zeroes.
    // Any future reads of this range will return all zeroes.
    // If there is no backing file, this will deallocate cluster storage when possible.
    fn zero_bytes(&mut self, address: u64, length: usize) -> std::io::Result<()> {
        let write_count: usize = self.limit_range_file(address, length);

        let mut nwritten: usize = 0;
        while nwritten < write_count {
            let curr_addr = address + nwritten as u64;
            let count = self.limit_range_cluster(curr_addr, write_count - nwritten);

            if self.backing_file.is_none() && count == self.raw_file.cluster_size() as usize {
                // Full cluster and no backing file in use - deallocate the storage.
                self.deallocate_cluster(curr_addr)?;
            } else {
                // Partial cluster - zero out the relevant bytes.
                let offset = if self.backing_file.is_some() {
                    // There is a backing file, so we need to allocate a cluster in order to
                    // zero out the hole-punched bytes such that the backing file contents do not
                    // show through.
                    Some(self.file_offset_write(curr_addr)?)
                } else {
                    // Any space in unallocated clusters can be left alone, since
                    // unallocated clusters already read back as zeroes.
                    self.file_offset_read(curr_addr)?
                };
                if let Some(offset) = offset {
                    // Partial cluster - zero it out.
                    self.raw_file.file().write_zeroes_all_at(offset, count)?;
                }
            }

            nwritten += count;
        }
        Ok(())
    }

    // Writes `count` bytes starting at `address`, calling `cb` repeatedly with the backing file,
    // number of bytes written so far, raw file offset, and number of bytes to write to the file in
    // that invocation.
    fn write_cb<F>(&mut self, address: u64, count: usize, mut cb: F) -> std::io::Result<usize>
    where
        F: FnMut(&mut File, usize, u64, usize) -> std::io::Result<()>,
    {
        let write_count: usize = self.limit_range_file(address, count);

        let mut nwritten: usize = 0;
        while nwritten < write_count {
            let curr_addr = address + nwritten as u64;
            let offset = self.file_offset_write(curr_addr)?;
            let count = self.limit_range_cluster(curr_addr, write_count - nwritten);

            cb(self.raw_file.file_mut(), nwritten, offset, count)?;

            nwritten += count;
        }
        Ok(write_count)
    }
    fn sync_caches(&mut self) -> std::io::Result<()> {
        // Write out all dirty L2 tables.
        for (l1_index, l2_table) in self.l2_cache.iter_mut().filter(|(_k, v)| v.dirty()) {
            // The index must be valid from when we insterted it.
            let addr = self.l1_table[*l1_index];
            if addr != 0 {
                self.raw_file.write_pointer_table(
                    addr,
                    l2_table.get_values(),
                    CLUSTER_USED_FLAG,
                )?;
            } else {
                return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
            }
            l2_table.mark_clean();
        }
        // Write the modified refcount blocks.
        self.refcounts.flush_blocks(&mut self.raw_file)?;
        // Make sure metadata(file len) and all data clusters are written.
        self.raw_file.file_mut().sync_all()?;

        // Push L1 table and refcount table last as all the clusters they point to are now
        // guaranteed to be valid.
        let mut sync_required = false;
        if self.l1_table.dirty() {
            self.raw_file.write_pointer_table(
                self.header.l1_table_offset,
                self.l1_table.get_values(),
                0,
            )?;
            self.l1_table.mark_clean();
            sync_required = true;
        }
        sync_required |= self.refcounts.flush_table(&mut self.raw_file)?;
        if sync_required {
            self.raw_file.file_mut().sync_data()?;
        }
        Ok(())
    }

    // Reads `count` bytes starting at `address`, calling `cb` repeatedly with the data source,
    // number of bytes read so far, offset to read from, and number of bytes to read from the file
    // in that invocation. If None is given to `cb` in place of the backing file, the `cb` should
    // infer zeros would have been read.
    fn read_cb<F>(&mut self, address: u64, count: usize, mut cb: F) -> std::io::Result<usize>
    where
        F: FnMut(Option<&mut dyn DiskFile>, usize, u64, usize) -> std::io::Result<()>,
    {
        let read_count: usize = self.limit_range_file(address, count);

        let mut nread: usize = 0;
        while nread < read_count {
            let curr_addr = address + nread as u64;
            let file_offset = self.file_offset_read(curr_addr)?;
            let count = self.limit_range_cluster(curr_addr, read_count - nread);

            if let Some(offset) = file_offset {
                cb(Some(self.raw_file.file_mut()), nread, offset, count)?;
            } else if let Some(backing) = self.backing_file.as_mut() {
                cb(Some(backing.as_mut()), nread, curr_addr, count)?;
            } else {
                cb(None, nread, 0, count)?;
            }

            nread += count;
        }
        Ok(read_count)
    }

    /// Rebuild the reference count tables.
    fn rebuild_refcounts(raw_file: &mut QcowRawFile, header: QcowHeader) -> Result<()> {
        fn add_ref(refcounts: &mut [u16], cluster_size: u64, cluster_address: u64) -> Result<()> {
            let idx = (cluster_address / cluster_size) as usize;
            if idx >= refcounts.len() {
                return Err(Error::InvalidClusterIndex);
            }
            refcounts[idx] += 1;
            Ok(())
        }

        // Add a reference to the first cluster (header plus extensions).
        fn set_header_refcount(refcounts: &mut [u16], cluster_size: u64) -> Result<()> {
            add_ref(refcounts, cluster_size, 0)
        }

        // Add references to the L1 table clusters.
        fn set_l1_refcounts(
            refcounts: &mut [u16],
            header: QcowHeader,
            cluster_size: u64,
        ) -> Result<()> {
            let l1_clusters = u64::from(header.l1_size).div_ceil(cluster_size);
            let l1_table_offset = header.l1_table_offset;
            for i in 0..l1_clusters {
                add_ref(refcounts, cluster_size, l1_table_offset + i * cluster_size)?;
            }
            Ok(())
        }

        // Traverse the L1 and L2 tables to find all reachable data clusters.
        fn set_data_refcounts(
            refcounts: &mut [u16],
            header: QcowHeader,
            cluster_size: u64,
            raw_file: &mut QcowRawFile,
        ) -> Result<()> {
            let l1_table = raw_file
                .read_pointer_table(
                    header.l1_table_offset,
                    header.l1_size as u64,
                    Some(L1_TABLE_OFFSET_MASK),
                )
                .map_err(Error::ReadingPointers)?;
            for l1_index in 0..header.l1_size as usize {
                let l2_addr_disk = *l1_table.get(l1_index).ok_or(Error::InvalidIndex)?;
                if l2_addr_disk != 0 {
                    // Add a reference to the L2 table cluster itself.
                    add_ref(refcounts, cluster_size, l2_addr_disk)?;

                    // Read the L2 table and find all referenced data clusters.
                    let l2_table = raw_file
                        .read_pointer_table(
                            l2_addr_disk,
                            cluster_size / size_of::<u64>() as u64,
                            Some(L2_TABLE_OFFSET_MASK),
                        )
                        .map_err(Error::ReadingPointers)?;
                    for data_cluster_addr in l2_table {
                        if data_cluster_addr != 0 {
                            add_ref(refcounts, cluster_size, data_cluster_addr)?;
                        }
                    }
                }
            }

            Ok(())
        }

        // Add references to the top-level refcount table clusters.
        fn set_refcount_table_refcounts(
            refcounts: &mut [u16],
            header: QcowHeader,
            cluster_size: u64,
        ) -> Result<()> {
            let refcount_table_offset = header.refcount_table_offset;
            for i in 0..header.refcount_table_clusters as u64 {
                add_ref(
                    refcounts,
                    cluster_size,
                    refcount_table_offset + i * cluster_size,
                )?;
            }
            Ok(())
        }

        // Allocate clusters for refblocks.
        // This needs to be done last so that we have the correct refcounts for all other
        // clusters.
        fn alloc_refblocks(
            refcounts: &mut [u16],
            cluster_size: u64,
            refblock_clusters: u64,
            pointers_per_cluster: u64,
        ) -> Result<Vec<u64>> {
            let refcount_table_entries = refblock_clusters.div_ceil(pointers_per_cluster);
            let mut ref_table = vec![0; refcount_table_entries as usize];
            let mut first_free_cluster: u64 = 0;
            for refblock_addr in &mut ref_table {
                loop {
                    if first_free_cluster >= refcounts.len() as u64 {
                        return Err(Error::NotEnoughSpaceForRefcounts);
                    }
                    if refcounts[first_free_cluster as usize] == 0 {
                        break;
                    }
                    first_free_cluster += 1;
                }

                *refblock_addr = first_free_cluster * cluster_size;
                add_ref(refcounts, cluster_size, *refblock_addr)?;

                first_free_cluster += 1;
            }

            Ok(ref_table)
        }

        // Write the updated reference count blocks and reftable.
        fn write_refblocks(
            refcounts: &[u16],
            mut header: QcowHeader,
            ref_table: &[u64],
            raw_file: &mut QcowRawFile,
            refcount_block_entries: u64,
        ) -> Result<()> {
            // Rewrite the header with lazy refcounts enabled while we are rebuilding the tables.
            header.compatible_features |= COMPATIBLE_FEATURES_LAZY_REFCOUNTS;
            raw_file
                .file_mut()
                .seek(SeekFrom::Start(0))
                .map_err(Error::SeekingFile)?;
            header.write_to(raw_file.file_mut())?;

            for (i, refblock_addr) in ref_table.iter().enumerate() {
                // Write a block of refcounts to the location indicated by refblock_addr.
                let refblock_start = i * (refcount_block_entries as usize);
                let refblock_end = min(
                    refcounts.len(),
                    refblock_start + refcount_block_entries as usize,
                );
                let refblock = &refcounts[refblock_start..refblock_end];
                raw_file
                    .write_refcount_block(*refblock_addr, refblock)
                    .map_err(Error::WritingHeader)?;

                // If this is the last (partial) cluster, pad it out to a full refblock cluster.
                if refblock.len() < refcount_block_entries as usize {
                    let refblock_padding =
                        vec![0u16; refcount_block_entries as usize - refblock.len()];
                    raw_file
                        .write_refcount_block(
                            *refblock_addr + refblock.len() as u64 * 2,
                            &refblock_padding,
                        )
                        .map_err(Error::WritingHeader)?;
                }
            }

            // Rewrite the top-level refcount table.
            raw_file
                .write_pointer_table(header.refcount_table_offset, ref_table, 0)
                .map_err(Error::WritingHeader)?;

            // Rewrite the header again, now with lazy refcounts disabled.
            header.compatible_features &= !COMPATIBLE_FEATURES_LAZY_REFCOUNTS;
            raw_file
                .file_mut()
                .seek(SeekFrom::Start(0))
                .map_err(Error::SeekingFile)?;
            header.write_to(raw_file.file_mut())?;

            Ok(())
        }

        let cluster_size = raw_file.cluster_size();

        let file_size = raw_file
            .file_mut()
            .metadata()
            .map_err(Error::GettingFileSize)?
            .len();

        let refcount_bits = 1u64 << header.refcount_order;
        let refcount_bytes = refcount_bits.div_ceil(8);
        let refcount_block_entries = cluster_size / refcount_bytes;
        let pointers_per_cluster = cluster_size / size_of::<u64>() as u64;
        let data_clusters = header.size.div_ceil(cluster_size);
        let l2_clusters = data_clusters.div_ceil(pointers_per_cluster);
        let l1_clusters = l2_clusters.div_ceil(cluster_size);
        let header_clusters = (size_of::<QcowHeader>() as u64).div_ceil(cluster_size);
        let max_clusters = data_clusters + l2_clusters + l1_clusters + header_clusters;
        let mut max_valid_cluster_index = max_clusters;
        let refblock_clusters = max_valid_cluster_index.div_ceil(refcount_block_entries);
        let reftable_clusters = refblock_clusters.div_ceil(pointers_per_cluster);
        // Account for refblocks and the ref table size needed to address them.
        let refblocks_for_refs =
            (refblock_clusters + reftable_clusters).div_ceil(refcount_block_entries);
        let reftable_clusters_for_refs = refblocks_for_refs.div_ceil(refcount_block_entries);
        max_valid_cluster_index += refblock_clusters + reftable_clusters;
        max_valid_cluster_index += refblocks_for_refs + reftable_clusters_for_refs;

        if max_valid_cluster_index > MAX_RAM_POINTER_TABLE_SIZE {
            return Err(Error::InvalidRefcountTableSize(max_valid_cluster_index));
        }

        let max_valid_cluster_offset = max_valid_cluster_index * cluster_size;
        if max_valid_cluster_offset < file_size - cluster_size {
            return Err(Error::InvalidRefcountTableSize(max_valid_cluster_offset));
        }

        let mut refcounts = vec![0; max_valid_cluster_index as usize];

        // Find all references clusters and rebuild refcounts.
        set_header_refcount(&mut refcounts, cluster_size)?;
        set_l1_refcounts(&mut refcounts, header.clone(), cluster_size)?;
        set_data_refcounts(&mut refcounts, header.clone(), cluster_size, raw_file)?;
        set_refcount_table_refcounts(&mut refcounts, header.clone(), cluster_size)?;

        // Allocate clusters to store the new reference count blocks.
        let ref_table = alloc_refblocks(
            &mut refcounts,
            cluster_size,
            refblock_clusters,
            pointers_per_cluster,
        )?;

        // Write updated reference counts and point the reftable at them.
        write_refblocks(
            &refcounts,
            header,
            &ref_table,
            raw_file,
            refcount_block_entries,
        )
    }

    // Gets the offset of `address` in the L1 table.
    fn l1_address_offset(&self, address: u64) -> u64 {
        let l1_index = self.l1_table_index(address);
        l1_index * size_of::<u64>() as u64
    }

    // Gets the offset of `address` in the L1 table.
    fn l1_table_index(&self, address: u64) -> u64 {
        (address / self.raw_file.cluster_size()) / self.l2_entries
    }

    // Gets the offset of `address` in the L2 table.
    fn l2_table_index(&self, address: u64) -> u64 {
        (address / self.raw_file.cluster_size()) % self.l2_entries
    }

    // Reads an L2 cluster from the disk, returning an error if the file can't be read or if any
    // cluster is compressed.
    fn read_l2_cluster(raw_file: &mut QcowRawFile, cluster_addr: u64) -> std::io::Result<Vec<u64>> {
        let file_values = raw_file.read_pointer_cluster(cluster_addr, None)?;
        if file_values.iter().any(|entry| entry & COMPRESSED_FLAG != 0) {
            return Err(std::io::Error::from_raw_os_error(libc::ENOTSUP));
        }
        Ok(file_values
            .iter()
            .map(|entry| *entry & L2_TABLE_OFFSET_MASK)
            .collect())
    }

    // Gets the maximum virtual size of this image.
    fn virtual_size(&self) -> u64 {
        self.header.size
    }

    fn find_avail_clusters(&mut self) -> Result<()> {
        let cluster_size = self.raw_file.cluster_size();

        let file_size = self
            .raw_file
            .file_mut()
            .metadata()
            .map_err(Error::GettingFileSize)?
            .len();

        for i in (0..file_size).step_by(cluster_size as usize) {
            let refcount = self
                .refcounts
                .get_cluster_refcount(&mut self.raw_file, i)
                .map_err(Error::GettingRefcount)?;
            if refcount == 0 {
                self.avail_clusters.push(i);
            }
        }

        Ok(())
    }

    // Limits the range so that it doesn't exceed the virtual size of the file.
    fn limit_range_file(&self, address: u64, count: usize) -> usize {
        if address.checked_add(count as u64).is_none() || address > self.virtual_size() {
            return 0;
        }
        min(count as u64, self.virtual_size() - address) as usize
    }

    // Limits the range so that it doesn't overflow the end of a cluster.
    fn limit_range_cluster(&self, address: u64, count: usize) -> usize {
        let offset: u64 = self.raw_file.cluster_offset(address);
        let limit = self.raw_file.cluster_size() - offset;
        min(count as u64, limit) as usize
    }

    // Deallocate the storage for the cluster starting at `address`.
    // Any future reads of this cluster will return all zeroes (or the backing file, if in use).
    fn deallocate_cluster(&mut self, address: u64) -> std::io::Result<()> {
        if address >= self.virtual_size() {
            return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
        }

        let l1_index = self.l1_table_index(address) as usize;
        let l2_addr_disk = *self
            .l1_table
            .get(l1_index)
            .ok_or_else(|| std::io::Error::from_raw_os_error(libc::EINVAL))?;
        let l2_index = self.l2_table_index(address) as usize;

        if l2_addr_disk == 0 {
            // The whole L2 table for this address is not allocated yet,
            // so the cluster must also be unallocated.
            return Ok(());
        }

        if !self.l2_cache.contains_key(&l1_index) {
            // Not in the cache.
            let table =
                VecCache::from_vec(Self::read_l2_cluster(&mut self.raw_file, l2_addr_disk)?);
            let l1_table = &self.l1_table;
            let raw_file = &mut self.raw_file;
            self.l2_cache.insert(l1_index, table, |index, evicted| {
                raw_file.write_pointer_table(
                    l1_table[index],
                    evicted.get_values(),
                    CLUSTER_USED_FLAG,
                )
            })?;
        }

        let cluster_addr = self.l2_cache.get(&l1_index).unwrap()[l2_index];
        if cluster_addr == 0 {
            // This cluster is already unallocated; nothing to do.
            return Ok(());
        }

        // Decrement the refcount.
        let refcount = self
            .refcounts
            .get_cluster_refcount(&mut self.raw_file, cluster_addr)
            .map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))?;
        if refcount == 0 {
            return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
        }

        let new_refcount = refcount - 1;
        let mut newly_unref = self.set_cluster_refcount(cluster_addr, new_refcount)?;
        self.unref_clusters.append(&mut newly_unref);

        // Rewrite the L2 entry to remove the cluster mapping.
        // unwrap is safe as we just checked/inserted this entry.
        self.l2_cache.get_mut(&l1_index).unwrap()[l2_index] = 0;

        if new_refcount == 0 {
            let cluster_size = self.raw_file.cluster_size();
            // This cluster is no longer in use; deallocate the storage.
            // The underlying FS may not support FALLOC_FL_PUNCH_HOLE,
            // so don't treat an error as fatal.  Future reads will return zeros anyways.
            let _ = self.raw_file.file().punch_hole(cluster_addr, cluster_size);
            self.unref_clusters.push(cluster_addr);
        }
        Ok(())
    }

    // Gets the offset of the given guest address in the host file. If L1, L2, or data clusters need
    // to be allocated, they will be.
    fn file_offset_write(&mut self, address: u64) -> std::io::Result<u64> {
        if address >= self.virtual_size() {
            return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
        }

        let l1_index = self.l1_table_index(address) as usize;
        let l2_addr_disk = *self
            .l1_table
            .get(l1_index)
            .ok_or_else(|| std::io::Error::from_raw_os_error(libc::EINVAL))?;
        let l2_index = self.l2_table_index(address) as usize;

        let mut set_refcounts = Vec::new();

        if !self.l2_cache.contains_key(&l1_index) {
            // Not in the cache.
            let l2_table = if l2_addr_disk == 0 {
                // Allocate a new cluster to store the L2 table and update the L1 table to point
                // to the new table.
                let new_addr: u64 = self.get_new_cluster(None)?;
                // The cluster refcount starts at one meaning it is used but doesn't need COW.
                set_refcounts.push((new_addr, 1));
                self.l1_table[l1_index] = new_addr;
                VecCache::new(self.l2_entries as usize)
            } else {
                VecCache::from_vec(Self::read_l2_cluster(&mut self.raw_file, l2_addr_disk)?)
            };
            let l1_table = &self.l1_table;
            let raw_file = &mut self.raw_file;
            self.l2_cache.insert(l1_index, l2_table, |index, evicted| {
                raw_file.write_pointer_table(
                    l1_table[index],
                    evicted.get_values(),
                    CLUSTER_USED_FLAG,
                )
            })?;
        }

        let cluster_addr = match self.l2_cache.get(&l1_index).unwrap()[l2_index] {
            0 => {
                let initial_data = if let Some(backing) = self.backing_file.as_mut() {
                    let cluster_size = self.raw_file.cluster_size();
                    let cluster_begin = address - (address % cluster_size);
                    let mut cluster_data = vec![0u8; cluster_size as usize];
                    let volatile_slice = unsafe {
                        VolatileSlice::new(cluster_data.as_mut_ptr(), cluster_data.len())
                    };
                    backing.read_exact_at_volatile(volatile_slice, cluster_begin)?;
                    Some(cluster_data)
                } else {
                    None
                };
                // Need to allocate a data cluster
                let cluster_addr = self.append_data_cluster(initial_data)?;
                self.update_cluster_addr(l1_index, l2_index, cluster_addr, &mut set_refcounts)?;
                cluster_addr
            }
            a => a,
        };

        for (addr, count) in set_refcounts {
            let mut newly_unref = self.set_cluster_refcount(addr, count)?;
            self.unref_clusters.append(&mut newly_unref);
        }

        Ok(cluster_addr + self.raw_file.cluster_offset(address))
    }

    // Gets the offset of the given guest address in the host file. If L1, L2, or data clusters have
    // yet to be allocated, return None.
    fn file_offset_read(&mut self, address: u64) -> std::io::Result<Option<u64>> {
        if address >= self.virtual_size() {
            return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
        }

        let l1_index = self.l1_table_index(address) as usize;
        let l2_addr_disk = *self
            .l1_table
            .get(l1_index)
            .ok_or_else(|| std::io::Error::from_raw_os_error(libc::EINVAL))?;

        if l2_addr_disk == 0 {
            // Reading from an unallocated cluster will return zeros.
            return Ok(None);
        }

        let l2_index = self.l2_table_index(address) as usize;

        if !self.l2_cache.contains_key(&l1_index) {
            // Not in the cache.
            let table =
                VecCache::from_vec(Self::read_l2_cluster(&mut self.raw_file, l2_addr_disk)?);

            let l1_table = &self.l1_table;
            let raw_file = &mut self.raw_file;
            self.l2_cache.insert(l1_index, table, |index, evicted| {
                raw_file.write_pointer_table(
                    l1_table[index],
                    evicted.get_values(),
                    CLUSTER_USED_FLAG,
                )
            })?;
        };

        let cluster_addr = self.l2_cache.get(&l1_index).unwrap()[l2_index];
        if cluster_addr == 0 {
            return Ok(None);
        }
        Ok(Some(cluster_addr + self.raw_file.cluster_offset(address)))
    }

    // Allocate a new cluster and return its offset within the raw file.
    fn get_new_cluster(&mut self, initial_data: Option<Vec<u8>>) -> std::io::Result<u64> {
        // First use a pre allocated cluster if one is available.
        if let Some(free_cluster) = self.avail_clusters.pop() {
            if let Some(initial_data) = initial_data {
                self.raw_file.write_cluster(free_cluster, initial_data)?;
            } else {
                self.raw_file.zero_cluster(free_cluster)?;
            }
            return Ok(free_cluster);
        }

        let max_valid_cluster_offset = self.refcounts.max_valid_cluster_offset();
        if let Some(new_cluster) = self.raw_file.add_cluster_end(max_valid_cluster_offset)? {
            if let Some(initial_data) = initial_data {
                self.raw_file.write_cluster(new_cluster, initial_data)?;
            }
            Ok(new_cluster)
        } else {
            error!("No free clusters in get_new_cluster()");
            Err(std::io::Error::from_raw_os_error(libc::ENOSPC))
        }
    }

    // Updates the l1 and l2 tables to point to the new `cluster_addr`.
    fn update_cluster_addr(
        &mut self,
        l1_index: usize,
        l2_index: usize,
        cluster_addr: u64,
        set_refcounts: &mut Vec<(u64, u16)>,
    ) -> io::Result<()> {
        if !self.l2_cache.get(&l1_index).unwrap().dirty() {
            // Free the previously used cluster if one exists. Modified tables are always
            // witten to new clusters so the L1 table can be committed to disk after they
            // are and L1 never points at an invalid table.
            // The index must be valid from when it was insterted.
            let addr = self.l1_table[l1_index];
            if addr != 0 {
                self.unref_clusters.push(addr);
                set_refcounts.push((addr, 0));
            }

            // Allocate a new cluster to store the L2 table and update the L1 table to point
            // to the new table. The cluster will be written when the cache is flushed, no
            // need to copy the data now.
            let new_addr: u64 = self.get_new_cluster(None)?;
            // The cluster refcount starts at one indicating it is used but doesn't need
            // COW.
            set_refcounts.push((new_addr, 1));
            self.l1_table[l1_index] = new_addr;
        }
        // 'unwrap' is OK because it was just added.
        self.l2_cache.get_mut(&l1_index).unwrap()[l2_index] = cluster_addr;
        Ok(())
    }

    // Allocate and initialize a new data cluster. Returns the offset of the
    // cluster in to the file on success.
    fn append_data_cluster(&mut self, initial_data: Option<Vec<u8>>) -> std::io::Result<u64> {
        let new_addr: u64 = self.get_new_cluster(initial_data)?;
        // The cluster refcount starts at one indicating it is used but doesn't need COW.
        let mut newly_unref = self.set_cluster_refcount(new_addr, 1)?;
        self.unref_clusters.append(&mut newly_unref);
        Ok(new_addr)
    }

    // Set the refcount for a cluster with the given address.
    // Returns a list of any refblocks that can be reused, this happens when a refblock is moved,
    // the old location can be reused.
    fn set_cluster_refcount(&mut self, address: u64, refcount: u16) -> std::io::Result<Vec<u64>> {
        let mut added_clusters = Vec::new();
        let mut unref_clusters = Vec::new();
        let mut refcount_set = false;
        let mut new_cluster = None;

        while !refcount_set {
            match self.refcounts.set_cluster_refcount(
                &mut self.raw_file,
                address,
                refcount,
                new_cluster.take(),
            ) {
                Ok(None) => {
                    refcount_set = true;
                }
                Ok(Some(freed_cluster)) => {
                    unref_clusters.push(freed_cluster);
                    refcount_set = true;
                }
                Err(refcount::Error::EvictingRefCounts(e)) => {
                    return Err(e);
                }
                Err(refcount::Error::InvalidIndex) => {
                    return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
                }
                Err(refcount::Error::NeedCluster(addr)) => {
                    // Read the address and call set_cluster_refcount again.
                    new_cluster = Some((
                        addr,
                        VecCache::from_vec(self.raw_file.read_refcount_block(addr)?),
                    ));
                }
                Err(refcount::Error::NeedNewCluster) => {
                    // Allocate the cluster and call set_cluster_refcount again.
                    let addr = self.get_new_cluster(None)?;
                    added_clusters.push(addr);
                    new_cluster = Some((
                        addr,
                        VecCache::new(self.refcounts.refcounts_per_block() as usize),
                    ));
                }
                Err(refcount::Error::ReadingRefCounts(e)) => {
                    return Err(e);
                }
            }
        }

        for addr in added_clusters {
            self.set_cluster_refcount(addr, 1)?;
        }
        Ok(unref_clusters)
    }
}

impl Drop for QcowFile {
    fn drop(&mut self) {
        let _ = self.inner.get_mut().unwrap().sync_caches();
    }
}

impl AsRawDescriptors for QcowFile {
    fn as_raw_descriptors(&self) -> Vec<RawDescriptor> {
        // Taking a lock here feels wrong, but this method is generally only used during
        // sandboxing, so it should be OK.
        let inner = self.inner.lock().unwrap();
        let mut descriptors = vec![inner.raw_file.file().as_raw_descriptor()];
        if let Some(backing) = &inner.backing_file {
            descriptors.append(&mut backing.as_raw_descriptors());
        }
        descriptors
    }
}

impl Read for QcowFile {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let inner = self.inner.get_mut().unwrap();
        let len = buf.len();
        let slice = unsafe { VolatileSlice::new(buf.as_mut_ptr(), buf.len()) };
        let read_count = inner.read_cb(
            inner.current_offset,
            len,
            |file, already_read, offset, count| {
                let mut sub_slice = slice.get_slice(already_read, count).unwrap();
                match file {
                    Some(f) => f.read_exact_at_volatile(sub_slice, offset),
                    None => {
                        unsafe {
                            std::ptr::write_bytes(&mut sub_slice as _, 0, sub_slice.len());
                        }
                        // sub_slice.write_bytes(0);
                        Ok(())
                    }
                }
            },
        )?;
        inner.current_offset += read_count as u64;
        Ok(read_count)
    }
}

impl Seek for QcowFile {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        let inner = self.inner.get_mut().unwrap();
        let new_offset: Option<u64> = match pos {
            SeekFrom::Start(off) => Some(off),
            SeekFrom::End(off) => {
                if off < 0 {
                    0i64.checked_sub(off)
                        .and_then(|increment| inner.virtual_size().checked_sub(increment as u64))
                } else {
                    inner.virtual_size().checked_add(off as u64)
                }
            }
            SeekFrom::Current(off) => {
                if off < 0 {
                    0i64.checked_sub(off)
                        .and_then(|increment| inner.current_offset.checked_sub(increment as u64))
                } else {
                    inner.current_offset.checked_add(off as u64)
                }
            }
        };

        if let Some(o) = new_offset {
            if o <= inner.virtual_size() {
                inner.current_offset = o;
                return Ok(o);
            }
        }
        Err(std::io::Error::from_raw_os_error(libc::EINVAL))
    }
}

impl Write for QcowFile {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let inner = self.inner.get_mut().unwrap();
        let write_count = inner.write_cb(
            inner.current_offset,
            buf.len(),
            |file, offset, raw_offset, count| {
                file.seek(SeekFrom::Start(raw_offset))?;
                file.write_all(&buf[offset..(offset + count)])
            },
        )?;
        inner.current_offset += write_count as u64;
        Ok(write_count)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.fsync()
    }
}

impl FileReadWriteAtVolatile for QcowFile {
    fn read_at_volatile(&self, slice: VolatileSlice, offset: u64) -> io::Result<usize> {
        let mut inner = self.inner.lock().unwrap();
        inner.read_cb(offset, slice.len(), |file, read, offset, count| {
            let mut sub_slice = slice.get_slice(read, count).unwrap();
            match file {
                Some(f) => f.read_exact_at_volatile(sub_slice, offset),
                None => {
                    unsafe {
                        std::ptr::write_bytes(&mut sub_slice as _, 0, sub_slice.len());
                    }
                    // sub_slice.write_bytes(0);
                    Ok(())
                }
            }
        })
    }

    fn write_at_volatile(&self, slice: VolatileSlice, offset: u64) -> io::Result<usize> {
        let mut inner = self.inner.lock().unwrap();
        inner.write_cb(offset, slice.len(), |file, offset, raw_offset, count| {
            let sub_slice = slice.get_slice(offset, count).unwrap();
            file.write_all_at_volatile(sub_slice, raw_offset)
        })
    }
}

impl FileSync for QcowFile {
    fn fsync(&self) -> std::io::Result<()> {
        let mut inner = self.inner.lock().unwrap();
        inner.sync_caches()?;
        let unref_clusters = std::mem::take(&mut inner.unref_clusters);
        inner.avail_clusters.extend(unref_clusters);
        Ok(())
    }

    fn fdatasync(&self) -> io::Result<()> {
        // QcowFile does not implement fdatasync. Just fall back to fsync.
        self.fsync()
    }
}

impl FileSetLen for QcowFile {
    fn set_len(&self, _len: u64) -> std::io::Result<()> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "set_len() not supported for QcowFile",
        ))
    }
}

impl DiskGetLen for QcowFile {
    fn get_len(&self) -> io::Result<u64> {
        Ok(self.virtual_size)
    }
}

impl FileAllocate for QcowFile {
    fn allocate(&self, offset: u64, len: u64) -> io::Result<()> {
        let mut inner = self.inner.lock().unwrap();
        // Call write_cb with a do-nothing callback, which will have the effect
        // of allocating all clusters in the specified range.
        inner.write_cb(
            offset,
            len as usize,
            |_file, _offset, _raw_offset, _count| Ok(()),
        )?;
        Ok(())
    }
}

impl PunchHole for QcowFile {
    fn punch_hole(&self, offset: u64, length: u64) -> std::io::Result<()> {
        let mut inner = self.inner.lock().unwrap();
        let mut remaining = length;
        let mut offset = offset;
        while remaining > 0 {
            let chunk_length = min(remaining, usize::MAX as u64) as usize;
            inner.zero_bytes(offset, chunk_length)?;
            remaining -= chunk_length as u64;
            offset += chunk_length as u64;
        }
        Ok(())
    }
}

impl WriteZeroesAt for QcowFile {
    fn write_zeroes_at(&self, offset: u64, length: usize) -> io::Result<usize> {
        self.punch_hole(offset, length as u64)?;
        Ok(length)
    }
}
