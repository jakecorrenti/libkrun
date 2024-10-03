mod qcow_raw_file;
mod refcount;
mod vec_cache;

use std::cmp::{max, min};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::sync::Mutex;

use qcow_raw_file::QcowRawFile;
use refcount::RefCount;
use vec_cache::{CacheMap, VecCache};

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
}
