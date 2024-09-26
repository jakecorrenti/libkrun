#![allow(dead_code)]

use super::super::helpers::{IoBuffer, IoBufferMut, IoBufferRef, IntAlignment};
use super::BlockResult;
use super::file::{Qcow2State, SplitGuestOffset};
use super::IoQueue;
use crate::numerical_enum;
use async_trait::async_trait;
use bincode::Options;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::mem::size_of;

pub const QCOW2_MAGIC: u32 = 0x51_46_49_fb;

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

numerical_enum! {
    pub enum Qcow2HeaderExtensionType as u32 {
        End = 0,
        BackingFileFormat = 0xe2792aca,
        FeatureNameTable = 0x6803f857,
    }
}

#[derive(Default, Deserialize, Serialize)]
#[repr(packed)]
struct Qcow2HeaderExtensionHeader {
    /// Type code of the header extension
    extension_type: u32,

    /// Data length
    length: u32,
}

numerical_enum! {
    #[derive(Hash)]
    pub enum Qcow2FeatureType as u8 {
        Incompatible = 0,
        Compatible = 1,
        Autoclear = 2,
    }
}

#[derive(Debug, Clone)]
pub enum Qcow2HeaderExtension {
    BackingFileFormat(String),
    FeatureNameTable(HashMap<(Qcow2FeatureType, u8), String>),
    Unknown { extension_type: u32, data: Vec<u8> },
}

pub struct Qcow2Header {
    raw: Qcow2RawHeader,
    backing_filename: Option<String>,
    extensions: Vec<Qcow2HeaderExtension>,
}

impl Qcow2Header {
    pub async fn from(queue: &IoQueue, read_only: bool) -> BlockResult<Self> {
        let mut header_buf = vec![0u8; size_of::<Qcow2RawHeader>()];
        queue
            .read(IoBufferMut::from_slice(&mut header_buf), 0)
            .await?;

        let bincode = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_big_endian();

        let header: Qcow2RawHeader = bincode.deserialize(&header_buf)?;
        if header.magic != QCOW2_MAGIC {
            return Err("Not a qcow2 file".into());
        }

        if header.version != 3 {
            let v = header.version;
            return Err(format!("qcow2 v{} is not supported", v).into());
        }

        let cluster_size = 1u64 << header.cluster_bits;

        let backing_filename = if header.backing_file_offset != 0 {
            let (offset, length) = (header.backing_file_offset, header.backing_file_size);
            if length > 1023 {
                return Err(format!(
                    "Backing file name is too long ({}, must not exceed 1023)",
                    length
                )
                .into());
            }

            let end = offset
                .checked_add(length as u64)
                .ok_or("Backing file name offset is invalid (too high)")?;
            if end >= cluster_size {
                return Err("Backing file name offset is invalid (too high)".into());
            }

            let mut backing_buf = vec![0; length as usize];
            queue
                .read(IoBufferMut::from_slice(&mut backing_buf), offset)
                .await?;

            Some(
                String::from_utf8(backing_buf)
                    .map_err(|err| format!("Backing file name is invalid: {}", err))?,
            )
        } else {
            None
        };

        let mut ext_offset: u64 = header.header_length as u64;
        let mut extensions = Vec::<Qcow2HeaderExtension>::new();
        loop {
            if ext_offset + size_of::<Qcow2HeaderExtensionHeader>() as u64 > cluster_size {
                return Err("Header extensions exceed the first cluster".into());
            }

            let mut ext_hdr_buf = vec![0; size_of::<Qcow2HeaderExtensionHeader>()];
            queue
                .read(IoBufferMut::from_slice(&mut ext_hdr_buf), ext_offset)
                .await?;

            ext_offset += size_of::<Qcow2HeaderExtensionHeader>() as u64;

            let ext_hdr: Qcow2HeaderExtensionHeader = bincode.deserialize(&ext_hdr_buf)?;
            if ext_offset + ext_hdr.length as u64 > cluster_size {
                return Err("Header extensions exceed the first cluster".into());
            }

            let mut ext_data = vec![0; ext_hdr.length as usize];
            queue
                .read(IoBufferMut::from_slice(&mut ext_data), ext_offset)
                .await?;

            ext_offset += (ext_hdr.length as u64).align_up(8u64).unwrap();

            let extension = match Qcow2HeaderExtension::from(ext_hdr.extension_type, ext_data)? {
                Some(ext) => ext,
                None => break,
            };

            extensions.push(extension);
        }

        let mut header = Qcow2Header {
            raw: header,
            backing_filename,
            extensions,
        };

        // No need to clear autoclear features for read-only images
        if header.raw.autoclear_features != 0 && !read_only {
            header.raw.autoclear_features = 0;
            header.write(queue).await?;
        }

        if header.raw.incompatible_features != 0 {
            let feats = (0..64)
                .filter(|bit| header.raw.incompatible_features & (1u64 << bit) != 0)
                .map(|bit| {
                    if let Some(name) = header.feature_name(Qcow2FeatureType::Incompatible, bit) {
                        format!("{} ({})", bit, name)
                    } else {
                        format!("{}", bit)
                    }
                })
                .collect::<Vec<String>>();

            return Err(
                format!("Unrecognized incompatible feature(s) {}", feats.join(", ")).into(),
            );
        }

        Ok(header)
    }

    pub async fn write(&mut self, queue: &IoQueue) -> BlockResult<()> {
        let header_len = size_of::<Qcow2RawHeader>().align_up(8usize).unwrap();
        let mut header_exts = self.serialize_extensions()?;

        if let Some(backing) = self.backing_filename.as_ref() {
            self.raw.backing_file_offset = (header_len + header_exts.len()).try_into()?;
            self.raw.backing_file_size = backing.as_bytes().len().try_into()?;
        } else {
            self.raw.backing_file_offset = 0;
            self.raw.backing_file_size = 0;
        }

        let mut full_buf = self.raw.serialize_vec()?;
        full_buf.append(&mut header_exts);
        if let Some(backing) = self.backing_filename.as_ref() {
            full_buf.extend_from_slice(backing.as_bytes());
        }

        if full_buf.len() > 1 << self.raw.cluster_bits {
            return Err(format!(
                "Header is too big to write ({}, larger than a cluster ({}))",
                full_buf.len(),
                1 << self.raw.cluster_bits
            )
            .into());
        }

        queue
            .grow_write(IoBufferRef::from_slice(&full_buf), 0)
            .await
    }

    pub fn size(&self) -> u64 {
        self.raw.size
    }

    pub fn cluster_bits(&self) -> u32 {
        self.raw.cluster_bits
    }

    pub fn refcount_order(&self) -> u32 {
        self.raw.refcount_order
    }

    pub fn l1_table_offset(&self) -> u64 {
        self.raw.l1_table_offset
    }

    pub fn l1_table_entries(&self) -> usize {
        self.raw.l1_size as usize
    }

    pub fn set_l1_table(&mut self, offset: u64, entries: usize) -> BlockResult<()> {
        self.raw.l1_size = entries.try_into()?;
        self.raw.l1_table_offset = offset;
        Ok(())
    }

    pub fn reftable_offset(&self) -> u64 {
        self.raw.refcount_table_offset
    }

    pub fn reftable_clusters(&self) -> usize {
        self.raw.refcount_table_clusters as usize
    }

    pub fn set_reftable(&mut self, offset: u64, clusters: usize) -> BlockResult<()> {
        self.raw.refcount_table_clusters = clusters.try_into()?;
        self.raw.refcount_table_offset = offset;
        Ok(())
    }

    pub fn backing_filename(&self) -> Option<&String> {
        self.backing_filename.as_ref()
    }

    pub fn backing_format(&self) -> Option<&String> {
        for e in &self.extensions {
            if let Qcow2HeaderExtension::BackingFileFormat(fmt) = e {
                return Some(fmt);
            }
        }

        None
    }

    pub fn feature_name(&self, feat_type: Qcow2FeatureType, bit: u32) -> Option<&String> {
        for e in &self.extensions {
            if let Qcow2HeaderExtension::FeatureNameTable(names) = e {
                if let Some(name) = names.get(&(feat_type, bit as u8)) {
                    return Some(name);
                }
            }
        }

        None
    }

    fn serialize_extensions(&self) -> BlockResult<Vec<u8>> {
        let bincode = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_big_endian();

        let mut result = Vec::new();
        for e in &self.extensions {
            let mut data = e.serialize_data()?;
            let ext_hdr = Qcow2HeaderExtensionHeader {
                extension_type: e.extension_type(),
                length: data.len().try_into()?,
            };
            result.append(&mut bincode.serialize(&ext_hdr)?);
            result.append(&mut data);
            result.resize(result.len().align_up(8usize).unwrap(), 0);
        }

        let end_ext = Qcow2HeaderExtensionHeader {
            extension_type: Qcow2HeaderExtensionType::End as u32,
            length: 0,
        };
        result.append(&mut bincode.serialize(&end_ext)?);
        result.resize(result.len().align_up(8usize).unwrap(), 0);

        Ok(result)
    }
}

impl Qcow2RawHeader {
    pub fn serialize_vec(&mut self) -> BlockResult<Vec<u8>> {
        self.header_length = size_of::<Self>().align_up(8usize).unwrap().try_into()?;

        let bincode = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_big_endian();

        let mut header_buf = bincode.serialize(self)?;
        header_buf.resize(header_buf.len().align_up(8usize).unwrap(), 0);

        assert!(header_buf.len() == self.header_length as usize);

        Ok(header_buf)
    }
}

impl Qcow2HeaderExtension {
    /// Parse an extension from its type and data.  Unrecognized types are stored as `Unknown`
    /// extensions, encountering the end of extensions returns `Ok(None)`.
    fn from(ext_type: u32, data: Vec<u8>) -> BlockResult<Option<Self>> {
        let ext = if let Ok(ext_type) = Qcow2HeaderExtensionType::try_from(ext_type) {
            match ext_type {
                Qcow2HeaderExtensionType::End => return Ok(None),
                Qcow2HeaderExtensionType::BackingFileFormat => {
                    let fmt = String::from_utf8(data)
                        .map_err(|err| format!("Invalid backing file format: {}", err))?;
                    Qcow2HeaderExtension::BackingFileFormat(fmt)
                }
                Qcow2HeaderExtensionType::FeatureNameTable => {
                    let mut feats = HashMap::new();
                    for feat in data.chunks(48) {
                        let feat_type: Qcow2FeatureType = match feat[0].try_into() {
                            Ok(ft) => ft,
                            Err(_) => continue, // skip unrecognized entries
                        };
                        let feat_name = String::from(
                            String::from_utf8_lossy(&feat[2..]).trim_end_matches('\0'),
                        );

                        feats.insert((feat_type, feat[1]), feat_name);
                    }
                    Qcow2HeaderExtension::FeatureNameTable(feats)
                }
            }
        } else {
            Qcow2HeaderExtension::Unknown {
                extension_type: ext_type,
                data,
            }
        };

        Ok(Some(ext))
    }

    fn extension_type(&self) -> u32 {
        match self {
            Qcow2HeaderExtension::BackingFileFormat(_) => {
                Qcow2HeaderExtensionType::BackingFileFormat as u32
            }
            Qcow2HeaderExtension::FeatureNameTable(_) => {
                Qcow2HeaderExtensionType::FeatureNameTable as u32
            }
            Qcow2HeaderExtension::Unknown {
                extension_type,
                data: _,
            } => *extension_type,
        }
    }

    fn serialize_data(&self) -> BlockResult<Vec<u8>> {
        match self {
            Qcow2HeaderExtension::BackingFileFormat(fmt) => Ok(fmt.as_bytes().into()),
            Qcow2HeaderExtension::FeatureNameTable(map) => {
                let mut result = Vec::new();
                for (bit, name) in map {
                    result.push(bit.0 as u8);
                    result.push(bit.1);

                    let mut padded_name = vec![0; 46];
                    let name_bytes = name.as_bytes();
                    // Might truncate in the middle of a multibyte character, but getting that
                    // right is complicated and probably not worth it
                    let truncated_len = std::cmp::min(name_bytes.len(), 46);
                    padded_name[..truncated_len].copy_from_slice(&name_bytes[..truncated_len]);
                    result.extend_from_slice(&padded_name);
                }
                Ok(result)
            }
            Qcow2HeaderExtension::Unknown {
                extension_type: _,
                data,
            } => Ok(data.clone()),
        }
    }
}

/// L1 table entry:
///
/// Bit  0 -  8:     Reserved (set to 0)
///
///      9 - 55:     Bits 9-55 of the offset into the image file at which the L2
///                  table starts. Must be aligned to a cluster boundary. If the
///                  offset is 0, the L2 table and all clusters described by this
///                  L2 table are unallocated.
///
///      56 - 62:    Reserved (set to 0)
///
///      63:         0 for an L2 table that is unused or requires COW, 1 if its
///                  refcount is exactly one. This information is only accurate
///                  in the active L1 table.
#[derive(Copy, Clone, Default, Debug)]
pub struct L1Entry(u64);

impl L1Entry {
    pub fn l2_offset(&self) -> u64 {
        self.0 & 0x00ff_ffff_ffff_fe00u64
    }

    pub fn is_copied(&self) -> bool {
        self.0 & (1u64 << 63) != 0
    }

    pub fn is_zero(&self) -> bool {
        self.l2_offset() == 0
    }

    pub fn reserved_bits(&self) -> u64 {
        self.0 & 0x7f00_0000_0000_01feu64
    }
}

impl TableEntry for L1Entry {
    fn try_from_plain(value: u64, qcow2_file: &Qcow2State) -> BlockResult<Self> {
        let entry = L1Entry(value);

        if entry.reserved_bits() != 0 {
            return Err(format!(
                "Invalid L1 entry 0x{:x}, reserved bits set (0x{:x})",
                value,
                entry.reserved_bits()
            )
            .into());
        }

        if qcow2_file.in_cluster_offset(entry.l2_offset()) != 0 {
            return Err(format!(
                "Invalid L1 entry 0x{:x}, offset (0x{:x}) is not aligned to cluster size (0x{:x})",
                value,
                entry.l2_offset(),
                qcow2_file.cluster_size()
            )
            .into());
        }

        Ok(entry)
    }

    fn into_plain(self) -> u64 {
        self.0
    }
}

#[derive(Debug, Clone)]
pub struct L1Table {
    offset: Option<u64>,
    data: Box<[L1Entry]>,
}

impl L1Table {
    pub fn empty() -> Self {
        Self {
            offset: None,
            data: Default::default(),
        }
    }

    /// Create a clone that covers at least `at_least_index`
    pub fn clone_and_grow(&self, at_least_index: usize, cluster_size: usize) -> Self {
        let new_size = std::cmp::max(at_least_index + 1, self.data.len());
        let new_size = new_size.align_up(cluster_size).unwrap();
        let mut new_data = vec![L1Entry::default(); new_size];
        new_data[..self.data.len()].copy_from_slice(&self.data);

        Self {
            offset: None,
            data: new_data.into_boxed_slice(),
        }
    }

    pub fn in_bounds(&self, index: usize) -> bool {
        index < self.data.len()
    }

    pub fn map_l2_offset(&mut self, index: usize, l2_offset: u64) {
        let l1entry = L1Entry((1 << 63) | l2_offset);
        debug_assert!(l1entry.reserved_bits() == 0);
        self.set(index, l1entry);
    }
}

impl From<Box<[L1Entry]>> for L1Table {
    fn from(data: Box<[L1Entry]>) -> Self {
        Self { offset: None, data }
    }
}

impl Table for L1Table {
    type Entry = L1Entry;

    fn entries(&self) -> usize {
        self.data.len()
    }

    fn get(&self, index: usize) -> L1Entry {
        match self.data.get(index) {
            Some(entry) => *entry,
            None => L1Entry(0),
        }
    }

    fn set(&mut self, index: usize, l1_entry: L1Entry) {
        self.data[index] = l1_entry;
    }

    fn get_offset(&self) -> Option<u64> {
        self.offset
    }

    fn set_offset(&mut self, offset: u64) {
        self.offset = Some(offset);
    }
}

/// L2 table entry:
///
/// Bit  0 -  61:    Cluster descriptor
///
///      62:         0 for standard clusters
///                  1 for compressed clusters
///
///      63:         0 for clusters that are unused, compressed or require COW.
///                  1 for standard clusters whose refcount is exactly one.
///                  This information is only accurate in L2 tables
///                  that are reachable from the active L1 table.
///
///                  With external data files, all guest clusters have an
///                  implicit refcount of 1 (because of the fixed host = guest
///                  mapping for guest cluster offsets), so this bit should be 1
///                  for all allocated clusters.
///
/// Standard Cluster Descriptor:
///
///     Bit       0:    If set to 1, the cluster reads as all zeros. The host
///                     cluster offset can be used to describe a preallocation,
///                     but it won't be used for reading data from this cluster,
///                     nor is data read from the backing file if the cluster is
///                     unallocated.
///
///                     With version 2 or with extended L2 entries (see the next
///                     section), this is always 0.
///
///          1 -  8:    Reserved (set to 0)
///
///          9 - 55:    Bits 9-55 of host cluster offset. Must be aligned to a
///                     cluster boundary. If the offset is 0 and bit 63 is clear,
///                     the cluster is unallocated. The offset may only be 0 with
///                     bit 63 set (indicating a host cluster offset of 0) when an
///                     external data file is used.
///
///         56 - 61:    Reserved (set to 0)
#[derive(Copy, Clone, Default, Debug)]
pub struct L2Entry(u64);

#[derive(Debug, Clone)]
pub struct Mapping {
    /// Where/how to get the mapped data from
    pub source: MappingSource,
    /// Offset in `source` from which to read the whole cluster data; for compressed clusters, this
    /// is generally not aligned to a cluster boundary
    pub cluster_offset: Option<u64>,
    /// For compressed data: Upper limit on the number of bytes that comprise the compressed data
    pub compressed_length: Option<usize>,
    /// If this is true, `cluster_offset` may be written to, and doing so will only change this
    /// cluster's data (note that for zero clusters, writing to a COPIED cluster will not change
    /// the visible data: first, the mapping must be changed to be a data cluster)
    pub copied: bool,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum MappingSource {
    /// Read the mapped data from the data file
    DataFile,
    /// Read the mapped data from the backing file
    Backing,
    /// This is zero data; use memset(0) instead of reading it
    Zero,
    /// Read compressed data from the data file
    Compressed,
}

impl L2Entry {
    pub fn cluster_offset(&self) -> u64 {
        self.0 & 0x00ff_ffff_ffff_fe00u64
    }

    pub fn is_compressed(&self) -> bool {
        self.0 & (1u64 << 62) != 0
    }

    pub fn is_copied(&self) -> bool {
        self.0 & (1u64 << 63) != 0
    }

    pub fn is_zero(&self) -> bool {
        self.0 & (1u64 << 0) != 0
    }

    pub fn reserved_bits(&self) -> u64 {
        if self.is_compressed() {
            self.0 & 0x8000_0000_0000_0000u64
        } else {
            self.0 & 0x3f00_0000_0000_01feu64
        }
    }

    pub fn compressed_descriptor(&self) -> u64 {
        self.0 & 0x3fff_ffff_ffff_ffffu64
    }

    /// If this entry is compressed, return the start host offset and upper limit on the compressed
    /// number of bytes
    pub fn compressed_range(&self, cluster_bits: u32) -> Option<(u64, usize)> {
        if self.is_compressed() {
            let desc = self.compressed_descriptor();
            let compressed_offset_bits = 62 - (cluster_bits - 8);
            let offset = desc & ((1 << compressed_offset_bits) - 1) & 0x00ff_ffff_ffff_ffffu64;
            let sectors = (desc >> compressed_offset_bits) as usize;
            // The first sector is not considered in `sectors`, so we add it and subtract the
            // number of bytes there that do not belong to this compressed cluster
            let length = (sectors + 1) * 512 - (offset & 511) as usize;

            Some((offset, length))
        } else {
            None
        }
    }

    /// If this entry is allocated, return the host cluster offset and the number of clusters it
    /// references
    pub fn allocation(&self, cluster_bits: u32) -> Option<(u64, usize)> {
        if let Some((offset, length)) = self.compressed_range(cluster_bits) {
            // Compressed clusters can cross host cluster boundaries, and thus occupy two clusters
            let cluster_size = 1u64 << cluster_bits;
            let cluster_base = offset & !(cluster_size - 1);
            let clusters =
                ((offset + length as u64 + cluster_size - 1) - cluster_base) >> cluster_bits;
            Some((cluster_base, clusters as usize))
        } else {
            match self.cluster_offset() {
                0 => None,
                ofs => Some((ofs, 1)),
            }
        }
    }

    pub fn into_mapping(self, guest_addr: &SplitGuestOffset, cluster_bits: u32) -> Mapping {
        if let Some((offset, length)) = self.compressed_range(cluster_bits) {
            Mapping {
                source: MappingSource::Compressed,
                cluster_offset: Some(offset),
                compressed_length: Some(length),
                copied: false,
            }
        } else if self.is_zero() {
            let offset = match self.cluster_offset() {
                0 => None,
                ofs => Some(ofs),
            };

            Mapping {
                source: MappingSource::Zero,
                cluster_offset: offset,
                compressed_length: None,
                copied: offset.is_some() && self.is_copied(),
            }
        } else {
            match self.cluster_offset() {
                0 => Mapping {
                    source: MappingSource::Backing,
                    cluster_offset: Some(guest_addr.cluster_offset(cluster_bits)),
                    compressed_length: None,
                    copied: false,
                },
                ofs => Mapping {
                    source: MappingSource::DataFile,
                    cluster_offset: Some(ofs),
                    compressed_length: None,
                    copied: self.is_copied(),
                },
            }
        }
    }

    pub fn from_mapping(value: Mapping, cluster_bits: u32) -> Self {
        debug_assert!(value.cluster_offset.unwrap_or(0) <= 0x00ff_ffff_ffff_ffffu64);

        let num_val: u64 = match value.source {
            MappingSource::DataFile => {
                debug_assert!(value.compressed_length.is_none());
                if value.copied {
                    (1 << 63) | value.cluster_offset.unwrap()
                } else {
                    value.cluster_offset.unwrap()
                }
            }

            MappingSource::Backing => {
                debug_assert!(value.compressed_length.is_none() && !value.copied);
                0
            }

            MappingSource::Zero => {
                debug_assert!(value.compressed_length.is_none());
                if value.copied {
                    (1 << 63) | value.cluster_offset.unwrap() | 0x1
                } else {
                    value.cluster_offset.unwrap_or(0) | 0x1
                }
            }

            MappingSource::Compressed => {
                debug_assert!(!value.copied);
                let compressed_offset_bits = 62 - (cluster_bits - 8);
                let offset = value.cluster_offset.unwrap();
                let length = value.compressed_length.unwrap();
                assert!(length < 1 << cluster_bits);

                // The first sector is not considered, so we subtract the number of bytes in it
                // that belong to this compressed cluster from `length`:
                // ceil((length - (512 - (offset & 511))) / 512)
                // = (length + 511 - 512 + (offset & 511)) / 512
                let sectors = (length - 1 + (offset & 511) as usize) / 512;

                (1 << 62) | ((sectors as u64) << compressed_offset_bits) | offset
            }
        };

        let entry = L2Entry(num_val);
        debug_assert!(entry.reserved_bits() == 0);
        entry
    }
}

impl Mapping {
    pub fn plain_offset(&self, in_cluster_offset: usize) -> Option<u64> {
        (self.source == MappingSource::DataFile && self.copied)
            .then(|| self.cluster_offset.unwrap() + in_cluster_offset as u64)
    }
}

impl TableEntry for L2Entry {
    fn try_from_plain(value: u64, qcow2_file: &Qcow2State) -> BlockResult<Self> {
        let entry = L2Entry(value);

        if entry.reserved_bits() != 0 {
            return Err(format!(
                "Invalid L2 entry 0x{:x}, reserved bits set (0x{:x})",
                value,
                entry.reserved_bits()
            )
            .into());
        }

        if !entry.is_compressed() && qcow2_file.in_cluster_offset(entry.cluster_offset()) != 0 {
            return Err(format!(
                "Invalid L2 entry 0x{:x}, offset (0x{:x}) is not aligned to cluster size (0x{:x})",
                value,
                entry.cluster_offset(),
                qcow2_file.cluster_size()
            )
            .into());
        }

        Ok(entry)
    }

    fn into_plain(self) -> u64 {
        self.0
    }
}

// Given an offset into the virtual disk, the offset into the image file can be
// obtained as follows:
//
// l2_entries = (cluster_size / sizeof(uint64_t))        [*]
//
// l2_index = (offset / cluster_size) % l2_entries
// l1_index = (offset / cluster_size) / l2_entries
//
// l2_table = load_cluster(l1_table[l1_index]);
// cluster_offset = l2_table[l2_index];
//
// return cluster_offset + (offset % cluster_size)
//
// [*] this changes if Extended L2 Entries are enabled, see next section
#[derive(Debug, Clone)]
pub struct L2Table {
    offset: Option<u64>,
    cluster_bits: u32,
    data: Box<[L2Entry]>,
}

impl L2Table {
    pub fn get_mapping(&self, lookup_addr: &SplitGuestOffset) -> Mapping {
        self.data[lookup_addr.l2_index].into_mapping(lookup_addr, self.cluster_bits)
    }

    /// If the previous entry pointed to an allocated cluster, return the old allocation so its
    /// refcount can be decreased (offset of the first cluster and number of clusters -- compressed
    /// clusters can span across host cluster boundaries).
    /// If the allocation is reused, `None` is returned, so this function only returns `Some(_)` if
    /// some cluster is indeed leaked.
    #[must_use]
    pub fn map_cluster(&mut self, index: usize, host_cluster: u64) -> Option<(u64, usize)> {
        let allocation = self.data[index].allocation(self.cluster_bits);

        self.data[index] = L2Entry::from_mapping(
            Mapping {
                source: MappingSource::DataFile,
                cluster_offset: Some(host_cluster),
                compressed_length: None,
                copied: true,
            },
            self.cluster_bits,
        );

        if let Some((a_offset, a_count)) = allocation {
            if a_offset == host_cluster && a_count == 1 {
                None
            } else {
                allocation
            }
        } else {
            None
        }
    }
}

impl From<Box<[L2Entry]>> for L2Table {
    fn from(data: Box<[L2Entry]>) -> Self {
        Self {
            offset: None,
            // Bit cheeky, but this must always be so (without subclusters)
            cluster_bits: (data.len() * size_of::<u64>()).trailing_zeros(),
            data,
        }
    }
}

impl Table for L2Table {
    type Entry = L2Entry;

    fn entries(&self) -> usize {
        self.data.len()
    }

    fn get(&self, index: usize) -> L2Entry {
        match self.data.get(index) {
            Some(entry) => *entry,
            None => L2Entry(0),
        }
    }

    fn set(&mut self, index: usize, l2_entry: L2Entry) {
        self.data[index] = l2_entry;
    }

    fn get_offset(&self) -> Option<u64> {
        self.offset
    }

    fn set_offset(&mut self, offset: u64) {
        self.offset = Some(offset);
    }
}

#[derive(Copy, Clone, Default, Debug)]
pub struct RefTableEntry(u64);

impl RefTableEntry {
    pub fn refblock_offset(&self) -> u64 {
        self.0 & 0xffff_ffff_ffff_fe00u64
    }

    pub fn is_empty(&self) -> bool {
        self.refblock_offset() == 0
    }

    pub fn reserved_bits(&self) -> u64 {
        self.0 & 0x0000_0000_0000_01ffu64
    }
}

impl TableEntry for RefTableEntry {
    fn try_from_plain(value: u64, qcow2_file: &Qcow2State) -> BlockResult<Self> {
        let entry = RefTableEntry(value);

        if entry.reserved_bits() != 0 {
            return Err(format!(
                "Invalid reftable entry 0x{:x}, reserved bits set (0x{:x})",
                value,
                entry.reserved_bits()
            )
            .into());
        }

        if qcow2_file.in_cluster_offset(entry.refblock_offset()) != 0 {
            return Err(format!(
                "Invalid reftable entry 0x{:x}, offset (0x{:x}) is not aligned to cluster size (0x{:x})",
                value,
                entry.refblock_offset(),
                qcow2_file.cluster_size()
            )
            .into());
        }

        Ok(entry)
    }

    fn into_plain(self) -> u64 {
        self.0
    }
}

#[derive(Debug, Clone)]
pub struct RefTable {
    offset: Option<u64>,
    data: Box<[RefTableEntry]>,
}

impl RefTable {
    pub fn empty() -> Self {
        Self {
            offset: None,
            data: Default::default(),
        }
    }

    /// Create a clone that covers at least `at_least_index`
    pub fn clone_and_grow(&self, at_least_index: usize, cluster_size: usize) -> Self {
        let new_size = std::cmp::max(at_least_index + 1, self.data.len());
        let new_size = new_size.align_up(cluster_size).unwrap();
        let mut new_data = vec![RefTableEntry::default(); new_size];
        new_data[..self.data.len()].copy_from_slice(&self.data);

        Self {
            offset: None,
            data: new_data.into_boxed_slice(),
        }
    }

    pub fn in_bounds(&self, index: usize) -> bool {
        index < self.data.len()
    }

    pub fn set_refblock_offset(&mut self, index: usize, rb_offset: u64) {
        let rt_entry = RefTableEntry(rb_offset);
        debug_assert!(rt_entry.reserved_bits() == 0);
        self.set(index, rt_entry);
    }
}

impl From<Box<[RefTableEntry]>> for RefTable {
    fn from(data: Box<[RefTableEntry]>) -> Self {
        Self { offset: None, data }
    }
}

impl Table for RefTable {
    type Entry = RefTableEntry;

    fn entries(&self) -> usize {
        self.data.len()
    }

    fn get(&self, index: usize) -> RefTableEntry {
        match self.data.get(index) {
            Some(entry) => *entry,
            None => RefTableEntry(0),
        }
    }

    fn set(&mut self, index: usize, rt_entry: RefTableEntry) {
        self.data[index] = rt_entry;
    }

    fn get_offset(&self) -> Option<u64> {
        self.offset
    }

    fn set_offset(&mut self, offset: u64) {
        self.offset = Some(offset);
    }
}

pub struct RefBlock {
    offset: Option<u64>,
    raw_data: Box<[u8]>,
    refcount_order: u32,
}

impl RefBlock {
    pub fn new_cleared(qcow2_file: &Qcow2State) -> Self {
        RefBlock {
            offset: None,
            raw_data: vec![0u8; qcow2_file.cluster_size()].into_boxed_slice(),
            refcount_order: qcow2_file.refcount_order(),
        }
    }

    pub async fn load(qcow2_file: &Qcow2State, queue: &IoQueue, offset: u64) -> BlockResult<Self> {
        let mut raw_data = vec![0u8; qcow2_file.cluster_size()];
        queue
            .read(IoBufferMut::from_slice(&mut raw_data), offset)
            .await?;

        Ok(RefBlock {
            offset: Some(offset),
            raw_data: raw_data.into_boxed_slice(),
            refcount_order: qcow2_file.refcount_order(),
        })
    }

    pub async fn write(&self, queue: &IoQueue) -> BlockResult<()> {
        let offset = self
            .offset
            .ok_or("Cannot write qcow2 refcount block, no offset set")?;

        queue
            .grow_write(IoBufferRef::from_slice(&self.raw_data), offset)
            .await
    }

    pub fn get_offset(&self) -> Option<u64> {
        self.offset
    }

    pub fn set_offset(&mut self, offset: u64) {
        self.offset = Some(offset);
    }

    pub fn get(&self, index: usize) -> u64 {
        match self.refcount_order {
            // refcount_bits == 1
            0 => ((self.raw_data[index / 8] >> (index % 8)) & 0b0000_0001) as u64,

            // refcount_bits == 2
            1 => ((self.raw_data[index / 4] >> (index % 4)) & 0b0000_0011) as u64,

            // refcount_bits == 4
            2 => ((self.raw_data[index / 2] >> (index % 2)) & 0b0000_1111) as u64,

            // refcount_bits == 8
            3 => self.raw_data[index] as u64,

            // refcount_bits == 16
            4 => u16::from_be_bytes(self.raw_data[index * 2..index * 2 + 2].try_into().unwrap())
                as u64,

            // refcount_bits == 32
            5 => u32::from_be_bytes(self.raw_data[index * 4..index * 4 + 4].try_into().unwrap())
                as u64,

            // refcount_bits == 64
            6 => u64::from_be_bytes(self.raw_data[index * 8..index * 8 + 8].try_into().unwrap()),

            _ => unreachable!(),
        }
    }

    fn set(&mut self, index: usize, value: u64) -> BlockResult<()> {
        match self.refcount_order {
            // refcount_bits == 1
            0 => {
                if value > 0b0000_0001 {
                    return Err(format!(
                        "Cannot increase refcount beyond {} with refcount_bits=1",
                        0b0000_0001
                    )
                    .into());
                }
                self.raw_data[index / 8] = (self.raw_data[index / 8]
                    & !(0b0000_0001 << (index % 8)))
                    | ((value as u8) << (index % 8));
            }

            // refcount_bits == 2
            1 => {
                if value > 0b0000_0011 {
                    return Err(format!(
                        "Cannot increase refcount beyond {} with refcount_bits=2",
                        0b0000_0011
                    )
                    .into());
                }
                self.raw_data[index / 4] = (self.raw_data[index / 4]
                    & !(0b0000_0011 << (index % 4)))
                    | ((value as u8) << (index % 4));
            }

            // refcount_bits == 4
            2 => {
                if value > 0b0000_1111 {
                    return Err(format!(
                        "Cannot increase refcount beyond {} with refcount_bits=4",
                        0b0000_1111
                    )
                    .into());
                }
                self.raw_data[index / 2] = (self.raw_data[index / 2]
                    & !(0b0000_1111 << (index % 2)))
                    | ((value as u8) << (index % 2));
            }

            // refcount_bits == 8
            3 => {
                if value > u8::MAX as u64 {
                    return Err(format!(
                        "Cannot increase refcount beyond {} with refcount_bits=8",
                        u8::MAX
                    )
                    .into());
                }
                self.raw_data[index] = value as u8;
            }

            // refcount_bits == 16
            4 => {
                if value > u16::MAX as u64 {
                    return Err(format!(
                        "Cannot increase refcount beyond {} with refcount_bits=16",
                        u16::MAX
                    )
                    .into());
                }
                self.raw_data[index * 2] = (value >> 8) as u8;
                self.raw_data[index * 2 + 1] = value as u8;
            }

            // refcount_bits == 32
            5 => {
                if value > u32::MAX as u64 {
                    return Err(format!(
                        "Cannot increase refcount beyond {} with refcount_bits=32",
                        u32::MAX
                    )
                    .into());
                }
                self.raw_data[index * 4] = (value >> 24) as u8;
                self.raw_data[index * 4 + 1] = (value >> 16) as u8;
                self.raw_data[index * 4 + 2] = (value >> 8) as u8;
                self.raw_data[index * 4 + 3] = value as u8;
            }

            // refcount_bits == 64
            6 => {
                let array: &mut [u8; 8] = (&mut self.raw_data[index * 8..index * 8 + 8])
                    .try_into()
                    .unwrap();
                *array = value.to_be_bytes();
            }

            _ => unreachable!(),
        }

        Ok(())
    }

    pub fn is_zero(&self, index: usize) -> bool {
        self.get(index) == 0
    }

    pub fn increment(&mut self, index: usize) -> BlockResult<()> {
        let val = self
            .get(index)
            .checked_add(1)
            .ok_or_else(|| format!("Cannot increase refcount beyond {}", u64::MAX))?;
        self.set(index, val)
    }

    pub fn decrement(&mut self, index: usize) -> BlockResult<()> {
        let val = self
            .get(index)
            .checked_sub(1)
            .ok_or("Cannot decrease refcount below 0")?;
        self.set(index, val)
    }

    fn byte_indices(&self, index: usize) -> std::ops::RangeInclusive<usize> {
        match self.refcount_order {
            0 => index / 8..=index / 8,
            1 => index / 4..=index / 4,
            2 => index / 2..=index / 2,
            3 => index..=index,
            4 => index * 2..=index * 2 + 1,
            5 => index * 4..=index * 4 + 3,
            6 => index * 8..=index * 8 + 7,
            _ => unreachable!(),
        }
    }
}

pub trait TableEntry
where
    Self: Copy + Sized,
{
    fn try_from_plain(value: u64, qcow2_file: &Qcow2State) -> BlockResult<Self>;
    fn into_plain(self) -> u64;
}

#[async_trait(?Send)]
pub trait Table: From<Box<[Self::Entry]>> {
    type Entry: TableEntry;

    fn entries(&self) -> usize;
    fn get(&self, index: usize) -> Self::Entry;
    fn set(&mut self, index: usize, value: Self::Entry);
    fn get_offset(&self) -> Option<u64>;
    fn set_offset(&mut self, offset: u64);

    fn byte_size(&self) -> usize {
        self.entries() * size_of::<u64>()
    }

    fn cluster_count(&self, qcow2_file: &Qcow2State) -> usize {
        (self.byte_size() + qcow2_file.cluster_size() - 1) / qcow2_file.cluster_size()
    }

    async fn load(
        qcow2_file: &Qcow2State,
        queue: &IoQueue,
        offset: u64,
        entries: usize,
    ) -> BlockResult<Self> {
        let byte_size = entries * size_of::<u64>();

        let mut buffer = IoBuffer::new(
            byte_size,
            std::cmp::max(queue.mem_align(), size_of::<u64>()),
        )?;
        queue.read(buffer.as_mut(), offset).await?;

        let raw_table = unsafe { buffer.as_ref().into_typed_slice::<u64>() };

        let mut table = Vec::<Self::Entry>::with_capacity(entries);
        for be_value in raw_table {
            table.push(Self::Entry::try_from_plain(
                u64::from_be(*be_value),
                qcow2_file,
            )?)
        }

        let mut table: Self = table.into_boxed_slice().into();
        table.set_offset(offset);
        Ok(table)
    }

    async fn write(&self, queue: &IoQueue) -> BlockResult<()> {
        let byte_size = self.byte_size();
        let offset = self
            .get_offset()
            .ok_or("Cannot write qcow2 metadata table, no offset set")?;

        let mut buffer = IoBuffer::new(
            byte_size,
            std::cmp::max(queue.mem_align(), size_of::<u64>()),
        )?;

        // Safe because we have just allocated this, and it fits the alignment
        let raw_table = unsafe { buffer.as_mut().into_typed_slice::<u64>() };
        for (i, be_value) in raw_table.iter_mut().enumerate() {
            *be_value = self.get(i).into_plain().to_be();
        }

        queue.grow_write(buffer.as_ref(), offset).await
    }

    async fn write_entry(&self, queue: &IoQueue, index: usize) -> BlockResult<()> {
        let offset = self
            .get_offset()
            .ok_or("Cannot write qcow2 metadata table, no offset set")?;

        let mut buffer = IoBuffer::new(
            size_of::<u64>(),
            std::cmp::max(queue.mem_align(), size_of::<u64>()),
        )?;

        // Safe because we have just allocated this, and it fits the alignment
        let raw_entry = unsafe { buffer.as_mut().into_typed_slice::<u64>() };
        raw_entry[0] = self.get(index).into_plain().to_be();

        queue
            .grow_write(buffer.as_ref(), offset + (index * size_of::<u64>()) as u64)
            .await
    }
}
