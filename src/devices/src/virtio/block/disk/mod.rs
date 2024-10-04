// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

mod base;
pub mod qcow;
pub mod sys;

use crate::virtio::file_traits::{FileReadWriteAtVolatile, FileSetLen, FileSync};

use crate::virtio::block::disk::base::descriptor::AsRawDescriptors;
use crate::virtio::block::disk::qcow::QcowFile;
use std::fmt::Debug;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;

/// Nesting depth limit for disk formats that can open other disk files.
const MAX_NESTING_DEPTH: u32 = 10;

#[derive(Debug)]
pub enum Error {
    MaxNestingDepthExceeded,
    OpenFile(String, base::errno::Error),
    QcowError(qcow::Error),
    ReadingHeader(io::Error),
    SeekingFile(io::Error),
    UnknownType,
    LockFileFailure(base::errno::Error),
    DirectFailed(base::errno::Error),
}

type Result<T> = std::result::Result<T, Error>;

/// The variants of image files on the host that can be used as virtual disks.
#[derive(Debug, PartialEq, Eq)]
pub enum ImageType {
    Raw,
    Qcow2,
}

pub struct DiskFileParams {
    pub path: PathBuf,
    pub is_read_only: bool,
    // Whether to call `base::set_sparse_file` on the file. Currently only affects Windows and is
    // irrelevant for read only files.
    pub is_sparse_file: bool,
    // Whether to open the file in overlapped mode. Only affects Windows.
    pub is_overlapped: bool,
    // Whether to disable OS page caches / buffering.
    pub is_direct: bool,
    // Whether to lock the file.
    pub lock: bool,
    // The nesting depth of the file. Used to avoid infinite recursion. Users outside the disk
    // crate should set this to zero.
    pub depth: u32,
}

/// A trait for getting the length of a disk image or raw block device.
pub trait DiskGetLen {
    /// Get the current length of the disk in bytes.
    fn get_len(&self) -> io::Result<u64>;
}
impl DiskGetLen for File {
    fn get_len(&self) -> io::Result<u64> {
        let mut s = self;
        let orig_seek = s.stream_position()?;
        let end = s.seek(SeekFrom::End(0))?;
        s.seek(SeekFrom::Start(orig_seek))?;
        Ok(end)
    }
}
/// Detect the type of an image file by checking for a valid header of the supported formats.
pub fn detect_image_type(file: &File, overlapped_mode: bool) -> Result<ImageType> {
    let mut f = file;
    let disk_size = f.get_len().map_err(Error::SeekingFile)?;
    let orig_seek = f.stream_position().map_err(Error::SeekingFile)?;

    // Try to read the disk in a nicely-aligned block size unless the whole file is smaller.
    const MAGIC_BLOCK_SIZE: usize = 4096;

    #[repr(align(4096))]
    struct BlockAlignedBuffer {
        data: [u8; MAGIC_BLOCK_SIZE],
    }

    let mut magic = BlockAlignedBuffer {
        data: [0u8; MAGIC_BLOCK_SIZE],
    };

    let magic_read_len = if disk_size > MAGIC_BLOCK_SIZE as u64 {
        MAGIC_BLOCK_SIZE
    } else {
        // This cast is safe since we know disk_size is less than MAGIC_BLOCK_SIZE (4096) and
        // therefore is representable in usize.
        disk_size as usize
    };

    read_from_disk(f, 0, &mut magic.data[0..magic_read_len], overlapped_mode)?;

    f.seek(SeekFrom::Start(orig_seek))
        .map_err(Error::SeekingFile)?;

    #[allow(unused_variables)] // magic4 is only used with the qcow or android-sparse features.
    if let Some(magic4) = magic.data.get(0..4) {
        if magic4 == qcow::QCOW_MAGIC.to_be_bytes() {
            return Ok(ImageType::Qcow2);
        }
    }

    Ok(ImageType::Raw)
}

pub fn read_from_disk(
    mut file: &File,
    offset: u64,
    buf: &mut [u8],
    _overlapped_mode: bool,
) -> Result<()> {
    file.seek(SeekFrom::Start(offset))
        .map_err(Error::SeekingFile)?;
    file.read_exact(buf).map_err(Error::ReadingHeader)
}

/// The prerequisites necessary to support a block device.
pub trait DiskFile:
    FileSetLen + DiskGetLen + FileReadWriteAtVolatile + Send + Debug + Write + AsRawDescriptors
{
    /// Creates a new DiskFile instance that shares the same underlying disk file image. IO
    /// operations to a DiskFile should affect all DiskFile instances with the same underlying disk
    /// file image.
    ///
    /// `try_clone()` returns [`io::ErrorKind::Unsupported`] Error if a DiskFile does not support
    /// creating an instance with the same underlying disk file image.
    fn try_clone(&self) -> io::Result<Box<dyn DiskFile>> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "unsupported operation",
        ))
    }
    fn flush(&self) -> io::Result<()>;
    fn sync_all(&self) -> io::Result<()>;
}

impl DiskFile for QcowFile {
    fn flush(&self) -> io::Result<()> {
        self.fsync()
    }

    fn sync_all(&self) -> io::Result<()> {
        self.sync_all()
    }
}

impl DiskFile for File {
    fn try_clone(&self) -> io::Result<Box<dyn DiskFile>> {
        Ok(Box::new(self.try_clone()?))
    }
    fn flush(&self) -> io::Result<()> {
        // I don't fully understand why calling the underlying File type's flush() will infinitely
        // hang, but CrosVM does a noop here because "Nothing to flush, all file mutations are
        // immediately sent to the OS."
        Ok(())
    }
    fn sync_all(&self) -> io::Result<()> {
        self.sync_all()
    }
}

/// Inspect the image file type and create an appropriate disk file to match it.
pub fn open_disk_file(params: DiskFileParams) -> Result<Box<dyn DiskFile>> {
    if params.depth > MAX_NESTING_DEPTH {
        return Err(Error::MaxNestingDepthExceeded);
    }

    let raw_image = sys::linux::open_raw_disk_image(&params)?;
    let image_type = detect_image_type(&raw_image, params.is_overlapped)?;
    Ok(match image_type {
        ImageType::Raw => {
            sys::linux::apply_raw_disk_file_options(&raw_image, params.is_sparse_file)?;
            Box::new(raw_image) as Box<dyn DiskFile>
        }
        ImageType::Qcow2 => {
            Box::new(qcow::QcowFile::from(raw_image, params).map_err(Error::QcowError)?)
                as Box<dyn DiskFile>
        }
        #[allow(unreachable_patterns)]
        _ => return Err(Error::UnknownType),
    })
}
