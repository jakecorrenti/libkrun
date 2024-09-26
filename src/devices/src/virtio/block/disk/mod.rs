// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

pub mod qcow2;
mod node;
mod helpers;

use crate::virtio::file_traits::{FileReadWriteAtVolatile, FileSetLen};
use std::fmt::Debug;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};

#[derive(Debug)]
pub enum Error {
    ReadingHeader(io::Error),
    SeekingFile(io::Error),
}

#[derive(Debug)]
pub struct BlockError {
    description: String,
    io: io::Error,
}

pub type BlockResult<R> = std::result::Result<R, BlockError>;

impl Clone for BlockError {
    fn clone(&self) -> Self {
        BlockError {
            description: self.description.clone(),
            io: io::Error::from(self.io.kind()),
        }
    }
}

impl From<io::Error> for BlockError {
    fn from(err: io::Error) -> Self {
        let description = err.to_string();
        BlockError {
            description,
            io: err,
        }
    }
}

impl From<io::ErrorKind> for BlockError {
    fn from(err: io::ErrorKind) -> Self {
        let io = io::Error::from(err);
        let description = io.to_string();
        BlockError { description, io }
    }
}

impl<T> From<tokio::sync::mpsc::error::SendError<T>> for BlockError {
    fn from(err: tokio::sync::mpsc::error::SendError<T>) -> Self {
        let description = err.to_string();
        let io = io::Error::new(io::ErrorKind::ConnectionAborted, description.clone());
        BlockError { description, io }
    }
}

impl<T> From<tokio::sync::mpsc::error::TrySendError<T>> for BlockError {
    fn from(err: tokio::sync::mpsc::error::TrySendError<T>) -> Self {
        let description = err.to_string();
        let io = io::Error::new(io::ErrorKind::ConnectionAborted, description.clone());
        BlockError { description, io }
    }
}

macro_rules! impl_from {
    ($type:ty, $kind:ident) => {
        impl From<$type> for BlockError {
            fn from(err: $type) -> Self {
                let description = err.to_string();
                let io = io::Error::new(io::ErrorKind::$kind, description.clone());
                BlockError { description, io }
            }
        }
    };
}

impl_from!(Box<bincode::ErrorKind>, InvalidData);
impl_from!(serde_json::Error, InvalidData);
impl_from!(std::num::TryFromIntError, InvalidData);
impl_from!(std::str::Utf8Error, InvalidData);
impl_from!(&str, Other);
impl_from!(String, Other);
#[cfg(feature = "io_uring")]
impl_from!(blkio::Error, Other);
impl_from!(std::alloc::LayoutError, OutOfMemory);

impl BlockError {
    pub fn from_desc(description: String) -> Self {
        let io = io::Error::new(io::ErrorKind::Other, description.clone());
        BlockError { description, io }
    }

    pub fn into_inner(self) -> io::Error {
        self.io
    }

    pub fn get_inner(&self) -> &io::Error {
        &self.io
    }

    pub fn into_description(self) -> String {
        self.description
    }

    #[must_use]
    pub fn prepend(mut self, prefix: &str) -> Self {
        self.description = format!("{}: {}", prefix, self.description);
        self
    }
}

impl std::fmt::Display for BlockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.description)
    }
}

impl std::error::Error for BlockError {}


type Result<T> = std::result::Result<T, Error>;

/// The variants of image files on the host that can be used as virtual disks.
#[derive(Debug, PartialEq, Eq)]
pub enum ImageType {
    Raw,
    Qcow2,
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

/// The prerequisites necessary to support a block device.
pub trait DiskFile:
    FileSetLen + DiskGetLen + FileReadWriteAtVolatile + Send + Debug + Write
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

/// Detect the type of an image file by checking for a valid header of the supported formats.
pub fn detect_image_type(file: &File, overlapped_mode: bool) -> Result<ImageType> {
    let mut f = file;
    let disk_size = f.get_len().map_err(Error::SeekingFile)?;
    let orig_seek = f.stream_position().map_err(Error::SeekingFile)?;

    println!("disk size {}", disk_size);

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
        if magic4 == qcow2::meta::QCOW2_MAGIC.to_be_bytes() {
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
