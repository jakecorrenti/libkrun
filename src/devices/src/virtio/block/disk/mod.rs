// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

pub mod qcow;

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};

#[derive(Debug)]
pub enum Error {
    ReadingHeader(io::Error),
    SeekingFile(io::Error),
}

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
