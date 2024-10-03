use std::fs::File;

use std::io::{self, BufWriter, Read, Seek, SeekFrom, Write};

#[derive(Debug)]
pub struct QcowRawFile {
    file: File,
    cluster_size: u64,
    cluster_mask: u64,
}

impl QcowRawFile {
    /// Creates a `QcowRawFile` from the given `File`, `None` is returned if `cluster_size` is not
    /// a power of two.
    pub fn from(file: File, cluster_size: u64) -> Option<Self> {
        if cluster_size.count_ones() != 1 {
            return None;
        }
        Some(QcowRawFile {
            file,
            cluster_size,
            cluster_mask: cluster_size - 1,
        })
    }

    /// Reads `count` 64 bit offsets and returns them as a vector.
    /// `mask` optionally ands out some of the bits on the file.
    pub fn read_pointer_table(
        &mut self,
        offset: u64,
        count: u64,
        mask: Option<u64>,
    ) -> io::Result<Vec<u64>> {
        let mut table = vec![0; count as usize];
        self.file.seek(SeekFrom::Start(offset))?;
        let mask = mask.unwrap_or(u64::MAX);
        for ptr in &mut table {
            let mut value = [0u8; 8];
            self.file.read_exact(&mut value)?;
            *ptr = u64::from_be_bytes(value) & mask;
        }
        Ok(table)
    }

    /// Writes `table` of u64 pointers to `offset` in the file.
    /// `non_zero_flags` will be ORed with all non-zero values in `table`.
    /// writing.
    pub fn write_pointer_table(
        &mut self,
        offset: u64,
        table: &[u64],
        non_zero_flags: u64,
    ) -> io::Result<()> {
        self.file.seek(SeekFrom::Start(offset))?;
        let mut buffer = BufWriter::with_capacity(size_of_val(table), &self.file);
        for addr in table {
            let val = if *addr == 0 {
                0
            } else {
                *addr | non_zero_flags
            };
            buffer.write_all(&val.to_be_bytes())?;
        }
        Ok(())
    }

    /// Returns the size of the file's clusters.
    pub fn cluster_size(&self) -> u64 {
        self.cluster_size
    }

    /// Returns a mutable reference to the underlying file.
    pub fn file_mut(&mut self) -> &mut File {
        &mut self.file
    }

    /// Writes a refcount block to the file.
    pub fn write_refcount_block(&mut self, offset: u64, table: &[u16]) -> io::Result<()> {
        self.file.seek(SeekFrom::Start(offset))?;
        let mut buffer = BufWriter::with_capacity(size_of_val(table), &self.file);
        for count in table {
            buffer.write_all(&count.to_be_bytes())?;
        }
        Ok(())
    }

    /// Read a refcount block from the file and returns a Vec containing the block.
    /// Always returns a cluster's worth of data.
    pub fn read_refcount_block(&mut self, offset: u64) -> io::Result<Vec<u16>> {
        let count = self.cluster_size / size_of::<u16>() as u64;
        let mut table = vec![0; count as usize];
        self.file.seek(SeekFrom::Start(offset))?;
        for refcount in &mut table {
            let mut value = [0u8; 2];
            self.file.read_exact(&mut value)?;
            *refcount = u16::from_be_bytes(value);
        }
        Ok(table)
    }
}
