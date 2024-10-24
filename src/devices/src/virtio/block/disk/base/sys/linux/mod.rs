use super::super::errno::Result;
use crate::syscall;
use crate::virtio::block::disk::base::descriptor::{
    AsRawDescriptor, FromRawDescriptor, RawDescriptor, SafeDescriptor,
};
use std::fs::File;
use std::os::unix::io::RawFd;
use std::path::Path;

use crate::virtio::block::disk::base::MaybeUninit;

/// The operation to perform with `flock`.
pub enum FlockOperation {
    LockShared,
    LockExclusive,
    Unlock,
}

/// Safe wrapper for flock(2) with the operation `op` and optionally `nonblocking`. The lock will be
/// dropped automatically when `file` is dropped.
#[inline(always)]
pub fn flock<F: super::super::descriptor::AsRawDescriptor>(
    file: &F,
    op: FlockOperation,
    nonblocking: bool,
) -> Result<()> {
    let mut operation = match op {
        FlockOperation::LockShared => libc::LOCK_SH,
        FlockOperation::LockExclusive => libc::LOCK_EX,
        FlockOperation::Unlock => libc::LOCK_UN,
    };

    if nonblocking {
        operation |= libc::LOCK_NB;
    }

    // SAFETY:
    // Safe since we pass in a valid fd and flock operation, and check the return value.
    crate::syscall!(unsafe { libc::flock(file.as_raw_descriptor(), operation) }).map(|_| ())
}

/// Open the file with the given path, or if it is of the form `/proc/self/fd/N` then just use the
/// file descriptor.
///
/// Note that this will not work properly if the same `/proc/self/fd/N` path is used twice in
/// different places, as the metadata (including the offset) will be shared between both file
/// descriptors.
pub fn open_file_or_duplicate<P: AsRef<Path>>(
    path: P,
    options: &std::fs::OpenOptions,
) -> Result<File> {
    let path = path.as_ref();
    // Special case '/proc/self/fd/*' paths. The FD is already open, just use it.
    Ok(if let Some(fd) = safe_descriptor_from_path(path)? {
        fd.into()
    } else {
        options.open(path)?
    })
}

/// If the given path is of the form /proc/self/fd/N for some N, returns `Ok(Some(N))`. Otherwise
/// returns `Ok(None)`.
pub fn safe_descriptor_from_path<P: AsRef<Path>>(path: P) -> Result<Option<SafeDescriptor>> {
    let path = path.as_ref();
    if path.parent() == Some(Path::new("/proc/self/fd")) {
        let raw_descriptor = path
            .file_name()
            .and_then(|fd_osstr| fd_osstr.to_str())
            .and_then(|fd_str| fd_str.parse::<RawFd>().ok())
            .ok_or_else(|| crate::virtio::block::disk::base::errno::Error::new(libc::EINVAL))?;
        let validated_fd = validate_raw_fd(&raw_descriptor)?;
        Ok(Some(
            // SAFETY:
            // Safe because nothing else has access to validated_fd after this call.
            unsafe { SafeDescriptor::from_raw_descriptor(validated_fd) },
        ))
    } else {
        Ok(None)
    }
}

/// Verifies that |raw_descriptor| is actually owned by this process and duplicates it
/// to ensure that we have a unique handle to it.
pub fn validate_raw_descriptor(raw_descriptor: RawDescriptor) -> Result<RawDescriptor> {
    validate_raw_fd(&raw_descriptor)
}

/// Verifies that |raw_fd| is actually owned by this process and duplicates it to ensure that
/// we have a unique handle to it.
pub fn validate_raw_fd(raw_fd: &RawFd) -> Result<RawFd> {
    // Checking that close-on-exec isn't set helps filter out FDs that were opened by
    // crosvm as all crosvm FDs are close on exec.
    // SAFETY:
    // Safe because this doesn't modify any memory and we check the return value.
    let flags = unsafe { libc::fcntl(*raw_fd, libc::F_GETFD) };
    if flags < 0 || (flags & libc::FD_CLOEXEC) != 0 {
        return Err(crate::virtio::block::disk::base::errno::Error::new(
            libc::EBADF,
        ));
    }

    // SAFETY:
    // Duplicate the fd to ensure that we don't accidentally close an fd previously
    // opened by another subsystem.  Safe because this doesn't modify any memory and
    // we check the return value.
    let dup_fd = unsafe { libc::fcntl(*raw_fd, libc::F_DUPFD_CLOEXEC, 0) };
    if dup_fd < 0 {
        return Err(crate::virtio::block::disk::base::errno::Error::last());
    }
    Ok(dup_fd as RawFd)
}

/// Safe wrapper for `fstat()`.
pub fn fstat<F: AsRawDescriptor>(f: &F) -> Result<libc::stat64> {
    let mut st = MaybeUninit::<libc::stat64>::zeroed();

    // SAFETY:
    // Safe because the kernel will only write data in `st` and we check the return
    // value.
    syscall!(unsafe { libc::fstat64(f.as_raw_descriptor(), st.as_mut_ptr()) })?;

    // SAFETY:
    // Safe because the kernel guarantees that the struct is now fully initialized.
    Ok(unsafe { st.assume_init() })
}

/// The operation to perform with `fallocate`.
pub enum FallocateMode {
    PunchHole,
    ZeroRange,
    Allocate,
}

impl From<FallocateMode> for i32 {
    fn from(value: FallocateMode) -> Self {
        match value {
            FallocateMode::Allocate => libc::FALLOC_FL_KEEP_SIZE,
            FallocateMode::PunchHole => libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE,
            FallocateMode::ZeroRange => libc::FALLOC_FL_ZERO_RANGE | libc::FALLOC_FL_KEEP_SIZE,
        }
    }
}

impl From<FallocateMode> for u32 {
    fn from(value: FallocateMode) -> Self {
        Into::<i32>::into(value) as u32
    }
}

/// Safe wrapper for `fallocate()`.
pub fn fallocate<F: AsRawDescriptor>(
    file: &F,
    mode: FallocateMode,
    offset: u64,
    len: u64,
) -> crate::virtio::block::disk::base::errno::Result<()> {
    let offset = if offset > libc::off64_t::MAX as u64 {
        return Err(crate::virtio::block::disk::base::errno::Error::new(
            libc::EINVAL,
        ));
    } else {
        offset as libc::off64_t
    };

    let len = if len > libc::off64_t::MAX as u64 {
        return Err(crate::virtio::block::disk::base::errno::Error::new(
            libc::EINVAL,
        ));
    } else {
        len as libc::off64_t
    };

    // SAFETY:
    // Safe since we pass in a valid fd and fallocate mode, validate offset and len,
    // and check the return value.
    syscall!(unsafe { libc::fallocate64(file.as_raw_descriptor(), mode.into(), offset, len) })
        .map(|_| ())
}

/// Checks whether a file is a block device fie or not.
pub fn is_block_file<F: AsRawDescriptor>(
    file: &F,
) -> crate::virtio::block::disk::base::errno::Result<bool> {
    let stat = fstat(file)?;
    Ok((stat.st_mode & libc::S_IFMT) == libc::S_IFBLK)
}

const BLOCK_IO_TYPE: u32 = 0x12;
crate::ioctl_io_nr!(BLKDISCARD, BLOCK_IO_TYPE, 119);

/// Discards the given range of a block file.
pub fn discard_block<F: AsRawDescriptor>(
    file: &F,
    offset: u64,
    len: u64,
) -> crate::virtio::block::disk::base::errno::Result<()> {
    let range: [u64; 2] = [offset, len];
    // SAFETY:
    // Safe because
    // - we check the return value.
    // - ioctl(BLKDISCARD) does not hold the descriptor after the call.
    // - ioctl(BLKDISCARD) does not break the file descriptor.
    // - ioctl(BLKDISCARD) does not modify the given range.
    syscall!(unsafe { libc::ioctl(file.as_raw_descriptor(), BLKDISCARD, &range) }).map(|_| ())
}
