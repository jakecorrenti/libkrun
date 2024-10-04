use std::path::Path;
use std::os::unix::io::RawFd;
use std::fs::File;
use crate::virtio::block::disk::base::descriptor::{FromRawDescriptor, RawDescriptor, SafeDescriptor};
use super::super::errno::Result;

/// The operation to perform with `flock`.
pub enum FlockOperation {
    LockShared,
    LockExclusive,
    Unlock,
}

/// Safe wrapper for flock(2) with the operation `op` and optionally `nonblocking`. The lock will be
/// dropped automatically when `file` is dropped.
#[inline(always)]
pub fn flock<F: super::super::descriptor::AsRawDescriptor>(file: &F, op: FlockOperation, nonblocking: bool) -> Result<()> {
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
pub fn open_file_or_duplicate<P: AsRef<Path>>(path: P, options: &std::fs::OpenOptions) -> Result<File> {
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
        return Err(crate::virtio::block::disk::base::errno::Error::new(libc::EBADF));
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
