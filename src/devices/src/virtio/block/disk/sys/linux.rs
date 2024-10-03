use std::fs::File;

use crate::virtio::block::disk::{DiskFileParams, Error, Result};

pub fn open_raw_disk_image(params: &DiskFileParams) -> Result<File> {
    let mut options = File::options();
    options.read(true).write(!params.is_read_only);

    let raw_image = base::open_file_or_duplicate(&params.path, &options)
        .map_err(|e| Error::OpenFile(params.path.display().to_string(), e))?;

    if params.lock {
        // Lock the disk image to prevent other crosvm instances from using it.
        let lock_op = if params.is_read_only {
            base::FlockOperation::LockShared
        } else {
            base::FlockOperation::LockExclusive
        };
        base::flock(&raw_image, lock_op, true).map_err(Error::LockFileFailure)?;
    }

    // If O_DIRECT is requested, set the flag via fcntl. It is not done at
    // open_file_or_reuse time because it will reuse existing fd and will
    // not actually use the given OpenOptions.
    if params.is_direct {
        base::add_fd_flags(raw_image.as_raw_fd(), libc::O_DIRECT).map_err(Error::DirectFailed)?;
    }

    Ok(raw_image)
}

pub fn apply_raw_disk_file_options(_raw_image: &File, _is_sparse_file: bool) -> Result<()> {
    // No op on unix.
    Ok(())
}
