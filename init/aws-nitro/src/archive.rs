// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result};
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use tar::Archive;

use crate::nsm::Nsm;

const NSM_PCR_ROOTFS: u16 = 16;

/// Extract a tar archive from memory into the filesystem, measuring each file's
/// data in NSM PCR 16.  Paths containing `etc/hostname` or `etc/hosts` are
/// written but not measured because they contain ephemeral per-container values.
///
/// The archive paths are rooted at `/` (mirrors the C libarchive disk writer
/// which used the process cwd of `/`), so entries like `rootfs/etc/passwd`
/// land at `/rootfs/etc/passwd`.
pub fn extract(nsm: &Nsm, data: &[u8]) -> Result<()> {
    let mut archive = Archive::new(std::io::Cursor::new(data));
    archive.set_preserve_permissions(true);
    archive.set_unpack_xattrs(true);
    archive.set_overwrite(true);

    let entries = archive.entries().context("read tar archive")?;

    for entry in entries {
        let mut entry = entry.context("read tar entry")?;
        let entry_type = entry.header().entry_type();
        let path_str = entry
            .path()
            .context("tar entry path")?
            .to_string_lossy()
            .into_owned();

        let should_measure =
            entry_type.is_file()
            && !path_str.contains("etc/hostname")
            && !path_str.contains("etc/hosts");

        if should_measure {
            // Read all data so we can measure it, then write manually.
            let mut file_data = Vec::new();
            entry
                .read_to_end(&mut file_data)
                .with_context(|| format!("read {path_str}"))?;

            // Measure in 2 KiB chunks as required by NSM.
            for chunk in file_data.chunks(0x800) {
                nsm.extend_pcr(NSM_PCR_ROOTFS, chunk)
                    .with_context(|| format!("measure {path_str} in PCR {NSM_PCR_ROOTFS}"))?;
            }

            // Write the file, rooted at `/` to match the C libarchive disk writer.
            let dest = std::path::Path::new("/").join(&path_str);
            if let Some(parent) = dest.parent() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("create dir {}", parent.display()))?;
            }
            std::fs::write(&dest, &file_data)
                .with_context(|| format!("write {}", dest.display()))?;

            let mode = entry.header().mode().unwrap_or(0o644);
            std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(mode)).ok();
        } else {
            // Dirs, symlinks, devices, and unmeasured files go through the tar
            // crate's unpacker which handles all entry types correctly.
            entry
                .unpack_in("/")
                .with_context(|| format!("unpack {path_str}"))?;
        }
    }

    Ok(())
}
