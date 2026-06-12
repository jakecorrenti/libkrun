// SPDX-License-Identifier: Apache-2.0

use std::fs::{self, File};
use std::io::{Cursor, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use anyhow::Context;
use aws_nitro_enclaves_nsm_api::api::{Request, Response};
use aws_nitro_enclaves_nsm_api::driver::nsm_process_request;

const NSM_PCR_ROOTFS: u16 = 16;
const NSM_PCR_CHUNK_SIZE: usize = 0x800; // 2 KiB

/// Extract a tar archive from `archive` into the current filesystem root,
/// measuring each file's data in NSM PCR 16.
///
/// `/etc/hostname` and `/etc/hosts` are excluded from measurement (they
/// contain ephemeral container-specific values).
pub fn extract(nsm_fd: i32, archive: &[u8]) -> anyhow::Result<()> {
    let cursor = Cursor::new(archive);
    let mut tar = tar::Archive::new(cursor);

    for entry in tar.entries().context("archive: iterate entries")? {
        let mut entry = entry.context("archive: read entry")?;
        let path = entry
            .path()
            .context("archive: get entry path")?
            .into_owned();

        if should_measure(&path) {
            write_and_measure_entry(nsm_fd, &mut entry, &path)
                .with_context(|| format!("archive: write+measure entry {path:?}"))?;
        } else {
            entry
                .unpack_in("/")
                .with_context(|| format!("archive: unpack {path:?}"))?;
        }
    }

    Ok(())
}

/// Returns true if this path should be measured in NSM PCR 16.
fn should_measure(path: &Path) -> bool {
    let s = path.to_string_lossy();
    !s.contains("rootfs/etc/hostname") && !s.contains("rootfs/etc/hosts")
}

/// Stream a tar entry to disk while simultaneously measuring its data in NSM PCR 16.
///
/// This avoids buffering the full entry in memory — each 2 KiB chunk is written
/// to disk and fed to the NSM in the same pass.
fn write_and_measure_entry<R: Read>(
    nsm_fd: i32,
    entry: &mut tar::Entry<R>,
    path: &Path,
) -> anyhow::Result<()> {
    let header = entry.header().clone();

    match header.entry_type() {
        tar::EntryType::Regular | tar::EntryType::Continuous => {
            if let Some(parent) = path.parent()
                && !parent.as_os_str().is_empty()
            {
                fs::create_dir_all(parent)
                    .with_context(|| format!("create parent dirs for {parent:?}"))?;
            }
            let mut f = File::create(path).with_context(|| format!("create file {path:?}"))?;

            // Stream: read → measure → write, one chunk at a time.
            let mut buf = vec![0u8; NSM_PCR_CHUNK_SIZE];
            loop {
                let n = entry
                    .read(&mut buf)
                    .with_context(|| format!("read entry data for {path:?}"))?;
                if n == 0 {
                    break;
                }
                nsm_pcr_extend(nsm_fd, &buf[..n])
                    .with_context(|| format!("NSM PCR extend for {path:?}"))?;
                f.write_all(&buf[..n])
                    .with_context(|| format!("write chunk for {path:?}"))?;
            }

            if let Ok(mode) = header.mode() {
                fs::set_permissions(path, fs::Permissions::from_mode(mode))
                    .with_context(|| format!("set permissions on {path:?}"))?;
            }
        }
        tar::EntryType::Directory => {
            fs::create_dir_all(path).with_context(|| format!("create dir {path:?}"))?;
            if let Ok(mode) = header.mode() {
                fs::set_permissions(path, fs::Permissions::from_mode(mode))
                    .with_context(|| format!("set permissions on {path:?}"))?;
            }
        }
        tar::EntryType::Symlink => match header.link_name() {
            Ok(Some(target)) => {
                std::os::unix::fs::symlink(&target, path)
                    .with_context(|| format!("symlink {path:?} -> {target:?}"))?;
            }
            Ok(None) => {
                eprintln!("archive: symlink {path:?} has no target, skipping");
            }
            Err(e) => {
                eprintln!("archive: symlink {path:?} invalid target: {e}, skipping");
            }
        },
        tar::EntryType::Link => {
            // Hard link: link_name() is the link target (existing file).
            match header.link_name() {
                Ok(Some(target)) => {
                    fs::hard_link(&target, path)
                        .with_context(|| format!("hard link {path:?} -> {target:?}"))?;
                }
                Ok(None) => {
                    eprintln!("archive: hard link {path:?} has no target, skipping");
                }
                Err(e) => {
                    eprintln!("archive: hard link {path:?} invalid target: {e}, skipping");
                }
            }
        }
        _ => {
            // Other entry types (char/block devices, fifos): silently skip.
            // These require CAP_MKNOD and are uncommon in container rootfs images.
        }
    }

    Ok(())
}

/// Extend NSM PCR 16 with a data chunk (already sized ≤ 2 KiB).
fn nsm_pcr_extend(nsm_fd: i32, data: &[u8]) -> anyhow::Result<()> {
    let response = nsm_process_request(
        nsm_fd,
        Request::ExtendPCR {
            index: NSM_PCR_ROOTFS,
            data: data.to_vec(),
        },
    );

    match response {
        Response::ExtendPCR { .. } => Ok(()),
        Response::Error(e) => anyhow::bail!("NSM ExtendPCR failed: {e:?}"),
        other => anyhow::bail!("NSM ExtendPCR unexpected response: {other:?}"),
    }
}
