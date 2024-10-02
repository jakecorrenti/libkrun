use std::fs::File;

#[derive(Debug)]
pub struct QcowRawFile {
    file: File,
    cluster_size: u64,
    cluster_mask: u64,
}
