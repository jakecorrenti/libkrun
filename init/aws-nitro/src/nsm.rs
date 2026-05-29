// SPDX-License-Identifier: Apache-2.0

use anyhow::{bail, Result};
use aws_nitro_enclaves_nsm_api::{
    api::{ErrorCode, Request, Response},
    driver::{nsm_exit, nsm_init, nsm_process_request},
};

const NSM_PCR_CHUNK_SIZE: usize = 0x800; // 2 KiB

pub struct Nsm {
    fd: i32,
}

impl Nsm {
    pub fn new() -> Result<Self> {
        let fd = nsm_init();
        if fd < 0 {
            bail!("unable to open NSM guest module");
        }
        Ok(Self { fd })
    }

    /// Extend a PCR with data, chunking into 2 KiB pieces as required by the NSM.
    pub fn extend_pcr(&self, index: u16, data: &[u8]) -> Result<()> {
        for chunk in data.chunks(NSM_PCR_CHUNK_SIZE) {
            let request = Request::ExtendPCR {
                index,
                data: chunk.to_vec(),
            };
            match nsm_process_request(self.fd, request) {
                Response::ExtendPCR { .. } => {}
                Response::Error(e) => bail!("nsm extend_pcr failed: {e:?}"),
                _ => bail!("nsm extend_pcr: unexpected response"),
            }
        }
        Ok(())
    }

    /// Lock all PCRs in [0, range) so they cannot be extended further.
    pub fn lock_pcrs(&self, range: u16) -> Result<()> {
        let request = Request::LockPCRs { range };
        match nsm_process_request(self.fd, request) {
            Response::LockPCRs => Ok(()),
            Response::Error(ErrorCode::InvalidOperation) => {
                // Dev-mode NSM doesn't support locking — treat as success.
                Ok(())
            }
            Response::Error(e) => bail!("nsm lock_pcrs failed: {e:?}"),
            _ => bail!("nsm lock_pcrs: unexpected response"),
        }
    }
}

impl Drop for Nsm {
    fn drop(&mut self) {
        nsm_exit(self.fd);
    }
}
