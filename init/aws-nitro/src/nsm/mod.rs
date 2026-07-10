use anyhow::bail;
use aws_nitro_enclaves_nsm_api::api::{Request, Response};
use aws_nitro_enclaves_nsm_api::driver as nitro_driver;

const NSM_PCR_EXEC_DATA: u16 = 17;

/// Measure the enclave execution environment {path, argv, envp} in NSM PCR 17.
///
/// NSM PCR 17 contains the measurement of the execution environment (path,
/// argv, envp).
pub fn pcr_extend_exec_path(
    nsm_fd: i32,
    path: &str,
    argv: &[String],
    envp: &[String],
) -> anyhow::Result<()> {
    // Measure the execution path.
    measure_exec_string(nsm_fd, path)?;

    // Measure each execution argument.
    for arg in argv {
        measure_exec_string(nsm_fd, arg)?;
    }

    // Measure each environment variable.
    for env in envp {
        measure_exec_string(nsm_fd, env)?;
    }

    Ok(())
}

fn measure_exec_string(fd: i32, data: &str) -> anyhow::Result<()> {
    let req = Request::ExtendPCR {
        index: NSM_PCR_EXEC_DATA,
        data: data.as_bytes().to_vec(),
    };
    let resp = nitro_driver::nsm_process_request(fd, req);
    match resp {
        Response::ExtendPCR { .. } => Ok(()),
        Response::Error(e) => bail!("failure to extend PCR {}: {:?}", NSM_PCR_EXEC_DATA, e),
        r => bail!("unexpected NSM response: {:?}", r),
    }
}
