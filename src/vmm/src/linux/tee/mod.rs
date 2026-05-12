#[cfg(feature = "amd-sev")]
pub mod amdsnp;

#[cfg(feature = "tdx")]
pub mod inteltdx;

#[cfg(feature = "tdx")]
#[allow(dead_code)]
pub mod tdvf_hob;
