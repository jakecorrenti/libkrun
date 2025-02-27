use tdx::launch::{TdxCapabilities, TdxVm};

use kvm_ioctls::VmFd;

#[derive(Debug)]
pub enum Error {
    CreateTdxVmStruct,
    GetCapabilities,
    InitVm,
    InitMemoryRegions(i32),
}

pub struct IntelTdx {
    caps: TdxCapabilities,
    vm: TdxVm,
}

impl IntelTdx {
    pub fn new(vm_fd: &VmFd) -> Result<Self, Error> {
        let vm = TdxVm::new(vm_fd)
            .or_else(|_| return Err(Error::CreateTdxVmStruct))?;
        let caps = vm
            .get_capabilities(vm_fd)
            .or_else(|_| return Err(Error::GetCapabilities))?;

        Ok(IntelTdx { caps, vm })
    }

    pub fn vm_prepare(
        &self,
        fd: &kvm_ioctls::VmFd,
        cpuid: kvm_bindings::CpuId,
    ) -> Result<(), Error> {
        self.vm
            .init_vm(fd, &self.caps, cpuid)
            .or_else(|_| return Err(Error::InitVm))?;

        Ok(())
    }

    pub fn configure_td_memory(
        &self,
        fd: &kvm_ioctls::VcpuFd,
        regions: &Vec<crate::vstate::MeasuredRegion>,
    ) -> Result<(), Error> {
        for region in regions {
            if let Err(e) = tdx::launch::TdxVcpu::init_mem_region(
                fd,
                region.guest_addr,
                (region.size / 4096) as u64,
                (arch::BIOS_START == region.guest_addr).into(),
                region.host_addr,
            ) {
                if e.code != libc::EAGAIN {
                    return Err(Error::InitMemoryRegions(e.code));
                }
            }
        }

        Ok(())
    }
}
