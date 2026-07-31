use macros::{guest, host};

pub struct TestAcpiSmp {
    pub(crate) num_cpus: u8,
}

#[host]
mod host {
    use super::*;
    use crate::common::setup_fs_and_enter;
    use crate::{ShouldRun, Test, TestSetup};
    use crate::{krun_call, krun_call_u32};
    use krun_sys::*;
    use std::os::fd::AsRawFd;

    impl Test for TestAcpiSmp {
        fn should_run(&self) -> ShouldRun {
            if cfg!(target_arch = "x86_64") {
                ShouldRun::Yes
            } else {
                ShouldRun::No("ACPI table generation is x86_64-only")
            }
        }

        fn start_vm(self: Box<Self>, test_setup: TestSetup) -> anyhow::Result<()> {
            unsafe {
                krun_call!(krun_init_log(
                    KRUN_LOG_TARGET_DEFAULT,
                    KRUN_LOG_LEVEL_TRACE,
                    KRUN_LOG_STYLE_AUTO,
                    0
                ))?;
                let ctx = krun_call_u32!(krun_create_ctx())?;
                krun_call!(krun_set_vm_config(ctx, self.num_cpus, 256))?;
                krun_call!(krun_add_virtio_console_default(
                    ctx,
                    std::io::stdin().as_raw_fd(),
                    std::io::stdout().as_raw_fd(),
                    std::io::stderr().as_raw_fd(),
                ))?;
                setup_fs_and_enter(ctx, test_setup)?;
            }
            Ok(())
        }
    }
}

#[guest]
mod guest {
    use super::*;
    use crate::Test;
    use std::fs;
    use std::path::Path;
    use std::str::FromStr;

    fn detect_num_cpus() -> u32 {
        let cpus = fs::read_to_string("/sys/devices/system/cpu/online").unwrap();
        let mut parts = cpus.split("-");
        let low = u32::from_str(parts.next().unwrap().trim()).unwrap();
        if let Some(high) = parts.next() {
            let high = u32::from_str(high.trim()).unwrap();
            high - low + 1
        } else {
            low + 1
        }
    }

    impl Test for TestAcpiSmp {
        fn in_guest(self: Box<Self>) {
            // The kernel only exposes a table under /sys/firmware/acpi/tables/
            // if it actually parsed that table at boot via ACPI (not the
            // MP-table path) -- this is the concrete signal this plan's
            // Global Constraints require checking for.
            assert!(
                Path::new("/sys/firmware/acpi/tables/APIC").exists(),
                "kernel did not parse the MADT -- ACPI was not used for boot"
            );
            assert!(
                Path::new("/sys/firmware/acpi/tables/FACP").exists(),
                "kernel did not parse the FADT"
            );

            assert_eq!(
                detect_num_cpus(),
                self.num_cpus as u32,
                "not all configured vCPUs came online via the ACPI MADT path"
            );

            println!("OK");
        }
    }
}
