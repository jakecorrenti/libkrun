// SPDX-License-Identifier: Apache-2.0

use std::time::Instant;

use crate::bus::BusDevice;

const ACPI_TIMER_OFFSET: u64 = 0x8;
const ACPI_TIMER_FREQUENCY_HZ: u64 = 3_579_545;

pub struct AcpiPmTimer {
    start: Instant,
}

impl Default for AcpiPmTimer {
    fn default() -> Self {
        Self::new()
    }
}

impl AcpiPmTimer {
    pub fn new() -> Self {
        Self {
            start: Instant::now(),
        }
    }
}

impl BusDevice for AcpiPmTimer {
    fn read(&mut self, _vcpuid: u64, offset: u64, data: &mut [u8]) {
        if offset == ACPI_TIMER_OFFSET && data.len() == 4 {
            let elapsed = self.start.elapsed();
            let nanos = elapsed.as_nanos() as u64;
            let ticks = (nanos * ACPI_TIMER_FREQUENCY_HZ / 1_000_000_000) as u32;
            let bytes = ticks.to_le_bytes();
            data.copy_from_slice(&bytes);
        } else {
            for d in data.iter_mut() {
                *d = 0;
            }
        }
    }

    fn write(&mut self, _vcpuid: u64, _offset: u64, _data: &[u8]) {}
}
