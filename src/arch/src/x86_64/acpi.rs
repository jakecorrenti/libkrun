// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::result;

use acpi_tables::Aml;
use acpi_tables::fadt::{FADTBuilder, Flags};
use acpi_tables::madt::{
    EnabledStatus, IoApic, LocalInterruptController, MADT, ProcessorLocalApic,
};
use acpi_tables::rsdp::Rsdp;
use acpi_tables::sdt::Sdt;
use acpi_tables::xsdt::XSDT;
use vm_memory::Bytes;
use vm_memory::{GuestAddress, GuestMemoryMmap};
use zerocopy::IntoBytes;

use crate::x86_64::layout::{HIMEM_START, RSDP_ADDR};

/// Standard local APIC physical base address.
const LOCAL_APIC_DEFAULT_PHYS_BASE: u32 = 0xfee0_0000;
/// Standard I/O APIC physical base address.
const IO_APIC_DEFAULT_PHYS_BASE: u32 = 0xfec0_0000;

/// Builds a 36-byte ACPI 2.0+ RSDP pointing at the given XSDT address.
fn build_rsdp(xsdt_addr: u64) -> Vec<u8> {
    Rsdp::new(*b"LIBKRN", xsdt_addr).as_bytes().to_vec()
}

/// Builds a minimal valid DSDT (36-byte header, no AML body).
fn build_dsdt() -> Vec<u8> {
    Sdt::new(*b"DSDT", 36, 2, *b"LIBKRN", *b"KRUNDSDT", 1)
        .as_slice()
        .to_vec()
}

/// Builds a minimal ACPI 6.x FADT pointing at the given DSDT address.
fn build_fadt(dsdt_addr: u64) -> Vec<u8> {
    let fadt = FADTBuilder::new(*b"LIBKRN", *b"KRUNFADT", 1)
        .acpi_enable()
        .dsdt_64(dsdt_addr)
        .flag(Flags::PwrButton)
        .flag(Flags::SlpButton)
        .finalize();
    let mut bytes = Vec::new();
    fadt.to_aml_bytes(&mut bytes);
    bytes
}

/// Builds an ACPI 6.x MADT with one Processor Local APIC entry per vCPU
/// and one I/O APIC entry.
fn build_madt(num_cpus: u8) -> Vec<u8> {
    let mut madt = MADT::new(
        *b"LIBKRN",
        *b"KRUNAPIC",
        1,
        LocalInterruptController::Address(LOCAL_APIC_DEFAULT_PHYS_BASE),
    );

    for cpu_id in 0..num_cpus {
        madt.add_structure(ProcessorLocalApic::new(
            cpu_id,
            cpu_id,
            EnabledStatus::Enabled,
        ));
    }

    madt.add_structure(IoApic::new(num_cpus + 1, IO_APIC_DEFAULT_PHYS_BASE, 0));

    let mut bytes = Vec::new();
    madt.to_aml_bytes(&mut bytes);
    bytes
}

/// Builds an ACPI 2.0+ XSDT with entries for the given 64-bit table addresses.
fn build_xsdt(entry_addrs: &[u64]) -> Vec<u8> {
    let mut xsdt = XSDT::new(*b"LIBKRN", *b"KRUNXSDT", 1);
    for addr in entry_addrs {
        xsdt.add_entry(*addr);
    }
    let mut bytes = Vec::new();
    xsdt.to_aml_bytes(&mut bytes);
    bytes
}

#[derive(Debug, Eq, PartialEq)]
pub enum Error {
    /// The reserved ACPI window (RSDP_ADDR..HIMEM_START) is too small to
    /// hold the generated tables.
    NotEnoughMemory,
    /// Failed to write a table into guest memory.
    WriteFailed,
}

pub type Result<T> = result::Result<T, Error>;

/// Builds and writes RSDP, XSDT, FADT, DSDT, and MADT into guest memory
/// starting at `RSDP_ADDR`. Must be called for every payload type,
/// including TEE — unlike `mptable::setup_mptable`, this is not gated by
/// the `tee` feature.
#[allow(dead_code)]
pub fn setup_acpi(mem: &GuestMemoryMmap, num_cpus: u8) -> Result<()> {
    let dsdt = build_dsdt();
    let madt = build_madt(num_cpus);

    // RSDP is a fixed 36 bytes; XSDT's size depends only on its entry
    // count (2: FADT + MADT), not their addresses.
    const RSDP_SIZE: u64 = 36;
    let xsdt_size = 36 + 2 * 8; // fixed SDT header + 2 entries
    let fadt_size_placeholder = build_fadt(0).len() as u64; // FADT's size doesn't vary with dsdt_addr's value

    let rsdp_addr = RSDP_ADDR;
    let xsdt_addr = rsdp_addr + RSDP_SIZE;
    let fadt_addr = xsdt_addr + xsdt_size as u64;
    let dsdt_addr = fadt_addr + fadt_size_placeholder;
    let madt_addr = dsdt_addr + dsdt.len() as u64;

    let fadt = build_fadt(dsdt_addr);
    let xsdt = build_xsdt(&[fadt_addr, madt_addr]);
    let rsdp = build_rsdp(xsdt_addr);

    let total_size = rsdp.len() as u64
        + xsdt.len() as u64
        + fadt.len() as u64
        + dsdt.len() as u64
        + madt.len() as u64;
    if rsdp_addr + total_size > HIMEM_START {
        return Err(Error::NotEnoughMemory);
    }

    mem.write_slice(&rsdp, GuestAddress(rsdp_addr))
        .map_err(|_| Error::WriteFailed)?;
    mem.write_slice(&xsdt, GuestAddress(xsdt_addr))
        .map_err(|_| Error::WriteFailed)?;
    mem.write_slice(&fadt, GuestAddress(fadt_addr))
        .map_err(|_| Error::WriteFailed)?;
    mem.write_slice(&dsdt, GuestAddress(dsdt_addr))
        .map_err(|_| Error::WriteFailed)?;
    mem.write_slice(&madt, GuestAddress(madt_addr))
        .map_err(|_| Error::WriteFailed)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn madt_has_one_lapic_entry_per_cpu() {
        let num_cpus = 4u8;
        let bytes = build_madt(num_cpus);
        assert_eq!(&bytes[0..4], b"APIC");

        let sum: u8 = bytes.iter().fold(0u8, |a, &b| a.wrapping_add(b));
        assert_eq!(sum, 0);

        // Fixed MADT header is 44 bytes (36-byte SDT header + 4 + 4), per ACPI 6.x.
        let mut offset = 44usize;
        let mut lapic_count = 0;
        let mut ioapic_count = 0;
        while offset < bytes.len() {
            let entry_type = bytes[offset];
            let entry_len = bytes[offset + 1] as usize;
            match entry_type {
                0 => lapic_count += 1,
                1 => ioapic_count += 1,
                t => panic!("unexpected MADT entry type {t}"),
            }
            offset += entry_len;
        }
        assert_eq!(lapic_count, num_cpus as usize);
        assert_eq!(ioapic_count, 1);
    }

    #[test]
    fn rsdp_checksums_are_valid() {
        let bytes = build_rsdp(crate::x86_64::layout::RSDP_ADDR);
        assert_eq!(bytes.len(), 36);

        // First 20 bytes (ACPI 1.0-compatible region) must sum to 0.
        let sum1: u8 = bytes[0..20].iter().fold(0u8, |a, &b| a.wrapping_add(b));
        assert_eq!(sum1, 0);

        // Full 36-byte structure must also sum to 0.
        let sum2: u8 = bytes.iter().fold(0u8, |a, &b| a.wrapping_add(b));
        assert_eq!(sum2, 0);

        assert_eq!(&bytes[0..8], b"RSD PTR ");
    }

    #[test]
    fn dsdt_is_valid_empty_table() {
        let bytes = build_dsdt();
        assert_eq!(&bytes[0..4], b"DSDT");
        assert_eq!(bytes.len(), 36); // fixed ACPI SDT header size, no AML body
        let sum: u8 = bytes.iter().fold(0u8, |a, &b| a.wrapping_add(b));
        assert_eq!(sum, 0);
    }

    #[test]
    fn fadt_layout_and_checksum() {
        let bytes = build_fadt(0x000e_1100);
        assert_eq!(&bytes[0..4], b"FACP");
        let sum: u8 = bytes.iter().fold(0u8, |a, &b| a.wrapping_add(b));
        assert_eq!(sum, 0);

        // x_dsdt field is at byte offset 140, little-endian u64 (ACPI 6.x FADT layout).
        let x_dsdt = u64::from_le_bytes(bytes[140..148].try_into().unwrap());
        assert_eq!(x_dsdt, 0x000e_1100);
    }

    #[test]
    fn xsdt_lists_all_entry_addresses() {
        let entries = [0x000e_2000u64, 0x000e_3000u64];
        let bytes = build_xsdt(&entries);
        assert_eq!(&bytes[0..4], b"XSDT");

        let sum: u8 = bytes.iter().fold(0u8, |a, &b| a.wrapping_add(b));
        assert_eq!(sum, 0);

        let header_size = 36; // fixed ACPI SDT header size
        for (i, expected) in entries.iter().enumerate() {
            let off = header_size + i * 8;
            let got = u64::from_le_bytes(bytes[off..off + 8].try_into().unwrap());
            assert_eq!(got, *expected);
        }
    }

    #[test]
    fn setup_acpi_fits_in_reserved_window() {
        let window_size = (HIMEM_START - RSDP_ADDR) as usize;
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(RSDP_ADDR), window_size)]).unwrap();

        setup_acpi(&mem, 4).unwrap();

        let rsdp: [u8; 8] = {
            let mut buf = [0u8; 8];
            mem.read_slice(&mut buf, GuestAddress(RSDP_ADDR)).unwrap();
            buf
        };
        assert_eq!(&rsdp, b"RSD PTR ");
    }

    #[test]
    fn setup_acpi_fails_if_window_too_small() {
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(RSDP_ADDR), 8)]).unwrap();
        assert!(setup_acpi(&mem, 4).is_err());
    }
}
