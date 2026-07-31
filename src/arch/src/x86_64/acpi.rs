// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use acpi_tables::rsdp::Rsdp;
use acpi_tables::sdt::Sdt;
use zerocopy::IntoBytes;

/// Builds a 36-byte ACPI 2.0+ RSDP pointing at the given XSDT address.
#[allow(dead_code)]
fn build_rsdp(xsdt_addr: u64) -> Vec<u8> {
    Rsdp::new(*b"LIBKRN", xsdt_addr).as_bytes().to_vec()
}

/// Builds a minimal valid DSDT (36-byte header, no AML body).
#[allow(dead_code)]
fn build_dsdt() -> Vec<u8> {
    Sdt::new(*b"DSDT", 36, 2, *b"LIBKRN", *b"KRUNDSDT", 1)
        .as_slice()
        .to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
