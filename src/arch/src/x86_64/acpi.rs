use std::{mem, slice};

use vm_memory::{ByteValued, Bytes, GuestAddress, GuestMemoryMmap};

use super::layout::{ACPI_REGION_SIZE, ACPI_RSDP_ADDR, ACPI_TABLES_START};

const LOCAL_APIC_ADDR: u32 = 0xFEE0_0000;
const IOAPIC_ADDR: u32 = 0xFEC0_0000;
const HW_REDUCED_ACPI: u32 = 1 << 20;

const OEM_ID: [u8; 6] = *b"KRUN  ";
const OEM_TABLE_ID: [u8; 8] = *b"KRUNVMM ";
const CREATOR_ID: [u8; 4] = *b"KRUN";

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    NotEnoughMemory,
    WriteMem(String),
}

type Result<T> = std::result::Result<T, Error>;

fn compute_checksum<T: Copy>(v: &T) -> u8 {
    let v_slice = unsafe { slice::from_raw_parts(v as *const T as *const u8, mem::size_of::<T>()) };
    let mut checksum: u8 = 0;
    for i in v_slice.iter() {
        checksum = checksum.wrapping_add(*i);
    }
    checksum
}

#[repr(C, packed)]
#[derive(Copy, Clone, Default)]
struct Rsdp {
    signature: [u8; 8],
    checksum: u8,
    oem_id: [u8; 6],
    revision: u8,
    rsdt_address: u32,
    length: u32,
    xsdt_address: u64,
    extended_checksum: u8,
    reserved: [u8; 3],
}

// SAFETY: Rsdp is a packed repr(C) struct with no padding.
unsafe impl ByteValued for Rsdp {}

#[repr(C, packed)]
#[derive(Copy, Clone, Default)]
struct SdtHeader {
    signature: [u8; 4],
    length: u32,
    revision: u8,
    checksum: u8,
    oem_id: [u8; 6],
    oem_table_id: [u8; 8],
    oem_revision: u32,
    creator_id: [u8; 4],
    creator_revision: u32,
}

// SAFETY: SdtHeader is a packed repr(C) struct with no padding.
unsafe impl ByteValued for SdtHeader {}

#[repr(C, packed)]
#[derive(Copy, Clone, Default)]
struct MadtLocalApic {
    entry_type: u8,
    length: u8,
    acpi_processor_uid: u8,
    apic_id: u8,
    flags: u32,
}

// SAFETY: MadtLocalApic is a packed repr(C) struct with no padding.
unsafe impl ByteValued for MadtLocalApic {}

#[repr(C, packed)]
#[derive(Copy, Clone, Default)]
struct MadtIoApic {
    entry_type: u8,
    length: u8,
    io_apic_id: u8,
    reserved: u8,
    io_apic_address: u32,
    global_system_interrupt_base: u32,
}

// SAFETY: MadtIoApic is a packed repr(C) struct with no padding.
unsafe impl ByteValued for MadtIoApic {}

const FADT_SIZE: usize = 276;
const FADT_FLAGS_OFFSET: usize = 112;
const FADT_X_DSDT_OFFSET: usize = 140;

pub fn setup_acpi_tables(mem: &GuestMemoryMmap, num_cpus: u8) -> Result<()> {
    let madt_size = mem::size_of::<SdtHeader>()
        + 8 // Local APIC Address (u32) + Flags (u32)
        + mem::size_of::<MadtLocalApic>() * num_cpus as usize
        + mem::size_of::<MadtIoApic>();
    let xsdt_size = mem::size_of::<SdtHeader>() + 2 * mem::size_of::<u64>();
    let dsdt_size = mem::size_of::<SdtHeader>();
    let fadt_size = FADT_SIZE;

    let total = mem::size_of::<Rsdp>() + xsdt_size + madt_size + fadt_size + dsdt_size;
    if total > ACPI_REGION_SIZE {
        return Err(Error::NotEnoughMemory);
    }

    let mut offset = ACPI_TABLES_START;

    // DSDT
    let dsdt_addr = offset;
    let dsdt = SdtHeader {
        signature: *b"DSDT",
        length: dsdt_size as u32,
        revision: 2,
        oem_id: OEM_ID,
        oem_table_id: OEM_TABLE_ID,
        oem_revision: 1,
        creator_id: CREATOR_ID,
        creator_revision: 1,
        ..Default::default()
    };
    let dsdt_checksum = (!compute_checksum(&dsdt)).wrapping_add(1);
    let dsdt = SdtHeader {
        checksum: dsdt_checksum,
        ..dsdt
    };
    mem.write_obj(dsdt, GuestAddress(dsdt_addr))
        .map_err(|e| Error::WriteMem(format!("{e:?}")))?;
    offset += dsdt_size as u64;

    // FADT — written as a byte buffer since the struct is 276 bytes
    let fadt_addr = offset;
    let fadt_header = SdtHeader {
        signature: *b"FACP",
        length: fadt_size as u32,
        revision: 6,
        oem_id: OEM_ID,
        oem_table_id: OEM_TABLE_ID,
        oem_revision: 1,
        creator_id: CREATOR_ID,
        creator_revision: 1,
        ..Default::default()
    };
    let mut fadt_bytes = vec![0u8; fadt_size];
    let header_bytes = unsafe {
        slice::from_raw_parts(
            &fadt_header as *const SdtHeader as *const u8,
            mem::size_of::<SdtHeader>(),
        )
    };
    fadt_bytes[..mem::size_of::<SdtHeader>()].copy_from_slice(header_bytes);
    fadt_bytes[FADT_FLAGS_OFFSET..FADT_FLAGS_OFFSET + 4]
        .copy_from_slice(&HW_REDUCED_ACPI.to_le_bytes());
    fadt_bytes[FADT_X_DSDT_OFFSET..FADT_X_DSDT_OFFSET + 8]
        .copy_from_slice(&dsdt_addr.to_le_bytes());
    let fadt_sum: u8 = fadt_bytes.iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
    fadt_bytes[9] = (!fadt_sum).wrapping_add(1);
    mem.write(&fadt_bytes, GuestAddress(fadt_addr))
        .map_err(|e| Error::WriteMem(format!("{e:?}")))?;
    offset += fadt_size as u64;

    // MADT
    let madt_addr = offset;
    let madt_header = SdtHeader {
        signature: *b"APIC",
        length: madt_size as u32,
        revision: 5,
        oem_id: OEM_ID,
        oem_table_id: OEM_TABLE_ID,
        oem_revision: 1,
        creator_id: CREATOR_ID,
        creator_revision: 1,
        ..Default::default()
    };
    mem.write_obj(madt_header, GuestAddress(madt_addr))
        .map_err(|e| Error::WriteMem(format!("{e:?}")))?;

    let mut madt_offset = madt_addr + mem::size_of::<SdtHeader>() as u64;

    // Local APIC Address + Flags
    mem.write_obj(LOCAL_APIC_ADDR, GuestAddress(madt_offset))
        .map_err(|e| Error::WriteMem(format!("{e:?}")))?;
    madt_offset += 4;
    mem.write_obj(1u32, GuestAddress(madt_offset))
        .map_err(|e| Error::WriteMem(format!("{e:?}")))?;
    madt_offset += 4;

    // Local APIC entries
    for i in 0..num_cpus {
        let lapic = MadtLocalApic {
            entry_type: 0,
            length: mem::size_of::<MadtLocalApic>() as u8,
            acpi_processor_uid: i,
            apic_id: i,
            flags: 1,
        };
        mem.write_obj(lapic, GuestAddress(madt_offset))
            .map_err(|e| Error::WriteMem(format!("{e:?}")))?;
        madt_offset += mem::size_of::<MadtLocalApic>() as u64;
    }

    // IOAPIC entry
    let ioapic = MadtIoApic {
        entry_type: 1,
        length: mem::size_of::<MadtIoApic>() as u8,
        io_apic_id: num_cpus,
        io_apic_address: IOAPIC_ADDR,
        ..Default::default()
    };
    mem.write_obj(ioapic, GuestAddress(madt_offset))
        .map_err(|e| Error::WriteMem(format!("{e:?}")))?;

    // Compute MADT checksum over the entire table
    let mut madt_bytes = vec![0u8; madt_size];
    mem.read(&mut madt_bytes, GuestAddress(madt_addr))
        .map_err(|e| Error::WriteMem(format!("{e:?}")))?;
    let madt_sum: u8 = madt_bytes.iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
    let madt_checksum = (!madt_sum).wrapping_add(1);
    mem.write_obj(
        madt_checksum,
        GuestAddress(madt_addr + 9), // checksum field offset in SdtHeader
    )
    .map_err(|e| Error::WriteMem(format!("{e:?}")))?;

    offset = madt_addr + madt_size as u64;

    // XSDT
    let xsdt_addr = offset;
    let xsdt_header = SdtHeader {
        signature: *b"XSDT",
        length: xsdt_size as u32,
        revision: 1,
        oem_id: OEM_ID,
        oem_table_id: OEM_TABLE_ID,
        oem_revision: 1,
        creator_id: CREATOR_ID,
        creator_revision: 1,
        ..Default::default()
    };
    mem.write_obj(xsdt_header, GuestAddress(xsdt_addr))
        .map_err(|e| Error::WriteMem(format!("{e:?}")))?;

    let entries_offset = xsdt_addr + mem::size_of::<SdtHeader>() as u64;
    mem.write_obj(fadt_addr, GuestAddress(entries_offset))
        .map_err(|e| Error::WriteMem(format!("{e:?}")))?;
    mem.write_obj(madt_addr, GuestAddress(entries_offset + 8))
        .map_err(|e| Error::WriteMem(format!("{e:?}")))?;

    // Compute XSDT checksum
    let mut xsdt_bytes = vec![0u8; xsdt_size];
    mem.read(&mut xsdt_bytes, GuestAddress(xsdt_addr))
        .map_err(|e| Error::WriteMem(format!("{e:?}")))?;
    let xsdt_sum: u8 = xsdt_bytes.iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
    let xsdt_checksum = (!xsdt_sum).wrapping_add(1);
    mem.write_obj(xsdt_checksum, GuestAddress(xsdt_addr + 9))
        .map_err(|e| Error::WriteMem(format!("{e:?}")))?;

    // RSDP
    let rsdp = Rsdp {
        signature: *b"RSD PTR ",
        oem_id: OEM_ID,
        revision: 2,
        rsdt_address: 0,
        length: mem::size_of::<Rsdp>() as u32,
        xsdt_address: xsdt_addr,
        ..Default::default()
    };
    // Legacy checksum (first 20 bytes)
    let legacy_sum: u8 = unsafe {
        slice::from_raw_parts(&rsdp as *const Rsdp as *const u8, 20)
            .iter()
            .fold(0u8, |acc, &b| acc.wrapping_add(b))
    };
    let legacy_checksum = (!legacy_sum).wrapping_add(1);
    // Extended checksum (all 36 bytes)
    let extended_sum = compute_checksum(&Rsdp {
        checksum: legacy_checksum,
        ..rsdp
    });
    let extended_checksum = (!extended_sum).wrapping_add(1);
    let rsdp = Rsdp {
        checksum: legacy_checksum,
        extended_checksum,
        ..rsdp
    };
    mem.write_obj(rsdp, GuestAddress(ACPI_RSDP_ADDR))
        .map_err(|e| Error::WriteMem(format!("{e:?}")))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use vm_memory::GuestMemoryMmap;

    fn create_guest_mem() -> GuestMemoryMmap {
        GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10_0000)]).unwrap()
    }

    #[test]
    fn test_setup_acpi_tables() {
        let mem = create_guest_mem();
        setup_acpi_tables(&mem, 4).unwrap();

        // Verify RSDP signature
        let mut sig = [0u8; 8];
        mem.read(&mut sig, GuestAddress(ACPI_RSDP_ADDR)).unwrap();
        assert_eq!(&sig, b"RSD PTR ");

        // Verify RSDP legacy checksum (first 20 bytes sum to 0)
        let mut rsdp_bytes = [0u8; 20];
        mem.read(&mut rsdp_bytes, GuestAddress(ACPI_RSDP_ADDR))
            .unwrap();
        let sum: u8 = rsdp_bytes.iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
        assert_eq!(sum, 0);

        // Verify RSDP extended checksum (all 36 bytes sum to 0)
        let mut rsdp_full = [0u8; 36];
        mem.read(&mut rsdp_full, GuestAddress(ACPI_RSDP_ADDR))
            .unwrap();
        let sum: u8 = rsdp_full.iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
        assert_eq!(sum, 0);
    }

    #[test]
    fn test_dsdt_checksum() {
        let mem = create_guest_mem();
        setup_acpi_tables(&mem, 1).unwrap();

        let mut dsdt_bytes = vec![0u8; mem::size_of::<SdtHeader>()];
        mem.read(&mut dsdt_bytes, GuestAddress(ACPI_TABLES_START))
            .unwrap();
        let sum: u8 = dsdt_bytes.iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
        assert_eq!(sum, 0);
    }

    #[test]
    fn test_single_cpu() {
        let mem = create_guest_mem();
        setup_acpi_tables(&mem, 1).unwrap();
    }

    #[test]
    fn test_max_cpus() {
        let mem = create_guest_mem();
        setup_acpi_tables(&mem, 255).unwrap();
    }
}
