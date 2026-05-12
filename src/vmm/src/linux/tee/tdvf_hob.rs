use vm_memory::{ByteValued, Bytes, GuestAddress, GuestMemoryMmap};

const EFI_HOB_TYPE_HANDOFF: u16 = 0x0001;
const EFI_HOB_TYPE_RESOURCE_DESCRIPTOR: u16 = 0x0003;
const EFI_HOB_TYPE_END_OF_HOB_LIST: u16 = 0xFFFF;

const EFI_RESOURCE_MEMORY_UNACCEPTED: u32 = 0x0000_0007;

const EFI_RESOURCE_ATTRIBUTE_PRESENT: u32 = 0x1;
const EFI_RESOURCE_ATTRIBUTE_INITIALIZED: u32 = 0x2;
const EFI_RESOURCE_ATTRIBUTE_TESTED: u32 = 0x4;
const EFI_RESOURCE_ATTRIBUTE_UNCACHEABLE: u32 = 0x400;
const EFI_RESOURCE_ATTRIBUTE_WRITE_COMBINEABLE: u32 = 0x800;
const EFI_RESOURCE_ATTRIBUTE_WRITE_THROUGH_CACHEABLE: u32 = 0x1000;
const EFI_RESOURCE_ATTRIBUTE_WRITE_BACK_CACHEABLE: u32 = 0x2000;

const SYSTEM_MEMORY_ATTRIBUTES: u32 = EFI_RESOURCE_ATTRIBUTE_PRESENT
    | EFI_RESOURCE_ATTRIBUTE_INITIALIZED
    | EFI_RESOURCE_ATTRIBUTE_TESTED
    | EFI_RESOURCE_ATTRIBUTE_UNCACHEABLE
    | EFI_RESOURCE_ATTRIBUTE_WRITE_COMBINEABLE
    | EFI_RESOURCE_ATTRIBUTE_WRITE_THROUGH_CACHEABLE
    | EFI_RESOURCE_ATTRIBUTE_WRITE_BACK_CACHEABLE;

const EFI_HOB_HANDOFF_TABLE_VERSION: u32 = 0x0009;

#[repr(C, packed)]
#[derive(Copy, Clone, Default)]
struct EfiHobGenericHeader {
    hob_type: u16,
    hob_length: u16,
    reserved: u32,
}

// SAFETY: EfiHobGenericHeader is a packed repr(C) struct with no padding.
unsafe impl ByteValued for EfiHobGenericHeader {}

#[repr(C, packed)]
#[derive(Copy, Clone, Default)]
struct EfiHobHandoffInfoTable {
    header: EfiHobGenericHeader,
    version: u32,
    boot_mode: u32,
    efi_memory_top: u64,
    efi_memory_bottom: u64,
    efi_free_memory_top: u64,
    efi_free_memory_bottom: u64,
    efi_end_of_hob_list: u64,
}

// SAFETY: EfiHobHandoffInfoTable is a packed repr(C) struct with no padding.
unsafe impl ByteValued for EfiHobHandoffInfoTable {}

#[repr(C, packed)]
#[derive(Copy, Clone, Default)]
struct EfiHobResourceDescriptor {
    header: EfiHobGenericHeader,
    owner: [u8; 16],
    resource_type: u32,
    resource_attribute: u32,
    physical_start: u64,
    resource_length: u64,
}

// SAFETY: EfiHobResourceDescriptor is a packed repr(C) struct with no padding.
unsafe impl ByteValued for EfiHobResourceDescriptor {}

#[derive(Debug)]
pub enum Error {
    WriteMem(vm_memory::GuestMemoryError),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::WriteMem(e) => write!(f, "Failed to write HOB to guest memory: {e}"),
        }
    }
}

type Result<T> = std::result::Result<T, Error>;

pub fn build_hobs(
    mem: &GuestMemoryMmap,
    hob_address: u64,
    hob_size: u64,
    ram_below_gap: u64,
    ram_above_gap: u64,
) -> Result<()> {
    let mut offset = 0u64;

    let phit_size = std::mem::size_of::<EfiHobHandoffInfoTable>() as u64;
    let resource_size = std::mem::size_of::<EfiHobResourceDescriptor>() as u64;
    let end_size = std::mem::size_of::<EfiHobGenericHeader>() as u64;

    let num_resources = if ram_above_gap > 0 { 2u64 } else { 1u64 };
    let end_of_hob_list = hob_address + phit_size + resource_size * num_resources;

    let phit = EfiHobHandoffInfoTable {
        header: EfiHobGenericHeader {
            hob_type: EFI_HOB_TYPE_HANDOFF,
            hob_length: phit_size as u16,
            reserved: 0,
        },
        version: EFI_HOB_HANDOFF_TABLE_VERSION,
        boot_mode: 0,
        efi_memory_top: hob_address + hob_size,
        efi_memory_bottom: hob_address,
        efi_free_memory_top: hob_address + hob_size,
        efi_free_memory_bottom: end_of_hob_list + end_size,
        efi_end_of_hob_list: end_of_hob_list,
    };
    mem.write_obj(phit, GuestAddress(hob_address + offset))
        .map_err(Error::WriteMem)?;
    offset += phit_size;

    let ram_low = EfiHobResourceDescriptor {
        header: EfiHobGenericHeader {
            hob_type: EFI_HOB_TYPE_RESOURCE_DESCRIPTOR,
            hob_length: resource_size as u16,
            reserved: 0,
        },
        owner: [0u8; 16],
        resource_type: EFI_RESOURCE_MEMORY_UNACCEPTED,
        resource_attribute: SYSTEM_MEMORY_ATTRIBUTES,
        physical_start: 0,
        resource_length: ram_below_gap,
    };
    mem.write_obj(ram_low, GuestAddress(hob_address + offset))
        .map_err(Error::WriteMem)?;
    offset += resource_size;

    if ram_above_gap > 0 {
        let ram_high = EfiHobResourceDescriptor {
            header: EfiHobGenericHeader {
                hob_type: EFI_HOB_TYPE_RESOURCE_DESCRIPTOR,
                hob_length: resource_size as u16,
                reserved: 0,
            },
            owner: [0u8; 16],
            resource_type: EFI_RESOURCE_MEMORY_UNACCEPTED,
            resource_attribute: SYSTEM_MEMORY_ATTRIBUTES,
            physical_start: arch::x86_64::layout::FIRST_ADDR_PAST_32BITS,
            resource_length: ram_above_gap,
        };
        mem.write_obj(ram_high, GuestAddress(hob_address + offset))
            .map_err(Error::WriteMem)?;
        offset += resource_size;
    }

    let end = EfiHobGenericHeader {
        hob_type: EFI_HOB_TYPE_END_OF_HOB_LIST,
        hob_length: end_size as u16,
        reserved: 0,
    };
    mem.write_obj(end, GuestAddress(hob_address + offset))
        .map_err(Error::WriteMem)?;

    Ok(())
}
