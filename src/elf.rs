//! A simple ELF binary loader
//!
//! This providers only enough functionality to read in an ELF file, verify it, and load it into memory.
//! It does not support any dynamic linking, relocation, or other features of the ELF format. 
//! It is assumed that the ELF binary is 64-bit (x64-64), little-endian, and has been configured with the 
//! proper linear address for loading into the upper half of the address space.
//!
//! See also:
//!  - https://en.wikipedia.org/wiki/Executable_and_Linkable_Format
//!  - https://wiki.osdev.org/ELF

use uefi::prelude::*;
use log::info;
use crate::types::Address;
use crate::pager::{PhysicalAddress, VirtualAddress};

pub struct Elf64File<'a> {
    raw_data: &'a [u8],
}

impl<'a> Elf64File<'a> {
    pub fn new(data: &'a [u8]) -> Result<Self, &'static str> {
        let result = Elf64File {
            raw_data: data,
        };

        let header = result.get_header().unwrap();

        // Verify magic
        if header.magic != ELF_MAGIC {
            return Err("Invalid ELF magic");
        }

        // Verify class
        if header.class != ELF_CLASS_64 {
            return Err("Not a 64-bit ELF");
        }

        // Verify data encoding
        if header.data != ELF_DATA_LITTLE_ENDIAN {
            return Err("Not little-endian ELF");
        }

        // Verify type
        if header.exe_type != ELF_TYPE_PIE_EXECUTABLE && header.exe_type != ELF_TYPE_EXECUTABLE {
            return Err("Not an executable ELF");
        }

        // Verify machine
        if header.machine != ELF_MACHINE_X86_64 {
            return Err("Not x86_64 ELF");
        }

        let entry_size = header.ph_entry_size as usize;
        let num_entries = header.ph_num as usize;
        info!("ph entry size {}, num {} struct size {}", entry_size, num_entries, size_of::<Elf64ProgramHeader>());

        Ok(result)
    }

    pub fn get_header(&self) -> Result<&Elf64Header, &'static str> {
        if self.raw_data.len() < size_of::<Elf64Header>() {
            return Err("ELF data too small");
        }

        unsafe {
            Ok(&*(self.raw_data.as_ptr() as *const Elf64Header))
        }  
    }

    pub fn get_program_headers(&self) -> Result<&[Elf64ProgramHeader], &'static str> {
        let header = self.get_header()?;

        let ph_offset = header.ph_offset as usize;
        let ph_entry_size = header.ph_entry_size as usize;
        let ph_num = header.ph_num as usize;

        let required_size = ph_offset + (ph_entry_size * ph_num);
        if self.raw_data.len() < required_size {
            return Err("ELF data too small for program headers");
        }

        let ph_slice = &self.raw_data[ph_offset..required_size];

        unsafe {
            let ptr = ph_slice.as_ptr() as *const Elf64ProgramHeader;
            Ok(core::slice::from_raw_parts(ptr, ph_num))
        }
    }

    pub fn get_mem_size(&self) -> usize {
        let program_headers = self.get_program_headers().unwrap();
        let mut max_addr = 0u64;
        let mut min_addr = u64::MAX as u64;

        for ph in program_headers.iter() {
            if ph.ph_type == PT_LOAD {
                let end_addr = ph.virt_address + ph.mem_size;
                if end_addr > max_addr {
                    max_addr = end_addr;
                }
                if ph.virt_address < min_addr {
                    min_addr = ph.virt_address;
                }
            }
        }

        (max_addr - min_addr) as usize
    }

    pub fn get_virtual_address(&self) -> VirtualAddress {
        let program_headers = self.get_program_headers().unwrap();
        let mut min_virtual = None;
        for ph in program_headers.iter() {
            if ph.ph_type == PT_LOAD {
                let vaddr = ph.virt_address;
                if min_virtual.is_none() || vaddr < min_virtual.unwrap() {
                    min_virtual = Some(vaddr);
                }
            }
        }
        VirtualAddress::from_addr(min_virtual.unwrap_or(0))
    }

    pub fn relocate(&self) -> Result<(), &'static str> {
        self.relocate_to(0)
    }

    pub fn relocate_to(&self, kernel_base_address: Address) -> Result<(), &'static str> {
        let program_headers = self.get_program_headers().unwrap();
        for (i, ph) in program_headers.iter().enumerate() {
            // Must copy these out as they're potentially unaligned and rust won't create references to 
            // unaligned data (even though Intel supports it)
            let ph_type= ph.ph_type;
            let ph_offset = ph.offset;
            let ph_vaddr = ph.virt_address;
            let ph_paddr = ph.phys_address;
            let ph_filesz = ph.file_size;
            let ph_memsz = ph.mem_size;
            let ph_align = ph.align;

            info!(
                "Program Header {}: type {}, offset 0x{:x}, vaddr 0x{:x}, paddr 0x{:x}, filesz 0x{:x}, memsz 0x{:x}, align 0x{:x}",
                i, ph_type, ph_offset, ph_vaddr, ph_paddr, ph_filesz, ph_memsz, ph_align);

            match ph_type {
                PT_LOAD => {
                    info!("  -> This is a loadable segment copying to 0x{:x} + 0x{:x}", kernel_base_address, ph_vaddr);
                    self.load_segment_to_address(
                        ph,
                        kernel_base_address
                    ).unwrap();
                }
                _ => {}
            }
        }

        Ok(())
    }


    pub fn load_segment_to_address(&self, ph: &Elf64ProgramHeader, kernel_base_address: Address) -> Result<(), &'static str> {
        let kernel_base_address = kernel_base_address as usize;
        let ph_offset = ph.offset as usize;
        let ph_filesz = ph.file_size as usize;
        let ph_vaddr = ph.virt_address as usize;

        if self.raw_data.len() < ph_offset + ph_filesz {
            return Err("Segment data is too small");
        }

        info!("      size {:x} vma {:x} file off {:x}",
            ph_filesz, ph_vaddr, ph_offset);

        let segment_data = &self.raw_data[ph_offset..ph_offset + ph_filesz];
        let dest_addr = kernel_base_address + ph_vaddr;

        unsafe {
            let dest_ptr = dest_addr as *mut u8;
            info!("    copying {:x} to {:x} ({} bytes)", segment_data.as_ptr() as usize, dest_ptr as usize, segment_data.len());
            core::ptr::copy_nonoverlapping(segment_data.as_ptr(), dest_ptr, segment_data.len());

            // zero out the remaining memory if mem_size > file_size
            let ph_memsz = ph.mem_size as usize;
            if ph_memsz > ph_filesz {
                let zero_start = dest_ptr.add(ph_filesz);
                let zero_size = ph_memsz - ph_filesz;
                info!("    zeroing {:x} ({} bytes)", zero_start as usize, zero_size);
                core::ptr::write_bytes(zero_start, 0, zero_size);
            }

            // debug... dump out the first 16 bytes of the loaded segment
            info!("      First 8 bytes of loaded segment:");
            for i in 0..8 {
                let byte = *dest_ptr.add(i);
                info!("      {:x}:    {:02x}", dest_ptr.add(i) as usize, byte);
            }
        }

        Ok(())
    }
}


#[repr(C, packed)]
pub struct Elf64Header {
    //pub e_ident: [u8; 16],   /* ELF identification bytes */
    pub magic: [u8; 4],      /* Magic number: 0x7F 'E' 'L' 'F' */
    pub class: u8,          /* 1 = 32-bit, 2 = 64-bit */
    pub data: u8,           /* 1 = little-endian, 2 = big-endian */
    pub header_version: u8,        /* ELF version */
    pub os_abi: u8,         /* Operating system ABI */
    pub abi_version: u8,    /* ABI version */
    pub pad: [u8; 7],       /* Padding bytes */

    pub exe_type: u16,     /* Type of file (e.g., Executable) */
    pub machine: u16,      /* Machine architecture */
    pub version: u32,      /* ELF format version */
    pub entry: u64,        /* Entry point address */
    pub ph_offset: u64,    /* Program header table file offset */
    pub sh_offset: u64,    /* Section header table file offset */
    pub flags: u32,        /* Architecture-specific flags */
    pub header_size: u16,  /* Size of ELF header in bytes */
    pub ph_entry_size: u16,    /* Size of program header entry */
    pub ph_num: u16,        /* Number of program header entries */
    pub sh_entry_size: u16,    /* Size of section header entry */
    pub sh_num: u16,          /* Number of section header entries */
    pub sh_string_index: u16,     /* Section name string table index */
}

impl Elf64Header {
    pub fn get_entry_point(&self) -> usize {
        self.entry as usize
    }
}

pub const ELF_MAGIC: [u8; 4] = [0x7F, b'E', b'L', b'F'];
pub const ELF_CLASS_64: u8 = 2;
pub const ELF_DATA_LITTLE_ENDIAN: u8 = 1;
pub const ELF_TYPE_EXECUTABLE: u16 = u16::from_be_bytes([0x00, 0x02]); // 2 (executable) in big-endian
pub const ELF_TYPE_PIE_EXECUTABLE: u16 = u16::from_be_bytes([0x00, 0x03]); // 3 (PIE executable) in big-endian
pub const ELF_MACHINE_X86_64: u16 = 0x3E;

#[repr(C, packed)]
pub struct Elf64ProgramHeader {
    pub ph_type: u32,
    pub flags: u32,
    pub offset: u64,
    pub virt_address: u64,
    pub phys_address: u64,
    pub file_size: u64,
    pub mem_size: u64,
    pub align: u64,
}

pub const PT_LOAD: u32 = 1;