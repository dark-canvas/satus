// https://en.wikipedia.org/wiki/Executable_and_Linkable_Format
// https://wiki.osdev.org/ELF

use uefi::prelude::*;

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
        if header.exe_type != ELF_TYPE_PIE_EXECUTABLE {
            return Err("Not an executable ELF");
        }

        // Verify machine
        if header.machine != ELF_MACHINE_X86_64 {
            return Err("Not x86_64 ELF");
        }

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
        let mut mem_size = 0usize;

        for ph in program_headers.iter() {
            if ph.ph_type == PT_LOAD {
                //let end_addr = ph.virt_address + ph.mem_size;
                //if end_addr > max_addr {
                //    max_addr = end_addr;
                //}
                mem_size += ph.mem_size as usize;
            }
        }

        mem_size
    }

    pub fn load_segment_to_address(&self, ph: &Elf64ProgramHeader, kernel_base_address: usize) -> Result<(), &'static str> {
        let ph_offset = ph.offset as usize;
        let ph_filesz = ph.file_size as usize;
        let ph_vaddr = ph.virt_address as usize;

        if self.raw_data.len() < ph_offset + ph_filesz {
            return Err("Segment data is too small");
        }

        let segment_data = &self.raw_data[ph_offset..ph_offset + ph_filesz];
        let dest_addr = kernel_base_address + ph_vaddr;

        unsafe {
            let dest_ptr = dest_addr as *mut u8;
            core::ptr::copy_nonoverlapping(segment_data.as_ptr(), dest_ptr, segment_data.len());

            // zero out the remaining memory if mem_size > file_size
            let ph_memsz = ph.mem_size as usize;
            if ph_memsz > ph_filesz {
                let zero_start = dest_ptr.add(ph_filesz);
                let zero_size = ph_memsz - ph_filesz;
                core::ptr::write_bytes(zero_start, 0, zero_size);
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