use uefi::boot::MemoryType;
use uefi::boot::AllocateType;
use uefi::{CStr16, cstr16};

const MAX_MODULES: usize = 51; // To fit in a 4096 byte page

// 16 bytes of header
#[repr(C)]
struct ModuuleListHeader {
    num_modules: u16,
    reserved: [u8; 14], // Padding to make the header 16 bytes

}
// Create an array of these that ends up being 4096 bytes (a page)
// KernelModuuleInfo is 64 bytes, so we can fit 64 of them in a page
// The location of the module is listed in page granularity, using u16 
// types, which can span ~2GB of memory, which should more more than 
// enough for bood-loader-loaded modules (other modules can be loaded 
// later, utilizing these other modules as needed)
#[repr(C)]
struct ModuleInfo {
    module_name: [u8; 64], // Assuming max module name length of 64 bytes
    entry: usize,
    page_start: u16, // 64k * 4k == 256mb worth of boot-loaded modules
    num_pages: u16,  // may or may not enough but there's room for expansion
    other: u32,
}

// List of modules loaded, occupies a full page.  This page will be 
// passed to the kernel via a register (rax?)
#[repr(C)]
struct ModuleListPage {
    header: ModuuleListHeader,
    modules: [ModuleInfo; MAX_MODULES], // If not enough we can link pages somewhow
}

pub struct ModuleList {
    raw_data: *mut ModuleListPage,
}

impl ModuleList {
    pub fn new() -> Result<ModuleList, &'static str> {
        let kernel_pages = 1; // Assuming 1 page is enough for the module list
        let non_null = uefi::boot::allocate_pages(
            AllocateType::AnyPages,
            MemoryType::LOADER_DATA,
            kernel_pages,
        )
        .map_err(|_| "Failed to allocate pages")?;

        let list = ModuleList { raw_data: non_null.as_ptr() as *mut ModuleListPage};
        unsafe {
            (*list.raw_data).header.num_modules = 0;
        }
        Ok(list)
    }

    pub fn get_page_ptr(&self) -> usize {
        self.raw_data as usize
    }

    pub fn get_num_modules(&self) -> usize {
        unsafe {
            (*self.raw_data).header.num_modules as usize
        }
    }

    pub fn append(&mut self, name: &CStr16, base_addr: usize, size: usize, entry: usize) -> Result<(), &'static str> {
        unsafe {
            let num_modules = (*self.raw_data).header.num_modules as usize;
            if num_modules >= 51 {
                return Err("Module list is full");
            }

            let module_info = &mut (*self.raw_data).modules[num_modules];
            // Copy the name into the module_info, truncating if necessary
            let name_bytes = name.as_bytes();
            let copy_len = core::cmp::min(name_bytes.len(), 64);
            module_info.module_name[..copy_len].copy_from_slice(&name_bytes[..copy_len]);
            module_info.entry = entry;
            module_info.page_start = (base_addr / 4096) as u16; // Assuming 4k pages
            module_info.num_pages = ((size + 4095) / 4096) as u16; // Round up to nearest page
            module_info.other = 0; // Reserved for future use

            (*self.raw_data).header.num_modules += 1;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_size() {
        assert_eq!(std::mem::size_of::<KernelModuuleListHeader>(), 16);
        assert_eq!(std::mem::size_of::<KernelModuleInfo>(), 80);
        assert_eq!(std::mem::size_of::<KernelModuleList>(), 4096);
    }
}