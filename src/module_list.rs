

// 16 bytes of header
#[repr(C)]
struct KernelModuuleListHeader {
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
struct KernelModuleInfo {
    module_name: [u8; 64], // Assuming max module name length of 64 bytes
    entry: usize,
    page_start: u16, // 64k * 4k == 256mb worth of boot-loaded modules
    num_pages: u16,  // may or may not enough but there's room for expansion
    other: u32,
}

// List of modules loaded, occupies a full page.  This page will be 
// passed to the kernel via a register (rax?)
#[repr(C)]
struct KernelModuleList {
    header: KernelModuuleListHeader,
    modules: [KernelModuleInfo; 51], // If not enough we can link pages somewhow
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