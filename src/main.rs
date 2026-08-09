//! Satus UEFI bootloader
//!
//! This is a simple UEFI bootloader which is designed to load an ELF binary (the kernel) into 
//! the upper portion of virtual memory, and then jump to its entry point.
//! The loader can also load additional ELF modules from a predefined directory on disk, and 
//! pass a pointer to the list of loaded modules to the kernel via a config struct in memory.

#![no_std]
#![cfg_attr(not(test), no_main)]

mod types;
mod elf;
mod pager;

use uefi::table::cfg::ConfigTableEntry;

extern crate satus_struct;
use satus_struct::config::Config;
use satus_struct::cpu_config::CpuConfig;
use satus_struct::cpu_config::PerCpuConfig;
use satus_struct::module_list::ModuleList;
use satus_struct::memory_map::{MemoryMap as SatusMemoryMap, MemoryRegionType};

use core::ptr::NonNull;
use core::time::Duration;
use core::ffi::c_void;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use log::{error, info};
use uefi::boot::{self, SearchType};
use uefi::prelude::*;
use uefi::data_types::Event;
use uefi::proto::device_path::text::{
    AllowShortcuts, DevicePathToText, DisplayOnly,
};
use uefi::proto::loaded_image::LoadedImage;
use uefi::Identify; // provides DevicePathToText::GUID
use uefi::proto::media::fs::SimpleFileSystem;
use uefi::fs::FileSystem;
use uefi::boot::ScopedProtocol;
use uefi::{CString16, CStr16, cstr16};
use uefi::mem::memory_map::MemoryMap;
use uefi::mem::memory_map::MemoryMapMut;
use uefi::boot::MemoryType;
use uefi::proto::console::text::{Input, Key, ScanCode};
use uefi::Char16;
use uefi::proto::console::gop::{BltOp, BltPixel, PixelFormat, GraphicsOutput};
use uefi::boot::AllocateType;
use uefi::proto::pi::mp::MpServices;

use core::panic::PanicInfo;
use core::arch::asm;

use x86_64::PhysAddr;
use x86_64::VirtAddr;
use x86_64::registers::control::Cr3;
use x86_64::structures::paging::PageTableFlags;
use x86_64::structures::paging::PageTable;
use x86_64::instructions::tables;
use x86_64::structures::paging::Size4KiB;
use x86_64::structures::paging::PhysFrame;
use x86_64::structures::paging::page_table::PageTableEntry;
use raw_cpuid::CpuId;

use pager::{Pager, VirtualAddress, PhysicalAddress, bytes_to_pages};

use types::Address;

#[cfg(test)]
extern crate std;

#[cfg(not(test))]
#[global_allocator]
static ALLOCATOR: uefi::allocator::Allocator = uefi::allocator::Allocator;

const PAGE_SIZE: usize = 4096;
const PAGE_SIZE_1GB: usize = 1024 * 1024 * 1024;

const PHYSICAL_OFFSET: Address = 0xFFFFFF0000000000;

#[cfg(not(test))]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    info!("panic: {}", info.message());
    if let Some(location) = info.location() {
        info!("  {}:{}",
            location.file(),
            location.line(),
        );
    }
    loop {
        core::hint::spin_loop();
    }
}

fn read_keyboard_events(input: &mut Input) -> Result<(),()> {
    loop {
        // Pause until a keyboard event occurs.
        let mut events = [input.wait_for_key_event().unwrap()];
        boot::wait_for_event(&mut events).discard_errdata().map_err(|_| ())?;

        let u_key = Char16::try_from('u').unwrap();
        match input.read_key().discard_errdata().map_err(|_| ())? {

            Some(Key::Printable(key)) => {
                let char_value: char = key.into();
                
                info!("Key {} pressed", char_value);
            }

            // Example of handling a special key: exit the loop when the
            // escape key is pressed.
            Some(Key::Special(ScanCode::ESCAPE)) => {
                info!("Continuing....");
                break;
            }
            _ => {}
        }
    }

    Ok(())
}

// returns "conventional" memory (aka, memory below 1MB) which is accessible in 
// 16-bit real mode via a segment, offset pair
fn get_real_mode_pages(num: usize) -> Result<Address, &'static str> {
    get_pages_with_type(num, AllocateType::MaxAddress(0x100000))
}

fn get_pages(num: usize) -> Result<Address, &'static str> {
    get_pages_with_type(num, AllocateType::AnyPages)
}

fn get_pages_with_type(num: usize, page_type: AllocateType) -> Result<Address, &'static str> {
    info!("Requesting {} pages ({} bytes)", num, num * PAGE_SIZE);
    let non_null = uefi::boot::allocate_pages(
        page_type,
        MemoryType::LOADER_DATA,
        num,
    )
    .map_err(|_| "Failed to allocate pages")?;

    Ok(non_null.as_ptr() as Address)
}

fn allocate_buffer(size_required: usize) -> Result<Address,&'static str> {
    let kernel_pages = (size_required + (PAGE_SIZE-1)) / PAGE_SIZE;
    let result = get_pages(kernel_pages)?;

    info!("Allocated {} pages ({} bytes) at address 0x{:x}", kernel_pages, kernel_pages * PAGE_SIZE, result);

    Ok(result)
}

fn print_image_path() -> Result<(),&'static str> {
    let loaded_image =
        boot::open_protocol_exclusive::<LoadedImage>(boot::image_handle())
        .map_err(|_| "Failed to open loaded image protocol")?;

    let device_path_to_text_handle = *boot::locate_handle_buffer(
        SearchType::ByProtocol(&DevicePathToText::GUID),
    ).map_err(|_| "Failed to locate DevicePathToText handles")?
    .first()
    .expect("DevicePathToText is missing");

    let device_path_to_text = boot::open_protocol_exclusive::<DevicePathToText>(
        device_path_to_text_handle,
    ).map_err(|_| "Failed to open DevicePathToText protocol")?;

    let image_device_path =
        loaded_image.file_path().expect("File path is not set");
    let image_device_path_text = device_path_to_text
        .convert_device_path_to_text(
            image_device_path,
            DisplayOnly(true),
            AllowShortcuts(false),
        )
        .expect("convert_device_path_to_text failed");

    info!("Image path: {}", &*image_device_path_text);
    Ok(())
}

fn gfx_test() {
    use uefi::proto::console::gop::{GraphicsOutput, PixelFormat};
    let gop_handle = 
        boot::get_handle_for_protocol::<GraphicsOutput>().expect("Can get GOP handle");
    let mut gop = 
        boot::open_protocol_exclusive::<GraphicsOutput>(gop_handle).unwrap();

    info!("Available GOP modes:");
    for mode in gop.modes() {
        let mode_info = mode.info();
        let (width, height) = mode_info.resolution();
        info!("  {}x{}, Pixel Format: {:?}", width, height, mode_info.pixel_format());
        if let Some(pixel_mask) = mode_info.pixel_bitmask() {
            info!("  R: 0x{:08x}\n  G: 0x{:08x}\n  B: 0x{:08x}", pixel_mask.red, pixel_mask.green, pixel_mask.blue);
        }
    }

    let mode_info = gop.current_mode_info();
    let (width, height) = mode_info.resolution();
    info!("GOP resolution: {}x{}", width, height);
    info!("Pixel format: {:?}", mode_info.pixel_format());

    let mut frame_buffer = gop.frame_buffer();
    let buffer_size = frame_buffer.size();
    info!("Frame buffer size: {} bytes", buffer_size);

    // clear to black
    /*
    let ptr = frame_buffer.as_mut_ptr();
    unsafe {
        for i in 0..buffer_size {
            ptr.add(i).write_volatile(0x0);
        }
    }
    */

    // Same thing, but without the unsafe..
    
    /*
    // Define color (Black)
    let black = BltPixel::new(0, 0, 0);

    // Perform a video fill operation
    gop.blt(BltOp::VideoFill {
        color: black,
        dest: (0, 0),
        dims: (width, height),
    }).expect("Failed to clear screen");
    */
    // TODO: display a loading animation
}

fn load_modules(mut fs: uefi::fs::FileSystem, module_list: &mut ModuleList) {
    // Iterate all the modules and load them, and save them to the list
    let path = cstr16!("\\efi\\boot\\modules");
    if let Ok(dir_listing) = fs.read_dir(path) {
        info!("Loading modules from {}", path);
        for file in dir_listing {
            let file_info = file.as_ref().unwrap(); // do we need as_ref) here?
            if file_info.is_regular_file() {
                let mut full_name = CString16::try_from(path).unwrap();
                full_name.push_str(cstr16!("\\"));
                full_name.push_str(file_info.file_name());
                info!("Loading module from path: {}", full_name);
                
                let module_buf = fs.read(full_name.as_ref()).unwrap();
                info!("Module size: {} bytes", module_buf.len());
                let elf_module = elf::Elf64File::new(module_buf.as_slice()).unwrap();
                let module_base_address = allocate_buffer(elf_module.get_mem_size()).unwrap();
                // TODO: this module wont be executable from this location... it'll need to be mapped to the correct place 
                // by the kernel (with each module in its own P3 address space)
                elf_module.relocate_to(module_base_address).unwrap();
                // TODO: we need the entry point... and where the module is expected to be loaded
                module_list.append(file_info.file_name().as_bytes(), module_base_address, elf_module.get_mem_size(), 0).unwrap();
            }
        }
    }
}

fn get_memory_type(ty: MemoryType) -> MemoryRegionType {
    match ty {
        MemoryType::RESERVED | MemoryType::ACPI_RECLAIM | MemoryType::ACPI_NON_VOLATILE |
        MemoryType::MMIO | MemoryType::MMIO_PORT_SPACE | MemoryType::PAL_CODE |
        MemoryType::PERSISTENT_MEMORY =>
            MemoryRegionType::Reserved,
        MemoryType::UNUSABLE | MemoryType::UNACCEPTED | MemoryType::MAX =>
            MemoryRegionType::NonExistent,
        // probably loader_code can be made available
        // loader_data is what we get when we allocate memory (such as for the kernel, or a page table)
        MemoryType::LOADER_CODE | MemoryType::LOADER_DATA =>
            MemoryRegionType::Allocated,
        // Conventional is legit available, boot services wont exist by the time the kernel 
        // gets to see this struct, and we wont be using runtime services...
        // NOTE: BOOT_SERVICES_DATA includes all the page tables!!!
        // We're including this in available memory, which means once these pages 
        // get entered into the kernel pager, and provided to consumers, we can no longer 
        // trust any memory mapped by the UEFI firmware, which means we must clean the 
        // identity map which the firmware produced for us... we can't do that in the boot-loader, 
        // though, as the boot loaded is executing within that identity map.
        // We can (and do) however, reallocate the GDT and PML4 table.
        MemoryType::BOOT_SERVICES_CODE | MemoryType::BOOT_SERVICES_DATA |
        MemoryType::RUNTIME_SERVICES_CODE | MemoryType::RUNTIME_SERVICES_DATA |
        MemoryType::CONVENTIONAL =>
            MemoryRegionType::Available,
        _ => panic!("Unknown memory type {:?}", ty)
    }
}

fn get_max_physical_address() -> Address {
    let mut max_addr : Address = 0;

    match uefi::boot::memory_map(MemoryType::LOADER_DATA) {
        Ok(mut mmap) => {
            for desc in mmap.entries() {
                let phys = desc.phys_start;
                let pages = desc.page_count;
                let end = phys + (pages * 4096);
                if end > max_addr {
                    max_addr = end;
                }
            }
        },
        Err(_) => panic!("Unable to query memory")
    }

    return max_addr;
}

/// Dump memory map (from rustyboot, but modified to new API)
fn create_memory_map(memory_map: &mut SatusMemoryMap) -> Result<(),&'static str> {
    let mut start_of_memory_region: u64 = 0;
    let mut last_memory_type: MemoryRegionType = MemoryRegionType::NonExistent;
    let mut num_pages = 0;
    let mut last_end = 0;

    match uefi::boot::memory_map(MemoryType::LOADER_DATA) {
        Ok(mut mmap) => {
            if !mmap.is_sorted() {
                mmap.sort();
            }
            for desc in mmap.entries() {
                let ty = desc.ty;
                let phys = desc.phys_start;
                let virt = desc.virt_start; // this is always 0? why?
                let pages = desc.page_count;
                let end = phys + (pages * 4096);

                let memory_type = get_memory_type(desc.ty);
                
                // Explicitly mark any non-contiguous chunks.  A gap between 0xa0000 (640k) and 0x100000 (1M) is expected.
                // This gap dates back to the original PC architecture, and was a region of memory reserved for hardware 
                // memory.
                if phys != last_end {
                    memory_map.add_region(last_memory_type, start_of_memory_region, last_end);
                    info!("  region {:x} - {:x} type {}", start_of_memory_region, last_end, last_memory_type as u8);
                    info!("--------------------------------------------------- {} page gap", (phys - last_end)/4096);
                    memory_map.add_region(MemoryRegionType::NonExistent, last_end, phys);
                    info!("  region gap {:x} - {:x} type non-existent", last_end, phys);
                    
                    start_of_memory_region = phys;
                    last_memory_type = memory_type;
                }

                if memory_type != last_memory_type {
                    if phys != start_of_memory_region {
                        memory_map.add_region(last_memory_type, start_of_memory_region, last_end);
                        info!("  region {:x} - {:x} type {}", start_of_memory_region, last_end, last_memory_type as u8);
                    }
                    last_memory_type = memory_type;
                    start_of_memory_region = phys;
                }

                info!(
                    "Type={:?}, phys=0x{:x} - 0x{:x}, virt=0x{:x}, pages={}",
                    ty, phys, phys + (pages*4096), virt, pages
                );
                if ty != MemoryType::RESERVED {
                    num_pages += pages;
                }
                last_end = end;
            }
            info!("{} total pages {} bytes of memory", num_pages, num_pages*4096);
            Ok(())
        }
        Err(e) => Err("Failed to get memory map"),
    }
}

fn get_total_pages() -> u64 {
    let mmap_storage = uefi::boot::memory_map(MemoryType::LOADER_DATA)
        .expect("Failed to get memory map");

    let mut total_pages = 0;
    let mut total_conventional = 0;
    for desc in mmap_storage.entries() {
        if desc.ty == MemoryType::CONVENTIONAL {
            total_conventional += desc.page_count;
        }
        total_pages += desc.page_count;
    }

    info!("Total pages: {}, Total conventional pages: {}", total_pages, total_conventional);


    total_pages
}

/// Search the UEFI system table for the RSDP address in the ACPI config.
/// The Root System Description Pointer (RSDP) address is provided to the kernel, and 
/// can be used to navigate to the MADT table in order to extract information on 
/// the available cores.
pub fn find_rsdp_address() -> Option<usize> {
    // the uefi-rs crate doesn't parse the system table, but we can get the raw pointer for it...
    let raw_sys_table_ptr = unsafe { uefi::table::system_table_raw().unwrap().as_ptr() };
    // TODO: what to do if I can't get the pointer?
    
    // and cast it to the structs provided by the uefi_raw crate
    let raw_table = unsafe { &*(raw_sys_table_ptr as *const uefi_raw::table::system::SystemTable) };
    
    // and create a slice of configuration table entries
    let config_tables = unsafe {
        core::slice::from_raw_parts(
            raw_table.configuration_table,
            raw_table.number_of_configuration_table_entries,
        )
    };

    // Pick out the ACPI/ACPI2 config table (cast from uefi_raw's guid format to uefi's type)
    let entry = config_tables.iter().find(|entry| {
        let guid = uefi::Guid::from_bytes(entry.vendor_guid.to_bytes());
        guid == ConfigTableEntry::ACPI2_GUID || guid == ConfigTableEntry::ACPI_GUID
    });

    entry.map(|e| e.vendor_table as usize)
}

pub fn set_framebuffer(config: &mut Config, gop: &mut ScopedProtocol<GraphicsOutput>) {
    let mode_info = gop.current_mode_info();
    let (width, height) = mode_info.resolution();
    let (red_mask, green_mask, blue_mask) = match mode_info.pixel_format() {
        PixelFormat::Rgb => (0x00FF0000, 0x0000FF00, 0x000000FF),
        PixelFormat::Bgr => (0x000000FF, 0x0000FF00, 0x00FF0000),
        PixelFormat::Bitmask => {
            let pixel_mask = mode_info.pixel_bitmask().expect("Pixel format is bitmask but no bitmask provided");
            (
                pixel_mask.red,
                pixel_mask.green,
                pixel_mask.blue
            )
        },
        PixelFormat::BltOnly => {
            panic!("Unsupported pixel format: BltOnly");
        }
    };
    config.set_framebuffer(
        gop.frame_buffer().as_mut_ptr() as Address,
        gop.frame_buffer().size() as u32);
    config.set_framebuffer_dimensions(
        width as u16, 
        height as u16,
        mode_info.stride() as u32);
    config.set_framebuffer_color_masks(
        red_mask, 
        green_mask, 
        blue_mask);
}

fn dump_memory(base_address: usize, mem_size: usize) {
    info!("Dumping memory at address 0x{:x}, size 0x{:x}", base_address, mem_size);

    unsafe {
        let ptr = base_address as *const u8;
        for row in 0..(mem_size/16) {
            let i = row * 16;
            let byte0: u8 = *ptr.add(i);
            let byte1: u8 = *ptr.add(i+1);
            let byte2: u8 = *ptr.add(i+2);
            let byte3: u8 = *ptr.add(i+3);
            let byte4: u8 = *ptr.add(i+4);
            let byte5: u8 = *ptr.add(i+5);
            let byte6: u8 = *ptr.add(i+6);
            let byte7: u8 = *ptr.add(i+7);
            let byte8: u8 = *ptr.add(i+8);
            let byte9: u8 = *ptr.add(i+9);
            let byte10: u8 = *ptr.add(i+10);
            let byte11: u8 = *ptr.add(i+11);
            let byte12: u8 = *ptr.add(i+12);
            let byte13: u8 = *ptr.add(i+13);
            let byte14: u8 = *ptr.add(i+14);
            let byte15: u8 = *ptr.add(i+15);

            info!("{:x}  : {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x}    {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x}", 
            base_address + i,
            byte0, byte1, byte2,  byte3,  byte4,  byte5,  byte6,  byte7, 
            byte8, byte9, byte10, byte11, byte12, byte13, byte14, byte15);  
        }
     }
}

pub fn get_pl4_table() -> &'static mut PageTable {
    unsafe {
        let (pl4_frame, _flags) = Cr3::read();
        &mut *(pl4_frame.start_address().as_u64() as *mut PageTable)
    }
}

fn create_physical_mirror() {
    let last_addr = get_max_physical_address();

    let pl3_table_addr = get_pages(1).unwrap();
    unsafe { core::ptr::write_bytes(pl3_table_addr as *mut u8, 0, 4096); }
    
    let pl4_table = get_pl4_table();
    let pl3_table = unsafe { &mut *(pl3_table_addr as *mut PageTable) };

    // iterate 1gb addresses until the end is >= the last page of memory
    for physical_address_gb in (0u64..511) {
        let physical_address = physical_address_gb * PAGE_SIZE_1GB as Address;

        if physical_address > last_addr {
            break;
        }

        pl3_table[physical_address_gb as usize].set_addr(
            PhysAddr::new(physical_address),
            PageTableFlags::GLOBAL | PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::HUGE_PAGE | PageTableFlags::NO_EXECUTE );
    }

    pl4_table[510].set_addr(
        PhysAddr::new(pl3_table_addr),
        PageTableFlags::GLOBAL | PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE );

}

fn adjust_config_for_physical_mirror(config: &mut Config) {
    // Adjust the pointers in the config struct to account for the physical mirror
    config.set_cpu_config_address(config.get_cpu_config_address() + PHYSICAL_OFFSET);
    config.set_module_list_address(config.get_module_list_address() + PHYSICAL_OFFSET);
    config.set_memory_map_address(config.get_memory_map_address() + PHYSICAL_OFFSET);
    config.set_framebuffer(config.get_framebuffer_address() + PHYSICAL_OFFSET,
        config.get_framebuffer_size());

    // don't forget to adjust the config itself...
    config.set_page_ptr(config.get_page_ptr() + PHYSICAL_OFFSET);

    // TODO: will need to ajdust the addresses in the module list as well?
    // Or just document that the contract says that they're physical addresses

}

fn create_kernel_stack(pager: &mut Pager, virtual_base: VirtualAddress, size: usize) {
    // allocate enough pages for atleast size bytes
    let num_pages = (size + PAGE_SIZE - 1) / PAGE_SIZE;
    let stack_size = num_pages * PAGE_SIZE;
    let stack = get_pages(num_pages).unwrap();
    info!("Allocated {} pages for {} byte stack at 0x{:016x}", num_pages, size, stack);

    // clear the stack with a sentinel pattern (0xa5)
    unsafe { core::ptr::write_bytes(stack as *mut u8, 0xab, num_pages*PAGE_SIZE); }

    // map it to virtual_base - allocated_size -> virtual_base
    pager.map_to_virtual_many(VirtualAddress(virtual_base.0 - stack_size as Address), PhysicalAddress(stack), num_pages, 
        PageTableFlags::WRITABLE | PageTableFlags::GLOBAL | PageTableFlags::NO_EXECUTE).unwrap();
}

// We copy the GDT into a buffer allocated by us so that it's categorized as LOADER_DATA rather than 
// BOOT_SERVICES_DATA or RUNTIME_SERVICES_DATA (by the UEFI firmware) as the kernel will treat the 
// latter two as available memory, so we must ensure we aren't using any of it by the time the 
// boot loader exits...
fn recreate_gdt() {
    let mut gdt_ptr = tables::sgdt();
    
    let gdt_base = gdt_ptr.base;
    let gdt_limit = gdt_ptr.limit;
    info!("GDT Base Address: {:?}", gdt_base);
    info!("GDT Limit: {:#x}", gdt_limit);

    let mut new_gdt = get_pages(1).unwrap();
    new_gdt += PHYSICAL_OFFSET;
    info!("New GDT addr: 0x{:016x}", new_gdt);

    unsafe {
        core::ptr::copy_nonoverlapping(gdt_base.as_ptr(), new_gdt as *mut u64, (gdt_limit+1) as usize);

        dump_memory(gdt_base.as_u64() as usize, 48);
        dump_memory(new_gdt as usize, 48);

        gdt_ptr.base = VirtAddr::new(new_gdt);
        tables::lgdt(&gdt_ptr);
    }
}

fn recreate_idt() {
    let mut idt_ptr = tables::sidt();
    
    let idt_base = idt_ptr.base;
    let idt_limit = idt_ptr.limit;
    info!("IDT Base Address: {:?}", idt_base);
    info!("IDT Limit: {:#x}", idt_limit);

    let mut new_idt = get_pages(1).unwrap();
    new_idt += PHYSICAL_OFFSET;
    info!("New IDT addr: 0x{:016x}", new_idt);

    unsafe {
        core::ptr::copy_nonoverlapping(idt_base.as_ptr(), new_idt as *mut u8, (idt_limit+1) as usize);

        //core::ptr::write_bytes(new_idt as *mut u8, 0, 4096/8);
        // attempt to add physical offset here...
        // const PHYSICAL_OFFSET: Address = 0xFFFFFF0000000000;
        // doesn't seem to work....
        let ints_by_u64 = new_idt as *mut u64;
        for interrupt in (0..(4096/16)) {
            //                                   ........
            *ints_by_u64.add(interrupt*2+1) |= 0x00000000ffffff00;
        }

        dump_memory(idt_base.as_u64() as usize, 4096);
        dump_memory(new_idt as usize, 4096);

        idt_ptr.base = VirtAddr::new(new_idt);
        tables::lidt(&idt_ptr);

        // test
            // Clear RAX, set RDX to 0, clear divisor (e.g., EBX)
            // and perform div on 32-bit (div ebx)
        asm!(
            "xor eax, eax",
            "xor edx, edx",
            "mov ebx, 0",
            "div ebx",
            out("eax") _,
            out("edx") _,
            //inout("ebx") 0 => _,
            options(nostack)
        );
    }
}

pub fn get_current_apic_id() -> u32 {
    let cpuid = CpuId::new();
    
    // Fetch feature info (CPUID leaf 1)
    cpuid.get_feature_info()
         .map(|info| info.initial_local_apic_id() as u32)
         .expect("Failed to read CPUID feature info")
}

fn breakpoint() {
    info!("Artificial breakpoint")
}

#[entry]
fn main() -> Status {
    uefi::helpers::init().unwrap();

    let address_of_main = main as *const ();
    info!("Address of main: 0x{:x}", address_of_main as usize);
    info!("Address of read_keyboard_events 0x{:x}", read_keyboard_events as usize);

    let handle = 
        boot::get_handle_for_protocol::<Input>().expect("Can get input");
    let mut input_protocol = 
        boot::open_protocol_exclusive::<Input>(handle).unwrap();

    print_image_path().unwrap();

    let fs: ScopedProtocol<SimpleFileSystem> = boot::get_image_file_system(boot::image_handle()).unwrap();
    let mut fs = FileSystem::new(fs);

    let kernel_path = cstr16!("\\efi\\boot\\kernel.elf");
    let kernel_buf = fs.read(kernel_path).unwrap(); // TODO: handle error
    let elf_binary = elf::Elf64File::new(kernel_buf.as_slice()).unwrap();

    info!("Kernel file contents read to 0x{:x} size: {} bytes, mem size: {} bytes", 
        kernel_buf.as_ptr() as usize, kernel_buf.len(), elf_binary.get_mem_size());

    let mut pager = Pager::new(|| { get_pages(1).map(PhysicalAddress::from_addr).map_err(|_| "pager: failed to allocate page") });

    let kernel_size_bytes = elf_binary.get_mem_size();
    let kernel_size_pages = bytes_to_pages(kernel_size_bytes);
    let kernel_virt_base = elf_binary.get_virtual_address();
    info!("Kernel is {} bytes ({} pages) at virtual address 0x{:x}", 
        kernel_size_bytes, kernel_size_pages, kernel_virt_base.as_u64());

    // technically, because memory is identity mapped, this is also mapped 
    // into the virtual space at the same address...
    let kernel_phys_address = allocate_buffer(kernel_size_bytes).unwrap();
    pager.map_to_virtual_many(kernel_virt_base, PhysicalAddress::from_addr(kernel_phys_address), kernel_size_pages, 
        PageTableFlags::GLOBAL | PageTableFlags::WRITABLE).expect("Failed to map kernel memory");

    info!("Relocating kernel to address 0x{:x} - 0x{:x}", 
        kernel_virt_base.as_u64(),
        kernel_virt_base.as_u64() as usize + elf_binary.get_mem_size());
    elf_binary.relocate().unwrap();

    // first module in the module list is the kernel itself
    let kernel_name = cstr16!("kernel");
    let mut module_list = ModuleList::new_from_page( get_pages(1).unwrap()).unwrap();
    module_list.append(kernel_name.as_bytes(), kernel_phys_address, kernel_size_bytes, 0).unwrap();

    info!("Loading modules...");
    load_modules(fs, &mut module_list);
    info!("Read {} modules", module_list.get_num_modules());

    info!("To debug with gdb:");
    info!("target remote localhost:1234");
    info!("add-symbol-file esp/efi/boot/kernel.elf 0x{:x}\n", kernel_virt_base.as_u64());

    // Trace out some SMP config...
    let mp_handle = 
        boot::get_handle_for_protocol::<MpServices>().expect("Can get multi-processor input handle");
    let mut mp_protocol = 
        boot::open_protocol_exclusive::<MpServices>(mp_handle).unwrap();

    let processor_count = mp_protocol.get_number_of_processors()
        .expect("Failed to get processor count");

    info!("Total logical processors in system: {}", processor_count.total);
    info!("Enabled logical processors: {}", processor_count.enabled);

    let mut cpu_config = CpuConfig::new_from_page( get_pages(1).unwrap() ).unwrap();
    info!("got cpu config");
    if cpu_config.ap_ready.load(Ordering::Acquire) {
        info!("aps are ready");
    } else {
        info!("aps are not ready");
    }
    cpu_config.set_num_cpus(processor_count.total as u32);

    let rsdp_pointer = find_rsdp_address().unwrap();
    info!("Found rsdp pointer {:x}", rsdp_pointer);
    cpu_config.rsdp_address = rsdp_pointer as Address;

    cpu_config.trampoline_address = get_real_mode_pages(1).unwrap();

    // allocate memory for per-cpu stacks and other information...
    // num_cpus * size_of::<PerCpuConfig>()
    let pages_required = (cpu_config.get_num_cpus() as usize * size_of::<PerCpuConfig>()) / 4096;
    let per_cpu_alloc = get_pages(pages_required).unwrap();

    // TODO: initialize it
    // TODO: figure out stacks?  Currently cpu-0 stack is allocated differently?
    let per_cpu_slice: &mut[PerCpuConfig] = unsafe {
        core::slice::from_raw_parts_mut( 
            per_cpu_alloc as *mut PerCpuConfig, 
            cpu_config.get_num_cpus() as usize )
    };
    for cpu in per_cpu_slice {
        cpu.stack_guard = 0x5150515051505150;
    }

    // TODO: move this into adjust_config_for_physical_mirror?
    cpu_config.per_cpu_config = per_cpu_alloc + PHYSICAL_OFFSET;

    info!("Press esc key to load kernel...");
    read_keyboard_events(input_protocol.get_mut().expect("Able to get input protocol"));

    // there's 1 active CPU already (we're running on it)
    cpu_config.active_cpus = AtomicU32::new(1);

    // the callback defined above will get called after the 1ms timeout, but it's largely 
    // meaningless... in order to ensure all the threads are actually started, we need to 
    // examine the active_cpus counter which is actually updated in each of the ap's 
    // execution paths...

    use uefi::proto::console::gop::{GraphicsOutput, PixelFormat};
    let gop_handle = 
        boot::get_handle_for_protocol::<GraphicsOutput>().expect("Can get GOP handle");
    let mut gop = 
        boot::open_protocol_exclusive::<GraphicsOutput>(gop_handle).unwrap();

    // TODO: modify satus-struct to use Address/u64 instead of usize for pointers
    let mut config = Config::new_from_page( get_pages(1).unwrap() ).unwrap();
    config.set_module_list(&module_list);
    config.set_cpu_config(&cpu_config);
    set_framebuffer(&mut config, &mut gop);

    create_physical_mirror();
    create_kernel_stack(&mut pager, VirtualAddress(kernel_virt_base.as_u64()), 2*1024*1024);

    recreate_gdt();

    // Make sure we do this after all allocations have been done...
    let mut memory_map = SatusMemoryMap::new_from_page( get_pages(1).unwrap() ).unwrap();
    create_memory_map(&mut memory_map);
    config.set_memory_map(&memory_map);

    adjust_config_for_physical_mirror(&mut config);

    let entry_point = elf_binary.get_header().unwrap().get_entry_point();
    info!("Kernel entry point: 0x{:x}", entry_point);
    unsafe {
        // dump the first 8 bytes of the kernel entry point for debugging
        let entry_ptr = entry_point as *const u8;
        info!("First 8 bytes of kernel entry point:");
        for i in 0..8 {
            let byte = *entry_ptr.add(i);
            info!("  {:x}:  {:02x}", entry_ptr.add(i) as usize, byte);
        }
        let mmap = uefi::boot::exit_boot_services(None);

        // Pass what info we've learned via a pointer to the config page in rax, and jump to the kernel.
        // Prevoiusly, I tried assigning the kernel entry to an extern "sysv64" fn() -> ! type, and  
        // calling the resultant function pointer, but I'd end up getting an illegal instruction pointer 
        // well beyond where the kernel was, which didn't make any sense at the time because the kernel 
        // was just a busy loop.  I never did disassemble the code, but suspected the function call was 
        // being interpretted as a relative memory address, than that absolute.  Given that I'm already 
        // using inline assembly for the config pass, I just opted for a simple jump to pass control 
        // to the kernel...
        asm!(
            "mov rsp, {stack_base}",  
            "mov rax, {config}",
            "jmp {kernel}",
            stack_base = in(reg) kernel_virt_base.as_u64(), // stack expands down from where the kernel resides
            config = in(reg) config.get_page_ptr(),
            kernel = in(reg) entry_point as usize,
        );
    }

    Status::SUCCESS
}

