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

extern crate satus_struct;
use satus_struct::config::Config;
use satus_struct::module_list::ModuleList;

use core::time::Duration;
use log::{error, info};
use uefi::boot::{self, SearchType};
use uefi::prelude::*;
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
use uefi::boot::MemoryType;
use uefi::proto::console::text::{Input, Key, ScanCode};
use uefi::Char16;
use uefi::proto::console::gop::{BltOp, BltPixel, PixelFormat, GraphicsOutput};
use uefi::boot::AllocateType;
use core::panic::PanicInfo;
use core::arch::asm;

use x86_64::registers::control::Cr3;

use pager::{Pager, VirtualAddress, PhysicalAddress, bytes_to_pages};

use types::Address;

#[cfg(test)]
extern crate std;

#[cfg(not(test))]
#[global_allocator]
static ALLOCATOR: uefi::allocator::Allocator = uefi::allocator::Allocator;

const PAGE_SIZE: usize = 4096;

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
    loop {}
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

fn get_pages(num: usize) -> Result<Address, &'static str> {
    info!("Requesting {} pages ({} bytes)", num, num * PAGE_SIZE);
    let non_null = uefi::boot::allocate_pages(
        AllocateType::AnyPages,
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
;
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
                module_list.append(file_info.file_name().as_bytes(), module_base_address as usize, elf_module.get_mem_size(), 0).unwrap();
            }
        }
    }
}

/// Dump memory map (from rustyboot, but modified to new API)
fn dump_memory_map() -> Result<(),&'static str> {
    match uefi::boot::memory_map(MemoryType::LOADER_DATA) {
        Ok(mmap) => {
            for desc in mmap.entries() {
                let ty = desc.ty;
                let phys = desc.phys_start;
                let virt = desc.virt_start; // this is always 0? why?
                let pages = desc.page_count;
                //let size_bytes = (pages as usize) * 4096;
                info!(
                    "Type={:?}, phys=0x{:x}, virt=0x{:x}, pages={}",
                    ty, phys, virt, pages
                );
            }
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
        gop.frame_buffer().as_mut_ptr() as usize,
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

#[entry]
fn main() -> Status {
    uefi::helpers::init().unwrap();

    let address_of_main = main as *const ();
    info!("Address of main: 0x{:x}", address_of_main as usize);

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
        x86_64::structures::paging::PageTableFlags::WRITABLE).expect("Failed to map kernel memory");

    info!("Relocating kernel to address 0x{:x} - 0x{:x}", 
        kernel_virt_base.as_u64(),
        kernel_virt_base.as_u64() as usize + elf_binary.get_mem_size());
    elf_binary.relocate().unwrap();

    // first module in the module list is the kernel itself
    let kernel_name = cstr16!("kernel");
    let mut module_list = ModuleList::new_from_page( get_pages(1).unwrap() as usize).unwrap();
    module_list.append(kernel_name.as_bytes(), kernel_virt_base.as_u64() as usize, kernel_size_bytes, 0).unwrap();

    info!("Loading modules...");
    load_modules(fs, &mut module_list);
    info!("Read {} modules", module_list.get_num_modules());

    info!("To debug with gdb:");
    info!("target remote localhost:1234");
    info!("add-symbol-table esp/efi/boot/kernel.elf 0x{:x}\n", kernel_virt_base.as_u64());

    info!("Press esc key to load kernel...");
    read_keyboard_events(input_protocol.get_mut().expect("Able to get input protocol"));

    use uefi::proto::console::gop::{GraphicsOutput, PixelFormat};
    let gop_handle = 
        boot::get_handle_for_protocol::<GraphicsOutput>().expect("Can get GOP handle");
    let mut gop = 
        boot::open_protocol_exclusive::<GraphicsOutput>(gop_handle).unwrap();

    // TODO: modify satus-struct to use Address/u64 instead of usize for pointers
    let mut config = Config::new_from_page( get_pages(1).unwrap() as usize ).unwrap();
    config.set_module_list(module_list.get_page_ptr());
    set_framebuffer(&mut config, &mut gop);

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
            "mov rax, {val}",
            "jmp {kernel}",
            val = in(reg) config.get_page_ptr(),
            kernel = in(reg) entry_point as usize,
        );
    }

    Status::SUCCESS
}

