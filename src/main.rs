#![no_std]
#![cfg_attr(not(test), no_main)]

mod elf;
mod module_list;

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
use uefi::proto::console::gop::{BltOp, BltPixel};
use uefi::boot::AllocateType;
use core::panic::PanicInfo;
use core::arch::asm;

use module_list::ModuleList;

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
                break;
            }
            _ => {}
        }
    }

    Ok(())
}

/// Dump memory map (from rustyboot, but modified to new API)
fn allocate_buffer(size_required: usize) -> Result<usize,&'static str> {
    let kernel_pages = (size_required + (PAGE_SIZE-1)) / PAGE_SIZE;
    let non_null = uefi::boot::allocate_pages(
        AllocateType::AnyPages,
        MemoryType::LOADER_DATA,
        kernel_pages,
    )
    .map_err(|_| "Failed to allocate pages")?;

    let raw_ptr: *mut u8 = non_null.as_ptr();
    let result = raw_ptr as usize;

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
    
    // Define color (Black)
    let black = BltPixel::new(0, 0, 0);

    // Perform a video fill operation
    gop.blt(BltOp::VideoFill {
        color: black,
        dest: (0, 0),
        dims: (width, height),
    }).expect("Failed to clear screen");

    // TODO: display a loading animation
}

fn load_modules(mut fs: uefi::fs::FileSystem, module_list: &mut module_list::ModuleList) {
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
                elf_module.load_to_address(module_base_address).unwrap();
                // TODO: we need the entry point...
                module_list.append(file_info.file_name(), module_base_address, elf_module.get_mem_size(), 0).unwrap();
            }
        }
    }
}


#[entry]
fn main() -> Status {
    uefi::helpers::init().unwrap();

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

    info!("Kernel read size: {} bytes, mem size: {} bytes", kernel_buf.len(), elf_binary.get_mem_size());

    let kernel_base_address = allocate_buffer(elf_binary.get_mem_size()).unwrap();
    elf_binary.load_to_address(kernel_base_address).unwrap();

    info!("Loading modules...");
    let mut module_list = ModuleList::new().unwrap();
    load_modules(fs, &mut module_list);
    info!("Read {} modules", module_list.get_num_modules());

    info!("Press esc key to load kernel...");
    read_keyboard_events(input_protocol.get_mut().expect("Able to get input protocol"));

    let entry_point = elf_binary.get_header().unwrap().get_entry_point() + kernel_base_address;
    unsafe {
        let kernel: extern "sysv64" fn() -> ! = core::mem::transmute(entry_point as *const ());
        let mmap = uefi::boot::exit_boot_services(None);
        asm!(
            "mov rax, {val}",
            val = in(reg) module_list.get_page_ptr(),
        );

        kernel();
    }

    Status::SUCCESS
}

