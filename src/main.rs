#![no_main]
#![no_std]

use core::time::Duration;
use log::{error, info};
use uefi::boot::{self, SearchType};
use uefi::prelude::*;
use uefi::proto::device_path::text::{
    AllowShortcuts, DevicePathToText, DisplayOnly,
};
use uefi::proto::loaded_image::LoadedImage;
//use uefi::{Identify, Result, Error};
use uefi::Identify; // provides DevicePathToText::GUID
use uefi::proto::media::fs::SimpleFileSystem;
use uefi::fs::FileSystem;
use uefi::boot::ScopedProtocol;
use uefi::{CStr16, cstr16};
use uefi::mem::memory_map::MemoryMap;
use uefi::boot::MemoryType;
use uefi::proto::console::text::{Input, Key, ScanCode};
//use uefi::{Char16, ResultExt};
use uefi::Char16;
use uefi::proto::console::gop::{BltOp, BltPixel};

mod elf;

fn read_keyboard_events(input: &mut Input) -> Result<(),()> {
    loop {
        // Pause until a keyboard event occurs.
        let mut events = [input.wait_for_key_event().unwrap()];
        boot::wait_for_event(&mut events).discard_errdata().map_err(|_| ())?;

        let u_key = Char16::try_from('u').unwrap();
        match input.read_key().discard_errdata().map_err(|_| ())? {
            // Example of handling a printable key: print a message when
            // the 'u' key is pressed.
            Some(Key::Printable(key)) if key == u_key => {
                info!("the 'u' key was pressed");
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
fn determine_kernel_base_address() -> Result<u64,&'static str> {
    // TODO: actually determine a good base address based on the memory map
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
            Ok(0x400000) // Load at 4mb
        }
        Err(_) => Err("Failed to get memory map"),
    }
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

    let path = cstr16!("\\");
    for file in fs.read_dir(path).unwrap() {
        info!("Found {}", file.unwrap().file_name())        
    }

    let kernel_path = cstr16!("\\efi\\boot\\kernel.elf");
    let kernel_buf = fs.read(kernel_path).unwrap(); // TODO: handle error
    info!("Kernel size: {} bytes", kernel_buf.len());

    let elf_binary = elf::Elf64File::new(kernel_buf.as_slice()).unwrap();

    let kernel_base_address = determine_kernel_base_address().unwrap();
    let program_headers = elf_binary.get_program_headers().unwrap();
    info!("Found {} program headers", program_headers.len());
    for (i, ph) in program_headers.iter().enumerate() {
        // Must copy these out as they're potentially unaligned and rust won't create references to 
        // unaligned data (even though Intel supports it)
        let ph_type= ph.ph_type;
        let ph_offset = ph.offset;
        let ph_vaddr = ph.virt_address;
        let ph_paddr = ph.phys_address;
        let ph_filesz = ph.file_size;
        let ph_memsz = ph.mem_size;
        let ph_flags = ph.flags;
        let ph_align = ph.align;
        info!(
            "Program Header {}: type=0x{:x}, offset=0x{:x}, vaddr=0x{:x}, paddr=0x{:x}, filesz=0x{:x}, memsz=0x{:x}, flags=0x{:x}, align=0x{:x}",
            i,
            ph_type,
            ph_offset,
            ph_vaddr,
            ph_paddr,
            ph_filesz,
            ph_memsz,
            ph_flags,
            ph_align
        );

        match ph_type {
            elf::PT_LOAD => {
                info!("  -> This is a loadable segment copying to {} + 0x{:x}", kernel_base_address, ph_vaddr);
                elf_binary.load_segment_to_address(
                    ph,
                    kernel_base_address
                ).unwrap();
                //info!("  -> Segment loaded to address 0x{:x}", kernel_base_address + ph_vaddr);
            }
            _ => {
                info!("  -> This segment type is not handled");
            }
        }
    }

    //boot::stall(Duration::from_secs(5));
    //gfx_test();

    read_keyboard_events(input_protocol.get_mut().expect("Able to get input protocol"));

    // read file into buffer
    // transmute buffer into Elf64Header
    // verify header fields
    // load program segments into memory (ideally mapped to 0xFFFFFFFF80000000)
    // exit boot services?
    // set up virtual memory mapping?
    // jump to entry point

    Status::SUCCESS
}

