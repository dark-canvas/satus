use uefi::boot::MemoryType;
use uefi::boot::AllocateType;
use uefi::boot::ScopedProtocol;
use uefi::proto::console::gop::{GraphicsOutput, PixelFormat};

// TODO: need a nice way to share these with the x86_64 based kernel, without pulling in all the 
// UEFI stuff (shared crate containing only data structs?)
pub struct Config {
    // hide the un-safe-ness
    raw_data: *mut ConfigPage,
}

#[repr(C)]
pub struct ConfigPage {
    pub framebuffer_addr: usize,
    pub framebuffer_size: u32,
    pub framebuffer_width: u16,
    pub framebuffer_height: u16,
    pub framebuffer_red_mask: u32,
    pub framebuffer_green_mask: u32,
    pub framebuffer_blue_mask: u32,
    pub framebuffer_bytes_per_line: u32,
    // I don't understand why UEFI doesn't have a bytes_per_pixel!?

    pub module_list_addr: usize,
}

impl Config {
    pub fn new() -> Result<Config, &'static str> {
        let non_null = uefi::boot::allocate_pages(
            AllocateType::AnyPages,
            MemoryType::LOADER_DATA,
            1, // we only need 1 page for the config
        )
        .map_err(|_| "Failed to allocate pages")?;

        let config = Config { raw_data: non_null.as_ptr() as *mut ConfigPage};
        unsafe {
            // clear the entire page to zero to start with
            core::ptr::write_bytes(config.raw_data as *mut u8, 0, 4096);
        }
        Ok(config)
    }

    pub fn get_page_ptr(&self) -> usize {
        self.raw_data as usize
    }

    pub fn set_framebuffer(&mut self, gop: &mut ScopedProtocol<GraphicsOutput>) {
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
        unsafe {
            (*self.raw_data).framebuffer_width = width as u16;
            (*self.raw_data).framebuffer_height = height as u16;
            (*self.raw_data).framebuffer_addr = gop.frame_buffer().as_mut_ptr() as usize;
            (*self.raw_data).framebuffer_size = gop.frame_buffer().size() as u32;
            (*self.raw_data).framebuffer_red_mask = red_mask;
            (*self.raw_data).framebuffer_green_mask = green_mask;
            (*self.raw_data).framebuffer_blue_mask = blue_mask;
            (*self.raw_data).framebuffer_bytes_per_line = mode_info.stride() as u32;
        }
    }

    pub fn set_module_list(&mut self, module_list_addr: usize) {
        unsafe {
            (*self.raw_data).module_list_addr = module_list_addr;
        }
    }
}