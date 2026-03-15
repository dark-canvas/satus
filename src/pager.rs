//! A basic paging implementation for x86_64
//!
//! This contains a limited pager with enough functionality to read in the page tables setup 
//! by the UEFI firmware, and also modify it (in order to load the kernel to upper memory).
//!
//! NOTE: it is assumed that any pages setup by the UEFI firmware are identity mapped.
//! NOTE: some UEFI firmwares map the PML4 table into a read-only page.

use x86_64::registers::control::Cr3;
use x86_64::structures::paging::PhysFrame;
use x86_64::structures::paging::PageTable;
use x86_64::structures::paging::page_table::PageTableEntry;
use x86_64::structures::paging::Size4KiB;
use x86_64::PhysAddr;

use log::info;

use crate::types::addr;

// Note sure if we need these...?
// Possibly they should also be capitalized
struct physical_addr(addr);
struct linear_addr(addr);

type GetPhysicalPage = fn() -> Result<usize, &'static str>;

pub struct Pager {
    pml4_table: &'static mut PageTable,
    get_page: GetPhysicalPage,
}

pub fn bytes_to_pages(bytes: usize) -> usize {
    (bytes + 0xFFF) / 0x1000 // Round up to nearest page
}

fn get_zeroed_page(get_page: GetPhysicalPage) -> Result<usize, &'static str> {
    let page_addr = (get_page)()?;
    unsafe {
        core::ptr::write_bytes(page_addr as *mut u8, 0, 0x1000);
    }
    Ok(page_addr)
}

impl physical_addr {
    fn from_addr(addr: usize) -> physical_addr {
        physical_addr(addr)
    }
    fn to_linear(&self) -> linear_addr {
        // For simplicity, we assume an identity mapping for all physical addresses.
        linear_addr(self.0)
    }
}

impl linear_addr {
    fn from_addr(addr: usize) -> linear_addr {
        linear_addr(addr)
    }
    fn to_physical(&self) -> physical_addr {
        // For simplicity, we assume an identity mapping for all physical addresses.
        physical_addr(self.0)
    }
}

impl Pager {
    pub fn new(get_page: GetPhysicalPage) -> Pager {
        let (pml4_frame, _flags) = Cr3::read();
        let pml4_addr: PhysAddr = pml4_frame.start_address();

        info!("PML4 Physical Address: {:?}", pml4_addr);

        let mut result = unsafe {
            let pml4_table = &mut *(pml4_frame.start_address().as_u64() as *mut PageTable);
            Pager { pml4_table, get_page }
        };
        match result.get_flags(pml4_frame.start_address().as_u64()) {
            Some(flags) => {
                if flags.contains(x86_64::structures::paging::PageTableFlags::WRITABLE) == false {
                    info!("PML4 is not writable, making a copy of it");
                    let new_frame = PhysFrame::<Size4KiB>::containing_address(
                        PhysAddr::new( get_zeroed_page(result.get_page).unwrap() as u64));
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            pml4_frame.start_address().as_u64() as *const u8,
                            new_frame.start_address().as_u64() as *mut u8,
                            0x1000,
                        );
                        result.pml4_table = &mut *(new_frame.start_address().as_u64() as *mut PageTable);
                        Cr3::write(new_frame, _flags);
                    }
                    // If the PML4 is not writable, we need to made a copy of it and re-set CR3 as 
                    // we'll need to modify it in order to map the kernel
                }
            }
            None => panic!("PML4 is not identity mapped"),
        }
        result
    }

    // TODO: this is gross... fix it
    pub fn count_pages(&self) -> u64 {
        let mut count = 0;

        unsafe {
            for entry in self.pml4_table.iter() {
                if !entry.is_unused() {
                    info!("Found non-empty PML4 entry with flags {:?} at address 0x{:x}", entry.flags(), entry.addr().as_u64());
                    //count += 512; // Each non-empty PML4 entry points to a page table with 512 entries
                    let pdpt_table = &mut *(entry.addr().as_u64() as *mut PageTable);
                    for pdpt_entry in pdpt_table.iter() {
                        if !pdpt_entry.is_unused() {
                            info!("Found non-empty PDPT entry with flags {:?} at address 0x{:x}", pdpt_entry.flags(), pdpt_entry.addr().as_u64());
                            if pdpt_entry.flags().contains(x86_64::structures::paging::PageTableFlags::HUGE_PAGE) {
                                count += 512 * 512; // Each non-empty PDPT entry that is a huge page maps 512*512 pages
                                continue;
                            }
                            //count += 512; // Each non-empty PDPT entry points to a page table with 512 entries
                            let pd_table = &mut *(pdpt_entry.addr().as_u64() as *mut PageTable);
                            for pd_entry in pd_table.iter() {
                                info!("Found non-empty PD entry with flags {:?} at address 0x{:x}", pd_entry.flags(), pd_entry.addr().as_u64());
                                if !pd_entry.is_unused() {
                                    if pd_entry.flags().contains(x86_64::structures::paging::PageTableFlags::HUGE_PAGE) {
                                        count += 512; // Each non-empty PD entry that is a huge page maps 512 pages
                                        continue;
                                    }
                                    //count += 512; // Each non-empty PD entry points to a page table with 512 entries
                                    let pt_table = &mut *(pd_entry.addr().as_u64() as *mut PageTable);
                                    for pt_entry in pt_table.iter() {
                                        info!("Found non-empty PT entry with flags {:?} at address 0x{:x}", pt_entry.flags(), pt_entry.addr().as_u64());
                                        if !pt_entry.is_unused() {
                                            count += 1; // Each non-empty PT entry maps a page
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        count
    }

    pub fn map_to_virtual_many(&mut self, virtual_addr: usize, phys_addrs: usize, num_pages: usize, flags: x86_64::structures::paging::PageTableFlags) -> Result<(), &'static str> {
        info!("Mapping {} pages 0x{:x} physical -> 0x{:x} virtualwith flags {:?}", 
            num_pages, phys_addrs, virtual_addr, flags);
        for i in 0..num_pages {
            let va = virtual_addr + i * 0x1000;
            let pa = phys_addrs + i * 0x1000;
            self.map_to_virtual(va, pa, flags)?;
        }

        Ok(())
    }

    pub fn map_to_virtual(&mut self, virtual_addr: usize, phys_addrs: usize, flags: x86_64::structures::paging::PageTableFlags) -> Result<(), &'static str> {
        let pml4_index = (virtual_addr >> 39) & 0o777;
        let pdpt_index = (virtual_addr >> 30) & 0o777;
        let pd_index = (virtual_addr >> 21) & 0o777;
        let pt_index = (virtual_addr >> 12) & 0o777;

        unsafe {
            let pml4_entry = &mut self.pml4_table[pml4_index];
            if pml4_entry.is_unused() {
                let new_frame = PhysFrame::<Size4KiB>::containing_address(
                    PhysAddr::new( get_zeroed_page(self.get_page)? as u64));
                info!("Setting PML4 entry {} to new frame at {:?}", pml4_index, new_frame.start_address());
                pml4_entry.set_addr(new_frame.start_address(), flags | x86_64::structures::paging::PageTableFlags::PRESENT);
                info!("Set PML4 entry {} to new frame at {:?}", pml4_index, new_frame.start_address());
            }

            let pdpt_table = &mut *(pml4_entry.addr().as_u64() as *mut PageTable);
            let pdpt_entry = &mut pdpt_table[pdpt_index];
            if pdpt_entry.is_unused() {
                let new_frame = PhysFrame::<Size4KiB>::containing_address(
                    PhysAddr::new( get_zeroed_page(self.get_page)? as u64));
                pdpt_entry.set_addr(new_frame.start_address(), flags | x86_64::structures::paging::PageTableFlags::PRESENT);
            }

            let pd_table = &mut *(pdpt_entry.addr().as_u64() as *mut PageTable);
            let pd_entry = &mut pd_table[pd_index];
            if pd_entry.is_unused() {
                let new_frame = PhysFrame::<Size4KiB>::containing_address(
                    PhysAddr::new( get_zeroed_page(self.get_page)? as u64));
                pd_entry.set_addr(new_frame.start_address(), flags | x86_64::structures::paging::PageTableFlags::PRESENT);
            }

            let pt_table = &mut *(pd_entry.addr().as_u64() as *mut PageTable);
            let pt_entry = &mut pt_table[pt_index];
            if !pt_entry.is_unused() {
                return Err("Virtual address already mapped");
            }

            // For simplicity, we only support mapping a single page here. In a real implementation, you'd want to handle larger mappings.
            pt_entry.set_addr(PhysAddr::new(phys_addrs as u64), flags | x86_64::structures::paging::PageTableFlags::PRESENT);
        }

        Ok(())
    }

    // TODO: use u64 as address, as the x86_64 crate genreally does a swell
    pub fn get_flags(&self, virtual_addr: u64) -> Option<x86_64::structures::paging::PageTableFlags> {
        let pml4_index = ((virtual_addr >> 39) & 0o777) as usize;
        let pdpt_index = ((virtual_addr >> 30) & 0o777) as usize;
        let pd_index = ((virtual_addr >> 21) & 0o777) as usize;
        let pt_index = ((virtual_addr >> 12) & 0o777) as usize;

        unsafe {
            let pml4_entry = &self.pml4_table[pml4_index];
            if pml4_entry.is_unused() {
                return None;
            }

            let pdpt_table = &mut *(pml4_entry.addr().as_u64() as *mut PageTable);
            let pdpt_entry = &pdpt_table[pdpt_index];
            if pdpt_entry.is_unused() {
                return None;
            }

            let pd_table = &mut *(pdpt_entry.addr().as_u64() as *mut PageTable);
            let pd_entry = &pd_table[pd_index];
            if pd_entry.is_unused() {
                return None;
            }

            if pd_entry.flags().contains(x86_64::structures::paging::PageTableFlags::HUGE_PAGE) {
                return Some(pd_entry.flags());
            }

            let pt_table = &mut *(pd_entry.addr().as_u64() as *mut PageTable);
            let pt_entry = &pt_table[pt_index];
            if pt_entry.is_unused() {
                return None;
            }

            Some(pt_entry.flags())
        }
    }
 

    pub fn virtual_to_physical(&self, virtual_addr: usize) -> Option<usize> {
        let pml4_index = (virtual_addr >> 39) & 0o777;
        let pdpt_index = (virtual_addr >> 30) & 0o777;
        let pd_index = (virtual_addr >> 21) & 0o777;
        let pt_index = (virtual_addr >> 12) & 0o777;

        unsafe {
            let pml4_entry = &self.pml4_table[pml4_index];
            if pml4_entry.is_unused() {
                return None;
            }

            // page directory entry is 4kb page...
            // TODO: this shouldn't have to be mutable, but (confirm this...)
            // the API for PageTableEntry doesn't have a way to get the address without mutably borrowing the entry
            let pdpt_table = &mut *(pml4_entry.addr().as_u64() as *mut PageTable);
            let pdpt_entry = &pdpt_table[pdpt_index];
            if pdpt_entry.is_unused() {
                return None;
            }

            // this could be a 2mb page...
            let pd_table = &mut *(pdpt_entry.addr().as_u64() as *mut PageTable);
            let pd_entry = &pd_table[pd_index];
            if pd_entry.is_unused() {
                return None;
            }

            if pd_entry.flags().contains(x86_64::structures::paging::PageTableFlags::HUGE_PAGE) {

                info!("Virtual address 0x{:x} maps to HUGE physical address 0x{:x} with flags {:?}", 
                    virtual_addr, pd_entry.addr().as_u64(), pd_entry.flags());

                return Some(pd_entry.addr().as_u64() as usize + (virtual_addr & 0x1FFFFF));
            }

            let pt_table = &mut *(pd_entry.addr().as_u64() as *mut PageTable);
            let pt_entry = &pt_table[pt_index];
            if pt_entry.is_unused() {
                return None;
            }

            info!("Virtual address 0x{:x} maps to physical address 0x{:x} with flags {:?}", 
                virtual_addr, pt_entry.addr().as_u64(), pt_entry.flags());

            Some(pt_entry.addr().as_u64() as usize + (virtual_addr & 0xFFF))
        }
    }


    pub fn output_mmap(&self) {
        unsafe {
            for (i, entry) in self.pml4_table.iter().enumerate() {
                if !entry.is_unused() {
                    info!("PML4 Entry {}: {:?}", i, entry);

                    let page_table = &mut *(entry.addr().as_u64() as *mut PageTable);
                    for (j, entry) in page_table.iter().enumerate() {
                        if !entry.is_unused() {
                            info!("  Page Table Entry {}: {:?}", j, entry);

                            let page_table_2 = &mut *(entry.addr().as_u64() as *mut PageTable);
                            for (k, entry) in page_table_2.iter().enumerate() {
                                if !entry.is_unused() {
                                    info!("    Page Table 2 Entry {}: {:?}", k, entry); 
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}