//! A basic paging implementation for x86_64
//!
//! This contains a limited pager with enough functionality to read in the page tables setup 
//! by the UEFI firmware, and also modify it (in order to load the kernel to upper memory).
//! 
//! In i386, there's only a page directory and a page table, so the code and types are simpler 
//! when compared to x86_64 which has up to 4 levels of tables (some more modern processors 
//! can actually have 5).
//!
//! By keeping with, and exanding the i386 terms, it is common for these 4 layers to be called:
//!   - PML4 - page map level 4
//!   - PDPT - page directory page table
//!   - PD   - page directory
//!   - PT   - page table
//!
//! However, I find these names awkward... they don't really communicate their relationship 
//! well, and (as noted, regarding new processors) they don't scale well.
//!
//! As such, I've opted to use a simpler scheme which makes the hierarchy obvious:
//!   - page_table_l4 (pl4)
//!   - page_table_l3 (pl3)
//!   - page_table_l2 (pl2)
//!   - page_table_l1 (pl1)
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

use crate::types::Address;

#[derive(Copy, Clone)]
pub struct PhysicalAddress(Address);
#[derive(Copy, Clone)]
pub struct VirtualAddress(Address);

type GetPhysicalPage = fn() -> Result<PhysicalAddress, &'static str>;

pub struct Pager {
    page_table_l4: &'static mut PageTable,
    get_page: GetPhysicalPage,
}

pub fn bytes_to_pages(bytes: usize) -> usize {
    (bytes + 0xFFF) / 0x1000 // Round up to nearest page
}

fn get_zeroed_page(get_page: GetPhysicalPage) -> Result<PhysicalAddress, &'static str> {
    let page_addr = (get_page)()?;
    unsafe {
        core::ptr::write_bytes(page_addr.0 as *mut u8, 0, 0x1000);
    }
    Ok(page_addr)
}

impl PhysicalAddress {
    pub fn from_addr(addr: Address) -> PhysicalAddress {
        PhysicalAddress(addr)
    }
    pub fn to_linear(&self) -> VirtualAddress {
        // For simplicity, we assume an identity mapping for all physical addresses.
        VirtualAddress(self.0)
    }
    pub fn as_u64(&self) -> u64 {
        self.0
    }
}

impl VirtualAddress {
    pub fn from_addr(addr: Address) -> VirtualAddress {
        VirtualAddress(addr)
    }
    pub fn to_physical(&self) -> PhysicalAddress {
        // For simplicity, we assume an identity mapping for all physical addresses.
        PhysicalAddress(self.0)
    }
    pub fn as_u64(&self) -> u64 {
        self.0
    }
}

impl Pager {
    pub fn new(get_page: GetPhysicalPage) -> Pager {
        let (pl4_frame, _flags) = Cr3::read();
        let pl4_addr: PhysAddr = pl4_frame.start_address();

        info!("PML4 Physical Address: {:?}", pl4_addr);

        let mut result = unsafe {
            let page_table_l4 = &mut *(pl4_frame.start_address().as_u64() as *mut PageTable);
            Pager { page_table_l4, get_page }
        };
        match result.get_flags(VirtualAddress::from_addr(pl4_frame.start_address().as_u64())) {
            Some(flags) => {
                if flags.contains(x86_64::structures::paging::PageTableFlags::WRITABLE) == false {
                    info!("PML4 is not writable, making a copy of it");
                    let new_frame = PhysFrame::<Size4KiB>::containing_address(
                        PhysAddr::new( get_zeroed_page(result.get_page).unwrap().0 ));
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            pl4_frame.start_address().as_u64() as *const u8,
                            new_frame.start_address().as_u64() as *mut u8,
                            0x1000,
                        );
                        result.page_table_l4 = &mut *(new_frame.start_address().as_u64() as *mut PageTable);
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
            for entry in self.page_table_l4.iter() {
                if !entry.is_unused() {
                    info!("Found non-empty PML4 entry with flags {:?} at address 0x{:x}", entry.flags(), entry.addr().as_u64());
                    //count += 512; // Each non-empty PML4 entry points to a page table with 512 entries
                    let pl3_table = &mut *(entry.addr().as_u64() as *mut PageTable);
                    for pl3_entry in pl3_table.iter() {
                        if !pl3_entry.is_unused() {
                            info!("Found non-empty PDPT entry with flags {:?} at address 0x{:x}", pl3_entry.flags(), pl3_entry.addr().as_u64());
                            if pl3_entry.flags().contains(x86_64::structures::paging::PageTableFlags::HUGE_PAGE) {
                                count += 512 * 512; // Each non-empty PDPT entry that is a huge page maps 512*512 pages
                                continue;
                            }
                            //count += 512; // Each non-empty PDPT entry points to a page table with 512 entries
                            let pl2_table = &mut *(pl3_entry.addr().as_u64() as *mut PageTable);
                            for pl2_entry in pl2_table.iter() {
                                info!("Found non-empty PD entry with flags {:?} at address 0x{:x}", pl2_entry.flags(), pl2_entry.addr().as_u64());
                                if !pl2_entry.is_unused() {
                                    if pl2_entry.flags().contains(x86_64::structures::paging::PageTableFlags::HUGE_PAGE) {
                                        count += 512; // Each non-empty PD entry that is a huge page maps 512 pages
                                        continue;
                                    }
                                    //count += 512; // Each non-empty PD entry points to a page table with 512 entries
                                    let pl1_table = &mut *(pl2_entry.addr().as_u64() as *mut PageTable);
                                    for pl1_entry in pl1_table.iter() {
                                        info!("Found non-empty PT entry with flags {:?} at address 0x{:x}", pl1_entry.flags(), pl1_entry.addr().as_u64());
                                        if !pl1_entry.is_unused() {
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

    pub fn map_to_virtual_many(&mut self, virtual_addr: VirtualAddress, phys_addrs: PhysicalAddress, num_pages: usize, flags: x86_64::structures::paging::PageTableFlags) -> Result<(), &'static str> {
        let virtual_addr = virtual_addr.0;
        let phys_addrs = phys_addrs.0;
        info!("Mapping {} pages 0x{:x} physical -> 0x{:x} virtualwith flags {:?}", 
            num_pages, phys_addrs, virtual_addr, flags);
        for i in 0..num_pages as u64 {
            let va = virtual_addr + i * 0x1000;
            let pa = phys_addrs + i * 0x1000;
            self.map_to_virtual(VirtualAddress::from_addr(va), PhysicalAddress::from_addr(pa), flags)?;
        }

        Ok(())
    }

    pub fn map_to_virtual(&mut self, virtual_addr: VirtualAddress, phys_addrs: PhysicalAddress, flags: x86_64::structures::paging::PageTableFlags) -> Result<(), &'static str> {
        let virtual_addr = virtual_addr.0;
        let phys_addrs = phys_addrs.0;
        let pl4_index = ((virtual_addr >> 39) & 0o777) as usize;
        let pl3_index = ((virtual_addr >> 30) & 0o777) as usize;
        let pl2_index = ((virtual_addr >> 21) & 0o777) as usize;
        let pl1_index = ((virtual_addr >> 12) & 0o777) as usize;

        unsafe {
            let pl4_entry = &mut self.page_table_l4[pl4_index];
            if pl4_entry.is_unused() {
                let new_frame = PhysFrame::<Size4KiB>::containing_address(
                    PhysAddr::new( get_zeroed_page(self.get_page)?.0));
                info!("Setting PML4 entry {} to new frame at {:?}", pl4_index, new_frame.start_address());
                pl4_entry.set_addr(new_frame.start_address(), flags | x86_64::structures::paging::PageTableFlags::PRESENT);
                info!("Set PML4 entry {} to new frame at {:?}", pl4_index, new_frame.start_address());
            }

            let pl3_table = &mut *(pl4_entry.addr().as_u64() as *mut PageTable);
            let pl3_entry = &mut pl3_table[pl3_index];
            if pl3_entry.is_unused() {
                let new_frame = PhysFrame::<Size4KiB>::containing_address(
                    PhysAddr::new( get_zeroed_page(self.get_page)?.0));
                pl3_entry.set_addr(new_frame.start_address(), flags | x86_64::structures::paging::PageTableFlags::PRESENT);
            }

            let pl2_table = &mut *(pl3_entry.addr().as_u64() as *mut PageTable);
            let pl2_entry = &mut pl2_table[pl2_index];
            if pl2_entry.is_unused() {
                let new_frame = PhysFrame::<Size4KiB>::containing_address(
                    PhysAddr::new( get_zeroed_page(self.get_page)?.0 ));
                pl2_entry.set_addr(new_frame.start_address(), flags | x86_64::structures::paging::PageTableFlags::PRESENT);
            }

            let pl1_table = &mut *(pl2_entry.addr().as_u64() as *mut PageTable);
            let pl1_entry = &mut pl1_table[pl1_index];
            if !pl1_entry.is_unused() {
                return Err("Virtual address already mapped");
            }

            // For simplicity, we only support mapping a single page here. In a real implementation, you'd want to handle larger mappings.
            pl1_entry.set_addr(PhysAddr::new(phys_addrs as u64), flags | x86_64::structures::paging::PageTableFlags::PRESENT);
        }

        Ok(())
    }

    pub fn get_flags(&self, virtual_addr: VirtualAddress) -> Option<x86_64::structures::paging::PageTableFlags> {
        let virtual_addr = virtual_addr.0;
        let pl4_index = ((virtual_addr >> 39) & 0o777) as usize;
        let pl3_index = ((virtual_addr >> 30) & 0o777) as usize;
        let pl2_index = ((virtual_addr >> 21) & 0o777) as usize;
        let pl1_index = ((virtual_addr >> 12) & 0o777) as usize;

        unsafe {
            let pl4_entry = &self.page_table_l4[pl4_index];
            if pl4_entry.is_unused() {
                return None;
            }

            let pl3_table = &mut *(pl4_entry.addr().as_u64() as *mut PageTable);
            let pl3_entry = &pl3_table[pl3_index];
            if pl3_entry.is_unused() {
                return None;
            }

            let pl2_table = &mut *(pl3_entry.addr().as_u64() as *mut PageTable);
            let pl2_entry = &pl2_table[pl2_index];
            if pl2_entry.is_unused() {
                return None;
            }

            if pl2_entry.flags().contains(x86_64::structures::paging::PageTableFlags::HUGE_PAGE) {
                return Some(pl2_entry.flags());
            }

            let pl1_table = &mut *(pl2_entry.addr().as_u64() as *mut PageTable);
            let pl1_entry = &pl1_table[pl1_index];
            if pl1_entry.is_unused() {
                return None;
            }

            Some(pl1_entry.flags())
        }
    }
 

    pub fn virtual_to_physical(&self, virtual_addr: VirtualAddress) -> Option<PhysicalAddress> {
        let virtual_addr = virtual_addr.0;
        let pl4_index = ((virtual_addr >> 39) & 0o777) as usize;
        let pl3_index = ((virtual_addr >> 30) & 0o777) as usize;
        let pl2_index = ((virtual_addr >> 21) & 0o777) as usize;
        let pl1_index = ((virtual_addr >> 12) & 0o777) as usize;

        unsafe {
            let pl4_entry = &self.page_table_l4[pl4_index];
            if pl4_entry.is_unused() {
                return None;
            }

            // page directory entry is 4kb page...
            // TODO: this shouldn't have to be mutable, but (confirm this...)
            // the API for PageTableEntry doesn't have a way to get the address without mutably borrowing the entry
            let pl3_table = &mut *(pl4_entry.addr().as_u64() as *mut PageTable);
            let pl3_entry = &pl3_table[pl3_index];
            if pl3_entry.is_unused() {
                return None;
            }

            // this could be a 2mb page...
            let pl2_table = &mut *(pl3_entry.addr().as_u64() as *mut PageTable);
            let pl2_entry = &pl2_table[pl2_index];
            if pl2_entry.is_unused() {
                return None;
            }

            if pl2_entry.flags().contains(x86_64::structures::paging::PageTableFlags::HUGE_PAGE) {

                info!("Virtual address 0x{:x} maps to HUGE physical address 0x{:x} with flags {:?}", 
                    virtual_addr, pl2_entry.addr().as_u64(), pl2_entry.flags());

                return Some(PhysicalAddress::from_addr(pl2_entry.addr().as_u64() + (virtual_addr & 0x1FFFFF)));
            }

            let pl1_table = &mut *(pl2_entry.addr().as_u64() as *mut PageTable);
            let pl1_entry = &pl1_table[pl1_index];
            if pl1_entry.is_unused() {
                return None;
            }

            info!("Virtual address 0x{:x} maps to physical address 0x{:x} with flags {:?}", 
                virtual_addr, pl1_entry.addr().as_u64(), pl1_entry.flags());

            Some(PhysicalAddress::from_addr(pl1_entry.addr().as_u64() + (virtual_addr & 0xFFF)))
        }
    }


    pub fn output_mmap(&self) {
        unsafe {
            for (i, entry) in self.page_table_l4.iter().enumerate() {
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