use x86_64::registers::control::Cr3;
use x86_64::structures::paging::PhysFrame;
use x86_64::structures::paging::PageTable;
use x86_64::structures::paging::page_table::PageTableEntry;
use x86_64::PhysAddr;

use log::info;

pub struct Pager {
    pml4_table: &'static mut PageTable,
}

impl Pager {
    pub fn new() -> Pager {
        let (pml4_frame, _flags) = Cr3::read();
        let pml4_addr: PhysAddr = pml4_frame.start_address();

        info!("PML4 Physical Address: {:?}", pml4_addr);

        unsafe {
            let pml4_table = &mut *(pml4_frame.start_address().as_u64() as *mut PageTable);
            Pager { pml4_table }
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
                return Some(pd_entry.addr().as_u64() as usize + (virtual_addr & 0x1FFFFF));
            }

            let pt_table = &mut *(pd_entry.addr().as_u64() as *mut PageTable);
            let pt_entry = &pt_table[pt_index];
            if pt_entry.is_unused() {
                return None;
            }

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