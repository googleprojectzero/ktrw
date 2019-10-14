//
// Project: KTRW
// Author:  Brandon Azad <bazad@google.com>
//
// Copyright 2019 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

#ifndef PAGE_TABLE__H_
#define PAGE_TABLE__H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// ---- Kernel virtual to physical translation ----------------------------------------------------

/*
 * kernel_virtual_to_physical
 *
 * Description:
 * 	Translate the specified kernel virtual address into the corresponding physical address. The
 * 	kernel's shared TTBR1_EL1 is used for translation.
 */
uint64_t kernel_virtual_to_physical(uint64_t kvaddr);

// ---- Cacheing ----------------------------------------------------------------------------------

/*
 * cache_invalidate
 *
 * Description:
 * 	Invalidate cache lines for the specified virtual address range.
 */
void cache_invalidate(void *address, size_t size);

/*
 * cache_clean_and_invalidate
 *
 * Description:
 * 	Clean and invalidate cache lines for the specified virtual address range.
 */
void cache_clean_and_invalidate(void *address, size_t size);

// ---- Memory mapping via TTBR0_EL1 --------------------------------------------------------------

/*
 * ttbr0_page_tables_init
 *
 * Description:
 * 	Set up TTBR0_EL1 for mapping physical memory. This mapping is only present on this CPU
 * 	core, and thus will not be accessible to the rest of the kernel.
 *
 * 	This function should only be called once this thread has been pinned to the CPU, since if
 * 	we move to another CPU core then the TTBR0_EL1 register will no longer point to our page
 * 	tables.
 */
void ttbr0_page_tables_init(void);

#define SH_NONE		0x0
#define SH_OUTER	0x2
#define SH_INNER	0x3

#define AP_RWNA		0x0
#define AP_RWRW		0x1
#define AP_RONA		0x2
#define AP_RORO		0x3

#define ATTR_Normal_WriteBack		0
#define ATTR_Normal_NonCacheable	1
#define ATTR_Normal_WriteThrough	2
#define ATTR_Device_nGnRnE		3
#define ATTR_Device_nGnRE		5

/*
 * ttbr0_map
 *
 * Description:
 * 	Map the specified physical address range. The page is mapped for all access and with the
 * 	specified attributes.
 *
 * 	Due to how the mapping is implemented, a maximum of 4095 pages can be mapped
 * 	simultaneously.
 */
void *ttbr0_map(uint64_t paddr, size_t size, unsigned attr);

/*
 * ttbr0_map_io
 *
 * Description:
 * 	A convenience wrapper around ttbr0_map() for mapping device memory suitable for MMIO.
 */
static inline void *
ttbr0_map_io(uint64_t paddr, size_t size) {
	return ttbr0_map(paddr, size, ATTR_Device_nGnRnE);
}

/*
 * ttbr0_unmap
 *
 * Description:
 * 	Unmap a mapping established via ttbr0_map().
 */
void ttbr0_unmap(void *address, size_t size);

// ---- Accessing physical memory -----------------------------------------------------------------

/*
 * physical_read_64
 *
 * Description:
 * 	Read a 64-bit value from physical memory.
 */
uint64_t physical_read_64(uint64_t paddr);

/*
 * physical_write_64
 *
 * Description:
 * 	Write a 64-bit value to physical memory.
 */
void physical_write_64(uint64_t paddr, uint64_t value);

// ---- Modifying page tables ---------------------------------------------------------------------

/*
 * ttbr1_page_table_set_page_attributes
 *
 * Description:
 * 	Set attributes on the TTBR1_EL1 translation table entry mapping the specified page.
 */
bool ttbr1_page_table_set_page_attributes(void *page,
		unsigned uxn, unsigned pxn, unsigned sh, unsigned ap, unsigned attr);

/*
 * ttbr1_page_table_swap_physical_page
 *
 * Description:
 * 	Modify the TTBR1_EL1 page tables so that all virtual mappings of the specified physical
 * 	page instead refer to another physical page.
 */
size_t ttbr1_page_table_swap_physical_page(uint64_t paddr_old, uint64_t paddr_new);

/*
 * page_table_sync()
 *
 * Description:
 * 	Ensure that changes to the page table become visible.
 */
void page_table_sync(void);

#endif
