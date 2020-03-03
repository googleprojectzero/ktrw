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

#include "page_table.h"

// ---- Page table values -------------------------------------------------------------------------

// The size of a page.
#define PAGE_SIZE	0x4000

// Create an L0, L1, or L2 TTE entry for 48-bit OAs.
#define TTE_L012_48b(NSTable, APTable, XNTable, PXNTable, Ignored_58_52, OA, Ignored_11_2)	\
	(((uint64_t) (NSTable) << 63) | \
	 ((uint64_t) (APTable) << 61) | \
	 ((uint64_t) (XNTable) << 60) | \
	 ((uint64_t) (PXNTable) << 59) | \
	 ((uint64_t) (Ignored_58_52) << 52) | \
	 ((uint64_t) (OA)) | \
	 ((uint64_t) (Ignored_11_2) << 2) | \
	 0b11)

// Create an L3 TTE entry for a 16k page.
#define TTE_L3_16k(Ignored_63, PBHA, Ignored_58_55, UXN, PXN, Contiguous, DBM, OA, \
		nG, AF, SH, AP, NS, AttrIdx) \
	(((uint64_t) (Ignored_63) << 63) | \
	 ((uint64_t) (PBHA) << 59) | \
	 ((uint64_t) (Ignored_58_55) << 55) | \
	 ((uint64_t) (UXN) << 54) | \
	 ((uint64_t) (PXN) << 53) | \
	 ((uint64_t) (Contiguous) << 52) | \
	 ((uint64_t) (DBM) << 51) | \
	 ((uint64_t) (OA)) | \
	 ((uint64_t) (nG) << 11) | \
	 ((uint64_t) (AF) << 10) | \
	 ((uint64_t) (SH) << 8) | \
	 ((uint64_t) (AP) << 6) | \
	 ((uint64_t) (NS) << 5) | \
	 ((uint64_t) (AttrIdx) << 2) | \
	 0b11)

// The number of virtual address bits for each page table level.
static const unsigned l1_size = 3;
static const unsigned l2_size = 11;
static const unsigned l3_size = 11;
static const unsigned pg_bits = 14;
static const unsigned phys_bits = 40;
static const uint64_t tt1_base = -(1uL << (l1_size + l2_size + l3_size + pg_bits));

// ---- Internal functions ------------------------------------------------------------------------

// Extract the specified bits from a 64-bit value.
static inline uint64_t
bits64(uint64_t value, unsigned hi, unsigned lo, unsigned shift) {
	return (((value << (63 - hi)) >> (63 - hi + lo)) << shift);
}

// Disable interrupts.
static inline uint64_t
disable_interrupts() {
	uint64_t daif;
	asm volatile("mrs %0, DAIF" : "=r"(daif));
	asm volatile("msr DAIFset, #0xf");
	return daif;
}

// Re-enable interrupts.
static inline void
enable_interrupts(uint64_t daif) {
	asm volatile("msr DAIF, %0" : : "r"(daif));
}

// Issue an ISB.
#define isb()	\
	asm volatile("isb")

// Issue a DMB.
#define dmb(_type)	\
	asm volatile("dmb " #_type)

// Issue a DSB.
#define dsb(_type)	\
	asm volatile("dsb " #_type)

// ---- Kernel virtual to physical translation ----------------------------------------------------

uint64_t
kernel_virtual_to_physical(uint64_t kvaddr) {
	uint64_t daif, par_el1;
	daif = disable_interrupts();
	asm volatile("at s1e1r, %0" : : "r"(kvaddr));
	isb();
	asm volatile("mrs %0, PAR_EL1" : "=r"(par_el1));
	enable_interrupts(daif);
	if (par_el1 & 0x1) {
		return -1;
	}
	return (bits64(par_el1, 47, 12, 12) | bits64(kvaddr, 11, 0, 0));
}

// ---- Cacheing ----------------------------------------------------------------------------------

void
cache_invalidate(void *address, size_t size) {
	uint64_t cache_line_size = 64;
	uint64_t start = ((uintptr_t) address) & ~(cache_line_size - 1);
	uint64_t end = ((uintptr_t) address + size + cache_line_size - 1) & ~(cache_line_size - 1);
	for (uint64_t addr = start; addr < end; addr += cache_line_size) {
		asm volatile("dc ivac, %0" : : "r"(addr));
	}
	dsb(sy);
}

void
cache_clean_and_invalidate(void *address, size_t size) {
	uint64_t cache_line_size = 64;
	uint64_t start = ((uintptr_t) address) & ~(cache_line_size - 1);
	uint64_t end = ((uintptr_t) address + size + cache_line_size - 1) & ~(cache_line_size - 1);
	for (uint64_t addr = start; addr < end; addr += cache_line_size) {
		asm volatile("dc civac, %0" : : "r"(addr));
	}
	dsb(sy);
}

// ---- Memory mapping via TTBR0_EL1 --------------------------------------------------------------

// The primitives we need to manipulate arbitrary page tables are arbitrary physical read,
// arbitrary physical write, and arbitrary virtual-to-physical translation. Normally the way to do
// this is to call ml_phys_read_data()/ml_phys_write_data(), but we want to find a way to do it
// without calling kernel functions. Thus, we'll build arbitrary physical read/write using
// TTBR0_EL1 (which we don't need anymore since this thread will never return to userspace).
//
// We set up a new page table hierarchy (using TCR_EL1 for measurements) that allows us to map
// address 0x1_0000_0000 to the page of our choosing. We then obtain the kernel virtual address of
// the TTBR0 L3 TTE mapping 0x100000000, which allows us to modify it (and hence what physical
// address that virtual address points to) arbitrarily.
//
// The even easier alternative is to set up page tables for a direct virtual-to-physical mapping in
// TTBR0_EL1. However, this requires a lot of space for the page tables, so the single-page
// approach used here is a better compromise.

// Our mapping space is that defined by a single page of L3 TTEs. Set the base address of the
// mapping to something recognizable.
static const uint64_t map_base = 7uLL << (l2_size + l3_size + pg_bits);
static const uint64_t map_size = 1uLL << (l3_size + pg_bits);

// The L1 page table. Only 8 entries are used.
__attribute__((aligned(PAGE_SIZE)))
static uint8_t l1_page_table[PAGE_SIZE];

// The L2 page table. Only 1 entry is used.
__attribute__((aligned(PAGE_SIZE)))
static uint8_t l2_page_table[PAGE_SIZE];

// The L3 page table.
__attribute__((aligned(PAGE_SIZE)))
static uint8_t l3_page_table[PAGE_SIZE];

// Access the page tables via TTEs.
static uint64_t *const l1_ttes = (uint64_t *)l1_page_table;
static uint64_t *const l2_ttes = (uint64_t *)l2_page_table;
static uint64_t *const l3_ttes = (uint64_t *)l3_page_table;

// Issue a DSB ISH and ISB.
static inline void
synchronize_page_table() {
	dsb(sy);
	isb();
}

// Given an L3 TTE index, return the virtual address.
static uint64_t
ttbr0_l3_index_to_vaddr(uint64_t l3_index) {
	return map_base + l3_index * PAGE_SIZE;
}

void
ttbr0_page_tables_init() {
	// Only initialize once.
	static bool initialized = false;
	if (initialized) {
		return;
	}
	initialized = true;
	// TODO: Validate AttrIdx with MAIR_EL1.
	// Get the physical addresses of the page tables.
	uint64_t l1_table_phys = kernel_virtual_to_physical((uintptr_t) l1_page_table);
	uint64_t l2_table_phys = kernel_virtual_to_physical((uintptr_t) l2_page_table);
	uint64_t l3_table_phys = kernel_virtual_to_physical((uintptr_t) l3_page_table);
	uint64_t ttbr0_el1 = l1_table_phys;
	// Initialize the base of the page table hierarchy.
	uint64_t l1_index = (map_base >> (l2_size + l3_size + pg_bits)) & ((1 << l1_size) - 1);
	uint64_t l2_index = (map_base >> (l3_size + pg_bits)) & ((1 << l2_size) - 1);
	l1_ttes[l1_index] = TTE_L012_48b(0, 0, 0, 0, 0, l2_table_phys, 0);
	l2_ttes[l2_index] = TTE_L012_48b(0, 0, 0, 0, 0, l3_table_phys, 0);
	// Set TTBR0_EL1.
	asm volatile("msr TTBR0_EL1, %0" : : "r"(ttbr0_el1));
	synchronize_page_table();
}

void *
ttbr0_map(uint64_t paddr, size_t size, unsigned attr) {
	paddr = bits64(paddr, 39, 14, 14);
	size_t page_count = (size + PAGE_SIZE - 1) / PAGE_SIZE;
	// Find a stretch of contiguous empty L3 entries big enough to establish the mapping.
	size_t l3_entry_count = PAGE_SIZE / sizeof(uint64_t);
	size_t l3_index = 0;
	size_t l3_count = 0;
	// Skip the first index; this is reserved for temporary fast mappings.
	for (size_t index = 1; index < l3_entry_count; index++) {
		if ((l3_ttes[index] & 0x1) == 0) {
			// This TTE is empty. Add it to the current run.
			if (l3_count == 0) {
				l3_index = index;
			}
			l3_count++;
			if (l3_count >= page_count) {
				goto found;
			}
		} else {
			// This TTE is full. Reset.
			l3_count = 0;
		}
	}
	return NULL;
found:;
	// We found a suitable stretch of entries. Populate them.
	for (size_t i = 0; i < l3_count; i++) {
		// Add the TTE to map the page.
		l3_ttes[l3_index + i] = TTE_L3_16k(0, 0, 0, 1, 0, 0, 0, paddr + PAGE_SIZE * i,
				1, 1, SH_OUTER, AP_RWNA, 0, attr);
	}
	// Ensure that the writes to the page table have finished.
	synchronize_page_table();
	// Return the address corresponding to these entries.
	return (void *)ttbr0_l3_index_to_vaddr(l3_index);
}

void
ttbr0_unmap(void *address, size_t size) {
	uint64_t vaddr = ((uint64_t) address) & ~(PAGE_SIZE - 1);
	size_t page_count = (size + PAGE_SIZE - 1) / PAGE_SIZE;
	// Ensure that this address range looks valid.
	if (!(map_base <= vaddr && vaddr + page_count * PAGE_SIZE <= map_base + map_size)) {
		return;
	}
	// Make sure any writes to the mapping are finished.
	synchronize_page_table();
	// Clear out the TTEs.
	uint64_t l3_index = (vaddr >> pg_bits) & ((1 << l3_size) - 1);
	for (size_t i = 0; i < page_count; i++) {
		l3_ttes[l3_index + i] = 0;
	}
	// Ensure that the writes to the page table have finished.
	synchronize_page_table();
	// Invalidate the old TLB entries.
	for (size_t i = 0; i < page_count; i++) {
		vaddr = ttbr0_l3_index_to_vaddr(l3_index + i);
		asm volatile("tlbi vaae1is, %0" : : "r"(vaddr >> 12));
	}
	// Make sure TLB invalidation has finished.
	isb();
}

// Establish a quick mapping of the physical address using the dedicated fast mapping L3 entry.
static void *
ttbr0_fast_map(uint64_t paddr, unsigned attr) {
	// Finalize any writes to the old mapping.
	synchronize_page_table();
	// Add the TTE to map the page. This mapping sets UXN = 1, PXN = 0, SH = 10, and AP = 00.
	l3_ttes[0] = TTE_L3_16k(0, 0, 0, 1, 0, 0, 0, paddr, 1, 1, SH_OUTER, AP_RWNA, 0, attr);
	// Synchronize to ensure that the new entry is in place.
	synchronize_page_table();
	// Invalidate any existing TLB mapping.
	uint64_t vaddr = ttbr0_l3_index_to_vaddr(0);
	asm volatile("tlbi vaae1is, %0" : : "r"(vaddr >> 12));
	// Ensure the TLB invalidation has finished.
	synchronize_page_table();
	// Return the virtual address.
	return (void *)vaddr;
}

// ---- Accessing physical memory -----------------------------------------------------------------

uint64_t
physical_read_64(uint64_t paddr) {
	// Conservatively map as device memory.
	uint64_t offset = paddr & (PAGE_SIZE - 1);
	uint8_t *page = ttbr0_fast_map(paddr - offset, ATTR_Device_nGnRnE);
	return *(volatile uint64_t *)(page + offset);
}

void
physical_write_64(uint64_t paddr, uint64_t value) {
	// Conservatively map as device memory.
	uint64_t offset = paddr & (PAGE_SIZE - 1);
	uint8_t *page = ttbr0_fast_map(paddr - offset, ATTR_Device_nGnRnE);
	*(volatile uint64_t *)(page + offset) = value;
}

// ---- Modifying page tables ---------------------------------------------------------------------

// Read TTBR1_EL1.
static inline uint64_t
read_ttbr1_el1() {
	uint64_t ttbr1_el1;
	asm volatile("mrs %0, TTBR1_EL1" : "=r"(ttbr1_el1));
	return ttbr1_el1;
}

// Perform a page table lookup.
// TODO: This should use TTBR0, TTBR1, and TCR rather than hardcoding.
static uint64_t
aarch64_page_table_lookup(uint64_t ttb,
		uint64_t vaddr,
		uint64_t *p_l1_tte0, uint64_t *l1_tte0,
		uint64_t *p_l2_tte0, uint64_t *l2_tte0,
		uint64_t *p_l3_tte0, uint64_t *l3_tte0,
		uint64_t *vaddr_next) {
	if (vaddr < tt1_base) {
		if (vaddr_next != NULL) {
			*vaddr_next = tt1_base;
		}
		return -1;
	}
	const uint64_t tte_physaddr_mask = ((1uLL << phys_bits) - 1) & ~((1 << pg_bits) - 1);
	uint64_t l1_table = ttb;
	uint64_t l1_index = (vaddr >> (l2_size + l3_size + pg_bits)) & ((1 << l1_size) - 1);
	uint64_t l2_index = (vaddr >> (l3_size + pg_bits)) & ((1 << l2_size) - 1);
	uint64_t l3_index = (vaddr >> pg_bits) & ((1 << l3_size) - 1);
	uint64_t pg_offset = vaddr & ((1 << pg_bits) - 1);
	uint64_t p_l1_tte = l1_table + 8 * l1_index;
	if (p_l1_tte0 != NULL) {
		*p_l1_tte0 = p_l1_tte;
	}
	uint64_t l1_tte = physical_read_64(p_l1_tte);
	if (l1_tte0 != NULL) {
		*l1_tte0 = l1_tte;
	}
	if ((l1_tte & 3) != 3) {
		if (vaddr_next != NULL) {
			uint64_t l1_span = 1uL << (l2_size + l3_size + pg_bits);
			*vaddr_next = (vaddr & ~(l1_span - 1)) + l1_span;
		}
		return -1;
	}
	uint64_t l2_table = l1_tte & tte_physaddr_mask;
	uint64_t p_l2_tte = l2_table + 8 * l2_index;
	if (p_l2_tte0 != NULL) {
		*p_l2_tte0 = p_l2_tte;
	}
	uint64_t l2_tte = physical_read_64(p_l2_tte);
	if (l2_tte0 != NULL) {
		*l2_tte0 = l2_tte;
	}
	if ((l2_tte & 3) != 3) {
		if (vaddr_next != NULL) {
			uint64_t l2_span = 1uL << (l3_size + pg_bits);
			*vaddr_next = (vaddr & ~(l2_span - 1)) + l2_span;
		}
		return -1;
	}
	uint64_t l3_table = l2_tte & tte_physaddr_mask;
	uint64_t p_l3_tte = l3_table + 8 * l3_index;
	if (p_l3_tte0 != NULL) {
		*p_l3_tte0 = p_l3_tte;
	}
	uint64_t l3_tte = physical_read_64(p_l3_tte);
	if (l3_tte0 != NULL) {
		*l3_tte0 = l3_tte;
	}
	if (vaddr_next != NULL) {
		uint64_t l3_span = 1uL << pg_bits;
		*vaddr_next = (vaddr & ~(l3_span - 1)) + l3_span;
	}
	if ((l3_tte & 3) != 3) {
		return -1;
	}
	uint64_t frame = l3_tte & tte_physaddr_mask;
	return frame | pg_offset;
}

bool
ttbr1_page_table_set_page_attributes(void *page,
		unsigned uxn, unsigned pxn, unsigned sh, unsigned ap, unsigned attr) {
	uint64_t l3_tte_mask = TTE_L3_16k(0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0x3, 0x3, 0, 0x7);
	uint64_t new_bits = TTE_L3_16k(0, 0, 0, !!uxn, !!pxn, 0, 0, 0, 0, 0, sh, ap, 0, attr);
	uint64_t ttbr1_el1 = read_ttbr1_el1();
	uint64_t p_l3_tte, l3_tte;
	uint64_t phys = aarch64_page_table_lookup(ttbr1_el1, (uint64_t) page,
			NULL, NULL, NULL, NULL, &p_l3_tte, &l3_tte, NULL);
	if (phys == -1) {
		return false;
	}
	uint64_t new_l3_tte = (l3_tte & ~l3_tte_mask) | new_bits;
	physical_write_64(p_l3_tte, new_l3_tte);
	return true;
}

size_t
ttbr1_page_table_swap_physical_page(uint64_t paddr_old, uint64_t paddr_new) {
	page_table_sync();
	uint64_t phys_mask = (1uL << phys_bits) - (1uL << pg_bits);
	uint64_t l3_tte_mask = TTE_L3_16k(0, 0, 0, 0, 0, 0, 0, phys_mask, 0, 0, 0, 0, 0, 0);
	uint64_t new_bits    = TTE_L3_16k(0, 0, 0, 0, 0, 0, 0, paddr_new, 0, 0, 0, 0, 0, 0);
	uint64_t ttbr1_el1 = read_ttbr1_el1();
	uint64_t va = 0;
	size_t changed = 0;
	for (;;) {
		uint64_t p_l3_tte, l3_tte, va_next;
		uint64_t phys = aarch64_page_table_lookup(ttbr1_el1, va,
				NULL, NULL, NULL, NULL, &p_l3_tte, &l3_tte, &va_next);
		if (phys == paddr_old) {
			uint64_t new_l3_tte = (l3_tte & ~l3_tte_mask) | new_bits;
			physical_write_64(p_l3_tte, new_l3_tte);
			changed++;
		}
		va = va_next;
		if (va == 0) {
			break;
		}
	}
	asm volatile("tlbi vmalle1is");
	page_table_sync();
	return changed;
}

void
page_table_sync() {
	synchronize_page_table();
}
