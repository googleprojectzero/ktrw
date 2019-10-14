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

#include "jit_heap.h"

#include "page_table.h"
#include "primitives.h"

// ---- JIT heap internals ------------------------------------------------------------------------

#define PAGE_SIZE	0x4000

#define JIT_HEAP_PAGES	(JIT_HEAP_SIZE / PAGE_SIZE)

// The JIT heap. Since we will be setting permissions on individual allocations, the allocation
// granularity is a single page. This means that the jit heap itself must be page-aligned.
static uint8_t *jit_heap;

_Static_assert(JIT_HEAP_PAGES < (1uL << (sizeof(uint8_t) * 8)),
		"struct jit_heap_page: The number of JIT heap pages must fit in a uint8_t");

// For each page in the JIT heap, we have a small structure describing the allocation to which that
// page belongs.
struct jit_heap_page {
	// The index of the first page of this allocation.
	uint8_t alloc_index;
	// The number of allocated pages in this allocation.
	uint8_t alloc_count;
	// The VM permissions of the page (rwx).
	uint8_t vm_permissions;
};

// The information for each heap page.
static struct jit_heap_page jit_heap_pages[JIT_HEAP_PAGES] = {};

// Verifies that the specified address is part of the JIT heap.
static bool
verify_jit_heap_address(void *address) {
	uint8_t *p = address;
	return (jit_heap <= p && p < jit_heap + JIT_HEAP_SIZE);
}

// Set the alloc_index and alloc_count fields of the pages in the allocation.
static void
claim_jit_heap_allocation(size_t alloc_index, size_t alloc_count) {
	struct jit_heap_page *page = &jit_heap_pages[alloc_index];
	for (size_t i = 0; i < alloc_count; i++) {
		page->alloc_index = alloc_index;
		page->alloc_count = alloc_count;
		page++;
	}
}

// Find a region in the heap large enough for the specified allocation. The jit_heap_page structs
// for all pages in the allocation have the alloc_index and alloc_count fields initialized. The
// jit_heap_page struct for the first page is returned.
struct jit_heap_page *
reserve_jit_heap_allocation(size_t page_count) {
	// Find a stretch of unallocated pages of the requisite size.
	size_t alloc_index = 0;
	size_t alloc_count = 0;
	for (size_t page_index = 0; page_index < JIT_HEAP_PAGES; page_index++) {
		if (jit_heap_pages[page_index].alloc_count == 0) {
			// This one is free. Bump the alloc_count.
			if (alloc_count == 0) {
				alloc_index = page_index;
			}
			alloc_count++;
			if (alloc_count >= page_count) {
				claim_jit_heap_allocation(alloc_index, alloc_count);
				return &jit_heap_pages[alloc_index];
			}
		} else {
			// This one is allocated. Reset our count.
			alloc_count = 0;
		}
	}
	return NULL;
}

// Get the address of the start of the allocation containing this page.
static void *
jit_heap_allocation_address(size_t alloc_index) {
	return &jit_heap[alloc_index * PAGE_SIZE];
}

// Find the JIT heap allocation starting at this address.
struct jit_heap_page *
find_jit_heap_allocation(void *address) {
	if (!verify_jit_heap_address(address)) {
		return NULL;
	}
	if ((((uintptr_t) address) & (PAGE_SIZE - 1)) != 0) {
		return NULL;
	}
	size_t page_index = ((uint8_t *) address - jit_heap) / PAGE_SIZE;
	struct jit_heap_page *page = &jit_heap_pages[page_index];
	if (page->alloc_index != page_index) {
		return NULL;
	}
	if (page->alloc_count == 0) {
		return NULL;
	}
	return page;
}

static void
clear_jit_heap_page(struct jit_heap_page *page) {
	page->alloc_index = 0;
	page->alloc_count = 0;
	page->vm_permissions = 0;
}

static void
clear_jit_heap_allocation(struct jit_heap_page *page) {
	size_t alloc_index = page->alloc_index;
	size_t alloc_count = page->alloc_count;
	bzero(&jit_heap[alloc_index], alloc_count * PAGE_SIZE);
	for (size_t i = 0; i < alloc_count; i++) {
		clear_jit_heap_page(page);
		page++;
	}
}

// ---- JIT heap API ------------------------------------------------------------------------------

void
jit_heap_init(void *heap) {
	jit_heap = heap;
	jit_heap_reset();
}

void
jit_heap_reset() {
	for (size_t i = 0; i < JIT_HEAP_PAGES; i++) {
		clear_jit_heap_page(&jit_heap_pages[i]);
	}
}

void *
jit_heap_allocate(size_t size, int vm_prot) {
	size_t page_count = (size + PAGE_SIZE - 1) / PAGE_SIZE;
	struct jit_heap_page *page = reserve_jit_heap_allocation(page_count);
	if (page == NULL) {
		return NULL;
	}
	size_t alloc_index = page->alloc_index;
	size_t alloc_count = page->alloc_count;
	page_table_sync();
	for (size_t i = 0; i < alloc_count; i++) {
		void *heap_page = jit_heap_allocation_address(alloc_index + i);
		// We'll set the page for maximum permissions, regardless of what the user asked
		// for.
		ttbr1_page_table_set_page_attributes(heap_page, 1, 0, SH_OUTER, AP_RWNA,
				ATTR_Normal_WriteBack);
	}
	page_table_sync();
	return jit_heap_allocation_address(alloc_index);
}

bool
jit_heap_deallocate(void *address) {
	struct jit_heap_page *page = find_jit_heap_allocation(address);
	if (page == NULL) {
		return false;
	}
	clear_jit_heap_allocation(page);
	return true;
}
