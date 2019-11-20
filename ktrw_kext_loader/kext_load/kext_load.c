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

#include "kext_load.h"

#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach-o/reloc.h>

#include "kernel_call.h"
#include "kernel_memory.h"
#include "kernel_slide.h"
#include "ktrr_bypass.h"
#include "log.h"
#include "map_file.h"
#include "resolve_symbol.h"


// The name of the kext entry point symbol.
static const char *KEXT_START_SYMBOL = "__kext_start";

// ---- Mach-O parsing ----------------------------------------------------------------------------

struct macho_info {
	const struct mach_header_64 *mh;
	size_t size;
	uint64_t base_vmaddr;
	uint64_t vmsize;
	uint64_t entry;
	const struct symtab_command *symtab;
	const struct dysymtab_command *dysymtab;
	const struct nlist_64 *nlist;
	const struct relocation_info *extrel;
	const struct relocation_info *locrel;
	const char *path;
};

/*
 * validate_macho
 *
 * Description:
 * 	Validate a Mach-O file and extract the relevant components to facilitate loading.
 */
static bool
validate_macho(const char *path, const struct mach_header_64 *mh, size_t size,
		const char *entry_symbol, struct macho_info *info) {
	info->mh = mh;
	info->size = size;
	info->path = path;
	// First check that this is at least the size of a valid Mach-O header.
	if (size < sizeof(*mh)) {
		ERROR("%s: Mach-O too small", path);
		return 0;
	}
	// Check the load commands.
	uint64_t base_vmaddr = 0;
	const struct symtab_command *symtab = NULL;
	const struct dysymtab_command *dysymtab = NULL;
	bool found_first_segment = false;
	uint64_t vmaddr = 0;
	const struct load_command *lcmds = (struct load_command *)(mh + 1);
	const struct load_command *lc = lcmds;
	for (uint32_t cmd_idx = 0; cmd_idx < mh->ncmds; cmd_idx++) {
		DEBUG_TRACE(2, "%s: load_command[%u]: cmd = %x, cmdsize = %x",
				path, cmd_idx, lc->cmd, lc->cmdsize);
		// Do basic validation of the load command.
		if ((uintptr_t)lc + sizeof(*lc) > (uintptr_t)lcmds + mh->sizeofcmds) {
			ERROR("%s: Load command %u out of range", path, cmd_idx);
			return false;
		}
		if ((uintptr_t)lc + lc->cmdsize > (uintptr_t)lcmds + mh->sizeofcmds) {
			ERROR("%s: Load command %u contents out of range", path, cmd_idx);
			return false;
		}
		// Validate each segment command.
		if (lc->cmd == LC_SEGMENT_64) {
			const struct segment_command_64 *sc = (struct segment_command_64 *)lc;
			if (lc->cmdsize < sizeof(*sc)) {
				ERROR("%s: Segment command %u too small", path, cmd_idx);
				return false;
			}
			if (sc->fileoff > size || sc->fileoff + sc->filesize > size) {
				ERROR("%s: Segment %u overflows file", path, cmd_idx);
				return false;
			}
			if (sc->filesize > sc->vmsize) {
				ERROR("%s: Segment %u file size is greater than virtual size",
						path, cmd_idx);
				return false;
			}
			if (sc->vmaddr + sc->vmsize < sc->vmaddr) {
				ERROR("%s: Segment %u wraps around", path, cmd_idx);
				return false;
			}
			if (sc->vmaddr != vmaddr) {
				ERROR("%s: Segment %u is not contiguous", path, cmd_idx);
				return false;
			}
			if (!found_first_segment) {
				if (sc->vmaddr != 0) {
					ERROR("%s: Segment %u does not start at address 0",
							path, cmd_idx);
					return false;
				}
				found_first_segment = true;
				base_vmaddr = sc->vmaddr;
			}
			vmaddr += sc->vmsize;
		}
		// Validate the symtab command.
		if (lc->cmd == LC_SYMTAB) {
			if (symtab != NULL) {
				ERROR("%s: Multiple SYMTAB commands", path);
				return false;
			}
			symtab = (struct symtab_command *)lc;
			if (lc->cmdsize < sizeof(*symtab)) {
				ERROR("%s: Symtab command %u too small", path, cmd_idx);
				return false;
			}
			size_t syms_size = symtab->nsyms * sizeof(struct nlist_64);
			if (symtab->symoff > size || symtab->symoff + syms_size > size) {
				ERROR("%s: Symbol table overflows file", path);
				return false;
			}
			// We'll need to validate the individual strings later.
			if (symtab->stroff >= size) {
				ERROR("%s: String table overflows file", path);
				return false;
			}
		}
		// Validate the dysymtab command.
		if (lc->cmd == LC_DYSYMTAB) {
			if (dysymtab != NULL) {
				ERROR("%s: Multiple DYSYMTAB commands", path);
				return false;
			}
			dysymtab = (struct dysymtab_command *)lc;
			if (lc->cmdsize < sizeof(*dysymtab)) {
				ERROR("%s: Dysymtab command %u too small", path, cmd_idx);
				return false;
			}
			size_t extreloff = dysymtab->extreloff;
			size_t extrels_size = dysymtab->nextrel * sizeof(struct relocation_info);
			if (extreloff > size || extreloff + extrels_size > size) {
				ERROR("%s: External relocation entries oveflow file", path);
				return false;
			}
		}
		// Advance to the next load command.
		lc = (struct load_command *)((uintptr_t)lc + lc->cmdsize);
	}
	// Check that we have at least one segment.
	if (!found_first_segment) {
		ERROR("%s: No segments", path);
		return false;
	}
	// Check that we have a symtab.
	if (symtab == NULL) {
		ERROR("%s: No symbol table", path);
		return false;
	}
	// Check that we have a dysymtab.
	if (dysymtab == NULL) {
		ERROR("%s: No dynamic symbol table", path);
		return false;
	}
	// Update the Mach-O info.
	uint64_t vmsize = vmaddr;
	info->base_vmaddr = base_vmaddr;
	info->vmsize = vmsize;
	info->symtab = symtab;
	info->dysymtab = dysymtab;
	// Validate the symbols and find the entry point symbol.
	const struct nlist_64 *nlist = (struct nlist_64 *)((uintptr_t)mh + symtab->symoff);
	info->nlist = nlist;
	bool found_entry = false;
	for (uint32_t sym_idx = 0; sym_idx < symtab->nsyms; sym_idx++) {
		const struct nlist_64 *nl = &nlist[sym_idx];
		uint32_t strx = nl->n_un.n_strx;
		if (symtab->stroff + strx >= size) {
			ERROR("%s: Symbol %u string index out-of-bounds", path, sym_idx);
			return false;
		}
		const char *name = (const char *)((uintptr_t)mh + symtab->stroff + strx);
		size_t max_len = size - (symtab->stroff + strx);
		size_t sym_len = strnlen(name, max_len);
		if (sym_len == max_len) {
			ERROR("%s: Symbol %u string runs out-of-bounds", path, sym_idx);
			return false;
		}
		// Check to see if this is the entry point symbol.
		int cmp = strcmp(name, entry_symbol);
		if (cmp == 0) {
			if (found_entry) {
				ERROR("%s: Multiple %s symbols", path, entry_symbol);
				return false;
			}
			if ((nl->n_type & N_STAB) != 0 || (nl->n_type & N_TYPE) != N_SECT) {
				ERROR("%s: Symbol %s has incorrect type", path, entry_symbol);
				return false;
			}
			found_entry = true;
			info->entry = nl->n_value;
		}
	}
	// Check that we found the entry point.
	if (!found_entry) {
		ERROR("%s: No %s symbol", path, entry_symbol);
		return false;
	}
	// Validate the external relocations.
	const struct relocation_info *extrel = (void *)((uintptr_t)mh + dysymtab->extreloff);
	info->extrel = extrel;
	for (uint32_t extrel_idx = 0; extrel_idx < dysymtab->nextrel; extrel_idx++) {
		const struct relocation_info *ri = &extrel[extrel_idx];
		if (!ri->r_extern) {
			WARNING("%s: External relocation %u is not external", path, extrel_idx);
			continue;
		}
		if (ri->r_symbolnum >= symtab->nsyms) {
			ERROR("%s: External relocation %u references out-of-bounds symbol",
					path, extrel_idx);
			return false;
		}
		const struct nlist_64 *nl = &nlist[ri->r_symbolnum];
		uint32_t strx = nl->n_un.n_strx;
		assert(symtab->stroff + strx < size);
		uint64_t vmaddr = base_vmaddr + ri->r_address;
		if (vmaddr + (1uLL << ri->r_length) > vmsize) {
			ERROR("%s: External relocation %u address %x is out of bounds",
					path, extrel_idx, ri->r_address);
			return false;
		}
		if (ri->r_length != 3) {
			WARNING("%s: External relocation %u has unexpected length %u",
					info->path, extrel_idx, ri->r_length);
			continue;
		}
	}
	// Validate the local relocations.
	const struct relocation_info *locrel = (void *)((uintptr_t)mh + dysymtab->locreloff);
	info->locrel = locrel;
	for (uint32_t locrel_idx = 0; locrel_idx < dysymtab->nlocrel; locrel_idx++) {
		const struct relocation_info *ri = &locrel[locrel_idx];
		if (ri->r_extern) {
			WARNING("%s: Local relocation %u is external", path, locrel_idx);
			continue;
		}
		uint64_t vmaddr = base_vmaddr + ri->r_address;
		if (vmaddr + (1uLL << ri->r_length) > vmsize) {
			ERROR("%s: Local relocation %u address %x is out of bounds",
					path, locrel_idx, ri->r_address);
			return false;
		}
		if (ri->r_length != 3) {
			WARNING("%s: Local relocation %u has unexpected length %u",
					info->path, locrel_idx, ri->r_length);
			continue;
		}
	}
	return true;
}

/*
 * map_macho
 *
 * Description:
 * 	Map the Mach-O file into memory.
 */
static bool
map_macho(struct macho_info *info, void **mapped) {
	const struct mach_header_64 *mh = info->mh;
	// Allocate space for the virtually mapped file.
	void *mapping = malloc(info->vmsize);
	assert(mapping != NULL);
	*mapped = mapping;
	// Start copying in the segments.
	const struct load_command *lc = (struct load_command *)(mh + 1);
	for (uint32_t cmd_idx = 0; cmd_idx < mh->ncmds; cmd_idx++) {
		if (lc->cmd == LC_SEGMENT_64) {
			const struct segment_command_64 *sc = (struct segment_command_64 *)lc;
			uint64_t vmoff = sc->vmaddr - info->base_vmaddr;
			void *vmseg = (uint8_t *)mapping + vmoff;
			void *fileseg = (uint8_t *)mh + sc->fileoff;
			memcpy(vmseg, fileseg, sc->filesize);
		}
		lc = (struct load_command *)((uintptr_t)lc + lc->cmdsize);
	}
	return true;
}

/*
 * relocate_macho
 *
 * Description:
 * 	Apply local relocations to base the kext at its new load address.
 */
static void
relocate_macho(struct macho_info *info, void *mapping, uint64_t new_base_vmaddr) {
	uint64_t base_vmaddr = info->base_vmaddr;
	const struct dysymtab_command *dysymtab = info->dysymtab;
	const struct relocation_info *locrel = info->locrel;
	// Process the dysymtab's local relocations.
	for (uint32_t locrel_idx = 0; locrel_idx < dysymtab->nlocrel; locrel_idx++) {
		const struct relocation_info *ri = &locrel[locrel_idx];
		// Skip extern or non-8-byte relocations.
		if (ri->r_extern || ri->r_length != 3) {
			continue;
		}
		// Find the offset of the relocation pointer in the virtually mapped Mach-O and
		// slide it to the new base address.
		uint64_t vmoff = ri->r_address;
		uint64_t *reloc_ptr = (uint64_t *)((uintptr_t)mapping + vmoff);
		*reloc_ptr = *reloc_ptr - base_vmaddr + new_base_vmaddr;
	}
}

// ---- Kext loading ------------------------------------------------------------------------------

/*
 * link_kext
 *
 * Description:
 * 	Perform in-memory linking of the mapped Mach-O.
 */
static bool
link_kext(void *mapping, struct macho_info *info) {
	const struct mach_header_64 *mh = info->mh;
	const struct symtab_command *symtab = info->symtab;
	const struct dysymtab_command *dysymtab = info->dysymtab;
	const struct nlist_64 *nlist = info->nlist;
	const struct relocation_info *extrel = info->extrel;
	// Process the dysymtab's external relocations.
	for (uint32_t extrel_idx = 0; extrel_idx < dysymtab->nextrel; extrel_idx++) {
		const struct relocation_info *ri = &extrel[extrel_idx];
		// Skip non-extern or non-8-byte relocations.
		if (!ri->r_extern || ri->r_length != 3) {
			continue;
		}
		// Get the name of the symbol.
		const struct nlist_64 *nl = &nlist[ri->r_symbolnum];
		uint32_t strx = nl->n_un.n_strx;
		const char *name = (const char *)((uintptr_t)mh + symtab->stroff + strx);
		// Resolve the symbol to its runtime address.
		uint64_t symbol_value = resolve_symbol(name);
		if (symbol_value == 0) {
			WARNING("%s: Could not resolve symbol %s", info->path, name);
			continue;
		}
		DEBUG_TRACE(1, "Resolved %s = 0x%llx", name, symbol_value + kernel_slide);
		// Find the offset of the relocation pointer in the virtually mapped Mach-O and
		// replace it with the resolved address of the symbol. r_address is the offset from
		// the first segment's vmaddr to the vmaddr of the pointer. Since we've put the
		// first segment's vmaddr at offset 0 in the mapping, this means that r_address is
		// exactly the offset into the mapping of the pointer we want to change.
		uint64_t vmoff = ri->r_address;
		*(uint64_t *)((uintptr_t)mapping + vmoff) = symbol_value + kernel_slide;
	}
	return true;
}

/*
 * map_kext
 *
 * Description:
 * 	Map the kext into kernel memory and set memory protections.
 */
static bool
map_kext(void *mapping, struct macho_info *info, uint64_t *kext_address) {
	const struct mach_header_64 *mh = info->mh;
	struct load_command *lcmds = (struct load_command *)(mh + 1);
	size_t vmsize = info->vmsize;
	// Allocate space for the kext.
	uint64_t kext = kernel_vm_allocate(vmsize);
	if (kext == 0) {
		ERROR("%s: Could not allocate kernel memory", info->path);
		return false;
	}
	// Now that we know the in-kernel address of the kext, process local relocations.
	DEBUG_TRACE(1, "kext = %llx", kext);
	relocate_macho(info, mapping, kext);
	// Copy in the kext data.
	bool ok = kernel_write(kext, mapping, vmsize);
	if (!ok) {
		kernel_vm_deallocate(kext, vmsize);
		ERROR("Could not write kext into kernel memory");
		return false;
	}
	// Set VM permissions on each of the kext's segments.
	const struct load_command *lc = lcmds;
	for (uint32_t cmd_idx = 0; cmd_idx < mh->ncmds; cmd_idx++) {
		if (lc->cmd == LC_SEGMENT_64) {
			const struct segment_command_64 *sc = (struct segment_command_64 *)lc;
			uint64_t vmaddr = kext + sc->vmaddr;
			DEBUG_TRACE(1, "Protecting segment %llx-%llx as %x",
					sc->vmaddr, sc->vmaddr + sc->vmsize, sc->initprot);
			// On iOS 12.4 it was sufficient to call mach_vm_protect(), but as of iOS
			// 13 that does not clear the page descriptor's PXN bit when setting
			// execute permissions; thus, it's necessary to manually correct the page
			// table bits ourselves.
			ktrr_vm_protect(vmaddr, sc->vmsize, sc->initprot);
		}
		lc = (struct load_command *)((uintptr_t)lc + lc->cmdsize);
	}
	*kext_address = kext;
	return true;
}

/*
 * load_and_run_kext
 *
 * Description:
 * 	Load the kernel extension into the kernel and run it with the specified argument.
 */
static uint64_t
load_and_run_kext(const char *path, void *data, size_t size, uint64_t argument) {
	DEBUG_TRACE(1, "Loading kext %s", path);
	struct mach_header_64 *mh = data;
	// Validate the Mach-O.
	struct macho_info info;
	bool ok = validate_macho(path, mh, size, KEXT_START_SYMBOL, &info);
	if (!ok) {
		return 0;
	}
	// Map the kext in userspace. This will need to be freed.
	void *userspace_mapping;
	ok = map_macho(&info, &userspace_mapping);
	if (!ok) {
		return 0;
	}
	// Link the kext.
	ok = link_kext(userspace_mapping, &info);
	if (!ok) {
		free(userspace_mapping);
		return 0;
	}
	// Map the kext. This also performs internal relocations.
	uint64_t kext_address;
	ok = map_kext(userspace_mapping, &info, &kext_address);
	free(userspace_mapping);
	if (!ok) {
		return 0;
	}
	// Start the kext.
	uint64_t kext_start = kext_address + info.entry;
	DEBUG_TRACE(1, "Starting kext %s", path);
	sleep(1);
	__unused uint32_t ret;
	ret = kernel_call_7(kext_start, 1, argument);
	DEBUG_TRACE(1, "_kext_start returned 0x%x", ret);
	return kext_address;
}

// ---- Public API --------------------------------------------------------------------------------

bool
kext_load_set_kernel_symbol_database(const char *path) {
	return load_symbol_database(path);
}

uint64_t
kext_load(const char *file, uint64_t argument) {
	// Map the Mach-O file into memory.
	size_t size;
	void *data = map_file(file, &size);
	if (data == NULL) {
		return 0;
	}
	// Load the kernel extension and run it.
	uint64_t address = load_and_run_kext(file, data, size, argument);
	// Clean up.
	unmap_file(data, size);
	return address;
}
