//
// Project: KTRW
// Author:  Brandon Azad <bazad@google.com>
//
// Copyright 2020 Google LLC
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

#include "pongo.h"

#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach-o/reloc.h>

// ---- Configuration -----------------------------------------------------------------------------

#define DISABLE_CHECKRA1N_KERNEL_PATCHES 1

// ---- Standard functions ------------------------------------------------------------------------

#undef memcmp
#define memcmp memcmp_
static int
memcmp(const void *s1, const void *s2, size_t n) {
	int diff = 0;
	for (size_t i = 0; diff == 0 && i < n; i++) {
		diff = ((uint8_t *) s1)[i] - ((uint8_t *) s2)[i];
	}
	return diff;
}

#undef memset

#undef strcpy

#undef strnlen
#define strnlen strnlen_
static size_t
strnlen(const char *s, size_t n) {
	size_t len = 0;
	while (len < n && s[len] != 0) {
		len++;
	}
	return len;
}

// ---- Pointer conversions -----------------------------------------------------------------------

static struct mach_header_64 *mh_execute_header;
static uint64_t kernel_slide;

#define sa_for_va(va)	((uint64_t) (va) - kernel_slide)
#define va_for_sa(sa)	((uint64_t) (sa) + kernel_slide)
#define ptr_for_sa(sa)	((void *) (((sa) - 0xFFFFFFF007004000uLL) + (uint8_t *) mh_execute_header))
#define ptr_for_va(va)	(ptr_for_sa(sa_for_va(va)))
#define sa_for_ptr(ptr)	((uint64_t) ((uint8_t *) (ptr) - (uint8_t *) mh_execute_header) + 0xFFFFFFF007004000uLL)
#define va_for_ptr(ptr)	(va_for_sa(sa_for_ptr(ptr)))
#define pa_for_ptr(ptr)	(sa_for_ptr(ptr) - gBootArgs->virtBase + gBootArgs->physBase)

// ---- Symbol table ------------------------------------------------------------------------------

// An in-memory symbol table for the current kernelcache.
struct kernelcache_symbol_table {
	struct kernelcache_symbol_table *next;
	size_t count;
	const char *const *symbol;
	const uint64_t *address;
};

// The chain of symbol tables for the current kernelcache.
static struct kernelcache_symbol_table *kernelcache_symbol_table = NULL;

// The UUID of the current kernelcache.
static uint8_t kernelcache_uuid[16];

// Whether the kernelcache UUID has been found by kernelcache_find_uuid().
static bool kernelcache_uuid_found = false;

// Find the UUID of the current kernelcache. Idempotent.
static void
kernelcache_find_uuid() {
	if (kernelcache_uuid_found) {
		return;
	}
	struct mach_header_64 *mh = mh_execute_header;
	struct load_command *lc = (void *) (mh + 1);
	uintptr_t lc_end = (uintptr_t) lc + mh->sizeofcmds;
	for (uint32_t cmd_idx = 0; cmd_idx < mh->ncmds; cmd_idx++) {
		if ((uintptr_t) lc + sizeof(*lc) > lc_end
				|| (uintptr_t) lc + lc->cmdsize > lc_end) {
			puts("Invalid kernel load commands");
			return;
		}
		if (lc->cmd == LC_UUID) {
			goto found;
		}
		lc = (void *) ((uintptr_t) lc + lc->cmdsize);
	}
	puts("Kernelcache UUID not found");
	return;
found:;
	struct uuid_command *uc = (void *) lc;
	memcpy(kernelcache_uuid, uc->uuid, sizeof(kernelcache_uuid));
	kernelcache_uuid_found = true;
}

// Binary format of kernelcache symbol table upload data:
// {
//     @ offset 0:
//     u32 kernelcache_count;
//     u32 symbol_strings_offset;
//     kernelcache_count * {
//         u8 kernelcache_uuid[16];
//         u32 kernelcache_symbols_offset;
//     };
//     @ kernelcache_symbols_offset:
//     {
//         u32 symbol_count;
//         symbol_count * {
//             u32 symbol_offset;
//             u64 address;
//         };
//     };
//     @ symbol_strings_offset:
//     char symbol_strings[] {
//         @ symbol_offset:
//         char symbol[];
//     }
// }

// Handles the "kernelcache-symbols" command, which is used to process the bulk uploaded data as a
// serialized symbol table.
static void
command_kernelcache_symbols() {
	// Grab the symbol table data.
	size_t size = loader_xfer_recv_count;
	loader_xfer_recv_count = 0;
	uint8_t *_data = loader_xfer_recv_data;
	// Make sure we have a kernelcache UUID.
	kernelcache_find_uuid();
	// Declare the allocation so that we can free it on the error path.
	struct kernelcache_symbol_table *symbol_table = NULL;
	// Set up state variables.
	uint8_t *_p = _data;
	uint8_t *const _end = _p + size;
	// Access macros.
#define ref(s)	({ if (_p + s > _end) { \
		       goto parse_error; \
		   } \
		   void *_r = _p; \
		   _p += s; \
		   _r; })
#define get(t)	({ *(t *) ref(sizeof(t)); })
#define addr(o)	({ if (_data + o > _end) { \
		       goto parse_error; \
		   } \
		   (void *) (_data + o); })
#define seek(o)	({ _p = addr(o); })
	// Parse the header.
	uint32_t kernelcache_count = get(uint32_t);
	uint32_t symbol_strings_offset = get(uint32_t);
	for (uint32_t i = 0; i < kernelcache_count; i++) {
		uint8_t *uuid = ref(sizeof(kernelcache_uuid));
		uint32_t kernelcache_symbols_offset = get(uint32_t);
		if (memcmp(uuid, kernelcache_uuid, sizeof(kernelcache_uuid)) == 0) {
			seek(kernelcache_symbols_offset);
			goto found_kernelcache;
		}
	}
	// Not found.
	puts("No matching kernelcache");
	return;
found_kernelcache:;
	// Allocate the kernelcache symbol table.
	uint32_t symbol_count = get(uint32_t);
	size_t symbol_array_size = symbol_count * sizeof(symbol_table->symbol[0]);
	size_t address_array_size = symbol_count * sizeof(symbol_table->address[0]);
	size_t symbol_strings_size = size - symbol_strings_offset;
	symbol_table = malloc(sizeof(*symbol_table)
			+ symbol_array_size + address_array_size
			+ symbol_strings_size);
	if (symbol_table == NULL) {
		puts("Failed to allocate symbol table");
		goto fail;
	}
	// Initialize the kernelcache_symbol_table fields.
	const char **symbols = (const char **) (symbol_table + 1);
	uint64_t *addresses = (uint64_t *) ((uintptr_t) symbols + symbol_array_size);
	symbol_table->count = symbol_count;
	symbol_table->symbol = symbols;
	symbol_table->address = addresses;
	// Ensure the symbol strings data is null terminated.
	char *symbol_table_strings = (char *) ((uintptr_t) addresses + address_array_size);
	const char *symbol_strings = addr(symbol_strings_offset);
	if (symbol_strings_size < 1) {
		goto parse_error;
	}
	if (symbol_strings[symbol_strings_size - 1] != 0) {
		goto parse_error;
	}
	// Populate the symbol table.
	for (uint32_t i = 0; i < symbol_count; i++) {
		uint32_t symbol_offset = get(uint32_t);
		uint64_t address = get(uint64_t);
		// We need at least one character (the null terminator) in the symbol; if we have
		// that, then we're guaranteed that the string doesn't go out-of-bounds by the
		// overall null-termination check above.
		if (symbol_offset + 1 > symbol_strings_size) {
			goto parse_error;
		}
		symbols[i] = symbol_table_strings + symbol_offset;
		addresses[i] = address;
	}
	// Copy in the symbol table strings. This may include unneeded strings, but it's simpler
	// than filtering.
	seek(symbol_strings_offset);
	memcpy(symbol_table_strings, ref(symbol_strings_size), symbol_strings_size);
	// The symbol table is ready! Link it in at the head of the existing chain.
	symbol_table->next = kernelcache_symbol_table;
	kernelcache_symbol_table = symbol_table;
	printf("Added %u kernelcache symbols", symbol_count);
	return;
parse_error:
	puts("Invalid symbol table");
fail:
	if (symbol_table != NULL) {
		free(symbol_table);
	}
#undef get
#undef ref
#undef seek
}

// Look up the static kernelcache address corresponding to the given named symbol.
static uint64_t
kernelcache_symbol_table_lookup(const char *symbol) {
	const struct kernelcache_symbol_table *symbol_table = kernelcache_symbol_table;
	for (; symbol_table != NULL; symbol_table = symbol_table->next) {
		for (uint32_t i = 0; i < symbol_table->count; i++) {
			if (strcmp(symbol_table->symbol[i], symbol) == 0) {
				return symbol_table->address[i];
			}
		}
	}
	return 0;
}

// ---- Kext loading ------------------------------------------------------------------------------

// The kmod_info struct from XNU.
#pragma pack(push, 4)
struct kmod_info {
	uint64_t next;
	int32_t  info_version;
	uint32_t id;
	char     name[64];
	char     version[64];
	int32_t  reference_count;
	uint64_t reference_list;
	uint64_t address;
	uint64_t size;
	uint64_t hdr_size;
	uint64_t start;
	uint64_t stop;
};
#pragma pack(pop)

// Load information for a kernel extension. Some fields point into the USB buffer.
struct kext_load_info {
	const struct mach_header_64 *header;
	void *kext;
	size_t file_size;
	size_t vm_size;
	uint64_t vm_base;
	struct kmod_info *kmod_info;
	struct symtab_command *symtab;
	struct dysymtab_command *dysymtab;
	const struct nlist_64 *nlist;
	const struct relocation_info *extrel;
	const struct relocation_info *locrel;
};

// Parse the kernel extension Mach-O to validate it and populate the kext_load_info.
static bool
kext_parse(const struct mach_header_64 *header, size_t file_size,
		struct kext_load_info *info) {
	// Basic sanity checks: Mach-O magic, kext type, size is sane, etc.
	if (header->magic != MH_MAGIC_64) {
		puts("Kext is not a 64-bit Mach-O");
		return false;
	}
	if (header->filetype != MH_KEXT_BUNDLE) {
		puts("Mach-O is not a KEXT type");
		return false;
	}
	if (sizeof(*header) + header->sizeofcmds > file_size) {
		puts("Invalid load commands size");
		return false;
	}
	// Store basic load info.
	info->header = header;
	info->file_size = file_size;
	// Iterate the load commands.
	uint64_t vmaddr = 0;
	bool found_first_segment = false;
	struct load_command *lc = (void *) (header + 1);
	uintptr_t lc_end = (uintptr_t) lc + header->sizeofcmds;
	for (uint32_t cmd_idx = 0; cmd_idx < header->ncmds; cmd_idx++) {
		// Check the command size.
		if ((uintptr_t) lc + sizeof(*lc) > lc_end) {
			puts("Invalid load commands");
			return false;
		}
		if ((uintptr_t) lc + lc->cmdsize > lc_end) {
			puts("Invalid load commands");
			return false;
		}
		// Forbid LC_SEGMENT.
		if (lc->cmd == LC_SEGMENT) {
			puts("LC_SEGMENT not permitted");
			return false;
		}
		// Destroy LC_SEGMENT_SPLIT_INFO. I haven't found a way to prevent this segment
		// from being generated during compile.
		if (lc->cmd == LC_SEGMENT_SPLIT_INFO) {
			lc->cmd ^= 0x41000000;
		}
		// Validate this segment. Segments must be contiguous.
		if (lc->cmd == LC_SEGMENT_64) {
			const struct segment_command_64 *sc = (void *) lc;
			if (lc->cmdsize < sizeof(*sc)) {
				puts("LC_SEGMENT_64 bad size");
				return false;
			}
			// Ensure no file overflow.
			if (sc->fileoff > file_size || sc->fileoff + sc->filesize > file_size
					|| sc->filesize > sc->vmsize) {
				puts("LC_SEGMENT_64 bad size");
				return false;
			}
			// Ensure no VM overflow.
			if (sc->vmaddr + sc->vmsize < sc->vmaddr) {
				puts("LC_SEGMENT_64 vm wrap");
				return false;
			}
			// If this is the first segment, set the base address.
			if (!found_first_segment) {
				// This is the first segment.
				found_first_segment = true;
				vmaddr = sc->vmaddr;
				info->vm_base = vmaddr;
				// The first segment must have file offset 0 in order to map the
				// Mach header at vm_base.
				if (sc->fileoff != 0 || sc->filesize < sizeof(*header)
						+ header->sizeofcmds) {
					puts("LC_SEGMENT_64 header not mapped");
					return false;
				}
			}
			// Ensure segments are contiguous.
			if (sc->vmaddr != vmaddr) {
				puts("LC_SEGMENT_64 not contiguous");
				return false;
			}
			vmaddr += sc->vmsize;
		}
		// Validate the symbol table.
		if (lc->cmd == LC_SYMTAB) {
			if (info->symtab != NULL) {
				puts("LC_SYMTAB repeated");
				return false;
			}
			struct symtab_command *symtab = (void *) lc;
			if (lc->cmdsize < sizeof(*symtab)) {
				puts("LC_SYMTAB bad size");
				return false;
			}
			// Validate the symbols (nlist_64 array).
			size_t size = symtab->nsyms * sizeof(struct nlist_64);
			if (symtab->symoff > file_size || symtab->symoff + size > file_size) {
				puts("LC_SYMTAB bad symbols");
				return false;
			}
			// Validate that the symbol strings don't start out-of-bounds (individual
			// strings still need validation).
			if (symtab->stroff >= file_size) {
				puts("LC_SYMTAB bad strings");
				return false;
			}
			info->symtab = symtab;
		}
		// Validate the dysymtab command.
		if (lc->cmd == LC_DYSYMTAB) {
			if (info->dysymtab != NULL) {
				puts("LC_DYSYMTAB repeated");
				return false;
			}
			struct dysymtab_command *dysymtab = (void *) lc;
			if (lc->cmdsize < sizeof(*dysymtab)) {
				puts("LC_DYSYMTAB bad size");
				return false;
			}
			// Validate the external relocations.
			size_t size = dysymtab->nextrel * sizeof(struct relocation_info);
			if (dysymtab->extreloff > file_size
					|| dysymtab->extreloff + size > file_size) {
				puts("LC_DYSYMTAB bad external relocations");
				return false;
			}
			// Validate the local relocations.
			size = dysymtab->nlocrel * sizeof(struct relocation_info);
			if (dysymtab->locreloff > file_size
					|| dysymtab->locreloff + size > file_size) {
				puts("LC_DYSYMTAB bad local relocations");
				return false;
			}
			info->dysymtab = dysymtab;
		}
		// Next load command.
		lc = (void *) ((uintptr_t) lc + lc->cmdsize);
	}
	// Set the VM size.
	uint64_t vm_end = vmaddr;
	info->vm_size = vm_end - info->vm_base;
	// We need LC_SEGMENT_64, LC_SYMTAB, and LC_DYSYMTAB.
	if (!found_first_segment) {
		puts("LC_SEGMENT_64 required");
		return false;
	}
	if (info->symtab == NULL) {
		puts("LC_SYMTAB required");
		return false;
	}
	if (info->dysymtab == NULL) {
		puts("LC_DYSYMTAB required");
		return false;
	}
	// Check the LC_SYMTAB strings. Also, find the _kmod_info symbol.
	info->nlist = (void *) ((uintptr_t) header + info->symtab->symoff);
	for (uint32_t sym_idx = 0; sym_idx < info->symtab->nsyms; sym_idx++) {
		const struct nlist_64 *nl = &info->nlist[sym_idx];
		size_t stroff = info->symtab->stroff + nl->n_un.n_strx;
		if (stroff < info->symtab->stroff || stroff >= file_size) {
			puts("LC_SYMTAB bad string");
			return false;
		}
		const char *name = (void *) ((uintptr_t) header + stroff);
		size_t max_len = file_size - stroff;
		// Ensure the symbol is null-terminated in bounds.
		size_t sym_len = strnlen(name, max_len);
		if (sym_len == max_len) {
			puts("LC_SYMTAB bad string");
			return false;
		}
		// Make sure that symbols point in-bounds.
		if ((nl->n_type & N_STAB) == 0 && (nl->n_type & N_TYPE) == N_SECT) {
			uint64_t address = nl->n_value;
			if (address < info->vm_base || vm_end < address) {
				puts("LC_SYMTAB bad address");
				return false;
			}
		}
		// Handle the _kmod_info symbol.
		if (strcmp(name, "_kmod_info") == 0) {
			if (info->kmod_info != 0) {
				puts("_kmod_info repeated");
				return false;
			}
			// Verify that the kmod_info is the right type.
			if ((nl->n_type & N_STAB) != 0
					|| (nl->n_type & N_TYPE) != N_SECT) {
				puts("_kmod_info bad type");
				return false;
			}
			// Verify the kmod_info is fully in-bounds.
			uint64_t address = nl->n_value;
			if (address + sizeof(struct kmod_info) < address
					|| address + sizeof(struct kmod_info) > vm_end) {
				puts("_kmod_info bad address");
				return false;
			}
			// Store the static kext address of the kmod_info struct. This is not a
			// valid pointer until after kext_map().
			info->kmod_info = (void *) nl->n_value;
		}
	}
	// We need a kmod_info symbol.
	if (info->kmod_info == 0) {
		puts("_kmod_info required");
		return false;
	}
	// Validate the external relocations.
	info->extrel = (void *) ((uintptr_t)header + info->dysymtab->extreloff);
	bool missing_symbols = false;
	for (uint32_t er_idx = 0; er_idx < info->dysymtab->nextrel; er_idx++) {
		const struct relocation_info *er = &info->extrel[er_idx];
		if (!er->r_extern) {
			puts("External relocation not external");
			return false;
		}
		if (er->r_length != 3) {
			puts("External relocation bad size");
			return false;
		}
		if (er->r_symbolnum >= info->symtab->nsyms) {
			puts("External relocation bad symbol");
			return false;
		}
		// Make sure we can resolve the symbol against the kernelcache.
		const struct nlist_64 *nl = &info->nlist[er->r_symbolnum];
		size_t stroff = info->symtab->stroff + nl->n_un.n_strx;
		const char *name = (void *) ((uintptr_t) header + stroff);
		uint64_t resolved = kernelcache_symbol_table_lookup(name);
		if (resolved == 0) {
			if (!missing_symbols) {
				missing_symbols = true;
				puts("Could not resolve symbols:");
			}
			puts(name);
			continue;
		}
		// Check that the reloccation address is in bounds.
		uint64_t vm_addr = info->vm_base + (uint64_t) er->r_address;
		if (vm_addr < info->vm_base || vm_addr > info->vm_size
				|| vm_addr + (1uLL << er->r_length) > info->vm_size) {
			puts("External relocation bad address");
			return false;
		}
	}
	// All symbols must resolve for linking to succeed.
	if (missing_symbols) {
		return false;
	}
	// Validate the local relocations.
	info->locrel = (void *) ((uintptr_t)header + info->dysymtab->locreloff);
	for (uint32_t lr_idx = 0; lr_idx < info->dysymtab->nlocrel; lr_idx++) {
		const struct relocation_info *lr = &info->locrel[lr_idx];
		if (lr->r_extern) {
			puts("Local relocation external");
			return false;
		}
		if (lr->r_length != 3) {
			puts("Local relocation bad size");
			return false;
		}
		// Check that the reloccation address is in bounds.
		uint64_t vm_addr = info->vm_base + (uint64_t) lr->r_address;
		if (vm_addr < info->vm_base || vm_addr > info->vm_size
				|| vm_addr + (1uLL << lr->r_length) > info->vm_size) {
			puts("Local relocation bad address");
			return false;
		}
	}
	return true;
}

// Allocate memory for the kernel extension in preparation for loading.
static bool
kext_alloc(struct kext_load_info *info) {
	size_t alloc_size = (info->vm_size + 0x3fff) & ~0x3fffuL;
	if ((uint32_t) alloc_size < info->vm_size) {
		goto fail;
	}
	void *alloc = alloc_static((uint32_t) alloc_size);
	if (alloc == NULL) {
		goto fail;
	}
	info->kext = alloc;
	return true;
fail:
	puts("Could not allocate kext");
	return false;
}

// Map the kernel extension by copying the "file" data to the kext allocation. After this
// operation, all the Mach-O pointers will be updated to point to the mapped copies in the kext
// itself.
//
// Because we're relying on the OSKext loading infrastructure, we need to adjust the vmaddr of each
// LC_SEGMENT_64 and section_64 to the corresponding static kernelcache address (i.e., excluding
// the kernel slide), due to the unconditional sliding of load commands in
// OSKext::slidePrelinkedExecutable(). Also, we need to set kmod_info->address to the static
// kernelcache address of the kext for OSKext::initWithPrelinkedInfoDict().
static void
kext_map(struct kext_load_info *info) {
	const struct mach_header_64 *mh = info->header;
	const struct load_command *lc = (void *) (mh + 1);
	// Iterate the load commands to find each LC_SEGMENT_64. These are the only load commands
	// that describe mapped data in a Mach-O kext.
	for (uint32_t cmd_idx = 0; cmd_idx < mh->ncmds; cmd_idx++) {
		if (lc->cmd == LC_SEGMENT_64) {
			// Copy the file contents into the VM region.
			const struct segment_command_64 *sc = (void *) lc;
			uint64_t vmoff = sc->vmaddr - info->vm_base;
			void *vmseg = (void *) ((uintptr_t) info->kext + vmoff);
			void *fileseg = (void *) ((uintptr_t) mh + sc->fileoff);
			memcpy(vmseg, fileseg, sc->filesize);
		}
		lc = (void *) ((uintptr_t) lc + lc->cmdsize);
	}
	// Update the Mach-O load command pointers of kext_load_info to point to the newly mapped
	// Mach-O's load commands, allowing us to update them. This does not apply to the nlist,
	// extrel, or locrel fields, which may not actually be mapped by a segment.
	uintptr_t mach_o_slide = (uintptr_t) info->kext - (uintptr_t) info->header;
	info->symtab = (void *) ((uintptr_t) info->symtab + mach_o_slide);
	info->dysymtab = (void *) ((uintptr_t) info->dysymtab + mach_o_slide);
	// Update virtual addresses in the load commands, in particular, LC_SEGMENT_64, to the
	// corresponding kernelcache static addresses.
	mh = info->kext;
	lc = (void *) (mh + 1);
	for (uint32_t cmd_idx = 0; cmd_idx < mh->ncmds; cmd_idx++) {
		if (lc->cmd == LC_SEGMENT_64) {
			struct segment_command_64 *sc = (void *) lc;
			sc->vmaddr = sc->vmaddr - info->vm_base + sa_for_ptr(info->kext);
			// TODO: Update sections. This is not strictly needed by XNU.
		}
		lc = (void *) ((uintptr_t) lc + lc->cmdsize);
	}
	// Set the kmod_info address and size fields, which aren't initialized by KMOD_DECL(). Once
	// again, the address needs to be a kernelcache static address.
	uintptr_t vmoff = (uintptr_t) info->kmod_info - info->vm_base;
	info->kmod_info = (void *) ((uintptr_t) info->kext + vmoff);
	info->kmod_info->address = sa_for_ptr(info->kext);
	info->kmod_info->size = info->vm_size;
}

// Apply local relocations relative to the kernel extension's true load address (i.e., including
// the kernel slide!) to ensure that pointers are adjusted for the kernel extension's new base
// address.
//
// Because we're relying on the OSKext loading infrastructure, we will need to set symtab->nsyms ==
// 0 and dysymtab->nlocrel == 0 for OSKext::slidePrelinkedExecutable().
static void
kext_relocate(struct kext_load_info *info) {
	uint64_t kext_va = va_for_ptr(info->kext);
	uintptr_t kext_va_slide = kext_va - info->vm_base;
	// Process LC_DYSYMTAB local relocations.
	for (uint32_t lr_idx = 0; lr_idx < info->dysymtab->nlocrel; lr_idx++) {
		const struct relocation_info *lr = &info->locrel[lr_idx];
		// Skip extern and non-8-byte relocations (though none should exist).
		if (lr->r_extern || lr->r_length != 3) {
			continue;
		}
		// Find the offset of the relocation pointer in the virtually mapped Mach-O and
		// slide it to the new base address. r_address is the offset from the first
		// segment's vmaddr to the vmaddr of the pointer.
		uint64_t vmoff = (uint64_t) lr->r_address - info->vm_base;
		uint64_t *reloc_ptr = (void *) ((uintptr_t) info->kext + vmoff);
		*reloc_ptr += kext_va_slide;
	}
	// Set dysymtab->nlocrel to 0 in order to prevent OSKext::slidePrelinkedExecutable() from
	// applying relocations a second time.
	info->dysymtab->nlocrel = 0;
	// Also set symtab->nsyms to 0 to prevent OSKext::slidePrelinkedExecutable() from calling
	// ml_static_slide() on each symbol address. (This is not strictly related to relocation.)
	info->symtab->nsyms = 0;
}

// Resolve symbol references from the kernel extension to the kernelcache using the preloaded
// symbol tables.
//
// Because we're relying on the OSKext loading infrastructure, we will need to set
// dysymtab->nextrel == 0 for OSKext::slidePrelinkedExecutable().
static void
kext_link(struct kext_load_info *info) {
	// Use the original unmapped kext for the string table, since it may not have been mapped
	// in a segment.
	uintptr_t strtab = (uintptr_t) info->header + info->symtab->stroff;
	// Process LC_DYSYMTAB external relocations.
	for (uint32_t er_idx = 0; er_idx < info->dysymtab->nextrel; er_idx++) {
		const struct relocation_info *er = &info->extrel[er_idx];
		// Skip non-extern and non-8-byte relocations (though none should exist).
		if (!er->r_extern || er->r_length != 3) {
			continue;
		}
		// Get the name of the symbol.
		const struct nlist_64 *nl = &info->nlist[er->r_symbolnum];
		const char *name = (void *) (strtab + nl->n_un.n_strx);
		// Resolve the symbol to the kernelcache address.
		uint64_t symbol_sa = kernelcache_symbol_table_lookup(name);
		if (symbol_sa == 0) {
			continue;
		}
		// Find the address of the external relocation pointer in the virtually mapped
		// kernel extension and replace it with the resolved dynamic address of the symbol.
		// r_address is the offset from the first segment's vmaddr to the vmaddr of the
		// pointer.
		uint64_t vmoff = (uint64_t) er->r_address - info->vm_base;
		uint64_t *link_ptr = (void *) ((uintptr_t) info->kext + vmoff);
		*link_ptr = va_for_sa(symbol_sa);

	}
	// Set dysymtab->nextrel to 0 in order to prevent OSKext::slidePrelinkedExecutable() from
	// failing.
	info->dysymtab->nextrel = 0;
}

// A __PRELINK_INFO.__info OSUnserializeXML dictionary describing the kernel extension.
static const char *prelink_info_str = "\
<dict>\
<key>CFBundleName</key>\
<string>KTRW_NNN0</string>\
<key>CFBundleIdentifier</key>\
<string>com.apple.kec.KTRW_NNN1</string>\
<key>CFBundleInfoDictionaryVersion</key>\
<string>6.0</string>\
<key>OSBundleCompatibleVersion</key>\
<string>1.0.0d1</string>\
<key>CFBundleVersion</key>\
<string>1.0.0</string>\
<key>CFBundleExecutable</key>\
<string>KTRW_HAX</string>\
<key>CFBundleSignature</key>\
<string>\?\?\?\?</string>\
<key>CFBundlePackageType</key>\
<string>KEXT</string>\
<key>CFBundleDevelopmentRegion</key>\
<string>English</string>\
<key>CFBundleShortVersionString</key>\
<string>1.0.0</string>\
<key>CFBundleSupportedPlatforms</key>\
<array>\
<string>iPhoneOS</string>\
</array>\
<key>AppleKernelExternalComponent</key>\
<true/>\
<key>_PrelinkExecutableRelativePath</key>\
<string>KTRW_HAX</string>\
<key>_PrelinkExecutableLoadAddr</key>\
<integer size=\"64\">0xADDRESS_________</integer>\
<key>_PrelinkExecutableSize</key>\
<integer size=\"64\">0xSIZE____________</integer>\
<key>_PrelinkKmodInfo</key>\
<integer size=\"64\">0xKMODINFO________</integer>\
<key>UIRequiredDeviceCapabilities</key>\
<array>\
<string>arm64</string>\
</array>\
<key>MinimumOSVersion</key>\
<string>13.3</string>\
<key>IOKitPersonalities</key>\
<dict>\
</dict>\
<key>OSBundleLibraries</key>\
<dict>\
<key>com.apple.kpi.bsd</key>\
<string>8.0.0b1</string>\
<key>com.apple.kpi.libkern</key>\
<string>8.0.0b2</string>\
<key>com.apple.kpi.mach</key>\
<string>8.0.0b2</string>\
<key>com.apple.kpi.iokit</key>\
<string>8.0.0b2</string>\
<key>com.apple.kpi.unsupported</key>\
<string>8.0</string>\
</dict>\
<key>UIDeviceFamily</key>\
<array>\
<integer IDREF=\"2\"/>\
</array>\
</dict>";

// The ID of the next kext to load, used to ensure __PRELINK_INFO dictionaries have unique keys.
static unsigned kext_id = 0;

// A table for converting a hexadecimal digit 0x0-0xf into its character representation.
static const char hex_char[16] = "0123456789abcdef";

// Format a 64-bit value as an n-character hexadecimal numeric string. This is used by
// kext_insert() to write values into the __PRELINK_INFO.__info dictionary.
static void
format_hex(char *buf, size_t n, uint64_t value) {
	for (size_t i = 0; i < n; i++) {
		buf[n - (i + 1)] = hex_char[value & 0xf];
		value >>= 4;
	}
}

// Insert the kernel extension into the kernelcache's __PRELINK_INFO.__info section to ensure that
// it has the proper VM protections set on it and has its initialization routines called during
// boot.
//
// Note that the current implementation makes several strong assumptions:
//
//     1. This is a new-style kernelcache, not an old-style kernelcache. Thus the only top-level
//        key in the __PRELINK_INFO.__info dictionary is the _PrelinkInfoDictionary key.
//     2. There is enough space at the end of the __PRELINK_INFO.__info section to insert the
//        prelink info for this kernel extension.
//     3. Only one kext is being inserted into the kernelcache, which allows us to hardcode the
//        bundle ID.
static void
kext_insert(struct kext_load_info *info) {
	// Get the kernelcache's __PRELINK_INFO.__info section.
	struct segment_command_64 *prelink_info_segment
		= macho_get_segment(mh_execute_header, "__PRELINK_INFO");
	struct section_64 *prelink_info_section
		= macho_get_section(prelink_info_segment, "__info");
	// Insert the plist before the "</array></dict>" at the end.
	char *p = ptr_for_va(prelink_info_section->addr);
	char *begin = p;
	p += prelink_info_section->size;
	while (p[-1] == 0) {
		p--;
	}
	while (strcmp(p, "</array></dict>") != 0) {
		if (p <= begin) {
			puts("Could not insert kernel extension into __PRELINK_INFO.__info");
			return;
		}
		p--;
	}
	strcpy(p, prelink_info_str);
	size_t info_size = strlen(prelink_info_str);
	// Re-insert the "</array></dict>" at the end.
	char *end = p + info_size;
	strcpy(end, "</array></dict>");
	// Patch up the info dict fields. _PrelinkKmodInfo must be unslid.
	char *nnn0 = memmem(p, info_size, "NNN0", 4);
	char *nnn1 = memmem(p, info_size, "NNN1", 4);
	char *address = memmem(p, info_size, "ADDRESS", 7);
	char *size = memmem(p, info_size, "SIZE", 4);
	char *kmodinfo = memmem(p, info_size, "KMODINFO", 8);
	format_hex(address, 16, sa_for_ptr(info->kext));
	format_hex(size, 16, info->vm_size);
	format_hex(kmodinfo, 16, sa_for_ptr(info->kmod_info));
	format_hex(nnn0, 4, kext_id);
	format_hex(nnn1, 4, kext_id);
	// Adjust the __PRELINK_INFO metadata.
	prelink_info_section->size += info_size;
	// Increment the kext ID for the next kext.
	kext_id++;
}

// Handles the "kextload" command, which is used to process the bulk uploaded data as an XNU kernel
// extension.
static void
command_kextload(const char *cmd, char *args) {
	// Grab the kext data.
	size_t kext_size = loader_xfer_recv_count;
	loader_xfer_recv_count = 0;
	if (kext_size < 0x4000) {
		puts("Kext is too small");
		return;
	}
	void *kext_header = (void *) loader_xfer_recv_data;
	// Validate and parse the kext in preparation for loading. Note that because the contents
	// are not copied out of the USB buffer, they may be concurrently overwritten with another
	// USB upload, leading to memory corruption.
	struct kext_load_info load_info = {};
	bool ok = kext_parse(kext_header, kext_size, &load_info);
	if (!ok) {
		return;
	}
	// Allocate memory for the kernel extension. No failures are permitted after this point.
	ok = kext_alloc(&load_info);
	if (!ok) {
		return;
	}
	// Copy the kernel extension segments.
	kext_map(&load_info);
	// Apply relocations at the load address.
	kext_relocate(&load_info);
	// Link the kernel extension against the kernelcache.
	kext_link(&load_info);
	// Insert the kernel extension into the kernelcache so that it will be run during boot.
	kext_insert(&load_info);
}

// ---- Kernel patching ---------------------------------------------------------------------------

// The next pre-boot hook in the chain.
static void (*next_preboot_hook)(void);

// Extract bits from an integer.
static inline uintmax_t
bits(uintmax_t x, unsigned sign, unsigned hi, unsigned lo, unsigned shift) {
	const unsigned bits = sizeof(uintmax_t) * 8;
	unsigned d = bits - (hi - lo + 1);
	if (sign) {
		return (uintmax_t) (((((intmax_t)  x) >> lo) << d) >> (d - shift));
	} else {
		return (((((uintmax_t) x) >> lo) << d) >> (d - shift));
	}
}

// Test whether the instruction matches the specified pattern.
static bool
MATCH(uint32_t insn, uint32_t match, uint32_t mask) {
	return ((insn & mask) == match);
}

// Resolve an ADRP/ADD instruction sequence to the pointer to the target value.
static void *
RESOLVE_ADRP_ADD(uint32_t *insn) {
	uint32_t adrp = insn[0];
	uint32_t add  = insn[1];
	// All registers must match. Also disallow SP.
	unsigned reg0 = (unsigned) bits(adrp, 0, 4, 0, 0);
	unsigned reg1 = (unsigned) bits(add,  0, 4, 0, 0);
	unsigned reg2 = (unsigned) bits(add,  0, 9, 5, 0);
	if (reg0 != reg1 || reg1 != reg2 || reg0 == 0x1f) {
		return NULL;
	}
	// Compute the target address.
	uint64_t pc = va_for_ptr(&insn[0]);
	uint64_t imm0 = bits(adrp, 1, 23, 5, 12+2) | bits(adrp, 0, 30, 29, 12);
	uint64_t imm1 = bits(add, 0, 21, 10, 0);
	uint64_t target = (pc & ~0xFFFuLL) + imm0 + imm1;
	return ptr_for_va(target);
}

// Called to patch the KTRR MMU lockdown instruction sequence.
static bool
ktrr_mmu_patch(xnu_pf_patch_t *patch, void *cacheable_stream) {
	uint32_t *insn = cacheable_stream;
	puts("Disabling KTRR MMU lockdown");
	insn[0] = 0xD503201F;	// NOP
	insn[2] = 0xD503201F;	// NOP
	insn[4] = 0xD503201F;	// NOP
	return true;
}

// Called to patch the KTRR AMCC lockdown instruction sequence.
static bool
ktrr_amcc_patch(xnu_pf_patch_t *patch, void *cacheable_stream) {
	uint32_t *insn = cacheable_stream;
	puts("Disabling KTRR AMCC lockdown");
	insn[0] = 0xD503201F;	// NOP
	insn[2] = 0xD503201F;	// NOP
	insn[3] = 0xD503201F;	// NOP
	insn[4] = 0xD503201F;	// NOP
	return true;
}

// Called to patch the OSKext::initWithPrelinkedInfoDict() function.
static bool
OSKext_init_patch(xnu_pf_patch_t *patch, void *cacheable_stream) {
	const int MAX_SEARCH = 30;
	uint32_t *insn = cacheable_stream;
	// First we need to resolve the ADRP/ADD target at [2].
	void *target = RESOLVE_ADRP_ADD(&insn[2]);
	if (target == NULL) {
		return false;
	}
	// Check if the target is "_PrelinkBundlePath", which indicates that this function is
	// OSKext::initWithPrelinkedInfoDict(). Bailing here is the most common path.
	if (strcmp(target, "_PrelinkBundlePath") != 0) {
		return false;
	}
	puts("Patching OSKext::initWithPrelinkedInfoDict()");
	// Search backwards until we get the prologue. Record the instruction that MOVs from X2.
	uint32_t *x2_insn = NULL;
	for (int i = 0;; i--) {
		if (i < -MAX_SEARCH) {
			return false;
		}
		// Check for either of the following instructions, signaling we hit the prologue:
		// 	SUB  SP, SP, #0xNNN		;; 0xNNN < 0x400
		// 	STP  X28, X27, [SP,#0xNNN]	;; 0xNNN < 0x100
		bool prologue = MATCH(insn[i], 0xD10003FF, 0xFFF01FFF)
			|| MATCH(insn[i], 0xA9006FFC, 0xFFC0FFFF);
		if (prologue) {
			break;
		}
		// Check for the instruction that saves argument X2, doCoalesedSlides:
		// 	MOV  Xn, X2
		bool mov_xn_x2 = MATCH(insn[i], 0xAA0203E0, 0xFFFFFFE0);
		if (mov_xn_x2) {
			x2_insn = &insn[i];
		}
	}
	// Check that we found the target instruction.
	if (x2_insn == NULL) {
		return false;
	}
	// Patch the instruction to zero out doCoalesedSlides:
	// 	MOV  Xn, XZR
	*x2_insn |= 0x001F0000;
	// We no longer need to match this. Disabling the patch speeds up execution time, since the
	// pattern is pretty frequent.
	xnu_pf_disable_patch(patch);
	return true;
}

// Apply the kernel patches needed for running loaded kernel extensions.
//
//     1. Disable KTRR on the MMU and AMCC to ensure our kernel extension can run outside the KTRR
//        RoRgn.
//     2. Force OSKext::initWithPrelinkedInfoDict() to set doCoalesedSlides to false so that
//        OSKext::setVMAttributes() is called. (Technically this is only needed on
//        _PrelinkKASLROffsets kernelcaches, but it is safe to apply always.)
static void
kextload_patch() {
	xnu_pf_patchset_t *patchset = xnu_pf_patchset_create(XNU_PF_ACCESS_32BIT);

	// Patch out KTRR MMU lockdown.
	const uint32_t ktrr_mmu_count = 5;
	uint64_t ktrr_mmu_match[ktrr_mmu_count] = {
		0xD51CF260,	// [0]  MSR  s3_4_c15_c2_3, Xn
		0x00000000,	// [1]  ?
		0xD51CF280,	// [2]  MSR  s3_4_c15_c2_4, Xn
		0x00000000,	// [3]  ?
		0xD51CF240,	// [4]  MSR  s3_4_c15_c2_2, Xn
	};
	uint64_t ktrr_mmu_mask[ktrr_mmu_count] = {
		0xFFFFFFE0,	// [0]  MSR
		0x00000000,	// [1]  ?
		0xFFFFFFE0,	// [2]  MSR
		0x00000000,	// [3]  ?
		0xFFFFFFE0,	// [4]  MSR
	};
	xnu_pf_maskmatch(patchset, ktrr_mmu_match, ktrr_mmu_mask, ktrr_mmu_count,
			true, ktrr_mmu_patch);

	// Patch out KTRR AMCC lockdown.
	const uint32_t ktrr_amcc_count = 5;
	uint64_t ktrr_amcc_match[ktrr_amcc_count] = {
		0xB907EC00,	// [0]  STR  Wn, [Xn,#0x7EC]
		0xD5033FDF,	// [1]  ISB
		0xD51CF260,	// [2]  MSR  s3_4_c15_c2_3, Xn
		0xD51CF280,	// [3]  MSR  s3_4_c15_c2_4, Xn
		0xD51CF240,	// [4]  MSR  s3_4_c15_c2_2, Xn
	};
	uint64_t ktrr_amcc_mask[ktrr_amcc_count] = {
		0xFFFFFC00,	// [0]  STR
		0xFFFFFFFF,	// [1]  ISB
		0xFFFFFFE0,	// [2]  MSR
		0xFFFFFFE0,	// [3]  MSR
		0xFFFFFFE0,	// [4]  MSR
	};
	xnu_pf_maskmatch(patchset, ktrr_amcc_match, ktrr_amcc_mask, ktrr_amcc_count,
			true, ktrr_amcc_patch);

	// Patch the prologue of OSKext::initWithPrelinkedInfoDict() to set doCoalesedSlides to
	// false. This enables the call to OSKext::setVMAttributes() later in the function on
	// _PrelinkKASLROffsets kernelcaches, which is required to ensure that the kernel extension
	// gets mapped with proper permissions.
	const uint32_t OSKext_init_count = 6;
	uint64_t OSKext_init_match[OSKext_init_count] = {
		0xF9400000,	// [0]  LDR  Xn, [Xn]
		0xF9400000,	// [1]  LDR  Xn, [Xn,#0xNNN]		;; 0xNNN < 0x200
		0x90000001,	// [2]  ADRP X1, #0xNNN
		0x91000021,	// [3]  ADD  X1, X1, #0xNNN		;; 0xNNN < 2^(12)
		0xAA0003E0,	// [4]  MOV  X0, Xn
		0xD63F0000,	// [5]  BLR  Xn
	};
	uint64_t OSKext_init_mask[OSKext_init_count] = {
		0xFFFFFC00,	// [0]  LDR
		0xFFFF0000,	// [1]  LDR
		0x9F00001F,	// [2]  ADRP
		0xFFC003FF,	// [3]  ADD
		0xFFE0FFFF,	// [4]  MOV
		0xFFFFFC1F,	// [5]  BLR
	};
	xnu_pf_maskmatch(patchset, OSKext_init_match, OSKext_init_mask, OSKext_init_count,
			true, OSKext_init_patch);

	// Run the patchset to patch the kernel.
	xnu_pf_emit(patchset);
	xnu_pf_range_t *text_exec = xnu_pf_segment(xnu_header(), "__TEXT_EXEC");
	xnu_pf_apply(text_exec, patchset);
	xnu_pf_patchset_destroy(patchset);
}

// The pre-boot hook for loading kernel extensions.
static void
kextload_preboot_hook() {
	puts("KTRW pongoOS kextload pre-boot hook");
#if DISABLE_CHECKRA1N_KERNEL_PATCHES
	puts("Skipping checkra1n pre-boot hook");
	ramdisk_size = 0;
#else // DISABLE_CHECKRA1N_KERNEL_PATCHES
	if (next_preboot_hook != NULL) {
		next_preboot_hook();
	}
#endif // DISABLE_CHECKRA1N_KERNEL_PATCHES
	kextload_patch();
}

// ---- Pongo module ------------------------------------------------------------------------------

void
module_entry() {
	puts("KTRW pongoOS kextload module");
	next_preboot_hook = preboot_hook;
	preboot_hook = kextload_preboot_hook;
	mh_execute_header = xnu_header();
	kernel_slide = xnu_slide_value(mh_execute_header);
	command_register("kextload",
			"Load an XNU kernel extension at boot time",
			command_kextload);
	command_register("kernelcache-symbols",
			"Load a symbol table for linking kernel extensions "
			"against the kernelcache",
			command_kernelcache_symbols);
}

const char *module_name = "kextload";

struct pongo_exports exported_symbols[] = {
	{ }
};
