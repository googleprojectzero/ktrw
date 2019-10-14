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

#define KERNEL_MEMORY_EXTERN
#include "kernel_memory.h"

#include <assert.h>

#include "log.h"
#include "mach_vm.h"
#include "platform.h"

// ---- Kernel memory functions -------------------------------------------------------------------

uint64_t
kernel_vm_allocate(size_t size) {
	mach_vm_address_t address = 0;
	kern_return_t kr = mach_vm_allocate(kernel_task_port, &address, size, VM_FLAGS_ANYWHERE);
	if (kr != KERN_SUCCESS) {
		ERROR("%s returned %d: %s", "mach_vm_allocate", kr, mach_error_string(kr));
		address = -1;
	} else {
		// Fault in each page.
		for (size_t offset = 0; offset < size; offset += page_size) {
			kernel_read64(address + offset);
		}
	}
	return address;
}

void
kernel_vm_deallocate(uint64_t address, size_t size) {
	kern_return_t kr = mach_vm_deallocate(kernel_task_port, address, size);
	if (kr != KERN_SUCCESS) {
		WARNING("%s returned %d: %s", "mach_vm_deallocate", kr, mach_error_string(kr));
	}
}

bool
kernel_vm_protect(uint64_t address, size_t size, vm_prot_t prot) {
	kern_return_t kr = mach_vm_protect(kernel_task_port, address, size, FALSE, prot);
	if (kr != KERN_SUCCESS) {
		ERROR("%s returned %d: %s", "mach_vm_protect", kr, mach_error_string(kr));
		return false;
	}
	return true;
}

void *
kernel_vm_remap(uint64_t address, size_t size) {
	assert((address & (page_size - 1)) == 0);
	assert((size & (page_size - 1)) == 0);
	mach_vm_address_t target_address = 0;
	vm_prot_t cur_prot, max_prot;
	kern_return_t kr = mach_vm_remap(
			mach_task_self(),
			&target_address,
			size,
			0,
			VM_FLAGS_ANYWHERE,
			kernel_task_port,
			address,
			FALSE,
			&cur_prot,
			&max_prot,
			VM_INHERIT_NONE);
	if (kr != KERN_SUCCESS) {
		ERROR("%s returned %d: %s", "mach_vm_remap", kr, mach_error_string(kr));
		return NULL;
	}
	return (void *)target_address;
}

bool
kernel_read(uint64_t address, void *data, size_t size) {
	mach_vm_size_t size_out;
	kern_return_t kr = mach_vm_read_overwrite(kernel_task_port, address,
			size, (mach_vm_address_t) data, &size_out);
	if (kr != KERN_SUCCESS) {
		ERROR("%s returned %d: %s", "mach_vm_read_overwrite", kr, mach_error_string(kr));
		ERROR("could not %s address 0x%016llx", "read", address);
		return false;
	}
	if (size_out != size) {
		ERROR("partial read of address 0x%016llx: %llu of %zu bytes",
				address, size_out, size);
		return false;
	}
	return true;
}

bool
kernel_write(uint64_t address, const void *data, size_t size) {
	const uint8_t *write_data = data;
	while (size > 0) {
		size_t write_size = size;
		if (write_size > page_size) {
			write_size = page_size;
		}
		kern_return_t kr = mach_vm_write(kernel_task_port, address,
				(mach_vm_address_t) write_data, (mach_msg_size_t) write_size);
		if (kr != KERN_SUCCESS) {
			ERROR("%s returned %d: %s", "mach_vm_write", kr, mach_error_string(kr));
			ERROR("could not %s address 0x%016llx", "write", address);
			return false;
		}
		address += write_size;
		write_data += write_size;
		size -= write_size;
	}
	return true;
}

uint8_t
kernel_read8(uint64_t address) {
	uint8_t value;
	bool ok = kernel_read(address, &value, sizeof(value));
	if (!ok) {
		return -1;
	}
	return value;
}

uint16_t
kernel_read16(uint64_t address) {
	uint16_t value;
	bool ok = kernel_read(address, &value, sizeof(value));
	if (!ok) {
		return -1;
	}
	return value;
}

uint32_t
kernel_read32(uint64_t address) {
	uint32_t value;
	bool ok = kernel_read(address, &value, sizeof(value));
	if (!ok) {
		return -1;
	}
	return value;
}

uint64_t
kernel_read64(uint64_t address) {
	uint64_t value;
	bool ok = kernel_read(address, &value, sizeof(value));
	if (!ok) {
		return -1;
	}
	return value;
}

bool
kernel_write8(uint64_t address, uint8_t value) {
	return kernel_write(address, &value, sizeof(value));
}

bool
kernel_write16(uint64_t address, uint16_t value) {
	return kernel_write(address, &value, sizeof(value));
}

bool
kernel_write32(uint64_t address, uint32_t value) {
	return kernel_write(address, &value, sizeof(value));
}

bool
kernel_write64(uint64_t address, uint64_t value) {
	return kernel_write(address, &value, sizeof(value));
}
