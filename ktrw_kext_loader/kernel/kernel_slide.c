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

#define KERNEL_SLIDE_EXTERN
#include "kernel_slide.h"

#include <assert.h>
#include <mach-o/loader.h>

#include "kernel_memory.h"
#include "kernel_parameters.h"
#include "kernel_tasks.h"
#include "log.h"

// Check if the given address is the kernel base.
static bool
is_kernel_base(uint64_t base) {
	// Read the data at the base address as a Mach-O header.
	struct mach_header_64 header = {};
	bool ok = kernel_read(base, &header, sizeof(header));
	if (!ok) {
		return false;
	}
	// Validate that this looks like the kernel base. We don't check the CPU subtype since it
	// may not exactly match the current platform's CPU subtype (e.g. on iPhone10,1,
	// header.cpusubtype is CPU_SUBTYPE_ARM64_ALL while platform.cpu_subtype is
	// CPU_SUBTYPE_ARM64_V8).
	if (!(header.magic == MH_MAGIC_64
			&& header.cputype == platform.cpu_type
			&& header.filetype == MH_EXECUTE
			&& header.ncmds > 2)) {
		return false;
	}
	return true;
}

// Call this once the kernel slide has been set up.
static void
did_set_kernel_slide() {
	INFO("KASLR slide is 0x%llx", kernel_slide);
}

// Some jailbreaks stash information about the kernel base in task_info(TASK_DYLD_INFO). Check to
// see if this information is populated for the kernel_task_port.
static bool
check_task_dyld_info() {
	struct task_dyld_info info;
	mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
	kern_return_t kr = task_info(kernel_task_port,
			TASK_DYLD_INFO, (task_info_t) &info, &count);
	if (kr != KERN_SUCCESS) {
		return false;
	}
	uint64_t kernel_base = info.all_image_info_addr;
	if (is_kernel_base(kernel_base)) {
		kernel_slide = info.all_image_info_addr - STATIC_ADDRESS(kernel_base);
		goto found_kernel_slide;
	}
	kernel_base = STATIC_ADDRESS(kernel_base) + info.all_image_info_size;
	if (is_kernel_base(kernel_base)) {
		kernel_slide = info.all_image_info_size;
		goto found_kernel_slide;
	}
	return false;
found_kernel_slide:
	did_set_kernel_slide();
	return true;
}

// Try to initialize the kernel slide from an address inside the kernel image (and after the kernel
// Mach-O header).
static bool
init_with_kernel_image_address(uint64_t address) {
	// Find the highest possible kernel base address that could still correspond to the given
	// kernel image address.
	uint64_t base = STATIC_ADDRESS(kernel_base);
	assert(address > base);
	base = base + ((address - base) / kernel_slide_step) * kernel_slide_step;
	// Now walk backwards from that kernel base one kernel slide at a time until we find the
	// real kernel base.
	while (base >= STATIC_ADDRESS(kernel_base)) {
		bool found = is_kernel_base(base);
		if (found) {
			kernel_slide = base - STATIC_ADDRESS(kernel_base);
			did_set_kernel_slide();
			return true;
		}
		base -= kernel_slide_step;
	}
	return false;
}

// If we have current_task, then we can find the kernel slide easily by looking up the host port.
static bool
init_with_current_task() {
	// Get the address of the host port.
	mach_port_t host = mach_host_self();
	assert(MACH_PORT_VALID(host));
	uint64_t host_port;
	bool ok = kernel_ipc_port_lookup(current_task, host, &host_port, NULL);
	mach_port_deallocate(mach_task_self(), host);
	if (!ok) {
		return false;
	}
	// Get the address of realhost.
	uint64_t realhost = kernel_read64(host_port + OFFSET(ipc_port, ip_kobject));
	// Initialize with that address.
	return init_with_kernel_image_address(realhost);
}

bool
kernel_slide_init() {
	if (kernel_slide != 0) {
		return true;
	}
	// Initialize the parameters.
	bool ok = kernel_parameters_init();
	if (!ok) {
		return false;
	}
	// Check if the kernel base is stashed in task_info(TASK_DYLD_INFO).
	ok = check_task_dyld_info();
	if (ok) {
		return true;
	}
	// If we have current_task, then we can init with the address of the host port.
	if (current_task != 0) {
		ok = init_with_current_task();
		if (ok) {
			return true;
		}
	}
	// No available method.
	ERROR("Could not determine the kernel slide");
	return false;
}

bool
kernel_slide_init_with_kernel_image_address(uint64_t address) {
	if (kernel_slide != 0) {
		return true;
	}
	bool ok = kernel_parameters_init();
	if (!ok) {
		return false;
	}
	ok = init_with_kernel_image_address(address);
	if (ok) {
		return true;
	}
	ERROR("Could not determine the kernel slide");
	return false;
}
