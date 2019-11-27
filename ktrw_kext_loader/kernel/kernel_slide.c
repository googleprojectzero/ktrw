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
#include "mach_vm.h"

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

typedef uint64_t kern_addr_t;
static kern_addr_t _tasks = 0;
// Find the task via iterate the kernel_task.tasks
static kern_addr_t get_pid_task_via_iter_tasks_queue(uint32_t pid, kern_addr_t task) {
  kern_addr_t task_addr = task;
  if (!_tasks) {
    while (task_addr != 0) {
      kern_addr_t proc_addr = kernel_read64(task_addr + OFFSET(task, bsd_info));
      uint32_t pid_found    = kernel_read32(proc_addr + OFFSET(proc, p_pid));
      if (pid_found == 0) {
        // KERN_STRUCT_OFFSET(queue_entry, prev) == 8
        _tasks = kernel_read64(task_addr + OFFSET(task, tasks) + 8);
        break;
      }
      // KERN_STRUCT_OFFSET(queue_entry, prev) == 8
      task_addr = kernel_read64(task_addr + OFFSET(task, tasks) + 8);
    }
  }

  // KERN_STRUCT_OFFSET(queue_entry, next) == 0
  task_addr = kernel_read64(_tasks + 0);
  do {
    kern_addr_t proc_addr = kernel_read64(task_addr + OFFSET(task, bsd_info));
    uint32_t pid_found    = kernel_read32(proc_addr + OFFSET(proc, p_pid));
    if (pid_found == pid) {
      return task_addr;
    }
    
    // KERN_STRUCT_OFFSET(queue_entry, next) == 0
    task_addr = kernel_read64(task_addr + OFFSET(task, tasks) + 0);
  } while (task_addr != _tasks);
  return 0;
}

static kern_addr_t _kernproc;
static void handle_cpu_data_trick(kern_addr_t cpu_data_kern_addr) {
  kern_addr_t cpu_active_thread = kernel_read64(cpu_data_kern_addr + OFFSET(cpu_data, cpu_active_thread));
  assert(cpu_active_thread);
  kern_addr_t task_kern_addr = kernel_read64(cpu_active_thread + OFFSET(thread, task));
  assert(task_kern_addr);
  kern_addr_t _kernel_task = get_pid_task_via_iter_tasks_queue(0, task_kern_addr);
  assert(_kernel_task);
  // Kernproc = &proc0
  _kernproc = kernel_read64(_kernel_task + OFFSET(task, bsd_info));
  assert(_kernproc);
}

static kern_addr_t brute_force_kernel_base(kern_addr_t kern_data_segment_variable_kern_addr) {
  kern_addr_t addr = kern_data_segment_variable_kern_addr & ~0x3fff;
  uint32_t magic   = kernel_read32(addr);
  while (magic != MH_MAGIC_64) {
    addr -= 0x4000;
    magic = kernel_read32(addr);
  }
  return addr;
}

#define VM_KERN_MEMORY_CPU 9
// cpu_data_alloc() with VM_KERN_MEMORY_CPU tag, and we can use the cpu_data.cpu_active_thread
// to find the kernel_task, kernproc etc.
static bool init_with_cpu_data_region() {
  kern_addr_t cpu_data_kern_addr = 0;
  struct vm_region_submap_short_info_64 submap_info;
  mach_msg_type_number_t count = VM_REGION_SUBMAP_SHORT_INFO_COUNT_64;
  mach_vm_address_t addr       = 0;
  mach_vm_size_t size          = 0;
  natural_t depth              = 0;
  while (true) {
    kern_return_t kr =
        mach_vm_region_recurse(kernel_task_port, &addr, &size, &depth, (vm_region_recurse_info_t)&submap_info, &count);
    if (kr == KERN_INVALID_ADDRESS || kr != KERN_SUCCESS) {
      break;
    }
    /*if (0 && submap_info.is_submap) {
      ++depth;
    } else */{
      // Catch cpu_data_alloc
      if (submap_info.user_tag == VM_KERN_MEMORY_CPU) {
        unsigned short cpu_number = kernel_read32(addr);
        if (cpu_number == 0x1) {
          cpu_data_kern_addr = addr;
          break;
        }
      }
      addr += size;
    }
  }
  if (!cpu_data_kern_addr)
    return false;
  handle_cpu_data_trick(cpu_data_kern_addr);
  // Kernproc = &proc0
  kern_addr_t _kernbase = brute_force_kernel_base(_kernproc);
  kernel_slide          = _kernbase - STATIC_ADDRESS(kernel_base);
  did_set_kernel_slide();
  return true;
}

// Try to find the kernel base using an unsafe heap scan to sample kernel pointers. As suggested by
// the function name, this method is UNSAFE and may panic the device. It should only be used in the
// absence of better options!
static bool
init_with_unsafe_heap_scan() {
	WARNING("Could not find the kernel base address");
	WARNING("Trying to find the kernel base address using an unsafe heap scan!");
	uint64_t kernel_region_base = 0xfffffff000000000;
	uint64_t kernel_region_end  = 0xfffffffbffffc000;
	// Try and find a pointer in the kernel heap to data in the kernel image. We'll take the
	// smallest such pointer.
	uint64_t kernel_ptr = (uint64_t)(-1);
	mach_vm_address_t address = 0;
	for (;;) {
		// Get the next memory region.
		mach_vm_size_t size = 0;
		uint32_t depth = 2;
		struct vm_region_submap_info_64 info;
		mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
		kern_return_t kr = mach_vm_region_recurse(kernel_task_port, &address, &size,
				&depth, (vm_region_recurse_info_t) &info, &count);
		if (kr != KERN_SUCCESS) {
			break;
		}
		// Skip any region that is not on the heap, not in a submap, not readable and
		// writable, or not fully mapped.
		int prot = VM_PROT_READ | VM_PROT_WRITE;
		if (info.user_tag != 12
		    || depth != 1
		    || (info.protection & prot) != prot
		    || info.pages_resident * 0x4000 != size) {
			goto next;
		}
		// Read the first word of each page in this region.
		for (size_t offset = 0; offset < size; offset += 0x4000) {
			uint64_t value = 0;
			bool ok = kernel_read(address + offset, &value, sizeof(value));
			if (ok
			    && kernel_region_base <= value
			    && value < kernel_region_end
			    && value < kernel_ptr) {
				kernel_ptr = value;
			}
		}
next:
		address += size;
	}
	// If we didn't find any such pointer, abort.
	if (kernel_ptr == (uint64_t)(-1)) {
		return false;
	}
	DEBUG_TRACE(1, "Found kernel pointer %p", (void *)kernel_ptr);
	// Now that we have a pointer, we want to scan pages until we reach the kernel's Mach-O
	// header. Unfortunately, the layout of the kernel differs on different iOS versions. iOS
	// 12.4 uses the old kernelcache format; on these kernelcaches, kernel_ptr will usually
	// point into one of the __PRELINK sections that lies before the Mach-O header in __TEXT.
	// On the other hand, iOS 13 uses the newer kernelcache format in which the __PRELINK
	// sections are empty and __TEXT is mapped first, and hence kernel_ptr lies after the
	// Mach-O header. We'll program for the newer kernelcache format.
	uint64_t page = kernel_ptr & ~0x3fff;
	for (;;) {
		bool found = is_kernel_base(page);
		if (found) {
			kernel_slide = page - STATIC_ADDRESS(kernel_base);
			did_set_kernel_slide();
			return true;
		}
		page -= 0x4000;
	}
	return false;
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
	// Try to parse cpu_data
  ok = init_with_cpu_data_region();
  if(ok) {
    return true;
  }
	// Try an unsafe heap scan. This is a last resort!
	ok = init_with_unsafe_heap_scan();
	if (ok) {
		return true;
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
