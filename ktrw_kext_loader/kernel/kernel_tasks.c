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

#define KERNEL_TASKS_EXTERN
#include "kernel_tasks.h"

#include <assert.h>
#include <unistd.h>

#include "kernel_memory.h"
#include "kernel_parameters.h"
#include "kernel_slide.h"
#include "log.h"

// ---- Kernel task functions ---------------------------------------------------------------------

bool
kernel_ipc_port_lookup(uint64_t task, mach_port_name_t port_name,
		uint64_t *ipc_port, uint64_t *ipc_entry) {
	// Get the task's ipc_space.
	uint64_t itk_space = kernel_read64(task + OFFSET(task, itk_space));
	// Get the size of the table.
	uint32_t is_table_size = kernel_read32(itk_space + OFFSET(ipc_space, is_table_size));
	// Get the index of the port and check that it is in-bounds.
	uint32_t port_index = MACH_PORT_INDEX(port_name);
	if (port_index >= is_table_size) {
		return false;
	}
	// Get the space's is_table and compute the address of this port's entry.
	uint64_t is_table = kernel_read64(itk_space + OFFSET(ipc_space, is_table));
	uint64_t entry = is_table + port_index * SIZE(ipc_entry);
	if (ipc_entry != NULL) {
		*ipc_entry = entry;
	}
	// Get the address of the port if requested.
	if (ipc_port != NULL) {
		*ipc_port = kernel_read64(entry + OFFSET(ipc_entry, ie_object));
	}
	return true;
}

// ---- Initialization ----------------------------------------------------------------------------

// Try to initialize kernel_task and current_task by walking the allproc list.
static bool
find_kernel_task_and_current_task() {
	if (STATIC_ADDRESS(allproc) == 0) {
		ERROR("Need allproc address to initialize tasks");
		return false;
	}
	uint64_t allproc = kernel_read64(STATIC_ADDRESS(allproc) + kernel_slide);
	uint64_t kernproc = 0;
	uint64_t current_proc = 0;
	int current_pid = getpid();
	uint64_t proc = allproc;
	for (;;) {
		if (proc == 0 || proc == -1) {
			break;
		}
		uint32_t pid = kernel_read32(proc + OFFSET(proc, p_pid));
		if (pid == 0) {
			kernproc = proc;
		} else if (pid == current_pid) {
			current_proc = proc;
		}
		proc = kernel_read64(proc + OFFSET(proc, p_list_next));
		if (proc == allproc) {
			break;
		}
	}
	if (kernproc != 0) {
		kernel_task = kernel_read64(kernproc + OFFSET(proc, task));
	}
	if (current_proc != 0) {
		current_task = kernel_read64(current_proc + OFFSET(proc, task));
	}
	return (kernel_task != 0 && current_task != 0);
}

bool
kernel_tasks_init() {
	static bool initialized = false;
	if (initialized) {
		return true;
	}
	bool ok = kernel_parameters_init();
	if (!ok) {
		return false;
	}
	ok = find_kernel_task_and_current_task();
	if (!ok) {
		return false;
	}
	initialized = true;
	return true;
}
