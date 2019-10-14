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

#define PLATFORM_EXTERN
#include "platform.h"

#include <assert.h>
#include <mach/mach.h>
#include <sys/sysctl.h>
#include <sys/utsname.h>

#include "log.h"

// ---- Initialization ----------------------------------------------------------------------------

void
platform_init() {
	// Only initialize once.
	static bool initialized = false;
	if (initialized) {
		return;
	}
	initialized = true;
	// Set the page size.
	platform.page_size = vm_kernel_page_size;
	page_size = platform.page_size;
	// Get the machine name (e.g. iPhone11,8).
	struct utsname u = {};
	int error = uname(&u);
	assert(error == 0);
	strncpy((char *)platform.machine, u.machine, sizeof(platform.machine));
	// Get the build (e.g. 16C50).
	size_t osversion_size = sizeof(platform.osversion);
	error = sysctlbyname("kern.osversion",
			(void *)platform.osversion, &osversion_size, NULL, 0);
	assert(error == 0);
	// Get basic host info.
	mach_port_t host = mach_host_self();
	assert(MACH_PORT_VALID(host));
	host_basic_info_data_t basic_info;
	mach_msg_type_number_t count = HOST_BASIC_INFO_COUNT;
	kern_return_t kr = host_info(host, HOST_BASIC_INFO, (host_info_t) &basic_info, &count);
	assert(kr == KERN_SUCCESS);
	platform.cpu_type     = basic_info.cpu_type;
	platform.cpu_subtype  = basic_info.cpu_subtype;
	platform.physical_cpu = basic_info.physical_cpu;
	platform.logical_cpu  = basic_info.logical_cpu;
	platform.memory_size  = basic_info.max_mem;
	mach_port_deallocate(mach_task_self(), host);
	// Log basic platform info.
	INFO("Platform: %s %s", platform.machine, platform.osversion);
}
