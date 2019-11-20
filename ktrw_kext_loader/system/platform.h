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

#ifndef PLATFORM__H_
#define PLATFORM__H_

#include <stdbool.h>
#include <stddef.h>
#include <mach/machine.h>

#ifdef PLATFORM_EXTERN
#define extern PLATFORM_EXTERN
#endif

/*
 * platform
 *
 * Description:
 * 	Basic information about the platform.
 */
struct platform {
	// The name of the platform, e.g. iPhone11,8.
	const char machine[32];
	// The version of the OS build, e.g. 16C50.
	const char osversion[32];
	// The platform CPU type.
	cpu_type_t cpu_type;
	// The platform CPU subtype.
	cpu_subtype_t cpu_subtype;
	// The number of physical CPU cores.
	unsigned physical_cpu;
	// The number of logical CPU cores.
	unsigned logical_cpu;
	// The kernel page size.
	size_t page_size;
	// The size of physical memory on the device.
	size_t memory_size;
};
extern struct platform platform;

/*
 * page_size
 *
 * Description:
 * 	The kernel page size on this platform, made available globally for convenience.
 */
extern size_t page_size;

/*
 * platform_init
 *
 * Description:
 * 	Initialize the platform.
 */
void platform_init(void);

#undef extern

#endif
