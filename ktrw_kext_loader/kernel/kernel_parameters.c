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

#define KERNEL_PARAMETERS_EXTERN PARAMETER_SHARED
#include "kernel_parameters.h"

#include "kernel_slide.h"
#include "log.h"
#include "platform_match.h"

// ---- Offset initialization ---------------------------------------------------------------------

static void
offsets__iphone10_1__16C101() {
	kernel_slide_step                       = 0x4000;
	SIZE(ipc_entry)                         = 0x18;
	OFFSET(ipc_entry, ie_object)            = 0;
	OFFSET(ipc_space, is_table_size)        = 0x14;
	OFFSET(ipc_space, is_table)             = 0x20;
	OFFSET(proc, p_list_next)               = 0;
	OFFSET(proc, task)                      = 0x10;
	OFFSET(proc, p_pid)                     = 0x60;
	OFFSET(task, itk_space)                 = 0x300;
	OFFSET(task, bsd_info)                  = 0x358;
	STATIC_ADDRESS(kernel_base)             = 0xFFFFFFF007004000;
}

static struct platform_initialization offsets[] = {
	{ "iPhone10,1", "16C101", offsets__iphone10_1__16C101 },
	{ "iPhone10,6", "16E227", offsets__iphone10_1__16C101 },
	{ "iPhone10,1", "16G77",  offsets__iphone10_1__16C101 },
};

// ---- Address initialization --------------------------------------------------------------------

static void
addresses__iphone10_1__16C101() {
	STATIC_ADDRESS(allproc) = 0xFFFFFFF0076D2B28;
}

static void
addresses__iphone10_6__16E227() {
	STATIC_ADDRESS(allproc) = 0xFFFFFFF0076CF918;
}

static void
addresses__iphone10_1__16G77() {
	STATIC_ADDRESS(allproc) = 0xFFFFFFF0076CF958;
}

static struct platform_initialization addresses[] = {
	{ "iPhone10,1", "16C101", addresses__iphone10_1__16C101 },
	{ "iPhone10,6", "16E227", addresses__iphone10_6__16E227 },
	{ "iPhone10,1", "16G77",  addresses__iphone10_1__16G77  },
};

// ---- Public API --------------------------------------------------------------------------------

#define ARRAY_COUNT(x)	(sizeof(x) / sizeof((x)[0]))

bool
kernel_parameters_init() {
	// Only run once.
	static bool initialized = false;
	if (initialized) {
		return true;
	}
	// Get general platform info.
	platform_init();
	// Initialize offsets.
	size_t count = run_platform_initializations(offsets, ARRAY_COUNT(offsets));
	if (count < 1) {
		ERROR("No kernel %s for %s %s", "offsets", platform.machine, platform.osversion);
		return false;
	}
	// Initialize addresses.
	count = run_platform_initializations(addresses, ARRAY_COUNT(addresses));
	if (count < 1) {
		ERROR("No kernel %s for %s %s", "addresses", platform.machine, platform.osversion);
		return false;
	}
	initialized = true;
	return true;
}
