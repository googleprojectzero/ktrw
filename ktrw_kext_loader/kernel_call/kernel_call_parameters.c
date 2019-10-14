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

#define KERNEL_CALL_PARAMETERS_EXTERN  PARAMETER_SHARED
#include "kernel_call_parameters.h"

#include "kernel_slide.h"
#include "log.h"
#include "platform_match.h"

// ---- Offset initialization ---------------------------------------------------------------------

static void
offsets__iphone10_1__16C101() {
	OFFSET(ipc_port, ip_kobject)                             = 104;
	OFFSET(proc, p_ucred)                                    = 0xf8;
	OFFSET(task, bsd_info)                                   = 0x358;
	SIZE(IOExternalTrap)                                     = 24;
	OFFSET(IOExternalTrap, object)                           = 0;
	OFFSET(IOExternalTrap, function)                         = 8;
	OFFSET(IOExternalTrap, offset)                           = 16;
	OFFSET(IORegistryEntry, reserved)                        = 16;
	OFFSET(IORegistryEntry__ExpansionData, fRegistryEntryID) = 8;
	VTABLE_INDEX(IOUserClient, getExternalTrapForIndex)      = 0x5b8 / 8;
	VTABLE_INDEX(IOUserClient, getTargetAndTrapForIndex)     = 0x5c0 / 8;
}

static struct platform_initialization offsets[] = {
	{ "iPhone10,1", "16C101", offsets__iphone10_1__16C101 },
	{ "iPhone10,6", "16E227", offsets__iphone10_1__16C101 },
	{ "iPhone10,1", "16G77",  offsets__iphone10_1__16C101 },
};

// ---- Address initialization --------------------------------------------------------------------

#define SLIDE(address)		(address == 0 ? 0 : address + kernel_slide)

static void
addresses__iphone10_1__16C101() {
	ADDRESS(mov_x0_x4__br_x5)                    = SLIDE(0xFFFFFFF006580164);
	ADDRESS(IOUserClient__vtable)                = SLIDE(0xFFFFFFF0070CC648);
	ADDRESS(IORegistryEntry__getRegistryEntryID) = SLIDE(0xFFFFFFF00759424C);
}

static void
addresses__iphone10_6__16E227() {
	ADDRESS(mov_x0_x4__br_x5)                    = SLIDE(0xFFFFFFF00659E068);
	ADDRESS(IOUserClient__vtable)                = SLIDE(0xFFFFFFF0070CC818);
	ADDRESS(IORegistryEntry__getRegistryEntryID) = SLIDE(0xFFFFFFF0075931F4);
}

static void
addresses__iphone10_1__16G77() {
	ADDRESS(mov_x0_x4__br_x5)                    = SLIDE(0xFFFFFFF00658D30C);
	ADDRESS(IOUserClient__vtable)                = SLIDE(0xFFFFFFF0070CC780);
	ADDRESS(IORegistryEntry__getRegistryEntryID) = SLIDE(0xFFFFFFF007594320);
}

static struct platform_initialization addresses[] = {
	{ "iPhone10,1", "16C101", addresses__iphone10_1__16C101 },
	{ "iPhone10,6", "16E227", addresses__iphone10_6__16E227 },
	{ "iPhone10,1", "16G77",  addresses__iphone10_1__16G77  },
};

// ---- Public API --------------------------------------------------------------------------------

#define ARRAY_COUNT(x)	(sizeof(x) / sizeof((x)[0]))

bool
kernel_call_parameters_init() {
	bool ok = kernel_slide_init();
	if (!ok) {
		return false;
	}
	size_t count = run_platform_initializations(offsets, ARRAY_COUNT(offsets));
	if (count < 1) {
		ERROR("No kernel_call %s for %s %s", "offsets",
				platform.machine, platform.osversion);
		return false;
	}
	count = run_platform_initializations(addresses, ARRAY_COUNT(addresses));
	if (count < 1) {
		ERROR("No kernel_call %s for %s %s", "addresses",
				platform.machine, platform.osversion);
		return false;
	}
	return true;
}
