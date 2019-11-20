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

#include "kernel_patches.h"

#include "kernel_memory.h"
#include "kernel_slide.h"
#include "log.h"
#include "platform_match.h"

// A structure to describe a patch consisting of a single instruction substitution.
struct instruction_substitution {
	uint64_t address;
	uint32_t instruction;
};

// A helper macro to get the number of elements in a static array.
#define ARRAY_COUNT(x)	(sizeof(x) / sizeof((x)[0]))

// ---- Kernel patches ----------------------------------------------------------------------------

// A helper to define a branch instruction. This only works for short ranges!
#define BRANCH(source, target)	(0x14000000 | (0x03FFFFFF & (uint32_t)(((int64_t)target - (int64_t)source) / 4)))

static void
task_for_pid_0__iPhone10_1__16C101() {
	INFO("Patching task_for_pid(0)");
	const struct instruction_substitution code_patches[] = {
		// task_for_pid():
		//   "if (pid == 0)" -> NOP
		{ 0xFFFFFFF007500F20, 0xD503201F },
		// task_for_pid():
		//   "task_for_pid_posix_check(p)" -> NOP
		{ 0xFFFFFFF007500F44, 0xD503201F },
		// task_for_pid():
		//   Skip the inlined code of mac_proc_check_get_task().
		//   ADRP X23, #mac_policy_list@PAGE -> B 0xFFFFFFF0075010F8
		{ 0xFFFFFFF007500F5C, BRANCH(0xFFFFFFF007500F5C, 0xFFFFFFF0075010F8) },
		// convert_port_to_locked_task():
		//   "if (caller == victim)" -> "if (caller == caller)"
		//   CMP X24, X23 -> CMP X24, X24
		{ 0xFFFFFFF007119530, 0xEB18031F },
		// convert_port_to_task_with_exec_token():
		//   "if (caller == victim)" -> "if (caller == caller)"
		//   CMP X8, X21 -> CMP X8, X8
		{ 0xFFFFFFF007119730, 0xEB08011F },
	};
	for (size_t i = 0; i < ARRAY_COUNT(code_patches); i++) {
		uint64_t address = code_patches[i].address + kernel_slide;
		kernel_write32(address, code_patches[i].instruction);
	}
}

static void
i_can_has_debugger__iPhone10_1__16C101() {
	INFO("Enabling PE_i_can_has_debugger()");
	uint64_t debug_enabled = 0xFFFFFFF00702D430 + kernel_slide;
	kernel_write32(debug_enabled, 1);
}

// A list of kernel patches to apply by platform.
static struct platform_initialization kernel_patches[] = {
	{ "iPhone10,1", "16C101", task_for_pid_0__iPhone10_1__16C101 },
	{ "iPhone10,1", "16C101", i_can_has_debugger__iPhone10_1__16C101 },
};

// ---- API ---------------------------------------------------------------------------------------

void
apply_kernel_patches() {
	run_platform_initializations(kernel_patches, ARRAY_COUNT(kernel_patches));
}
