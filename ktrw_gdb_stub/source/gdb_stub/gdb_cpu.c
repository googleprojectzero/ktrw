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

#include "gdb_cpu.h"

#include "gdb_state.h"

// ---- Checking CPU state ------------------------------------------------------------------------

bool
valid_cpu_id(int cpu_id) {
	return (0 <= cpu_id && cpu_id < CPU_COUNT && ((1 << cpu_id) & gdb.cpu_mask));
}

bool
cpu_is_halted(int cpu_id) {
	// The cpu_id must be between 0 and CPU_COUNT - 1.
	uint32_t cpu_bit = 1 << cpu_id;
	return ((gdb.halted & cpu_bit) && (gdb.cpu_mask & cpu_bit));
}

bool
cpu_is_running(int cpu_id) {
	// The cpu_id must be between 0 and CPU_COUNT - 1.
	uint32_t cpu_bit = 1 << cpu_id;
	return (!(gdb.halted & cpu_bit) && (gdb.cpu_mask & cpu_bit));
}

// ---- Interrupting and resuming CPUs ------------------------------------------------------------

// Call this function just after resuming a CPU to update internal state.
static void
gdb_cpu_resumed(int cpu_id) {
	gdb.halted &= ~(1 << cpu_id);
	gdb.cpu_debug[cpu_id].halted_watchpoint = INVALID_ADDRESS;
	gdb.cpu_debug[cpu_id].state = CPU_STATE_RUNNING;
}

void
gdb_interrupt_cpu(int cpu_id) {
	if (cpu_is_running(cpu_id)) {
		gdb_stub_interrupt_cpu(cpu_id);
	}
}

void
gdb_resume_cpu(int cpu_id) {
	if (cpu_is_halted(cpu_id)) {
		gdb_stub_resume_cpu(cpu_id);
		gdb_cpu_resumed(cpu_id);
	}
}

void
gdb_interrupt() {
	for (int cpu_id = 0; cpu_id < CPU_COUNT; cpu_id++) {
		if (valid_cpu_id(cpu_id)) {
			gdb_interrupt_cpu(cpu_id); // Only if running.
		}
	}
}

void
gdb_resume() {
	for (int cpu_id = 0; cpu_id < CPU_COUNT; cpu_id++) {
		if (valid_cpu_id(cpu_id)) {
			gdb_resume_cpu(cpu_id); // Only if halted.
		}
	}
}

void
gdb_step_cpu(int cpu_id) {
	if (cpu_is_halted(cpu_id)) {
		gdb_stub_step_cpu(cpu_id);
		gdb_cpu_resumed(cpu_id);
	}
}
