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

#include "debug.h"

#include "page_table.h"

// ---- Mapping the debug registers ---------------------------------------------------------------

// 0x208010000, 0x208110000, 0x208210000, 0x208310000, 0x208410000, 0x208510000
uint64_t cpu_register_base[MAX_CPU_COUNT];

uint64_t external_debug_registers[MAX_CPU_COUNT];
uint64_t dbgwrap_registers[MAX_CPU_COUNT];

void
map_debug_registers() {
	for (uint32_t cpu_id = 0; cpu_id < MAX_CPU_COUNT; cpu_id++) {
		if (external_debug_registers[cpu_id] != 0 || cpu_register_base[cpu_id] == 0) {
			continue;
		}
		external_debug_registers[cpu_id] = (uint64_t)
			ttbr0_map_io(cpu_register_base[cpu_id] + 0x00000, 0x1000);
		dbgwrap_registers[cpu_id] = (uint64_t)
			ttbr0_map_io(cpu_register_base[cpu_id] + 0x30000, 0x1000);
	}
}
