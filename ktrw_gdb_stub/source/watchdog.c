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

#include "watchdog.h"

#include "page_table.h"

// ---- WatchDog Timer ----------------------------------------------------------------------------

uint64_t watchdog_timer_register_base = 0x2352b0000;

// The memory-mapped WatchDog Timer registers.
static uint64_t watchdog_registers;

// Map the WatchDog Timer registers.
static void
map_watchdog_registers() {
	if (watchdog_registers == 0) {
		watchdog_registers = (uint64_t) ttbr0_map_io(watchdog_timer_register_base, 0x1000);
	}
}

void
disable_watchdog_timer() {
	map_watchdog_registers();
	*(volatile uint32_t *)(watchdog_registers + 0x0c) = 0;
	*(volatile uint32_t *)(watchdog_registers + 0x1c) = 0;
}
