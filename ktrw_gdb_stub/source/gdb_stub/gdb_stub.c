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

#include "gdb_stub.h"

#include <stdarg.h>

#include "gdb_internal.h"
#include "gdb_packets.h"
#include "gdb_rsp.h"
#include "gdb_state.h"

// Define the main GDB state.
struct gdb_stub_state gdb;

void
gdb_stub_init(uint32_t cpu_mask, uint32_t halted_mask) {
	halted_mask &= cpu_mask;
	gdb.cpu_mask    = cpu_mask;
	gdb.halted      = halted_mask;
	gdb.current_cpu = -1; // No current CPU.
	for (int cpu_id = 0; cpu_id < CPU_COUNT; cpu_id++) {
		gdb.cpu_debug[cpu_id].halted_watchpoint = INVALID_ADDRESS;
		int state = CPU_STATE_RUNNING;
		if (halted_mask & (1 << cpu_id)) {
			state = CPU_STATE_HALTED;
		}
		gdb.cpu_debug[cpu_id].state = state;
	}
	gdb.process_halted = 0;
	gdb.all_stop.stop_reply_deferred = false;
	gdb.all_stop.first_stop = INVALID_CPU;
	gdb.non_stop.enabled = false;
	gdb.non_stop.stopped = 0;
	gdb.non_stop.queue   = 0;
	gdb.non_stop.pending = 0;
	gdb.error_strings = false;
	gdb.list_threads_in_stop_reply = false;
	gdb.mach_header = NULL;
	gdb.hardware_watchpoint_count = 0;
}

void
gdb_stub_set_mach_header(const struct mach_header_64 *mach_header) {
	gdb.mach_header = mach_header;
}

void
gdb_stub_set_hardware_watchpoint_count(unsigned hardware_watchpoint_count) {
	gdb.hardware_watchpoint_count = hardware_watchpoint_count;
}

// Record that a halt has taken place.
static void
gdb_stub_record_halt(int cpu_id) {
	gdb.halted         |= (1 << cpu_id);
	gdb.process_halted |= (1 << cpu_id);
	// If we are in all-stop mode, and we have a deferred stop reply, and this is the first
	// stop we've observed, record it and switch to this CPU.
	if (!gdb.non_stop.enabled
			&& gdb.all_stop.stop_reply_deferred
			&& gdb.all_stop.first_stop == INVALID_CPU) {
		gdb.all_stop.first_stop = cpu_id;
		gdb.current_cpu = cpu_id;
	}
}

void
gdb_stub_hit_hardware_breakpoint(int cpu_id) {
	gdb_stub_record_halt(cpu_id);
	gdb.cpu_debug[cpu_id].state = CPU_STATE_HALTED_HARDWARE_BREAKPOINT;
}

void
gdb_stub_hit_hardware_watchpoint(int cpu_id, uint64_t address) {
	gdb_stub_record_halt(cpu_id);
	gdb.cpu_debug[cpu_id].halted_watchpoint = address;
	gdb.cpu_debug[cpu_id].state = CPU_STATE_HALTED_HARDWARE_WATCHPOINT;
}

void
gdb_stub_did_step(int cpu_id) {
	gdb_stub_record_halt(cpu_id);
	gdb.cpu_debug[cpu_id].state = CPU_STATE_HALTED_SINGLE_STEP;
}

void
gdb_stub_did_halt(int cpu_id) {
	gdb_stub_record_halt(cpu_id);
	gdb.cpu_debug[cpu_id].state = CPU_STATE_HALTED;
}

void
gdb_stub_process_halts(uint32_t halted_mask) {
	if (halted_mask != gdb.halted) {
		// If we ever get out-of-sync, send a debugging message. This will likely break the
		// connection with the debugger.
		gdb_stub_log("%s: halted_mask(%x) != gdb.halted(%x)",
				__func__, halted_mask, gdb.halted);
	}
	if (gdb.process_halted != 0) {
		gdb_process_cpu_halts(gdb.process_halted);
		gdb.process_halted = 0;
	}
}

void
gdb_stub_packet() {
	char packet[GDB_RSP_MAX_PACKET_SIZE];
	size_t size;
	// Try to receive the packet.
	bool ok = gdb_rsp_receive_packet(packet, &size);
	if (!ok) {
		return;
	}
	// Dispatch the packet to the appropriate handler.
	gdb_process_packet(packet, size);
}

void
gdb_stub_log(const char *message, ...) {
	char buffer[GDB_RSP_MAX_PACKET_SIZE];
	char *p = buffer;
	va_list ap;
	va_start(ap, message);
	vsnprintf_cat(buffer, sizeof(buffer), &p, message, ap);
	va_end(ap);
	gdb_stub_serial_write(buffer, p - buffer);
}
