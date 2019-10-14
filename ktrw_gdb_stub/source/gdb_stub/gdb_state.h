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

#ifndef GDB_STATE__H_
#define GDB_STATE__H_

#include <stdbool.h>

#include "gdb_stub.h"

// ---- Definitions -------------------------------------------------------------------------------

// An identifier for an invalid CPU. -1 is reserved to mean "all CPUs" or "unknown".
#define INVALID_CPU	(-2)

// An invalid address.
#define INVALID_ADDRESS		((uint64_t)(-1))

// The possible CPU states.
enum {
	CPU_STATE_RUNNING,
	CPU_STATE_HALTED,
	CPU_STATE_HALTED_HARDWARE_BREAKPOINT,
	CPU_STATE_HALTED_HARDWARE_WATCHPOINT,
	CPU_STATE_HALTED_SINGLE_STEP,
};

// A struct holding the GDB stub's state.
struct gdb_stub_state {
	// The mask of available CPUs being debugged.
	uint32_t cpu_mask;
	// The mask of CPUs currently halted.
	uint32_t halted;
	// The current CPU.
	int current_cpu;
	// CPU debug state.
	struct {
		// The current CPU state. This indicates why the CPU is halted.
		int state;
		// The watchpoint address for which this CPU has halted. If INVALID_ADDRESS, then
		// the CPU is not currently halted because of a watchpoint.
		uint64_t halted_watchpoint;
	} cpu_debug[6];
	// The mask of CPUs that have just halted and need processing.
	uint32_t process_halted;
	// State for all-stop mode.
	struct {
		// True if GDB sent us a packet that requires we send a stop-reply, but we've
		// deferred sending the reply waiting for the appropriate stop to occur.
		bool stop_reply_deferred;
		// The first CPU that generated an "interesting" stop event (breakpoint or
		// watchpoint). This is what we'll try to report to LLDB, since reporting a stop
		// event for the current CPU when nothing is happening there seems to confuse LLDB
		// and make it loop single-stepping.
		int first_stop;
	} all_stop;
	// State for non-stop mode.
	struct {
		// Whether non-stop mode is currently enabled.
		bool enabled;
		// The mask of CPUs that GDB has confirmed it knows are halted.
		uint32_t stopped;
		// A mask of CPUs still left to report in non-stop mode.
		uint32_t queue;
		// A mask for the CPU for which there is an outstanding stop notification/packet
		// that has not yet been confirmed by a "vStopped" packet. This will be OR'd into
		// stopped once GDB ack's the packet.
		uint32_t pending;
	} non_stop;
	// Whether to send error strings with error packets. Controlled by QEnableErrorStrings.
	bool error_strings;
	// Whether to include a list of threads in stop reply packets. Controlled by
	// QListThreadsInStopReply.
	bool list_threads_in_stop_reply;
	// The main executable (kernel) Mach-O.
	const struct mach_header_64 *mach_header;
	// The number of available hardware watchpoints. We only need this for the
	// qWatchpointSupportInfo packet, which in turn is only needed so LLDB will respect
	// watchpoint_exceptions_received:before, which is needed so that LLDB will correctly
	// handle watchpoints.
	unsigned hardware_watchpoint_count;
};

// The GDB state.
extern struct gdb_stub_state gdb;

#endif
