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

#include "gdb_packets.h"

#include "primitives.h"

#include "gdb_cpu.h"
#include "gdb_internal.h"
#include "gdb_rsp.h"
#include "gdb_state.h"

// ---- Utility functions -------------------------------------------------------------------------

// Convert a CPU ID into a thread ID suitable for LLDB.
static int
thread_for_cpu(int cpu_id) {
	if (cpu_id == -1) {
		return -1;
	} else {
		return cpu_id + 1;
	}
}

// Convert a GDB thread ID into a CPU ID.
static int
cpu_for_thread(int thread_id) {
	if (thread_id == -1) {
		return -1;
	}
	if (thread_id == 0) {
		return INVALID_CPU;
	}
	int cpu_id = thread_id - 1;
	if (!valid_cpu_id(cpu_id)) {
		return INVALID_CPU;
	}
	return cpu_id;
}

// A type hack to allow return statements in packet sending functions. Otherwise, returning a void
// expression from a void function will be an error with -Wpedantic.
typedef struct sends_a_packet {} sends_a_packet;
#define PACKET_SENT		((struct sends_a_packet){})
#define PACKET_DEFERRED		((struct sends_a_packet){})
#define PACKET_NOTIFICATION	((struct sends_a_packet){})

// Send a packet containing the specified data.
static sends_a_packet
send_packet_data(const void *data, size_t size) {
	gdb_rsp_send_packet(data, size);
	return PACKET_SENT;
}

// Send a notification containing the specified data.
static void
send_notification_data(const void *data, size_t size) {
	gdb_rsp_send_notification(data, size);
}

// Send an empty packet.
static sends_a_packet
send_empty_packet() {
	return send_packet_data(NULL, 0);
}

// Send a packet containing the specified string.
static sends_a_packet
send_string_packet(const char *str) {
	return send_packet_data(str, strlen(str));
}

// ---- Packet parsing functions ------------------------------------------------------------------

// State for input packet processing.
struct packet {
	char *data;
	unsigned size;
	char *p;
};

// Initialize a packet with a data buffer.
#define PACKET_WITH_DATA(_buffer, _size)	{ .data = _buffer, .size = _size, .p = _buffer }

// Sends a GDB packet constructed using the pkt_* API.
static sends_a_packet
send_packet(struct packet *pkt) {
	size_t size = pkt->p - pkt->data;
	if (size > pkt->size) {
		size = pkt->size;
	}
	return send_packet_data(pkt->data, size);
}

// Sends a GDB notification constructed using the pkt_* API.
static void
send_notification(struct packet *pkt) {
	send_notification_data(pkt->data, pkt->p - pkt->data);
}

// Saves the current packet cursor.
static char *
pkt_save(struct packet *pkt) {
	return pkt->p;
}

// Restores the packet cursor to the specified place.
static void
pkt_reset(struct packet *pkt, char *p) {
	pkt->p = p;
}

// Returns true if all the data has been read from the packet.
static bool
pkt_empty(struct packet *pkt) {
	return (pkt->p >= pkt->data + pkt->size);
}

// Read a single character/byte from the packet.
static bool
pkt_read_char(struct packet *pkt, char *ch) {
	if (pkt_empty(pkt)) {
		return false;
	}
	*ch = *pkt->p;
	pkt->p++;
	return true;
}

// Read an exact C-string from the packet.
static bool
pkt_read_match(struct packet *pkt, const char *str) {
	char *orig_p = pkt->p;
	for (;;) {
		if (*str == 0) {
			return true;
		}
		if (pkt_empty(pkt)) {
			break;
		}
		if (*pkt->p != *str) {
			break;
		}
		pkt->p++;
		str++;
	}
	pkt->p = orig_p;
	return false;
}

// Read a big-endian hexadecimal integer (max size 64 bits) from the packet.
static bool
pkt_read_hex_u64(struct packet *pkt, uint64_t *value) {
	uint64_t v = 0;
	unsigned i = 0;
	for (;; i++) {
		if (pkt_empty(pkt)) {
			break;
		}
		char ch = *pkt->p;
		int digit = hex_digit(ch);
		if (digit == -1) {
			break;
		}
		pkt->p++;
		v = (v << 4) | (digit & 0xf);
		if (i == 16) {
			goto done;
		}
	}
	// Make sure we processed at least some data.
	if (i == 0) {
		// We expect a value.
		return false;
	}
done:
	// Return the value.
	*value = v;
	return true;
}

// Read the raw binary data of the packet.
static bool
pkt_read_data(struct packet *pkt, const void **data, size_t *size) {
	char *end = pkt->data + pkt->size;
	char *p = pkt->p;
	if (p <= end) {
		*data = p;
		*size = end - p;
		pkt->p = end;
		return true;
	} else {
		return false;
	}
}

// Read hex-encoded data from the packet.
static bool
pkt_read_hex_data(struct packet *pkt, void *data, size_t *size, size_t max_size) {
	char *orig_p = pkt->p;
	uint8_t *dst = data;
	uint8_t *end = dst + max_size;
	while (dst < end) {
		// Parse the high hex digit.
		if (pkt_empty(pkt)) {
			break;
		}
		char ch = *pkt->p;
		int hi = hex_digit(ch);
		if (hi == -1) {
			break;
		}
		pkt->p++;
		// Parse the low hex digit.
		if (pkt_empty(pkt)) {
			goto fail;
		}
		ch = *pkt->p;
		int lo = hex_digit(ch);
		if (lo == -1) {
			goto fail;
		}
		pkt->p++;
		// Store the hex data.
		*dst = ((hi & 0xf) << 4) | (lo & 0xf);
		dst++;
	}
	if (size != NULL) {
		*size = dst - (uint8_t *)data;
	}
	return true;
fail:
	pkt->p = orig_p;
	return false;
}

// Read a CPU ID (represented to GDB as a thread ID) from the packet. 0 is not considered a valid
// CPU ID, so it must be handled separately.
static bool
pkt_read_thread_id(struct packet *pkt, int *cpu_id) {
	uint64_t thread_id;
	bool ok = pkt_read_match(pkt, "-1");
	if (ok) {
		*cpu_id = -1;
		return true;
	}
	ok = pkt_read_hex_u64(pkt, &thread_id);
	if (ok) {
		if ((int)thread_id != thread_id) {
			*cpu_id = INVALID_CPU;
		} else {
			*cpu_id = cpu_for_thread((int)thread_id);
		}
		return true;
	}
	return false;
}

// Write a formatted string to the packet.
static void
pkt_vsprintf(struct packet *pkt, const char *fmt, va_list ap) {
	vsnprintf_cat(pkt->data, pkt->size, &pkt->p, fmt, ap);
}

// Write a formatted string to the packet.
static void
pkt_sprintf(struct packet *pkt, const char *fmt, ...) {
	va_list ap;
	va_start(ap, fmt);
	pkt_vsprintf(pkt, fmt, ap);
	va_end(ap);
}

// Write hex-encoded binary data to the packet.
static void
pkt_put_hex_data(struct packet *pkt, const void *data, size_t size) {
	const uint8_t *src = data;
	for (size_t i = 0; i < size; i++) {
		pkt_sprintf(pkt, "%02x", src[i]);
	}
}

// Write a CPU ID (represented to GDB as a thread ID) to the packet.
static void
pkt_put_thread_id(struct packet *pkt, int cpu_id) {
	if (cpu_id == -1) {
		pkt_sprintf(pkt, "-1");
	} else {
		pkt_sprintf(pkt, "%x", thread_for_cpu(cpu_id));
	}
}

// Remove the specified number of bytes from the end of the packet.
static void
pkt_chop(struct packet *pkt, size_t size) {
	size_t filled = pkt->p - pkt->data;
	if (size > filled) {
		size = filled;
	}
	pkt->p -= size;
}

// ---- Packet dispatching by name ----------------------------------------------------------------

// A struct to link a specific packet name and separator with the appropriate packet handler to
// invoke.
struct dispatch {
	const char *match;
	char separator;
	sends_a_packet (*handler)(struct packet *pkt);
};

// Count the number of dispatch elements in a dispatch array.
#define DISPATCH_COUNT(a)	(sizeof(a) / sizeof(a[0]))

// Dispatch a packet to the appropriate handler, invoking the unhandled() callback if none of the
// handlers match.
static sends_a_packet
pkt_dispatch(const struct dispatch *dispatch, size_t count, struct packet *pkt,
		sends_a_packet (*unhandled)(void)) {
	char *start = pkt_save(pkt);
	for (unsigned i = 0; i < count; i++) {
		const struct dispatch *d = &dispatch[i];
		bool match = pkt_read_match(pkt, d->match);
		if (match) {
			if (d->separator == '$') {
				if (!pkt_empty(pkt)) {
					pkt_reset(pkt, start);
					continue;
				}
			} else if (d->separator != 0) {
				char sep = 0;
				pkt_read_char(pkt, &sep);
				if (sep != d->separator) {
					pkt_reset(pkt, start);
					continue;
				}
			}
			return d->handler(pkt);
		}
	}
	return unhandled();
}

// ---- Error reply packets -----------------------------------------------------------------------

// Send the packet "OK".
static sends_a_packet
send_ok() {
	return send_string_packet("OK");
}

// Send an error packet "Exx". Don't use this function directly.
static sends_a_packet
send_error_packet(int error, const char *message, ...) {
	char buffer[GDB_RSP_MAX_PACKET_SIZE];
	struct packet reply = PACKET_WITH_DATA(buffer, sizeof(buffer));
	pkt_sprintf(&reply, "E%02x", (error & 0xff));
	if (gdb.error_strings && message != NULL) {
		// Build the message in a separate buffer.
		char message_buffer[256];
		char *ptr = message_buffer;
		va_list ap;
		va_start(ap, message);
		vsnprintf_cat(message_buffer, sizeof(message_buffer), &ptr, message, ap);
		va_end(ap);
		size_t length = ptr - message_buffer;
		if (length > sizeof(message_buffer)) {
			length = sizeof(message_buffer);
		}
		// Hex-encode the error string into the error reply.
		pkt_sprintf(&reply, ";");
		pkt_put_hex_data(&reply, message_buffer, length);
	}
	return send_packet(&reply);
}

// Error types. Use the functions below.
enum {
	ERROR_BAD_PACKET = 1,
	ERROR_NO_THREAD,
	ERROR_INVALID_ADDRESS,
	ERROR_INVALID_LENGTH,
	ERROR_INVALID_REGISTER,
	ERROR_CPU_NOT_STOPPED,
	ERROR_ADD_BREAKPOINT,
	ERROR_JIT_ALLOCATE,
	ERROR_JIT_DEALLOCATE,
};

static sends_a_packet
send_error_bad_packet(const char *name) {
	return send_error_packet(ERROR_BAD_PACKET, "%s packet: Bad packet", name);
}

static sends_a_packet
send_error_no_thread_selected(const char *name) {
	return send_error_packet(ERROR_NO_THREAD, "%s packet: No thread selected", name);
}

static sends_a_packet
send_error_invalid_address(const char *name, uint64_t address) {
	return send_error_packet(ERROR_INVALID_ADDRESS,
			"%s packet: Invalid address 0x%016llx", name, address);
}

static sends_a_packet
send_error_invalid_length(const char *name) {
	return send_error_packet(ERROR_INVALID_LENGTH, "%s packet: Invalid length", name);
}

static sends_a_packet
send_error_invalid_register(const char *name) {
	return send_error_packet(ERROR_INVALID_REGISTER, "%s packet: Invalid register", name);
}

static sends_a_packet
send_error_cpu_not_stopped(const char *name, int cpu_id) {
	return send_error_packet(ERROR_CPU_NOT_STOPPED,
			"%s packet: CPU %d not stopped", name, cpu_id);
}

static sends_a_packet
send_error_add_breakpoint(const char *name, uint64_t address) {
	return send_error_packet(ERROR_ADD_BREAKPOINT,
			"%s packet: Could not add breakpoint at address 0x%016llx",
			name, address);
}

static sends_a_packet
send_error_jit_allocate(const char *name, uint64_t size) {
	return send_error_packet(ERROR_JIT_ALLOCATE,
			"%s packet: Could not allocate 0x%016llx bytes of JIT memory",
			name, size);
}

static sends_a_packet
send_error_jit_deallocate(const char *name, uint64_t address) {
	return send_error_packet(ERROR_JIT_DEALLOCATE,
			"%s packet: Address 0x%016llx was not allocated by JIT",
			name, address);
}

// ---- Stop reply packets ------------------------------------------------------------------------

// Construct a stop reply for a stopped thread.
static void
build_T_stop_reply(struct packet *pkt, int cpu_id) {
	int signal = 0;
	int state = gdb.cpu_debug[cpu_id].state;
	if (state == CPU_STATE_HALTED_HARDWARE_BREAKPOINT
			|| state == CPU_STATE_HALTED_HARDWARE_WATCHPOINT
			|| state == CPU_STATE_HALTED_SINGLE_STEP) {
		signal = 5;
	}
	pkt_sprintf(pkt, "T%02x", signal);
	pkt_sprintf(pkt, "thread:%x;", thread_for_cpu(cpu_id));
	pkt_sprintf(pkt, "core:%x;", cpu_id);
	const char *reason = NULL;
	if (state == CPU_STATE_HALTED_HARDWARE_BREAKPOINT) {
		pkt_sprintf(pkt, "hwbreak:;");
		// We should only specify reason;breakpoint if a breakpoint set using a "z" packet
		// was hit. Since we currently only set breakpoints due to "z" packets, this is
		// always the case.
		reason = "breakpoint";
	}
	if (state == CPU_STATE_HALTED_HARDWARE_WATCHPOINT) {
		uint64_t address = gdb.cpu_debug[cpu_id].halted_watchpoint;
		pkt_sprintf(pkt, "watch:%llx;", address);
		reason = "watchpoint";
	}
	if (reason != NULL) {
		pkt_sprintf(pkt, "reason:%s;", reason);
	}
	if (gdb.list_threads_in_stop_reply) {
		pkt_sprintf(pkt, "threads:");
		for (int cpu_id = 0; cpu_id < CPU_COUNT; cpu_id++) {
			if (valid_cpu_id(cpu_id)) {
				pkt_sprintf(pkt, "%x,", thread_for_cpu(cpu_id));
			}
		}
		pkt_chop(pkt, 1);
		pkt_sprintf(pkt, ";");
		pkt_sprintf(pkt, "thread-pcs:");
		for (int cpu_id = 0; cpu_id < CPU_COUNT; cpu_id++) {
			if (valid_cpu_id(cpu_id)) {
				if (cpu_is_halted(cpu_id)) {
					uint64_t pc = gdb_stub_cpu_pc(cpu_id);
					pkt_sprintf(pkt, "%llx,", pc);
				} else {
					pkt_sprintf(pkt, "xx,");
				}
			}
		}
		pkt_chop(pkt, 1);
		pkt_sprintf(pkt, ";");
	}
	// TODO: Try to stuff as many registers as possible into the stop reply.
}

// Send a stop reply packet for a stopped thread.
static sends_a_packet
send_T_stop_reply_packet(int cpu_id, bool packet) {
	char buffer[GDB_RSP_MAX_PACKET_SIZE];
	struct packet reply = PACKET_WITH_DATA(buffer, sizeof(buffer));
	build_T_stop_reply(&reply, cpu_id);
	if (packet) {
		return send_packet(&reply);
	}
	send_notification(&reply);
	return PACKET_NOTIFICATION;
}

// Send a stop reply packet in all-stop mode.
static sends_a_packet
all_stop__send_stop_reply_packet() {
	// If we have a specific current CPU and it's halted, report it with "T".
	int cpu_id = gdb.current_cpu;
	if (cpu_id != -1 && cpu_is_halted(cpu_id)) {
		return send_T_stop_reply_packet(cpu_id, true);
	}
	// Otherwise, try and find a halted CPU and tell GDB about it.
	for (int cpu_id = 0; cpu_id < CPU_COUNT; cpu_id++) {
		if (cpu_is_halted(cpu_id)) {
			return send_T_stop_reply_packet(cpu_id, true);
		}
	}
	// Otherwise, no CPUs are halted, so GDB really shouldn't have asked. Just send "OK".
	return send_ok();
}

// Abandon any existing stop reply notification sequence and initialize the queue to send stop
// reply notifications/packets about the specified CPUs.
static void
non_stop__set_stop_reply_notification_queue(uint32_t notify_mask) {
	// Replace the existing queue mask with the new mask. This ensures that an existing
	// vStopped sequence will be abandoned.
	gdb.non_stop.queue = notify_mask;
	gdb.non_stop.pending = 0;
}

// Update any existing stop reply notification sequence to send stop reply notifications/packets
// about the specified CPUs.
static void
non_stop__update_stop_reply_notification_queue(uint32_t notify_mask) {
	// Add the new notifications to the existing queue.
	gdb.non_stop.queue |= notify_mask;
}

// Send a stop reply packet for the specified CPU, moving it from the queue to pending.
static sends_a_packet
non_stop__send_stop_reply_packet_for_cpu(int cpu_id, bool packet) {
	// Move this CPU from non_stop.queue to non_stop.pending.
	gdb.non_stop.queue &= ~(1 << cpu_id);
	gdb.non_stop.pending |= (1 << cpu_id);
	// Send the stop reply packet for this CPU.
	return send_T_stop_reply_packet(cpu_id, packet);
}

// Choose a CPU from the stop reply notification queue and send a stop reply packet for it.
static sends_a_packet
non_stop__send_stop_reply_packet(bool packet) {
	// First check to see if we have a queued packet for a halted CPU.
	for (int cpu_id = 0; cpu_id < CPU_COUNT; cpu_id++) {
		if (gdb.non_stop.queue & (1 << cpu_id)) {
			return non_stop__send_stop_reply_packet_for_cpu(cpu_id, packet);
		}
	}
	// All CPUs are running or we are done with the sequence.
	if (packet) {
		return send_ok();
	}
	// For notifications, we don't have an actual packet.
	return PACKET_NOTIFICATION;
}

// Some commands don't send a stop reply until a halt occurs. This only makes sense in all-stop
// mode.
static sends_a_packet
all_stop__defer_stop_reply_until_halt() {
	// It is possible that stop_reply_deferred is already true. This could happen for example
	// if LLDB sends "c" to continue followed by "^C" to interrupt.
	gdb.all_stop.stop_reply_deferred = true;
	// When we defer a stop reply, it means that we next expect to be notified that something
	// interesting is happening when a CPU halts. first_stop will be set to the CPU ID of the
	// first CPU to halt.
	gdb.all_stop.first_stop = INVALID_CPU;
	return PACKET_DEFERRED;
}

// In all-stop mode, records that we are deferring sending a stop reply until a subsequent halt
// event. In non-stop mode, sends "OK". This is appropriate for "c", "vCont", etc.
static sends_a_packet
send_stop_reply() {
	// In non-stop mode, we can just send "OK": any subsequent stop will be the subject of a
	// future stop reply notification.
	if (gdb.non_stop.enabled) {
		return send_ok();
	}
	// In all-stop mode, we're supposed to wait until the next halt and then send a stop reply
	// packet for one halted CPU.
	return all_stop__defer_stop_reply_until_halt();
}

// ---- Unknown packet ----------------------------------------------------------------------------

static sends_a_packet
gdb_pkt__unknown(void) {
	return send_empty_packet();
}

// ---- ^C pseudo-packet ---------------------------------------------------------------------------

static sends_a_packet
interrupt() {
	// According to the spec, if an interrupt is received while the system is stopped, we
	// should queue it and deliver it after it is next resumed. Rather than do that, we'll
	// simply proceed anyway: gdb_interrupt() will be a no-op and then we'll defer.
	// First asynchronously interrupt the running CPUs.
	gdb_interrupt();
	// In non-stop mode, we're supposed to wait until the next halt and then send a stop reply
	// notification for each halted CPU. This happens automatically.
	if (gdb.non_stop.enabled) {
		return PACKET_DEFERRED;
	}
	// In all-stop mode, we're supposed to wait until the next halt and then send a stop reply
	// packet for one halted CPU.
	return all_stop__defer_stop_reply_until_halt();
}

static sends_a_packet
gdb_pkt__ctrl_c(struct packet *pkt) {
	if (!pkt_empty(pkt)) {
		return gdb_pkt__unknown();
	}
	return interrupt();
}

// ---- ? packet ----------------------------------------------------------------------------------

static sends_a_packet
gdb_pkt__questionmark(struct packet *pkt) {
	if (!pkt_empty(pkt)) {
		return gdb_pkt__unknown();
	}
	// In non-stop mode, we begin a new stop reply notification sequence for all halted CPUs.
	if (gdb.non_stop.enabled) {
		// Put every halted CPU in the queue, abandoning any prior notification sequence.
		non_stop__set_stop_reply_notification_queue(gdb.halted);
		// Send the first stop reply packet in the sequence. This is usually a
		// notification, but is a packet in response to "?".
		return non_stop__send_stop_reply_packet(true);
	}
	// In all-stop mode, we just send any old stop reply.
	return all_stop__send_stop_reply_packet();
}

// ---- c packet ----------------------------------------------------------------------------------

static sends_a_packet
gdb_pkt__c(struct packet *pkt) {
	if (!pkt_empty(pkt)) {
		return send_error_bad_packet("c");
	}
	// First asynchronously resume the halted CPUs.
	gdb_resume();
	// Send a stop-reply packet at the appropriate time. In all-stop mode, this will defer
	// replying until we observe a stop.
	return send_stop_reply();
}

// ---- g packet ----------------------------------------------------------------------------------

static sends_a_packet
gdb_pkt__g(struct packet *pkt) {
	if (!pkt_empty(pkt)) {
		return gdb_pkt__unknown();
	}
	if (gdb.current_cpu == -1) {
		return send_error_no_thread_selected("g");
	}
	if (!cpu_is_halted(gdb.current_cpu)) {
		return send_error_cpu_not_stopped("g", gdb.current_cpu);
	}
	// Read the registers.
	struct gdb_registers registers;
	gdb_stub_read_registers(gdb.current_cpu, &registers);
	// Format the data as hex.
	char buffer[GDB_RSP_MAX_PACKET_SIZE];
	struct packet reply = PACKET_WITH_DATA(buffer, sizeof(buffer));
	pkt_put_hex_data(&reply, &registers, sizeof(registers));
	return send_packet(&reply);
}

// ---- G packet ----------------------------------------------------------------------------------

static sends_a_packet
gdb_pkt__G(struct packet *pkt) {
	if (gdb.current_cpu == -1) {
		return send_error_no_thread_selected("G");
	}
	if (!cpu_is_halted(gdb.current_cpu)) {
		return send_error_cpu_not_stopped("G", gdb.current_cpu);
	}
	struct gdb_registers registers;
	size_t size;
	bool ok = pkt_read_hex_data(pkt, &registers, &size, sizeof(registers))
		&& size == sizeof(registers)
		&& pkt_empty(pkt);
	if (!ok) {
		return send_error_bad_packet("G");
	}
	gdb_stub_write_registers(gdb.current_cpu, &registers);
	return send_ok();
}

// ---- Hg packet ---------------------------------------------------------------------------------

static sends_a_packet
gdb_pkt__Hg(struct packet *pkt) {
	// Parse the thread-id to get a cpu_id. Note that -1 and 0 are valid in this case.
	int cpu_id;
	bool ok = pkt_read_match(pkt, "0")
		&& pkt_empty(pkt);
	if (ok) {
		for (cpu_id = 0; cpu_id < CPU_COUNT; cpu_id++) {
			if (valid_cpu_id(cpu_id)) {
				break;
			}
		}
	} else {
		ok = pkt_read_thread_id(pkt, &cpu_id)
			&& pkt_empty(pkt);
		if (!ok || cpu_id == INVALID_CPU) {
			return send_error_bad_packet("Hg");
		}
	}
	// Set the current CPU.
	gdb.current_cpu = cpu_id;
	return send_ok();
}

// ---- H packet ----------------------------------------------------------------------------------

static sends_a_packet
gdb_pkt__H(struct packet *pkt) {
	char op = 0;
	pkt_read_char(pkt, &op);
	switch (op) {
		case 'g':
			return gdb_pkt__Hg(pkt);
		default:
			return gdb_pkt__unknown();
	}
}

// ---- k packet ----------------------------------------------------------------------------------

static sends_a_packet
gdb_pkt__k(struct packet *pkt) {
	if (!pkt_empty(pkt)) {
		return send_error_bad_packet("k");
	}
	// Clear all backend state. This will delete breakpoints, watchpoints, JIT allocations,
	// etc.
	gdb_stub_reset_state();
	// Reset the halt reasons for all CPUs.
	for (int cpu_id = 0; cpu_id < CPU_COUNT; cpu_id++) {
		if (valid_cpu_id(cpu_id)) {
			int state = CPU_STATE_RUNNING;
			if (cpu_is_halted(cpu_id)) {
				state = CPU_STATE_HALTED;
			}
			gdb.cpu_debug[cpu_id].state = state;
		}
	}
	// Reset options.
	gdb.list_threads_in_stop_reply = false;
	gdb.error_strings = false;
	// Send empty reply.
	return send_empty_packet();
}

// ---- m packet ----------------------------------------------------------------------------------

static sends_a_packet
gdb_pkt__m(struct packet *pkt) {
	uint64_t address;
	uint64_t length;
	bool ok = pkt_read_hex_u64(pkt, &address)
		&& pkt_read_match(pkt, ",")
		&& pkt_read_hex_u64(pkt, &length)
		&& pkt_empty(pkt);
	if (!ok) {
		return send_error_bad_packet("m");
	}
	uint8_t data[GDB_RSP_MAX_PACKET_SIZE / 2];
	if (length > sizeof(data)) {
		return send_error_invalid_length("m");
	}
	size_t read = gdb_stub_read_memory(gdb.current_cpu, address, data, length);
	if (read == 0 && length > 0) {
		return send_error_invalid_address("m", address);
	}
	char buffer[GDB_RSP_MAX_PACKET_SIZE];
	struct packet reply = PACKET_WITH_DATA(buffer, sizeof(buffer));
	pkt_put_hex_data(&reply, data, read);
	return send_packet(&reply);
}

// ---- M packet ----------------------------------------------------------------------------------

static sends_a_packet
gdb_pkt__M(struct packet *pkt) {
	uint64_t address;
	uint64_t length;
	bool ok = pkt_read_hex_u64(pkt, &address)
		&& pkt_read_match(pkt, ",")
		&& pkt_read_hex_u64(pkt, &length)
		&& pkt_read_match(pkt, ":");
	if (!ok) {
		return send_error_bad_packet("M");
	}
	uint8_t data[GDB_RSP_MAX_PACKET_SIZE / 2];
	if (length > sizeof(data)) {
		return send_error_invalid_length("M");
	}
	size_t size;
	ok = pkt_read_hex_data(pkt, data, &size, sizeof(data))
		&& size == length
		&& pkt_empty(pkt);
	if (!ok) {
		return send_error_bad_packet("M");
	}
	if (length > 0) {
		size_t written = gdb_stub_write_memory(gdb.current_cpu, address, data, length);
		if (written != length) {
			return send_error_invalid_address("M", address + written);
		}
	}
	return send_ok();
}

// ---- p packet ----------------------------------------------------------------------------------

static sends_a_packet
gdb_pkt__p(struct packet *pkt) {
	uint64_t reg_id;
	bool ok = pkt_read_hex_u64(pkt, &reg_id)
		&& pkt_empty(pkt);
	if (!ok) {
		return send_error_bad_packet("p");
	}
	if ((int)reg_id != reg_id || reg_id > gdb_register_count) {
		return send_error_invalid_register("p");
	}
	if (!cpu_is_halted(gdb.current_cpu)) {
		return send_error_cpu_not_stopped("p", gdb.current_cpu);
	}
	// Read the register value.
	const struct gdb_register_info *reg = &gdb_register_info[reg_id];
	struct gdb_registers registers;
	gdb_stub_read_registers(gdb.current_cpu, &registers);
	uint8_t *register_data = (uint8_t *)&registers + reg->offset;
	size_t register_size = reg->bitsize / 8;
	// Format the data as hex.
	char buffer[GDB_RSP_MAX_PACKET_SIZE];
	struct packet reply = PACKET_WITH_DATA(buffer, sizeof(buffer));
	pkt_put_hex_data(&reply, register_data, register_size);
	return send_packet(&reply);
}

// ---- P packet ----------------------------------------------------------------------------------

static sends_a_packet
gdb_pkt__P(struct packet *pkt) {
	uint64_t reg_id;
	uint8_t reg_value[32];
	size_t reg_size;
	bool ok = pkt_read_hex_u64(pkt, &reg_id)
		&& pkt_read_match(pkt, "=")
		&& pkt_read_hex_data(pkt, &reg_value, &reg_size, sizeof(reg_value))
		&& pkt_empty(pkt);
	if (!ok) {
		return send_error_bad_packet("P");
	}
	if ((int)reg_id != reg_id || reg_id > gdb_register_count) {
		return send_error_invalid_register("P");
	}
	const struct gdb_register_info *reg = &gdb_register_info[reg_id];
	if (reg_size != reg->bitsize / 8) {
		return send_error_invalid_register("P");
	}
	if (!cpu_is_halted(gdb.current_cpu)) {
		return send_error_cpu_not_stopped("P", gdb.current_cpu);
	}
	// Read all registers.
	struct gdb_registers registers;
	gdb_stub_read_registers(gdb.current_cpu, &registers);
	// Copy the value over the target register.
	uint8_t *register_data = (uint8_t *)&registers + reg->offset;
	memcpy(register_data, reg_value, reg_size);
	// Write all registers.
	gdb_stub_write_registers(gdb.current_cpu, &registers);
	return send_ok();
}

// ---- qC packet ---------------------------------------------------------------------------------

static sends_a_packet
gdb_pkt__qC(struct packet *pkt) {
	char buffer[GDB_RSP_MAX_PACKET_SIZE];
	struct packet reply = PACKET_WITH_DATA(buffer, sizeof(buffer));
	pkt_sprintf(&reply, "QC");
	pkt_put_thread_id(&reply, gdb.current_cpu);
	return send_packet(&reply);
}

// ---- qfThreadInfo packet -----------------------------------------------------------------------

static sends_a_packet
gdb_pkt__qfThreadInfo(struct packet *pkt) {
	char buffer[GDB_RSP_MAX_PACKET_SIZE];
	struct packet reply = PACKET_WITH_DATA(buffer, sizeof(buffer));
	pkt_sprintf(&reply, "m");
	for (int cpu_id = 0; cpu_id < CPU_COUNT; cpu_id++) {
		if (valid_cpu_id(cpu_id)) {
			pkt_sprintf(&reply, "%x,", thread_for_cpu(cpu_id));
		}
	}
	pkt_chop(&reply, 1);
	return send_packet(&reply);
}

// ---- qsThreadInfo packet -----------------------------------------------------------------------

static sends_a_packet
gdb_pkt__qsThreadInfo(struct packet *pkt) {
	return send_string_packet("l");
}

// ---- qSupported packet -------------------------------------------------------------------------

static sends_a_packet
gdb_pkt__qSupported(struct packet *pkt) {
	char buffer[GDB_RSP_MAX_PACKET_SIZE];
	struct packet reply = PACKET_WITH_DATA(buffer, sizeof(buffer));
	pkt_sprintf(&reply, "PacketSize=%x;", GDB_RSP_MAX_PACKET_SIZE);
	pkt_sprintf(&reply, "QNonStop+;");
	pkt_sprintf(&reply, "hwbreak+;");
	pkt_sprintf(&reply, "qXfer:features:read+;");
	pkt_chop(&reply, 1);
	return send_packet(&reply);
}

// ---- qXfer:features:read:target.xml packet -----------------------------------------------------

// Build the target.xml document. Because the generated data is very large, GDB will fetch it in
// chunks, meaning we should support generating only part of the data starting at a specified
// offset. Returns the total length of the complete XML.
static size_t
build_target_xml(char *buffer, size_t size, size_t offset) {
	char *b = buffer;
	size_t s = size;
	char *p = b - offset;
	snprintf_cat(b, s, &p, "<?xml version=\"1.0\"?>\n");
	snprintf_cat(b, s, &p, "<target version=\"1.0\">\n");
	snprintf_cat(b, s, &p, "<feature name=\"com.apple.debugserver.arm64\">\n");
	for (reg_id_t reg_id = 0; reg_id < gdb_register_count; reg_id++) {
		const struct gdb_register_info *reg = &gdb_register_info[reg_id];
		snprintf_cat(b, s, &p, "  <reg name=\"%s\"", reg->name);
		snprintf_cat(b, s, &p, " regnum=\"%u\"", reg_id);
		snprintf_cat(b, s, &p, " offset=\"%u\"", reg->offset);
		snprintf_cat(b, s, &p, " bitsize=\"%u\"", reg->bitsize);
		snprintf_cat(b, s, &p, " group=\"%s\"", gdb_register_group_name[reg->group]);
		if (reg->type != 0) {
			snprintf_cat(b, s, &p, " type=\"%s\"", gdb_register_type_name[reg->type]);
		}
		if (reg->altname != NULL) {
			snprintf_cat(b, s, &p, " altname=\"%s\"", reg->altname);
		}
		if (reg->encoding != 0) {
			snprintf_cat(b, s, &p, " encoding=\"%s\"",
					gdb_register_encoding_name[reg->encoding]);
		}
		if (reg->format != 0) {
			snprintf_cat(b, s, &p, " format=\"%s\"",
					gdb_register_format_name[reg->format]);
		}
		snprintf_cat(b, s, &p, " group_id=\"%u\"", reg->set);
		if (reg->ehframe_reg != INVALID_REG_ID) {
			snprintf_cat(b, s, &p, " ehframe_regnum=\"%u\"", reg->ehframe_reg);
		}
		if (reg->dwarf_reg != INVALID_REG_ID) {
			snprintf_cat(b, s, &p, " dwarf_regnum=\"%u\"", reg->dwarf_reg);
		}
		if (reg->generic != 0) {
			snprintf_cat(b, s, &p, " generic=\"%s\"",
					gdb_register_generic_name[reg->generic]);
		}
		if (reg->value_regs[0] != INVALID_REG_ID) {
			snprintf_cat(b, s, &p, " value_regnums=\"");
			for (unsigned i = 0;; i++) {
				reg_id_t value_id = reg->value_regs[i];
				if (value_id == INVALID_REG_ID) {
					break;
				}
				if (i > 0) {
					snprintf_cat(b, s, &p, ",");
				}
				snprintf_cat(b, s, &p, "%u", value_id);
			}
			snprintf_cat(b, s, &p, "\"");
		}
		if (reg->invalidate_regs[0] != INVALID_REG_ID) {
			snprintf_cat(b, s, &p, " invalidate_regnums=\"");
			for (unsigned i = 0;; i++) {
				reg_id_t invalidate_id = reg->invalidate_regs[i];
				if (invalidate_id == INVALID_REG_ID) {
					break;
				}
				if (i > 0) {
					snprintf_cat(b, s, &p, ",");
				}
				snprintf_cat(b, s, &p, "%u", invalidate_id);
			}
			snprintf_cat(b, s, &p, "\"");
		}
		snprintf_cat(b, s, &p, "/>\n");
	}
	snprintf_cat(b, s, &p, "</feature>\n");
	snprintf_cat(b, s, &p, "<groups>\n");
	for (unsigned set_id = 0; set_id < gdb_register_set_count; set_id++) {
		const struct gdb_register_set_info *set = &gdb_register_set_info[set_id];
		snprintf_cat(b, s, &p, "  <group id=\"%u\"", set_id);
		snprintf_cat(b, s, &p, " name=\"%s\"", set->description);
		snprintf_cat(b, s, &p, "/>\n");
	}
	snprintf_cat(b, s, &p, "</groups>\n");
	snprintf_cat(b, s, &p, "</target>\n");
	snprintf_cat(b, s, &p, "\0");
	return p - (b - offset);
}

static sends_a_packet
gdb_pkt__qXfer_features_read_target_xml(struct packet *pkt) {
	uint64_t offset;
	uint64_t length;
	char buffer[GDB_RSP_MAX_PACKET_SIZE];
	bool ok = pkt_read_hex_u64(pkt, &offset)
		&& pkt_read_match(pkt, ",")
		&& pkt_read_hex_u64(pkt, &length)
		&& pkt_empty(pkt);
	if (!ok || length > sizeof(buffer) - 1) {
		return send_error_bad_packet("qXfer");
	}
	size_t xml_size = build_target_xml(buffer + 1, length, offset);
	if (offset > xml_size) {
		return send_error_bad_packet("qXfer");
	}
	size_t fragment_size = xml_size - offset;
	if (fragment_size <= length) {
		buffer[0] = 'l';
	} else {
		buffer[0] = 'm';
		fragment_size = length;
	}
	return send_packet_data(buffer, 1 + fragment_size);
}

// ---- qThreadStopInfo packet --------------------------------------------------------------------

static sends_a_packet
gdb_pkt__qThreadStopInfo(struct packet *pkt) {
	int cpu_id;
	bool ok = pkt_read_thread_id(pkt, &cpu_id)
		&& pkt_empty(pkt);
	if (!ok || cpu_id == INVALID_CPU) {
		return send_error_bad_packet("qThreadStopInfo");
	}
	if (!cpu_is_halted(cpu_id)) {
		return send_error_cpu_not_stopped("qThreadStopInfo", cpu_id);
	}
	return send_T_stop_reply_packet(cpu_id, true);
}

// ---- qHostInfo packet --------------------------------------------------------------------------

static sends_a_packet
gdb_pkt__qHostInfo(struct packet *pkt) {
	char buffer[GDB_RSP_MAX_PACKET_SIZE];
	struct packet reply = PACKET_WITH_DATA(buffer, sizeof(buffer));
	if (gdb.mach_header != NULL) {
		pkt_sprintf(&reply, "cputype:%u;", gdb.mach_header->cputype);
		pkt_sprintf(&reply, "cpusubtype:%u;", gdb.mach_header->cpusubtype);
	}
	pkt_sprintf(&reply, "ostype:ios;");
	pkt_sprintf(&reply, "watchpoint_exceptions_received:before;");
	pkt_sprintf(&reply, "vendor:apple;");
	pkt_sprintf(&reply, "endian:little;");
	pkt_sprintf(&reply, "ptrsize:8;");
	return send_packet(&reply);
}

// ---- qProcessInfo packet -----------------------------------------------------------------------

static sends_a_packet
gdb_pkt__qProcessInfo(struct packet *pkt) {
	char buffer[GDB_RSP_MAX_PACKET_SIZE];
	struct packet reply = PACKET_WITH_DATA(buffer, sizeof(buffer));
	pkt_sprintf(&reply, "pid:0;");
	if (gdb.mach_header != NULL) {
		pkt_sprintf(&reply, "cputype:%x;", gdb.mach_header->cputype);
		pkt_sprintf(&reply, "cpusubtype:%x;", gdb.mach_header->cpusubtype);
	}
	pkt_sprintf(&reply, "ostype:ios;");
	pkt_sprintf(&reply, "vendor:apple;");
	pkt_sprintf(&reply, "endian:little;");
	pkt_sprintf(&reply, "ptrsize:8;");
	return send_packet(&reply);
}

// ---- qWatchpointSupportInfo packet -------------------------------------------------------------

static sends_a_packet
gdb_pkt__qWatchpointSupportInfo(struct packet *pkt) {
	char buffer[GDB_RSP_MAX_PACKET_SIZE];
	struct packet reply = PACKET_WITH_DATA(buffer, sizeof(buffer));
	pkt_sprintf(&reply, "num:%u;", gdb.hardware_watchpoint_count);
	return send_packet(&reply);
}

// ---- q packet ----------------------------------------------------------------------------------

static const struct dispatch q_dispatch[] = {
	{ "C", '$', gdb_pkt__qC },
	{ "fThreadInfo", '$', gdb_pkt__qfThreadInfo },
	{ "sThreadInfo", '$', gdb_pkt__qsThreadInfo },
	{ "Supported", 0, gdb_pkt__qSupported },
	{ "Xfer:features:read:target.xml", ':', gdb_pkt__qXfer_features_read_target_xml },
	{ "ThreadStopInfo", 0, gdb_pkt__qThreadStopInfo },
	{ "HostInfo", '$', gdb_pkt__qHostInfo },
	{ "ProcessInfo", '$', gdb_pkt__qProcessInfo },
	{ "WatchpointSupportInfo:", '$', gdb_pkt__qWatchpointSupportInfo },
	// TODO: It would be nice to support LLDB's "qMemoryRegionInfo" packet. This would be based
	// on parsing pagetables, which would go in when supporting LLDB's "_M" packet for memory
	// allocation/JIT.
};

static sends_a_packet
gdb_pkt__q(struct packet *pkt) {
	return pkt_dispatch(q_dispatch, DISPATCH_COUNT(q_dispatch), pkt, gdb_pkt__unknown);
}

// ---- QEnableErrorStrings packet ----------------------------------------------------------------

static sends_a_packet
gdb_pkt__QEnableErrorStrings(struct packet *pkt) {
	gdb.error_strings = true;
	return send_ok();
}

// ---- QListThreadsInStopReply packet ------------------------------------------------------------

static sends_a_packet
gdb_pkt__QListThreadsInStopReply(struct packet *pkt) {
	gdb.list_threads_in_stop_reply = true;
	return send_ok();
}

// ---- QNonStop packet ---------------------------------------------------------------------------

static sends_a_packet
gdb_pkt__QNonStop(struct packet *pkt) {
	return gdb_pkt__unknown();
#if 0
	char enable = 0;
	bool ok = pkt_read_char(pkt, &enable)
		&& pkt_empty(pkt);
	if (!ok) {
		return send_error_bad_packet("QNonStop");
	}
	if (enable != '0' && enable != '1') {
		return send_error_bad_packet("QNonStop");
	}
	if (enable == '0') {
		// Switch to all-stop mode.
		gdb.non_stop.enabled = false;
	} else if (enable == '1') {
		// Switch to non-stop mode.
		gdb.non_stop.enabled = true;
	}
	// Common initializations.
	gdb.all_stop.stop_reply_deferred = false;
	gdb.non_stop.stopped = 0;
	gdb.non_stop.queue   = 0;
	gdb.non_stop.pending = 0;
	return send_ok();
#endif
}

// ---- Q packet ----------------------------------------------------------------------------------

static const struct dispatch Q_dispatch[] = {
	{ "EnableErrorStrings", '$', gdb_pkt__QEnableErrorStrings },
	{ "ListThreadsInStopReply", '$', gdb_pkt__QListThreadsInStopReply },
	{ "NonStop", ':', gdb_pkt__QNonStop },
};

static sends_a_packet
gdb_pkt__Q(struct packet *pkt) {
	return pkt_dispatch(Q_dispatch, DISPATCH_COUNT(Q_dispatch), pkt, gdb_pkt__unknown);
}

// ---- vStopped packet ---------------------------------------------------------------------------

static sends_a_packet
gdb_pkt__vStopped(struct packet *pkt) {
	// If we're in all-stop mode, unknown.
	if (!gdb.non_stop.enabled) {
		return gdb_pkt__unknown();
	}
	// We received the ack, so move the CPU from pending to stopped.
	gdb.non_stop.stopped |= gdb.non_stop.pending;
	gdb.non_stop.pending = 0;
	// Send the next stop reply packet in the sequence.
	return non_stop__send_stop_reply_packet(true);
}

// ---- vCont? packet -----------------------------------------------------------------------------

static sends_a_packet
gdb_pkt__vCont_questionmark(struct packet *pkt) {
	if (!pkt_empty(pkt)) {
		return gdb_pkt__unknown();
	}
	// We support continue (c), step (s), and stop (t).
	return send_string_packet("vCont;c;s;t");
}

// ---- vCont packet ------------------------------------------------------------------------------

static sends_a_packet
gdb_pkt__vCont(struct packet *pkt) {
	// First handle the prefix packet "vCont?".
	bool is_query = pkt_read_match(pkt, "?");
	if (is_query) {
		return gdb_pkt__vCont_questionmark(pkt);
	}
	// We can't have zero actions.
	if (pkt_empty(pkt)) {
		return send_error_bad_packet("vCont");
	}
	// Each action is of the form ";action[:thread-id]". The earliest action matching a CPU is
	// the one that is applied.
	char cpu_action[CPU_COUNT] = {};
	while (!pkt_empty(pkt)) {
		char action = 0;
		bool ok = pkt_read_match(pkt, ";")
			&& pkt_read_char(pkt, &action);
		if (!ok) {
			return send_error_bad_packet("vCont");
		}
		if (action != 'c' && action != 's' && action != 't') {
			return send_error_bad_packet("vCont");
		}
		bool have_thread = pkt_read_match(pkt, ":");
		if (!have_thread) {
set_action_for_all_cpus:
			for (int cpu_id = 0; cpu_id < CPU_COUNT; cpu_id++) {
				if (cpu_action[cpu_id] == 0) {
					cpu_action[cpu_id] = action;
				}
			}
			continue;
		}
		int cpu_id;
		ok = pkt_read_thread_id(pkt, &cpu_id);
		if (!ok || cpu_id == INVALID_CPU) {
			return send_error_bad_packet("vCont");
		}
		if (cpu_id == -1) {
			goto set_action_for_all_cpus;
		}
		if (cpu_action[cpu_id] == 0) {
			cpu_action[cpu_id] = action;
		}
	}
	// Now that we've parsed all the actions, it's time to apply them. Note that in non-stop
	// mode, a thread is considered running until GDB acknowledges the stop reply packet with a
	// "vStopped" packet. (However, we currently don't distinguish between halted and stopped
	// CPUs in non-stop mode.)
	for (int cpu_id = 0; cpu_id < CPU_COUNT; cpu_id++) {
		char action = cpu_action[cpu_id];
		if (action == 'c') {
			// Continue. This will be ignored for non-halted CPUs.
			gdb_resume_cpu(cpu_id);
		} else if (action == 's') {
			// Step. This will be ignored for non-halted CPUs.
			gdb_step_cpu(cpu_id);
		} else if (action == 't') {
			// Stop. This will be ignored for halted CPUs.
			gdb_interrupt_cpu(cpu_id);
		}
	}
	// Send a stop-reply packet at the appropriate time. In all-stop mode, this will defer
	// replying until we observe a stop.
	return send_stop_reply();
}

// ---- vCtrlC packet -----------------------------------------------------------------------------

static sends_a_packet
gdb_pkt__vCtrlC(struct packet *pkt) {
	return interrupt();
}

// ---- v packet ----------------------------------------------------------------------------------

static const struct dispatch v_dispatch[] = {
	{ "Stopped", '$', gdb_pkt__vStopped },
	{ "Cont", 0, gdb_pkt__vCont },
	{ "CtrlC", '$', gdb_pkt__vCtrlC },
};

static sends_a_packet
gdb_pkt__v(struct packet *pkt) {
	return pkt_dispatch(v_dispatch, DISPATCH_COUNT(v_dispatch), pkt, gdb_pkt__unknown);
}

// ---- x packet ----------------------------------------------------------------------------------

static sends_a_packet
gdb_pkt__x(struct packet *pkt) {
	uint64_t address;
	uint64_t length;
	bool ok = pkt_read_hex_u64(pkt, &address)
		&& pkt_read_match(pkt, ",")
		&& pkt_read_hex_u64(pkt, &length)
		&& pkt_empty(pkt);
	if (!ok) {
		return send_error_bad_packet("x");
	}
	if (address == 0 && length == 0) {
		return send_ok();
	}
	uint8_t data[GDB_RSP_MAX_PACKET_SIZE];
	if (length > sizeof(data)) {
		return send_error_invalid_length("x");
	}
	size_t read = gdb_stub_read_memory(gdb.current_cpu, address, data, length);
	if (read == 0 && length > 0) {
		return send_error_invalid_address("x", address);
	}
	return send_packet_data(data, length);
}

// ---- X packet ----------------------------------------------------------------------------------

static sends_a_packet
gdb_pkt__X(struct packet *pkt) {
	uint64_t address;
	uint64_t length;
	const void *data;
	size_t size;
	bool ok = pkt_read_hex_u64(pkt, &address)
		&& pkt_read_match(pkt, ",")
		&& pkt_read_hex_u64(pkt, &length)
		&& pkt_read_match(pkt, ":")
		&& pkt_read_data(pkt, &data, &size)
		&& size == length;
	if (!ok) {
		return send_error_bad_packet("X");
	}
	if (length > 0) {
		size_t written = gdb_stub_write_memory(gdb.current_cpu, address, data, length);
		if (written != length) {
			return send_error_invalid_address("X", address + written);
		}
	}
	return send_ok();
}

// ---- z packet ----------------------------------------------------------------------------------

static bool
parse_z_base(struct packet *pkt, uint64_t *type, uint64_t *address, uint64_t *kind) {
	return pkt_read_hex_u64(pkt, type)
		&& pkt_read_match(pkt, ",")
		&& pkt_read_hex_u64(pkt, address)
		&& pkt_read_match(pkt, ",")
		&& pkt_read_hex_u64(pkt, kind);
}

static sends_a_packet
clear_hardware_breakpoint(uint64_t address, uint64_t kind) {
	if (kind != sizeof(uint32_t) && kind != 0) {
		return send_error_bad_packet("z");
	}
	// Remove a hardware breakpoint at the specified address on all CPUs. We ignore whether the
	// operation succeeded.
	gdb_stub_clear_hardware_breakpoint(address);
	return send_ok();
}

static sends_a_packet
clear_hardware_watchpoint(uint64_t type, uint64_t address, uint64_t kind) {
	// Clear a hardware watchpoint at the specified address on all CPUs. The kind parameter is
	// the size of the watchpoint. We ignore whether the operation succeeded.
	size_t size = kind;
	gdb_stub_clear_hardware_watchpoint(address, size, type);
	return send_ok();
}

static sends_a_packet
gdb_pkt__z(struct packet *pkt) {
	uint64_t type;
	uint64_t address;
	uint64_t kind;
	bool ok = parse_z_base(pkt, &type, &address, &kind)
		&& pkt_empty(pkt);
	if (!ok) {
		return send_error_bad_packet("z");
	}
	switch (type) {
		case 1:	// Hardware breakpoint.
			return clear_hardware_breakpoint(address, kind);
		case 2:	// Write watchpoint.
			return clear_hardware_watchpoint('w', address, kind);
		case 3:	// Read watchpoint.
			return clear_hardware_watchpoint('r', address, kind);
		case 4:	// Access watchpoint.
			return clear_hardware_watchpoint('a', address, kind);
		default:
			return gdb_pkt__unknown();
	}
}

// ---- Z packet ----------------------------------------------------------------------------------

static sends_a_packet
set_hardware_breakpoint(uint64_t address, uint64_t kind, struct packet *pkt) {
	if (!pkt_empty(pkt)) {
		// For now, we don't handle cond_list or cmds.
		return send_error_bad_packet("Z");
	}
	if (kind != sizeof(uint32_t) && kind != 0) {
		return send_error_bad_packet("Z");
	}
	// Add a hardware breakpoint at the specified address on all CPUs.
	bool ok = gdb_stub_set_hardware_breakpoint(address);
	if (!ok) {
		return send_error_add_breakpoint("Z", address);
	}
	return send_ok();
}

static sends_a_packet
set_hardware_watchpoint(char type, uint64_t address, uint64_t kind, struct packet *pkt) {
	if (!pkt_empty(pkt)) {
		return send_error_bad_packet("Z");
	}
	// Add a hardware watchpoint at the specified address on all CPUs. The kind parameter is
	// the size of the watchpoint.
	size_t size = kind;
	bool ok = gdb_stub_set_hardware_watchpoint(address, size, type);
	if (!ok) {
		return send_error_add_breakpoint("Z", address);
	}
	return send_ok();
}

static sends_a_packet
gdb_pkt__Z(struct packet *pkt) {
	uint64_t type;
	uint64_t address;
	uint64_t kind;
	bool ok = parse_z_base(pkt, &type, &address, &kind);
	if (!ok) {
		return send_error_bad_packet("Z");
	}
	switch (type) {
		case 1:	// Hardware breakpoint.
			return set_hardware_breakpoint(address, kind, pkt);
		case 2:	// Write watchpoint.
			return set_hardware_watchpoint('w', address, kind, pkt);
		case 3:	// Read watchpoint.
			return set_hardware_watchpoint('r', address, kind, pkt);
		case 4:	// Access watchpoint.
			return set_hardware_watchpoint('a', address, kind, pkt);
		default:
			return gdb_pkt__unknown();
	}
}

// ---- _M packet ---------------------------------------------------------------------------------

static sends_a_packet
gdb_pkt___M(struct packet *pkt) {
	uint64_t size;
	bool ok = pkt_read_hex_u64(pkt, &size)
		&& pkt_read_match(pkt, ",")
		&& !pkt_empty(pkt);
	if (!ok) {
		return send_error_bad_packet("_M");
	}
	bool r = pkt_read_match(pkt, "r");
	bool w = pkt_read_match(pkt, "w");
	bool x = pkt_read_match(pkt, "x");
	ok = pkt_empty(pkt);
	if (!ok) {
		return send_error_bad_packet("_M");
	}
	int perm = (!!r << 2) | (!!w << 1) | (!!x << 0);
	uint64_t addr = gdb_stub_allocate_jit_memory(size, perm);
	if (addr == 0) {
		return send_error_jit_allocate("_M", size);
	}
	char buffer[GDB_RSP_MAX_PACKET_SIZE];
	struct packet reply = PACKET_WITH_DATA(buffer, sizeof(buffer));
	pkt_sprintf(&reply, "%llx", addr);
	return send_packet(&reply);
}

// ---- _m packet ---------------------------------------------------------------------------------

static sends_a_packet
gdb_pkt___m(struct packet *pkt) {
	uint64_t addr;
	bool ok = pkt_read_hex_u64(pkt, &addr)
		&& pkt_empty(pkt);
	if (!ok) {
		return send_error_bad_packet("_m");
	}
	ok = gdb_stub_deallocate_jit_memory(addr);
	if (!ok) {
		return send_error_jit_deallocate("_m", addr);
	}
	return send_ok();
}

// ---- _ packet ----------------------------------------------------------------------------------

static sends_a_packet
gdb_pkt__underscore(struct packet *pkt) {
	char op = 0;
	pkt_read_char(pkt, &op);
	switch (op) {
		case 'M':
			return gdb_pkt___M(pkt);
		case 'm':
			return gdb_pkt___m(pkt);
	}
	return gdb_pkt__unknown();
}

// ---- Process an RSP packet from GDB ------------------------------------------------------------

static sends_a_packet
gdb_process_packet_internal(struct packet *pkt) {
	if (pkt_empty(pkt)) {
		goto unknown;
	}
	char ch = 0;
	pkt_read_char(pkt, &ch);
	switch (ch) {
		case '\x03':
			return gdb_pkt__ctrl_c(pkt);
		case '?':
			return gdb_pkt__questionmark(pkt);
		case 'c':
			return gdb_pkt__c(pkt);
		case 'g':
			return gdb_pkt__g(pkt);
		case 'G':
			return gdb_pkt__G(pkt);
		case 'H':
			return gdb_pkt__H(pkt);
		case 'k':
			return gdb_pkt__k(pkt);
		case 'm':
			return gdb_pkt__m(pkt);
		case 'M':
			return gdb_pkt__M(pkt);
		case 'p':
			return gdb_pkt__p(pkt);
		case 'P':
			return gdb_pkt__P(pkt);
		case 'q':
			return gdb_pkt__q(pkt);
		case 'Q':
			return gdb_pkt__Q(pkt);
		case 'v':
			return gdb_pkt__v(pkt);
		case 'x':
			return gdb_pkt__x(pkt);
		case 'X':
			return gdb_pkt__X(pkt);
		case 'z':
			return gdb_pkt__z(pkt);
		case 'Z':
			return gdb_pkt__Z(pkt);
		case '_':
			return gdb_pkt__underscore(pkt);
	}
unknown:
	return gdb_pkt__unknown();
}

void
gdb_process_packet(void *data, size_t size) {
	struct packet pkt = PACKET_WITH_DATA(data, size);
	gdb_process_packet_internal(&pkt);
}

// ---- Handle CPU halts and send packets to GDB --------------------------------------------------

void
gdb_process_cpu_halts(uint32_t halted_mask) {
	// In non-stop mode, we want to begin a stop reply notification sequence containing all
	// these CPUs, or add these CPUs to an existing sequence.
	if (gdb.non_stop.enabled) {
		// Update the notification queue.
		non_stop__update_stop_reply_notification_queue(halted_mask);
		// If there is no outstanding notification sequence pending, send the first stop
		// reply notification.
		if (gdb.non_stop.pending == 0) {
			non_stop__send_stop_reply_packet(false);
		}
		// Otherwise, there is an outstanding stop reply notification or packet in a
		// notification sequence. (This could even be due to a "?" packet.) This
		// notification will be sent once we receive the "vStopped" acknowledgement from
		// GDB.
		return;
	}
	// In all-stop mode, if we're going to report a stop reply to GDB, we need to stop all the
	// other CPUs as well. The actual halt still happens asynchronously, so we will be notified
	// here again once those other CPUs halt too.
	gdb_interrupt();
	// In all-stop mode, only send the deferred stop reply once all the CPUs have halted.
	if (gdb.all_stop.stop_reply_deferred && gdb.halted == gdb.cpu_mask) {
		gdb.all_stop.stop_reply_deferred = false;
		// Send a stop reply for one of the halted CPUs. If we hit a breakpoint, then we
		// should have switched the current CPU to that CPU, so we should report it now.
		all_stop__send_stop_reply_packet();
	}
	// Otherwise, if we don't have a deferred stop reply or if not all the CPUs have halted
	// yet, do nothing.
}
