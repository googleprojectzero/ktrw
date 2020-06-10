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

#include "gdb_stub/gdb_stub.h"

#include "debug.h"
#include "devicetree.h"
#include "jit_heap.h"
#include "kernel_extern.h"
#include "page_table.h"
#include "usb/usb.h"
#include "watchdog.h"

#include "third_party/boot_args.h"
#include "third_party/kmod.h"

// ---- Kernel symbols ----------------------------------------------------------------------------

typedef void (*thread_continue_t)(void *parameter, int wait_result);
typedef struct thread *thread_t;

KERNEL_EXTERN void _disable_preemption(void);
KERNEL_EXTERN void _enable_preemption(void);
KERNEL_EXTERN const struct mach_header_64 _mh_execute_header;
KERNEL_EXTERN struct boot_args const_boot_args;
KERNEL_EXTERN void IOSleep(unsigned milliseconds);
KERNEL_EXTERN void *kernel_map;
KERNEL_EXTERN int kernel_memory_allocate(void *map, void **address, size_t size, uintptr_t mask, int flags, int tag);
KERNEL_EXTERN int kernel_thread_start(thread_continue_t continuation, void *parameter, thread_t *thread);
KERNEL_EXTERN size_t ml_nofault_copy(const void *vsrc, void *vdst, size_t size);
KERNEL_EXTERN void thread_deallocate(thread_t thread);
KERNEL_EXTERN void panic(const char *str, ...);

// ---- CPU debugging -----------------------------------------------------------------------------

static bool
debug_cpu_execute_instruction(int cpu_id, uint32_t instruction) {
	rEDITR(cpu_id) = instruction;
	for (size_t i = 0; i < 40; i++) {
		uint32_t edscr = rEDSCR(cpu_id);
		if (edscr & EDSCR_ERR) {
			break;
		}
		if (edscr & EDSCR_ITE) {
			return true;
		}
	}
	rEDRCR(cpu_id) = EDRCR_CSE;
	return false;
}

static uint64_t
debug_cpu_read_dtr(int cpu_id) {
	uint64_t dtrrx = rDBGDTRRX(cpu_id);
	uint64_t dtrtx = rDBGDTRTX(cpu_id);
	return (dtrrx << 32) | dtrtx;
}

static void
debug_cpu_write_dtr(int cpu_id, uint64_t value) {
	rDBGDTRTX(cpu_id) = (value >> 32) & 0xffffffff;
	rDBGDTRRX(cpu_id) = value & 0xffffffff;
}

static void
debug_cpu_halt(int cpu_id) {
	uint64_t dbgwrap = rDBGWRAP(cpu_id);
	if ((dbgwrap & DBGWRAP_CpuIsHalted) == 0) {
		rDBGWRAP(cpu_id) = dbgwrap | DBGWRAP_Halt;
	}
}

static void
debug_cpu_restart(int cpu_id) {
	uint64_t dbgwrap = rDBGWRAP(cpu_id);
	rDBGWRAP(cpu_id) = (dbgwrap & ~DBGWRAP_Halt) | DBGWRAP_Restart;
}

static void
debug_cpu_disable_reset(int cpu_id) {
	uint64_t dbgwrap = rDBGWRAP(cpu_id);
	rDBGWRAP(cpu_id) = dbgwrap | DBGWRAP_DisableReset;
}

static void
debug_cpu_wait_for_halt(int cpu_id) {
	// Wait for the halt to show up in DBGWRAP.
	for (;;) {
		if (rDBGWRAP(cpu_id) & DBGWRAP_CpuIsHalted) {
			break;
		}
	}
	// Wait for the halt to show up in EDPRSR. This shouldn't be necessary but it's helpful to
	// know that both registers agree.
	for (;;) {
		if (rEDPRSR(cpu_id) & EDPRSR_HALTED) {
			break;
		}
	}
	// Unlock the OS Lock to enable debug access.
	rOSLAR(cpu_id) = 0;
}

static void
debug_cpu_set_single_step(int cpu_id) {
	uint32_t edecr = rEDECR(cpu_id);
	if (!(edecr & EDECR_SS)) {
		rEDECR(cpu_id) = edecr | EDECR_SS;
	}
}

static void
debug_cpu_clear_single_step(int cpu_id) {
	uint32_t edecr = rEDECR(cpu_id);
	if (edecr & EDECR_SS) {
		rEDECR(cpu_id) = edecr & ~EDECR_SS;
	}
}

// ---- CPU state ---------------------------------------------------------------------------------

// The mask of CPUs being debugged.
static uint32_t cpu_mask;

// Returns true if the specified CPU ID corresponds to a core that is being debugged.
static bool
valid_cpu_id(int cpu_id) {
	return ((cpu_mask & (1 << cpu_id)) != 0);
}

// ---- Single stepping ---------------------------------------------------------------------------

// When single stepping in a debugger, it's really helpful if we don't receive any IRQs or FIQs
// that throw us into a totally unrelated piece of code. The external debug registers allow us to
// disable interrupts without modifying PSTATE.DAIF using the EDSCR.INTdis. The way to do this is
// the following:
//
//   1. On single step, set EDSCR.INTdis = 0b11 to disable interrupts to EL1.
//   2. On subsequent halt, clear EDSCR.INTdis.
//
// This should preserve behavior (except for the timing of the delivered exceptions).
//
// An alternative way to do this is to directly set PSTATE.DAIF via DSPSR_EL0 on each instruction
// step. This works as expected, but to ensure correct behavior, the executed instruction must be
// read and, in the case of MRS and MSR instructions accessing DAIF, post-processed.

// Disable interrupts on the specified CPU right before we're about to perform a single-stepping
// operation.
static void
disable_interrupts_before_single_step(int cpu_id) {
	// Set EDSCR.INTdis = 0b01.
	uint32_t edscr = rEDSCR(cpu_id);
	rEDSCR(cpu_id) = (edscr & ~EDSCR_INTdis(0b11)) | EDSCR_INTdis(0b11);
}

// Re-enable interrupts on the specified CPU right after halting from a single-stepping operation.
static void
restore_interrupts_after_single_step(int cpu_id) {
	// Set EDSCR.INTdis = 0b00.
	uint32_t edscr = rEDSCR(cpu_id);
	rEDSCR(cpu_id) = (edscr & ~EDSCR_INTdis(0b11)) | EDSCR_INTdis(0b00);
}

// ---- Handling interrupts -----------------------------------------------------------------------

// Unfortunately, there is an inconvenient and tricky to address race related to halting cores. We
// can't halt the rest of the system along with the AP, so other (non-AP) components continue to
// operate while the AP is halted. This is especially problematic with regards to interrupts. If we
// stop servicing IRQs on all AP cores, the AOP will panic. Thus, we must have at least 1 core
// servicing IRQs. However, if any core services an IRQ while another core is halted, then the IRQ
// might try to grab a lock held by the halted core, causing a spinlock timeout.
//
// The current implementation disables FIQs on the debugger core but allows IRQs, even when the
// other cores are halted. This makes the debugger fundamentally unstable: if we halt a core while
// it is holding an IRQ-critical lock, we will panic when an IRQ is delivered to the debugger core
// and the IRQ servicing code tries to take the same lock.
//
// In order to make things a bit more stable, we make the following assumption: when an
// IRQ-critical lock is being held, it probably makes sense that the core holding it has disabled
// IRQs. Thus, when halting a core, we'll do the following dance:
//
//   1. Since we're about to halt a core that might be holding an IRQ-critical lock, disable IRQs
//      on our own core.
//   2. Halt the debugged core.
//   3. Once the halt is detected, read DSPSR_EL0.DAIF to see whether or not IRQs are
//      disabled on the debugged core.
//   4. If IRQs are disabled on the debugged core, then it might be in an IRQ critical region.
//      a. Resume the debugged core.
//      b. Re-enable IRQs, since the debugged core is no longer halted.
//      c. Wait a small amount of time.
//      d. Go back to step 1.
//   5. Otherwise, if IRQs are not disabled on the debugged core, then the debugged core is
//      probably not in an IRQ critical region. Re-enable IRQs on our own core.
//
// A more reliable but more invasive approach would be to check both the IRQ/FIQ status and the
// currently running thread's preemption status, only halting once interrupts and preemption are
// enabled. However, so far this approach seems to work pretty well in practice.
//
// As an additional optimization, we definitely want to handle the case where a core is sitting in
// its idle loop with interrupts disabled. Otherwise, it can take a significant amount of time to
// halt all the cores. To do this generically, we'll assume that even if the debugged core is
// halted with IRQs disabled, if it's just after a WFI instruction, then it's probably a safe spot
// to halt.

// A count of how many times we need to disable interrupts on the debugger CPU.
static int debugger_disable_interrupts_count = 0;

// A mask of which CPUs have been issued an interrupt-safe halt. These CPUs have an outstanding IRQ
// disable on the debugger core that may need to be cleared.
static uint32_t interrupt_safe_halt_in_progress = 0;

// A mask of which CPUs are currently running and pending an interrupt-safe halt. We attempted to
// halt these CPUs before but restarted them because it didn't look safe to halt there.
static uint32_t retry_interrupt_safe_halt = 0;

// A cache of known-safe places to halt a CPU even if interrupts are disabled. We want to have this
// cache because reading the instruction from memory could be expensive and we want safely halting
// other cores after a breakpoint or watchpoint event to be as fast as possible.
#define CACHED_INTERRUPT_SAFE_HALT_PC_CAPACITY	2
static uint64_t cached_interrupt_safe_halt_pcs[CACHED_INTERRUPT_SAFE_HALT_PC_CAPACITY];
static unsigned cached_interrupt_safe_halt_pc_count = 0;

// Disable interrupts on the debugger CPU.
static void
debugger_disable_interrupts() {
	int old_count = debugger_disable_interrupts_count;
	debugger_disable_interrupts_count++;
	if (old_count == 0) {
		asm volatile("msr DAIFSet, 0x2");
	}
}

// Re-enable interrupts on the debugger CPU.
static void
debugger_enable_interrupts() {
	int old_count = debugger_disable_interrupts_count;
	debugger_disable_interrupts_count--;
	if (old_count == 1) {
		asm volatile("msr DAIFClr, 0x2");
	}
}

// Disable interrupts to the debugger in order to halt the specified CPU. This function can safely
// be called multiple times for the same CPU, and only the first call will take effect until the
// corresponding call to debugger_enable_interrupts_for_halting_cpu().
static void
debugger_disable_interrupts_for_halting_cpu(int cpu_id) {
	if ((interrupt_safe_halt_in_progress & (1 << cpu_id)) == 0) {
		debugger_disable_interrupts();
		interrupt_safe_halt_in_progress |= (1 << cpu_id);
	}
}

// Re-enable interrupts after having disabled interrupts in order to halt the specified CPU. This
// function can safely be called multiple times for the same CPU, and only the first call will take
// effect until the corresponding call to debugger_disable_interrupts_for_halting_cpu().
static void
debugger_enable_interrupts_for_halting_cpu(int cpu_id) {
	if (interrupt_safe_halt_in_progress & (1 << cpu_id)) {
		debugger_enable_interrupts();
		interrupt_safe_halt_in_progress &= ~(1 << cpu_id);
	}
}

// Try to halt the CPU in an IRQ-safe way. This should only be called the first time we try to halt
// a CPU; subsequent attempts should use retry_pending_interrupt_safe_halts(), which will re-halt
// all CPUs that have yet to be successfully halted.
static void
try_interrupt_safe_halt(int cpu_id) {
	// Disable IRQs on the debugger core. That way, if the core we're about to halt is holding
	// an IRQ-critical lock, we won't be interrupted with an IRQ that tries to grab that lock.
	// What prevents another, not-yet-halted core from trying to grab the lock? Nothing. But
	// that's not a problem, since that core will just spin until we resume the halted core and
	// it drops the lock.
	debugger_disable_interrupts_for_halting_cpu(cpu_id);
	// Now halt the core.
	debug_cpu_halt(cpu_id);
	// Clear the retry_interrupt_safe_halt bit since the core will no longer be running.
	retry_interrupt_safe_halt &= ~(1 << cpu_id);
}

// Internal function. Returns true if the halt is interrupt safe.
static bool
halt_is_interrupt_safe(int cpu_id) {
	// Read X0.
	debug_cpu_execute_instruction(cpu_id, 0xD5130400); // MSR DBGDTR_EL0, X0
	uint64_t x0 = debug_cpu_read_dtr(cpu_id);
	// Read DSPSR_EL0.
	debug_cpu_execute_instruction(cpu_id, 0xD53B4500); // MRS X0, DSPSR_EL0
	debug_cpu_execute_instruction(cpu_id, 0xD5130400); // MSR DBGDTR_EL0, X0
	uint64_t dspsr = debug_cpu_read_dtr(cpu_id);
	bool interrupts_enabled = (dspsr & 0xc0) == 0;
	// If interrupts are disabled, then this might be unsafe. Read PC for another data point.
	uint64_t pc = 0;
	if (!interrupts_enabled) {
		debug_cpu_execute_instruction(cpu_id, 0xD53B4520); // MRS X0, DLR_EL0
		debug_cpu_execute_instruction(cpu_id, 0xD5130400); // MSR DBGDTR_EL0, X0
		pc = debug_cpu_read_dtr(cpu_id);
	}
	// Restore X0.
	debug_cpu_write_dtr(cpu_id, x0);
	debug_cpu_execute_instruction(cpu_id, 0xD5330400); // MRS X0, DBGDTR_EL0
	// If interrupts are enabled, then this is probably safe.
	if (interrupts_enabled) {
		return true;
	}
	// Otherwise, this might be safe, but we might be in an IRQ critical region. Check if the
	// current PC is in our cache of safe places to halt even with interrupts disabled.
	for (unsigned i = 0; i < cached_interrupt_safe_halt_pc_count; i++) {
		if (pc == cached_interrupt_safe_halt_pcs[i]) {
			return true;
		}
	}
	// Read the previous instruction. If it is WFI, then probably we're in cpu_idle(), and it's
	// okay to halt. Of course, there's no guarantee that the previous instruction executed was
	// really the one at PC-4. But it's all heuristic anyway.
	uint32_t insn;
	size_t read = gdb_stub_read_memory(cpu_id, pc - sizeof(insn), &insn, sizeof(insn));
	if (read != sizeof(insn)) {
		return false;
	}
	if (insn == 0xD503207F) {
		goto safe;
	}
	// If interrupts are disabled and we weren't at a WFI instruction, assume this is an unsafe
	// place to halt.
	return false;
safe:
	// This looks like a safe place to halt. Add this PC to our cache of safe halt PCs.
	if (cached_interrupt_safe_halt_pc_count < CACHED_INTERRUPT_SAFE_HALT_PC_CAPACITY) {
		cached_interrupt_safe_halt_pcs[cached_interrupt_safe_halt_pc_count] = pc;
		cached_interrupt_safe_halt_pc_count++;
	}
	return true;
}

// Check if the CPU halted due to debug_cpu_halt() has halted at an IRQ-safe spot. If not, restart
// the CPU and flag it as halt-pending.
static bool
check_interrupt_safe_halt(int cpu_id) {
	// Check if the halt is safe.
	bool safe = halt_is_interrupt_safe(cpu_id);
	if (!safe) {
		// The core is not halted in a safe spot, so we need to restart the core to let it
		// make progress.
		debug_cpu_restart(cpu_id);
		// Mark this core as needing a future retry to halt it safely.
		retry_interrupt_safe_halt |= (1 << cpu_id);
	}
	// At this point, either the core is halted in a safe spot, or we have restarted the core
	// in hopes of halting it later. In either case, this core is no longer a blocker on taking
	// an IRQ.
	debugger_enable_interrupts_for_halting_cpu(cpu_id);
	return safe;
}

// Usually, when we issue a halt with try_interrupt_safe_halt(), it will be caught and state
// cleaned up in check_interrupt_safe_halt(). However, there are 2 ways this process could go
// wrong:
//
//   - If a breakpoint/watchpoint is hit before try_interrupt_safe_halt() can cause the halt, then
//     IRQs will be disabled, retry_interrupt_safe_halt will be clear,
//     interrupt_safe_halt_in_progress will be set, and check_interrupt_safe_halt() will not be
//     called. We should assume that we halted safely, so IRQs should be re-enabled.
//
//   - If a breakpoint/watchpoint is hit after check_interrupt_safe_halt() resumes a CPU, then
//     IRQs will be enabled, retry_interrupt_safe_halt will be set, interrupt_safe_halt_in_progress
//     will be clear, and check_interrupt_safe_halt() will not be called. We should assume that we
//     halted safely, so we need to clear retry_interrupt_safe_halt.
//
// The above description makes it sound like retry_interrupt_safe_halt and
// interrupt_safe_halt_in_progress are always complements. However, both will be 0 when a CPU has
// halted from the outset because of a breakpoint or watchpoint (i.e., before
// try_interrupt_safe_halt() was ever called). Thus, we actually do need both flags.
static void
halted_ignore_interrupt_safe_status(int cpu_id) {
	debugger_enable_interrupts_for_halting_cpu(cpu_id);
	retry_interrupt_safe_halt &= ~(1 << cpu_id);
}

// If we tried to halt a CPU but found it was in an IRQ critical region and had to resume it, retry
// halting it now. Returns true if any CPUs had been restarted with check_interrupt_safe_halt(),
// have just been halted again, and thus need to be re-checked.
static bool
retry_pending_interrupt_safe_halts() {
	if (retry_interrupt_safe_halt == 0) {
		return false;
	}
	for (int cpu_id = 0; cpu_id < CPU_COUNT; cpu_id++) {
		if (retry_interrupt_safe_halt & (1 << cpu_id)) {
			try_interrupt_safe_halt(cpu_id);
		}
	}
	return true;
}

// ---- Breakpoints -------------------------------------------------------------------------------

// We are using the hardware breakpoint registers for breakpoint support. This means we're limited
// to only 6 breakpoints on the iPhone 8.

// The number of available hardware breakpoints.
static unsigned hardware_breakpoint_count;

// The hardware breakpoints.
static uint64_t hardware_breakpoint_address[16];

// Initialize the hardware breakpoints to empty.
static void
init_hardware_breakpoints() {
	for (int n = 0; n < hardware_breakpoint_count; n++) {
		hardware_breakpoint_address[n] = -1;
	}
}

// Find the index of a hardware breakpoint.
static int
find_hardware_breakpoint_index(uint64_t address) {
	for (int n = 0; n < hardware_breakpoint_count; n++) {
		uint64_t breakpoint = hardware_breakpoint_address[n];
		if (breakpoint == address) {
			return n;
		}
	}
	return -1;
}

// ---- Watchpoints -------------------------------------------------------------------------------

// The hardware places some restrictions on the address ranges that can be watched with a
// watchpoint.
//
// If the watched address range is 8 or fewer bytes, then it must be contained within an 8-byte
// aligned region.
//
// Alternatively, if the watched address range is 8 or more bytes, then:
//
//   - the size of the watched range must be a power of two not more than 2^31 bytes (2 GB), and
//   - the address of the watched range must be aligned to the size.
//
// Ideally, in order to accomodate this hardware restriction while allowing the debugger to set
// semi-arbitrary watchpoint ranges, we'd transparently set the watchpoint on the smallest
// hardware-supported range that encompasses the soft range, and then if we receive a watchpoint
// halt, we'd check whether the address that triggered the hardware watchpoint actually falls
// within the soft range, restarting if not.
//
// Unfortunately, we quickly run into a problem with such a design: How do we check whether the
// address recorded in EDWAR is a true watchpoint hit? We know that EDWAR represents a valid hit to
// the hard watchpoint, but checking if it's valid for the soft watchpoint as well is challenging.
//
// According to the ARMv8 Architecture Reference Manual:
//
// 	The address recorded must be both:
// 		- From the inclusive range between:
// 			- The lowest address accessed by the memory access that triggered the
// 			  watchpoint.
// 			- The highest watchpointed address accessed by the memory access. A
// 			  watchpointed address is an address that the watchpoint is watching.
// 		- Within a naturally-aligned block of memory that is all of the following:
// 			- A power-of-two size.
// 			- No larger than the DC ZVA block size.
// 			- Contains a watchpointed address accessed by the memory access.
// 	The size of the block is IMPLEMENTATION DEFINED. There is no architectural means of
// 	discovering the size.
//
// Suppose we set a single watchpoint, perform a single memory access, and the watchpoint is
// triggered. Let's say that the accessed range is [A1, A2], and the watchpoint range is [W1, W2].
// Let's call the recorded EDWAR address W. The first requirement states that A1 <= W <= W2. This
// means that W will not lie after the range [W1, W2], but allows the possibility that W lies
// before it (but not before A1). The second requirement basically bounds how far W can be before
// W1. Conceptually, if you think of the block as a cache line, then this requirement says that W
// must lie in the same cache line as an intersection of [A1, A2] and [W1, W2].
//
// Unfortunately, this design makes it impossible for us to reliably tell whether a hard watchpoint
// should trigger a soft watchpoint. Even if we can match EDWAR to the corresponding hard
// watchpoint range [W1, W2], if EDWAR lies before the soft watchpoint range [S1, S2], we can't
// distinguish whether or not the access actually touched S1. (Similarly, the implementation could
// allow an access that spans S2 to report an address larger than S2, so long as it is not larger
// than W2.)
//
// You can confirm this behavior quite easily: Set a watchpoint on some address range [0x0ff0,
// 0x1000], and perform the access [0x0fe4, 0x0ff4] using a LDP instruction. You'll find that EDWAR
// is set to 0x0fe4, which is outside the hard watchpoint range. There is no way to get the size of
// the actual access that triggered the watchpoint, aside from disassembling the current
// instruction to check.
//
// Thus, in place of a better solution, we'll simply deny setting a watchpoint if it does not have
// a valid hardware representation. This means that certain useful operations, for example watching
// the address range spanned by a heap allocation, will be impossible to do natively in LLDB with a
// single command.
//
// In practice, this is not too much of a concern. LLDB's "watchpoint set expression command" can't
// set watchpoints larger than 8 bytes anyway.

// The number of available watchpoints.
static unsigned hardware_watchpoint_count;

// The watchpoint ranges.
static uint64_t hardware_watchpoint_address[16];
static uint32_t hardware_watchpoint_size[16];
static char hardware_watchpoint_type[16];

// Mark a hardware watchpoint as empty.
static void
clear_hardware_watchpoint(int n) {
	hardware_watchpoint_address[n] = 0;
	hardware_watchpoint_size[n] = 0;
	hardware_watchpoint_type[n] = 0;
}

// Initialize the hardware watchpoints to empty.
static void
init_hardware_watchpoints() {
	for (int n = 0; n < hardware_watchpoint_count; n++) {
		clear_hardware_watchpoint(n);
	}
}

// Find the index of a hardware watchpoint. For simplicity we only consider exact matches of
// address and size, and ignore the watchpoint type.
static int
find_hardware_watchpoint_index(uint64_t address, size_t size, char type) {
	for (int n = 0; n < hardware_watchpoint_count; n++) {
		uint64_t wp_address = hardware_watchpoint_address[n];
		uint32_t wp_size = hardware_watchpoint_size[n];
		uint32_t wp_type = hardware_watchpoint_type[n];
		if (wp_address == address && wp_size == size && wp_type == type) {
			return n;
		}
	}
	return -1;
}

// Watchpoints must be address-aligned and size-aligned. This routine computes the log base 2 of
// the watchpoint alignment needed for the specified address range.
static int
hardware_watchpoint_alignment(uint64_t address, uint64_t size) {
	if (size <= 1) {
		return 0;
	}
	uint64_t start = address;
	uint64_t end = start + size - 1;
	// We can compute the smallest power of two for which the address range is entirely contained
	// in a multiple of that power of two based on the XOR of the start and inclusive end
	// addresses.
	uint64_t xor = start ^ end;
	// Now, find the next power of two greater than the XOR. We can do this by counting the
	// number of leading zeros.
	unsigned alignment = 8 * sizeof(long long) - __builtin_clzll(xor);
	if (alignment > 31) {
		return -1;
	}
	return alignment;
}

// Find the watchpoint address matching the given memory access address. The memory access could be
// before the watchpoint address range. In that case, we return the address of the watchpoint
// closest to the access.
static uint64_t
find_matching_hardware_watchpoint_address(uint64_t access) {
	uint64_t w_closest = -1;
	for (int n = 0; n < hardware_watchpoint_count; n++) {
		size_t w_size = hardware_watchpoint_size[n];
		if (w_size == 0) {
			continue;
		}
		uint64_t w_address = hardware_watchpoint_address[n];
		if (w_address <= access && access + 1 <= w_address + w_size) {
			return access;
		}
		if (access < w_address && w_address < w_closest) {
			w_closest = w_address;
		}
	}
	return w_closest;
}

// Retrieve the address of the hardware watchpoint hit.
static uint64_t
hardware_watchpoint_halt_address(int cpu_id) {
	uint64_t access_lo = rEDWAR_lo(cpu_id);
	uint64_t access_hi = rEDWAR_hi(cpu_id);
	uint64_t access = (access_hi << 32) | access_lo;
	return find_matching_hardware_watchpoint_address(access);
}

// ---- GDB stub functions ------------------------------------------------------------------------

void
gdb_stub_reset_state() {
	jit_heap_reset();
	init_hardware_breakpoints();
	init_hardware_watchpoints();
}

size_t
gdb_stub_serial_read(void *data, size_t size) {
	return usb_read(data, size);
}

size_t
gdb_stub_serial_write(const void *data, size_t size) {
	return usb_write(data, size);
}

bool
gdb_stub_set_hardware_breakpoint(uint64_t address) {
	// Verify the alignment of the address.
	if (address & 0x3) {
		return false;
	}
	// Find the slot in which to place the breakpoint.
	int n = find_hardware_breakpoint_index(-1);
	if (n < 0) {
		return false;
	}
	// Set the breakpoint.
	hardware_breakpoint_address[n] = address;
	uint32_t dbgbcr = (0 << 24)	// RES0 [31:24]
		| (0 << 20)	// BT [23:20]
		| (0 << 16)	// LBN [19:16]
		| (0 << 16)	// SSC [15:14]
		| (0 << 13)	// HMC [13]
		| (0 << 9)	// RES0 [12:9]
		| (0xf << 5)	// BAS [8:5]
		| (0 << 3)	// RES0 [4:3]
		| (0x3 << 1)	// PMC [2:1]
		| (0x1 << 0);	// E [0]
	for (int cpu_id = 0; cpu_id < CPU_COUNT; cpu_id++) {
		if (valid_cpu_id(cpu_id)) {
			rDBGBCR(cpu_id, n) = dbgbcr;
			rDBGBVR(cpu_id, n) = address;
		}
	}
	return true;
}

bool
gdb_stub_clear_hardware_breakpoint(uint64_t address) {
	int n = find_hardware_breakpoint_index(address);
	if (n < 0) {
		return false;
	}
	hardware_breakpoint_address[n] = -1;
	for (int cpu_id = 0; cpu_id < CPU_COUNT; cpu_id++) {
		if (valid_cpu_id(cpu_id)) {
			rDBGBCR(cpu_id, n) = 0;
			rDBGBVR(cpu_id, n) = 0;
		}
	}
	return true;
}

bool
gdb_stub_set_hardware_watchpoint(uint64_t address, size_t size, char type) {
	// Find the slot in which to place the watchpoint.
	int n = find_hardware_watchpoint_index(0, 0, 0);
	if (n < 0) {
		return false;
	}
	// Find out the alignment needed to set a hardware watchpoint that encompasses the
	// specified address range.
	int align = hardware_watchpoint_alignment(address, size);
	if (align < 0) {
		return false;
	}
	// Validate the address and size against the supplied alignment.
	if (align <= 3) {
		// If we need less than 8 bytes of alignment, round up to 8 (we'll be using the BAS
		// method).
		align = 3;
	}
	uint64_t aligned_size = (1 << align);
	uint64_t aligned_address = address & ~(aligned_size - 1);
	if (align > 3) {
		// If we need more than 8 bytes of alignment, then verify that the alignment
		// matches the size and the address is aligned.
		if (address != aligned_address || size != aligned_size) {
			return false;
		}
	}
	// Compute MASK and BAS.
	uint32_t mask;
	uint32_t bas;
	if (align <= 3) {
		// If we need 8 bytes or less of alignment, use the BAS method.
		unsigned offset = address - aligned_address;
		unsigned bits = (1 << size) - 1;
		bas = bits << offset;
		mask = 0b00000;
	} else {
		// If we need more than 8 bytes of alignment, use the MASK method. Also ensure that
		// the supplied address was already aligned.
		bas = 0b11111111;
		mask = align;
	}
	// Compute LSC.
	uint32_t lsc;
	if (type == 'r') {
		lsc = 0b01;
	} else if (type == 'w') {
		lsc = 0b10;
	} else {
		lsc = 0b11;
	}
	// Set the watchpoint.
	hardware_watchpoint_address[n] = address;
	hardware_watchpoint_size[n] = size;
	hardware_watchpoint_type[n] = type;
	uint32_t dbgwcr = (0 << 29)	// RES0 [31:29]
		| (mask << 24)	// MASK [28:24]
		| (0 << 21)	// RES0 [23:21]
		| (0 << 20)	// WT [20]
		| (0 << 16)	// LBN [19:16]
		| (0 << 14)	// SSC [15:14]
		| (0 << 13)	// HMC [13]
		| (bas << 5)	// BAS [12:5]
		| (lsc << 3)	// LSC [4:3]
		| (0x3 << 1)	// PAC [2:1]
		| (0x1 << 0);	// E [0]
	for (int cpu_id = 0; cpu_id < CPU_COUNT; cpu_id++) {
		if (valid_cpu_id(cpu_id)) {
			rDBGWCR(cpu_id, n) = dbgwcr;
			rDBGWVR(cpu_id, n) = aligned_address;
		}
	}
	return true;
}

bool
gdb_stub_clear_hardware_watchpoint(uint64_t address, size_t size, char type) {
	int n = find_hardware_watchpoint_index(address, size, type);
	if (n < 0) {
		return false;
	}
	clear_hardware_watchpoint(n);
	for (int cpu_id = 0; cpu_id < CPU_COUNT; cpu_id++) {
		if (valid_cpu_id(cpu_id)) {
			rDBGWCR(cpu_id, n) = 0;
			rDBGWVR(cpu_id, n) = 0;
		}
	}
	return true;
}

void
gdb_stub_interrupt_cpu(int cpu_id) {
	// After the GDB stub calls this function, the CPU is still considered running until we
	// notify the GDB stub of the subsequent halt.
	try_interrupt_safe_halt(cpu_id);
	// Disable the watchdog timer again.
	disable_watchdog_timer();
}

void
gdb_stub_resume_cpu(int cpu_id) {
	// Once the GDB stub calls this function, for all intents and purposes, this CPU is running
	// and GDB will consider it so until we notify the GDB stub of a subsequent halt. Thus, if
	// EDPRSR.SDR is set, we need to report any subsequent halt.
	debug_cpu_clear_single_step(cpu_id);
	debug_cpu_restart(cpu_id);
	// Disable the watchdog timer again.
	disable_watchdog_timer();
}

void
gdb_stub_step_cpu(int cpu_id) {
	// Disable IRQ and FIQ interrupts on the core in preparation of single stepping.
	disable_interrupts_before_single_step(cpu_id);
	// Perform the step operation as usual.
	debug_cpu_set_single_step(cpu_id);
	debug_cpu_restart(cpu_id);
	// Disable the watchdog timer again.
	disable_watchdog_timer();
}

uint64_t
gdb_stub_cpu_pc(int cpu_id) {
	// Read X0.
	debug_cpu_execute_instruction(cpu_id, 0xD5130400); // MSR DBGDTR_EL0, X0
	uint64_t x0 = debug_cpu_read_dtr(cpu_id);
	// Read PC.
	debug_cpu_execute_instruction(cpu_id, 0xD53B4520); // MRS X0, DLR_EL0
	debug_cpu_execute_instruction(cpu_id, 0xD5130400); // MSR DBGDTR_EL0, X0
	uint64_t pc = debug_cpu_read_dtr(cpu_id);
	// Restore X0.
	debug_cpu_write_dtr(cpu_id, x0);
	debug_cpu_execute_instruction(cpu_id, 0xD5330400); // MRS X0, DBGDTR_EL0
	return pc;
}

void
gdb_stub_read_registers(int cpu_id, struct gdb_registers *registers) {
	// Read X0 - X30.
	for (unsigned x_reg = 0; x_reg < 31; x_reg++) {
		debug_cpu_execute_instruction(cpu_id, 0xD5130400 | x_reg); // MSR DBGDTR_EL0, Xn
		registers->x[x_reg].x = debug_cpu_read_dtr(cpu_id);
	}
	// Read SP.
	debug_cpu_execute_instruction(cpu_id, 0x910003E0); // MOV X0, SP
	debug_cpu_execute_instruction(cpu_id, 0xD5130400); // MSR DBGDTR_EL0, X0
	registers->sp = debug_cpu_read_dtr(cpu_id);
	// Read PC.
	debug_cpu_execute_instruction(cpu_id, 0xD53B4520); // MRS X0, DLR_EL0
	debug_cpu_execute_instruction(cpu_id, 0xD5130400); // MSR DBGDTR_EL0, X0
	registers->pc = debug_cpu_read_dtr(cpu_id);
	// Read CPSR.
	debug_cpu_execute_instruction(cpu_id, 0xD53B4500); // MRS X0, DSPSR_EL0
	debug_cpu_execute_instruction(cpu_id, 0xD5130400); // MSR DBGDTR_EL0, X0
	registers->cpsr = (uint32_t) debug_cpu_read_dtr(cpu_id);
	// Read V0 - V31.
	for (unsigned v_reg = 0; v_reg < 32; v_reg++) {
		debug_cpu_execute_instruction(cpu_id, 0x9E660000 | (v_reg << 5)); // FMOV X0, Dn
		debug_cpu_execute_instruction(cpu_id, 0xD5130400); // MSR DBGDTR_EL0, X0
		uint64_t v_lo = debug_cpu_read_dtr(cpu_id);
		debug_cpu_execute_instruction(cpu_id, 0x9EAE0000 | (v_reg << 5)); // FMOV X0, Vn.D[1]
		debug_cpu_execute_instruction(cpu_id, 0xD5130400); // MSR DBGDTR_EL0, X0
		uint64_t v_hi = debug_cpu_read_dtr(cpu_id);
		registers->v[v_reg].q[0] = v_lo;
		registers->v[v_reg].q[1] = v_hi;
	}
	// Read FPSR.
	debug_cpu_execute_instruction(cpu_id, 0xD53B4420); // MRS X0, FPSR
	debug_cpu_execute_instruction(cpu_id, 0xD5130400); // MSR DBGDTR_EL0, X0
	registers->fpsr = (uint32_t) debug_cpu_read_dtr(cpu_id);
	// Read FPCR.
	debug_cpu_execute_instruction(cpu_id, 0xD53B4400); // MRS X0, FPCR
	debug_cpu_execute_instruction(cpu_id, 0xD5130400); // MSR DBGDTR_EL0, X0
	registers->fpcr = (uint32_t) debug_cpu_read_dtr(cpu_id);
	// Restore X0.
	debug_cpu_write_dtr(cpu_id, registers->x[0].x);
	debug_cpu_execute_instruction(cpu_id, 0xD5330400); // MRS X0, DBGDTR_EL0
}

void
gdb_stub_write_registers(int cpu_id, const struct gdb_registers *registers) {
	// Write SP.
	debug_cpu_write_dtr(cpu_id, registers->sp);
	debug_cpu_execute_instruction(cpu_id, 0xD5330400); // MRS X0, DBGDTR_EL0
	debug_cpu_execute_instruction(cpu_id, 0x910003E0); // MOV X0, SP
	// Write PC.
	debug_cpu_write_dtr(cpu_id, registers->pc);
	debug_cpu_execute_instruction(cpu_id, 0xD5330400); // MRS X0, DBGDTR_EL0
	debug_cpu_execute_instruction(cpu_id, 0xD51B4520); // MSR DLR_EL0, X0
	// Write CPSR.
	debug_cpu_write_dtr(cpu_id, registers->cpsr);
	debug_cpu_execute_instruction(cpu_id, 0xD5330400); // MRS X0, DBGDTR_EL0
	debug_cpu_execute_instruction(cpu_id, 0xD51B4500); // MSR DSPSR_EL0, X0
	// Write V0 - V31.
	for (unsigned v_reg = 0; v_reg < 32; v_reg++) {
		uint64_t v_lo = registers->v[v_reg].q[0];
		uint64_t v_hi = registers->v[v_reg].q[1];
		debug_cpu_write_dtr(cpu_id, v_lo);
		debug_cpu_execute_instruction(cpu_id, 0xD5330400); // MRS X0, DBGDTR_EL0
		debug_cpu_execute_instruction(cpu_id, 0x9E670000 | v_reg); // FMOV Dn, X0
		debug_cpu_write_dtr(cpu_id, v_hi);
		debug_cpu_execute_instruction(cpu_id, 0xD5330400); // MRS X0, DBGDTR_EL0
		debug_cpu_execute_instruction(cpu_id, 0x9EAF0000 | v_reg); // FMOV Vn.D[1], X0
	}
	// Write FPSR.
	debug_cpu_write_dtr(cpu_id, registers->fpsr);
	debug_cpu_execute_instruction(cpu_id, 0xD5330400); // MRS X0, DBGDTR_EL0
	debug_cpu_execute_instruction(cpu_id, 0xD51B4420); // MSR FPSR, X0
	// Write FPCR.
	debug_cpu_write_dtr(cpu_id, registers->fpcr);
	debug_cpu_execute_instruction(cpu_id, 0xD5330400); // MRS X0, DBGDTR_EL0
	debug_cpu_execute_instruction(cpu_id, 0xD51B4400); // MSR FPCR, X0
	// Write X0 - X30.
	for (unsigned x_reg = 0; x_reg < 31; x_reg++) {
		debug_cpu_write_dtr(cpu_id, registers->x[x_reg].x);
		debug_cpu_execute_instruction(cpu_id, 0xD5330400 | x_reg); // MRS Xn, DBGDTR_EL0
	}
}

size_t
gdb_stub_read_memory(int cpu_id, uint64_t address, void *data, size_t length) {
	// TODO: This should handle the case where the CPU has a different TTBR1.
	return ml_nofault_copy((const void *)address, data, length);
}

size_t
gdb_stub_write_memory(int cpu_id, uint64_t address, const void *data, size_t length) {
	// TODO: This should handle the case where the CPU has a different TTBR1.
	return ml_nofault_copy(data, (void *)address, length);
}

uint64_t
gdb_stub_allocate_jit_memory(size_t size, int perm) {
	void *address = jit_heap_allocate(size, perm);
	return (uint64_t) address;
}

bool
gdb_stub_deallocate_jit_memory(uint64_t address) {
	return jit_heap_deallocate((void *) address);
}

// ---- Dynamic system configuration --------------------------------------------------------------

// Get the device tree.
static struct devicetree
get_devicetree() {
	const void *devicetree_data = const_boot_args.deviceTreeP;
	const size_t devicetree_size = const_boot_args.deviceTreeLength;
	return (struct devicetree) { devicetree_data, devicetree_size };
}

// Parse the device tree to determine the number of CPUs, the base address of each CPU's debug
// registers, and the base address of the watchdog timer registers.
static bool
parse_devicetree_info() {
	struct devicetree devicetree = get_devicetree();
	// We'll dynamically detect the available CPUs by looking up the nodes "cpu0", "cpu1", ...
	// in the device tree.
	unsigned cpu_count = 0;
	for (int cpu_id = 0; cpu_id < CPU_COUNT; cpu_id++) {
		// Build the CPU name. Because we only support platforms with up to 6 CPUs, this
		// method always works.
		char cpu_name[8] = "cpu0";
		cpu_name[3] += cpu_id;
		// Look up the device tree node with property "name" = "cpuN".
		struct devicetree_node node = devicetree_find_node_by_property(devicetree,
				"name", cpu_name);
		if (!devicetree_node_valid(node)) {
			break;
		}
		// We have another CPU. Look up the registers.
		struct devicetree_property reg_private = devicetree_node_get_property(node,
				"reg-private");
		if (reg_private.size != sizeof(uint64_t)) {
			gdb_stub_log("error: Could not parse the private register information "
					"for %s from the device tree", cpu_name);
			return false;
		}
		cpu_register_base[cpu_count] = *(uint64_t *)reg_private.data;
		cpu_count++;
	}
	// We need at least 2 CPUs in order to run the debugger.
	if (cpu_count < 2) {
		gdb_stub_log("error: %s%u %s detected", (cpu_count == 0 ? "" : "Only "),
				cpu_count, (cpu_count == 1 ? "CPU" : "CPUs"));
		return false;
	}
	// Build the CPU mask.
	cpu_mask = (1 << cpu_count) - 1;
	// Look up the watchdog timer node.
	struct devicetree_node node = devicetree_find_node_by_property(devicetree, "name", "wdt");
	if (!devicetree_node_valid(node)) {
		gdb_stub_log("error: Could not find the watchdog timer in the device tree");
		return false;
	}
	// Find the watchdog timer register info.
	struct devicetree_property reg = devicetree_node_get_property(node, "reg");
	if (reg.size != 4 * sizeof(uint64_t)) {
		gdb_stub_log("error: Could not parse the register information "
				"for %s from the device tree", "wdt");
		return false;
	}
	uint64_t wdt_reg = *(uint64_t *)reg.data;
	watchdog_timer_register_base = 0x200000000 + wdt_reg;
	return true;
}

// ---- Debug initialization ----------------------------------------------------------------------

// Get the CPU ID of the current CPU.
static int
get_current_cpu() {
	uint64_t mpidr_el1 = __builtin_arm_rsr64("MPIDR_EL1");
	return (mpidr_el1 & 0xff);
}

// Prepare the CPUs specified in cpu_mask for debugging.
static void
prepare_cpus_for_debugging() {
	// Enable debugging access on the CPUs.
	for (int cpu_id = 0; cpu_id < CPU_COUNT; cpu_id++) {
		if (valid_cpu_id(cpu_id)) {
			rEDLAR(cpu_id) = 0xC5ACCE55;
		}
	}
	for (int cpu_id = 0; cpu_id < CPU_COUNT; cpu_id++) {
		if (valid_cpu_id(cpu_id)) {
			while (rEDLSR(cpu_id) & EDLSR_SLK) {}
		}
	}
	// Halt all CPUs. We use the interrupt-safe halt routine to minimize the chance of
	// panicking the system. Also, set EDPRCR.CORENPDRQ to prevent the core power domain from
	// powering down.
	for (int cpu_id = 0; cpu_id < CPU_COUNT; cpu_id++) {
		if (valid_cpu_id(cpu_id)) {
			debug_cpu_disable_reset(cpu_id);
			try_interrupt_safe_halt(cpu_id);
		}
	}
	// Wait for all CPUs to halt safely.
	for (;;) {
		// Wait for each CPU to halt and check if the halt was safe.
		for (int cpu_id = 0; cpu_id < CPU_COUNT; cpu_id++) {
			if (valid_cpu_id(cpu_id)) {
				// Wait for halt.
				debug_cpu_wait_for_halt(cpu_id);
				// Check if the halt is safe. If it is not, the CPU will be
				// automatically restarted.
				check_interrupt_safe_halt(cpu_id);
			}
		}
		// Retry any halts that were not safe. This returns true if any CPUs have been
		// restarted by check_interrupt_safe_halt() and thus need to be checked again.
		bool recheck = retry_pending_interrupt_safe_halts();
		if (!recheck) {
			break;
		}
	}
	// Initialize each CPU for debugging.
	unsigned min_bp_count = 16;
	unsigned min_wp_count = 16;
	for (int cpu_id = 0; cpu_id < CPU_COUNT; cpu_id++) {
		if (valid_cpu_id(cpu_id)) {
			// Get the number of available breakpoints.
			uint32_t eddfr_lo = rEDDFR_lo(cpu_id);
			unsigned bp_count = (eddfr_lo >> 12) & 0xf;
			if (bp_count > 0) {
				bp_count += 1;
			}
			if (bp_count < min_bp_count) {
				min_bp_count = bp_count;
			}
			// Get the number of available watchpoints.
			unsigned wp_count = (eddfr_lo >> 20) & 0xf;
			if (wp_count > 0) {
				wp_count += 1;
			}
			if (wp_count < min_wp_count) {
				min_wp_count = wp_count;
			}
			// Get the current EDSCR value.
			uint32_t edscr = rEDSCR(cpu_id);
			// Set EDSCR.TDA so that a halting debug event is generated if the core
			// tries to access DBGBCR<n>_EL1, DBGBVR<n>_EL1, DBGWCR<n>_EL1, or
			// DBGWVR<n>_EL1.
			edscr |= EDSCR_TDA;
			// Set EDSCR.HDE to enable halting for breakpoints, watchpoints, and halt
			// instructions.
			edscr |= EDSCR_HDE;
			// Set EDSCR.
			rEDSCR(cpu_id) = edscr;
			// Read EDPRSR to clear EDPRSR.SDR.
			(void)rEDPRSR(cpu_id);
		}
	}
	// Initialize the number of available breakpoints and watchpoints.
	hardware_breakpoint_count = min_bp_count;
	hardware_watchpoint_count = min_wp_count;
	// Initialize the hardware breakpoints and watchpoints as empty.
	init_hardware_breakpoints();
	init_hardware_watchpoints();
}

// ---- Handling halt events ----------------------------------------------------------------------

// The mask of CPUs currently halted.
uint32_t halted_mask;

// Handle a CPU halt because of a breakpoint.
static void
handle_breakpoint(int cpu_id) {
	halted_ignore_interrupt_safe_status(cpu_id);
	gdb_stub_hit_hardware_breakpoint(cpu_id);
}

// Handle a CPU halt because of a watchpoint.
static void
handle_watchpoint(int cpu_id) {
	// Get the watchpoint address.
	uint64_t address = hardware_watchpoint_halt_address(cpu_id);
	// Ignore whether or not this halt is interrupt safe.
	halted_ignore_interrupt_safe_status(cpu_id);
	// Report this watchpoint halt to GDB.
	gdb_stub_hit_hardware_watchpoint(cpu_id, address);
}

// Handle a CPU halt because a single-step operation completed.
static void
handle_step(int cpu_id) {
	halted_ignore_interrupt_safe_status(cpu_id);
	// After completing a single step operation, restore interrupts to their true (if no
	// debugger were present) value.
	restore_interrupts_after_single_step(cpu_id);
	// Report this single-step halt to GDB.
	gdb_stub_did_step(cpu_id);
}

// Handle a CPU halt due to an attempt to access the debug registers. Unlike with breakpoints,
// watchpoints, and single-step, this is an internal event that we simply need to fix up on this
// one CPU.
static void
handle_software_debug_access(int cpu_id) {
	// Read X0.
	debug_cpu_execute_instruction(cpu_id, 0xD5130400); // MSR DBGDTR_EL0, X0
	uint64_t x0 = debug_cpu_read_dtr(cpu_id);
	// Read PC.
	debug_cpu_execute_instruction(cpu_id, 0xD53B4520); // MRS X0, DLR_EL0
	debug_cpu_execute_instruction(cpu_id, 0xD5130400); // MSR DBGDTR_EL0, X0
	uint64_t pc = debug_cpu_read_dtr(cpu_id);
	// TODO: Process the instruction rather than just skipping it!
	// Set PC = PC + 4.
	debug_cpu_write_dtr(cpu_id, pc + 4);
	debug_cpu_execute_instruction(cpu_id, 0xD5330400); // MRS X0, DBGDTR_EL0
	debug_cpu_execute_instruction(cpu_id, 0xD51B4520); // MSR DLR_EL0, X0
	// Restore X0.
	debug_cpu_write_dtr(cpu_id, x0);
	debug_cpu_execute_instruction(cpu_id, 0xD5330400); // MRS X0, DBGDTR_EL0
	// Resume the CPU after the offending instruction.
	debug_cpu_restart(cpu_id);
}

// Handle a CPU halt for any other reason (likely because gdb_stub_interrupt_cpu() was called).
static bool
handle_halt(int cpu_id) {
	// The CPU has halted due to a call to gdb_stub_interrupt_cpu(). We need to check whether
	// the CPU has halted in an interrupt-safe spot.
	bool safe = check_interrupt_safe_halt(cpu_id);
	if (!safe) {
		// If the halt is not safe, then the CPU has been automatically resumed. We'll need
		// to call retry_pending_interrupt_safe_halts() later to retry the halt.
		return false;
	}
	// If the halt is safe, simply report it.
	gdb_stub_did_halt(cpu_id);
	return true;
}

// Check for and handle a halt on the specified CPU.
static void
check_cpu(int cpu_id) {
	uint32_t cpu_bit = (1 << cpu_id);
	bool newly_halted = false;
	// We're primarily interested in 2 registers: EDPRSR and EDSCR. We check EDPRSR first,
	// since that tells us whether we'll need to notify the GDB stub.
	uint32_t edprsr = rEDPRSR(cpu_id);
	if (edprsr & EDPRSR_SDR) {
		halted_mask &= ~cpu_bit;
	}
	if (!(halted_mask & cpu_bit) && (edprsr & EDPRSR_HALTED)) {
		halted_mask |= cpu_bit;
		newly_halted = true;
	}
	// If we are not newly halted, there's no reason to notify the GDB stub.
	if (!newly_halted) {
		return;
	}
	// Since we're newly halted, unlock the OS Lock to enable debug access.
	rOSLAR(cpu_id) = 0;
	// Now we need to check EDSCR so that we can report the reason for the exception.
	uint32_t edscr = rEDSCR(cpu_id);
	// The bits we care about are EDSCR.STATUS, which contain the debug status.
	bool still_halted = true;
	uint32_t status = edscr & EDSCR_STATUS;
	switch (status) {
		case 0b000001:	// PE is restarting, exiting debug state.
		case 0b000010:	// PE is in Non-debug state.
			// We shouldn't observe this state. Clear the halted bit so that we catch
			// it next time.
			still_halted = false;
			break;
		case 0b000111:	// Breakpoint.
			handle_breakpoint(cpu_id);
			break;
		case 0b101011:	// Watchpoint.
			handle_watchpoint(cpu_id);
			break;
		case 0b011011:	// Halting step, normal.
		case 0b011111:	// Halting step, exclusive.
		case 0b111011:	// Halting step, no syndrome.
			handle_step(cpu_id);
			break;
		case 0b100011:	// OS Unlock Catch.
		case 0b100111:	// Reset Catch.
		case 0b110111:	// Exception Catch.
			// If we observe this state we should silently continue.
			debug_cpu_restart(cpu_id);
			break;
		case 0b110011:	// Software access to debug register.
			handle_software_debug_access(cpu_id);
			break;
		case 0b010011:	// External debug request.
		case 0b101111:	// HLT instruction.
			// There's no more specific reason we can report to the GDB stub.
			still_halted = handle_halt(cpu_id);
			break;
	}
	// If we're no longer halted, clear the halted bit.
	if (!still_halted) {
		halted_mask &= ~cpu_bit;
	}
}

// Check for and handle halts on all CPUs.
static void
check_cpus() {
	// If there were any pending interrupt-safe halts from last iteration, perform those now.
	// Doing this here means that we give each CPU a wide running window in the event that it
	// is halted in an unsafe spot, because unsafe halts are restarted in check_cpu().
	retry_pending_interrupt_safe_halts();
	// Now check each CPU to update halt state.
	for (int cpu_id = 0; cpu_id < CPU_COUNT; cpu_id++) {
		if (valid_cpu_id(cpu_id)) {
			check_cpu(cpu_id);
		}
	}
	// Now process the halts.
	gdb_stub_process_halts(halted_mask);
}

// ---- GDB stub thread ---------------------------------------------------------------------------

#define PAGE_SIZE	0x4000

// A thread function wrapper around gdb_stub_main().
static void
gdb_stub_thread(void *parameter, int wait_result) {
	// Sleep for a few seconds (the exact amount is configured during build, but defaults to 30
	// seconds) to allow the system to start up.
	if (KTRW_GDB_STUB_ACTIVATION_DELAY > 0) {
		IOSleep(KTRW_GDB_STUB_ACTIVATION_DELAY * 1000);
	}
	// Parse the device tree for basic system configuration.
	bool ok = parse_devicetree_info();
	if (!ok) {
		panic("Could not parse devicetree");
		return;
	}
	// Allocate device memory for the USB stack.
	void *usb_dma_page = NULL;
	kernel_memory_allocate(kernel_map, &usb_dma_page, PAGE_SIZE, PAGE_SIZE - 1, 0x8, 99);
	if (usb_dma_page == NULL) {
		panic("Could not allocate USB DMA memory");
		return;
	}
	// Allocate normal memory for the USB stack.
	void *usb_memory = NULL;
	kernel_memory_allocate(kernel_map, &usb_memory, USB_STACK_MEMORY_SIZE,
			PAGE_SIZE - 1, 0, 99);
	if (usb_memory == NULL) {
		panic("Could not allocate USB stack memory");
		return;
	}
	// Initialize early state for the USB stack.
	usb_init(usb_dma_page, usb_memory);
	// Allocate memory for the JIT heap.
	void *jit_heap = NULL;
	kernel_memory_allocate(kernel_map, &jit_heap, JIT_HEAP_SIZE, PAGE_SIZE - 1, 0, 99);
	if (jit_heap == NULL) {
		panic("Could not allocate JIT heap memory");
		return;
	}
	// Initialize the JIT heap.
	jit_heap_init(jit_heap);
	// Sleep for a bit. This lets the system reach idle state, from where we are much more
	// likely to safely enable the debugger.
	IOSleep(100);
	// Disable thread preemption. This is sufficient to pin the this thread to the current CPU,
	// but does not prevent the delivery of IRQ and FIQ interrupts.
	_disable_preemption();
	// We can't permanently disable IRQs (see "Handling interrupts"), but we can disable FIQs.
	asm volatile("msr DAIFSet, 0x1");
	// Initialize the TTBR0 page tables so that we can map physical memory. This must happen
	// after we disable preepmtion.
	ttbr0_page_tables_init();
	// Disable the watchdog timer, as we will be halting CPUs. This isn't 100% reliable, as the
	// watchdog timer seems to be periodically reenabled. As a workaround, I'm disabling it
	// again each time a CPU halts or is restarted. However, I still want to call it here so
	// that the registers get mapped before we interfere too much with normal system operation
	// by halting cores.
	disable_watchdog_timer();
	// Map the CoreSight External Debug and DBGWRAP registers.
	map_debug_registers();
	// Get the current CPU ID. This is the debugger CPU. All other CPUs will be debugged by
	// this one.
	int debug_cpu = get_current_cpu();
	cpu_mask &= ~(1 << debug_cpu);
	// Prepare all the other CPUs for debugging, including halting them.
	prepare_cpus_for_debugging();
	halted_mask = cpu_mask;
	// Now that other CPUs are halted, we can start the USB stack. This needs to be done with
	// interrupts disabled: we prevent USB IRQs by writing to a USB register, but until that
	// write occurs, an IRQ could arrive and mess up our USB initialization.
	debugger_disable_interrupts();
	usb_start();
	debugger_enable_interrupts();
	// Initialize GDB state.
	gdb_stub_init(cpu_mask, halted_mask);
	gdb_stub_set_mach_header(&_mh_execute_header);
	gdb_stub_set_hardware_watchpoint_count(hardware_watchpoint_count);
	// Enter the main loop. Ideally we'd have an event-driven system where the CPU sleeps until
	// either input becomes available over USB or a CPU halts. However, this will have to be
	// polling.
	for (;;) {
		// Check for halted CPUs.
		check_cpus();
		// Process the USB stack.
		usb_process();
		// Handle any input from GDB.
		gdb_stub_packet();
		// Commit to writing to USB. This is a separate step so that GDB RSP's "+" ACK is
		// coalesced with the subsequent packet data, making communication more efficient.
		usb_write_commit();
	}
	// We shouldn't reach this, but if we do, re-enable preemption and interrupts.
	asm volatile("msr DAIFClr, 0x1");
	_enable_preemption();
}

// ---- Entry -------------------------------------------------------------------------------------

KMOD_DECL(ktrw, KTRW_VERSION)

static int
ktrw_module_start(struct kmod_info *kmod, void *data) {
	thread_t thread;
	int kr = kernel_thread_start(gdb_stub_thread, NULL, &thread);
	if (kr != 0) {
		return 1;
	}
	thread_deallocate(thread);
	return 0;
}

static int
ktrw_module_stop(struct kmod_info *kmod, void *data) {
	// No stopping KTRW.
	return 1;
}
