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

#ifndef DEBUG__H_
#define DEBUG__H_

#include <stdint.h>

// The maximum number of CPUs.
#define MAX_CPU_COUNT	6

// The physical base address of the CPU registers. This should be initialized prior to mapping the
// debug registers.
extern uint64_t cpu_register_base[];

// The memory-mapped CoreSight External Debug registers, per CPU.
extern uint64_t external_debug_registers[];

// The memory-mapped DBGWRAP registers, per CPU.
extern uint64_t dbgwrap_registers[];

#define rEDECR(cpu)	*(volatile uint32_t *)(external_debug_registers[(cpu)] + 0x024)
#define rEDWAR_lo(cpu)	*(volatile uint32_t *)(external_debug_registers[(cpu)] + 0x030)
#define rEDWAR_hi(cpu)	*(volatile uint32_t *)(external_debug_registers[(cpu)] + 0x034)
#define rDBGDTRRX(cpu)	*(volatile uint32_t *)(external_debug_registers[(cpu)] + 0x080)
#define rEDITR(cpu)	*(volatile uint32_t *)(external_debug_registers[(cpu)] + 0x084)
#define rEDSCR(cpu)	*(volatile uint32_t *)(external_debug_registers[(cpu)] + 0x088)
#define rDBGDTRTX(cpu)	*(volatile uint32_t *)(external_debug_registers[(cpu)] + 0x08c)
#define rEDRCR(cpu)	*(volatile uint32_t *)(external_debug_registers[(cpu)] + 0x090)
#define rOSLAR(cpu)	*(volatile uint32_t *)(external_debug_registers[(cpu)] + 0x300)
#define rEDPRSR(cpu)	*(volatile uint32_t *)(external_debug_registers[(cpu)] + 0x314)
#define rDBGBVR(cpu, n)	*(volatile uint64_t *)(external_debug_registers[(cpu)] + 0x400 + 16 * n)
#define rDBGBCR(cpu, n)	*(volatile uint32_t *)(external_debug_registers[(cpu)] + 0x408 + 16 * n)
#define rDBGWVR(cpu, n)	*(volatile uint64_t *)(external_debug_registers[(cpu)] + 0x800 + 16 * n)
#define rDBGWCR(cpu, n)	*(volatile uint32_t *)(external_debug_registers[(cpu)] + 0x808 + 16 * n)
#define rEDDFR_lo(cpu)	*(volatile uint32_t *)(external_debug_registers[(cpu)] + 0xd28)
#define rEDDFR_hi(cpu)	*(volatile uint32_t *)(external_debug_registers[(cpu)] + 0xd2c)
#define rEDLAR(cpu)	*(volatile uint32_t *)(external_debug_registers[(cpu)] + 0xfb0)
#define rEDLSR(cpu)	*(volatile uint32_t *)(external_debug_registers[(cpu)] + 0xfb4)

#define rDBGWRAP(cpu)	*(volatile uint64_t *)(dbgwrap_registers[(cpu)] + 0x000)

#define EDECR_SS		(1 << 2)

#define EDSCR_ITE		(1 << 24)
#define EDSCR_INTdis(b)		(((b) & 0x3) << 22)
#define EDSCR_TDA		(1 << 21)
#define EDSCR_HDE		(1 << 14)
#define EDSCR_ERR		(1 << 6)
#define EDSCR_STATUS		(0x3f)

#define EDRCR_CSE		(1 << 2)

#define EDPRSR_SDR		(1 << 11)
#define EDPRSR_HALTED		(1 << 4)

#define EDLSR_SLI		(1 << 0)
#define EDLSR_SLK		(1 << 1)

#define DBGWRAP_Halt		(1uL << 31)
#define DBGWRAP_Restart		(1uL << 30)
#define DBGWRAP_HaltAfterReset	(1uL << 29)	// EDECR.RCE ?
#define DBGWRAP_CpuIsHalted	(1uL << 28)
#define DBGWRAP_DisableReset	(1uL << 26)	// EDPRCR.CORENPDRQ ?

/*
 * map_debug_registers
 *
 * Description:
 * 	Map the debug registers.
 */
void map_debug_registers(void);

#endif
