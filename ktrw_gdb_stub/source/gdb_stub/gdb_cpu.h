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

#ifndef GDB_CPU__H_
#define GDB_CPU__H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// ---- Checking CPU state ------------------------------------------------------------------------

/*
 * valid_cpu_id
 *
 * Description:
 * 	Returns true if the CPU ID is valid.
 */
bool valid_cpu_id(int cpu_id);

/*
 * cpu_is_halted
 *
 * Description:
 * 	Returns true if the specified CPU is halted.
 */
bool cpu_is_halted(int cpu_id);

/*
 * cpu_is_running
 *
 * Description:
 * 	Returns true if the specified CPU is running.
 */
bool cpu_is_running(int cpu_id);

// ---- Interrupting and resuming CPUs ------------------------------------------------------------

/*
 * gdb_interrupt_cpu
 *
 * Description:
 * 	Asynchronously interrupt a CPU, if it is running.
 */
void gdb_interrupt_cpu(int cpu_id);

/*
 * gdb_resume_cpu
 *
 * Description:
 * 	Asynchronously resume a CPU, if it is halted.
 */
void gdb_resume_cpu(int cpu_id);

/*
 * gdb_interrupt
 *
 * Description:
 * 	Asynchronously interrupt all running CPUs.
 */
void gdb_interrupt(void);

/*
 * gdb_resume
 *
 * Description:
 * 	Asynchronously resume all halted CPUs.
 */
void gdb_resume(void);

/*
 * gdb_step_cpu
 *
 * Description:
 * 	Asynchronously single-step a CPU, if it is halted.
 */
void gdb_step_cpu(int cpu_id);

#endif
