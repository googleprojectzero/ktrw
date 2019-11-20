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

#ifndef KTRR_BYPASS__H_
#define KTRR_BYPASS__H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * have_ktrr_bypass
 *
 * Description:
 * 	Checks whether a KTRR bypass is available for this platform. Only A11 devices are confirmed
 * 	to have the necessary debug registers accessible.
 */
bool have_ktrr_bypass(void);

/*
 * ktrr_bypass
 *
 * Description:
 * 	Disables KTRR and remaps the RoRgn to be writable.
 *
 * Implementation:
 * 	KTRR is disabled using the CoreSight External Debug registers along with a proprietary
 * 	register called DBGWRAP. These registers allow placing a CPU core into a debug state in
 * 	which register values can be inspected and modified and execution can be single-stepped. By
 * 	single-stepping through execution of the reset vector after a core resets, we can subvert
 * 	initialization of KTRR and specify a custom page table base to be written to TTBR1_EL1,
 * 	allowing the kernel to be remapped to new physical pages outside of the AMCC-protected
 * 	RoRgn.
 *
 * Limitations:
 * 	Note that these changes only persist while the device is plugged in and active; changes may
 * 	be lost (leaking memory and possibly leaving the system unstable) anytime after sleeping.
 * 	In particular, once the debug power domain is switched off, the debug registers will reset,
 * 	losing state which prevents the CPU cores from resetting. It is possible to work around
 * 	this restriction for a fully persistent KTRR bypass, but I have not implemented that here.
 */
void ktrr_bypass(void);

/*
 * ktrr_vm_protect
 *
 * Description:
 * 	Set virtual memory protection on an address range.
 *
 * 	This is stronger than kernel_vm_protect() since it can be used to make memory executable.
 */
void ktrr_vm_protect(uint64_t address, size_t size, int prot);

#endif
