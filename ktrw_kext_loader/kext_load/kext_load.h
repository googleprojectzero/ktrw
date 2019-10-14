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

#ifndef KEXT_LOAD__H_
#define KEXT_LOAD__H_

#include <stdint.h>

/*
 * kext_load
 *
 * Description:
 * 	Dynamically load a Mach-O file into the kernel and call its entry point function. The
 * 	address of the kernel extension in kernel memory is returned.
 *
 * 	The "kext" file isn't a true kext in the sense of a macOS kernel extension. Rather, it's a
 * 	binary that conforms to certain formatting standards that allow us to map it into kernel
 * 	memory and resolve its symbols from a kernel image symbol database.
 *
 * Compiling the kext:
 * 	In order to be loadable, the Mach-O must be compiled as position-independent arm64. Use the
 * 	following CFLAGS:
 *
 * 		-arch arm64 -fno-builtin -fno-common -mkernel
 *
 * 	For linking you'll want the following LDFLAGS:
 *
 * 		-Xlinker -kext -nostdlib -Xlinker -fatal_warnings
 *
 * 	In the source of the kext, mark any kernel symbols that need to be resolved at link time
 * 	with:
 *
 * 		extern __attribute__((weak_import))
 *
 * 	The entry point should be a function _kext_start() with the following prototype:
 *
 * 		uint32_t _kext_start(uint64_t argument)
 *
 * Linking the kext:
 * 	Symbols in the kext are resolved to their runtime values by consulting the appropriate
 * 	symbol database for the device and OS version located in the kernel_symbols/ directory.
 *
 * 	In the kext, you can dynamically check whether the external symbol was resolved by testing
 * 	its address: if the address of the symbol is 0, then it is unresolved and should not be
 * 	used.
 *
 * Loading the kext:
 * 	The kext is loaded into kernel memory and then virtual memory protections are set according
 * 	to the protections in each segment command. The _kext_start() function is then called from
 * 	userspace using kernel_call_7(). _kext_start() will be supplied the 64-bit argument value
 * 	given to kext_load().
 *
 * Unloading the kext:
 * 	TODO: Not yet supported.
 */
uint64_t kext_load(const char *file, uint64_t argument);

#endif
