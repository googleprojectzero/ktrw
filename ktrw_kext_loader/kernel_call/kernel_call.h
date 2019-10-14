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

#ifndef KERNEL_CALL__H_
#define KERNEL_CALL__H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * kernel_call_init
 *
 * Description:
 * 	Initialize kernel_call functions.
 */
bool kernel_call_init(void);

/*
 * kernel_call_deinit
 *
 * Description:
 * 	Deinitialize the kernel call subsystem and restore the kernel to a safe state.
 */
void kernel_call_deinit(void);

/*
 * kernel_call_7
 *
 * Description:
 * 	Call a kernel function with the specified arguments.
 *
 * Restrictions:
 * 	See kernel_call_7v().
 */
uint32_t kernel_call_7(uint64_t function, size_t argument_count, ...);

/*
 * kernel_call_7v
 *
 * Description:
 * 	Call a kernel function with the specified arguments.
 *
 * Restrictions:
 * 	At most 7 arguments can be passed.
 * 	arguments[0] must be nonzero.
 * 	The return value is truncated to 32 bits.
 */
uint32_t kernel_call_7v(uint64_t function, size_t argument_count, const uint64_t arguments[]);

#endif
