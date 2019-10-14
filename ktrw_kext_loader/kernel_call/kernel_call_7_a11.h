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

#ifndef KERNEL_CALL_7_A11__H_
#define KERNEL_CALL_7_A11__H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * kernel_call_7_a11_init
 *
 * Description:
 * 	Initialize kernel_call_7 on A11 (non-PAC) devices. If this fails, still call
 * 	kernel_call_7_a11_deinit().
 *
 * Initializes:
 * 	kernel_call_parameters_init()
 * 	kernel_call_7v()
 */
bool kernel_call_7_a11_init(void);

/*
 * kernel_call_7_a11_deinit
 *
 * Description:
 * 	Deinitialize kernel_call_7 on A11 devices.
 */
void kernel_call_7_a11_deinit(void);

#endif
