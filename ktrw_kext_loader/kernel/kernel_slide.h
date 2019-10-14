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

#ifndef KERNEL_SLIDE__H_
#define KERNEL_SLIDE__H_

#include <stdbool.h>
#include <stdint.h>

#ifdef KERNEL_SLIDE_EXTERN
#define extern KERNEL_SLIDE_EXTERN
#endif

/*
 * kernel_slide
 *
 * Description:
 * 	The kASLR slide.
 */
extern uint64_t kernel_slide;

/*
 * kernel_slide_init
 *
 * Description:
 * 	Find the value of the kernel slide using task_info(TASK_DYLD_INFO) or current_task.
 */
bool kernel_slide_init(void);

/*
 * kernel_slide_init_with_kernel_image_address
 *
 * Description:
 * 	Find the value of the kernel slide using kernel_read(), starting with an address that is
 * 	known to reside within the kernel image.
 */
bool kernel_slide_init_with_kernel_image_address(uint64_t address);

#undef extern

#endif
