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

#ifndef KERNEL_TASKS__H_
#define KERNEL_TASKS__H_

#include <stdbool.h>
#include <stdint.h>

#ifdef KERNEL_TASKS_EXTERN
#define extern KERNEL_TASKS_EXTERN
#endif

/*
 * kernel_task
 *
 * Description:
 * 	The address of the kernel_task in kernel memory.
 */
extern uint64_t kernel_task;

/*
 * current_task
 *
 * Description:
 * 	The address of the current task in kernel memory.
 */
extern uint64_t current_task;

/*
 * kernel_tasks_init
 *
 * Description:
 * 	Initialize kernel_task and current_task. kernel_slide must already be initialized.
 */
bool kernel_tasks_init(void);

#undef extern

#endif
