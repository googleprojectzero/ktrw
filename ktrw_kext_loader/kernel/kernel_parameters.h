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

#ifndef KERNEL_PARAMETERS__H_
#define KERNEL_PARAMETERS__H_

#include "parameters.h"

#ifdef KERNEL_PARAMETERS_EXTERN
#define extern KERNEL_PARAMETERS_EXTERN
#endif

// The static base address of the kernel.
extern uint64_t STATIC_ADDRESS(kernel_base);

// The kernel_slide granularity.
extern uint64_t kernel_slide_step;

// Parameters for struct ipc_entry.
extern size_t SIZE(ipc_entry);
extern size_t OFFSET(ipc_entry, ie_object);

// Parameters for struct ipc_port.
extern size_t OFFSET(ipc_port, ip_kobject);

// Parameters for struct ipc_space.
extern size_t OFFSET(ipc_space, is_table_size);
extern size_t OFFSET(ipc_space, is_table);

// Parameters for struct proc.
extern size_t OFFSET(proc, p_list_next);
extern size_t OFFSET(proc, task);
extern size_t OFFSET(proc, p_pid);

// Parameters for struct task.
extern size_t OFFSET(task, itk_space);
extern size_t OFFSET(task, bsd_info);

// The static address of the allproc variable.
extern uint64_t STATIC_ADDRESS(allproc);

/*
 * kernel_parameters_init
 *
 * Description:
 * 	Initialize the parameters used in the kernel subsystem.
 */
bool kernel_parameters_init(void);

#undef extern

#endif
