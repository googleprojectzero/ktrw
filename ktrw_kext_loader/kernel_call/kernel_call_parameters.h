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

#ifndef KERNEL_CALL_PARAMETERS__H_
#define KERNEL_CALL_PARAMETERS__H_

#include "parameters.h"

#ifdef KERNEL_CALL_PARAMETERS_EXTERN
#define extern KERNEL_CALL_PARAMETERS_EXTERN
#endif

extern uint64_t ADDRESS(mov_x0_x4__br_x5);
extern uint64_t ADDRESS(IOUserClient__vtable);
extern uint64_t ADDRESS(IORegistryEntry__getRegistryEntryID);

// Parameters for struct ipc_port.
extern size_t OFFSET(ipc_port, ip_kobject);

// Parameters for struct proc.
extern size_t OFFSET(proc, p_ucred);

// Parameters for struct task.
extern size_t OFFSET(task, bsd_info);

// Parameters for IOExternalTrap.
extern size_t SIZE(IOExternalTrap);
extern size_t OFFSET(IOExternalTrap, object);
extern size_t OFFSET(IOExternalTrap, function);
extern size_t OFFSET(IOExternalTrap, offset);

// Parameters for IORegistryEntry.
extern size_t OFFSET(IORegistryEntry, reserved);
extern size_t OFFSET(IORegistryEntry__ExpansionData, fRegistryEntryID);

// Parameters for IOUserClient.
extern uint32_t VTABLE_INDEX(IOUserClient, getExternalTrapForIndex);
extern uint32_t VTABLE_INDEX(IOUserClient, getTargetAndTrapForIndex);

/*
 * kernel_call_parameters_init
 *
 * Description:
 * 	Initialize the addresses used in the kernel_call subsystem.
 */
bool kernel_call_parameters_init(void);

#undef extern

#endif
