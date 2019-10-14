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

#ifndef KTRR_BYPASS_PARAMETERS__H_
#define KTRR_BYPASS_PARAMETERS__H_

#include "log.h"
#include "parameters.h"

#ifdef KTRR_BYPASS_PARAMETERS_EXTERN
#define extern KTRR_BYPASS_PARAMETERS_EXTERN
#endif

extern uint64_t gPhysBase;
extern uint64_t gVirtBase;
extern uint64_t rorgn_begin;
extern uint64_t rorgn_end;
extern uint64_t cpu_ttep;
extern uint64_t kernel_pmap;
extern uint64_t ADDRESS(pmap_find_phys);
extern uint64_t ADDRESS(ml_phys_read_data);
extern uint64_t ADDRESS(ml_phys_write_data);
extern uint64_t ADDRESS(ml_io_map);
extern uint64_t ADDRESS(ldr_w0_x0__ret);
extern uint64_t ADDRESS(str_w1_x0__ret);
extern uint64_t ADDRESS(CpuDataEntries);
extern size_t SIZE(cpu_data_entry);
extern size_t OFFSET(cpu_data_entry, cpu_data_vaddr);
extern size_t OFFSET(cpu_data, cpu_regmap_paddr);
extern size_t OFFSET(cpu_data, ed_mmio);
extern size_t OFFSET(cpu_data, utt_mmio);

/*
 * ktrr_bypass_parameters_init
 *
 * Description:
 * 	Initialize the parameters used in the KTRR bypass.
 */
bool ktrr_bypass_parameters_init(void);

#undef extern

#endif
