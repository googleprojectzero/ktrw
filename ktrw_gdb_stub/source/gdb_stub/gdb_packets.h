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

#ifndef GDB_PACKETS__H_
#define GDB_PACKETS__H_

#include <stddef.h>
#include <stdint.h>

/*
 * gdb_process_packet
 *
 * Description:
 * 	Handle a GDB RSP packet and send any replies.
 */
void gdb_process_packet(void *data, size_t size);

/*
 * gdb_process_cpu_halts
 *
 * Description:
 * 	Handle any CPU halts and send any replies.
 */
void gdb_process_cpu_halts(uint32_t halted_mask);

#endif
