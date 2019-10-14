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

#ifndef JIT_HEAP__H_
#define JIT_HEAP__H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// The size of the JIT heap.
#define JIT_HEAP_SIZE	(64 * 0x4000)

/*
 * jit_heap_init
 *
 * Description:
 * 	Initialize the JIT heap to use the specified allocation.
 */
void jit_heap_init(void *heap);

/*
 * jit_heap_reset
 *
 * Description:
 * 	Reset the JIT heap, freeing all outstanding allocations.
 */
void jit_heap_reset(void);

/*
 * jit_heap_allocate
 *
 * Description:
 * 	Allocate memory from the JIT heap with the specified permissions.
 */
void *jit_heap_allocate(size_t size, int vm_prot);

/*
 * jit_heap_deallocate
 *
 * Description:
 * 	Deallocate the specified JIT heap allocation.
 */
bool jit_heap_deallocate(void *address);

#endif
