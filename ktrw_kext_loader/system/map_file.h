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

#ifndef MAP_FILE__H_
#define MAP_FILE__H_

#include <stddef.h>

/*
 * map_file
 *
 * Description:
 * 	Maps the specified file into memory. Returns the address and size of the mapping.
 */
void *map_file(const char *path, size_t *size);

/*
 * unmap_file
 *
 * Description:
 * 	Unmap a file mapped with map_file().
 */
void unmap_file(void *data, size_t size);

#endif
