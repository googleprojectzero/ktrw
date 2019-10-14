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

#ifndef BUNDLE_PATH__H_
#define BUNDLE_PATH__H_

#include <stddef.h>

/*
 * get_bundle_path
 *
 * Description:
 * 	Copy the absolute path to the bundle directory (without the trailing slash) into the
 * 	specified buffer.
 */
void get_bundle_path(char *buffer, size_t size);

#endif
