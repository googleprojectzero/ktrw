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

#include "kernel_call.h"

#include <assert.h>
#include <stdarg.h>

#include "kernel_call_7_a11.h"

// ---- Public API --------------------------------------------------------------------------------

bool
kernel_call_init() {
	bool ok = kernel_call_7_a11_init();
	if (!ok) {
		kernel_call_7_a11_deinit();
	}
	return ok;
}

void
kernel_call_deinit() {
	kernel_call_7_a11_deinit();
}

uint32_t
kernel_call_7(uint64_t function, size_t argument_count, ...) {
	assert(argument_count <= 7);
	uint64_t arguments[7];
	va_list ap;
	va_start(ap, argument_count);
	for (size_t i = 0; i < argument_count && i < 7; i++) {
		arguments[i] = va_arg(ap, uint64_t);
	}
	va_end(ap);
	return kernel_call_7v(function, argument_count, arguments);
}
