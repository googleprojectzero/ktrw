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


#include <stddef.h>
#include <stdint.h>

// These functions and globals are used in compiler-generated code. We'd prefer not to use the
// kernel's versions, since calling kernel functions and reading kernel variables could interfere
// with the operation of the debugger. (When using per-core hardware breakpoints and watchpoints
// this will obviously be fine, but it could be problematic if the debugger rewrites kernel
// memory.)

uint64_t __stack_chk_guard = 0x1122334455667788;

void
__stack_chk_fail() {
	for (;;) {}
}

void
bzero(void *s, size_t n) {
	uint8_t *p = s;
	for (size_t i = 0; i < n; i++) {
		p[i] = 0;
	}
}

// These functions are not necessarily used automatically by the compiler but they are useful to
// have.

void
memcpy(void *restrict dst, const void *restrict src, size_t n) {
	for (size_t i = 0; i < n; i++) {
		((uint8_t *)dst)[i] = ((uint8_t *)src)[i];
	}
}

void
memmove(void *dst, const void *src, size_t n) {
	uint8_t *d = dst;
	const uint8_t *s = src;
	if (d < s) {
		for (size_t i = 0; i < n; i++) {
			d[i] = s[i];
		}
	} else if (s < d) {
		size_t i = n;
		while (i > 0) {
			i--;
			d[i] = s[i];
		}
	}
}

size_t
strlen(const char *str) {
	const char *end = str;
	for (;;) {
		if (*end == 0) {
			return (end - str);
		}
		end++;
	}
}

int
strcmp(const char *s1, const char *s2) {
	for (;;) {
		unsigned char c1 = (unsigned char) *s1;
		unsigned char c2 = (unsigned char) *s2;
		int diff = c1 - c2;
		if (diff != 0) {
			return diff;
		}
		if (c1 == 0) {
			return 0;
		}
		s1++;
		s2++;
	}
}

int
strncmp(const char *s1, const char *s2, size_t n) {
	while (n > 0) {
		unsigned char c1 = (unsigned char) *s1;
		unsigned char c2 = (unsigned char) *s2;
		int diff = c1 - c2;
		if (diff != 0) {
			return diff;
		}
		if (c1 == 0) {
			return 0;
		}
		s1++;
		s2++;
		n--;
	}
	return 0;
}
