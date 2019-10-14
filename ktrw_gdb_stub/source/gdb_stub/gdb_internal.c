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

#include "gdb_internal.h"

#include <stdarg.h>

#include "gdb_rsp.h"
#include "kernel_extern.h"

// ---- Kernel symbols ----------------------------------------------------------------------------

KERNEL_EXTERN int vsnprintf(char *buf, size_t size, const char *fmt, va_list ap);

// ---- Formatting functions ----------------------------------------------------------------------

int
hex_digit(char ch) {
	if ('0' <= ch && ch <= '9') {
		return ch - '0';
	} else if ('a' <= ch && ch <= 'f') {
		return ch - 'a' + 0xa;
	} else if ('A' <= ch && ch <= 'F') {
		return ch - 'A' + 0xa;
	}
	return -1;
}

const char hex_char[16] = "0123456789abcdef";

void
vsnprintf_cat(char *buffer, size_t size, char **cursor, const char *format, va_list ap) {
	// Write the formatted data to a stack buffer. This allows us to skip the whole
	// null-terminator deal altogether.
	char src_buffer[GDB_RSP_MAX_PACKET_SIZE + 1];
	int len = vsnprintf(src_buffer, sizeof(src_buffer), format, ap);
	size_t written = len;
	// TODO: Ensure that no single print atom takes too much space! The vsnprintf() function
	// doesn't give us this flexibility, so we'll just silently drop characters :( In this
	// hack, if a single atom is larger than the source buffer size, we pretend that the atom
	// exactly filled the source buffer. Doing it this way (rather than only truncating if the
	// atom actually shows up in the output buffer) allows for consistency when windowing a
	// generated output string.
	if (written > sizeof(src_buffer)) {
		written = sizeof(src_buffer);
	}
	// Get copy parameters.
	char *dst = *cursor;
	char *src = src_buffer;
	size_t src_size = written;
	// Handle the case where the cursor is before the buffer so we need to discard some
	// characters from the source.
	if (dst < buffer) {
		size_t skip = buffer - dst;
		// Only skip up to the size of the source.
		if (skip >= src_size) {
			skip = src_size;
		}
		dst += skip;
		src += skip;
		src_size -= skip;
	}
	// Copy into dst as long as we're within the bounds of the output buffer and up to the size
	// of the source.
	if (buffer <= dst && dst < buffer + size) {
		size_t dst_size = buffer + size - dst;
		size_t copy_size = (dst_size < src_size ? dst_size : src_size);
		for (size_t i = 0; i < copy_size; i++) {
			dst[i] = src[i];
		}
	}
	// Update the cursor. Even if we exited the copy loop early, we update the cursor past the
	// ends of the buffer as if the whole source were copied.
	*cursor = dst + src_size;
}

void
snprintf_cat(char *buffer, size_t size, char **cursor, const char *format, ...) {
	va_list ap;
	va_start(ap, format);
	vsnprintf_cat(buffer, size, cursor, format, ap);
	va_end(ap);
}
