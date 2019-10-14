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

#ifndef GDB_INTERNAL__H_
#define GDB_INTERNAL__H_

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>

/*
 * hex_digit
 *
 * Description:
 * 	Convert a character representing a hexadecimal digit to its numeric value or -1.
 */
int hex_digit(char ch);

/*
 * hex_char
 *
 * Description:
 * 	A table converting an integer between 0 and 15 to the corresponding hexadecimal digit.
 */
extern const char hex_char[16];

/*
 * snprintf_cat
 *
 * Description:
 * 	Print a formatted string to a buffer without null-terminating. The cursor specifies where
 * 	in or before the buffer printing should start. On return, cursor is updated to point to
 * 	where in or before the buffer printing would have ended if the buffer were infinite in both
 * 	directions. Only formatted data that actually falls within the true bounds of the buffer
 * 	will actually be written.
 *
 * 	Due to the current implementation of this function, correct behavior is only guaranteed if
 * 	at most 1024 characters are printed in a single call.
 */
void snprintf_cat(char *buffer, size_t size, char **cursor, const char *format, ...);

/*
 * vsnprintf_cat
 *
 * Description:
 * 	See snprintf_cat().
 */
void vsnprintf_cat(char *buffer, size_t size, char **cursor, const char *format, va_list ap);

#endif
