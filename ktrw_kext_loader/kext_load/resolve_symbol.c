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

#include "resolve_symbol.h"

#include <ctype.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

#include "bundle_path.h"
#include "log.h"
#include "map_file.h"
#include "platform.h"


// ---- Internal functions ------------------------------------------------------------------------

// The mapped database file.
static void *symbol_database = NULL;
static size_t symbol_database_size = 0;

/*
 * lookup_symbol
 *
 * Description:
 * 	Parses the memory-mapped database file line-by-line looking for the matching symbol.
 */
static uint64_t
lookup_symbol(const char *name) {
	const char *str = symbol_database;
	const char *const end = str + symbol_database_size;
	// Each iteration of this loop starts at the beginning of a line.
	for (;;) {
		char ch;
		// At the start of the line. Skip any leading whitespace.
		for (;;) {
			if (str >= end) {
				return 0;
			}
			ch = *str;
			if (ch != ' ' && ch != '\t') {
				break;
			}
			str++;
		}
		// At the symbol name.
		const char *p = name;
		for (;;) {
			if (*p == 0) {
				break;
			}
			if (*p != ch) {
				goto next_line;
			}
			p++;
			str++;
			if (str >= end) {
				return 0;
			}
			ch = *str;
		}
		// Matched the name. Consume some whitespace.
		if (ch != ' ' && ch != '\t') {
			// Not a match.
			goto next_line;
		}
		for (;;) {
			str++;
			if (str >= end) {
				return 0;
			}
			ch = *str;
			if (ch != ' ' && ch != '\t') {
				break;
			}
		}
		// Matched the name plus whitespace. Extract the value.
		uint64_t value = 0;
		if (str + 2 + 16 > end) {
			goto next_line;
		}
		if (ch != '0') {
			goto next_line;
		}
		str++;
		ch = *str;
		if (ch != 'x') {
			goto next_line;
		}
		str++;
		ch = *str;
		for (size_t i = 0;;) {
			uint64_t digit;
			if ('0' <= ch && ch <= '9') {
				digit = ch - '0';
			} else if ('a' <= ch && ch <= 'f') {
				digit = ch - 'a' + 0xa;
			} else if ('A' <= ch && ch <= 'F') {
				digit = ch - 'A' + 0xa;
			} else {
				goto next_line;
			}
			value = (value << 4) | digit;
			i++;
			str++;
			if (i >= 16) {
				break;
			}
			if (str >= end) {
				return 0;
			}
			ch = *str;
		}
		// Alright, we have a value! Make sure that we don't have more.
		if (str >= end) {
			return value;
		}
		ch = *str;
		if (ch != ' ' && ch != '\t' && ch != '\n') {
			WARNING("Invalid value for symbol %s", name);
			return 0;
		}
		// Correctly formatted value!
		return value;
		// Find the next newline character and then skip it to start the next line.
next_line:
		for (;;) {
			if (str >= end) {
				return 0;
			}
			if (ch == '\n') {
				break;
			}
			str++;
			ch = *str;
		}
		str++;
	}
}

// ---- Public API --------------------------------------------------------------------------------

bool
load_symbol_database() {
	if (symbol_database != NULL) {
		return true;
	}
	platform_init();
	char bundle_path[1024];
	get_bundle_path(bundle_path, sizeof(bundle_path));
	char database_path[1024];
	snprintf(database_path, sizeof(database_path), "%s/kernel_symbols/%s_%s.txt",
			bundle_path, platform.machine, platform.osversion);
	symbol_database = map_file(database_path, &symbol_database_size);
	if (symbol_database == NULL) {
		WARNING("No kernel symbol database for %s %s", platform.machine, platform.osversion);
		return false;
	}
	return true;
}

uint64_t
resolve_symbol(const char *symbol) {
	return lookup_symbol(symbol);
}
