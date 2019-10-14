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

#include "log.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

void
log_internal(char type, const char *format, ...) {
	if (log_implementation != NULL) {
		va_list ap;
		va_start(ap, format);
		log_implementation(type, format, ap);
		va_end(ap);
	}
}

// The default logging implementation prints to stderr with a nice hacker prefix.
static void
log_stderr(char type, const char *format, va_list ap) {
	char *message = NULL;
	vasprintf(&message, format, ap);
	assert(message != NULL);
	switch (type) {
		case 'D': type = 'D'; break;
		case 'I': type = '+'; break;
		case 'W': type = '!'; break;
		case 'E': type = '-'; break;
	}
	fprintf(stderr, "[%c] %s\n", type, message);
	free(message);
}

void (*log_implementation)(char type, const char *format, va_list ap) = log_stderr;
