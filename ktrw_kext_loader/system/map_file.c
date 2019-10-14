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

#include "map_file.h"

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "log.h"


void *
map_file(const char *path, size_t *size) {
	int fd = open(path, O_RDONLY);
	if (fd < 0) {
		ERROR("Could not open file \"%s\": %s", path, strerror(errno));
		return NULL;
	}
	struct stat st;
	int err = fstat(fd, &st);
	if (err != 0) {
		ERROR("Could not stat file \"%s\": %s", path, strerror(errno));
		close(fd);
		return NULL;
	}
	size_t file_size = st.st_size;
	void *data = mmap(NULL, file_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	close(fd);
	if (data == MAP_FAILED) {
		ERROR("Could not map file \"%s\": %s", path, strerror(errno));
		return NULL;
	}
	*size = file_size;
	return data;
}

void
unmap_file(void *data, size_t size) {
	munmap(data, size);
}
