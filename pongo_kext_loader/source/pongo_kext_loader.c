//
// Project: KTRW
// Author:  Brandon Azad <bazad@google.com>
//
// Copyright 2020 Google LLC
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

#include <assert.h>
#include <CoreFoundation/CoreFoundation.h>
#include <dirent.h>
#include <errno.h>
#include <IOKit/IOCFPlugin.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/usb/IOUSBLib.h>
#include <mach/mach.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/event.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

// ---- Logging -----------------------------------------------------------------------------------

#define ERROR(fmt, ...)		printf("Error: "fmt"\n", ##__VA_ARGS__)
#define WARNING(fmt, ...)	printf("Warning: "fmt"\n", ##__VA_ARGS__)

// ---- pongoOS USB interface ---------------------------------------------------------------------

// Allocate a CFDictionary that will match the pongoOS USB device descriptor.
static CFDictionaryRef
create_pongo_iokit_usb_matching_dictionary() {
	CFMutableDictionaryRef matchingDict = IOServiceMatching(kIOUSBDeviceClassName);
	int32_t appleVendorId = kAppleVendorID;
	CFNumberRef vendorId = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, &appleVendorId);
	CFDictionarySetValue(matchingDict, CFSTR(kUSBVendorID), vendorId);
	CFRelease(vendorId);
	int32_t pongoProductId = 0x4141;
	CFNumberRef productId = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, &pongoProductId);
	CFDictionarySetValue(matchingDict, CFSTR(kUSBProductID), productId);
	CFRelease(productId);
	return matchingDict;
}

// A pongoOS USB device.
struct _pongo_usb_device {
	io_service_t service;
	IOUSBDeviceInterface182 **device;
	IOUSBInterfaceInterface182 **interface;
#if 0
	void (*read_callback)(void *context, ssize_t read_count);
	void *read_context;
#endif
};
typedef struct _pongo_usb_device *pongo_usb_device;

// Represents an empty/invalid device.
#define PONGO_USB_NULL	((pongo_usb_device) NULL)

// The maximum number of tries to open.
#define PONGO_USB_OPEN_MAX_TRIES	5

// Open the pongoOS USB device.
static pongo_usb_device
pongo_usb_open(io_service_t service, mach_port_t notification_port_set) {
	// Create a Plug-In interface for the service.
	IOCFPlugInInterface **plugIn;
	SInt32 score;
	kern_return_t kr = IOCreatePlugInInterfaceForService(service, kIOUSBDeviceUserClientTypeID,
			kIOCFPlugInInterfaceID, &plugIn, &score);
	if (kr != KERN_SUCCESS) {
		ERROR("Could not create IOCFPlugInInterface for pongoOS USB device");
		goto fail_0;
	}
	// Create an IOUSBDeviceInterface for the USB device.
	IOUSBDeviceInterface182 **device = NULL;
	(*plugIn)->QueryInterface(plugIn, CFUUIDGetUUIDBytes(kIOUSBDeviceInterfaceID182),
			(LPVOID *)&device);
	(*plugIn)->Release(plugIn);
	if (device == NULL) {
		ERROR("Could not create IOUSBDeviceInterface for pongoOS USB device");
		goto fail_0;
	}
	// Open the IOUSBDeviceInterface. This allows us to call DeviceRequest() to perform control
	// transfers. This may take multiple tries.
	IOReturn result;
	for (int try = 0;; try++) {
		result = (*device)->USBDeviceOpen(device);
		if (result == kIOReturnSuccess) {
			break;
		}
		if (try >= PONGO_USB_OPEN_MAX_TRIES) {
			ERROR("Could not open IOUSBDeviceInterface for pongoOS USB device: 0x%x: %s",
					result, mach_error_string(result));
			goto fail_1;
		}
		usleep(100000);
	}
	// Try to find the interface. This may take multiple tries.
	IOUSBFindInterfaceRequest interfaceMatch;
	interfaceMatch.bInterfaceClass    = 0xfe;
	interfaceMatch.bInterfaceSubClass = 0x13;
	interfaceMatch.bInterfaceProtocol = 0x37;
	interfaceMatch.bAlternateSetting  = 0;
	io_service_t interface_service;
	for (int try = 0;; try++) {
		// Create an iterator over the interfaces.
		io_iterator_t interfaces;
		result = (*device)->CreateInterfaceIterator(device, &interfaceMatch, &interfaces);
		if (result != kIOReturnSuccess) {
			ERROR("Could not create iterator over pongoOS USB device's interfaces");
			goto fail_2;
		}
		// Grab the first interface match.
		interface_service = IOIteratorNext(interfaces);
		IOObjectRelease(interfaces);
		if (interface_service != IO_OBJECT_NULL) {
			break;
		}
		if (try >= PONGO_USB_OPEN_MAX_TRIES) {
			ERROR("No interfaces found for pongoOS USB device");
			goto fail_2;
		}
		usleep(100000);
	}
	// Create a Plug-In interface for the service.
	kr = IOCreatePlugInInterfaceForService(interface_service, kIOUSBInterfaceUserClientTypeID,
			kIOCFPlugInInterfaceID, &plugIn, &score);
	IOObjectRelease(interface_service);
	if (kr != KERN_SUCCESS) {
		ERROR("Could not create IOCFPlugInInterface for pongoOS USB interface");
		goto fail_2;
	}
	// Create an IOUSBDeviceInterface for the USB device.
	IOUSBInterfaceInterface182 **interface = NULL;
	(*plugIn)->QueryInterface(plugIn, CFUUIDGetUUIDBytes(kIOUSBInterfaceInterfaceID182),
			(LPVOID *)&interface);
	(*plugIn)->Release(plugIn);
	if (interface == NULL) {
		ERROR("Could not create IOUSBInterfaceInterface for pongoOS USB interface");
		goto fail_2;
	}
	// Open the interface.
	result = (*interface)->USBInterfaceOpen(interface);
	if (result != kIOReturnSuccess) {
		ERROR("Could not open IOUSBInterfaceInterface for pongoOS USB device");
		goto fail_3;
	}
	// Check the number of endpoints.
	UInt8 numEndpoints;
	result = (*interface)->GetNumEndpoints(interface, &numEndpoints);
	if (result != kIOReturnSuccess) {
		ERROR("Could not get the number of endpoints for the pongoOS USB device interface");
		goto fail_4;
	}
	if (numEndpoints != 2) {
		WARNING("Unexpected number of endpoints for the pongoOS USB device interface: %u",
				numEndpoints);
	}
	// Register a Mach port to receive asynchronous I/O completion notifications.
	mach_port_t io_port = MACH_PORT_NULL;
	kr = (*interface)->CreateInterfaceAsyncPort(interface, &io_port);
	if (kr != KERN_SUCCESS) {
		ERROR("Could not create pongoOS USB asynchronous notification port");
		goto fail_4;
	}
	// Add the async port to the notification port set.
	kr = mach_port_insert_member(mach_task_self(), io_port, notification_port_set);
	mach_port_deallocate(mach_task_self(), io_port);
	if (kr != KERN_SUCCESS) {
		ERROR("Could not add pongoOS USB asynchronous notification port to port set");
		goto fail_4;
	}
	// Create the pongo_usb_device.
	pongo_usb_device pongo = calloc(1, sizeof(*pongo));
	assert(pongo != NULL);
	pongo->service = service;
	pongo->device = device;
	pongo->interface = interface;
	return pongo;
fail_4:
	(*interface)->USBInterfaceClose(interface);
fail_3:
	(*interface)->Release(interface);
fail_2:
	(*device)->USBDeviceClose(device);
fail_1:
	(*device)->Release(device);
fail_0:
	return PONGO_USB_NULL;
}

// Close the device returned by pongo_usb_open().
static void
pongo_usb_close(pongo_usb_device pongo) {
	if (pongo != PONGO_USB_NULL) {
		if (pongo->interface != NULL) {
			(*pongo->interface)->USBInterfaceClose(pongo->interface);
			(*pongo->interface)->Release(pongo->interface);
		}
		if (pongo->device != NULL) {
			(*pongo->device)->USBDeviceClose(pongo->device);
			(*pongo->device)->Release(pongo->device);
		}
		if (pongo->service != IO_OBJECT_NULL) {
			IOObjectRelease(pongo->service);
		}
		free(pongo);
	}
}

// Checks whether the specified IOService corresponds to the pongoOS USB device.
static bool
pongo_usb_matches_service(pongo_usb_device pongo, io_service_t service) {
	return (pongo != PONGO_USB_NULL && pongo->service == service);
}

// Send a command string synchronously to pongoOS.
static ssize_t
pongo_usb_send_command(pongo_usb_device pongo, const char *command, size_t size) {
	if (size == 0) {
		size = strlen(command) + 1;
	}
	assert(size < 256);
	IOUSBDevRequest request = {};
	request.bmRequestType = 0x21;
	request.bRequest      = 0x3;
	request.wValue        = 0;
	request.wIndex        = 0;
	request.wLength       = (uint16_t) size;
	request.pData         = (void *) command;
	IOReturn result = (*pongo->device)->DeviceRequest(pongo->device, &request);
	if (result != kIOReturnSuccess) {
		ERROR("Could not send pongoOS command: %x: %s",
				result, mach_error_string(result));
		return -1;
	}
	return request.wLenDone;
}

// Initialize bulk data upload to pongoOS.
static ssize_t
pongo_usb_init_bulk_upload(pongo_usb_device pongo) {
	IOUSBDevRequest request = {};
	request.bmRequestType = 0x21;
	request.bRequest      = 0x1;
	request.wValue        = 0;
	request.wIndex        = 0;
	request.wLength       = 0;
	request.pData         = NULL;
	IOReturn result = (*pongo->device)->DeviceRequest(pongo->device, &request);
	if (result != kIOReturnSuccess) {
		ERROR("Could not initialize pongoOS bulk upload: %x: %s",
				result, mach_error_string(result));
		return -1;
	}
	return request.wLenDone;
}

// Clear bulk data uploaded to pongoOS.
static ssize_t
pongo_usb_discard_bulk_upload(pongo_usb_device pongo) {
	IOUSBDevRequest request = {};
	request.bmRequestType = 0x21;
	request.bRequest      = 0x2;
	request.wValue        = 0;
	request.wIndex        = 0;
	request.wLength       = 0;
	request.pData         = NULL;
	IOReturn result = (*pongo->device)->DeviceRequest(pongo->device, &request);
	if (result != kIOReturnSuccess) {
		ERROR("Could not initialize pongoOS bulk upload: %x: %s",
				result, mach_error_string(result));
		return -1;
	}
	return request.wLenDone;
}

// Upload bulk data synchronously to pongoOS.
static bool
pongo_usb_send_bulk_data(pongo_usb_device pongo, const void *data, size_t size) {
	IOReturn result = (*pongo->interface)->WritePipe(pongo->interface, 2,
			(void *) data, size);
	if (result != kIOReturnSuccess) {
		pongo_usb_discard_bulk_upload(pongo);
	}
	return (result == kIOReturnSuccess);
}

#if 0

// An internal function to invoke the callback supplied to pongo_usb_recv().
static void
pongo_usb_recv_done(void *refCon, IOReturn result, void *arg0) {
	pongo_usb_device pongo = refCon;
	UInt32 read_size = (UInt32) (uintptr_t) arg0;
	void (*callback)(void *context, ssize_t read_count) = pongo->read_callback;
	void *context = pongo->read_context;
	pongo->read_callback = NULL;
	pongo->read_context = NULL;
	ssize_t read_count = read_size;
	if (result != kIOReturnSuccess) {
		ERROR("Could not %s pongoOS data: %x: %s", "read",
				result, mach_error_string(result));
		read_count = -1;
	}
	callback(context, read_count);
}

// Asynchronously receive data from pongoOS.
static void
pongo_usb_recv(pongo_usb_device pongo, void *data, size_t size,
		void (*callback)(void *context, ssize_t size), void *context) {
	assert(pongo->read_callback == NULL && pongo->read_context == NULL);
	pongo->read_callback = callback;
	pongo->read_context  = context;
	(*pongo->interface)->ReadPipeAsync(pongo->interface, 1, data, size,
			pongo_usb_recv_done, pongo);
}

#endif

// ---- Map a file for reading --------------------------------------------------------------------

// Map a file for reading.
static void *
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

// Unmap a file mapped with map_file().
static void
unmap_file(void *data, size_t size) {
	munmap(data, size);
}

// ---- Kernelcache symbol tables -----------------------------------------------------------------

// The paths to the kernelcache symbol tables directory.
static const char **kernelcache_symbols_path = NULL;
static size_t kernelcache_symbols_path_count = 0;

// Set the path to the kextload pongo module.
static void
set_kernelcache_symbols_path(const char *path) {
	kernelcache_symbols_path_count++;
	size_t new_size = kernelcache_symbols_path_count * sizeof(*kernelcache_symbols_path);
	kernelcache_symbols_path = realloc(kernelcache_symbols_path, new_size);
	kernelcache_symbols_path[kernelcache_symbols_path_count - 1] = path;
}

// A kernelcache symbol table.
struct _kernelcache_symbol_table {
	void *data;
	size_t size;
};
typedef struct _kernelcache_symbol_table kernelcache_symbol_table;

// Parse a hexadecimal digit.
static int hex_digit(char digit) {
	if ('0' <= digit && digit <= '9') {
		return digit - '0';
	} else if ('A' <= digit && digit <= 'F') {
		return digit - 'A' + 0xa;
	} else if ('a' <= digit && digit <= 'f') {
		return digit - 'a' + 0xa;
	}
	return -1;
}

// State for text parsing.
struct text_parser {
	const char *p;
	const char *e;
};

static bool
tp_end(struct text_parser *tp) {
	return (tp->p >= tp->e);
}

static void
tp_next_line(struct text_parser *tp) {
	while (tp->p < tp->e && *tp->p != '\n') {
		tp->p++;
	}
	tp->p++;
}

static bool
tp_space(struct text_parser *tp) {
	bool skipped = false;
	while (tp->p < tp->e && (*tp->p == ' ' || *tp->p == '\t')) {
		tp->p++;
		skipped = true;
	}
	return skipped;
}

static void
tp_line_comment(struct text_parser *tp) {
	if (tp->p < tp->e && *tp->p == '#') {
		while (tp->p < tp->e && *tp->p != '\n') {
			tp->p++;
		}
	}
}

static void
tp_comments(struct text_parser *tp) {
	while (tp->p < tp->e && *tp->p == '#') {
		tp_next_line(tp);
	}
}

static void
tp_comments_or_empty(struct text_parser *tp) {
	while (tp->p < tp->e && (*tp->p == '#' || *tp->p == '\n')) {
		tp_next_line(tp);
	}
}

static bool
tp_match(struct text_parser *tp, const char *str) {
	size_t len = strlen(str);
	if (tp->p < tp->e && tp->p + len <= tp->e) {
		int cmp = strncmp(tp->p, str, len);
		if (cmp == 0) {
			tp->p += len;
			return true;
		}
	}
	return false;
}

static bool
tp_ident(struct text_parser *tp, const char **ident, size_t *len) {
	const char *p = tp->p;
	while (p < tp->e) {
		char ch = *p;
		bool is_ident = (('a' <= ch && ch <= 'z')
				|| ('A' <= ch && ch <= 'Z')
				|| ('0' <= ch && ch <= '9')
				|| (ch == '_'));
		if (!is_ident) {
			break;
		}
		p++;
	}
	if (p == tp->p) {
		return false;
	}
	*ident = tp->p;
	*len = p - tp->p;
	tp->p = p;
	return true;
}

static bool
tp_hex_byte(struct text_parser *tp, uint8_t *byte) {
	if (tp->p + 2 <= tp->e) {
		int hi = hex_digit(tp->p[0]);
		int lo = hex_digit(tp->p[1]);
		if (hi != -1 && lo != -1) {
			*byte = (((uint8_t) hi & 0xf) << 4) | ((uint8_t) lo & 0xf);
			tp->p += 2;
			return true;
		}
	}
	return false;
}

static bool
tp_hex_u64(struct text_parser *tp, uint64_t *value) {
	const char *b = tp->p;
	bool ok = tp_match(tp, "0x");
	if (!ok) {
		goto fail;
	}
	uint64_t v = 0;
	for (int i = 0; i < 8; i++) {
		uint8_t byte;
		ok = tp_hex_byte(tp, &byte);
		if (!ok) {
			goto fail;
		}
		v = (v << 8) | byte;
	}
	if (tp->p < tp->e && hex_digit(*tp->p) != -1) {
		goto fail;
	}
	*value = v;
	return true;
fail:
	tp->p = b;
	return false;
}

// Kernelcache symbols file format:
//     # <comment>
//     KERNELCACHE UUID: <00112233-4455-6677-8899-aabbccddeeff>
//     DEVICE:           <device> <build>
//     DEVICE:           <device> <build>
//
//     <symbol_name> <address>
//     <symbol_name> <address>

// Parse the header of a kernelcache symbols file and retrieve the kernelcache UUID.
static bool
parse_kernelcache_symbols_header(struct text_parser *tp, uint8_t kernelcache_uuid[16]) {
	// Skip any initial comment lines.
	tp_comments(tp);
	// We need exactly match "KERNELCACHE UUID:" for the first directive.
	bool ok = tp_match(tp, "KERNELCACHE UUID:");
	if (!ok) {
		ERROR("Expected \"KERNELCACHE UUID\"");
		return false;
	}
	tp_space(tp);
	// Now parse the UUID.
	for (int i = 0; i < 16; i++) {
		bool ok = tp_hex_byte(tp, &kernelcache_uuid[i]);
		if (ok && (i == 3 || i == 5 || i == 7 || i == 9 || i == 15)) {
			ok = tp_match(tp, (i == 15 ? "\n" : "-"));
		}
		if (!ok) {
			ERROR("Bad \"KERNELCACHE UUID\"");
			return false;
		}
	}
	// Parse any "DEVICE" directives and/or comments.
	for (;;) {
		// Skip any comment lines.
		tp_comments(tp);
		// If we exactly match "DEVICE:", just skip this declaration, since we don't use
		// it.
		bool ok = tp_match(tp, "DEVICE:");
		if (ok) {
			tp_next_line(tp);
			continue;
		}
		// If we exactly match a newline, then we have a blank line, so stop.
		ok = tp_match(tp, "\n");
		if (ok) {
			break;
		}
		// Otherwise, if we get here, then nothing matched! Abort.
		ERROR("Bad directive");
		return false;
	}
	// We matched the header! Return the current position.
	return true;
}

// Parse a single symbol from a kernelcache symbols file.
static bool
parse_kernelcache_symbols_symbol(struct text_parser *tp,
		char **symbol, size_t *length, uint64_t *address) {
	// Skip any initial comment lines or empty lines.
	tp_comments_or_empty(tp);
	// Check if we're at the end.
	if (tp_end(tp)) {
		return true;
	}
	// Get the symbol.
	const char *ident;
	size_t len;
	bool ok = tp_ident(tp, &ident, &len);
	if (!ok) {
		ERROR("Expected symbol");
		return false;
	}
	// Skip some whitespace.
	ok = tp_space(tp);
	if (!ok) {
		ERROR("Expected space");
		return false;
	}
	// Read a hex 64-bit integer.
	ok = tp_hex_u64(tp, address);
	if (!ok) {
		ERROR("Expected address");
		return false;
	}
	// Skip any space.
	tp_space(tp);
	// Skip any line comment.
	tp_line_comment(tp);
	// We expect a newline or end of file.
	ok = tp_end(tp) || tp_match(tp, "\n");
	if (!ok) {
		ERROR("Expected end of line");
		return false;
	}
	// We're done! Fill the symbol.
	*symbol = strndup(ident, len);
	*length = len;
	return true;
}

struct kcs_sym {
	uint32_t off;
	uint64_t addr;
};

struct kcs_kc {
	uint8_t uuid[16];
	uint32_t symcnt;
	struct kcs_sym *syms;
};

struct kcs_state {
	struct kcs_kc *kcs;
	uint32_t kccnt;
	uint32_t maxsymcnt;
	char *symstr;
	size_t symsize;
};

// Update a kcs_state partial kernelcache symbol table state with the kernelcache symbols files in
// a directory.
static bool
kernelcache_symbol_table_update_directory(struct kcs_state *state, const char *dirpath) {
	// Open the directory for iterating.
	DIR *dir = opendir(dirpath);
	if (dir == NULL) {
		ERROR("Could not iterate directory \"%s\"", dirpath);
		return false;
	}
	// Iterate the directory.
	for (;;) {
		// Get the next entry.
		struct dirent *dp = readdir(dir);
		if (dp == NULL) {
			break;
		}
		// Only process regular files.
		if (dp->d_type != DT_REG) {
			goto next_0;
		}
		// Skip hidden entries.
		if (dp->d_name[0] == '.') {
			goto next_0;
		}
		// Require file extension ".txt".
		const char *extension = ".txt";
		if (dp->d_namlen <= strlen(extension)) {
			goto next_0;
		}
		const char *file_ext = dp->d_name + dp->d_namlen - strlen(extension);
		if (strcmp(file_ext, extension) != 0) {
			goto next_0;
		}
		// Generate the full path.
		char path[PATH_MAX + 1];
		snprintf(path, sizeof(path), "%s/%s", dirpath, dp->d_name);
		// Read the file.
		size_t file_size;
		void *file_data = map_file(path, &file_size);
		if (file_data == NULL) {
			goto next_0;
		}
		// Parse the header for the UUID.
		struct text_parser tp = { file_data, (void *) ((uintptr_t) file_data + file_size) };
		uint8_t uuid[16];
		bool ok = parse_kernelcache_symbols_header(&tp, uuid);
		if (!ok) {
			ERROR("Invalid kernelcache symbols file \"%s\"", path);
			goto next_1;
		}
		// Check if this UUID already exists.
		struct kcs_kc *kc;
		for (size_t kc_idx = 0; kc_idx < state->kccnt; kc_idx++) {
			kc = &state->kcs[kc_idx];
			if (memcmp(kc->uuid, uuid, 16) == 0) {
				// This UUID already exists.
				WARNING("Duplicate UUID %02X%02X%02X%02X-%02X%02X-"
						"%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
						uuid[ 0], uuid[ 1], uuid[ 2], uuid[ 3],
						uuid[ 4], uuid[ 5], uuid[ 6], uuid[ 7],
						uuid[ 8], uuid[ 9], uuid[10], uuid[11],
						uuid[12], uuid[13], uuid[14], uuid[15]);
				goto kernelcache_uuid_already_exists;
			}
		}
		// Otherwise, allocate a new kc_syms struct in the array.
		state->kccnt++;
		state->kcs = realloc(state->kcs, state->kccnt * sizeof(*state->kcs));
		kc = &state->kcs[state->kccnt - 1];
		// Initialize the new kc_syms struct.
		memcpy(kc->uuid, uuid, sizeof(kc->uuid));
		kc->symcnt = 0;
		kc->syms = NULL;
kernelcache_uuid_already_exists:
		// Now parse the symbols.
		for (;;) {
			// Parse one symbol.
			char *symbol = NULL;
			size_t length;
			uint64_t address;
			ok = parse_kernelcache_symbols_symbol(&tp, &symbol, &length, &address);
			if (!ok) {
				ERROR("Invalid kernelcache symbols file \"%s\"", path);
				break;
			}
			// If we didn't get a symbol, then this is the end.
			if (symbol == NULL) {
				break;
			}
			// TODO: Handle inserting another copy of the same symbol.
			// Insert this symbol in the kernelcache's array.
			kc->symcnt++;
			kc->syms = realloc(kc->syms, kc->symcnt * sizeof(*kc->syms));
			struct kcs_sym *sym = &kc->syms[kc->symcnt - 1];
			sym->addr = address;
			// Check if this symbol already exists in the symbol_strings blob and set
			// the offset.
			void *found = memmem(state->symstr, state->symsize, symbol, length + 1);
			if (found != NULL) {
				// This symbol already exists. Set the offset directly.
				size_t offset = ((uintptr_t) found - (uintptr_t) state->symstr);
				sym->off = (uint32_t) offset;
			} else {
				// This symbol is new. Insert it into the blob.
				size_t new_size = state->symsize + length + 1;
				state->symstr = realloc(state->symstr, new_size);
				strcpy(state->symstr + state->symsize, symbol);
				sym->off = (uint32_t) state->symsize;
				assert(sym->off == state->symsize);
				state->symsize = new_size;
			}
			// Free the symbol.
			free(symbol);
		}
		// All symbols have been parsed, we're done with this file! Update the maximum
		// symbol count so we can pre-allocate the serialized blob.
		if (kc->symcnt > state->maxsymcnt) {
			state->maxsymcnt = kc->symcnt;
		}
next_1:;
		// Unmap the file.
		unmap_file(file_data, file_size);
next_0:;
	}
	// Close the directory.
	closedir(dir);
	return true;
}

// Binary format of kernelcache symbol table upload data:
// {
//     @ offset 0:
//     u32 kernelcache_count;
//     u32 symbol_strings_offset;
//     kernelcache_count * {
//         u8 kernelcache_uuid[16];
//         u32 kernelcache_symbols_offset;
//     };
//     @ kernelcache_symbols_offset:
//     {
//         u32 symbol_count;
//         symbol_count * {
//             u32 symbol_offset;
//             u64 address;
//         };
//     };
//     @ symbol_strings_offset:
//     char symbol_strings[] {
//         @ symbol_offset:
//         char symbol[];
//     }
// }

// Generate a symbol table.
static kernelcache_symbol_table
kernelcache_symbol_table_generate() {
	// For each directory, collect an intermediate representation of all the symbols.
	struct kcs_state state = {};
	for (size_t i = 0; i < kernelcache_symbols_path_count; i++) {
		kernelcache_symbol_table_update_directory(&state, kernelcache_symbols_path[i]);
	}
	// At this point we've parsed all the structures. Time to build the serialized kernelcache
	// symbol table blob.
	kernelcache_symbol_table symbol_table = { NULL, 0 };
	size_t size = sizeof(uint32_t) + sizeof(uint32_t);
	size_t kc_desc_size = sizeof(state.kcs[0].uuid) + sizeof(uint32_t);
	size += state.kccnt * kc_desc_size;
	size_t offset = size;
	size_t sym_size = sizeof(uint32_t) + sizeof(uint64_t);
	size_t kc_syms_size = sizeof(uint32_t) + state.maxsymcnt * sym_size;
	size += state.kccnt * kc_syms_size;
	size += state.symsize;
	uint8_t *blob = malloc(size);
	*(uint32_t *) (blob) = state.kccnt;	// kernelcache_count
	size_t kc_desc = sizeof(uint32_t) + sizeof(uint32_t);
	for (size_t kc_idx = 0; kc_idx < state.kccnt; kc_idx++) {
		// Build the descriptor for this kernelcache UUID.
		assert((uint32_t) offset == offset);
		struct kcs_kc *kc = &state.kcs[kc_idx];
		memcpy(blob + kc_desc, kc->uuid, sizeof(kc->uuid));	// kernelcache_uuid
		kc_desc += sizeof(kc->uuid);
		*(uint32_t *) (blob + kc_desc) = (uint32_t) offset;	// kernelcache_symbols_offset
		kc_desc += sizeof(uint32_t);
		// Build the kernelcache symbols table.
		assert((uint32_t) kc->symcnt == kc->symcnt);
		*(uint32_t *) (blob + offset) = kc->symcnt;	// symbol_count
		offset += sizeof(uint32_t);
		for (size_t i = 0; i < kc->symcnt; i++) {
			*(uint32_t *)(blob + offset) = kc->syms[i].off;	// symbol_offset
			offset += sizeof(uint32_t);
			*(uint64_t *)(blob + offset) = kc->syms[i].addr;	// address
			offset += sizeof(uint64_t);
		}
		assert(offset <= size);
	}
	// Append the symbol strings.
	assert(offset + state.symsize <= size);
	*(uint32_t *)(blob + sizeof(uint32_t)) = offset;	// symbol_strings_offset
	size = offset + state.symsize;
	memcpy(blob + offset, state.symstr, state.symsize);
	symbol_table.data = blob;
	symbol_table.size = size;
	// Free the state allocations.
	for (size_t kc_idx = 0; kc_idx < state.kccnt; kc_idx++) {
		free(state.kcs[kc_idx].syms);
	}
	free(state.kcs);
	free(state.symstr);
	return symbol_table;
}

// Free a symbol table created with kernelcache_symbol_table_generate().
static void
kernelcache_symbol_table_destroy(kernelcache_symbol_table symbol_table) {
	free(symbol_table.data);
}

// ---- pongoOS kext loading ----------------------------------------------------------------------

// The path to the kextload pongo module.
static const char *pongo_kextload_path;

// The path to the iOS kernel extension we want to load.
static const char **kext_path = NULL;
size_t kext_path_count = 0;

// Set the path to the kextload pongo module.
static void
set_pongo_kextload_path(const char *path) {
	pongo_kextload_path = path;
}

// Set the path to the iOS kernel extension we want to load.
static void
set_kext_path(const char *path) {
	kext_path_count++;
	kext_path = realloc(kext_path, kext_path_count * sizeof(*kext_path));
	kext_path[kext_path_count - 1] = path;
}

// Load the kextload pongo module.
static bool
pongo_kext_load_init(pongo_usb_device pongo) {
	// Read the kextload pongoOS module.
	size_t kextload_module_size;
	void *kextload_module = map_file(pongo_kextload_path, &kextload_module_size);
	if (kextload_module == NULL) {
		return false;
	}
	// Set boot arguments to "-v". This clears the ramdisk and enables verbose boot.
	pongo_usb_send_command(pongo, "xargs -v\n", 0);
	// Allow XNU to use the framebuffer for verbose boot.
	pongo_usb_send_command(pongo, "xfb\n", 0);
	// Upload the kextload pongoOS module.
	pongo_usb_init_bulk_upload(pongo);
	pongo_usb_send_bulk_data(pongo, kextload_module, kextload_module_size);
	pongo_usb_send_command(pongo, "modload\n", 0);
	// Unmap the module.
	unmap_file(kextload_module, kextload_module_size);
	// Sleep awhile to let the command process before executing the next command.
	// TODO: Do this asynchronously.
	usleep(200 * 1000);
	return true;
}

// Load a symbol table to the pongoOS device.
static bool
pongo_kext_load_symbols(pongo_usb_device pongo) {
	// Generate the symbol table.
	kernelcache_symbol_table symbol_table = kernelcache_symbol_table_generate();
	if (symbol_table.data == NULL) {
		ERROR("Could not generate symbol table");
		return false;
	}
	// Upload the symbol table.
	pongo_usb_init_bulk_upload(pongo);
	pongo_usb_send_bulk_data(pongo, symbol_table.data, symbol_table.size);
	pongo_usb_send_command(pongo, "kernelcache-symbols\n", 0);
	// Destroy the symbol table.
	kernelcache_symbol_table_destroy(symbol_table);
	// Sleep awhile to let the command process before executing the next command.
	// TODO: Do this asynchronously.
	usleep(200 * 1000);
	return true;
}

// Load an XNU kernel extension.
static bool
pongo_kext_load(pongo_usb_device pongo, const char *path) {
	// Read the kernel extension.
	size_t kext_size;
	void *kext = map_file(path, &kext_size);
	if (kext == NULL) {
		return false;
	}
	// Upload the kernel extension.
	pongo_usb_init_bulk_upload(pongo);
	pongo_usb_send_bulk_data(pongo, kext, kext_size);
	pongo_usb_send_command(pongo, "kextload\n", 0);
	// Unmap the module.
	unmap_file(kext, kext_size);
	// Sleep awhile to let the command process before executing the next command.
	// TODO: Do this asynchronously.
	usleep(200 * 1000);
	return true;
}

// Boot XNU.
static void
pongo_kext_boot_xnu(pongo_usb_device pongo) {
	// Boot the kernel with the kernel extension(s).
	pongo_usb_send_command(pongo, "bootx\n", 0);
}

// State for a currently tracked pongoOS device.
struct pongo_instance {
	struct pongo_instance *next;
	pongo_usb_device device;
	int state; // 0 = need kextload module; 1 = need symbols; 2 = need kext; 3 = need boot
};

// State for the pongoOS kext loading subsystem.
struct pongo_kext_loader_state {
	int kq;
	mach_port_t port_set;
	struct pongo_instance *instances;
};

// Create a pongo_instance to keep track of a pongoOS device on which we will operate.
static struct pongo_instance *
pongo_instance_create(struct pongo_kext_loader_state *state, io_service_t service) {
	printf("[%x] Found pongoOS device\n", service);
	pongo_usb_device device = pongo_usb_open(service, state->port_set);
	if (device == PONGO_USB_NULL) {
		return NULL;
	}
	struct pongo_instance *instance = calloc(1, sizeof(*instance));
	instance->device = device;
	instance->next = state->instances;
	state->instances = instance;
	return instance;
}

// Perform the kext loading operation on the pongo_instance object.
static bool
pongo_instance_load_kext(struct pongo_instance *instance) {
	// TODO: Make these steps asynchronous.
	printf("[%x] Loading pongoOS kextload module\n", instance->device->service);
	bool ok = pongo_kext_load_init(instance->device);
	if (!ok) {
		goto fail;
	}
	printf("[%x] Loading kernel symbols\n", instance->device->service);
	ok = pongo_kext_load_symbols(instance->device);
	if (!ok) {
		goto fail;
	}
	printf("[%x] Loading kernel extensions\n", instance->device->service);
	for (size_t i = 0; i < kext_path_count; i++) {
		ok = pongo_kext_load(instance->device, kext_path[i]);
		if (!ok) {
			goto fail;
		}
	}
	pongo_kext_boot_xnu(instance->device);
	return true;
fail:
	ERROR("Could not load kernel extension on pongoOS device %x", instance->device->service);
	return false;
}

// Destroy a pongo_instance and clean up state once the pongoOS device goes away.
static void
pongo_instance_destroy(struct pongo_kext_loader_state *state, io_service_t service) {
	printf("[%x] Closing pongoOS device\n", service);
	// Find the matching instance in the linked list. link is the pointer to instance.
	struct pongo_instance **link = &state->instances;
	struct pongo_instance *instance;
	for (;;) {
		instance = *link;
		if (instance == NULL) {
			return;
		}
		if (pongo_usb_matches_service(instance->device, service)) {
			break;
		}
		link = &instance->next;
	}
	// Unlink the instance.
	*link = instance->next;
	instance->next = NULL;
	// Close the pongoOS USB device.
	pongo_usb_close(instance->device);
	// Free the allocation.
	free(instance);
}

// A pongoOS device was added. Do the kext load operation.
static void
pongo_device_added(void *refCon, io_iterator_t iterator) {
	struct pongo_kext_loader_state *state = refCon;
	for (;;) {
		io_service_t service = IOIteratorNext(iterator);
		if (service == IO_OBJECT_NULL) {
			break;
		}
		// Open the pongoOS device.
		struct pongo_instance *instance = pongo_instance_create(state, service);
		if (instance != NULL) {
			pongo_instance_load_kext(instance);
		}
		IOObjectRelease(service);
	}
}

// A pongoOS device was removed.
static void
pongo_device_removed(void *refCon, io_iterator_t iterator) {
	struct pongo_kext_loader_state *state = refCon;
	for (;;) {
		io_service_t service = IOIteratorNext(iterator);
		if (service == IO_OBJECT_NULL) {
			break;
		}
		// Close the pongoOS device.
		pongo_instance_destroy(state, service);
		IOObjectRelease(service);
	}
}

// Dispatch notification callbacks received on the port set.
static void
handle_notification_message(struct pongo_kext_loader_state *state) {
	for (;;) {
		struct {
			mach_msg_header_t hdr;
			uint8_t data[0x300];
		} msg = {};
		kern_return_t kr = mach_msg(&msg.hdr,
				MACH_RCV_MSG | MACH_RCV_TIMEOUT,
				0,
				sizeof(msg),
				state->port_set,
				0,
				MACH_PORT_NULL);
		if (kr != KERN_SUCCESS) {
			if (kr != MACH_RCV_TIMED_OUT) {
				ERROR("Could not receive Mach message");
			}
			break;
		}
		IODispatchCalloutFromMessage(NULL, &msg.hdr, NULL);
	}
}

// The main kext loading loop.
static bool
pongo_usb_kext_loader() {
	bool success = false;
	struct pongo_kext_loader_state state = {};
	// Open a kernel event queue.
	state.kq = kqueue();
	if (state.kq < 0) {
		ERROR("Could not create kqueue");
		goto fail_0;
	}
	// Create a Mach port set to monitor Mach ports using kqueue()/kevent().
	kern_return_t kr = mach_port_allocate(mach_task_self(),
			MACH_PORT_RIGHT_PORT_SET, &state.port_set);
	if (kr != KERN_SUCCESS) {
		ERROR("Could not create port set");
		goto fail_1;
	}
	// Add the port set to the kqueue.
	struct kevent kev;
	EV_SET(&kev, state.port_set, EVFILT_MACHPORT, EV_ADD, 0, 0, 0);
	int count = kevent(state.kq, &kev, 1, NULL, 0, NULL);
	if (count < 0) {
		ERROR("Could not register to receive message notifications on the port set");
		goto fail_2;
	}
	// Create a notification port on which to listen for notifications that pongoOS devices
	// have been added or removed, and add the notification port to the port set.
	IONotificationPortRef notify_port = IONotificationPortCreate(kIOMasterPortDefault);
	mach_port_t notify_mach_port = IONotificationPortGetMachPort(notify_port);
	kr = mach_port_insert_member(mach_task_self(), notify_mach_port, state.port_set);
	if (kr != KERN_SUCCESS) {
		ERROR("Could not insert notification port into port set");
		goto fail_3;
	}
	// Register to receive notifications when a pongoOS device has been added.
	CFDictionaryRef match_pongo = create_pongo_iokit_usb_matching_dictionary();
	io_iterator_t pongo_device_added_iterator = IO_OBJECT_NULL;
	CFRetain(match_pongo);
	kr = IOServiceAddMatchingNotification(notify_port, kIOFirstMatchNotification,
			match_pongo, pongo_device_added,
			&state, &pongo_device_added_iterator);
	if (kr != KERN_SUCCESS) {
		CFRelease(match_pongo);
		ERROR("Could not register to receive pongoOS USB first match notifications");
		goto fail_3;
	}
	// Register to receive notifications when a pongoOS device has been removed.
	io_iterator_t pongo_device_removed_iterator;
	kr = IOServiceAddMatchingNotification(notify_port, kIOTerminatedNotification,
			match_pongo, pongo_device_removed,
			&state, &pongo_device_removed_iterator);
	if (kr != KERN_SUCCESS) {
		ERROR("Could not register to receive pongoOS USB removal notifications");
		goto fail_4;
	}
	// Arm the pongoOS device added and removed notifications. This will also process any
	// existing devices.
	pongo_device_added(&state, pongo_device_added_iterator);
	pongo_device_removed(&state, pongo_device_removed_iterator);
	// Enter the main processing loop.
	for (;;) {
		// Wait for an event to occur.
		memset(&kev, 0, sizeof(kev));
		count = kevent(state.kq, NULL, 0, &kev, 1, NULL);
		if (count < 0) {
			ERROR("%s: %s", "kevent", strerror(errno));
			goto fail_5;
		}
		if (count == 0) {
			WARNING("%s returned %d", "kevent", count);
			continue;
		}
		// Handle a message on our port set. These are always dispatch messages, and will
		// dispatch to pongo_device_added(), pongo_device_removed(), or
		// pongo_usb_recv_done().
		if (kev.filter == EVFILT_MACHPORT && kev.ident == state.port_set) {
			// Process any messages that need to be dispatched.
			handle_notification_message(&state);
			// Note port closure.
			if (kev.flags & EV_EOF) {
				WARNING("EOF port");
			}
		}
	}
	success = true;
	// Clean up.
fail_5:
	IOObjectRelease(pongo_device_removed_iterator);
fail_4:
	IOObjectRelease(pongo_device_added_iterator);
fail_3:
	IONotificationPortDestroy(notify_port);
fail_2:
	mach_port_destroy(mach_task_self(), state.port_set);
fail_1:
	close(state.kq);
fail_0:
	return success;
}

// ---- Main --------------------------------------------------------------------------------------

// Print usage information.
_Noreturn static void
usage() {
	printf("%s -l <kextload-module> (-s <kernel-symbols>)... (-k <xnu-kext>)...\n"
		"\n"
		"Loads and boots an XNU kernel extension on all attached pongoOS devices.\n"
		"\n"
		"    <kextload-module>   The pongoOS kext loading module\n"
		"    <kernel-symbols>    A directory containing kernel symbols\n"
		"    <xnu-kext>          An XNU kernel extension to load into the kernelcache\n"
		"\n",
		getprogname());
	exit(1);
}

// Checks whether the specified path is readable. This is strictly advisory, since the file can be
// modified after this point.
static void
path_accessible(const char *path, int type, const char *description) {
	int ret = access(path, type);
	if (ret != 0) {
		ERROR("Can not read %s \"%s\"", description, path);
		exit(1);
	}
}

static void
handle_pongo_kextload_path(const char *path) {
	if (pongo_kextload_path != NULL) {
		ERROR("Only one pongoOS kext loading module is allowed");
		exit(1);
	}
	path_accessible(path, R_OK, "pongoOS kextload module");
	set_pongo_kextload_path(path);
}

static void
handle_symbols_path(const char *path) {
	path_accessible(path, X_OK, "kernel symbols directory");
	set_kernelcache_symbols_path(path);
}

static void
handle_kext_path(const char *path) {
	path_accessible(path, R_OK, "XNU kernel extension");
	set_kext_path(path);
}

// Main function.
int
main(int argc, const char *argv[]) {
	if (argc <= 1) {
		usage();
	}
	// Parse the arguments.
	int argi = 1;
#define next_arg()	({ if (argi >= argc) { \
			       usage(); \
			   } \
			   argv[argi++]; })
	while (argi < argc) {
		const char *arg = next_arg();
		if (strcmp(arg, "-l") == 0) {
			const char *path = next_arg();
			handle_pongo_kextload_path(path);
		} else if (strcmp(arg, "-s") == 0) {
			const char *path = next_arg();
			handle_symbols_path(path);
		} else if (strcmp(arg, "-k") == 0) {
			const char *path = next_arg();
			handle_kext_path(path);
		} else {
			usage();
		}
	}
	bool error = false;
	if (pongo_kextload_path == NULL) {
		ERROR("No pongoOS kext loading module specified");
		error = true;
	}
	if (kernelcache_symbols_path_count == 0) {
		ERROR("No kernelcache symbols directory specified");
		error = true;
	}
	if (kext_path_count == 0) {
		ERROR("No XNU kernel extensions specified");
		error = true;
	}
	if (error) {
		exit(1);
	}
	pongo_usb_kext_loader();
	return 0;
}
