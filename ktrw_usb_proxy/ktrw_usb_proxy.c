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

#include <assert.h>
#include <CoreFoundation/CoreFoundation.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <IOKit/IOCFPlugin.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/usb/IOUSBLib.h>
#include <mach/mach.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/event.h>
#include <sys/socket.h>
#include <unistd.h>

// ---- KTRW USB interface ------------------------------------------------------------------------

// Allocate a CFDictionary that will match the KTRW debugger's USB device descriptor.
static CFDictionaryRef
create_ktrw_iokit_usb_matching_dictionary() {
	CFMutableDictionaryRef matchingDict = IOServiceMatching(kIOUSBDeviceClassName);
	int32_t appleVendorId = kAppleVendorID;
	CFNumberRef vendorId = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, &appleVendorId);
	CFDictionarySetValue(matchingDict, CFSTR(kUSBVendorID), vendorId);
	CFRelease(vendorId);
	int32_t ktrwProductId = 0x1337;
	CFNumberRef productId = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, &ktrwProductId);
	CFDictionarySetValue(matchingDict, CFSTR(kUSBProductID), productId);
	CFRelease(productId);
	return matchingDict;
}

// A KTRW USB device.
struct _ktrw_usb_device {
	io_service_t service;
	IOUSBDeviceInterface182 **device;
	IOUSBInterfaceInterface182 **interface;
	void (*read_callback)(void *context, ssize_t read_count);
	void *read_context;
};
typedef struct _ktrw_usb_device *ktrw_usb_device;

// Represents an empty/invalid device.
#define KTRW_USB_NULL	((ktrw_usb_device) NULL)

// The maximum number of tries to open.
#define KTRW_USB_OPEN_MAX_TRIES	5

// Open the KTRW USB device.
static ktrw_usb_device
ktrw_usb_open(io_service_t service, mach_port_t notification_port_set) {
	// Create a Plug-In interface for the service.
	IOCFPlugInInterface **plugIn;
	SInt32 score;
	kern_return_t kr = IOCreatePlugInInterfaceForService(service, kIOUSBDeviceUserClientTypeID,
			kIOCFPlugInInterfaceID, &plugIn, &score);
	if (kr != KERN_SUCCESS) {
		printf("Error: Could not create IOCFPlugInInterface for KTRW USB device\n");
		goto fail_0;
	}
	// Create an IOUSBDeviceInterface for the USB device.
	IOUSBDeviceInterface182 **device = NULL;
	(*plugIn)->QueryInterface(plugIn, CFUUIDGetUUIDBytes(kIOUSBDeviceInterfaceID182),
			(LPVOID *)&device);
	(*plugIn)->Release(plugIn);
	if (device == NULL) {
		printf("Error: Could not create IOUSBDeviceInterface for KTRW USB device\n");
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
		if (try >= KTRW_USB_OPEN_MAX_TRIES) {
			printf("Error: Could not open IOUSBDeviceInterface for KTRW USB device: 0x%x: %s\n",
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
			printf("Error: Could not create iterator over KTRW USB device's interfaces\n");
			goto fail_2;
		}
		// Grab the first interface match.
		interface_service = IOIteratorNext(interfaces);
		IOObjectRelease(interfaces);
		if (interface_service != IO_OBJECT_NULL) {
			break;
		}
		if (try >= KTRW_USB_OPEN_MAX_TRIES) {
			printf("Error: No interfaces found for KTRW USB device\n");
			goto fail_2;
		}
		usleep(100000);
	}
	// Create a Plug-In interface for the service.
	kr = IOCreatePlugInInterfaceForService(interface_service, kIOUSBInterfaceUserClientTypeID,
			kIOCFPlugInInterfaceID, &plugIn, &score);
	IOObjectRelease(interface_service);
	if (kr != KERN_SUCCESS) {
		printf("Error: Could not create IOCFPlugInInterface for KTRW USB interface\n");
		goto fail_2;
	}
	// Create an IOUSBDeviceInterface for the USB device.
	IOUSBInterfaceInterface182 **interface = NULL;
	(*plugIn)->QueryInterface(plugIn, CFUUIDGetUUIDBytes(kIOUSBInterfaceInterfaceID182),
			(LPVOID *)&interface);
	(*plugIn)->Release(plugIn);
	if (interface == NULL) {
		printf("Error: Could not create IOUSBInterfaceInterface for KTRW USB interface\n");
		goto fail_2;
	}
	// Open the interface.
	result = (*interface)->USBInterfaceOpen(interface);
	if (result != kIOReturnSuccess) {
		printf("Error: Could not open IOUSBInterfaceInterface for KTRW USB device\n");
		goto fail_3;
	}
	// Check the number of endpoints.
	UInt8 numEndpoints;
	result = (*interface)->GetNumEndpoints(interface, &numEndpoints);
	if (result != kIOReturnSuccess) {
		printf("Error: Could not get the number of endpoints for the KTRW USB device interface\n");
		goto fail_4;
	}
	if (numEndpoints != 2) {
		printf("Warning: Unexpected number of endpoints for the KTRW USB device "
				"interface: %u\n", numEndpoints);
	}
	// Register a Mach port to receive asynchronous I/O completion notifications.
	mach_port_t io_port = MACH_PORT_NULL;
	kr = (*interface)->CreateInterfaceAsyncPort(interface, &io_port);
	if (kr != KERN_SUCCESS) {
		printf("Error: Could not create KTRW USB asynchronous notification port\n");
		goto fail_4;
	}
	// Add the async port to the notification port set.
	kr = mach_port_insert_member(mach_task_self(), io_port, notification_port_set);
	mach_port_deallocate(mach_task_self(), io_port);
	if (kr != KERN_SUCCESS) {
		printf("Error: Could not add KTRW USB asynchronous notification port to port set\n");
		goto fail_4;
	}
	// Create the ktrw_usb_device.
	ktrw_usb_device ktrw = calloc(1, sizeof(*ktrw));
	assert(ktrw != NULL);
	ktrw->service = service;
	ktrw->device = device;
	ktrw->interface = interface;
	return ktrw;
fail_4:
	(*interface)->USBInterfaceClose(interface);
fail_3:
	(*interface)->Release(interface);
fail_2:
	(*device)->USBDeviceClose(device);
fail_1:
	(*device)->Release(device);
fail_0:
	return KTRW_USB_NULL;
}

// Close the device returned by ktrw_usb_open().
static void
ktrw_usb_close(ktrw_usb_device ktrw) {
	if (ktrw != KTRW_USB_NULL) {
		if (ktrw->interface != NULL) {
			(*ktrw->interface)->USBInterfaceClose(ktrw->interface);
			(*ktrw->interface)->Release(ktrw->interface);
		}
		if (ktrw->device != NULL) {
			(*ktrw->device)->USBDeviceClose(ktrw->device);
			(*ktrw->device)->Release(ktrw->device);
		}
		if (ktrw->service != IO_OBJECT_NULL) {
			IOObjectRelease(ktrw->service);
		}
		free(ktrw);
	}
}

// Checks whether the specified IOService corresponds to the KTRW USB device.
static bool
ktrw_usb_matches_service(ktrw_usb_device ktrw, io_service_t service) {
	return (ktrw != KTRW_USB_NULL && ktrw->service == service);
}

// Send data synchronously to KTRW.
static ssize_t
ktrw_usb_send(ktrw_usb_device ktrw, const void *data, size_t size) {
	assert(size <= 0x1000);
	IOUSBDevRequest request = {};
	request.bmRequestType = USBmakebmRequestType(kUSBOut, kUSBVendor, kUSBDevice);
	request.bRequest      = 0x41;
	request.wValue        = 0;
	request.wIndex        = 0x1337;
	request.wLength       = (uint16_t) size;
	request.pData         = (void *) data;
	IOReturn result = (*ktrw->device)->DeviceRequest(ktrw->device, &request);
	if (result != kIOReturnSuccess) {
		printf("Error: Could not %s KTRW data: %x: %s\n", "write",
				result, mach_error_string(result));
		return -1;
	}
	return request.wLenDone;
}

// An internal function to invoke the callback supplied to ktrw_usb_recv().
static void
ktrw_usb_recv_done(void *refCon, IOReturn result, void *arg0) {
	ktrw_usb_device ktrw = refCon;
	UInt32 read_size = (UInt32) (uintptr_t) arg0;
	void (*callback)(void *context, ssize_t read_count) = ktrw->read_callback;
	void *context = ktrw->read_context;
	ktrw->read_callback = NULL;
	ktrw->read_context = NULL;
	ssize_t read_count = read_size;
	if (result != kIOReturnSuccess) {
		printf("Error: Could not %s KTRW data: %x: %s\n", "read",
				result, mach_error_string(result));
		read_count = -1;
	}
	callback(context, read_count);
}

// Asynchronously receive data from KTRW.
static void
ktrw_usb_recv(ktrw_usb_device ktrw, void *data, size_t size,
		void (*callback)(void *context, ssize_t size), void *context) {
	assert(size <= 0x1000);
	assert(ktrw->read_callback == NULL && ktrw->read_context == NULL);
	ktrw->read_callback = callback;
	ktrw->read_context  = context;
	(*ktrw->interface)->ReadPipeAsync(ktrw->interface, 1, data, size,
			ktrw_usb_recv_done, ktrw);
}

// ---- KTRW USB proxy loop -----------------------------------------------------------------------

// Log data passing from KTRW to GDB or GDB to KTRW. Pass a state of 0 for KTRW -> ???, 1 for KTRW
// -> GDB, 2 for GDB -> KTRW, 3 for GDB -> ???.
static void
log_data(const void *data, size_t size, size_t read, int state) {
	const char *char_data = data;
	char buffer[size];
	for (size_t i = 0; i < read; i++) {
		char ch = char_data[i];
		if (!isprint(ch)) {
			ch = '.';
		}
		buffer[i] = ch;
	}
	const char *marker = "??";
	const char *sep = "";
	switch (state) {
		case 0: sep = "  "; marker = "-|"; break;
		case 1: sep = "  "; marker = "->"; break;
		case 2: sep = "";   marker = "<-"; break;
		case 3: sep = "";   marker = "|-"; break;
	}
	printf(" %s%s %.*s\n", marker, sep, (int)read, buffer);
}

// Holds state for a connection between KTRW and GDB.
struct ktrw_connection_state {
	ktrw_usb_device ktrw;
	int socket;
	mach_port_t port_set;
	// We need this read buffer here because reading from KTRW is asynchronous. Writing to KTRW
	// is synchronous, so we don't need the corresponding write buffer.
	uint8_t ktrw_read_buffer[0x1000];
};

// Handle input from KTRW and queue another request to receive input. This function is indirectly
// called by handle_notification_message()/IODispatchCalloutFromMessage(), which processes the
// completion notification for the read request.
static void
handle_ktrw_input(void *context, ssize_t read_count) {
	struct ktrw_connection_state *state = context;
	if (state->ktrw == KTRW_USB_NULL) {
		printf("Error: KTRW device disappeared\n");
		return;
	}
	// Process the input data.
	if (read_count > 0) {
		log_data(state->ktrw_read_buffer, sizeof(state->ktrw_read_buffer),
				read_count, (state->socket < 0 ? 0 : 1));
		// Send the data to the socket.
		if (state->socket >= 0) {
			ssize_t written = write(state->socket,
					state->ktrw_read_buffer, read_count);
			if (written != read_count) {
				printf("Error: %s: %s\n", "write", strerror(errno));
			}
		}
	}
	// Fire off another read request.
	ktrw_usb_recv(state->ktrw, state->ktrw_read_buffer, sizeof(state->ktrw_read_buffer),
			handle_ktrw_input, state);
}

// A KTRW device was added.
static void
ktrw_device_added(void *refCon, io_iterator_t iterator) {
	struct ktrw_connection_state *state = refCon;
	for (;;) {
		io_service_t service = IOIteratorNext(iterator);
		if (service == IO_OBJECT_NULL) {
			break;
		}
		if (state->ktrw != KTRW_USB_NULL) {
			printf("Ignoring additional KTRW device\n");
		} else {
			// Open the KTRW device.
			printf("Found KTRW device %x\n", service);
			state->ktrw = ktrw_usb_open(service, state->port_set);
			if (state->ktrw != KTRW_USB_NULL) {
				printf("Opened KTRW device\n");
				// Fire off the first read.
				ktrw_usb_recv(state->ktrw, state->ktrw_read_buffer,
						sizeof(state->ktrw_read_buffer), handle_ktrw_input,
						state);
			}
		}
		IOObjectRelease(service);
	}
}

// A KTRW device was removed.
static void
ktrw_device_removed(void *refCon, io_iterator_t iterator) {
	struct ktrw_connection_state *state = refCon;
	for (;;) {
		io_service_t service = IOIteratorNext(iterator);
		if (service == IO_OBJECT_NULL) {
			break;
		}
		if (ktrw_usb_matches_service(state->ktrw, service)) {
			printf("Closing KTRW device\n");
			ktrw_usb_close(state->ktrw);
			state->ktrw = KTRW_USB_NULL;
		}
		IOObjectRelease(service);
	}
}

// Handle a connection request on the server socket. Only one client is allowed at a time.
static void
handle_server_connection(int server_fd, int kq, struct ktrw_connection_state *state) {
	// Accept a connection on our server socket.
	struct sockaddr_storage conn_addr;
	socklen_t conn_addr_len = sizeof(conn_addr);
	int conn_fd = accept(server_fd, (struct sockaddr *) &conn_addr, &conn_addr_len);
	if (conn_fd < 0) {
		printf("Error: %s: %s\n", "accept", strerror(errno));
		goto fail_0;
	}
	// If we don't have a KTRW device or already have a connected client, reject.
	if (state->ktrw == KTRW_USB_NULL) {
		printf("Closing connection: No KTRW USB devices available\n");
		goto fail_1;
	}
	if (state->socket != -1) {
		printf("Closing connection: Already have a connection\n");
		goto fail_1;
	}
	// Mark the socket as non-blocking.
	int flags = fcntl(conn_fd, F_GETFL, 0);
	if (flags == -1) {
		printf("Error: %s: %s\n", "fcntl", strerror(errno));
		goto fail_1;
	}
	flags |= O_NONBLOCK;
	int err = fcntl(conn_fd, F_SETFL, flags);
	if (err != 0) {
		printf("Error: %s: %s\n", "fcntl", strerror(errno));
		goto fail_1;
	}
	// Monitor the socket file descriptor for the ability to read.
	struct kevent kev;
	EV_SET(&kev, conn_fd, EVFILT_READ, EV_ADD, 0, 0, 0);
	int count = kevent(kq, &kev, 1, NULL, 0, NULL);
	if (count < 0) {
		printf("Error: %s: %s\n", "kevent", strerror(errno));
		goto fail_1;
	}
	// Success!
	state->socket = conn_fd;
	return;
fail_1:
	close(conn_fd);
fail_0:
	return;
}

// Handle input on the socket synchronously. Socket input is forwarded directly over USB to KTRW.
static void
handle_socket_input(struct ktrw_connection_state *state, intptr_t input_size) {
	size_t left = input_size;
	while (left) {
		// Read the packet. We don't need the source address since we're assuming this all
		// takes place on localhost.
		char buffer[0x1000];
		size_t capacity = sizeof(buffer);
		if (capacity > left) {
			capacity = left;
		}
		ssize_t read_count = read(state->socket, buffer, capacity);
		// If we failed to read anything, stop processing.
		if (read_count <= 0) {
			break;
		}
		// Process the input data.
		log_data(buffer, sizeof(buffer), read_count,
				(state->ktrw != KTRW_USB_NULL ? 2 : 3));
		// We've consumed read_count bytes.
		left -= read_count;
		// Send the data to KTRW.
		if (state->ktrw != KTRW_USB_NULL) {
			ssize_t sent = ktrw_usb_send(state->ktrw, buffer, read_count);
			if (sent < read_count) {
				printf("Error: Could not send data to KTRW\n");
			}
		}
	}
}

// Dispatch notification callbacks received on the port set.
static void
handle_notification_message(struct ktrw_connection_state *state) {
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
				printf("Error: Could not receive Mach message\n");
			}
			break;
		}
		IODispatchCalloutFromMessage(NULL, &msg.hdr, NULL);
	}
}

static bool
ktrw_usb_proxy(int server_fd) {
	bool success = false;
	// This struct holds state for the connection.
	struct ktrw_connection_state state = {};
	state.ktrw = KTRW_USB_NULL;
	state.socket = -1;
	state.port_set = MACH_PORT_NULL;
	// Open a kernel event queue.
	int kq = kqueue();
	if (kq < 0) {
		printf("Error: Could not create kqueue\n");
		goto fail_0;
	}
	// Monitor the server file descriptor for an available connection.
	struct kevent kev;
	EV_SET(&kev, server_fd, EVFILT_READ, EV_ADD, 0, 0, 0);
	int count = kevent(kq, &kev, 1, NULL, 0, NULL);
	if (count < 0) {
		printf("Error: Could not register to receive connection notifications on the server socket\n");
		goto fail_1;
	}
	// Create a Mach port set to monitor Mach ports using kqueue()/kevent().
	kern_return_t kr = mach_port_allocate(mach_task_self(),
			MACH_PORT_RIGHT_PORT_SET, &state.port_set);
	if (kr != KERN_SUCCESS) {
		printf("Error: Could not create port set\n");
		goto fail_1;
	}
	// Add the port set to the kqueue.
	EV_SET(&kev, state.port_set, EVFILT_MACHPORT, EV_ADD, 0, 0, 0);
	count = kevent(kq, &kev, 1, NULL, 0, NULL);
	if (count < 0) {
		printf("Error: Could not register to receive message notifications on the port set\n");
		goto fail_2;
	}
	// Create a notification port on which to listen for notifications that KTRW devices have
	// been added or removed, and add the notification port to the port set.
	IONotificationPortRef notify_port = IONotificationPortCreate(kIOMasterPortDefault);
	mach_port_t notify_mach_port = IONotificationPortGetMachPort(notify_port);
	kr = mach_port_insert_member(mach_task_self(), notify_mach_port, state.port_set);
	if (kr != KERN_SUCCESS) {
		printf("Error: Could not insert notification port into port set\n");
		goto fail_3;
	}
	// Register to receive notifications when a KTRW device has been added.
	CFDictionaryRef match_ktrw = create_ktrw_iokit_usb_matching_dictionary();
	io_iterator_t ktrw_device_added_iterator = IO_OBJECT_NULL;
	CFRetain(match_ktrw);
	kr = IOServiceAddMatchingNotification(notify_port, kIOFirstMatchNotification,
			match_ktrw, ktrw_device_added,
			&state, &ktrw_device_added_iterator);
	if (kr != KERN_SUCCESS) {
		CFRelease(match_ktrw);
		printf("Error: Could not register to receive KTRW USB first match notifications\n");
		goto fail_3;
	}
	// Register to receive notifications when a KTRW device has been removed.
	io_iterator_t ktrw_device_removed_iterator;
	kr = IOServiceAddMatchingNotification(notify_port, kIOTerminatedNotification,
			match_ktrw, ktrw_device_removed,
			&state, &ktrw_device_removed_iterator);
	if (kr != KERN_SUCCESS) {
		printf("Error: Could not register to receive KTRW USB removal notifications\n");
		goto fail_4;
	}
	// Arm the KTRW device added and removed notifications. This will also process any existing
	// devices.
	ktrw_device_added(&state, ktrw_device_added_iterator);
	ktrw_device_removed(&state, ktrw_device_removed_iterator);
	// Enter the main processing loop.
	for (;;) {
		// Wait for an event to occur.
		memset(&kev, 0, sizeof(kev));
		count = kevent(kq, NULL, 0, &kev, 1, NULL);
		if (count < 0) {
			printf("Error: %s: %s\n", "kevent", strerror(errno));
			goto fail_5;
		}
		if (count == 0) {
			printf("Warning: %s returned %d\n", "kevent", count);
			continue;
		}
		// Handle an event on our server file descriptor.
		if (kev.filter == EVFILT_READ && kev.ident == server_fd) {
			// If we've received EOF on our server socket, exit.
			if (kev.flags & EV_EOF) {
				printf("EOF server\n");
				break;
			}
			// Create a client connection.
			handle_server_connection(server_fd, kq, &state);
		}
		// Handle an event on our socket file descriptor.
		if (kev.filter == EVFILT_READ && kev.ident == state.socket) {
			// Process any input.
			handle_socket_input(&state, kev.data);
			// If we've received EOF, then our socket is no longer functional. Close it
			// (which removes it from the kqueue) and set it to -1 so that we can
			// accept new connections.
			if (kev.flags & EV_EOF) {
				printf("EOF socket\n");
				close(state.socket);
				state.socket = -1;
			}
		}
		// Handle a message on our port set. These are always dispatch messages.
		if (kev.filter == EVFILT_MACHPORT && kev.ident == state.port_set) {
			// Process any messages that need to be dispatched.
			handle_notification_message(&state);
			// Note port closure.
			if (kev.flags & EV_EOF) {
				printf("EOF port\n");
			}
		}
	}
	success = true;
	// Clean up.
fail_5:
	IOObjectRelease(ktrw_device_removed_iterator);
fail_4:
	IOObjectRelease(ktrw_device_added_iterator);
fail_3:
	IONotificationPortDestroy(notify_port);
fail_2:
	mach_port_destroy(mach_task_self(), state.port_set);
fail_1:
	close(kq);
fail_0:
	return success;
}

// ---- Main --------------------------------------------------------------------------------------

// Open the socket that listens for connections.
static bool
open_server_socket(unsigned port, int *server_fd) {
	// Create the socket.
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		printf("Error: %s: %s\n", "socket", strerror(errno));
		goto fail_0;
	}
	// Allow immediate reuse of the port.
	int optval = 1;
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
	// Bind the socket to the port.
	struct sockaddr_in sa = {};
	sa.sin_family      = AF_INET;
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	sa.sin_port        = htons(port);
	int err = bind(fd, (struct sockaddr *)&sa, sizeof(sa));
	if (err != 0) {
		printf("Error: %s: %s\n", "bind", strerror(errno));
		goto fail_1;
	}
	// Don't store a listening backlog.
	err = listen(fd, 0);
	if (err != 0) {
		printf("Error: %s: %s\n", "listen", strerror(errno));
		goto fail_1;
	}
	// Success!
	*server_fd = fd;
	return true;
fail_1:
	close(fd);
fail_0:
	return false;
}

// Print usage information.
_Noreturn static void
usage() {
	printf("%s <tcp-port>\n"
		"\n"
		"    <tcp-port>          39399\n"
		"\n",
		getprogname());
	exit(1);
}

// Convert a string to number.
static bool
parse_int(const char *str, unsigned long *value) {
	char *end;
	unsigned long v = strtoul(str, &end, 10);
	if (*end != 0) {
		return false;
	}
	*value = v;
	return true;
}

// Main function.
int
main(int argc, const char *argv[]) {
	// Parse the arguments.
	if (argc != 2) {
		usage();
	}
	unsigned long port;
	bool ok = parse_int(argv[1], &port);
	if (!ok || port > 65535) {
		usage();
	}
	// Open the socket.
	int server_fd = -1;
	ok = open_server_socket(port, &server_fd);
	if (!ok) {
		return 1;
	}
	ktrw_usb_proxy(server_fd);
	close(server_fd);
	return 0;
}
