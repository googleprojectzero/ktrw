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

#ifndef IOKITLIB__H_
#define IOKITLIB__H_

#include <CoreFoundation/CoreFoundation.h>
#include <mach/mach.h>

typedef mach_port_t	io_object_t;
typedef io_object_t	io_connect_t;
typedef io_object_t	io_iterator_t;
typedef io_object_t	io_service_t;

extern const mach_port_t kIOMasterPortDefault;

kern_return_t
IOObjectRelease(
	io_object_t	object );

io_object_t
IOIteratorNext(
	io_iterator_t	iterator );

io_service_t
IOServiceGetMatchingService(
	mach_port_t	masterPort,
	CFDictionaryRef	matching CF_RELEASES_ARGUMENT);

kern_return_t
IOServiceGetMatchingServices(
	mach_port_t	masterPort,
	CFDictionaryRef	matching CF_RELEASES_ARGUMENT,
	io_iterator_t * existing );

kern_return_t
IOServiceOpen(
	io_service_t    service,
	task_port_t	owningTask,
	uint32_t	type,
	io_connect_t  *	connect );

kern_return_t
IOServiceClose(
	io_connect_t	connect );

kern_return_t
IOConnectCallMethod(
	mach_port_t	 connection,		// In
	uint32_t	 selector,		// In
	const uint64_t	*input,			// In
	uint32_t	 inputCnt,		// In
	const void      *inputStruct,		// In
	size_t		 inputStructCnt,	// In
	uint64_t	*output,		// Out
	uint32_t	*outputCnt,		// In/Out
	void		*outputStruct,		// Out
	size_t		*outputStructCnt)	// In/Out
AVAILABLE_MAC_OS_X_VERSION_10_5_AND_LATER;

kern_return_t
IOConnectTrap6(io_connect_t	connect,
	uint32_t		index,
	uintptr_t	p1,
	uintptr_t	p2,
	uintptr_t	p3,
	uintptr_t	p4,
	uintptr_t	p5,
	uintptr_t	p6);

CFMutableDictionaryRef
IOServiceMatching(
	const char *	name ) CF_RETURNS_RETAINED;

#endif
