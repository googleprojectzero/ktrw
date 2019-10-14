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

#ifndef PARAMETERS__H_
#define PARAMETERS__H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "platform.h"

// Marks a parameter as a weak symbol, allowing multiple non-conflicting definitions.
#define PARAMETER_SHARED __attribute__((weak))

// Generate the name for an offset.
#define OFFSET(base_, object_)		_##base_##__##object_##__offset_

// Generate the name for the size of an object.
#define SIZE(object_)			_##object_##__size_

// Generate the name for the address of an object.
#define ADDRESS(object_)		_##object_##__address_

// Generate the name for the static (unslid) address of an object.
#define STATIC_ADDRESS(object_)		_##object_##__static_address_

// A structure describing the PAC codes used as part of the context for signing and verifying
// virtual method pointers in a vtable.
struct vtable_pac_codes {
	size_t count;
	const uint16_t *codes;
};

// Generate the name for an offset in a virtual method table.
#define VTABLE_INDEX(class_, method_)	_##class_##_##method_##__vtable_index_

// Generate the name for a list of vtable PAC codes.
#define VTABLE_PAC_CODES(class_)	_##class_##__vtable_pac_codes_

// A helper macro for INIT_VTABLE_PAC_CODES().
#define VTABLE_PAC_CODES_DATA(class_)	_##class_##__vtable_pac_codes_data_

// Initialize a list of vtable PAC codes. In order to store the PAC code array in constant memory,
// we place it in a static variable. Consequently, this macro will produce name conflicts if used
// outside a function.
#define INIT_VTABLE_PAC_CODES(class_, ...)						\
	static const uint16_t VTABLE_PAC_CODES_DATA(class_)[] = { __VA_ARGS__ };	\
	VTABLE_PAC_CODES(class_) = (struct vtable_pac_codes) {				\
		.count = sizeof(VTABLE_PAC_CODES_DATA(class_)) / sizeof(uint16_t),	\
		.codes = (const uint16_t *) VTABLE_PAC_CODES_DATA(class_),		\
	}

// A convenience macro for accessing a field of a structure.
#define FIELD(object_, struct_, field_, type_)	\
	( *(type_ *) ( ((uint8_t *) object_) + OFFSET(struct_, field_) ) )

#endif
