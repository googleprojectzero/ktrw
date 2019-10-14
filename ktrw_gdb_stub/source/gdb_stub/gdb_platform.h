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

#ifndef GDB_PLATFORM__H_
#define GDB_PLATFORM__H_

#include <stdint.h>

// The maximum number of supported CPUs. The actual number of CPUs may be less than this.
#define CPU_COUNT	6

// The packed register definitions. This is the struct used to transfer registers between GDB and
// the stub.
struct __attribute__((packed)) gdb_registers {
	union {
		uint64_t x;
		uint32_t w;
	} x[31];
	uint64_t sp;
	uint64_t pc;
	uint32_t cpsr;
	union {
		uint64_t q[2];
		double d;
		float s;
	} v[32];
	uint32_t fpsr;
	uint32_t fpcr;
};

// A type for register IDs.
typedef uint16_t reg_id_t;

// An invalid register ID.
#define INVALID_REG_ID	((reg_id_t)(-1))

// Information describing a register to GDB.
struct gdb_register_info {
	const char *name;		// The register's name.
	const char *altname;		// An alternative name for the register.
	uint8_t generic;		// The GDB generic name of this register.
	uint8_t type;			// The GDB type of this register.
	uint8_t encoding;		// The GDB encoding of this register.
	uint8_t format;			// The GDB format of this register.
	uint8_t group;			// The GDB group of this register.
	uint8_t set;			// The register set to which this register belongs.
	uint16_t offset;		// The offset in the struct gdb_registers.
	uint16_t bitsize;		// The size of this register in bits.
	reg_id_t ehframe_reg;		// The exception handler frame register number.
	reg_id_t dwarf_reg;		// The DWARF register number.
	reg_id_t value_regs[4];		// A list of registers that contain this register.
	reg_id_t invalidate_regs[4];	// A list of registers to invalidate if this one is set.
};

// The list of gdb_register_info structs.
extern const struct gdb_register_info gdb_register_info[];
extern const unsigned gdb_register_count;

// Lookup tables for the string values of the generic, type, encoding, format, and group fields.
extern const char *const gdb_register_generic_name[];
extern const char *const gdb_register_type_name[];
extern const char *const gdb_register_encoding_name[];
extern const char *const gdb_register_format_name[];
extern const char *const gdb_register_group_name[];

// Information describing a register set to GDB.
struct gdb_register_set_info {
	const char *description;
};

// The list of register sets.
extern const struct gdb_register_set_info gdb_register_set_info[];
extern const unsigned gdb_register_set_count;

#endif
