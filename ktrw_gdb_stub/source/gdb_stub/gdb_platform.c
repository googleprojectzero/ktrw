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

#include "gdb_platform.h"

#include <stddef.h>

// ---- Macros ------------------------------------------------------------------------------------

#include "if_value.h"

#define ARRAY_COUNT(a)	(sizeof(a) / sizeof(a[0]))

// ---- Generic registers -------------------------------------------------------------------------

enum {
	GENERIC_none,
	GENERIC_arg1,
	GENERIC_arg2,
	GENERIC_arg3,
	GENERIC_arg4,
	GENERIC_arg5,
	GENERIC_arg6,
	GENERIC_arg7,
	GENERIC_arg8,
	GENERIC_fp,
	GENERIC_ra,
	GENERIC_sp,
	GENERIC_pc,
};

#define GENERIC(_name)	[GENERIC_##_name] = #_name

const char *const gdb_register_generic_name[] = {
	GENERIC(arg1),
	GENERIC(arg2),
	GENERIC(arg3),
	GENERIC(arg4),
	GENERIC(arg5),
	GENERIC(arg6),
	GENERIC(arg7),
	GENERIC(arg8),
	GENERIC(fp),
	GENERIC(ra),
	GENERIC(sp),
	GENERIC(pc),
};

// ---- Register types ----------------------------------------------------------------------------

enum {
	TYPE_int,
	TYPE_float,
};

#define TYPE(_type)	[TYPE_##_type] = #_type

const char *const gdb_register_type_name[] = {
	TYPE(int),
	TYPE(float),
};

// ---- Register formats --------------------------------------------------------------------------

enum {
	FORMAT_hex,
	FORMAT_float,
	FORMAT_vector_uint8,
};

#define FORMAT(_format, _str)	[FORMAT_##_format] = #_str

const char *const gdb_register_format_name[] = {
	FORMAT(hex, hex),
	FORMAT(float, float),
	FORMAT(vector_uint8, vector-uint8),
};

// ---- Register encodings ------------------------------------------------------------------------

enum {
	ENCODING_uint,
	ENCODING_ieee754,
	ENCODING_vector,
};

#define ENCODING(_encoding)	[ENCODING_##_encoding] = #_encoding

const char *const gdb_register_encoding_name[] = {
	ENCODING(uint),
	ENCODING(ieee754),
	ENCODING(vector),
};

// ---- Register groups ---------------------------------------------------------------------------

enum {
	GROUP_general,
	GROUP_vector,
	GROUP_float,
};

#define GROUP(_group)	[GROUP_##_group] = #_group

const char *const gdb_register_group_name[] = {
	GROUP(general),
	GROUP(vector),
	GROUP(float),
};

// ---- Register sets -----------------------------------------------------------------------------

enum {
	SET_General,
	SET_Float,
};

#define SET(_set, _desc)	\
	[SET_##_set] = { \
		.description = _desc, \
	}

const struct gdb_register_set_info gdb_register_set_info[] = {
	SET(General, "General Purpose Registers"),
	SET(Float,   "Floating Point Registers"),
};

const unsigned gdb_register_set_count = ARRAY_COUNT(gdb_register_set_info);

// ---- Register definitions ----------------------------------------------------------------------

#define _MAKE_REG_LIST_1(_first, ...)	IF_VALUE(_first)( _first, __VA_ARGS__ )( __VA_ARGS__ )
#define MAKE_REG_LIST(...)		{ _MAKE_REG_LIST_1(__VA_ARGS__, INVALID_REG_ID) }

#define REG(_name, _field, _altname, _generic, _group, _type, _encoding, _format, _set, _dwarf, _ehframe, _value, _invalidate)	\
	[_name] = { \
		.name            = #_name, \
		.altname         = IF_VALUE(_altname)(#_altname)(NULL), \
		.generic         = IF_VALUE(_generic)(GENERIC_##_generic)(0), \
		.type            = IF_VALUE(_type)(TYPE_##_type)(0), \
		.encoding        = IF_VALUE(_encoding)(ENCODING_##_encoding)(0), \
		.format          = IF_VALUE(_format)(FORMAT_##_format)(0), \
		.group           = GROUP_##_group, \
		.set             = SET_##_set, \
		.offset          = offsetof(struct gdb_registers, _field), \
		.bitsize         = sizeof(((struct gdb_registers *)NULL)->_field) * 8, \
		.ehframe_reg     = IF_VALUE(_ehframe)(_ehframe)(INVALID_REG_ID), \
		.dwarf_reg       = IF_VALUE(_dwarf)(_dwarf)(INVALID_REG_ID), \
		.value_regs      = MAKE_REG_LIST _value, \
		.invalidate_regs = MAKE_REG_LIST _invalidate, \
	}

enum {
	x0,   x1,   x2,   x3,   x4,   x5,   x6,   x7,
	x8,   x9,   x10,  x11,  x12,  x13,  x14,  x15,
	x16,  x17,  x18,  x19,  x20,  x21,  x22,  x23,
	x24,  x25,  x26,  x27,  x28,  fp,   lr,   sp,
	pc,   cpsr,
	w0,   w1,   w2,   w3,   w4,   w5,   w6,   w7,
	w8,   w9,   w10,  w11,  w12,  w13,  w14,  w15,
	w16,  w17,  w18,  w19,  w20,  w21,  w22,  w23,
	w24,  w25,  w26,  w27,  w28,
	v0,   v1,   v2,   v3,   v4,   v5,   v6,   v7,
	v8,   v9,   v10,  v11,  v12,  v13,  v14,  v15,
	v16,  v17,  v18,  v19,  v20,  v21,  v22,  v23,
	v24,  v25,  v26,  v27,  v28,  v29,  v30,  v31,
	fpsr, fpcr,
	s0,   s1,   s2,   s3,   s4,   s5,   s6,   s7,
	s8,   s9,   s10,  s11,  s12,  s13,  s14,  s15,
	s16,  s17,  s18,  s19,  s20,  s21,  s22,  s23,
	s24,  s25,  s26,  s27,  s28,  s29,  s30,  s31,
	d0,   d1,   d2,   d3,   d4,   d5,   d6,   d7,
	d8,   d9,   d10,  d11,  d12,  d13,  d14,  d15,
	d16,  d17,  d18,  d19,  d20,  d21,  d22,  d23,
	d24,  d25,  d26,  d27,  d28,  d29,  d30,  d31,
};

// These register definitions are constructed to match the target.xml generated by lldb's
// debugserver.
const struct gdb_register_info gdb_register_info[] = {
	/*  name  field    alt  generic group    type   encoding format        grp_id dwarf eh  value  invalidate */
	REG(x0,   x[0].x,  arg1,  arg1, general, ,      ,        ,             General, 0,  0,  (),    ( x0, w0)),
	REG(x1,   x[1].x,  arg2,  arg2, general, ,      ,        ,             General, 1,  1,  (),    ( x1, w1)),
	REG(x2,   x[2].x,  arg3,  arg3, general, ,      ,        ,             General, 2,  2,  (),    ( x2, w2)),
	REG(x3,   x[3].x,  arg4,  arg4, general, ,      ,        ,             General, 3,  3,  (),    ( x3, w3)),
	REG(x4,   x[4].x,  arg5,  arg5, general, ,      ,        ,             General, 4,  4,  (),    ( x4, w4)),
	REG(x5,   x[5].x,  arg6,  arg6, general, ,      ,        ,             General, 5,  5,  (),    ( x5, w5)),
	REG(x6,   x[6].x,  arg7,  arg7, general, ,      ,        ,             General, 6,  6,  (),    ( x6, w6)),
	REG(x7,   x[7].x,  arg8,  arg8, general, ,      ,        ,             General, 7,  7,  (),    ( x7, w7)),
	REG(x8,   x[8].x,  ,      ,     general, ,      ,        ,             General, 8,  8,  (),    ( x8, w8)),
	REG(x9,   x[9].x,  ,      ,     general, ,      ,        ,             General, 9,  9,  (),    ( x9, w9)),
	REG(x10,  x[10].x, ,      ,     general, ,      ,        ,             General, 10, 10, (),    (x10,w10)),
	REG(x11,  x[11].x, ,      ,     general, ,      ,        ,             General, 11, 11, (),    (x11,w11)),
	REG(x12,  x[12].x, ,      ,     general, ,      ,        ,             General, 12, 12, (),    (x12,w12)),
	REG(x13,  x[13].x, ,      ,     general, ,      ,        ,             General, 13, 13, (),    (x13,w13)),
	REG(x14,  x[14].x, ,      ,     general, ,      ,        ,             General, 14, 14, (),    (x14,w14)),
	REG(x15,  x[15].x, ,      ,     general, ,      ,        ,             General, 15, 15, (),    (x15,w15)),
	REG(x16,  x[16].x, ,      ,     general, ,      ,        ,             General, 16, 16, (),    (x16,w16)),
	REG(x17,  x[17].x, ,      ,     general, ,      ,        ,             General, 17, 17, (),    (x17,w17)),
	REG(x18,  x[18].x, ,      ,     general, ,      ,        ,             General, 18, 18, (),    (x18,w18)),
	REG(x19,  x[19].x, ,      ,     general, ,      ,        ,             General, 19, 19, (),    (x19,w19)),
	REG(x20,  x[20].x, ,      ,     general, ,      ,        ,             General, 20, 20, (),    (x20,w20)),
	REG(x21,  x[21].x, ,      ,     general, ,      ,        ,             General, 21, 21, (),    (x21,w21)),
	REG(x22,  x[22].x, ,      ,     general, ,      ,        ,             General, 22, 22, (),    (x22,w22)),
	REG(x23,  x[23].x, ,      ,     general, ,      ,        ,             General, 23, 23, (),    (x23,w23)),
	REG(x24,  x[24].x, ,      ,     general, ,      ,        ,             General, 24, 24, (),    (x24,w24)),
	REG(x25,  x[25].x, ,      ,     general, ,      ,        ,             General, 25, 25, (),    (x25,w25)),
	REG(x26,  x[26].x, ,      ,     general, ,      ,        ,             General, 26, 26, (),    (x26,w26)),
	REG(x27,  x[27].x, ,      ,     general, ,      ,        ,             General, 27, 27, (),    (x27,w27)),
	REG(x28,  x[28].x, ,      ,     general, ,      ,        ,             General, 28, 28, (),    (x28,w28)),
	REG(fp,   x[29].x, x29,   fp,   general, ,      ,        ,             General, 29, 29, (),    ()),
	REG(lr,   x[30].x, x30,   ra,   general, ,      ,        ,             General, 30, 30, (),    ()),
	REG(sp,   sp,      xsp,   sp,   general, ,      ,        ,             General, 31, 31, (),    ()),
	REG(pc,   pc,      ,      pc,   general, ,      ,        ,             General, 32, 32, (),    ()),
	REG(cpsr, cpsr,    flags, ,     general, ,      ,        ,             General, 33, 33, (),    ()),
	/*  name  field    alt  generic group    type   encoding format        grp_id dwarf eh  value  invalidate */
	REG(w0,   x[0].w,  ,      ,     general, ,      ,        ,             General, ,   ,   (x0),  ( x0, w0)),
	REG(w1,   x[1].w,  ,      ,     general, ,      ,        ,             General, ,   ,   (x1),  ( x1, w1)),
	REG(w2,   x[2].w,  ,      ,     general, ,      ,        ,             General, ,   ,   (x2),  ( x2, w2)),
	REG(w3,   x[3].w,  ,      ,     general, ,      ,        ,             General, ,   ,   (x3),  ( x3, w3)),
	REG(w4,   x[4].w,  ,      ,     general, ,      ,        ,             General, ,   ,   (x4),  ( x4, w4)),
	REG(w5,   x[5].w,  ,      ,     general, ,      ,        ,             General, ,   ,   (x5),  ( x5, w5)),
	REG(w6,   x[6].w,  ,      ,     general, ,      ,        ,             General, ,   ,   (x6),  ( x6, w6)),
	REG(w7,   x[7].w,  ,      ,     general, ,      ,        ,             General, ,   ,   (x7),  ( x7, w7)),
	REG(w8,   x[8].w,  ,      ,     general, ,      ,        ,             General, ,   ,   (x8),  ( x8, w8)),
	REG(w9,   x[9].w,  ,      ,     general, ,      ,        ,             General, ,   ,   (x9),  ( x9, w9)),
	REG(w10,  x[10].w, ,      ,     general, ,      ,        ,             General, ,   ,   (x10), (x10,w10)),
	REG(w11,  x[11].w, ,      ,     general, ,      ,        ,             General, ,   ,   (x11), (x11,w11)),
	REG(w12,  x[12].w, ,      ,     general, ,      ,        ,             General, ,   ,   (x12), (x12,w12)),
	REG(w13,  x[13].w, ,      ,     general, ,      ,        ,             General, ,   ,   (x13), (x13,w13)),
	REG(w14,  x[14].w, ,      ,     general, ,      ,        ,             General, ,   ,   (x14), (x14,w14)),
	REG(w15,  x[15].w, ,      ,     general, ,      ,        ,             General, ,   ,   (x15), (x15,w15)),
	REG(w16,  x[16].w, ,      ,     general, ,      ,        ,             General, ,   ,   (x16), (x16,w16)),
	REG(w17,  x[17].w, ,      ,     general, ,      ,        ,             General, ,   ,   (x17), (x17,w17)),
	REG(w18,  x[18].w, ,      ,     general, ,      ,        ,             General, ,   ,   (x18), (x18,w18)),
	REG(w19,  x[19].w, ,      ,     general, ,      ,        ,             General, ,   ,   (x19), (x19,w19)),
	REG(w20,  x[20].w, ,      ,     general, ,      ,        ,             General, ,   ,   (x20), (x20,w20)),
	REG(w21,  x[21].w, ,      ,     general, ,      ,        ,             General, ,   ,   (x21), (x21,w21)),
	REG(w22,  x[22].w, ,      ,     general, ,      ,        ,             General, ,   ,   (x22), (x22,w22)),
	REG(w23,  x[23].w, ,      ,     general, ,      ,        ,             General, ,   ,   (x23), (x23,w23)),
	REG(w24,  x[24].w, ,      ,     general, ,      ,        ,             General, ,   ,   (x24), (x24,w24)),
	REG(w25,  x[25].w, ,      ,     general, ,      ,        ,             General, ,   ,   (x25), (x25,w25)),
	REG(w26,  x[26].w, ,      ,     general, ,      ,        ,             General, ,   ,   (x26), (x26,w26)),
	REG(w27,  x[27].w, ,      ,     general, ,      ,        ,             General, ,   ,   (x27), (x27,w27)),
	REG(w28,  x[28].w, ,      ,     general, ,      ,        ,             General, ,   ,   (x28), (x28,w28)),
	/*  name  field    alt  generic group    type   encoding format        grp_id dwarf eh  value  invalidate */
	REG(v0,   v[0].q,  q0,    ,     vector,  float, vector,  vector_uint8, Float,   64, ,   (),    (v0, d0, s0 )),
	REG(v1,   v[1].q,  q1,    ,     vector,  float, vector,  vector_uint8, Float,   65, ,   (),    (v1, d1, s1 )),
	REG(v2,   v[2].q,  q2,    ,     vector,  float, vector,  vector_uint8, Float,   66, ,   (),    (v2, d2, s2 )),
	REG(v3,   v[3].q,  q3,    ,     vector,  float, vector,  vector_uint8, Float,   67, ,   (),    (v3, d3, s3 )),
	REG(v4,   v[4].q,  q4,    ,     vector,  float, vector,  vector_uint8, Float,   68, ,   (),    (v4, d4, s4 )),
	REG(v5,   v[5].q,  q5,    ,     vector,  float, vector,  vector_uint8, Float,   69, ,   (),    (v5, d5, s5 )),
	REG(v6,   v[6].q,  q6,    ,     vector,  float, vector,  vector_uint8, Float,   70, ,   (),    (v6, d6, s6 )),
	REG(v7,   v[7].q,  q7,    ,     vector,  float, vector,  vector_uint8, Float,   71, ,   (),    (v7, d7, s7 )),
	REG(v8,   v[8].q,  q8,    ,     vector,  float, vector,  vector_uint8, Float,   72, ,   (),    (v8, d8, s8 )),
	REG(v9,   v[9].q,  q9,    ,     vector,  float, vector,  vector_uint8, Float,   73, ,   (),    (v9, d9, s9 )),
	REG(v10,  v[10].q, q10,   ,     vector,  float, vector,  vector_uint8, Float,   74, ,   (),    (v10,d10,s10)),
	REG(v11,  v[11].q, q11,   ,     vector,  float, vector,  vector_uint8, Float,   75, ,   (),    (v11,d11,s11)),
	REG(v12,  v[12].q, q12,   ,     vector,  float, vector,  vector_uint8, Float,   76, ,   (),    (v12,d12,s12)),
	REG(v13,  v[13].q, q13,   ,     vector,  float, vector,  vector_uint8, Float,   77, ,   (),    (v13,d13,s13)),
	REG(v14,  v[14].q, q14,   ,     vector,  float, vector,  vector_uint8, Float,   78, ,   (),    (v14,d14,s14)),
	REG(v15,  v[15].q, q15,   ,     vector,  float, vector,  vector_uint8, Float,   79, ,   (),    (v15,d15,s15)),
	REG(v16,  v[16].q, q16,   ,     vector,  float, vector,  vector_uint8, Float,   80, ,   (),    (v16,d16,s16)),
	REG(v17,  v[17].q, q17,   ,     vector,  float, vector,  vector_uint8, Float,   81, ,   (),    (v17,d17,s17)),
	REG(v18,  v[18].q, q18,   ,     vector,  float, vector,  vector_uint8, Float,   82, ,   (),    (v18,d18,s18)),
	REG(v19,  v[19].q, q19,   ,     vector,  float, vector,  vector_uint8, Float,   83, ,   (),    (v19,d19,s19)),
	REG(v20,  v[20].q, q20,   ,     vector,  float, vector,  vector_uint8, Float,   84, ,   (),    (v20,d20,s20)),
	REG(v21,  v[21].q, q21,   ,     vector,  float, vector,  vector_uint8, Float,   85, ,   (),    (v21,d21,s21)),
	REG(v22,  v[22].q, q22,   ,     vector,  float, vector,  vector_uint8, Float,   86, ,   (),    (v22,d22,s22)),
	REG(v23,  v[23].q, q23,   ,     vector,  float, vector,  vector_uint8, Float,   87, ,   (),    (v23,d23,s23)),
	REG(v24,  v[24].q, q24,   ,     vector,  float, vector,  vector_uint8, Float,   88, ,   (),    (v24,d24,s24)),
	REG(v25,  v[25].q, q25,   ,     vector,  float, vector,  vector_uint8, Float,   89, ,   (),    (v25,d25,s25)),
	REG(v26,  v[26].q, q26,   ,     vector,  float, vector,  vector_uint8, Float,   90, ,   (),    (v26,d26,s26)),
	REG(v27,  v[27].q, q27,   ,     vector,  float, vector,  vector_uint8, Float,   91, ,   (),    (v27,d27,s27)),
	REG(v28,  v[28].q, q28,   ,     vector,  float, vector,  vector_uint8, Float,   92, ,   (),    (v28,d28,s28)),
	REG(v29,  v[29].q, q29,   ,     vector,  float, vector,  vector_uint8, Float,   93, ,   (),    (v29,d29,s29)),
	REG(v30,  v[30].q, q30,   ,     vector,  float, vector,  vector_uint8, Float,   94, ,   (),    (v30,d30,s30)),
	REG(v31,  v[31].q, q31,   ,     vector,  float, vector,  vector_uint8, Float,   95, ,   (),    (v31,d31,s31)),
	/*  name  field    alt  generic group    type   encoding format        grp_id dwarf eh  value  invalidate */
	REG(fpsr, fpsr,    ,      ,     general, ,      ,        ,             Float,   ,   ,   (),    ()),
	REG(fpcr, fpcr,    ,      ,     general, ,      ,        ,             Float,   ,   ,   (),    ()),
	/*  name  field    alt  generic group    type   encoding format        grp_id dwarf eh  value  invalidate */
	REG(s0,   v[0].s,  ,      ,     float,   float, ieee754, float,        Float,   ,   ,   (v0),  (v0, d0, s0 )),
	REG(s1,   v[1].s,  ,      ,     float,   float, ieee754, float,        Float,   ,   ,   (v1),  (v1, d1, s1 )),
	REG(s2,   v[2].s,  ,      ,     float,   float, ieee754, float,        Float,   ,   ,   (v2),  (v2, d2, s2 )),
	REG(s3,   v[3].s,  ,      ,     float,   float, ieee754, float,        Float,   ,   ,   (v3),  (v3, d3, s3 )),
	REG(s4,   v[4].s,  ,      ,     float,   float, ieee754, float,        Float,   ,   ,   (v4),  (v4, d4, s4 )),
	REG(s5,   v[5].s,  ,      ,     float,   float, ieee754, float,        Float,   ,   ,   (v5),  (v5, d5, s5 )),
	REG(s6,   v[6].s,  ,      ,     float,   float, ieee754, float,        Float,   ,   ,   (v6),  (v6, d6, s6 )),
	REG(s7,   v[7].s,  ,      ,     float,   float, ieee754, float,        Float,   ,   ,   (v7),  (v7, d7, s7 )),
	REG(s8,   v[8].s,  ,      ,     float,   float, ieee754, float,        Float,   ,   ,   (v8),  (v8, d8, s8 )),
	REG(s9,   v[9].s,  ,      ,     float,   float, ieee754, float,        Float,   ,   ,   (v9),  (v9, d9, s9 )),
	REG(s10,  v[10].s, ,      ,     float,   float, ieee754, float,        Float,   ,   ,   (v10), (v10,d10,s10)),
	REG(s11,  v[11].s, ,      ,     float,   float, ieee754, float,        Float,   ,   ,   (v11), (v11,d11,s11)),
	REG(s12,  v[12].s, ,      ,     float,   float, ieee754, float,        Float,   ,   ,   (v12), (v12,d12,s12)),
	REG(s13,  v[13].s, ,      ,     float,   float, ieee754, float,        Float,   ,   ,   (v13), (v13,d13,s13)),
	REG(s14,  v[14].s, ,      ,     float,   float, ieee754, float,        Float,   ,   ,   (v14), (v14,d14,s14)),
	REG(s15,  v[15].s, ,      ,     float,   float, ieee754, float,        Float,   ,   ,   (v15), (v15,d15,s15)),
	REG(s16,  v[16].s, ,      ,     float,   float, ieee754, float,        Float,   ,   ,   (v16), (v16,d16,s16)),
	REG(s17,  v[17].s, ,      ,     float,   float, ieee754, float,        Float,   ,   ,   (v17), (v17,d17,s17)),
	REG(s18,  v[18].s, ,      ,     float,   float, ieee754, float,        Float,   ,   ,   (v18), (v18,d18,s18)),
	REG(s19,  v[19].s, ,      ,     float,   float, ieee754, float,        Float,   ,   ,   (v19), (v19,d19,s19)),
	REG(s20,  v[20].s, ,      ,     float,   float, ieee754, float,        Float,   ,   ,   (v20), (v20,d20,s20)),
	REG(s21,  v[21].s, ,      ,     float,   float, ieee754, float,        Float,   ,   ,   (v21), (v21,d21,s21)),
	REG(s22,  v[22].s, ,      ,     float,   float, ieee754, float,        Float,   ,   ,   (v22), (v22,d22,s22)),
	REG(s23,  v[23].s, ,      ,     float,   float, ieee754, float,        Float,   ,   ,   (v23), (v23,d23,s23)),
	REG(s24,  v[24].s, ,      ,     float,   float, ieee754, float,        Float,   ,   ,   (v24), (v24,d24,s24)),
	REG(s25,  v[25].s, ,      ,     float,   float, ieee754, float,        Float,   ,   ,   (v25), (v25,d25,s25)),
	REG(s26,  v[26].s, ,      ,     float,   float, ieee754, float,        Float,   ,   ,   (v26), (v26,d26,s26)),
	REG(s27,  v[27].s, ,      ,     float,   float, ieee754, float,        Float,   ,   ,   (v27), (v27,d27,s27)),
	REG(s28,  v[28].s, ,      ,     float,   float, ieee754, float,        Float,   ,   ,   (v28), (v28,d28,s28)),
	REG(s29,  v[29].s, ,      ,     float,   float, ieee754, float,        Float,   ,   ,   (v29), (v29,d29,s29)),
	REG(s30,  v[30].s, ,      ,     float,   float, ieee754, float,        Float,   ,   ,   (v30), (v30,d30,s30)),
	REG(s31,  v[31].s, ,      ,     float,   float, ieee754, float,        Float,   ,   ,   (v31), (v31,d31,s31)),
	/*  name  field    alt  generic group    type   encoding format        grp_id dwarf eh  value  invalidate */
	REG(d0,   v[0].d,  ,      ,     float,   float, ieee754, float,        Float,   ,   ,   (v0),  (v0, d0, s0 )),
	REG(d1,   v[1].d,  ,      ,     float,   float, ieee754, float,        Float,   ,   ,   (v1),  (v1, d1, s1 )),
	REG(d2,   v[2].d,  ,      ,     float,   float, ieee754, float,        Float,   ,   ,   (v2),  (v2, d2, s2 )),
	REG(d3,   v[3].d,  ,      ,     float,   float, ieee754, float,        Float,   ,   ,   (v3),  (v3, d3, s3 )),
	REG(d4,   v[4].d,  ,      ,     float,   float, ieee754, float,        Float,   ,   ,   (v4),  (v4, d4, s4 )),
	REG(d5,   v[5].d,  ,      ,     float,   float, ieee754, float,        Float,   ,   ,   (v5),  (v5, d5, s5 )),
	REG(d6,   v[6].d,  ,      ,     float,   float, ieee754, float,        Float,   ,   ,   (v6),  (v6, d6, s6 )),
	REG(d7,   v[7].d,  ,      ,     float,   float, ieee754, float,        Float,   ,   ,   (v7),  (v7, d7, s7 )),
	REG(d8,   v[8].d,  ,      ,     float,   float, ieee754, float,        Float,   ,   ,   (v8),  (v8, d8, s8 )),
	REG(d9,   v[9].d,  ,      ,     float,   float, ieee754, float,        Float,   ,   ,   (v9),  (v9, d9, s9 )),
	REG(d10,  v[10].d, ,      ,     float,   float, ieee754, float,        Float,   ,   ,   (v10), (v10,d10,s10)),
	REG(d11,  v[11].d, ,      ,     float,   float, ieee754, float,        Float,   ,   ,   (v11), (v11,d11,s11)),
	REG(d12,  v[12].d, ,      ,     float,   float, ieee754, float,        Float,   ,   ,   (v12), (v12,d12,s12)),
	REG(d13,  v[13].d, ,      ,     float,   float, ieee754, float,        Float,   ,   ,   (v13), (v13,d13,s13)),
	REG(d14,  v[14].d, ,      ,     float,   float, ieee754, float,        Float,   ,   ,   (v14), (v14,d14,s14)),
	REG(d15,  v[15].d, ,      ,     float,   float, ieee754, float,        Float,   ,   ,   (v15), (v15,d15,s15)),
	REG(d16,  v[16].d, ,      ,     float,   float, ieee754, float,        Float,   ,   ,   (v16), (v16,d16,s16)),
	REG(d17,  v[17].d, ,      ,     float,   float, ieee754, float,        Float,   ,   ,   (v17), (v17,d17,s17)),
	REG(d18,  v[18].d, ,      ,     float,   float, ieee754, float,        Float,   ,   ,   (v18), (v18,d18,s18)),
	REG(d19,  v[19].d, ,      ,     float,   float, ieee754, float,        Float,   ,   ,   (v19), (v19,d19,s19)),
	REG(d20,  v[20].d, ,      ,     float,   float, ieee754, float,        Float,   ,   ,   (v20), (v20,d20,s20)),
	REG(d21,  v[21].d, ,      ,     float,   float, ieee754, float,        Float,   ,   ,   (v21), (v21,d21,s21)),
	REG(d22,  v[22].d, ,      ,     float,   float, ieee754, float,        Float,   ,   ,   (v22), (v22,d22,s22)),
	REG(d23,  v[23].d, ,      ,     float,   float, ieee754, float,        Float,   ,   ,   (v23), (v23,d23,s23)),
	REG(d24,  v[24].d, ,      ,     float,   float, ieee754, float,        Float,   ,   ,   (v24), (v24,d24,s24)),
	REG(d25,  v[25].d, ,      ,     float,   float, ieee754, float,        Float,   ,   ,   (v25), (v25,d25,s25)),
	REG(d26,  v[26].d, ,      ,     float,   float, ieee754, float,        Float,   ,   ,   (v26), (v26,d26,s26)),
	REG(d27,  v[27].d, ,      ,     float,   float, ieee754, float,        Float,   ,   ,   (v27), (v27,d27,s27)),
	REG(d28,  v[28].d, ,      ,     float,   float, ieee754, float,        Float,   ,   ,   (v28), (v28,d28,s28)),
	REG(d29,  v[29].d, ,      ,     float,   float, ieee754, float,        Float,   ,   ,   (v29), (v29,d29,s29)),
	REG(d30,  v[30].d, ,      ,     float,   float, ieee754, float,        Float,   ,   ,   (v30), (v30,d30,s30)),
	REG(d31,  v[31].d, ,      ,     float,   float, ieee754, float,        Float,   ,   ,   (v31), (v31,d31,s31)),
};

const unsigned gdb_register_count = ARRAY_COUNT(gdb_register_info);
