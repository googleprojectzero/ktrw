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

#ifndef IF_VALUE

/*
 * IF_VALUE(_x_)(_y_)(_z_)
 *
 * Description:
 * 	If _x_ is not empty, produces _y_, else produces _z_. Do not use or redefine macros
 * 	beginning with _IF_VALUE_.
 */

// _IF_VALUE__SECOND() returns the second argument.
#define _IF_VALUE__SECOND(_a, _b, ...)		_b
// _IF_VALUE__SECOND_2() does the same as _IF_VALUE__SECOND() after an additional round of
// parameter expansion.
#define _IF_VALUE__SECOND_2(_a, _b, ...)	_IF_VALUE__SECOND(_a, _b, __VA_ARGS__)
// _IF_VALUE__CHECK__IF_VALUE__IS_EMPTY() is used by _IF_VALUE__CHECK to test whether the argument
// is _IF_VALUE__IS_EMPTY and return _IF_VALUE__IS_EMPTY if so.
#define _IF_VALUE__CHECK__IF_VALUE__IS_EMPTY()	~, _IF_VALUE__IS_EMPTY
// _IF_VALUE__CHECK() produces _IF_VALUE__IS_EMPTY if _first is _IF_VALUE__IS_EMPTY and
// _IF_VALUE__NOT_EMPTY otherwise.
#define _IF_VALUE__CHECK(_first, ...)		_IF_VALUE__SECOND_2(_IF_VALUE__CHECK_ ## _first (), _IF_VALUE__NOT_EMPTY, ~)
// _IF_VALUE__CHECK_2() does the same as _IF_VALUE__CHECK() after an additional round of parameter
// expansion.
#define _IF_VALUE__CHECK_2(_first, ...)		_IF_VALUE__CHECK(_first, __VA_ARGS__)
// _IF_VALUE__IS_EMPTY takes 2 groups of parentheses and returns the unwrapped value of the first
// group.
#define _IF_VALUE__IS_EMPTY(...)		_IF_VALUE__IS_EMPTY_1
#define _IF_VALUE__IS_EMPTY_1(...)		__VA_ARGS__
// _IF_VALUE__NOT_EMPTY takes 2 groups of parentheses and returns the unwrapped value of the second
// group.
#define _IF_VALUE__NOT_EMPTY(...)		__VA_ARGS__ _IF_VALUE__NOT_EMPTY_1
#define _IF_VALUE__NOT_EMPTY_1(...)		/* nothing */
// IF_VALUE() produces _IF_VALUE__IS_EMPTY if _maybe_empty is empty and _IF_VALUE__NOT_EMPTY
// otherwise.
#define IF_VALUE(_maybe_empty)	_IF_VALUE__CHECK_2(_IF_VALUE__CHECK _maybe_empty (_IF_VALUE__IS_EMPTY, ~), ~)

#endif
