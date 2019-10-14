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

#ifndef PLATFORM_MATCH__H_
#define PLATFORM_MATCH__H_

#include <stdbool.h>
#include <stddef.h>

/*
 * platform_matches_device
 *
 * Description:
 * 	Check whether the current platform matches the specified device or range of devices.
 *
 * Match format:
 * 	The match string may either specify a single device glob or a range of device globs. For
 * 	example:
 *
 * 	"iPhone11,8"		Matches only iPhone11,8
 * 	"iPhone11,*"		Matches all iPhone11 devices, including e.g. iPhone11,4.
 * 	"iPhone*,*"		Matches all iPhone devices.
 * 	"iPhone11,4-iPhone11,8"	Matches all iPhone devices between 11,4 and 11,8, inclusive.
 * 	"iPhone10,*-11,*"	Matches all iPhone10 and iPhone11 devices.
 * 	"iPhon10,1|iPhone10,6"	Matches iPhone10,1 and iPhone10,6.
 * 	"*", NULL		Matches all devices.
 */
bool platform_matches_device(const char *device_range);

/*
 * platform_matches_build
 *
 * Description:
 * 	Check whether the current platform matches the specified build version or range of build
 * 	versions.
 *
 * Match format:
 * 	The match string may either specify a single build version or a range of build versions.
 * 	For example:
 *
 * 	"16C50"			Matches only build 16C50.
 * 	"16B92-16C50"		Matches all builds between 16B92 and 16C50, inclusive.
 *
 * 	As a special case, either build version may be replaced with "*" to indicate a lack of
 * 	lower or upper bound:
 *
 * 	"*-16B92"		Matches all builds up to and including 16B92.
 * 	"16C50-*"		Matches build 16C50 and later.
 * 	"*", NULL		Matches all build versions.
 */
bool platform_matches_build(const char *build_range);

/*
 * platform_matches
 *
 * Description:
 * 	A convenience function that combines platform_matches_device() and
 * 	platform_matches_build().
 */
bool platform_matches(const char *device_range, const char *build_range);

// A struct describing an initialization for a particular set of devices and builds.
struct platform_initialization {
	const char *devices;
	const char *builds;
	void (*init)(void);
};

/*
 * run_platform_initializations
 *
 * Description:
 * 	Run each of the platform initializations that match the current device and build.
 *
 * 	Returns the number of initializations that ran.
 */
size_t run_platform_initializations(struct platform_initialization *inits, size_t count);

#endif
