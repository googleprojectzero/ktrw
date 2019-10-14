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

#ifndef WATCHDOG__H_
#define WATCHDOG__H_

#include <stdint.h>

// The physical address of the WatchDog Timer registers. This should be initialized prior to
// calling disable_watchdog_timer().
extern uint64_t watchdog_timer_register_base;

/*
 * disable_watchdog_timer
 *
 * Description:
 * 	Disables the WatchDog Timer.
 */
void disable_watchdog_timer(void);

#endif
