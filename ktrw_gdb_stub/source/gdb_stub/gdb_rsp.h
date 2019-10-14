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

#ifndef GDB_RSP__H_
#define GDB_RSP__H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// The maximum size of the data in a packet. This is calculated such that it is big enough to hold
// the "g" packet (788 bytes of register data hex-encoded to a 0x628 byte packet) but small enough
// that it is guaranteed that the RSP ACK and RSP-encoded packet will still fit within the
// 0x1000 byte USB transport buffer.
#define GDB_RSP_MAX_PACKET_SIZE		0x700

/*
 * gdb_rsp_send_packet
 *
 * Description:
 * 	Send a packet to GDB.
 */
void gdb_rsp_send_packet(const void *data, size_t size);

/*
 * gdb_rsp_send_notification
 *
 * Description:
 * 	Send a notification packet to GDB.
 */
void gdb_rsp_send_notification(const void *data, size_t size);

/*
 * gdb_rsp_receive_packet
 *
 * Description:
 * 	Receive a packet from GDB.
 */
bool gdb_rsp_receive_packet(void *data, size_t *size);

#endif
