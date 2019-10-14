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

#include "gdb_rsp.h"

#include <stdarg.h>

#include "primitives.h"

#include "gdb_internal.h"
#include "gdb_stub.h"

// ---- GDB Remote Serial Protocol ----------------------------------------------------------------

// The GDB Remote Serial Protocol really works much better as a serial getchar/putchar API than as
// a "read and write data as available" API, but this file aims to shim between those two worlds.
//
// The debugger works in a RCV->SND, RCV->SND, loop: we do nothing until we receive data, then
// process it, then send the reply. Things get complicated when we start having to deal with ACKs,
// but we can simplify things by relying on the fact that there will only ever be one outstanding
// packet waiting to be ACK'd.
//
// We operate as follows:
//
//     1. We start in gdb_rsp_receive_packet(). When trying to receive a packet, we will append as
//        much as we can from usb_read() into the receive_buffer and then start processing from the
//        front.
//
//     2. If we have in-flight data, we discard everything until we get a '+' or '-'. If we get a
//        '-', that means our last sent data was NAK'd, so we need to send it again. We call
//        gdb_stub_serial_write() to retry sending the packet. We don't have any data to report, so
//        we return false from gdb_rsp_receive_packet().
//
//     3. If instead we got a '+', that means that the in-flight data was ACK'd, so we discard the
//        in-flight data from the send_buffer.
//
//        This means that for all steps after this point, there is no in-flight data in the
//        send_buffer.
//
//     4. If we find a packet in receive_buffer, we decode it into the caller's buffer. If we find
//        only a partial packet, we process and discard everything before the packet start and
//        return false. If we find a packet at the start of the buffer, the buffer is full, and
//        there's no packet end, then we were sent a too-large packet, so we send a NAK '-' and
//        return false.
//
//     5. If we did have a packet, we try to discard as many non-control characters from after the
//        end of the packet as we can. This means throwing away any characters before '^C' and '$'.
//        Any remaining data is moved to the start of the buffer.
//
//     6. At this point we have a full packet, so we write an ACK '+' directly to USB by calling
//        gdb_stub_serial_write().
//
//        (This isn't a great way of handling this, but neither is putting the ACK in the send
//        buffer, since we explicitly don't want to retransmit the '+' if GDB replies with '-' to
//        the next packet.)
//
//     7. We return from gdb_rsp_receive_packet(), and the GDB stub will process the decoded
//        packet. Eventually (maybe after a long time) it will generate a reply packet, which it
//        will give to us by calling gdb_rsp_send_packet().
//
//     8. In gdb_rsp_send_packet() we write the encoded packet to the send_buffer (we know there is
//        no in-flight data because of step 3), mark the data as in-flight, and call
//        gdb_stub_serial_write() to send it.
//
// This processing model breaks down in the face of notifications in non-stop mode. With
// notifications, we could for example receive a vCont packet, reply OK, and then before the OK has
// been ACK'd, a thread halts and we need to inform GDB, meaning we would have 2 "packets"
// outstanding. For now, we simply disable non-stop mode and notifications.


// The maximum size of a serialized packet. This must be strictly less than 0x1000.
#define GDB_RSP_MAX_SERIAL_PACKET_SIZE		(2 * GDB_RSP_MAX_PACKET_SIZE + 8)

static uint8_t send_buffer[GDB_RSP_MAX_SERIAL_PACKET_SIZE];
static size_t send_buffer_count;

static uint8_t receive_buffer[GDB_RSP_MAX_SERIAL_PACKET_SIZE];
static size_t receive_buffer_count;

#define BUG(_n)		(*(volatile uint64_t *)(_n) = _n)

void
gdb_rsp_send_packet(const void *data, size_t size) {
	if (send_buffer_count > 0) {
		BUG(0x7273702073206966);	// 'rsp s if'
	}
	const uint8_t *packet_data = data;
	size_t encoded_size = 0;
#define PUT_CHAR(_byte)						\
	do {							\
		if (encoded_size >= sizeof(send_buffer)) {	\
			goto send_buffer_full;			\
		}						\
		send_buffer[encoded_size] = _byte;		\
		encoded_size++;					\
	} while (0)
	PUT_CHAR('$');
	uint8_t checksum = 0;
	for (size_t i = 0; i < size; i++) {
		uint8_t byte = packet_data[i];
		if (byte == '$' || byte == '#' || byte == '*' || byte == '}') {
			checksum += '}';
			PUT_CHAR('}');
			byte ^= 0x20;
		}
		checksum += byte;
		PUT_CHAR(byte);
	}
	PUT_CHAR('#');
	PUT_CHAR(hex_char[(checksum >> 4) & 0xf]);
	PUT_CHAR(hex_char[checksum & 0xf]);
	send_buffer_count = encoded_size;
	gdb_stub_serial_write(send_buffer, send_buffer_count);
	return;
send_buffer_full:
	BUG(0x7273702073206f66);	// 'rsp s of'
}

void
gdb_rsp_send_notification(const void *data, size_t size) {
	BUG(0x727370206e6f7466);	// 'rsp notf'
}

bool
gdb_rsp_receive_packet(void *data, size_t *size) {
	// Receive as much data as we can into the receive buffer.
	size_t capacity = sizeof(receive_buffer) - receive_buffer_count;
	if (capacity == 0) {
		BUG(0x7273702072206f66);	// 'rsp r of'
	}
	size_t received = gdb_stub_serial_read(receive_buffer + receive_buffer_count, capacity);
	size_t now_filled_count = receive_buffer_count + received;
	uint8_t *packet_start = NULL;
	uint8_t *p = receive_buffer;
	uint8_t *end = p + now_filled_count;
	uint8_t ch;
	bool have_packet = false;
	uint8_t computed_checksum = 0;
	uint8_t sent_checksum = 0;
	bool escape = false;
	uint8_t *packet = data;
	size_t packet_size = 0;
#define GET_CHAR()	(*p++)
#define PEEK_CHAR()	(*p)
#define END_OF_DATA()	(p >= end)
	// If we have in-flight data in the send_buffer, discard everything until we get an ACK or
	// NAK.
	if (send_buffer_count > 0) {
		// Discard until we get to the end or hit a '+' or '-'.
		for (;;) {
			if (END_OF_DATA()) {
				goto finalize_memmove;
			}
			ch = GET_CHAR();
			// If we got a NAK, resend the send_buffer data.
			if (ch == '-') {
				gdb_stub_serial_write(send_buffer, send_buffer_count);
				goto finalize_memmove;
			}
			// If we got an ACK, mark the send_buffer as all sent.
			if (ch == '+') {
				send_buffer_count = 0;
				break;
			}
		}
	}
	// Discard any characters before the start of the packet.
	for (;;) {
		if (END_OF_DATA()) {
			goto finalize_memmove;
		}
		ch = GET_CHAR();
		if (ch == '$') {
			packet_start = p - 1;
			goto packet_start;
		}
		if (ch == '\x03') {
			packet_start = p - 1;
			goto interrupt;
		}
		// Discard all other characters.
	}
interrupt:
	// GDB sent an interrupt.
	packet[0] = ch;
	*size = 1;
	have_packet = true;
	goto discard_trailing_bytes;
packet_start:
	// We got the start character for a packet. Process as much data as we can in the packet.
	for (;;) {
		if (END_OF_DATA()) {
			goto finalize_partial_packet;
		}
		ch = GET_CHAR();
		if (ch == '#') {
			goto packet_end;
		}
		computed_checksum += ch;
		if (escape) {
			ch ^= 0x20;
			escape = false;
		} else if (ch == '}') {
			escape = true;
			continue;
		}
		if (packet_size >= GDB_RSP_MAX_PACKET_SIZE) {
			goto packet_too_large;
		}
		packet[packet_size] = ch;
		packet_size++;
	}
packet_end:
	// If we have a non-terminated escape, send a NAK.
	if (escape) {
		goto packet_invalid;
	}
	// We got the end character for a packet. Compute the packet checksum.
	for (unsigned i = 0; i < 2; i++) {
		if (END_OF_DATA()) {
			goto finalize_partial_packet;
		}
		ch = GET_CHAR();
		int d = hex_digit(ch);
		if (d == -1) {
			goto packet_invalid;
		}
		sent_checksum = (sent_checksum << 4) | d;
	}
	if (computed_checksum != sent_checksum) {
		goto packet_invalid;
	}
	// We have a valid packet, and we've copied it into the caller's buffer.
	have_packet = true;
	*size = packet_size;
	// Send an ACK.
	gdb_stub_serial_write("+", 1);
discard_trailing_bytes:
	// Now discard as many trailing bytes as we can.
	for (;;) {
		if (END_OF_DATA()) {
			break;
		}
		ch = PEEK_CHAR();
		if (ch == '$' || ch == '\x03' || ch == '+' || ch == '-') {
			break;
		}
		GET_CHAR();
	}
	goto finalize_memmove;
packet_invalid:
packet_too_large:
	// If the packet is invalid or too large, send a NAK.
	gdb_stub_serial_write("-", 1);
	goto discard_trailing_bytes;
finalize_partial_packet:
	if (packet_start == receive_buffer && now_filled_count == sizeof(receive_buffer)) {
	}
	p = packet_start;
finalize_memmove:
	receive_buffer_count = end - p;
	memmove(receive_buffer, p, receive_buffer_count);
	return have_packet;
}
