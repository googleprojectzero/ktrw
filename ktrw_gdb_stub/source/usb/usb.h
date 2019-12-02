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

#ifndef USB__H_
#define USB__H_

#include <stddef.h>
#include <stdint.h>

// The amount of memory needed for the USB stack.
#define USB_STACK_MEMORY_SIZE	0x4000

/*
 * usb_init
 *
 * Description:
 * 	Initialize state for the USB stack. This does not interact with the USB hardware so it may
 * 	be called before preemption is disabled.
 *
 * 	dma should be a pointer to a page with a low physical address suitable for use by the USB
 * 	controller's DMA engine.
 *
 * 	memory should be a pointer to a page-aligned allocation of size USB_STACK_MEMORY_SIZE for
 * 	internal use by the USB stack.
 */
void usb_init(void *dma, void *memory);

/*
 * usb_start
 *
 * Description:
 * 	Start the USB stack for communication with the host.
 *
 * 	This should only be called once the system is stopped and with interrupts disabled.
 */
void usb_start(void);

/*
 * usb_process
 *
 * Description:
 * 	Perform a single round of USB processing. This should be called after usb_read() and
 * 	usb_write(), and at every USB interrupt. A simple implementation would be to call this
 * 	function on every iteration of the debugger main loop.
 */
void usb_process(void);

/*
 * usb_read
 *
 * Description:
 * 	Read data sent over USB.
 *
 * 	Up to 0x1000 bytes of data will be buffered.
 */
size_t usb_read(void *buffer, size_t size);

/*
 * usb_write
 *
 * Description:
 * 	Write data out over USB. No actual data is sent until a call to usb_write_commit().
 *
 * 	The maximum packet size is 0x1000. However, it is possible that less than 0x1000 bytes can
 * 	be written if the buffer is already partially full from the last write.
 */
size_t usb_write(const void *buffer, size_t size);

/*
 * usb_write_commit
 *
 * Description:
 * 	Send any data written via usb_write() over USB to the host.
 */
void usb_write_commit(void);

// ---- Transfer API ------------------------------------------------------------------------------

/*
 * usb_in_transfer
 *
 * Description:
 * 	Perform an IN transfer on the specified endpoint.
 *
 * 	The data buffer must remain alive until the completion callback is invoked.
 */
void usb_in_transfer(uint8_t ep_addr, const void *data, uint32_t size, void (*callback)(void));

/*
 * usb_out_transfer
 *
 * Description:
 * 	Perform an OUT transfer on the specified endpoint.
 */
void usb_out_transfer(uint8_t ep_addr, void *data, uint32_t size,
		void (*callback)(void *data, uint32_t size, uint32_t transferred));

/*
 * usb_out_transfer_dma
 *
 * Description:
 * 	Perform an OUT transfer on the specified endpoint, optimized for when the data buffer is
 * 	suitable for DMA.
 */
void usb_out_transfer_dma(uint8_t ep_addr, void *data, uint32_t dma, uint32_t size,
		void (*callback)(void *data, uint32_t size, uint32_t transferred));

#endif
