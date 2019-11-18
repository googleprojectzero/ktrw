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

#include "usb/usb.h"

#include "page_table.h"

#include "primitives.h"

#include <stdint.h>

//
// The Synopsys DesignWare Hi-Speed USB 2.0 On-the-Go Controller USB stack
// ------------------------------------------------------------------------------------------------
//
// In order to communicate with KTRW running in the iOS kernel using a regular USB lightning cable,
// I had to implement a USB stack capable of operating the iPhone's Synopsys DesignWare Hi-Speed
// USB 2.0 On-the-Go Controller. This was a nontrivial task, made more complicated by the
// following:
//
//     1. The Synopsys USB OTG controller uses a proprietary controller interface, and I do not
//        have access to the the data sheet or programming manual.
//
//     2. I could not find an open-source driver implementation for operating the Synopsys OTG
//        controller in Device mode until after most of this work was complete.
//
//     3. As this code is running in the iPhone kernel but outside the purview of iOS itself, we do
//        not have access to luxuries like dynamic memory allocation.
//
// Because I didn't have a reference implementation or data sheet, the best way I could think of to
// create a functional USB stack for this hardware was to reverse engineer Apple's SecureROM and
// reimplement its USB stack in C. This means that I have inferred how to operate the Synopsys OTG
// controller almost exclusively using static analysis and panic-printf debugging.
//
// The following USB stack implementation is based on my reversing of Apple's SecureROM for the
// iPhone 8. It seems to operate well enough in practice for my very specific use case. However,
// because I did not have a datasheet while writing this code, it probably contains many bugs due
// to misusing the USB controller interface. It also emphasizes clean design over USB performance,
// so it may be slower than other implementations.
//
// That being said, I was able to improve on a few aspects of the USB stack's design in the process
// of reversing and reimplementing it from the SecureROM. If anyone at Apple wants to borrow this
// code, please feel free. :)
//

// ---- Debugging ---------------------------------------------------------------------------------

// Enable or disable USB stack debugging.
#define DEBUG_USB 0

#if DEBUG_USB

#define USB_DEBUG_FATAL		0x01		// Always logged
#define USB_DEBUG_APP		0x02		// Application-level behavior
#define USB_DEBUG_STANDARD	0x04		// Standard requests
#define USB_DEBUG_STAGE		0x04		// USB control transfer stages
#define USB_DEBUG_FUNC		0x08		// USB functions
#define USB_DEBUG_XFER		0x10		// USB transfers
#define USB_DEBUG_INTR		0x20		// USB interrupts
#define USB_DEBUG_REG		0x40		// USB register writes
#define USB_DEBUG_INIT		0x80		// USB initialization

// Which debugging types we are logging.
static uint32_t USB_DEBUG_ENABLED = 0;

// The current iteration of the USB stack.
static uint64_t USB_DEBUG_ITERATION = 0;

#define USB_DEBUG_INCREMENT_ITERATION()		(USB_DEBUG_ITERATION++)
static void USB_DEBUG(uint32_t type, const char *format, ...);
static void USB_DEBUG_PRINT_REGISTERS(void);
#define USB_DEBUG_ABORT()	USB_DEBUG_ABORT_INTERNAL(__func__)
static void USB_DEBUG_ABORT_INTERNAL(const char *function);
#define USB_DEBUG_ABORT_ON_ITERATION(_iteration)		\
	do {							\
		if (USB_DEBUG_ITERATION >= _iteration) {	\
			USB_DEBUG_PRINT_REGISTERS();		\
			USB_DEBUG_ABORT();			\
		}						\
	} while (0)

#else	// !DEBUG_USB

#define USB_DEBUG_INCREMENT_ITERATION()			do { } while (0)
#define USB_DEBUG(_type, _format, ...)			do { } while (0)
#define USB_DEBUG_PRINT_REGISTERS()			do { } while (0)
#define USB_DEBUG_ABORT()				do { } while (0)
#define USB_DEBUG_ABORT_ON_ITERATION(_iteration)	do { } while (0)

#endif	// DEBUG_USB

// Declare a bug. This is used for severe issues, where the best option is aborting.
#define BUG(n)	_BUG(n)

static inline _Noreturn void
_BUG(uint64_t n) {
	*(volatile uint64_t *)(n) = n;
	for (;;);
}

// ---- USB types ---------------------------------------------------------------------------------

struct setup_packet {
	uint8_t  bmRequestType;
	uint8_t  bRequest;
	uint16_t wValue;
	uint16_t wIndex;
	uint16_t wLength;
} __attribute__((packed));

struct device_descriptor {
	uint8_t  bLength;
	uint8_t  bDescriptorType;
	uint16_t bcdUSB;
	uint8_t  bDeviceClass;
	uint8_t  bDeviceSubClass;
	uint8_t  bDeviceProtocol;
	uint8_t  bMaxPacketSize0;
	uint16_t idVendor;
	uint16_t idProduct;
	uint16_t bcdDevice;
	uint8_t  iManufacturer;
	uint8_t  iProduct;
	uint8_t  iSerialNumber;
	uint8_t  bNumConfigurations;
} __attribute__((packed));

struct configuration_descriptor {
	uint8_t  bLength;
	uint8_t  bDescriptorType;
	uint16_t wTotalLength;
	uint8_t  bNumInterfaces;
	uint8_t  bConfigurationValue;
	uint8_t  iConfiguration;
	uint8_t  bmAttributes;
	uint8_t  bMaxPower;
} __attribute__((packed));

struct interface_descriptor {
	uint8_t bLength;
	uint8_t bDescriptorType;
	uint8_t bInterfaceNumber;
	uint8_t bAlternateSetting;
	uint8_t bNumEndpoints;
	uint8_t bInterfaceClass;
	uint8_t bInterfaceSubClass;
	uint8_t bInterfaceProtocol;
	uint8_t iInterface;
} __attribute__((packed));

struct endpoint_descriptor {
	uint8_t  bLength;
	uint8_t  bDescriptorType;
	uint8_t  bEndpointAddress;
	uint8_t  bmAttributes;
	uint16_t wMaxPacketSize;
	uint8_t  bInterval;
} __attribute__((packed));

struct string_descriptor {
	uint8_t bLength;
	uint8_t bDescriptorType;
	uint8_t bString[0];
} __attribute__((packed));

// ---- USB configuration -------------------------------------------------------------------------

// The maximum packet size for EP 0 is 64 bytes.
#define EP0_MAX_PACKET_SIZE	64

// The maximum packet size for EP 1 IN depends on the endpoint type. For Bulk endpoints, the
// maximum packet size is 512 bytes. For Interrupt endpoints, the maximum packet size is 1024
// bytes.
#define EP1_MAX_PACKET_SIZE	1024

enum {
	/* 0 is reserved */
	iManufacturer = 1,
	iProduct      = 2,
	iSerialNumber = 3,
};

static const char *string_descriptors[] = {
	[iManufacturer] = "Brandon Azad",
	[iProduct]      = "KTRW",
	[iSerialNumber] = "Google Project Zero",
};

static const uint32_t string_descriptor_count = sizeof(string_descriptors) / sizeof(string_descriptors[0]);

struct device_descriptor device_descriptor = {
	.bLength            = sizeof(struct device_descriptor),
	.bDescriptorType    = 1,
	.bcdUSB             = 0x200,
	.bDeviceClass       = 0,
	.bDeviceSubClass    = 0,
	.bDeviceProtocol    = 0,
	.bMaxPacketSize0    = EP0_MAX_PACKET_SIZE,
	.idVendor           = 0x5ac,
	.idProduct          = 0x1337,
	.bcdDevice          = 0,
	.iManufacturer      = iManufacturer,
	.iProduct           = iProduct,
	.iSerialNumber      = iSerialNumber,
	.bNumConfigurations = 1,
};

struct full_configuration_descriptor {
	struct configuration_descriptor configuration;
	struct interface_descriptor     interface;
	struct endpoint_descriptor      endpoint_0;
	struct endpoint_descriptor      endpoint_1;
} __attribute__((packed));

struct full_configuration_descriptor configuration_descriptor = {
	.configuration = {
		.bLength             = sizeof(configuration_descriptor.configuration),
		.bDescriptorType     = 2,
		.wTotalLength        = sizeof(configuration_descriptor),
		.bNumInterfaces      = 1,
		.bConfigurationValue = 1,
		.iConfiguration      = iProduct,
		.bmAttributes        = 0x80,
		.bMaxPower           = 250,
	},
	.interface = {
		.bLength            = sizeof(configuration_descriptor.interface),
		.bDescriptorType    = 4,
		.bInterfaceNumber   = 0,
		.bAlternateSetting  = 0,
		.bNumEndpoints      = 1,
		.bInterfaceClass    = 0xfe,
		.bInterfaceSubClass = 0x13,
		.bInterfaceProtocol = 0x37,
		.iInterface         = 0,
	},
	.endpoint_0 = {
		.bLength          = sizeof(configuration_descriptor.endpoint_0),
		.bDescriptorType  = 5,
		.bEndpointAddress = 0x00,
		.bmAttributes     = 0,		// Control
		.wMaxPacketSize   = EP0_MAX_PACKET_SIZE,
		.bInterval        = 0,
	},
	.endpoint_1 = {
		.bLength          = sizeof(configuration_descriptor.endpoint_1),
		.bDescriptorType  = 5,
		.bEndpointAddress = 0x81,	// IN
		.bmAttributes     = 3,		// Interrupt
		.wMaxPacketSize   = EP1_MAX_PACKET_SIZE,
		.bInterval        = 1,		// Poll every 125us
	},
};

// ---- The KTRW USB API --------------------------------------------------------------------------

// These functions are provided by the layer below us.
static void ep0_begin_data_in_stage(const void *data, uint16_t size, void (*callback)(void));
static void ep0_begin_data_out_stage(bool (*callback)(const void *data, uint16_t size));
static void usb_in_transfer(uint8_t ep_addr, const void *data, uint16_t size,
		void (*callback)(void));

// The KTRW USB protocol supports 2 control transfer types:
//
//     - IN 0x41: Send data from KTRW to GDB.
//
//       wValue starts at 0 and is incremented each time the data is received successfully. That
//       way, if another request comes in for the same wValue index, we can detect that the
//       previous data was not received and resend it. (This feature isn't currently used.)
//
//       wIndex is 0x1337.
//
//     - OUT 0x41: Receive data from GDB to KTRW.
//
//       wValue starts at 0 and is incremented each time new data is sent. (This feature isn't
//       currently used.)
//
//       wIndex is 0x1337.
//

static uint8_t ktrw_send_data[0x1000];
static uint16_t ktrw_send_count;
static uint16_t ktrw_send_in_flight;

static uint8_t ktrw_recv_data[0x1000];
static uint16_t ktrw_recv_count;

static void
ktrw_send_done() {
	USB_DEBUG(USB_DEBUG_APP, "ktrw_send done");
	if (ktrw_send_in_flight > ktrw_send_count) {
		USB_DEBUG(USB_DEBUG_FATAL, "in_flight %u > %u send_count",
				ktrw_send_in_flight, ktrw_send_count);
		BUG(0x6966203e207363);	// 'if > sc'
	}
	uint16_t send_left = ktrw_send_count - ktrw_send_in_flight;
	memmove(ktrw_send_data, ktrw_send_data + ktrw_send_in_flight, send_left);
	ktrw_send_count = send_left;
	ktrw_send_in_flight = send_left;
	if (send_left > 0) {
		USB_DEBUG(USB_DEBUG_APP, "ktrw_send'(%.*s)", (int) ktrw_send_in_flight,
				(char *) ktrw_send_data);
		usb_in_transfer(0x81, ktrw_send_data, send_left, ktrw_send_done);
	}
}

static bool
ktrw_recv_done(const void *data, uint16_t size) {
	uint16_t copy_size = sizeof(ktrw_recv_data) - ktrw_recv_count;
	if (copy_size < size) {
		return false;
	}
	if (copy_size > size) {
		copy_size = size;
	}
	USB_DEBUG(USB_DEBUG_APP, "ktrw_recv(%.*s)", (int) size, (char *) data);
	memcpy(ktrw_recv_data + ktrw_recv_count, data, copy_size);
	ktrw_recv_count += copy_size;
	return true;
}

static bool
ktrw_recv(uint16_t wLength) {
	uint16_t capacity = sizeof(ktrw_recv_data) - ktrw_recv_count;
	if (wLength > capacity) {
		return false;
	}
	ep0_begin_data_out_stage(ktrw_recv_done);
	return true;
}

static bool
ep0_vendor_request(struct setup_packet *setup) {
	if ((setup->bmRequestType & 0x80) == 0) {
		if (setup->bRequest == 0x41 && setup->wIndex == 0x1337) {
			return ktrw_recv(setup->wLength);
		}
	}
	return false;
}

size_t
usb_read(void *data, size_t size) {
	size_t read_size = ktrw_recv_count;
	if (read_size > size) {
		read_size = size;
	}
	memcpy(data, ktrw_recv_data, read_size);
	size_t recv_left = ktrw_recv_count - read_size;
	memmove(ktrw_recv_data, ktrw_recv_data + read_size, recv_left);
	ktrw_recv_count = recv_left;
	return read_size;
}

size_t
usb_write(const void *data, size_t size) {
	size_t write_size = sizeof(ktrw_send_data) - ktrw_send_count;
	if (write_size > size) {
		write_size = size;
	}
	memcpy(ktrw_send_data + ktrw_send_count, data, write_size);
	ktrw_send_count += write_size;
	return write_size;
}

void
usb_write_commit() {
	if (ktrw_send_count > 0 && ktrw_send_in_flight == 0) {
		ktrw_send_in_flight = ktrw_send_count;
		USB_DEBUG(USB_DEBUG_APP, "ktrw_send(%.*s)", (int) ktrw_send_in_flight,
				(char *) ktrw_send_data);
		usb_in_transfer(0x81, ktrw_send_data, ktrw_send_count, ktrw_send_done);
	}
}

// ---- The high-level USB API --------------------------------------------------------------------

// USB functions needed by this level.
static void usb_set_address(uint8_t address);

#define MAX_USB_DESCRIPTOR_LENGTH	63

static bool
get_string_descriptor(uint8_t index) {
	if (index >= string_descriptor_count) {
		return false;
	}
	struct {
		struct string_descriptor descriptor;		// 2 bytes
		uint16_t utf16[MAX_USB_DESCRIPTOR_LENGTH];	// 126 bytes
	} sd;
	uint16_t length;
	if (index == 0) {
		length = 1;
		sd.utf16[0] = 0x0409;
	} else {
		const char *string = string_descriptors[index];
		length = strlen(string);
		if (length > MAX_USB_DESCRIPTOR_LENGTH) {
			length = MAX_USB_DESCRIPTOR_LENGTH;
		}
		for (uint8_t i = 0; i < length; i++) {
			sd.utf16[i] = string[i];
		}
	}
	uint16_t size = sizeof(sd.descriptor) + length * sizeof(sd.utf16[0]);
	sd.descriptor.bLength = size;
	sd.descriptor.bDescriptorType = 3;	// String descriptor
	ep0_begin_data_in_stage(&sd, size, NULL);
	return true;
}

static bool
ep0_get_descriptor_request(struct setup_packet *setup) {
	uint8_t type  = (uint8_t) (setup->wValue >> 8);
	uint8_t index = (uint8_t) (setup->wValue & 0xff);
	switch (type) {
		case 1:		// Device descriptor
			ep0_begin_data_in_stage(&device_descriptor,
					sizeof(device_descriptor), NULL);
			return true;
		case 2:		// Configuration descriptor
			ep0_begin_data_in_stage(&configuration_descriptor,
					sizeof(configuration_descriptor), NULL);
			return true;
		case 3:		// String descriptor
			return get_string_descriptor(index);
		default:
			goto invalid;
	}
invalid:
	USB_DEBUG(USB_DEBUG_STANDARD, "Unhandled get descriptor type %d", type);
	USB_DEBUG_ABORT();
	return false;
}

static bool
ep0_standard_in_request(struct setup_packet *setup) {
	switch (setup->bRequest) {
		case 6:		// GET_DESCRIPTOR
			return ep0_get_descriptor_request(setup);
		case 8:		// GET_CONFIGURATION
			ep0_begin_data_in_stage(&configuration_descriptor.configuration
					.bConfigurationValue, 1, NULL);
			return true;
		case 10:	// GET_INTERFACE
			ep0_begin_data_in_stage(&configuration_descriptor.interface
					.bAlternateSetting, 1, NULL);
			return true;
	}
	USB_DEBUG(USB_DEBUG_STANDARD, "Unhandled standard IN request %d", setup->bRequest);
	USB_DEBUG_ABORT();
	return false;
}

static bool
ep0_standard_out_request(struct setup_packet *setup) {
	switch (setup->bRequest) {
		case 5:		// SET_ADDRESS
			usb_set_address(setup->wValue & 0x7f);
			return true;
		case 9:		// SET_CONFIGURATION
			// Ignore :)
			return true;
		case 11:	// SET_INTERFACE
			// Ignore :)
			return true;
	}
	USB_DEBUG(USB_DEBUG_STANDARD, "Unhandled standard OUT request %d", setup->bRequest);
	USB_DEBUG_ABORT();
	return false;
}

static bool
ep0_standard_request(struct setup_packet *setup) {
	if ((setup->bmRequestType & 0x80) == 0x80) {
		return ep0_standard_in_request(setup);
	} else {
		return ep0_standard_out_request(setup);
	}
}

static bool
ep0_setup_stage(struct setup_packet *setup) {
	USB_DEBUG(USB_DEBUG_STAGE, "[%llu] SETUP {%02x,%02x,%04x,%04x,%04x}",
			USB_DEBUG_ITERATION, setup->bmRequestType, setup->bRequest,
			setup->wValue, setup->wIndex, setup->wLength);
	uint8_t type = setup->bmRequestType & 0x60;
	switch (type) {
		case 0:		// Standard
			return ep0_standard_request(setup);
		case 0x40:	// Vendor
			return ep0_vendor_request(setup);
	}
	USB_DEBUG(USB_DEBUG_STAGE, "Unhandled request type 0x%x", type);
	return false;
}

// ---- Registers ---------------------------------------------------------------------------------

// We'll define SYNOPSYS_OTG_REGISTER() to wrap register offsets in a struct, which forces us to
// use them in a type-safe way.
struct _reg { uint32_t off; };
#define SYNOPSYS_OTG_REGISTER(_x)	((struct _reg) { _x })

// Include the registers.
#include "usb/synopsys_otg_regs.h"

// This is the physical base address of the Synopsys DWC USB 2.0 OTG registers.
// TODO: Get this value from the device tree.
uintptr_t synopsys_register_base = 0x230100000;

// The MMIO mapping of the Synopsys OTG registers.
static uintptr_t synopsys_registers;

static uint32_t
reg_read(struct _reg reg) {
	return *(volatile uint32_t *)(synopsys_registers + reg.off);
}

static void
reg_write(struct _reg reg, uint32_t val) {
	if (reg.off != rGINTSTS.off) {
		USB_DEBUG(USB_DEBUG_REG, "wr%03x %x", reg.off, val);
	}
	*(volatile uint32_t *)(synopsys_registers + reg.off) = val;
}

static void
reg_and(struct _reg reg, uint32_t val) {
	USB_DEBUG(USB_DEBUG_REG, "an%03x %x", reg.off, val);
	*(volatile uint32_t *)(synopsys_registers + reg.off) &= val;
}

static void
reg_or(struct _reg reg, uint32_t val) {
	USB_DEBUG(USB_DEBUG_REG, "or%03x %x", reg.off, val);
	*(volatile uint32_t *)(synopsys_registers + reg.off) |= val;
}

// ---- USB endpoint state ------------------------------------------------------------------------

// The maximum size of a single transfer.
#define MAX_TRANSFER_SIZE	0x1000

// A sentinel value for transfer_size to indicate that we actually want to send an empty packet.
#define TRANSFER_EMPTY		0xffff

// For EP 0 OUT transactions, indicates that we expect the next packet to be an OUT DATA
// transaction. Otherwise, the default is that we always expect a SETUP packet.
#define RECV_DATA		0x1

// State for managing data transfer over an endpoint.
struct endpoint_state {
	// The endpoint type. 0 = Control, 1 = Isochronous, 2 = Bulk, 3 = Interrupt. Initialized
	// during endpoint activation.
	uint8_t type;
	// The endpoint number. Initialized during endpoint activation.
	uint8_t n;
	// The maximum packet size on this endpoint. Initialized during endpoint activation.
	uint16_t max_packet_size;
	// The amount of data to transfer to/from the host. If transfer_size == TRANSFER_EMPTY,
	// then we expect to send/receive an empty packet.
	uint16_t transfer_size;
	// The amount of data transferred so far. This can be greater than transfer_size only for
	// OUT endpoints if the host unexpectedly sent us more data than it claimed it would.
	uint16_t transferred;
	// For IN endpoints, the amount of data in flight to the host. For OUT endpoints,
	// RECV_SETUP to indicate that we expect to receive a setup packet and RECV_DATA to
	// indicate that we expect to receive a data packet. 0 means that we haven't decided yet.
	uint16_t in_flight;
	// The physical address of the DMA buffer. Initialized in usb_init().
	uint32_t transfer_data_dma;
	// The virtual address of the DMA buffer of data to transfer. This buffer is of size
	// MAX_TRANSFER_SIZE. Initialized in usb_init().
	uint8_t *transfer_data;
};

// The endpoints.
static struct endpoint_state ep0_in;
static struct endpoint_state ep0_out;
static struct endpoint_state ep1_in;

// ---- Low-level transfer API for IN endpoints ---------------------------------------------------

// Execute an IN transaction (EP 0) or IN transfer (EP !0) on the endpoint. This function should
// not be called directly.
static void
ep_in_send(struct endpoint_state *ep) {
	if (ep->transfer_size == ep->transferred || ep->transferred >= MAX_TRANSFER_SIZE) {
		USB_DEBUG(USB_DEBUG_XFER, "transfer_size %u, transferred %u",
				ep->transfer_size, ep->transferred);
		BUG(0x73656e642033);	// 'send 3'
	}
	// Compute the size of the transfer and the number of packets.
	uint16_t transfer_size = ep->transfer_size - ep->transferred;
	uint16_t packet_count = 1;
	if (ep->transfer_size == TRANSFER_EMPTY) {
		// If we are sending an empty packet, transfer_size is 0.
		transfer_size = 0;
	} else {
		if (ep->type == 0) {
			// If we are sending data on EP 0 IN, then cap the transfer size at 1
			// packet.
			if (transfer_size > ep->max_packet_size) {
				transfer_size = ep->max_packet_size;
			}
		} else {
			// If we are sending at least one full packet of data on EP !0 IN, then
			// compute the number of packets we need to send. If the data we're sending
			// completely fills all packets with no remainder, then we'll also need to
			// tack on an empty packet to signal the end of the transfer. I thought
			// this could be programmed here, but it appears to not work correctly, so
			// I've moved sending the zlp to ep_in_send_done().
			if (transfer_size >= ep->max_packet_size) {
				packet_count = (transfer_size + ep->max_packet_size - 1)
					/ ep->max_packet_size;
			}
		}
	}
	USB_DEBUG(USB_DEBUG_XFER, "EP%u IN xfer %u|%u", ep->n, packet_count, transfer_size);
	// Set the registers.
	reg_write(rDIEPDMA(ep->n), ep->transfer_data_dma + ep->transferred);
	reg_write(rDIEPTSIZ(ep->n), (packet_count << 19) | transfer_size);
	reg_or(rDIEPCTL(ep->n), 0x84000000);
	// We now have data in flight.
	ep->in_flight = transfer_size;
}

// Call this once the hardware signals that atransfer on an IN endpoint initiated with
// ep_in_send_data() is complete (DIEPINT(n).xfercompl). This function will update state and return
// true if all the requested data has been sent.
static bool
ep_in_send_done(struct endpoint_state *ep) {
	USB_DEBUG(USB_DEBUG_XFER, "DIEPTSIZ(%u) = %x", ep->n, reg_read(rDIEPTSIZ(ep->n)));
	ep->transferred += ep->in_flight;
	ep->in_flight = 0;
	if (ep->transfer_size == TRANSFER_EMPTY) {
		ep->transfer_size = 0;
	}
	if (ep->transferred == ep->transfer_size) {
		// Handle sending a zlp after transferring a whole number of full packets.
		// Initially this was done by configuring DIEPTSIZ to include the zlp, but that
		// seems to hang the USB stack in some cases.
		if (ep->transfer_size > 0 && ep->transfer_size % ep->max_packet_size == 0) {
			ep->transferred = 0;
			ep->transfer_size = TRANSFER_EMPTY;
			ep_in_send(ep);
			return false;
		}
		USB_DEBUG(USB_DEBUG_XFER, "EP%u IN xfer done", ep->n);
		return true;
	} else {
		if (ep->type != 0) {
			// If this isn't a control endpoint, then we expect to be able to transfer
			// the whole thing in one shot. We shouldn't be notified if the transfer is
			// incomplete.
			USB_DEBUG(USB_DEBUG_XFER, "EP%u IN tranferred %x != %x transfer_size",
					ep->n, ep->transferred, ep->transfer_size);
			BUG(0x73656e642034);	// 'send 4'
		}
		ep_in_send(ep);
		return false;
	}
}

// Send data on an IN endpoint. Call ep_in_send_done() every time DIEPINT(ep->n).xfercompl is
// asserted to check whether the data has been sent and to continue sending data if the transfer is
// only partially complete.
static void
ep_in_send_data(struct endpoint_state *ep, const void *data, uint16_t size) {
	if (ep->transfer_size != ep->transferred) {
		BUG(0x73656e642031);	// 'send 1'
	}
	if (size > MAX_TRANSFER_SIZE) {
		BUG(0x73656e642032);	// 'send 2'
	}
	ep->transfer_size = (size == 0 ? TRANSFER_EMPTY : size);
	ep->transferred = 0;
	ep->in_flight = 0;
	memcpy(ep->transfer_data, data, size);
	cache_clean_and_invalidate(ep->transfer_data, size);
	ep_in_send(ep);
}

// ---- Low-level transfer API for EP 0 OUT -------------------------------------------------------

// This code is structured a bit differently from that for IN endpoints above. The reason for this
// is that while we have control of exactly what we send, we don't have control of exactly what we
// receive, so there are more edge cases we need to handle. This requires us to process one packet
// at a time in the interrupt handler, rather than firing off a request and being notified once
// it's all done. (The structure of the DOEP* registers for EP 0 also emphasize this: they prevent
// us from receiving more than 1 packet at a time.)
//
// The SecureROM does this by receiving 1 packet at a time, always into the same buffer at the same
// address, and then copying the data to the appropriate destination. That could work here, but it
// would require a different high-level API for handling control transfers, one that would send the
// supplied data to the upper layers one chunk at a time, rather than all at once when the transfer
// is complete. The flexibility of being able to send data piecemeal isn't actually a significant
// advantage for us, because if the transaction is aborted, then all that data should be discarded;
// this means that all the received data must be buffered anyway. In other circumstances, where the
// receiver can somehow compress the data as it is received in chunks, the other design might be
// better.
//
// Instead, I'll receive and buffer partially completed DATA OUT stages in the DMA buffer.

// Execute the SETUP or OUT DATA transaction pending on EP 0 OUT. A SETUP packet will always be
// received into the start of the buffer, so there is no need to reset buffer state after receiving
// a maximally-sized DATA OUT stage.
//
// This function should be called every time we want to actually receive any data on EP 0 OUT,
// including after a USB reset, after an interrupt on EP 0 OUT, and after completing the DATA IN
// stage of a control transfer (so that we can actually receive the STATUS OUT stage).
static void
ep0_out_recv() {
	if (ep0_out.in_flight != RECV_DATA) {
		ep0_out.transfer_size = 0;
		ep0_out.transferred = 0;
	} else if (ep0_out.transferred >= MAX_TRANSFER_SIZE) {
		BUG(0x726563762033);	// 'recv 3'
	}
	reg_write(rDOEPDMA(0), ep0_out.transfer_data_dma + ep0_out.transferred);
	reg_write(rDOEPTSIZ(0), (1 << 19) | EP0_MAX_PACKET_SIZE);
	reg_or(rDOEPCTL(0), (ep0_out.in_flight == RECV_DATA ? 0x84000000 : 0x80000000));
}

// When a setup packet is received, call this routine to receive a pointer to it. The setup packet
// should be copied out of the buffer.
//
// It is fine to call this function after calling ep0_out_recv_data() to initiate a DATA OUT stage.
// Any data from an in-progress but incomplete DATA OUT stage is discarded. The endpoint is primed
// to receive a SETUP packet.
static struct setup_packet *
ep0_out_recv_setup_done() {
	struct setup_packet *setup = (void *)(ep0_out.transfer_data + ep0_out.transferred);
	cache_invalidate(setup, sizeof(*setup));
	ep0_out.transfer_size = 0;
	ep0_out.transferred = 0;
	ep0_out.in_flight = 0;
	return setup;
}

// Prime EP 0 OUT to receive OUT DATA transactions as part of a DATA OUT stage of a control
// transfer, rather than the default behavior of receiving a SETUP packet. This function can only
// be called once per control transfer.
//
// ep0_out_recv() still needs to be called to actually begin the transfer. Each time an OUT DATA
// transaction is successfully received on the endpoint, call ep0_out_recv_data_done() to update
// state and test whether all data has been received.
static void
ep0_out_recv_data(uint16_t size) {
	if (ep0_out.in_flight != 0) {
		BUG(0x726563762031);	// 'recv 1'
	}
	if (size > MAX_TRANSFER_SIZE) {
		BUG(0x726563762032);	// 'recv 2'
	}
	ep0_out.transfer_size = (size == 0 ? TRANSFER_EMPTY : size);
	ep0_out.transferred = 0;
	ep0_out.in_flight = RECV_DATA;
}

// Call this during an OUT DATA transaction for a control transfer once the hardware signals that a
// packet has been successfully received. This will update state and return whether the transfer is
// complete.
//
// This function does not call ep0_out_recv() to retrieve more data.
static bool
ep0_out_recv_data_done() {
	// We expect to reach here only after ep0_out_recv_data() has been called to
	// specify that we expect data.
	if (ep0_out.in_flight != RECV_DATA) {
		BUG(0x726563762034);	// 'recv 4'
	}
	uint32_t left = reg_read(rDOEPTSIZ(0)) & 0x7f;
	uint32_t size = EP0_MAX_PACKET_SIZE - left;
	if (size > 0) {
		ep0_out.transferred += size;
	}
	if (ep0_out.transfer_size == TRANSFER_EMPTY) {
		ep0_out.transfer_size = 0;
	}
	// The DATA OUT stage is done once we've received the expected amount of data or once we've
	// received a partial packet.
	if (ep0_out.transferred >= ep0_out.transfer_size
			|| left != 0) {
		ep0_out.in_flight = 0;
		cache_invalidate(ep0_out.transfer_data, ep0_out.transferred);
		return true;
	} else {
		return false;
	}
}

// ---- Controlling USB functionality -------------------------------------------------------------

// The maximum number of iterations we'll loop for when waiting for a USB register write to take
// effect.
#define LOOP_ITERS	10000000

static void
ep_in_activate(struct endpoint_state *ep, uint8_t n, uint8_t type, uint16_t max_packet_size,
		uint8_t txfifo) {
	USB_DEBUG(USB_DEBUG_FUNC, "EP%u IN activate", n);
	ep->n = n;
	ep->type = type;
	ep->max_packet_size = max_packet_size;
	// For Bulk and Interrupt endpoints, initialize FIFO state.
	if (type == 2 || type == 3) {
		// setd0pid | snak | txfnum | eptype | usbactep | mps
		reg_write(rDIEPCTL(1), (1 << 28) | (1 << 27) | (txfifo << 22) | (type << 18)
				| (1 << 15) | max_packet_size);
	}
	reg_or(rDAINTMSK, (1 << n));
}

static void
ep_in_abort(struct endpoint_state *ep) {
	USB_DEBUG(USB_DEBUG_FUNC, "EP%u IN abort", ep->n);
	ep->transfer_size = 0;
	ep->transferred = 0;
	ep->in_flight = 0;
	if (reg_read(rDIEPCTL(ep->n)) & 0x80000000) {
		reg_or(rDIEPCTL(ep->n), 0x40000000);
		for (unsigned i = 0; i < LOOP_ITERS; i++) {
			if (reg_read(rDIEPINT(ep->n)) & 0x2) {
				break;
			}
		}
	}
	reg_write(rDIEPINT(ep->n), reg_read(rDIEPINT(ep->n)));
}

static void
ep_in_stall(struct endpoint_state *ep) {
	USB_DEBUG(USB_DEBUG_FUNC, "EP%u IN stall", ep->n);
	reg_or(rDIEPCTL(ep->n), 0x200000);
}

static void
ep0_out_stall() {
	USB_DEBUG(USB_DEBUG_FUNC, "EP0 OUT stall");
	reg_or(rDOEPCTL(0), 0x200000);
}

static void
usb_set_address(uint8_t address) {
	USB_DEBUG(USB_DEBUG_FUNC, "Set address %u", address);
	uint32_t dcfg = reg_read(rDCFG);
	dcfg = (dcfg & ~0x7f0) | (((uint32_t) address << 4) & 0x7f0);
	reg_write(rDCFG, dcfg);
}

static void
usb_reset() {
	USB_DEBUG(USB_DEBUG_FUNC, "Reset");
	ep_in_abort(&ep0_in);
	ep_in_abort(&ep1_in);
	usb_set_address(0);
	reg_write(rDOEPMSK, 0);
	reg_write(rDIEPMSK, 0);
	reg_write(rDAINTMSK, 0);
	reg_write(rDIEPINT(0), 0x1f);
	reg_write(rDOEPINT(0), 0xf);
	reg_write(rGRXFSIZ,    0x0000021b);
	reg_write(rGNPTXFSIZ,  0x0010021b);	//   64 bytes
	reg_write(rDTXFSIZ(1), 0x0040022b);	//  256 bytes
	reg_write(rDTXFSIZ(2), 0x0100026b);	// 1024 bytes
	reg_write(rDTXFSIZ(3), 0x0100036b);	// 1024 bytes
	reg_write(rDTXFSIZ(4), 0x0100046b);	// 1024 bytes
	reg_write(rDOEPCTL(0), 0);
	reg_write(rDIEPCTL(0), 0);
	reg_or(rGINTMSK, 0xc0000);
	reg_write(rDOEPMSK, 0xd);
	reg_write(rDIEPMSK, 0xd);
	reg_write(rDAINTMSK, 0x10001);
	ep_in_activate(&ep0_in, 0, 0, EP0_MAX_PACKET_SIZE, 0);
	uint8_t ep_type = configuration_descriptor.endpoint_1.bmAttributes;
	uint16_t ep_mps = configuration_descriptor.endpoint_1.wMaxPacketSize;
	ep_in_activate(&ep1_in, 1, ep_type, ep_mps, 2);
	ep0_out_recv();
}

// ---- USB interrupt handling --------------------------------------------------------------------

// This is the API we export to the layer above:
//
// At the start:
//
//     - We will call ep0_setup_stage() when the SETUP stage is done and we have a setup packet.
//       This function should return true if the request was recognized and the control transfer
//       should continue, and false to stall EP 0 OUT.
//
// For IN control transfers:
//
//     - ep0_setup_stage() should call ep0_begin_data_in_stage() to begin the DATA IN stage. The
//       third parameter to ep0_begin_data_in_stage() is a callback function
//       status_out_stage_callbock to invoke if the entire transfer completes successfully.
//
//     - When the DATA IN stage is complete, we will call ep0_out_recv_data(0, true) to begin the
//       STATUS OUT stage.
//
//     - If the STATUS OUT stage does not complete successfully (because a non-zero-length packet
//       was received), then we will stall EP 0 OUT without calling status_out_stage_callback().
//
//       (The reason for this behavior is that we're relying on DCTL.nzstsouthshk to send the STALL
//       handshake in response to a non-zero-length STATUS OUT stage. When this bit is set, we
//       won't receive the offending STATUS OUT.)
//
//       If an IN control transfer specified a status_out_stage_callback and that callback was not
//       invoked, then that means the data was not successfully received by the host.
//
//     - If the STATUS OUT stage completes successfully (we receive a zero-length packet), then we
//       will call status_out_stage_callback().
//
// For OUT control transfers:
//
//     - If there is a DATA OUT stage, ep0_setup_stage() should call ep0_begin_data_out_stage() to
//       begin the DATA OUT stage. The only parameter to ep0_begin_data_out_stage() is a callback
//       function data_out_stage_callback that will be invoked when the data is successfully
//       received.
//
//     - If we receive a setup packet before the transfer is complete, ep0_setup_stage() is called
//       again without calling data_out_stage_callback().
//
//     - If we receive the wrong amount of data, EP 0 OUT is stalled without calling
//       data_out_stage_callback().
//
//     - Otherwise, if the DATA OUT stage is received successfully, we will call
//       data_out_stage_callback() with the received data. This function should return true if we
//       should send a successful zero-length STATUS IN stage, or false if we should stall EP 0 IN.
//
// Structuring control transfers in this way makes things less efficient, since the host may send
// the last packet and an ack at the same time, and we now force it to take a retry. But I think
// it's much simpler to use this API.

// This holds state for a pair of IN/OUT control endpoints to manage a control transfer.
struct control_transfer_state {
	struct setup_packet setup_packet;
	bool setup_packet_pending;
	bool (*data_out_stage_callback)(const void *data, uint16_t size);
	void (*status_out_stage_callback)(void);
};

// This holds state for a non-control IN endpoint to manage transfers.
struct in_transfer_state {
	void (*in_transfer_done)(void);
};

// State for IN/OUT EP 0 control transfers.
static struct control_transfer_state ep0;

// State for EP 1 IN transfers.
struct in_transfer_state ep1;

// You may try to send more data than was requested, but the request will be truncated to the size
// requested by the host.
static void
ep0_begin_data_in_stage(const void *data, uint16_t size, void (*callback)(void)) {
	if (size > ep0.setup_packet.wLength) {
		size = ep0.setup_packet.wLength;
	}
	USB_DEBUG(USB_DEBUG_STAGE, "DATA IN %u", size);
	ep0.status_out_stage_callback = callback;
	ep_in_send_data(&ep0_in, data, size);
}

static void
ep0_begin_data_out_stage(bool (*callback)(const void *, uint16_t)) {
	USB_DEBUG(USB_DEBUG_STAGE, "DATA OUT %u", ep0.setup_packet.wLength);
	ep0.data_out_stage_callback = callback;
	ep0_out_recv_data(ep0.setup_packet.wLength);
	// We explicitly do not want to call ep0_out_recv() here; we will do that once this whole
	// stack unwinds and we're back in ep0_out_interrupt().
}

// Queue data for sending on the specified bulk or interrupt endpoint. The data won't be sent until
// the host initiates an IN transfer. Once the transfer is complete, the specified callback will be
// invoked.
static void
usb_in_transfer(uint8_t ep_addr, const void *data, uint16_t size, void (*callback)(void)) {
	struct endpoint_state *ep;
	struct in_transfer_state *state;
	if (ep_addr == 0x81) {
		ep = &ep1_in;
		state = &ep1;
	} else {
		BUG(0x6e6f206570);	// 'no ep'
	}
	if (state->in_transfer_done != NULL) {
		BUG(0x636220736574);	// 'cb set'
	}
	state->in_transfer_done = callback;
	ep_in_send_data(ep, data, size);
}

static void
ep0_in_interrupt() {
	uint32_t diepint = reg_read(rDIEPINT(0));
	reg_write(rDIEPINT(0), diepint);
	USB_DEBUG(USB_DEBUG_INTR, "DIEPINT(0) %x", diepint);
	if (diepint & 0x1) {
		bool done = ep_in_send_done(&ep0_in);
		if (done) {
			if (ep0.setup_packet.bmRequestType & 0x80) {
				// This is an IN control transfer and we're done sending the data,
				// so we want to begin the STATUS OUT stage.
				//
				// Note that there's an edge case here: Let's say the host has
				// requested 0x123 bytes, and we have only 0x80. We send 2 full
				// packets then think we're done. The host however doesn't know
				// that yet, it still thinks we're going to send more, so it issues
				// another DATA IN. Because of this, we need to send an incomplete
				// packet to let it know that that's all there is.
				uint16_t requested = ep0.setup_packet.wLength;
				uint16_t sent = ep0_in.transferred;
				bool partial = sent == 0 || (sent % EP0_MAX_PACKET_SIZE) != 0;
				if (requested > sent && !partial) {
					// We have no more data, but the host doesn't yet know that
					// this transfer is complete since we haven't sent a
					// partial packet. Send an empty packet now to let it know.
					USB_DEBUG(USB_DEBUG_STAGE, "Send partial packet");
					ep_in_send_data(&ep0_in, NULL, 0);
				} else {
					// Either we've sent all the requested data, or we've
					// already sent a partial packet (possibly the zero-length
					// one from the if case), so the host knows the transfer is
					// done. Begin the STATUS OUT stage by requesting an empty
					// packet.
					USB_DEBUG(USB_DEBUG_STAGE, "STATUS OUT");
					// Call ep0_out_recv() because we're not in the
					// ep0_out_interrupt() stack.
					//
					// Even though it's possible we have both IN and OUT
					// interrupts to handle for EP 0, I believe that it should
					// be fine to call ep0_out_recv_data() and ep0_out_recv()
					// here. Up until this point we have had EP 0 OUT send a
					// NAK for all OUT DATA packets. Thus, the only interesting
					// interrupt on EP 0 OUT could be a setup packet. If that's
					// the case, then receiving that setup packet will clear
					// the request to receive data.
					ep0_out_recv_data(0);
					ep0_out_recv();
				}
			} else {
				// This is an OUT control transfer, which means that we must have
				// completed the STATUS IN stage. Nothing to do.
			}
		}
	}
	if (diepint & 0x8) {
		USB_DEBUG(USB_DEBUG_INTR, "TIMEOUT");
		USB_DEBUG_PRINT_REGISTERS();
		USB_DEBUG_ABORT();
	}
	if (diepint & 0x4) {
		BUG(0x61686220696e);	// 'ahb in'
	}
}

static void
ep0_out_interrupt() {
	uint32_t doepint = reg_read(rDOEPINT(0));
	reg_write(rDOEPINT(0), doepint);
	if (doepint & 0x8000) {
		// We've received a setup packet.
		struct setup_packet *setup = ep0_out_recv_setup_done();
		ep0.setup_packet = *setup;
		ep0.setup_packet_pending = true;
		ep0.data_out_stage_callback = NULL;
		ep0.status_out_stage_callback = NULL;
	}
	if ((doepint & 0x8) && ep0.setup_packet_pending) {
		// The SETUP stage is done, so process the queued setup packet.
		ep0.setup_packet_pending = false;
		bool success = false;
		// Only begin processing the setup packet if we will have enough room for the whole
		// transfer. We could break down the layering to allow even bigger contiguous
		// transfers, but this works fine for me.
		if (ep0.setup_packet.wLength <= MAX_TRANSFER_SIZE) {
			success = ep0_setup_stage(&ep0.setup_packet);
		}
		if (success) {
			// The SETUP stage was successful.
			if (ep0.setup_packet.bmRequestType & 0x80) {
				// This is an IN control transfer. There will be a DATA IN stage,
				// so we don't expect to receive the STATUS OUT stage yet. The DATA
				// IN was initialized by ep0_setup_stage().
#if DEBUG_USB
				// Check to make sure that ep0_begin_data_in_stage() was called.
				if (ep0_in.transfer_size == ep0_in.transferred) {
					USB_DEBUG(USB_DEBUG_FATAL,
							"ep0_begin_data_in_stage() not called!");
					USB_DEBUG_ABORT();
				}
#endif
			} else {
				// This is an OUT control transfer. We may or may not have a data
				// stage.
				if (ep0.setup_packet.wLength > 0) {
					// We do have a DATA OUT stage. The size should have been
					// set it ep0_setup_stage() by a call to
					// ep0_begin_data_out_stage() (which internally calls
					// ep0_out_recv_data()).
#if DEBUG_USB
					if (ep0_out.in_flight != RECV_DATA) {
						USB_DEBUG(USB_DEBUG_FATAL, "ep0_begin_data_out_"
								"stage() not called!");
					}
#endif
				} else {
					// We do not have a DATA OUT stage, so we move directly to
					// the STATUS IN stage.
					USB_DEBUG(USB_DEBUG_STAGE, "STATUS IN");
					ep_in_send_data(&ep0_in, NULL, 0);
				}
			}
		} else {
			// The SETUP stage failed, so stall the next endpoint that will be queried.
			if (ep0.setup_packet.bmRequestType & 0x80) {
				// This was supposed to be an IN control transfer, so stall EP 0
				// IN.
				ep_in_stall(&ep0_in);
			} else {
				// This was supposed to be an OUT control transfer.
				if (ep0.setup_packet.wLength > 0) {
					// If there was supposed to be a DATA OUT stage, stall EP 0
					// OUT.
					ep0_out_stall();
				} else {
					// If we were supposed to go directly to STATUS IN, stall
					// EP 0 IN.
					ep_in_stall(&ep0_in);
				}
			}
		}
	} else if ((doepint & 0x8021) == 0x21) {
		// After an OUT control transfer with data completes, we get a zero-length OUT DATA
		// with DOEPINT 0x21 (stsphsercvd | xfercompl). This is expected, don't stall.
		USB_DEBUG(USB_DEBUG_STAGE, "STATUS IN done");
	} else if ((doepint & 0x8021) == 0x1) {
		// This packet is part of the DATA OUT stage or STATUS OUT stage.
		bool done = ep0_out_recv_data_done();
		if (done) {
			// ep0_out_recv_data_done() has reset the receive state, so the next call
			// to ep0_out_recv() expects a setup packet. But before we start receiving
			// more data, process the data we did receive.
			if (ep0.setup_packet.bmRequestType & 0x80) {
				// This is an IN control transfer, so this packet is part of the
				// STATUS OUT stage.
				if (ep0_out.transferred != 0
						|| ep0_out.transfer_size != 0) {
					// STATUS OUT failed.
					ep0_out_stall();
				} else {
					// STATUS OUT completed successfully.
					USB_DEBUG(USB_DEBUG_STAGE, "STATUS OUT done");
					if (ep0.status_out_stage_callback != NULL) {
						ep0.status_out_stage_callback();
						ep0.status_out_stage_callback = NULL;
					}
				}
			} else {
				// This is an OUT control transfer, so this packet is part of the
				// DATA OUT stage.
				if (ep0_out.transferred != ep0_out.transfer_size) {
					// The wrong amount of data was transferred.
					ep0_out_stall();
				} else {
					// We got all the data. Give it to the layer above us to
					// process the DATA OUT stage.
					if (ep0.data_out_stage_callback == NULL) {
						BUG(0x6e6f20646f206362);	// 'no do cb'
					}
					bool success = ep0.data_out_stage_callback(
							ep0_out.transfer_data,
							ep0_out.transfer_size);
					ep0.data_out_stage_callback = NULL;
					if (success) {
						// The DATA OUT stage was successful. Move to the
						// STATUS IN stage.
						USB_DEBUG(USB_DEBUG_STAGE, "STATUS IN");
						ep_in_send_data(&ep0_in, NULL, 0);
					} else {
						// The DATA OUT stage failed.
						ep_in_stall(&ep0_in);
					}
				}
			}
		} else {
			// The DATA OUT transaction is not done. The call to ep0_out_recv() below
			// will continue receiving OUT DATA.
		}
	}
	if (doepint & 0x4) {
		BUG(0x616862206f7574);	// 'ahb out'
	}
	// We call ep0_out_recv() after everything has been processed to ensure that in all cases
	// we'll re-enable the endpoint. ep0_out_recv() will only allow receiving OUT DATA if
	// ep0_out_recv_data() was called.
	ep0_out_recv();
}

static void
ep1_in_interrupt() {
	uint32_t diepint = reg_read(rDIEPINT(1));
	reg_write(rDIEPINT(1), diepint);
	USB_DEBUG(USB_DEBUG_INTR, "DIEPINT(1) %x", diepint);
	if (diepint & 0x1) {
		bool done = ep_in_send_done(&ep1_in);
		if (done) {
			// The transfer is done! Notify the upper layer.
			USB_DEBUG(USB_DEBUG_APP, "EP%u IN done", ep1_in.n);
			if (ep1.in_transfer_done == NULL) {
				BUG(0x6e6f203169206362);	// 'no 1i cb'
			}
			// We need to clear ep1.in_transfer_done before invoking the callback,
			// since in_transfer_done() might itself register another transfer.
			void (*in_transfer_done)(void) = ep1.in_transfer_done;
			ep1.in_transfer_done = NULL;
			in_transfer_done();
		}
	}
	if (diepint & 0x8) {
		USB_DEBUG(USB_DEBUG_STAGE | USB_DEBUG_INTR, "TIMEOUT");
		USB_DEBUG_PRINT_REGISTERS();
		USB_DEBUG_ABORT();
	}
	if (diepint & 0x4) {
		BUG(0x61686220696e2031);	// 'ahb in 1'
	}
}

static void
usb_ep_interrupt() {
	uint32_t daint = reg_read(rDAINT);
	if (daint != 0) {
		USB_DEBUG(USB_DEBUG_INTR, "[%llu] DAINT %x", USB_DEBUG_ITERATION, daint);
	}
	if (daint & 0x1) {
		ep0_in_interrupt();
	}
	if (daint & 0x2) {
		ep1_in_interrupt();
	}
	if (daint & 0x10000) {
		ep0_out_interrupt();
	}
}

// ---- The USB API -------------------------------------------------------------------------------

static void *fake_synopsys_registers;

void
usb_init(void *dma, void *memory) {
	uintptr_t dma_page_v = (uintptr_t) dma;
	uintptr_t dma_page_p = kernel_virtual_to_physical(dma_page_v);
	ep0_out.transfer_data     = (void *)   (dma_page_v + 0 * MAX_TRANSFER_SIZE);
	ep0_out.transfer_data_dma = (uint32_t) (dma_page_p + 0 * MAX_TRANSFER_SIZE);
	ep0_in.transfer_data      = (void *)   (dma_page_v + 1 * MAX_TRANSFER_SIZE);
	ep0_in.transfer_data_dma  = (uint32_t) (dma_page_p + 1 * MAX_TRANSFER_SIZE);
	ep1_in.transfer_data      = (void *)   (dma_page_v + 2 * MAX_TRANSFER_SIZE);
	ep1_in.transfer_data_dma  = (uint32_t) (dma_page_p + 2 * MAX_TRANSFER_SIZE);
	fake_synopsys_registers = memory;
}

void
usb_start() {
	if (synopsys_registers == 0) {
		synopsys_registers = (uintptr_t) ttbr0_map_io(synopsys_register_base, 0x4000);
	}
	size_t count __attribute__((unused));
	count = ttbr1_page_table_swap_physical_page(synopsys_register_base,
			kernel_virtual_to_physical((uintptr_t) fake_synopsys_registers));
	USB_DEBUG(USB_DEBUG_INIT, "Rerouted %zu kernel mapping(s) of the USB registers", count);
	reg_write(rGRSTCTL, 0x1);
	for (unsigned i = 0; i < LOOP_ITERS; i++) {
		if ((reg_read(rGRSTCTL) & 0x1) == 0) {
			break;
		}
	}
	reg_or(rDCTL, 0x2);
	for (unsigned i = 0; i < LOOP_ITERS; i++) {
		if ((reg_read(rGRSTCTL) & 0x80000000) != 0) {
			break;
		}
	}
	reg_write(rGAHBCFG, 0x2e);
	reg_write(rGUSBCFG, 0x1408);
	reg_write(rDCFG, 0x4);
	reg_write(rGINTMSK, 0);
	reg_write(rDOEPMSK, 0);
	reg_write(rDIEPMSK, 0);
	reg_write(rDAINTMSK, 0);
	reg_write(rDIEPINT(0), 0x1f);
	reg_write(rDOEPINT(0), 0xf);
	reg_write(rGINTMSK, 0x1000);
	reg_and(rDCTL, ~0x2);
}

void
usb_process() {
	USB_DEBUG_INCREMENT_ITERATION();
	uint32_t gintsts = reg_read(rGINTSTS);
	reg_write(rGINTSTS, gintsts);
	if (gintsts & 0xC0000) {
		usb_ep_interrupt();
	}
	if (gintsts & 0x1000) {
		usb_reset();
	}
	USB_DEBUG_ABORT_ON_ITERATION(100000000);
}

// ---- The USB debug implementation --------------------------------------------------------------

#if DEBUG_USB

#include <stdarg.h>

#include "kernel_extern.h"

KERNEL_EXTERN void panic(const char *format, ...);
KERNEL_EXTERN void paniclog_append_noflush(const char *format, ...);
KERNEL_EXTERN int vsnprintf(char *buf, size_t size, const char *fmt, va_list ap);

static void
USB_DEBUG(unsigned type, const char *format, ...) {
	if ((type & (USB_DEBUG_ENABLED | USB_DEBUG_FATAL)) != 0) {
		va_list ap;
		va_start(ap, format);
		char buf[512];
		vsnprintf(buf, sizeof(buf), format, ap);
		va_end(ap);
		paniclog_append_noflush("%s\n", buf);
	}
}

static void
USB_DEBUG_ABORT_INTERNAL(const char *function) {
	USB_DEBUG(USB_DEBUG_FATAL, "ABORT: %s: %llu", function, USB_DEBUG_ITERATION);
	panic("");
}

static void
USB_DEBUG_PRINT_REGISTERS() {
#define USB_DEBUG_REG_VALUE(reg) USB_DEBUG(USB_DEBUG_FATAL, #reg " = 0x%08x", reg_read(reg))
	USB_DEBUG_REG_VALUE(rGOTGCTL);
	USB_DEBUG_REG_VALUE(rGOTGINT);
	USB_DEBUG_REG_VALUE(rGAHBCFG);
	USB_DEBUG_REG_VALUE(rGUSBCFG);
	USB_DEBUG_REG_VALUE(rGRSTCTL);
	USB_DEBUG_REG_VALUE(rGINTSTS);
	USB_DEBUG_REG_VALUE(rGINTMSK);
	USB_DEBUG_REG_VALUE(rGRXSTSR);
	USB_DEBUG_REG_VALUE(rGRXSTSP);
	USB_DEBUG_REG_VALUE(rGRXFSIZ);
	USB_DEBUG_REG_VALUE(rGNPTXFSIZ);
	USB_DEBUG_REG_VALUE(rGNPTXSTS);
	USB_DEBUG_REG_VALUE(rGI2CCTL);
	USB_DEBUG_REG_VALUE(rGPVNDCTL);
	USB_DEBUG_REG_VALUE(rGGPIO);
	USB_DEBUG_REG_VALUE(rGUID);
	USB_DEBUG_REG_VALUE(rGSNPSID);
	USB_DEBUG_REG_VALUE(rGHWCFG1);
	USB_DEBUG_REG_VALUE(rGHWCFG2);
	USB_DEBUG_REG_VALUE(rGHWCFG3);
	USB_DEBUG_REG_VALUE(rGHWCFG4);
	USB_DEBUG_REG_VALUE(rGLPMCFG);
	USB_DEBUG_REG_VALUE(rGPWRDN);
	USB_DEBUG_REG_VALUE(rGDFIFOCFG);
	USB_DEBUG_REG_VALUE(rADPCTL);

	USB_DEBUG_REG_VALUE(rHPTXFSIZ);
	USB_DEBUG_REG_VALUE(rDTXFSIZ(0));
	USB_DEBUG_REG_VALUE(rDTXFSIZ(1));
	USB_DEBUG_REG_VALUE(rDTXFSIZ(2));
	USB_DEBUG_REG_VALUE(rDTXFSIZ(3));
	USB_DEBUG_REG_VALUE(rDTXFSIZ(4));

	USB_DEBUG_REG_VALUE(rDCFG);
	USB_DEBUG_REG_VALUE(rDCTL);
	USB_DEBUG_REG_VALUE(rDSTS);
	USB_DEBUG_REG_VALUE(rDIEPMSK);
	USB_DEBUG_REG_VALUE(rDOEPMSK);
	USB_DEBUG_REG_VALUE(rDAINT);
	USB_DEBUG_REG_VALUE(rDAINTMSK);

	USB_DEBUG_REG_VALUE(rDIEPCTL(0));
	USB_DEBUG_REG_VALUE(rDIEPINT(0));
	USB_DEBUG_REG_VALUE(rDIEPTSIZ(0));
	USB_DEBUG_REG_VALUE(rDIEPDMA(0));
	USB_DEBUG_REG_VALUE(rDTXFSTS(0));

	USB_DEBUG_REG_VALUE(rDOEPCTL(0));
	USB_DEBUG_REG_VALUE(rDOEPINT(0));
	USB_DEBUG_REG_VALUE(rDOEPTSIZ(0));
	USB_DEBUG_REG_VALUE(rDOEPDMA(0));

	USB_DEBUG_REG_VALUE(rDIEPCTL(1));
	USB_DEBUG_REG_VALUE(rDIEPINT(1));
	USB_DEBUG_REG_VALUE(rDIEPTSIZ(1));
	USB_DEBUG_REG_VALUE(rDIEPDMA(1));
	USB_DEBUG_REG_VALUE(rDTXFSTS(1));
}

#endif
