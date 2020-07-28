TARGET = ktrw_gdb_stub.ikext

ARCH = arm64
SDK  = iphoneos
KTRW_VERSION = 0.1.0
ACTIVATION_DELAY = 30

SYSROOT := $(shell xcrun --sdk $(SDK) --show-sdk-path)
ifeq ($(SYSROOT),)
$(error Could not find SDK $(SDK))
endif
CLANG := $(shell xcrun --sdk $(SDK) --find clang)
CC := $(CLANG) -isysroot $(SYSROOT) -arch $(ARCH)

CFLAGS  = -fno-builtin -fno-common -mkernel
CFLAGS += -Isource
CFLAGS += -O2
CFLAGS += -Wall -Werror -Wpedantic -Wno-gnu -Wno-language-extension-token
# TODO: -Wconversion

DEFINES = -DKTRW_VERSION='"$(KTRW_VERSION)"' \
	  -DKTRW_GDB_STUB_ACTIVATION_DELAY='$(ACTIVATION_DELAY)'

LDFLAGS  = -Xlinker -kext -nostdlib -Xlinker -fatal_warnings

SOURCES = source/gdb_stub/gdb_cpu.c \
	  source/gdb_stub/gdb_internal.c \
	  source/gdb_stub/gdb_packets.c \
	  source/gdb_stub/gdb_platform.c \
	  source/gdb_stub/gdb_rsp.c \
	  source/gdb_stub/gdb_stub.c \
	  source/usb/synopsys_otg.c \
	  source/debug.c \
	  source/devicetree.c \
	  source/jit_heap.c \
	  source/ktrw.c \
	  source/page_table.c \
	  source/primitives.c \
	  source/watchdog.c

HEADERS = source/gdb_stub/gdb_cpu.h \
	  source/gdb_stub/gdb_internal.h \
	  source/gdb_stub/gdb_packets.h \
	  source/gdb_stub/gdb_platform.h \
	  source/gdb_stub/gdb_rsp.h \
	  source/gdb_stub/gdb_state.h \
	  source/gdb_stub/gdb_stub.h \
	  source/third_party/boot_args.h \
	  source/usb/synopsys_otg_regs.h \
	  source/usb/usb.h \
	  source/debug.h \
	  source/devicetree.h \
	  source/if_value.h \
	  source/jit_heap.h \
	  source/kernel_extern.h \
	  source/page_table.h \
	  source/primitives.h \
	  source/watchdog.h

$(TARGET): $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) $(DEFINES) $(LDFLAGS) -o $@ $(SOURCES)

symbols: $(TARGET)
	@nm -u $(TARGET)

clean:
	rm -rf -- $(TARGET).$(ARCH).ld
	rm -f -- $(TARGET)
