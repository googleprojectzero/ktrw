TARGET = ktrw_kext_loader

ARCH  = arm64
SDK   = iphoneos
DEBUG = 0

SYSROOT := $(shell xcrun --sdk $(SDK) --show-sdk-path)
ifeq ($(SYSROOT),)
$(error Could not find SDK $(SDK))
endif
CLANG := $(shell xcrun --sdk $(SDK) --find clang)
CC := $(CLANG) -isysroot $(SYSROOT) -arch $(ARCH)

CFLAGS  = -Iheaders -Ikernel -Ikernel_call -Ikernel_patches -Ikext_load -Iktrr -Isystem
CFLAGS += -O2
CFLAGS += -Wall -Werror -Wpedantic -Wno-gnu -Wno-language-extension-token
CFLAGS += -Wno-keyword-macro

ifneq ($(DEBUG),0)
CFLAGS += -DDEBUG=$(DEBUG)
endif

LDFLAGS = -framework CoreFoundation -framework IOKit

SOURCES = kernel/kernel_memory.c \
	  kernel/kernel_parameters.c \
	  kernel/kernel_slide.c \
	  kernel/kernel_tasks.c \
	  kernel_call/kernel_call.c \
	  kernel_call/kernel_call_7_a11.c \
	  kernel_call/kernel_call_parameters.c \
	  kernel_patches/kernel_patches.c \
	  kext_load/kext_load.c \
	  kext_load/resolve_symbol.c \
	  ktrr/ktrr_bypass.c \
	  ktrr/ktrr_bypass_parameters.c \
	  system/log.c \
	  system/map_file.c \
	  system/platform.c \
	  system/platform_match.c \
	  main.c

HEADERS = headers/IOKitLib.h \
	  headers/mach_vm.h \
	  kernel/kernel_memory.h \
	  kernel/kernel_parameters.h \
	  kernel/kernel_slide.h \
	  kernel/kernel_tasks.h \
	  kernel_call/kernel_call.h \
	  kernel_call/kernel_call_7_a11.h \
	  kernel_call/kernel_call_parameters.h \
	  kernel_patches/kernel_patches.h \
	  kext_load/kext_load.h \
	  kext_load/resolve_symbol.h \
	  ktrr/ktrr_bypass.h \
	  ktrr/ktrr_bypass_parameters.h \
	  system/log.h \
	  system/map_file.h \
	  system/parameters.h \
	  system/platform.h \
	  system/platform_match.h

$(TARGET): $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) $(DEFINES) $(LDFLAGS) -o $@ $(SOURCES)

clean:
	rm -f -- $(TARGET)
