TARGET = kextload.pongo-module

ARCH = arm64
SDK  = iphoneos
ABI  = aapcs

SYSROOT := $(shell xcrun --sdk $(SDK) --show-sdk-path)
ifeq ($(SYSROOT),)
$(error Could not find SDK $(SDK))
endif
CLANG := $(shell xcrun --sdk $(SDK) --find clang)
CC := $(CLANG) -isysroot $(SYSROOT) -arch $(ARCH)

CFLAGS  = -mabi=$(ABI) -fno-builtin -fno-common -mkernel
CFLAGS += -Isource/third_party
CFLAGS += -O2
CFLAGS += -Wall -Werror -Wpedantic -Wno-gnu -Wno-language-extension-token -Wconversion

LDFLAGS  = -Xlinker -kext -nostdlib -Xlinker -fatal_warnings

SOURCES = source/pongo_kextload.c

HEADERS = source/third_party/pongo.h

$(TARGET): $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) $(DEFINES) $(LDFLAGS) -o $@ $(SOURCES)

symbols: $(TARGET)
	@nm -u $(TARGET)

clean:
	rm -rf -- $(TARGET).$(ARCH).ld
	rm -f -- $(TARGET)
