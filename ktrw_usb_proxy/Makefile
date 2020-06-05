TARGET = ktrw_usb_proxy

DEBUG ?= 0

CFLAGS = -O2 -Wall -Werror

ifneq ($(DEBUG),0)
CFLAGS += -DDEBUG=$(DEBUG)
endif

SOURCES = ktrw_usb_proxy.c

HEADERS =

FRAMEWORKS = -framework IOKit -framework CoreFoundation

$(TARGET): $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) $(DEFINES) $(LDFLAGS) $(FRAMEWORKS) -o $@ $(SOURCES)

clean:
	rm -f -- $(TARGET)
