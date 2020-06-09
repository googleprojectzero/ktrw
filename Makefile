TARGET_DIRECTORIES = pongo_kext_loader pongo_kextload ktrw_gdb_stub ktrw_usb_proxy

all: $(TARGET_DIRECTORIES)

.PHONY: all $(TARGET_DIRECTORIES)

$(TARGET_DIRECTORIES):
	$(MAKE) -C $@

CLEAN_TARGET_DIRECTORIES = $(TARGET_DIRECTORIES:%=clean-%)

clean: $(CLEAN_TARGET_DIRECTORIES)

.PHONY: clean $(CLEAN_TARGET_DIRECTORIES)

$(CLEAN_TARGET_DIRECTORIES):
	$(MAKE) -C $(@:clean-%=%) clean
