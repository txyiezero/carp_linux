# Top-level Makefile for CARP Linux
# Builds kernel module and userspace tools

.PHONY: all module tools clean install uninstall test

all: module tools

module:
	$(MAKE) -C kmod

tools:
	$(MAKE) -C tools

clean:
	$(MAKE) -C kmod clean
	$(MAKE) -C tools clean

install: all
	$(MAKE) -C kmod install
	$(MAKE) -C tools install

uninstall:
	rm -f /lib/modules/*/extra/carp.ko
	rm -f /usr/local/sbin/carpd
	depmod -a

test:
	bash tests/carp_basic.sh
