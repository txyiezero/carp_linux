# Kernel module
obj-m += carp.o
carp-objs := carp_main.o carp_hmac.o

KDIR ?= /lib/modules/$(shell uname -r)/build

all: module userspace

module:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

userspace: carp_config

carp_config: carp_config.c
	gcc -Wall -o $@ $<

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f carp_config