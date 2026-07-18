# Kbuild Makefile for CARP Linux kernel module
obj-m := carp.o
carp-objs := carp_main.o carp_input.o carp_output.o carp_netlink.o carp_netdev.o

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

install:
	$(MAKE) -C $(KDIR) M=$(PWD) modules_install
	depmod -a

unload:
	-rmmod carp

load:
	insmod carp.ko

.PHONY: all clean install unload load
