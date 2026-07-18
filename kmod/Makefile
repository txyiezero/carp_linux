# Kbuild Makefile for CARP Linux kernel module
obj-m := carp.o
carp-objs := carp_main.o carp_input.o carp_output.o carp_route.o carp_netlink.o

KERNELDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean

install:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules_install
	depmod -a

unload:
	-rmmod carp

load:
	insmod carp.ko

.PHONY: all clean install unload load
