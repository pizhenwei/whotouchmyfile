obj-m := probe.o
#KDIR := /lib/modules/$(shell uname -r)/build
KDIR := /root/usr/src/kernels/3.10.0-327.36.57.6.x86_64
PWD := $(shell pwd)
default:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules
