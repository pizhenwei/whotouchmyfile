obj-m := probe.o
KERNELDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all:
	make -C $(KERNELDIR) M=$(PWD) modules
