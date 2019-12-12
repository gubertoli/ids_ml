PWD := $(shell pwd)
obj-m += netfilter_rule.o
all:
	make ARCH=arm64 CROSS_COMPILE=$(CROSS) -C $(KERNEL) SUBDIRS=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
