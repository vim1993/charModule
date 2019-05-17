obj-m := helloWorld.o
KERNEL_BUILD := /lib/modules/$(shell uname -r)/build
all:
	make -C $(KERNEL_BUILD) M=$(shell pwd) modules
clean:
	rm -rf *.o *.ko *.mod.c .*.cmd *.markers *.order *.symvers .tmp_versions
