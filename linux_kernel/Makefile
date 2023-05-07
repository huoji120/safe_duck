CONFIG_MODULE_SIG=n
obj-m += safe_duck.o
safe_duck-objs := main.o msg.o global.o some_struct.o
PWD  := $(shell pwd)
KVER := $(shell uname -r)
KDIR := /lib/modules/$(KVER)/build
all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules
clean:
	 rm -rf .*.cmd *.o *.mod.c *.ko .tmp_versions *.o.d *.mod 
