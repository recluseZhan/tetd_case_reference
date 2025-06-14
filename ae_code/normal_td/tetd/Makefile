obj-m += manual_remap1.o
manual_remap1-objs := manual_remap.o

obj-m += read1.o
read1-objs := read.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) clean

