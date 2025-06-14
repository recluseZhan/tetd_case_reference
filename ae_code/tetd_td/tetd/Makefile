obj-m += manual_remap1.o
manual_remap1-objs := manual_remap.o

obj-m += write1.o
write1-objs := aesni_encrypt.o aesni_encrypt2.o write.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) clean

