Add the XML file for configuring TD as follows (IVSHMEM).

```
<qemu:arg value='-device'/>
<qemu:arg value='ivshmem-plain,memdev=hostmem,bus=pcie.0,addr=0x7'/>
<qemu:arg value='-object'/>
<qemu:arg value='memory-backend-file,size=1M,share=on,mem-path=/dev/shm/ivshmem,id=hostmem'/>
```

Enter TD to verify whether the configuration is successful.

```
# BAR0:dev reg(MMIO)
# BAR1:MSI-X PBA(ivshmem-doorbell)
# BAR2:shared mem

lspci
ls -l /sys/bus/pci/devices/
lspci -vvv -s 00:07.0
# cat /sys/bus/pci/devices
```

Run as follows.

```
sh test.sh
cd rw_test

# The TD of TETD is used for writing, and other TD/VM are used for reading.
gcc write.c -o write
(gcc read.c -o read)

./write
(./read)
(sudo dmesg)
```

