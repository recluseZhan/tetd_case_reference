sudo rmmod read1
sudo rmmod manual_remap1
make clean

make
sudo insmod manual_remap1.ko
sudo insmod read1.ko
dmesg
