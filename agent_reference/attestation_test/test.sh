#!/bin/bash

make
sudo insmod attestation1.ko
sudo dmesg
sudo rmmod attestation1.ko
make clean
