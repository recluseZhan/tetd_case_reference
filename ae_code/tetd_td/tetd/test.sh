#!/bin/bash

## reader
sudo rmmod write1
sudo rmmod manual_remap1
make clean

make

## sign
sudo apt-get install openssl libssl-dev libssl-doc

# Generate a key pair.
openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:3072
openssl rsa -in private_key.pem -pubout -out public_key.pem

# View the key pair.
#openssl rsa -in private_key.pem -text -noout
#openssl rsa -in public_key.pem -pubin -text -noout

gcc sha256_asm_ni.S sign_main.c -lssl -lcrypto

## run
sudo insmod manual_remap1.ko
sudo insmod write1.ko
dmesg | grep "tetd" | tail -n 1
./a.out

rm *.out *.pem
