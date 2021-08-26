#!/bin/bash
#
# prepare a clean compilation for openssl
# then run bndriver 
#

date
make clean
./config no-threads no-shared -d -g3 

make > make-woasm.txt
./buildbntest.sh out.txt 5 12 A7B2E9B6F9 5

# gdb test/bndriver


