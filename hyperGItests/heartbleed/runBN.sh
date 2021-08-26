#!/bin/bash
# Sample usage for gcc
#   ./runBN.sh gcc out.txt 16 2 input.txt
# *) run test subject for gcc 
# *) send output to the out.txt file
# *) get input from input.txt whose length is 16
# *) use the big integer length 2 (16/8)
#
# Sample usage for fuzzer
#   ./runBN.sh fuzz out.txt 16 2 input.txt
#
if [ $1 = "fuzz" ]
then
    echo "Fuzzer"
    CC=clang
    FUZZER="-fsanitize=address,fuzzer"
    FNAME="bn_lib"
else
    echo "gcc"
    CC=gcc
    FUZZER=
    FNAME="bntemp"
fi

cd test
./${FNAME} $3 $4 < ../$5 > ../${2} 2>&1

./${FNAME} $3 $4 < ../$5 >> ../${2} 2>&1
./${FNAME} $3 $4 < ../$5 >> ../${2} 2>&1
./${FNAME} $3 $4 < ../$5 >> ../${2} 2>&1
./${FNAME} $3 $4 < ../$5 >> ../${2} 2>&1

