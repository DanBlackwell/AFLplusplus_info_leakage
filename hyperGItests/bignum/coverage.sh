#!/bin/bash
# Sample usage for gcc
#   ./coverage.sh 
# builds bin2bn.c and all related files then
# runs python3 driver.py which has a set of 68 tests where each runs 5 times.
# 
CC=gcc
FNAME="crypto/bn/bin2bn"

date
rm -f test/bndriver ${FNAME}.o crypto/bn/bn_lib.o  *.gcov  
VAR1=$(${CC}  -I. -Iinclude --coverage -g -O0 -fprofile-arcs -ftest-coverage -fprofile-generate  -fPIC -m64 -Wa,--noexecstack -g3 -DOPENSSL_USE_NODELETE -DL_ENDIAN -DOPENSSL_PIC -DOPENSSL_CPUID_OBJ -DOPENSSL_IA32_SSE2 -DOPENSSL_BN_ASM_MONT -DOPENSSL_BN_ASM_MONT5 -DOPENSSL_BN_ASM_GF2m -DSHA1_ASM -DSHA256_ASM -DSHA512_ASM -DKECCAK1600_ASM -DRC4_ASM -DMD5_ASM -DAESNI_ASM -DVPAES_ASM -DGHASH_ASM -DECP_NISTZ256_ASM -DX25519_ASM -DPOLY1305_ASM -DOPENSSLDIR="\"/usr/local/ssl\"" -DENGINESDIR="\"/usr/local/lib/engines-1.1\""   -MMD -MF ${FNAME}.d.tmp -MT ${FNAME}.o -c -o ${FNAME}.o ${FNAME}.c 2>&1)

FNAME="crypto/bn/bn_lib"
VAR2=$(${CC}  -I. -Iinclude --coverage -g -O0 -fprofile-arcs -ftest-coverage -fprofile-generate  -fPIC -m64 -Wa,--noexecstack -g3 -DOPENSSL_USE_NODELETE -DL_ENDIAN -DOPENSSL_PIC -DOPENSSL_CPUID_OBJ -DOPENSSL_IA32_SSE2 -DOPENSSL_BN_ASM_MONT -DOPENSSL_BN_ASM_MONT5 -DOPENSSL_BN_ASM_GF2m -DSHA1_ASM -DSHA256_ASM -DSHA512_ASM -DKECCAK1600_ASM -DRC4_ASM -DMD5_ASM -DAESNI_ASM -DVPAES_ASM -DGHASH_ASM -DECP_NISTZ256_ASM -DX25519_ASM -DPOLY1305_ASM -DOPENSSLDIR="\"/usr/local/ssl\"" -DENGINESDIR="\"/usr/local/lib/engines-1.1\""   -MMD -MF ${FNAME}.d.tmp -MT ${FNAME}.o -c -o ${FNAME}.o ${FNAME}.c 2>&1)

if echo "$VAR1" | grep -q "error:"; then
  echo "Error:"
else
	ar r libcrypto.a ${FNAME}.o
	
	FNAME="bndriver"
	cd test

    ${LDCMD:-${CC}} -I.. -I../include -fprofile-generate -fprofile-arcs -ftest-coverage -m64 -Wa,--noexecstack -Wall -O0 -g -g3 -L.. -o ${FNAME} ${FNAME}.c -lcrypto -ldl 
    cd ..    
	python3 driver.py
	gcov -cd crypto/bn/bn_lib.info
	mv *.gcov crypto/bn/
fi
date

