#!/bin/bash
# ======================
# triangle.c fuzzer
# ======================
#
# Builds and runs for afl-fuzz for triangle.c program
#
# Sample Usage
#   ./afl-fuzz.sh  folder_num  maxRunTime
# Example:
#      ./afl-fuzz.sh 2 20
#   runs afl-fuzz for 20 seconds 
#   and stores the results in out2 folder
#
module load gcc/7.3.0-xegsmw4 llvm/11.0.1-py3-wge433b
AFLHOME=/work/LAS/mcohen-lab/imesecan/afl-3.12c
PATH=${PATH}:${AFLHOME}/bin
LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:${AFLHOME}/lib
export AFL_QUIET=1
export AFL_SKIP_CPUFREQ=1
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1

FILENAME=bn_lib
FNAME="crypto/bn/${FILENAME}"
DRIVER="bnafl-driver"
EXT=c
CC="afl-clang-fast"
CFLAGS="-g -O0"
FOLDER=$1
FUZZ_TIME=$2

date
rm -rf ${OUTPUT}  ${CORPUS}  test/${DRIVER}   ${FNAME}.o

VAR=$(${CC}  -I. -Iinclude -fPIC -m64 -Wa,--noexecstack -Wall -O0 -g -g3 -DOPENSSL_USE_NODELETE -DL_ENDIAN -DOPENSSL_PIC -DOPENSSL_CPUID_OBJ -DOPENSSL_IA32_SSE2 -DOPENSSL_BN_ASM_MONT -DOPENSSL_BN_ASM_MONT5 -DOPENSSL_BN_ASM_GF2m -DSHA1_ASM -DSHA256_ASM -DSHA512_ASM -DKECCAK1600_ASM -DRC4_ASM -DMD5_ASM -DAESNI_ASM -DVPAES_ASM -DGHASH_ASM -DECP_NISTZ256_ASM -DX25519_ASM -DPOLY1305_ASM -DOPENSSLDIR="\"/usr/local/ssl\"" -DENGINESDIR="\"/usr/local/lib/engines-1.1\""   -MMD -MF ${FNAME}.d.tmp -MT ${FNAME}.o -c -o ${FNAME}.o ${FNAME}.c 2>&1)

if echo "$VAR" | grep -q "error:"; then
  echo "error:"
else
    ar r libcrypto.a ${FNAME}.o

    ${LDCMD:-${CC}} -I. -I./include -m64 -Wa,--noexecstack -Wall -O0 -g3 -L. -o ${DRIVER} ${DRIVER}.c -lcrypto -ldl 
fi
date

