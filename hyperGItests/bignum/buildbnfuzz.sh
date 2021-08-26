#!/bin/bash
#
# Sample usage for fuzzer
#   ./buildbntest.sh fuzz out.txt
# Fuzz the subject and redirect output to out.txt
#
    
export FUZZ_CXXFLAGS="-fno-omit-frame-pointer -g -fsanitize=address,fuzzer \
-fsanitize-coverage=edge,indirect-calls,trace-cmp,trace-div,trace-gep "
CC="afl-clang-fast"
FNAME="bnlib"

cd test
rm -f ${FNAME}
${CC} -I.. -I../include  -DOPENSSL_THREADS -D_REENTRANT -DDSO_DLFCN -DHAVE_DLFCN_H -Wa,--noexecstack -m64 -DL_ENDIAN -DTERMIO -O0 -Wall -DOPENSSL_IA32_SSE2 -DOPENSSL_BN_ASM_MONT -DOPENSSL_BN_ASM_MONT5 -DOPENSSL_BN_ASM_GF2m -DSHA1_ASM -DSHA256_ASM -DSHA512_ASM -DMD5_ASM -DAES_ASM -DVPAES_ASM -DBSAES_ASM -DWHIRLPOOL_ASM -DGHASH_ASM -g -c -o ${FNAME}.o ${FNAME}.c

( :; LIBDEPS="${LIBDEPS:--L.. -lssl -L.. -lcrypto  -ldl}"; LDCMD="${LDCMD:-${CC} -g }"; LDFLAGS="${LDFLAGS:--DOPENSSL_THREADS -D_REENTRANT -DDSO_DLFCN -DHAVE_DLFCN_H -m64 -DL_ENDIAN -DTERMIO -O0 -Wall -DOPENSSL_IA32_SSE2 -DOPENSSL_BN_ASM_MONT -DOPENSSL_BN_ASM_MONT5 -DOPENSSL_BN_ASM_GF2m -DSHA1_ASM -DSHA256_ASM -DSHA512_ASM -DMD5_ASM -DAES_ASM -DVPAES_ASM -DBSAES_ASM -DWHIRLPOOL_ASM -DGHASH_ASM}"; LIBPATH=`for x in $LIBDEPS; do echo $x; done | sed -e 's/^ *-L//;t' -e d | uniq`; LIBPATH=`echo $LIBPATH | sed -e 's/ /:/g'`; LD_LIBRARY_PATH=$LIBPATH:$LD_LIBRARY_PATH ${LDCMD} ${LDFLAGS} -g -o ${APPNAME:=${FNAME}} ${FNAME}.o ${LIBDEPS} )


./${FNAME} > ../${1} 2>&1

