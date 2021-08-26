#!/bin/bash
# Sample usage for gcc
#   ./buildbntest.sh gcc out.txt 16 32 input.txt 5
# *) build test subject for gcc 
# *) send output to the out.txt file
# *) get input from input.txt whose actual length is 16
# *) however, assume the length is 32
# *) run the program repeatedly 5 times
#
# Sample usage for fuzzer
#   ./buildbntest.sh fuzz out.txt
# Fuzz the subject and redirect output to out.txt
#

if [ $1 = "fuzz" ]
then
    echo "Fuzzer"
    export FUZZ_CXXFLAGS="-fno-omit-frame-pointer -g -fsanitize=address,fuzzer \
    -fsanitize-coverage=edge,indirect-calls,trace-cmp,trace-div,trace-gep "
    CC="clang $FUZZ_CXXFLAGS"
    FNAME="bnlib2"
else
    ifile="../$5"
    echo "gcc reading from ${ifile}"
    CC=gcc
    FUZZER=
    FNAME="bntemp2"
fi

cd test
rm -f ${FNAME}
${CC} -I.. -I../include  -DOPENSSL_THREADS -D_REENTRANT -DDSO_DLFCN -DHAVE_DLFCN_H -Wa,--noexecstack -m64 -DL_ENDIAN -DTERMIO -O0 -Wall -DOPENSSL_IA32_SSE2 -DOPENSSL_BN_ASM_MONT -DOPENSSL_BN_ASM_MONT5 -DOPENSSL_BN_ASM_GF2m -DSHA1_ASM -DSHA256_ASM -DSHA512_ASM -DMD5_ASM -DAES_ASM -DVPAES_ASM -DBSAES_ASM -DWHIRLPOOL_ASM -DGHASH_ASM -g -c -o ${FNAME}.o ${FNAME}.c

( :; LIBDEPS="${LIBDEPS:--L.. -lssl -L.. -lcrypto  -ldl}"; LDCMD="${LDCMD:-${CC} -g }"; LDFLAGS="${LDFLAGS:--DOPENSSL_THREADS -D_REENTRANT -DDSO_DLFCN -DHAVE_DLFCN_H -m64 -DL_ENDIAN -DTERMIO -O0 -Wall -DOPENSSL_IA32_SSE2 -DOPENSSL_BN_ASM_MONT -DOPENSSL_BN_ASM_MONT5 -DOPENSSL_BN_ASM_GF2m -DSHA1_ASM -DSHA256_ASM -DSHA512_ASM -DMD5_ASM -DAES_ASM -DVPAES_ASM -DBSAES_ASM -DWHIRLPOOL_ASM -DGHASH_ASM}"; LIBPATH=`for x in $LIBDEPS; do echo $x; done | sed -e 's/^ *-L//;t' -e d | uniq`; LIBPATH=`echo $LIBPATH | sed -e 's/ /:/g'`; LD_LIBRARY_PATH=$LIBPATH:$LD_LIBRARY_PATH ${LDCMD} ${LDFLAGS} -g -o ${APPNAME:=${FNAME}} ${FNAME}.o ${LIBDEPS} )


if [ $1 = "fuzz" ]
then
    # LSAN_OPTIONS=verbosity=1:log_threads=1
    ./${FNAME} > ../${2} 2>&1
else
    ./${FNAME} $3 $3 $5 > ../${2} 2>&1

    for (( c=0; c<$6; c++ ))
    do
        ./${FNAME} $3 $4 $5 >> ../${2} 2>&1
    done
fi
