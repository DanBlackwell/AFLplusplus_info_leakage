#!/bin/bash
# Sample usage for gcc
#   ./buildbntest.sh 
#

CC=afl-clang-fast
FNAME="crypto/bn/bn_lib"

date
rm -f test/bndriver ${FNAME}.o 
VAR=$(${CC}  -I. -Iinclude -fPIC -m64 -Wa,--noexecstack -Wall -O0 -g -g3 -DOPENSSL_USE_NODELETE -DL_ENDIAN -DOPENSSL_PIC -DOPENSSL_CPUID_OBJ -DOPENSSL_IA32_SSE2 -DOPENSSL_BN_ASM_MONT -DOPENSSL_BN_ASM_MONT5 -DOPENSSL_BN_ASM_GF2m -DSHA1_ASM -DSHA256_ASM -DSHA512_ASM -DKECCAK1600_ASM -DRC4_ASM -DMD5_ASM -DAESNI_ASM -DVPAES_ASM -DGHASH_ASM -DECP_NISTZ256_ASM -DX25519_ASM -DPOLY1305_ASM -DOPENSSLDIR="\"/usr/local/ssl\"" -DENGINESDIR="\"/usr/local/lib/engines-1.1\""   -MMD -MF ${FNAME}.d.tmp -MT ${FNAME}.o -c -o ${FNAME}.o ${FNAME}.c 2>&1)

if echo "$VAR" | grep -q "error:"; then
  echo "error:"
fi

ar r libcrypto.a ${FNAME}.o
ranlib libcrypto.a || echo Never mind.
rm -f apps/openssl
${LDCMD:-${CC}} -m64 -Wa,--noexecstack -Wall -O0 -g -g3 -L.   \
	-o apps/openssl apps/asn1pars.o apps/ca.o apps/ciphers.o apps/cms.o apps/crl.o apps/crl2p7.o apps/dgst.o apps/dhparam.o apps/dsa.o apps/dsaparam.o apps/ec.o apps/ecparam.o apps/enc.o apps/engine.o apps/errstr.o apps/gendsa.o apps/genpkey.o apps/genrsa.o apps/nseq.o apps/ocsp.o apps/openssl.o apps/passwd.o apps/pkcs12.o apps/pkcs7.o apps/pkcs8.o apps/pkey.o apps/pkeyparam.o apps/pkeyutl.o apps/prime.o apps/rand.o apps/rehash.o apps/req.o apps/rsa.o apps/rsautl.o apps/s_client.o apps/s_server.o apps/s_time.o apps/sess_id.o apps/smime.o apps/speed.o apps/spkac.o apps/srp.o apps/storeutl.o apps/ts.o apps/verify.o apps/version.o apps/x509.o \
	 apps/libapps.a -lssl -lcrypto -ldl 

FNAME="bndriver"
pushd test
	${LDCMD:-${CC}} -I.. -I../include -m64 -Wa,--noexecstack -Wall -O0 -g -g3 -L.. -o ${FNAME} ${FNAME}.c -lcrypto -ldl 
popd
	
python3 driver.py  # run driver.py which runs 5 times each of 68 test subjects in two tests
date

