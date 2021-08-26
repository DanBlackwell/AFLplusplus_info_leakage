#!/bin/bash

#echo "Compiling..."
FILENAME="heartbeat_simple"
cd ssl
rm -f d1_bot*.g* heartbeat.o d1_both.o ../test/heartbeat_simple.exe

VAR=$(gcc -I../crypto -I.. -I../include -g -O0 -DOPENSSL_THREADS -D_REENTRANT -DDSO_DLFCN -DHAVE_DLFCN_H -Wa,--noexecstack -m64 -DL_ENDIAN -DTERMIO -Wall -DOPENSSL_IA32_SSE2 -DOPENSSL_BN_ASM_MONT -DOPENSSL_BN_ASM_MONT5 -DOPENSSL_BN_ASM_GF2m -DSHA1_ASM -DSHA256_ASM -DSHA512_ASM -DMD5_ASM -DAES_ASM -DVPAES_ASM -DBSAES_ASM -DWHIRLPOOL_ASM -DGHASH_ASM -g -c -o heartbeat.o heartbeat.c 2>&1)

if echo "$VAR" | grep -q "error:"; then
  echo "Error: $VAR"
else
	gcc -I../crypto -I.. -I../include --coverage -g -O0 -fprofile-arcs -ftest-coverage -fprofile-generate -DOPENSSL_THREADS -D_REENTRANT -DDSO_DLFCN -DHAVE_DLFCN_H -Wa,--noexecstack -m64 -DL_ENDIAN -DTERMIO -Wall -DOPENSSL_IA32_SSE2 -DOPENSSL_BN_ASM_MONT -DOPENSSL_BN_ASM_MONT5 -DOPENSSL_BN_ASM_GF2m -DSHA1_ASM -DSHA256_ASM -DSHA512_ASM -DMD5_ASM -DAES_ASM -DVPAES_ASM -DBSAES_ASM -DWHIRLPOOL_ASM -DGHASH_ASM -o d1_both.o -c d1_both.c >out.txt 2>&1

	ar  r ../libssl.a s2_meth.o  s2_srvr.o  s2_clnt.o  s2_lib.o  s2_enc.o s2_pkt.o s3_meth.o  s3_srvr.o  s3_clnt.o  s3_lib.o  s3_enc.o s3_pkt.o s3_both.o s23_meth.o s23_srvr.o s23_clnt.o s23_lib.o s23_pkt.o t1_meth.o   t1_srvr.o t1_clnt.o  t1_lib.o  t1_enc.o d1_meth.o d1_srvr.o d1_clnt.o  d1_lib.o  d1_pkt.o d1_both.o d1_enc.o d1_srtp.o ssl_lib.o ssl_err2.o ssl_cert.o ssl_sess.o ssl_ciph.o ssl_stat.o ssl_rsa.o ssl_asn1.o ssl_txt.o ssl_algs.o bio_ssl.o ssl_err.o kssl.o tls_srp.o t1_reneg.o 
	/usr/bin/ranlib ../libssl.a || echo Never mind.
	if [ -n "" ]; then \
		(cd ..; make libssl.so.1.0.0); \
	fi

	cd ../test

	gcc -g -o leakage.o -c leakage.c -lm
	gcc -I.. -I../include -fprofile-arcs -ftest-coverage -DOPENSSL_THREADS -D_REENTRANT -DDSO_DLFCN -DHAVE_DLFCN_H -Wa,--noexecstack -DL_ENDIAN -DTERMIO -DOPENSSL_IA32_SSE2 -DOPENSSL_BN_ASM_MONT -DOPENSSL_BN_ASM_MONT5 -DOPENSSL_BN_ASM_GF2m -DSHA1_ASM -DSHA256_ASM -DSHA512_ASM -DMD5_ASM -DAES_ASM -DVPAES_ASM -DBSAES_ASM -DWHIRLPOOL_ASM -DGHASH_ASM -g -O0 -c -o ${FILENAME}.o ${FILENAME}.c >> out.txt

	( :; LIBDEPS="${LIBDEPS:--L.. -lssl -L.. -lcrypto  -ldl -lm }"; LDCMD="${LDCMD:-gcc }"; LDFLAGS="${LDFLAGS:--DOPENSSL_THREADS -D_REENTRANT -DDSO_DLFCN -DHAVE_DLFCN_H -Wa,--noexecstack -m64 -DL_ENDIAN -DTERMIO -Wall -DOPENSSL_IA32_SSE2 -DOPENSSL_BN_ASM_MONT -DOPENSSL_BN_ASM_MONT5 -DOPENSSL_BN_ASM_GF2m -DSHA1_ASM -DSHA256_ASM -DSHA512_ASM -DMD5_ASM -DAES_ASM -DVPAES_ASM -DBSAES_ASM -DWHIRLPOOL_ASM -DGHASH_ASM}"; LIBPATH=`for x in $LIBDEPS; do echo $x; done | sed -e 's/^ *-L//;t' -e d | uniq`; LIBPATH=`echo $LIBPATH | sed -e 's/ /:/g'`; LD_LIBRARY_PATH=$LIBPATH:$LD_LIBRARY_PATH ${LDCMD} ${LDFLAGS} -O0 -fprofile-generate leakage.o -o ${FILENAME}.exe ${FILENAME}.o ${LIBDEPS} ) >> out.txt

	./${FILENAME}.exe $1
	sleep 0.2
	cd ../ssl/
	gcov -cd d1_both.info
	rm out.txt ../test/out.txt string_fortified.h.gcov stdio2.h.gcov >/dev/null 2>&1
fi

cd ..

