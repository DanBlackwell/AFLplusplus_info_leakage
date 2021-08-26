//
// Sample usage for gcc
//   ./bntemp 16 < input.txt
// run bntemp reading 16 bytes from input.txt
// 

#ifdef OPENSSL_NO_DEPRECATED
#undef OPENSSL_NO_DEPRECATED
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "e_os.h"
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/x509.h>

static const char rnd_seed[] = "String for random number generator think it has entropy";

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t size) 
{
	if(size < 10) 
		return 0;

	uint8_t *p = (uint8_t *)malloc(size -3);
	int i = 0;
	for( ; i < size-4; i++)
		p[i] = Data[i];
	p[size-4] = 0;
    int bnval = (int)&(Data[size-4]);
    int bnlen = bnval % 65536;

    /*BN_generate_prime may fail, if not seeded */
	RAND_seed(rnd_seed, sizeof rnd_seed); 
	
	BIGNUM *a = BN_bin2bn(p, bnlen, NULL);
	printf("%s\n", BN_bn2hex(a));
    
    BN_free(a);
	return 0;
}


