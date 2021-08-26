//
// Reads from "Data" array provided by libfuzzer.
//   Data is an array at least 21 and at most 4096 bytes.
//   The last three chars are the assumed length
//   Other characters are the input data to prepare the bignum
//

#ifdef OPENSSL_NO_DEPRECATED
#undef OPENSSL_NO_DEPRECATED
#endif  

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "e_os.h"
#include <openssl/bn.h>
#include <openssl/rand.h>

typedef unsigned char ucp;
static const char rnd_seed[] = "String for random number generator to think it has entropy";

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) 
{
	if (Size < 20 || Size > 4096)
		return 0;
	
    Size -= 3;      // Size of the input
	int L2=0;       // Size assumed 
	int i=Size, prod = 1; 
    for( ; i < Size + 3; i++)
    {
        L2 += Data[i] * prod;
        prod *= 256;
    }
	
	ucp *p = (ucp *)malloc(Size+1);
    for( i = 0; i < Size; i++) 
        p[i] = Data[i];
    
    p[Size] = 0; 

    // if not seeded, BN_generate_prime may fail
	RAND_seed(rnd_seed, sizeof rnd_seed); 

    // get prime number from the given string with the given length
    BIGNUM *a = BN_bin2bn(p, L2, NULL);
    char *st = BN_bn2hex(a);
	//printf("%s;\n", st);
    
    free(p);
    free(st);
    BN_free(a);
	return 0;
}

