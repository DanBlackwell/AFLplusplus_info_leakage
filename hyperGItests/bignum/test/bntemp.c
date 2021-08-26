//
// Sample usage for gcc
//   ./bntemp2 L1 L2 hex_string
// where L1 is the actual string length
//       L2 is the assumed length of the string
//       hex_string is the hex_string with the length 2*L1
//
// run bntemp2 reading L1 hex bytes from hex_string
// However assume that string had L2 bytes and prepare bn accordingly
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

typedef unsigned char ucp;
static const char rnd_seed[] = "String for random number generator to think it has entropy";

int hexval(unsigned char c)
{
    if(c >= '0' && c<='9')
        return c - '0';
    return c - 'A' + 10;
}

int hex2int(unsigned char c0, unsigned char c1)
{
    return hexval(c0) * 16 + hexval(c1);
}

int main(int argc, char *argv[])
{
	if(argc < 4)
	    return 0;
    
    int i, L1 = atoi(argv[1]);  // actual length
    int L2 = atoi(argv[2]);     // Assumed length

    ucp *p = (ucp *)malloc(L1+1);
    for( i = 0; i < L1*2; i+=2)
        p[i/2] = hex2int(argv[3][i], argv[3][i+1]);
    p[L1] = 0; 

    /*if not seeded, BN_generate_prime may fail */
	RAND_seed(rnd_seed, sizeof rnd_seed); 

    // get prime number from the given string with the given length
    BIGNUM *a = BN_bin2bn(p, L2, NULL);
	printf("%s;;;\n", BN_bn2hex(a));
    
    BN_free(a);
	return 0;
}


