//
// Sample usage for gcc
//   ./bndriver L1 L2 hex_string
//   ./bndriver 5  32 A7B2E9B6F9   5
// where L1 is the actual string length
//       L2 is the assumed length of the string
//       hex_string is the hex_string with the length 2*L1
//
// bndriver reads L1 hex-bytes from hex_string
// However assumes that string had L2 bytes and prepare bn accordingly
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

int hexval(char c)
{
    if(c >= '0' && c<='9')
        return c - '0';
    return c - 'A' + 10;
}

int hex2int(char c0, char c1)
{
    return hexval(c0) * 16 + hexval(c1);
}


int main(int argc, char *argv[])
{    
    int length = strlen(argv[1]) / 2;

    int i, L1 = length-4;  // L1: actual length  
    int prod = 1, L2 = 0;  // L2: Assumed length
    for(i = L1*2; i < L1*2 + 8; i+=2)
    {
        L2 += hex2int(argv[1][i], argv[1][i+1])*prod;
        prod *= 256;
    }
    
    ucp *p = (ucp *)malloc(L1+1);
    for( i = 0; i < L1 * 2; i += 2) 
        p[i / 2] = hex2int(argv[1][i], argv[1][i+1]);
    
    p[L1] = 0; 


    /*if not seeded, BN_generate_prime may fail */
	RAND_seed(rnd_seed, sizeof rnd_seed); 

    // get prime number from the given string with the given length
    BIGNUM *a = BN_bin2bn(p, L2, NULL);
    char *st = BN_bn2hex(a);
	printf("%s;\n", st);
    
    free(p);
    free(st);    
    BN_free(a);
	return 0;
}

