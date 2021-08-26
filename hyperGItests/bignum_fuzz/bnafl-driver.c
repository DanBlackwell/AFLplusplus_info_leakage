//
// Reads from "Data" provided by aflfuzzer.
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
#include <unistd.h>

/*
    This file is used to drive input from afl-fuzz for 
    crypto/bn/bn_lib.c program. 
*/
typedef unsigned char ucp;

int main(int argc, char *argv[])
{
	int Max = 4096;
    uint8_t Data[Max];
	int length = read(STDIN_FILENO, Data, Max);
	
	if(length < 20) 
	    return 0;
	
	int L2=0, Size=length-3;
    int i = Size-1, prod = 1; 
    for( ; i < Size + 2; i++)
    {
        L2 += Data[i] * prod;
        prod *= 256;
    }
    ucp *p = (ucp *)malloc(Size+1);
    for(i=0; i<Size; i++)
        p[i] = Data[i];
    p[Size] = 0;
    
    // get prime number from the given string with the given length
    BIGNUM *a = BN_bin2bn(p, L2, NULL);
    char *st = BN_bn2hex(a);
	//printf("%s;\n", st);
    
    free(p);
    free(st);
    BN_free(a);	
	
    return 0;
}

