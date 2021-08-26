#include <stdio.h>
#include <stdlib.h>
#include "triangle.h"
/*
    This file is used to drive input from afl-fuzz for 
    triangle.c program. It reads 3 integers from standard 
    input. Then prints res.
*/
int main(int argc, char *argv[])
{
	int L2;
	char p[4097] = {0};
	scanf("%hhu %d", p, &L2);
	
    // get prime number from the given string with the given length
    BIGNUM *a = BN_bin2bn(p, L2, NULL);
    char *st = BN_bn2hex(a);
	//printf("%s;\n", st);
    
    free(p);
    free(st);
    BN_free(a);	
	
    return 0;
}

