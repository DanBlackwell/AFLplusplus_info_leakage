/*
    driver.cpp is used by build.sh and coverage.sh. it is the driver file 
    for underflow.c. It receives pairs of h and ppos values from input stream
    list. Then for each pair, it calls underflow function and prints 
    the output from the function call.
    Sample Usage
        ./executable_name 3 100 5 1200 ...
    Sample Output
        0 5
*/
#include <string.h>
#include <math.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <stddef.h>
#include "underflow.h"

int isNumStart(char input) {
    return (input >= '0' && input <= '9') || input == '-';
}

int main(int argc, char *argv[])
{
    int h; ll ppos;

    int isMinifiedInput = 1;
    char peek = getchar();
	
    isMinifiedInput &= isNumStart(peek);
    ungetc(peek, stdin);

    isMinifiedInput &= scanf("%d", &h);

    isMinifiedInput &= getchar() == ' ' && isNumStart((peek = getchar()));
    ungetc(peek, stdin);
    isMinifiedInput &= scanf("%lld", &ppos);

    isMinifiedInput &= getchar() == '\n' && getchar() == EOF;

    if (!isMinifiedInput) {
	printf("Invalid input - expected 2 numbers\n");
        return 1;
    }

    int res = underflow(h, ppos);
    printf("%d\n", res);
    
    return 0;
}
