#include <stdio.h>
#include <stdlib.h>
#include "triangle.h"

int isNum(char input) {
	return (input >= '0' && input <= '9') || input == '+' || input == '-';
}

/*
    This file is used to drive input from afl-fuzz for 
    triangle.c program. It reads 3 integers from standard 
    input. Then prints res.
*/
int main(int argc, char *argv[])
{
	int secret, side2, side3;
	char peek;

	peek = getchar();
	if (!isNum(peek))
		return 1;
	ungetc(peek, stdin);

	if (scanf("%d", &secret) != 1)
		return 1;
	if (getchar() != ' ')
		return 1;
	peek = getchar();
	if (!isNum(peek))
		return 1;
	ungetc(peek, stdin);

	if (scanf("%d", &side2) != 1)
		return 1;
	if (getchar() != ' ')
		return 1;
	peek = getchar();
	if (!isNum(peek))
		return 1;
	ungetc(peek, stdin);

	if (scanf("%d", &side3) != 1)
		return 1;
	if (getchar() != '\n' || getchar() != EOF)
		return 1;
	
	if(secret <1 || side2 < 1 || side3 < 1 
	    || !valid(secret,side2,side3)) 
	    return 1;
	
	int res = triangle(secret, side2, side3);
    printf("%d %d %d %d\n", secret, side2, side3, res);

  return 0;
}
