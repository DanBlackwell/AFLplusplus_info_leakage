#include <stdio.h> 
#include <unistd.h>
#include <limits.h>
#include "triangle.h" 

int isNumStart(char input) {
    return (input >= '1' && input <= '9');
}

int main(int argc, char *argv[])
{
    long long int secret, side2, side3;
    int isMinifiedInput = 1;
    char peek = getchar();
	
    isMinifiedInput &= isNumStart(peek);
    ungetc(peek, stdin);

    isMinifiedInput &= scanf("%lld", &secret);

    isMinifiedInput &= getchar() == ' ' && isNumStart((peek = getchar()));
    ungetc(peek, stdin);
    isMinifiedInput &= scanf("%lld", &side2);

    isMinifiedInput &= getchar() == ' ' && isNumStart((peek = getchar()));
    ungetc(peek, stdin);
    isMinifiedInput &= scanf("%lld", &side3);

    isMinifiedInput &= getchar() == '\n' && getchar() == EOF;

    isMinifiedInput &= (secret > 0 && side2 > 0 && side3 > 0);
    isMinifiedInput &= (secret <= INT_MAX && side2 <= INT_MAX && side3 <= INT_MAX);

    if (!isMinifiedInput) {
	printf("%d %d %d\n", secret, side2, side3);
        return 1;
    }

    if (side2 + side3 <= secret || secret + side2 <= side3 || secret + side3 <= side2) {
	printf("Sides don't form a triangle (longest side longer than other 2 combined)\n");
	return 1;
    }

    printf("%d\n", triangle(secret, side2, side3));

    return 0;
}
