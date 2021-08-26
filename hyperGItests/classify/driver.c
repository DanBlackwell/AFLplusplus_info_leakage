#include <stdio.h> 
#include "classify.h" 

int isNumStart(char input) {
    return (input >= '0' && input <= '9') || input == '-';
}

int main(int argc, char *argv[])
{
    unsigned char ch;
    unsigned char h;

    int isMinifiedInput = 1;
    char peek = getchar();
	
    isMinifiedInput &= isNumStart(peek);
    ungetc(peek, stdin);

    isMinifiedInput &= scanf("%hhu", &ch);

    isMinifiedInput &= getchar() == ' ' && isNumStart((peek = getchar()));
    ungetc(peek, stdin);
    isMinifiedInput &= scanf("%hhu", &h);

    isMinifiedInput &= getchar() == '\n' && getchar() == EOF;

    if (!isMinifiedInput) {
	printf("Invalid input - expected 2 numbers\n");
        return 1;
    }
	
    int res = classify(ch, h);
    printf("%d ", res);
   
    return 0;
}

