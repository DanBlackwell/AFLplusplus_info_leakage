#include <string.h> 
#include <stdio.h>
#include <stdlib.h>
#include "atalk.h"
#include <stddef.h>
#include <unistd.h>
#include <stdint.h>

int char2hex(char c) {
  int result = 0;

  if (c > '9') {
    if (c >= 'a' && c <= 'f')
      result = 10 + c - 'a';
    else if (c >= 'A' && c <= 'F')
      result = 10 + c - 'A';
    else
      return -1;
  } else if (c >= '0') {
    result = c - '0';
  } else {
    return -1;
  }

  return result;
}


int hexToByte(char upper, char lower, uint8_t *result) {
	int upperVal = char2hex(upper);
	int lowerVal = char2hex(lower);
	if (lowerVal == -1 || upperVal == -1)
		return 1;

	*result = (upperVal << 4) | lowerVal;
	return 0;
}

int main (int argc, char *argv[])
{
    // Read data
    const int max = 9 + ALEN;
    uint8_t data[max+1];
    char buf[1024];
    int length = read(STDIN_FILENO, buf, 1024);

    if (length != 2 * max) {
	printf("Expected length 50, but got %d\n", length);
        return 1;
    }

    int invalid = 0;
    for (int i = 0; i < length; i+=2) {
	    invalid |= hexToByte(buf[i], buf[i+1], &data[i/2]);
    }
    if (invalid)
	    return 1;

    atptr sock = (atptr) data;
    atptr uaddr = (atptr) calloc(1, sizeof(struct atalk_sock));
    int peer = data[8+ALEN] % 2;
    int res = atalk_getname(sock, uaddr, peer);
	
    free(uaddr);

    return 0;
}


