#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <unistd.h>
#include <sys/syscall.h>
#include "../write_wrappers/wrapper.h"

int classifyMyNumber(const uint8_t *data, size_t size) {
    unsigned char classify = 0;
    int retval = 0;
    
    for (int i = 0; i < size; i++) {
        classify ^= data[i];
    }

    if (classify % 64 == 0) {
      if (1 / classify - 128 > 0) 
        retval = 7;
      else
        retval = 12;
    }

    if (classify > 245) {
        retval = 4;
    }

    if (classify < 38) {
        retval = 6;
    }

    return retval;
}

int main(int argc, char *argv[]) {
  if (argc != 4) {
    printError("Usage: %s hashfuzz_partition_1 hashfuzz_partition_2 hashfuzz_partition_3\n", argv[0]);
    return 1;
  }

  initHashfuzz(argc, argv);

  char buf[4096];
  ssize_t len;
  len = read(STDIN_FILENO, buf, 4096);

  printf("class: %d\n", classifyMyNumber(buf, len));

	return 0;
}	
