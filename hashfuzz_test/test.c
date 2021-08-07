#include <stdio.h>
#include <stdint.h>

int classifyMyNumber(const uint8_t *data, size_t size) {
    int class = 0;
    
    for (int i = 0; i < size; i++) {
        class += data[i];
    }

    if (class % 64 == 0) {
        return 1;
    }

    if (class > 245) {
        return 4;
    }

    if (class < 38) {
        return 6;
    }

    return 2;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  classifyMyNumber(Data, Size);
  return 0;  // Non-zero return values are reserved for future use.
}