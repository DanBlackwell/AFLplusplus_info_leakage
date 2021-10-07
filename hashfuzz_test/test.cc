#include <stdio.h>
#include <stdint.h>

int classifyMyNumber(const uint8_t *data, size_t size) {
    unsigned char classify = 0;
    int retval = 0;
    
    for (int i = 0; i < size; i++) {
        classify ^= data[i];
    }

    if (classify % 64 == 0) {
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
	return 0;
}	

// extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
//   classifyMyNumber(Data, Size);
//   return 0;  // Non-zero return values are reserved for future use.
// }
