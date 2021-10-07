#include "types.h"
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <time.h>
#include <math.h>

struct path_partitions *hashfuzzFoundPartitions;
u32 hashfuzzFoundPartitionsFilled = 0;
u32 hashfuzzFoundPartitionsLen;

int findParity(int x) {
  int y = x ^ (x >> 1);
  y = y ^ (y >> 2);
  y = y ^ (y >> 4);
  y = y ^ (y >> 8);
  y = y ^ (y >> 16);

  return y & 1;
}

int isPowerOfTwo(int x) {
    return (!(x & (x - 1)) && x);
}

u8 hashfuzzClassify(const u8* input, u32 len, u8 partitions) {
    static u8 partitionBoundaries[8];
    static u8 initialised = 0;
    static u8 sampled[256];

    assert(partitions <= 64);

    // No need to classify if there's only one partition
    if (partitions < 2) {
        return 0;
    }

    // partitions should be a power of 2
    assert(isPowerOfTwo(partitions));

    int boundariesNeeded = 1;
    while(1) {
        if (1 << boundariesNeeded == partitions) 
            break;
        boundariesNeeded++;
    }

    if (boundariesNeeded > initialised) {
        if (!initialised) {
            time_t t;
            srand((unsigned) time(&t));
        }

        for (int i = initialised; i < boundariesNeeded; i++) {
            int randPos = rand() % (256 - initialised);
            int index = 0;

            while (1) {
                if (!sampled[index]) {
                    if (!randPos) {
                        sampled[index] = 1;
                        partitionBoundaries[initialised] = index;
                        break;
                    }

                    randPos--;

                }
                
                index++;

            }

            initialised++;
        }
    }

    u8 hashes[8] = {0};
    for (u32 i = 0; i < len; i++) {        
        for (int j = 0; j < boundariesNeeded; j++) {
            hashes[j] = (hashes[j] + findParity(partitionBoundaries[j] & input[i])) % 2;
        }
    }

    int class = 0;
    for (int i = 0; i < boundariesNeeded; i++) {
        class |= hashes[i] << i;
    }

    return class;
}

// int main(void) {
//     #define PARTITIONS 32
//     u32 count[PARTITIONS] = {};

//     for (int i = 0; i < PARTITIONS * 1000; i++) {
//         u8 val[4] = {rand(), rand(), rand(), rand()};
//         int class = hashfuzzClassify(val, sizeof(val), PARTITIONS);
//         count[class]++;
//         // printf("classifying %u: %d\n", val, class);
//     }

//     printf("classes: { %d", count[0]);
//     for (int i = 1; i < PARTITIONS; i++) {
//         printf(", %d", count[i]);
//     } 
//     printf("}\n");
// }