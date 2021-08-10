#ifndef HASHFUZZ_H
#define HASHFUZZ_H

#include "types.h"

u8 hashfuzzClassify(const u8* input, u32 len, u8 partitions);

#endif