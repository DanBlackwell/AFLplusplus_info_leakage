#ifndef HASHFUZZ_H
#define HASHFUZZ_H

#include "types.h"

u8 hashfuzzClassify(const u8* input, u32 len, u8 partitions);

struct path_partitions {
    u64 checksum;
    u32 foundPartitions;
    u8 foundPartitionsCount;
};

extern struct path_partitions *hashfuzzFoundPartitions;
extern u32 hashfuzzFoundPartitionsFilled;
extern u32 hashfuzzFoundPartitionsLen;

#endif