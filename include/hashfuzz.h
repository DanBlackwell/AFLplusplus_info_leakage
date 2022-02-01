#ifndef HASHFUZZ_H
#define HASHFUZZ_H

#include "types.h"
#include "hashmap.h"

s32 path_partitions_compare(const void *a, const void *b, void *udata);
u64 path_partitions_hash(const void *item, u64 seed0, u64 seed1);

u8 hashfuzzClassify(const u8* input, u32 len, u8 partitions);

struct path_partitions {
    u64 checksum;
    u32 foundPartitions;
    u8 foundPartitionsCount;
    struct queue_entry *queue_entries[64];
    float normalised_compression_dist;
};

// extern struct path_partitions *hashfuzzFoundPartitions;
// extern u32 hashfuzzFoundPartitionsFilled;
// extern u32 hashfuzzFoundPartitionsLen;

extern struct hashmap *hashfuzzFoundPartitions;

#endif
