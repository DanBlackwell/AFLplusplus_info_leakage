//
// Created by dan on 11/04/2022.
//

#ifndef AFLPLUSPLUS_LEAKAGE_UTILS_H
#define AFLPLUSPLUS_LEAKAGE_UTILS_H

#include <stdint.h>

void find_public_and_secret_inputs(const char *testcase_buf, uint32_t testcase_len,
                                   uint8_t **public_start_pos, uint32_t *public_len,
                                   uint8_t **secret_start_pos, uint32_t *secret_len);

void create_buffer_from_public_and_secret_inputs(
    const uint8_t *public_input, uint32_t public_input_len,
    const uint8_t *secret_input, uint32_t secret_input_len,
    char **combined_buf, uint32_t *combined_buf_len
);

// Fetch decoded (ie not base64) public input for queue entry [MALLOCs]
void public_input_for_queue_entry(struct queue_entry *q, char **public_input, u32 *public_len);

// Fetch decoded (ie not base64) secret queue entry [MALLOCs]
void secret_input_for_queue_entry(struct queue_entry *q, char **secret_input, u32 *secret_len);

u8 leakage_fuzz_stuff(afl_state_t *afl,
                      u8 *public_in_buf,
                      u32 public_len,
                      u8 *secret_in_buf,
                      u32 secret_len);

u8 leakage_save_if_interesting(afl_state_t *afl,
                               void *combined_buf, u32 combined_len,
                               u8 *public_input_buf, u32 public_len,
                               u8 *secret_input_buf, u32 secret_len,
                               u8 fault);

#define SECRET_BUFS_COUNT 2
struct input_output_hashes {
  u64 public_input_hash;
  u64 secret_input_hash;
  u64 output_hash;

  u8 *public_input_buf;
  u32 public_input_buf_len;

  u8 secret_input_bufs_filled;
  u8 *secret_input_bufs[SECRET_BUFS_COUNT];
  u32 secret_input_buf_len[SECRET_BUFS_COUNT];
};

uint64_t input_hash(const void *input_str_w_len, uint64_t seed0, uint64_t seed1);

int32_t input_compare(const void *a, const void *b, void *udata);

#endif  // AFLPLUSPLUS_LEAKAGE_UTILS_H
