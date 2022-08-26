#ifndef DECODE_INPUTS
#define DECODE_INPUTS

int find_public_and_secret_inputs(const char *testcase_buf, uint32_t testcase_len,
                                  uint8_t **public_start_pos, uint32_t *public_len,
                                  uint8_t **secret_start_pos, uint32_t *secret_len);

#endif
