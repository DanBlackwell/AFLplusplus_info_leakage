//
// Created by dan on 11/04/2022.
//

#ifndef AFLPLUSPLUS_LEAKAGE_UTILS_H
#define AFLPLUSPLUS_LEAKAGE_UTILS_H

#include <stdint.h>

int find_public_and_secret_inputs(const char *testcase_buf,
                                  uint8_t **public_start_pos, uint32_t *public_len,
                                  uint8_t **secret_start_pos, uint32_t *secret_len);

void create_buffer_from_public_and_secret_inputs(const uint8_t *public_input, uint32_t public_input_len,
                                                 const uint8_t *secret_input, uint32_t secret_input_len,
                                                 char **combined_buf, uint32_t *combined_buf_len);

#endif  // AFLPLUSPLUS_LEAKAGE_UTILS_H
