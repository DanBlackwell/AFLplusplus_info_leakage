//
// Created by dan on 13/02/2022.
//

#ifndef AFLPLUSPLUS_AFL_FUZZ_NCD_QUEUE_H
#define AFLPLUSPLUS_AFL_FUZZ_NCD_QUEUE_H

#include "afl-fuzz.h"

bool select_non_favored_queue_entry(afl_state_t *afl);
bool select_favored_queue_entry(afl_state_t *afl);


#endif  // AFLPLUSPLUS_AFL_FUZZ_NCD_QUEUE_H
