//
// Created by dan on 12/04/2022.
//

#include "../include/afl-fuzz.h"
#include "../include/leakage_utils.h"
#include "../include/json.h"

#define PUBLIC_KEY "PUBLIC"
#define SECRET_KEY "SECRET"

/* Parses a testcase_buf to extract pointers and lengths for public and secret
 * segments of the testcase input. public_input and secret_input are malloced */

void find_public_and_secret_inputs(const char *testcase_buf, u32 testcase_len,
                                   uint8_t **public_input, uint32_t *public_len,
                                   uint8_t **secret_input, uint32_t *secret_len) {

  char *raw_public = malloc(testcase_len),
       *raw_secret = malloc(testcase_len);

  const struct json_attr_t json_attrs[] = {
      {PUBLIC_KEY, t_string, .addr.string = raw_public, .len = testcase_len },
      {SECRET_KEY, t_string, .addr.string = raw_secret, .len = testcase_len }
  };

  int err = json_read_object(testcase_buf, json_attrs, NULL);

  if (err) {
    printf("Failed to decode testcase_buf (json error: %s).\n  RAW: %s",
           json_error_string(err), testcase_buf);
    exit(1);
  }

  *public_len = Base64decode_len(raw_public);
  *public_input = malloc(*public_len);
  *public_len = Base64decode(*public_input, raw_public);
  free(raw_public);

  *secret_len = Base64decode_len(raw_secret);
  *secret_input = malloc(*secret_len);
  *secret_len = Base64decode(*secret_input, raw_secret);
  free(raw_secret);
}


void create_buffer_from_public_and_secret_inputs(const uint8_t *public_input, u32 public_input_len,
                                                 const uint8_t *secret_input, u32 secret_input_len,
                                                 char **combined_buf, u32 *combined_buf_len) {

  const char *json_out_template = "{\n  \"" PUBLIC_KEY "\": \"%s\",\n  \"" SECRET_KEY "\": \"%s\"\n}";

  u32 expected_len = strlen(json_out_template) +
                     Base64encode_len((int)public_input_len) +
                     Base64encode_len((int)secret_input_len);

  char *encoded_public = ck_alloc(expected_len);
  Base64encode(encoded_public, public_input, (int)public_input_len);

  char *encoded_secret = ck_alloc(expected_len);
  Base64encode(encoded_secret, secret_input, (int)secret_input_len);

  *combined_buf = ck_alloc(expected_len);
  *combined_buf_len = snprintf(*combined_buf,
                               expected_len,
                               json_out_template,
                               encoded_public,
                               encoded_secret);

  if (*combined_buf_len >= expected_len) {
    FATAL("Would expect the output str to be shorter than %u characters, \nRAW: %s", expected_len, *combined_buf);
  }

  ck_free(encoded_public);
  ck_free(encoded_secret);
}


// HASHMAP FUNCTIONS

uint64_t input_hash(const void *io_hash,
                    __attribute__((unused)) uint64_t seed0,
                    __attribute__((unused)) uint64_t seed1) {
  return ((const struct input_output_hashes *)io_hash)->public_input_hash;
}

int32_t input_compare(const void *a, const void *b, __attribute__((unused)) void *udata) {
  const struct input_output_hashes *io1 = a, *io2 = b;
  return io1->public_input_hash < io2->public_input_hash;
}


/* Adds the new queue entry to the cache. */

inline void leakage_queue_testcase_store_mem(afl_state_t *afl, struct queue_entry *q,
                                     u8 *mem) {

  u32 len = q->len;

  if (unlikely(afl->q_testcase_cache_size + len >=
                   afl->q_testcase_max_cache_size ||
               afl->q_testcase_cache_count >=
                   afl->q_testcase_max_cache_entries - 1)) {

    // no space? will be loaded regularly later.
    return;

  }

  u32 tid;

  if (unlikely(afl->q_testcase_max_cache_count >=
               afl->q_testcase_max_cache_entries)) {

    // uh we were full, so now we have to search from start
    tid = afl->q_testcase_smallest_free;

  } else {

    tid = afl->q_testcase_max_cache_count;

  }

  while (unlikely(afl->q_testcase_cache[tid] != NULL))
    ++tid;

  /* Map the test case into memory. */

  q->testcase_buf = malloc(len);

  if (unlikely(!q->testcase_buf)) {

    PFATAL("Unable to malloc '%s' with len %u", q->fname, len);

  }

  memcpy(q->testcase_buf, mem, len);

  const char *public = "\"PUBLIC\": \"";
  q->public_input_start = strstr(mem, public) + strlen(public);

  const char *secret = "\"SECRET\": \"";
  q->secret_input_start = strstr(mem, secret) + strlen(secret);

  printf("Caching to MEM: secret_input starts at: %p, public at %p, in combined at %p\n",
         q->secret_input_start, q->public_input_start,
         q->testcase_buf);


  /* Register testcase as cached */
  afl->q_testcase_cache[tid] = q;
  afl->q_testcase_cache_size += len;
  ++afl->q_testcase_cache_count;

  if (likely(tid >= afl->q_testcase_max_cache_count)) {

    afl->q_testcase_max_cache_count = tid + 1;

  } else if (unlikely(tid == afl->q_testcase_smallest_free)) {

    afl->q_testcase_smallest_free = tid + 1;

  }

}


/* Check if the result of an execve() during routine fuzzing is interesting,
   save or queue the input test case for further analysis if so. Returns 1 if
   entry is saved, 0 otherwise. */

u8 __attribute__((hot))
leakage_save_if_interesting(afl_state_t *afl,
                            void *combined_buf, u32 combined_len,
                            u8 *public_input_buf, u32 public_len,
                            u8 *secret_input_buf, u32 secret_len,
                            u8 fault) {

  if (unlikely(public_len + secret_len == 0)) { return 0; }

  u8 *queue_fn = "";
  u8  new_bits = '\0';
  s32 fd;
  u8  keeping = 0, res, classified = 0;
  u64 cksum = 0;

  u8 fn[PATH_MAX];

  /* Update path frequency. */

  /* Generating a hash on every input is super expensive. Bad idea and should
     only be used for special schedules */
  if (unlikely(afl->schedule >= FAST && afl->schedule <= RARE)) {

    cksum = hash64(afl->fsrv.trace_bits, afl->fsrv.map_size, HASH_CONST);

    /* Saturated increment */
    if (afl->n_fuzz[cksum % N_FUZZ_SIZE] < 0xFFFFFFFF)
      afl->n_fuzz[cksum % N_FUZZ_SIZE]++;

  }

  u64 input_hash = hash64(public_input_buf, public_len, HASH_CONST);
  struct input_output_hashes sought = { .public_input_hash = input_hash };
  struct input_output_hashes *found = hashmap_get(
      afl->public_input_to_output_map,
      &sought
  );

  u64 output_hash = hash64(afl->fsrv.stdout_raw_buffer,
                           afl->fsrv.stdout_raw_buffer_len,
                           HASH_CONST);

  if (!found) {

    u64 secret_input_hash = hash64(secret_input_buf, secret_len, HASH_CONST);
    sought.secret_input_hash = secret_input_hash;
    sought.output_hash = output_hash;

    hashmap_set(afl->public_input_to_output_map, &sought);
    printf("Added to io_map { L: %llu, H: %llu, OUT: %llu }\n",
           sought.public_input_hash, sought.secret_input_hash, sought.output_hash);

  } else if (found->output_hash != output_hash) {

    u64 secret_input_hash = hash64(secret_input_buf, secret_len, HASH_CONST);
    FATAL("Found a leaking hypertest: { L: %llu, H1: %llu, H2: %llu }\noutput1: %llu, output2: %llu",
          input_hash, found->secret_input_hash, secret_input_hash, output_hash, found->output_hash);

  }

  if (likely(fault == afl->crash_mode)) {

    /* Keep only if there are new bits in the map, add to queue for
       future fuzzing, etc. */

    new_bits = has_new_bits_unclassified(afl, afl->virgin_bits);

    if (likely(!new_bits)) {

      if (unlikely(afl->crash_mode)) { ++afl->total_crashes; }
      return 0;

    }

    classified = new_bits;

#ifndef SIMPLE_FILES

    queue_fn = alloc_printf(
        "%s/queue/id:%06u,%s", afl->out_dir, afl->queued_paths,
        describe_op(afl, new_bits, NAME_MAX - strlen("id:000000,")));

#else

    queue_fn =
        alloc_printf("%s/queue/id_%06u", afl->out_dir, afl->queued_paths);

#endif                                                    /* ^!SIMPLE_FILES */
    fd = open(queue_fn, O_WRONLY | O_CREAT | O_EXCL, DEFAULT_PERMISSION);
    if (unlikely(fd < 0)) { PFATAL("Unable to create '%s'", queue_fn); }
    ck_write(fd, combined_buf, combined_len, queue_fn);
    close(fd);
    add_to_queue(afl, queue_fn, combined_len, 0);
    afl->queue_top->public_input_len = public_len;
    afl->queue_top->secret_input_len = secret_len;

#ifdef INTROSPECTION
    if (afl->custom_mutators_count && afl->current_custom_fuzz) {

      LIST_FOREACH(&afl->custom_mutator_list, struct custom_mutator, {

        if (afl->current_custom_fuzz == el && el->afl_custom_introspection) {

          const char *ptr = el->afl_custom_introspection(el->data);

          if (ptr != NULL && *ptr != 0) {

            fprintf(afl->introspection_file, "QUEUE CUSTOM %s = %s\n", ptr,
                    afl->queue_top->fname);

          }

        }

      });

    } else if (afl->mutation[0] != 0) {

      fprintf(afl->introspection_file, "QUEUE %s = %s\n", afl->mutation,
              afl->queue_top->fname);

    }

#endif

    if (new_bits == 2) {

      afl->queue_top->has_new_cov = 1;
      ++afl->queued_with_cov;

    }

    /* AFLFast schedule? update the new queue entry */
    if (cksum) {

      afl->queue_top->n_fuzz_entry = cksum % N_FUZZ_SIZE;
      afl->n_fuzz[afl->queue_top->n_fuzz_entry] = 1;

    }

    /* due to classify counts we have to recalculate the checksum */
    cksum = afl->queue_top->exec_cksum =
        hash64(afl->fsrv.trace_bits, afl->fsrv.map_size, HASH_CONST);

    /* Try to calibrate inline; this also calls update_bitmap_score() when
       successful. */

    res = calibrate_case(afl, afl->queue_top, combined_buf, afl->queue_cycle - 1, 0);

    if (unlikely(res == FSRV_RUN_ERROR)) {

      FATAL("Unable to execute target application");

    }

    if (likely(afl->q_testcase_max_cache_size)) {

      leakage_queue_testcase_store_mem(afl, afl->queue_top, combined_buf);

    }

    if (afl->fsrv.leakage_hunting && !afl->fsrv.stdout_raw_buffer) {
      FATAL("Leakage hunting enabled, but fsrv has no stdout_raw_buffer allocated");
    }

    afl->queue_top->public_output_buffer = ck_alloc(afl->fsrv.stdout_raw_buffer_len);
    memcpy(afl->queue_top->public_output_buffer, afl->fsrv.stdout_raw_buffer, afl->fsrv.stdout_raw_buffer_len);

    printf("combined_buf: %s\n", (char *)combined_buf);
    printf("public_input: %.*s, secret_input: %.*s\n", public_len, public_input_buf, secret_len, secret_input_buf);
    printf("public output (%u chars): %.*s\n", afl->fsrv.stdout_raw_buffer_len, afl->fsrv.stdout_raw_buffer_len, afl->fsrv.stdout_raw_buffer);

    keeping = 1;

  }

  switch (fault) {

    case FSRV_RUN_TMOUT:

      /* Timeouts are not very interesting, but we're still obliged to keep
         a handful of samples. We use the presence of new bits in the
         hang-specific bitmap as a signal of uniqueness. In "non-instrumented"
         mode, we just keep everything. */

      ++afl->total_tmouts;

      if (afl->unique_hangs >= KEEP_UNIQUE_HANG) { return keeping; }

      if (likely(!afl->non_instrumented_mode)) {

        if (!classified) {

          classify_counts(&afl->fsrv);
          classified = 1;

        }

        simplify_trace(afl, afl->fsrv.trace_bits);

        if (!has_new_bits(afl, afl->virgin_tmout)) { return keeping; }

      }

      ++afl->unique_tmouts;
#ifdef INTROSPECTION
      if (afl->custom_mutators_count && afl->current_custom_fuzz) {

        LIST_FOREACH(&afl->custom_mutator_list, struct custom_mutator, {

          if (afl->current_custom_fuzz == el && el->afl_custom_introspection) {

            const char *ptr = el->afl_custom_introspection(el->data);

            if (ptr != NULL && *ptr != 0) {

              fprintf(afl->introspection_file,
                      "UNIQUE_TIMEOUT CUSTOM %s = %s\n", ptr,
                      afl->queue_top->fname);

            }

          }

        });

      } else if (afl->mutation[0] != 0) {

        fprintf(afl->introspection_file, "UNIQUE_TIMEOUT %s\n", afl->mutation);

      }

#endif

      /* Before saving, we make sure that it's a genuine hang by re-running
         the target with a more generous timeout (unless the default timeout
         is already generous). */

      if (afl->fsrv.exec_tmout < afl->hang_tmout) {

        u8 new_fault;
        write_to_testcase(afl, combined_buf, combined_len);
        new_fault = fuzz_run_target(afl, &afl->fsrv, afl->hang_tmout);
        classify_counts(&afl->fsrv);

        /* A corner case that one user reported bumping into: increasing the
           timeout actually uncovers a crash. Make sure we don't discard it if
           so. */

        if (!afl->stop_soon && new_fault == FSRV_RUN_CRASH) {

          goto keep_as_crash;

        }

        if (afl->stop_soon || new_fault != FSRV_RUN_TMOUT) { return keeping; }

      }

#ifndef SIMPLE_FILES

      snprintf(fn, PATH_MAX, "%s/hangs/id:%06llu,%s", afl->out_dir,
               afl->unique_hangs,
               describe_op(afl, 0, NAME_MAX - strlen("id:000000,")));

#else

      snprintf(fn, PATH_MAX, "%s/hangs/id_%06llu", afl->out_dir,
               afl->unique_hangs);

#endif                                                    /* ^!SIMPLE_FILES */

      ++afl->unique_hangs;

      afl->last_hang_time = get_cur_time();

      break;

    case FSRV_RUN_CRASH:

    keep_as_crash:

      /* This is handled in a manner roughly similar to timeouts,
         except for slightly different limits and no need to re-run test
         cases. */

      ++afl->total_crashes;

      if (afl->unique_crashes >= KEEP_UNIQUE_CRASH) { return keeping; }

      if (likely(!afl->non_instrumented_mode)) {

        if (!classified) { classify_counts(&afl->fsrv); }

        simplify_trace(afl, afl->fsrv.trace_bits);

        if (!has_new_bits(afl, afl->virgin_crash)) { return keeping; }

      }

      if (unlikely(!afl->unique_crashes)) { write_crash_readme(afl); }

#ifndef SIMPLE_FILES

      snprintf(fn, PATH_MAX, "%s/crashes/id:%06llu,sig:%02u,%s", afl->out_dir,
               afl->unique_crashes, afl->fsrv.last_kill_signal,
               describe_op(afl, 0, NAME_MAX - strlen("id:000000,sig:00,")));

#else

      snprintf(fn, PATH_MAX, "%s/crashes/id_%06llu_%02u", afl->out_dir,
               afl->unique_crashes, afl->last_kill_signal);

#endif                                                    /* ^!SIMPLE_FILES */

      ++afl->unique_crashes;
#ifdef INTROSPECTION
      if (afl->custom_mutators_count && afl->current_custom_fuzz) {

        LIST_FOREACH(&afl->custom_mutator_list, struct custom_mutator, {

          if (afl->current_custom_fuzz == el && el->afl_custom_introspection) {

            const char *ptr = el->afl_custom_introspection(el->data);

            if (ptr != NULL && *ptr != 0) {

              fprintf(afl->introspection_file, "UNIQUE_CRASH CUSTOM %s = %s\n",
                      ptr, afl->queue_top->fname);

            }

          }

        });

      } else if (afl->mutation[0] != 0) {

        fprintf(afl->introspection_file, "UNIQUE_CRASH %s\n", afl->mutation);

      }

#endif
      if (unlikely(afl->infoexec)) {

        // if the user wants to be informed on new crashes - do that
#if !TARGET_OS_IPHONE
        // we dont care if system errors, but we dont want a
        // compiler warning either
        // See
        // https://stackoverflow.com/questions/11888594/ignoring-return-values-in-c
        (void)(system(afl->infoexec) + 1);
#else
        WARNF("command execution unsupported");
#endif

      }

      afl->last_crash_time = get_cur_time();
      afl->last_crash_execs = afl->fsrv.total_execs;

      break;

    case FSRV_RUN_ERROR:
      FATAL("Unable to execute target application");

    default:
      return keeping;

  }

  /* If we're here, we apparently want to save the crash or hang
     test case, too. */

  fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, DEFAULT_PERMISSION);
  if (unlikely(fd < 0)) { PFATAL("Unable to create '%s'", fn); }
  ck_write(fd, combined_buf, combined_len, fn);
  close(fd);

  return keeping;

}