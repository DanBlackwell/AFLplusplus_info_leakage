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

  char *raw_public = NULL, *raw_secret = NULL;

  json_char *json = (json_char *)testcase_buf;
  json_value *value = json_parse(json, testcase_len);

  switch (value->type) {
    case json_object: {
      u32 len = value->u.object.length;

      for (u32 i = 0; i < len; i++) {

        char *name = value->u.object.values[i].name;
        // printf("found name %s\n", name);

        json_type type = value->u.object.values[i].value->type;
        if (type != json_string) {
          printf("Saw json field %s that was not a string (type: %d)\n", name, type);
          continue;
        }

        char *str = value->u.object.values[i].value->u.string.ptr;
        u32 length = value->u.object.values[i].value->u.string.length;

        if (!strcmp(name, PUBLIC_KEY)) {
          raw_public = str;
        } else if (!strcmp(name, SECRET_KEY)) {
          raw_secret = str;
        } else {
          printf("saw json string { \"%s\": \"%.*s\" }\n", name, length, str);
        }

      }
      break;
    }
    default:
      FATAL("JSON: %*.s was not a json-object", testcase_len, testcase_buf);
  }

  if (!raw_public) {
    FATAL("Failed to find PUBLIC in json: %.*s\n", testcase_len, testcase_buf);
  }

  if (!raw_secret) {
    FATAL("Failed to find SECRET in json: %.*s\n", testcase_len, testcase_buf);
  }

  *public_len = Base64decode_len(raw_public);
  *public_input = malloc(*public_len);
  *public_len = Base64decode((char *)*public_input, raw_public);

  *secret_len = Base64decode_len(raw_secret);
  *secret_input = malloc(*secret_len);
  *secret_len = Base64decode((char *)*secret_input, raw_secret);

  json_value_free(value);
}

void locate_public_and_secret_inputs(struct queue_entry *q) {
  if (!q->testcase_buf) {
    FATAL("testcase_buf is NULL");
  }

  const char *public = "\"PUBLIC\": \"";
  q->public_input_start = strstr((char *)q->testcase_buf, public) + strlen(public);
  for (u32 i = 0; i < q->len - (q->public_input_start - q->testcase_buf); i++) {
    if (q->public_input_start[i] == '\"') {
      q->public_input_len = i;
      break;
    }
  }

  const char *secret = "\"SECRET\": \"";
  q->secret_input_start = strstr((char *)q->testcase_buf, secret) + strlen(secret);
  for (u32 i = 0; i < q->len - (q->secret_input_start - q->testcase_buf); i++) {
    if (q->secret_input_start[i] == '\"') {
      q->secret_input_len = i;
      break;
    }
  }

//  printf("Locating public and secret inputs in %.*s: secret_input: %.*s, public_input: %.*s\n",
//         q->len, q->testcase_buf, q->secret_input_len, q->secret_input_start,
//         q->public_input_len, q->public_input_start);

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
    FATAL("Would expect the output str to be shorter than %u characters, was %u chars\nRAW: %s", expected_len, *combined_buf_len, *combined_buf);
  }

  ck_free(encoded_public);
  ck_free(encoded_secret);
}

void public_input_for_queue_entry(struct queue_entry *q, char **public_input, u32 *public_len) {
  if (!q->testcase_buf) {
    FATAL("testcase_buf not loaded for queue_entry!");
  }

  if (!q->public_input_start || !q->secret_input_start) {
    locate_public_and_secret_inputs(q);
  }

  char tmp = q->public_input_start[q->public_input_len];
  q->public_input_start[q->public_input_len] = 0;
  *public_len = Base64decode_len((char *)q->public_input_start);
  *public_input = ck_alloc(*public_len);
  Base64decode(*public_input, (char *)q->public_input_start);
  q->public_input_start[q->public_input_len] = tmp;
}

void secret_input_for_queue_entry(struct queue_entry *q, char **secret_input, u32 *secret_len) {
  if (!q->testcase_buf) {
    FATAL("testcase_buf not loaded for queue_entry!");
  }

  if (!q->public_input_start || !q->secret_input_start) {
    FATAL("public_input_start: %p, secret_input_start: %p", q->public_input_start, q->secret_input_start);
  }

  char tmp = q->secret_input_start[q->secret_input_len];
  q->secret_input_start[q->secret_input_len] = 0;
  *secret_len = Base64decode_len((char *)q->secret_input_start);
  *secret_input = ck_alloc(*secret_len);
  Base64decode(*secret_input, (char *)q->secret_input_start);
  q->secret_input_start[q->secret_input_len] = tmp;
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

static inline void leakage_queue_testcase_store_mem(afl_state_t *afl, struct queue_entry *q,
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

  locate_public_and_secret_inputs(q);

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

u8 check_for_instability(afl_state_t *afl, const u8 *in_buf, u32 in_len, const u8 *expected_out_buf, const u32 expected_out_len) {
  static u8 *expected_out_buf_copy = NULL;
  static u32 expected_out_len_copy = 0;

  if (expected_out_len > expected_out_len_copy) {
    expected_out_buf_copy = ck_realloc(expected_out_buf_copy, expected_out_len);
  }
  expected_out_len_copy = expected_out_len;
  memcpy(expected_out_buf_copy, expected_out_buf, expected_out_len);

  for (int i = 0; i < 100; i++) {
    write_to_testcase(afl, (void *)in_buf, in_len);
    u8 fault = fuzz_run_target(afl, &afl->fsrv, afl->fsrv.exec_tmout);
    if (fault) {
      printf("Discarding potential leaky input as it gave a fault\n");
      return 1;
    }

    if (afl->fsrv.stdout_raw_buffer_len != expected_out_len ||
        memcmp(afl->fsrv.stdout_raw_buffer, expected_out_buf_copy, expected_out_len)) {
      printf("Discarding potential leaky input as it did not produce a consistent output\n");

      printf("First run output (%d bytes): [", expected_out_len);
      for (u32 i = 0; i < expected_out_len; i++)
        printf("%hhu, ", expected_out_buf_copy[i]);
      printf("\b\b]\n");

      printf("Repeat %d run output (%d bytes): [", i, afl->fsrv.stdout_raw_buffer_len);
      for (u32 i = 0; i < afl->fsrv.stdout_raw_buffer_len; i++)
        printf("%hhu, ", afl->fsrv.stdout_raw_buffer[i]);
      printf("\b\b]\n");


      return 1;
    }
  }

  return 0;
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
    sought.output_hashes[0] = output_hash;

//    {
//      u32   len = afl->fsrv.stdout_raw_buffer_len;
//      char *tmp = malloc(len * 2);
//      u32   tmp_len = 0;
//      for (u32 i = 0; i < len; i++, tmp_len++) {
//        if (afl->fsrv.stdout_raw_buffer[i] == '\n') {
//          tmp[tmp_len++] = '\\';
//          tmp[tmp_len] = 'n';
//        } else {
//          tmp[tmp_len] = afl->fsrv.stdout_raw_buffer[i];
//        }
//      }
//
//      printf("Adding to io_map: { L: %.*s, H: %.*s, O: \"%.*s\" }\n",
//             public_len, public_input_buf, secret_len, secret_input_buf,
//             tmp_len, tmp);
//      free(tmp);
//    }

    hashmap_set(afl->public_input_to_output_map, &sought);
//    printf("Added to io_map { L: %llu, H: %llu, OUT: %llu }\n",
//           sought.public_input_hash, sought.secret_input_hash, sought.output_hash);

  } else {

    if (output_hash == found->output_hashes[0]) {
      goto skip_leak_check;
    }

    for (int i = 0; i < found->secret_input_bufs_filled; i++) {
      if (secret_len == found->secret_input_buf_len[i] &&
          !memcmp(secret_input_buf, found->secret_input_bufs[i], secret_len))
      {
        //printf("We already have this secret input buf in our list - discard it\n");
        goto skip_leak_check;
      } else if (output_hash == found->output_hashes[i]) {
        goto skip_leak_check;
      }
    }

    if (found->secret_input_bufs_filled >= SECRET_BUFS_COUNT) {
      goto skip_leak_check;
    }

    u8 unstable = check_for_instability(afl, combined_buf, combined_len,
                                        afl->fsrv.stdout_raw_buffer,
                                        afl->fsrv.stdout_raw_buffer_len);

    if (unstable) goto skip_leak_check;

    if (!found->public_input_buf) {
      // Store a copy of the public input
      found->public_input_buf_len = public_len;
      found->public_input_buf = ck_alloc(public_len);
      memcpy(found->public_input_buf, public_input_buf, public_len);
    }

    // Store a copy of the secret input
    u32 pos = found->secret_input_bufs_filled;
    found->secret_input_buf_len[pos] = secret_len;
    found->secret_input_bufs[pos] = ck_alloc(secret_len);
    memcpy(found->secret_input_bufs[pos], secret_input_buf, secret_len);
    found->output_hashes[pos] = output_hash;
    found->secret_input_bufs_filled++;

    if (found->secret_input_bufs_filled <= 1) {
      afl->detected_leaks_count++;
    } else {
      char buf[280];
      snprintf(buf, 280, "%s/leaks", afl->out_dir);

      if (!afl->stored_hypertest_leaks_count) {
        DIR *leaks_dir = opendir(buf);

        if (leaks_dir) {
          if (delete_files((u8 *)buf, (u8 *)"leak")) {
            FATAL("Failed to delete files in %s", buf);
          }
        }

        if (mkdir(buf, 0777)) { FATAL("Failed to create dir %s", buf); }

        leaks_dir = opendir(buf);
        if (!leaks_dir) { FATAL("Failed to open dir %s after mkdir??", buf); }

        closedir(leaks_dir);
      }

      afl->stored_hypertest_leaks_count++;

      char *leak_input = (char *)alloc_printf(
          "%s/leak_id:%06u,input_1", buf, afl->stored_hypertest_leaks_count);
      printf("storing to %s\n", leak_input);
      fd = open(leak_input, O_WRONLY | O_CREAT | O_EXCL, DEFAULT_PERMISSION);
      if (unlikely(fd < 0)) { PFATAL("Unable to create '%s'", leak_input); }

      char *comb_buf;
      u32   comb_len;
      create_buffer_from_public_and_secret_inputs(
          found->public_input_buf, found->public_input_buf_len,
          found->secret_input_bufs[0], found->secret_input_buf_len[0],
          &comb_buf, &comb_len);
      ck_write(fd, comb_buf, comb_len, leak_input);
      close(fd);
      ck_free(comb_buf);

      leak_input = (char *)alloc_printf("%s/leak_id:%06u,input_2", buf,
                                        afl->stored_hypertest_leaks_count);
      printf("storing to %s\n", leak_input);
      fd = open(leak_input, O_WRONLY | O_CREAT | O_EXCL, DEFAULT_PERMISSION);
      if (unlikely(fd < 0)) { PFATAL("Unable to create '%s'", leak_input); }

      create_buffer_from_public_and_secret_inputs(
          found->public_input_buf, found->public_input_buf_len,
          found->secret_input_bufs[1], found->secret_input_buf_len[1],
          &comb_buf, &comb_len);
      ck_write(fd, comb_buf, comb_len, leak_input);
      close(fd);
      ck_free(comb_buf);
    }
  }

skip_leak_check:

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

    afl->queue_top->public_output_bufer_len = afl->fsrv.stdout_raw_buffer_len;
    afl->queue_top->public_output_buffer = ck_alloc(afl->fsrv.stdout_raw_buffer_len);
    memcpy(afl->queue_top->public_output_buffer, afl->fsrv.stdout_raw_buffer, afl->fsrv.stdout_raw_buffer_len);

//    printf("json_combined_buf: %s\n", (char *)combined_buf);
//    printf("public_input: %.*s, secret_input: %.*s\n", public_len, public_input_buf, secret_len, secret_input_buf);
//    printf("public output (%u chars): %.*s\n", afl->fsrv.stdout_raw_buffer_len, afl->fsrv.stdout_raw_buffer_len, afl->fsrv.stdout_raw_buffer);

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
