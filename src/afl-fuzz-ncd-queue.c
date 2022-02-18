//
// Created by dan on 13/02/2022.
//

#include <stdbool.h>
#include "../include/afl-fuzz-ncd-queue.h"

/* returns bool set to true if the queue is exhausted for this cycle */
bool select_non_favored_queue_entry(afl_state_t *afl) {
  static u64 last_select = 0;
  u64 execs_since_last = afl->fsrv.total_execs - last_select;
  //      printf("Selecting new fuzzing entry: %llu execs\n", execs_since_last);
  last_select = afl->fsrv.total_execs;

  struct edge_entry *best = NULL;
  double             best_rarity = 0.0;
  u8                 least_fuzzed_entries = 255;

  for (u32 i = 0; i < afl->edge_entry_count; i++) {
    struct edge_entry *entry = &afl->edge_entries[i];
    if (!entry->completed_fuzzing_this_cycle && entry->discovery_execs &&
                                                entry->fuzzed_inputs_this_cycle <= least_fuzzed_entries) {
      bool beats_least_fuzzed =
          entry->fuzzed_inputs_this_cycle < least_fuzzed_entries;

      if (beats_least_fuzzed) {
        least_fuzzed_entries = entry->fuzzed_inputs_this_cycle;
      }

      if (execs_since_last) {
        u64 execs_since = afl->fsrv.total_execs - entry->discovery_execs;
        entry->execs_per_hit = (float)execs_since / (float)entry->hit_count;
      }

      if (beats_least_fuzzed || entry->execs_per_hit > best_rarity) {
        best_rarity = entry->execs_per_hit;
        best = entry;
      }
    }
  }

  if (!best) {
    if (afl->queued_discovered == 0) {
      afl->current_entry = 0;
      afl->queue_cur = afl->queue_buf[afl->current_entry];
      afl->queue_cur->fuzzed_this_cycle = true;
    } else {
      for (u32 i = 0; i < afl->queued_paths; i++) {
        if (!afl->queue_buf[i]->fuzzed_this_cycle) {
          printf("Queue entry %u was not fuzzed this cycle\n", i);
        }
      }

      printf("Marking completed\n");
      return true;
    }
  } else {
    if (best->entry_count < 1) {
      PFATAL("Selected edge_entry with no queue_entry's...");
    }

    afl->cur_edge = best;

    u8 unfuzzed_entries = 0;
    for (int i = 0; i < best->entry_count; i++) {
      if (!best->entries[i]->fuzzed_this_cycle) unfuzzed_entries++;
    }

    if (!unfuzzed_entries) {
      FATAL("Picked edge with no unfuzzed entries WTF\n");
    }

    u32 next = rand_below(afl, unfuzzed_entries);
    for (int i = 0; i < best->entry_count; i++) {
      if (!best->entries[i]->fuzzed_this_cycle) {
        if (!next) {
          afl->queue_cur = best->entries[i];
          best->entries[i]->fuzzed_this_cycle = true;
          best->fuzzed_inputs_this_cycle++;
          // If this was the last unfuzzed_entry then mark completed
          best->completed_fuzzing_this_cycle = (unfuzzed_entries == 1);
          //                printf("Selected edge %u with rarity: %f, entry: %d for fuzzing\n", best_pos, best_rarity, i);
          break;
        }
        next--;
      }
    }
  }

  bool found_in_queue = false;
  for (u32 j = 0; j < afl->queued_paths; j++) {
    if (afl->queue_buf[j] == afl->queue_cur) {
      afl->current_entry = j;
      found_in_queue = true;
      break;
    }
  }

  if (!found_in_queue) {
    PFATAL("Failed to find entry %s in queue\n", afl->queue_cur->fname);
  }

  return false;
}

bool select_favored_queue_entry(afl_state_t *afl) {
  u32 to_fetch = rand_below(afl, afl->pending_favored);

  for (u32 edgeNum = 0; edgeNum < afl->edge_entry_count; edgeNum++) {
    struct edge_entry *edge = &afl->edge_entries[edgeNum];

    for (u32 entryNum = 0; entryNum < edge->entry_count; entryNum++) {
      struct queue_entry *entry = edge->entries[entryNum];

      if (entry->favored && !entry->fuzzed_this_cycle) {
        if (to_fetch == 0) {
          afl->queue_cur = entry;
          entry->fuzzed_this_cycle = true;

          edge->fuzzed_inputs_this_cycle++;
          if (edge->fuzzed_inputs_this_cycle == edge->entry_count) {
            edge->completed_fuzzing_this_cycle = true;
          }

          bool found = false;
          for (u32 i = 0; i < afl->queued_paths; i++) {
            if (afl->queue_buf[i] == entry) {
              afl->current_entry = i;
              found = true;
              break;
            }
          }

          if (!found) { FATAL("Failed to find favored entry in queue"); }

          printf("Fuzzing favored entry: %u belonging to edge %u\n",
                 afl->current_entry, edgeNum);

          return true;
        }

        to_fetch--;
      }
    }
  }

  return false;
}