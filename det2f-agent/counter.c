#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include "common.h"
#include "counter.h"
#include "u2f.h"

#define KEY_LEN 15                  // in bytes
#define VAL_LEN 5                   // in bytes
#define KEY_VAL_WORDS 5             // in words
#define ENTRY_TYPE_MASK_UINT32 0x3 << TYPE_SHIFT_AMT_UINT32
#define ENTRY_TYPE_MASK_UINT16 0x3 << TYPE_SHIFT_AMT_UINT16
#define ENTRY_TYPE_MASK_UINT8 0x3 << TYPE_SHIFT_AMT_UINT8
#define KEY_TYPE 0                  // in binary 00
#define INDEX_TYPE 2                // in binary 10
#define TYPE_SHIFT_AMT_UINT32 30    // in bits
#define TYPE_SHIFT_AMT_UINT16 14    // in bits
#define TYPE_SHIFT_AMT_UINT8 6      // in bits
#define ENTRY_SHIFT_AMT 2           // in bits
#define ENTRY_KEY_MASK_UINT32 0xffffffff >> 2
#define ENTRY_KEY_MASK_UINT16 0xffff >> 2
#define KEY_LOG_FMT_LEN 16          // in bytes
#define KEY_LOG_FMT_WORDS 4         // in words
#define INDEX_LOG_FMT_LEN 2         // in bytes
#define END_OF_LOG 0xffffffff
#define CTR_VAL_LEN 40              // in bytes


/*
 * A new log-based set of LRU counters using 3 pages: 2 data pages and 1 log.
 *
 * Each data page has 1 word at the beginning with a serial number. The page
 * with the higher serial number is valid. The data page contains a table of
 * keys (hashes of IDs, 120 bits) and values (40 bits) where each key-value pair
 * is 5 bytes and there are 100 pairs in the table. There is also a single
 * overflow counter.
 *
 * To increment the counter, append the encoded key to the log or, if the key is
 * present in the table, the encoded index. Keys and indexes are encoded at the
 * word boundary such that the type is discernible and there is a valid bit (set
 * to 0 when written to) so that we can check if the log is corrupted.
 *
 * To lookup a value, first lookup the key in the table. If it is not present,
 * use the value of the overflow counter. Then walk through the log,
 * incrementing the value each time you pass a matching key or index. This is
 * the corresponding counter value.
 *
 * Garbage collection is triggered when the log is full or corrupted (a word is
 * not correctly encoded). For each key in the log, we count the number of times
 * that the key is appended. The 100 most accessed keys are guaranteed to be in
 * the next version of the table. For all the most accessed keys not in the old
 * table, we evict old keys that were not in the 100 most accessed. For each key
 * in the new table, we look up the corresponding value and write the key-value
 * pairs to a table on the currently invalid page (page with the lower serial
 * number). We then take the max of the current overflow counter and all the
 * evicted counter values and set that as the new current overflow counter. We
 * increment the serial number to set the new table to be valid, and then erase
 * the log.
 */

struct counter {
  uint32_t *LOG;
  uint32_t *DATA_1;
  uint32_t *DATA_2;
  int NUM_COUNTERS;
  int PAGE_WORDS;
  int OVERFLOW_CTR_INDEX;
};

LRUCounter LRUCounter_new(int num_counters, int page_words) {
  int rv;
  LRUCounter c = NULL;
  CHECK_A(c = (LRUCounter)malloc(sizeof(counter)));
  c->PAGE_WORDS = page_words;
  c->NUM_COUNTERS = num_counters;
  c->OVERFLOW_CTR_INDEX = c->NUM_COUNTERS;
  CHECK_A(c->LOG = (uint32_t *)malloc(c->PAGE_WORDS * sizeof(uint32_t)));
  CHECK_A(c->DATA_1 = (uint32_t *)malloc(c->PAGE_WORDS * sizeof(uint32_t)));
  CHECK_A(c->DATA_2 = (uint32_t *)malloc(c->PAGE_WORDS * sizeof(uint32_t)));
  memset(c->LOG, 0xff, c->PAGE_WORDS * sizeof(uint32_t));
  memset(c->DATA_1, 0xff, c->PAGE_WORDS * sizeof(uint32_t));
  memset(c->DATA_2, 0xff, c->PAGE_WORDS * sizeof(uint32_t));
cleanup:
  if (rv == ERROR) {
    LRUCounter_free(c);
    return NULL;
  }
  return c;
}

// TODO: error checking
void LRUCounter_write_to_storage(LRUCounter c, const char *path) {
  FILE *f = fopen(path, "w");
  fwrite(c->LOG, c->PAGE_WORDS, 1, f);
  fwrite(c->DATA_1, c->PAGE_WORDS, 1, f);
  fwrite(c->DATA_2, c->PAGE_WORDS, 1, f);
  fclose(f);
}

int LRUCounter_read_from_storage(LRUCounter c, const char *path) {
  int rv;
  FILE *f = NULL;
  CHECK_A (f = fopen(path, "r"));
  CHECK_C(fread(c->LOG, c->PAGE_WORDS, 1, f) == 1);
  CHECK_C(fread(c->DATA_1, c->PAGE_WORDS, 1, f) == 1);
  CHECK_C(fread(c->DATA_2, c->PAGE_WORDS, 1, f) == 1);
cleanup:
  if (f) fclose(f);
  return rv;
}

void LRUCounter_free(LRUCounter c) {
  if (!c) return;
  if (c->LOG) free(c->LOG);
  if (c->DATA_1) free(c->DATA_1);
  if (c->DATA_2) free(c->DATA_2);
  free(c);
}

static void _write(uint32_t *p, size_t o, uint32_t v) {
  p[o] = v;
}

static void _erase(LRUCounter c, void *p) {
  memset(p, 0xff, c->PAGE_WORDS * sizeof(uint32_t));
}

/*
static void print_key(const char *tag, const uint8_t *key) {
  int i;
  fprintf(stderr, "%s: ", tag);
  for (i = 0; i < KEY_LEN; i++) {
    fprintf(stderr, "0x%02x ", key[i]);
  }
  fprintf(stderr, "\n");
}*/


/* Encodes a key of length KEY_LEN in KEY_LOG_FMT_WORDS where each word is
 * prefixed with KEY_TYPE. */
static void convert_key_to_log_fmt(const uint8_t *key,
                                            uint32_t *logged_key) {
  uint32_t tmp_key[KEY_LOG_FMT_WORDS];
  uint32_t base, remaining;
  memcpy(tmp_key, key, KEY_LEN);
  base = KEY_TYPE << TYPE_SHIFT_AMT_UINT32;
  logged_key[0] = base + (tmp_key[0] & ENTRY_KEY_MASK_UINT32);
  remaining = tmp_key[0] >> TYPE_SHIFT_AMT_UINT32;
  logged_key[1] = ((tmp_key[1] << (2 * ENTRY_SHIFT_AMT)) >> ENTRY_SHIFT_AMT) +
      base + remaining;
  remaining = tmp_key[1] >> (TYPE_SHIFT_AMT_UINT32 - ENTRY_SHIFT_AMT);
  logged_key[2] = ((tmp_key[2] << (3 * ENTRY_SHIFT_AMT)) >> ENTRY_SHIFT_AMT) +
      base + remaining;
  remaining = tmp_key[2]  >> (TYPE_SHIFT_AMT_UINT32 - (2 * ENTRY_SHIFT_AMT));
  logged_key[3] = ((tmp_key[3] << (4 * ENTRY_SHIFT_AMT)) >> ENTRY_SHIFT_AMT) +
      base + remaining;
}

/* Decode a logged key of length KEY_LOG_FMT_WORDS to a key of length KEY_LEN.
 * Removes prefix of KEY_TYPE before each word. */
static void convert_key_from_log_fmt(const uint32_t *logged_key,
                                              uint8_t *key) {
  uint32_t tmp_key[KEY_LOG_FMT_WORDS];
  uint32_t remaining;
  tmp_key[0] = (logged_key[0] & ENTRY_KEY_MASK_UINT32) +
      (logged_key[1] << TYPE_SHIFT_AMT_UINT32);
  remaining = (logged_key[1] & ENTRY_KEY_MASK_UINT32) >> ENTRY_SHIFT_AMT;
  tmp_key[1] = remaining +
      (logged_key[2] << (TYPE_SHIFT_AMT_UINT32 - ENTRY_SHIFT_AMT));
  remaining = ((logged_key[2] & ENTRY_KEY_MASK_UINT32) >> (2 * ENTRY_SHIFT_AMT));
  tmp_key[2] = remaining +
      (logged_key[3] << (TYPE_SHIFT_AMT_UINT32 - (2 * ENTRY_SHIFT_AMT)));
  tmp_key[3] = ((logged_key[3]) & ENTRY_KEY_MASK_UINT32) >> (3 * ENTRY_SHIFT_AMT);
  memcpy(key, tmp_key, KEY_LEN);
}

/* Encodes an index in INDEX_LOG_FMT_LEN bytes where the index is prefixed with
 * INDEX_TYPE. */
static void convert_index_to_log_fmt(int key_index,
                                              uint8_t *logged_index) {
  logged_index[0] = key_index;
  logged_index[1] = INDEX_TYPE << TYPE_SHIFT_AMT_UINT8;
}

static int convert_index_from_log_fmt(uint8_t *logged_index) {
  return logged_index[0];
}

/* Append a raw key value (not encoded) to the log at start_index. start_index
 * is in bytes, and must be a valid log index (have at least KEY_LOG_FMT_WORDS
 * before end of the page). */
static void write_full_key(LRUCounter c, const uint8_t *key, size_t start_index) {
  size_t start_index_words;
  uint32_t logged_key[KEY_LOG_FMT_WORDS];
  int i;
  if (start_index % sizeof(uint32_t) == 2) {
    /* Keys must be word-aligned, so might need to skip over 2 bytes. */
    start_index += 2;
  }
  start_index_words = start_index % sizeof(uint32_t) == 0 ?
      start_index / sizeof(uint32_t) : (start_index / sizeof(uint32_t)) + 1;
  convert_key_to_log_fmt(key, logged_key);
  for (i = 0; i < KEY_LOG_FMT_WORDS; i++) {
    _write(c->LOG, start_index_words + i, logged_key[i]);
  }
}

/* Append a raw index value (not encoded) to the log at stard_index. start_index
 * is in bytes, and must be a valid log index (have at least KEY_LOG_FMT_WORDS
 * before end of the page). */
static void write_key_index(LRUCounter c, int key_index, size_t start_index) {
  uint8_t logged_index[INDEX_LOG_FMT_LEN];
  uint32_t write_index;
  convert_index_to_log_fmt(key_index, logged_index);
  if (start_index % sizeof(uint32_t) == 2) {
    /* Read first index in word. */
    write_index = c->LOG[start_index / sizeof(uint32_t)] -
        (0xffff << 16);
    /* Write index at second position in word. */
    write_index = c->LOG[start_index / sizeof(uint32_t)] - (0xffff << 16);
    write_index += (logged_index[0] + (logged_index[1] << 8)) << 16;
  } else {
    /* Write index at first position in word. */
    write_index = logged_index[0] + (logged_index[1] << 8) + (0xffff << 16);
  }
  _write(c->LOG, start_index / sizeof(uint32_t), write_index);
}

/* Read counter value of key-value pair at key_index. If key_index == -1, return
 * the value of the overflow counter. If data_page is NULL, return 0. */
static uint64_t read_table_val(LRUCounter c, int key_index,
                                        const uint32_t *data_page) {
  uint64_t val, top;
  if (data_page == NULL) return 0;
  if (key_index == -1) key_index = c->OVERFLOW_CTR_INDEX;
  /* Get lower 32 bits of value. */
  val = data_page[(key_index * KEY_VAL_WORDS) +
      ((KEY_LEN + 1) / sizeof(uint32_t)) + 1];
  /* Get upper 8 bits of value. */
  top = ((uint8_t *)(data_page))
      [(key_index * KEY_VAL_WORDS * sizeof(uint32_t)) + KEY_LEN + 1];
  val += (top << 32);
  return val;
}

/* Given a key, find the index in the table in data_page. If key is not present
 * in the table or data_page is NULL, returns -1. */
static int get_key_index(LRUCounter c, const uint8_t *key, const uint32_t *data_page) {
  int i;
  if (data_page == NULL) {
    return -1;
  }
  for (i = 0; i < c->NUM_COUNTERS; i++) {
    if (*(data_page + (i * KEY_VAL_WORDS + 1)) == END_OF_LOG) break;
    if (memcmp(key, data_page + (i * KEY_VAL_WORDS) + 1, KEY_LEN) == 0) {
      return i;
    }
  }
  return -1;
}

/* Lookup the value corresponding to a key and its key_index (may be -1 if key
 * is not in the table). Takes the currently valid data_page. Assumes that the
 * log is valid (check for corruption must be done before). */
static uint64_t lookup_val(LRUCounter c, const uint8_t *key, int key_index,
                                    const uint32_t *data_page) {
  uint8_t logged_key[KEY_LOG_FMT_LEN];
  uint8_t logged_index[INDEX_LOG_FMT_LEN];
  int log_index = 0;    /* in words */
  uint64_t val;
  val = read_table_val(c, key_index, data_page);
  /* Iterate through log and look for matches and increment val. */
  convert_key_to_log_fmt(key, (uint32_t *)logged_key);
  convert_index_to_log_fmt(key_index, logged_index);
  while (1) {
    if (c->LOG[log_index] == END_OF_LOG || log_index == c->PAGE_WORDS) {
      return val;
    }
    /* Check for a full key. */
    if ((c->LOG[log_index] & ENTRY_TYPE_MASK_UINT32) >>
        TYPE_SHIFT_AMT_UINT32 == KEY_TYPE) {
      if (memcmp(logged_key, c->LOG + log_index, KEY_LOG_FMT_LEN) == 0) {
        val++;
      }
      log_index += KEY_LOG_FMT_WORDS;
    }
    /* Check for key index. */
    else if (((c->LOG[log_index] & ENTRY_TYPE_MASK_UINT16) >>
              TYPE_SHIFT_AMT_UINT16) == INDEX_TYPE) {
      if (memcmp(c->LOG + log_index, logged_index, INDEX_LOG_FMT_LEN) == 0) {
        val++;
      }
      if (memcmp(((uint8_t *)(c->LOG + log_index)) + 2,
                 logged_index, INDEX_LOG_FMT_LEN) == 0) {
        val++;
      }
      log_index++;
    } else {
      fprintf(stderr, "ERROR: LOG CORRUPTION: 0x%x at index %d\n",
             c->LOG[log_index], log_index);
    }
  }
}

/* Given the key_index (should not be -1) and the currently valid data_page,
 * retrieve the unencoded key. */
static void get_key_from_index(int key_index,
                                        const uint32_t *data_page,
                                        uint8_t *key) {
  memcpy(key, data_page + (key_index * KEY_VAL_WORDS) + 1, KEY_LEN);
}

/* Check if a given data page has been used, meaning that it has not been erased
 * and the serial number was written correctly (repeated twice). */
static int was_page_used(uint32_t *data_page) {
  return ((data_page[0] != END_OF_LOG) &&
          ((data_page[0] & 0xffff) == (data_page[0] >> 16)));
}

/* Return currently valid data page. Checks that serial number is valid
 * (repeated twice) to avoid returning a partially erased page. */
static uint32_t *get_data_page(LRUCounter c) {
  /* No data pages used yet. */
  if (!was_page_used(c->DATA_1) &&
      !was_page_used(c->DATA_2)) {
    return NULL;
  }
  /* Only one data page in use. */
  if (!was_page_used(c->DATA_1)) {
      return c->DATA_2;
  }
  if (!was_page_used(c->DATA_2)) {
      return c->DATA_1;
  }
  /* Both pages are in use, compare serial number. */
  return c->DATA_1[0] > c->DATA_2[0] ? c->DATA_1 : c->DATA_2;
}

/* Return the currently invalid page. */
static uint32_t *get_next_data_page(LRUCounter c) {
  /* No data pages used yet. */
  if (!was_page_used(c->DATA_1) &&
      !was_page_used(c->DATA_2)) {
    return c->DATA_1;
  }
  /* Only one data page in use. */
  if (!was_page_used(c->DATA_1)) {
    return c->DATA_1;
  }
  if (!was_page_used(c->DATA_2)) {
    return c->DATA_2;
  }
  /* Both pages are in use, compare serial number. */
  return c->DATA_2[0] > c->DATA_1[0] ? c->DATA_1 : c->DATA_2;
}

/* Struct used in garbage collection for tracking the keys in the table and log
 * as well as the number of times they appear in the log and their index (if
 * any) in the table. */
typedef struct {
  uint8_t key[KEY_LEN];   // Key for counter value.
  int num_incs;           // Number of times key or key_index appears in log.
  int key_index;          // Index of key in table, -1 if not present.
} gc_ctr;

/* Mark that a key has been used by incrementing the current count or appending
 * to the list. Returns the new list size. */
static int add_key_use(const uint8_t *key, gc_ctr *use_list,
                                int list_size) {
  int i;
  for (i = 0; i < list_size; i++) {
    if (memcmp(use_list[i].key, key, KEY_LEN) == 0) {
      break;
    }
  }
  /* Append key. */
  if (i == list_size) {
    memcpy(use_list[i].key, key, KEY_LEN);
    use_list[i].num_incs = 1;
    use_list[i].key_index = -1;
    return list_size + 1;
  }
  /* Key is already in list. */
  else {
    use_list[i].num_incs++;
    return list_size;
  }
}

/* Run quicksort on gc_ctr list, ordered from smallest number of accesses to
 * largest. */
static void sort(gc_ctr *list, int first, int last) {
  int i, j, pivot;
  gc_ctr tmp;
  if (first < last) {
    pivot = first;
    i = first;
    j = last;
    while (i < j) {
      while (list[i].num_incs <= list[pivot].num_incs && i < last) i++;
      while (list[j].num_incs > list[pivot].num_incs) j--;
      if (i < j) {
        tmp = list[i];
        list[i] = list[j];
        list[j] = tmp;
      }
    }
    tmp = list[pivot];
    list[pivot] = list[j];
    list[j] = tmp;
    sort(list, first, j-1);
    sort(list, j+1, last);
  }
}

/* Garbage collect the log. Should be called when log is full or corrupted.
 * Process the log, write a table on the currently invalid page, mark it as
 * valid, and clear the log. */
static void garbage_collect(LRUCounter c) {
  int i, j, list_size, log_index, num_entries, key_index, write_offset;
  uint32_t *old_page, *new_page;
  uint64_t val, max;
  uint32_t write_words[KEY_VAL_WORDS];
  uint32_t serialno;
  uint8_t key[KEY_LEN];
  gc_ctr use_list[c->NUM_COUNTERS + (c->PAGE_WORDS / KEY_LOG_FMT_WORDS)];

  old_page = get_data_page(c);
  memset(use_list, 0,
         sizeof(gc_ctr) * (c->NUM_COUNTERS + (c->PAGE_WORDS / KEY_LOG_FMT_WORDS)));

  /* Look through table and record counts of all keys. */
  if (old_page != NULL) {
    for (i = 0; i < c->NUM_COUNTERS; i++) {
      get_key_from_index(i, old_page, use_list[i].key);
      /* Break if hit end of table. */
      if (((uint32_t *)use_list[i].key)[0] == END_OF_LOG) break;
      use_list[i].num_incs = 0;
      use_list[i].key_index = i;
    }
    list_size = i;
  } else {
    list_size = 0;
  }

  /* Walk through log and record counts and number of increments for all keys.*/
  log_index = 0;
  while (log_index < c->PAGE_WORDS) {
    /* Check for a full key. */
    if ((c->LOG[log_index] & ENTRY_TYPE_MASK_UINT32) >>
        TYPE_SHIFT_AMT_UINT32 == KEY_TYPE) {
      convert_key_from_log_fmt(c->LOG + log_index, key);
      list_size = add_key_use(key, use_list, list_size);
      log_index += KEY_LOG_FMT_WORDS;
    }
    /* Check for a key index. */
    else if (((c->LOG[log_index] & ENTRY_TYPE_MASK_UINT16) >>
              TYPE_SHIFT_AMT_UINT16) == INDEX_TYPE) {
      /* First index. */
      key_index = convert_index_from_log_fmt
          ((uint8_t *)(c->LOG + log_index));
      get_key_from_index(key_index, old_page, key);
      list_size = add_key_use(key, use_list, list_size);
      /* Check for second index. */
      if ((((uint8_t *)c->LOG)[(log_index * 4) + 3] &
           ENTRY_TYPE_MASK_UINT8) >> TYPE_SHIFT_AMT_UINT8 == INDEX_TYPE) {
        key_index = convert_index_from_log_fmt
            (((uint8_t *)(c->LOG + log_index)) + 2);
        get_key_from_index(key_index, old_page, key);
        list_size = add_key_use(key, use_list, list_size);
      }
      log_index++;
    }
    /* Log is corrupt -- stop scanning. */
    else {
      fprintf(stderr, "Found log corruption at index %d\n", log_index);
      break;
    }
  }

  /* Sort keys by number of times they appear in the log. */
  sort(use_list, 0, list_size - 1);
  num_entries = c->NUM_COUNTERS < list_size ? c->NUM_COUNTERS : list_size;

  /* Find new page and erase it. */
  new_page = get_next_data_page(c);
  _erase(c, new_page);

  /* Write new entries. */
  write_offset = 0;
  for (i = list_size - 1; i >= list_size - num_entries; i--) {
    val = lookup_val(c, use_list[i].key, use_list[i].key_index, old_page);
    memset(write_words, 0, sizeof(write_words));
    memcpy(write_words, use_list[i].key, KEY_LEN);
    write_words[4] = ((val << 32) >> 32); /* lower 32 bits. */
    write_words[3] += ((val >> 32) << 32);  /* top 8 bits. */
    /* Sanity check. */
    if (write_offset >= c->NUM_COUNTERS) {
      fprintf(stderr, "ERROR: bad write offset %d", write_offset);
    }
    for (j = 0; j < KEY_VAL_WORDS; j++) {
      _write(new_page, (write_offset * KEY_VAL_WORDS) + j + 1, write_words[j]);
    }
    write_offset++;
  }

  /* Calculate overflow counter. The new overflow counter value is the max of
   * the old overflow counter value and all counter values that are not included
   * in the new table. */
  max = read_table_val(c, c->OVERFLOW_CTR_INDEX, old_page);
  for (i = list_size - num_entries - 1; i >= 0; i--) {
    val = lookup_val(c, use_list[i].key, use_list[i].key_index, old_page);
    if ((uint32_t)val > (uint32_t)max &&
        (uint32_t)(val >> 32) >= (uint32_t)(max >> 32)) {
      max = val;
    }
  }

  /* Write the new overflow counter value to the table. */
  memset(write_words, 0, sizeof(write_words));
  write_words[4] = (max << 32) >> 32;   /* lower 32 bits. */
  write_words[3] += ((max >> 32) << 32);  /* top 8 bits. */
  for (i = 0; i < KEY_VAL_WORDS; i++) {
    _write(new_page, (c->OVERFLOW_CTR_INDEX * KEY_VAL_WORDS) + i + 1, write_words[i]);
  }

  /* Write higher serial number to new page. */
  serialno = old_page == NULL ? 0 : (old_page[0] & 0xffff);
  fprintf(stderr, "new serialno: %d\n", serialno + 1);
  _write(new_page, 0, (serialno + 1) + ((serialno + 1) << 16));

  /* Erase log. */
  _erase(c, c->LOG);
  fprintf(stderr, "GC DONE\n");
}

static void convert_to_key(const uint8_t *app_id, uint8_t *key_out) {
  EVP_MD_CTX *ctx;
  uint8_t digest[SHA256_DIGEST_LENGTH];
  ctx = EVP_MD_CTX_create();
  EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
  EVP_DigestUpdate(ctx, app_id, U2F_APPID_SIZE);
  EVP_DigestFinal_ex(ctx, digest, NULL);
  memcpy(key_out, digest, KEY_LEN);
}

/* Returns the index (in bytes) at which to start writing the next log entry.
 * Returns -1 if the log is corrupted or we have hit the end of the log (there
 * is not enough space for the largest entry left, meaning < KEY_LOG_FMT_WORDS
 * left in log). */
static int find_start_index(LRUCounter c) {
  // keep going as long as find prefixed with 01 or 00.
  // When hit ffff, return start index
  // If reach end first or don't find a valid pattern, return -1
  int log_index = 0;
  /* Walk through log as long as words prefixed with KEY_TYPE or INDEX_TYPE.
   * When we hit END_OF_LOG (ffff), we check that there's enough room for
   * another key entry and if there is, return that index. If we find corruption
   * in the log (word not END_OF_LOG or prefixed with KEY_TYPE or INDEX_TYPE),
   * we return -1. */
  /* Walk through log as long as words are prefixed with KEY_TYPE or INDEX_TYPE,
   * or until we hit the end of the log. */
  while (log_index != c->PAGE_WORDS) {
    /* Reach end of log on word boundary. Make sure there's enough room for the
     * next entry. */
    if (c->LOG[log_index] == END_OF_LOG) {
      return c->PAGE_WORDS - log_index >= KEY_LOG_FMT_WORDS ? log_index * 4 : -1;
    }
    /* Find entire hash of key. */
    else if ((c->LOG[log_index] & ENTRY_TYPE_MASK_UINT32) >>
             TYPE_SHIFT_AMT_UINT32 == KEY_TYPE) {
      log_index += KEY_LOG_FMT_WORDS;
    }
    /* Find first index in word. */
    else if ((c->LOG[log_index] & ENTRY_TYPE_MASK_UINT16) >>
             TYPE_SHIFT_AMT_UINT16 == INDEX_TYPE) {
      if ((((uint8_t *)c->LOG)[(log_index * 4) + 3] &
           ENTRY_TYPE_MASK_UINT8) >> TYPE_SHIFT_AMT_UINT8 == INDEX_TYPE) {
        /* Find second index in word. */
        log_index++;
      } else {
        /* No second index in word, look ahead to next potential hash. */
        if ((c->LOG[log_index + 1] & ENTRY_TYPE_MASK_UINT32) >>
            TYPE_SHIFT_AMT_UINT32 != KEY_TYPE) {
          return c->PAGE_WORDS - (log_index + 1) >= KEY_LOG_FMT_WORDS ?
              (4 * log_index) + 2 : -1;
        }
        log_index++;
      }
    }
    /* No valid bit pattern found. Log corrupted. */
    else {
      return -1;
    }
  }
  /* Hit end of log. */
  return -1;
}

/* Given an app id, increment and return the corresponding counter value. */
uint64_t LRUCounter_incr(LRUCounter c, const uint8_t *app_id) {
  uint32_t *data_page;
  uint8_t key[KEY_LEN];
  int key_index, start_index;
  uint64_t val;

  data_page = get_data_page(c);
  start_index = find_start_index(c); /* in bytes */

  /* Check if need to garbage collect log. */
  if (start_index == -1) {
    garbage_collect(c);
    data_page = get_data_page(c);
    start_index = 0;
  }

  /* Increment counter value. If key exists in table, append index to log. If
   * key doesn't exist in table, append key to log. */
  convert_to_key(app_id, key);
  key_index = get_key_index(c, key, data_page);
  if (key_index >= 0) {
    write_key_index(c, key_index, start_index);
  } else {
    write_full_key(c, key, start_index);
  }

  /* Read counter value. */
  val = lookup_val(c, key, key_index, data_page);
  return val;
}
