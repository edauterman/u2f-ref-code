// Copyright 2018 Google Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#include "counter.h"
#include "common.h"
#include "u2f.h"
#include "u2f_util.h"

using namespace std;

static void AbortOrNot() {
  abort();
}

static void set_app_id(uint16_t num, uint8_t *app_id) {
  int i;
  app_id[0] = num & 0xff;
  app_id[1] = num >> 8;
  for (i = 2; i < U2F_APPID_SIZE; i++) {
    app_id[i] = 0;
  }
}

/* Test incrementing 100 individual counters 10 times each. Should all have
 * their own individual counter, no eviction needed. */
static int ctr_tests5(LRUCounter c) {
  int i, j, val, success;
  uint8_t app_ids[100][U2F_APPID_SIZE];

  success = 1;
  for (i = 0; i < 100; i++) {
    set_app_id(i, app_ids[i]);
  }
  for (i = 0; i < 10; i++) {
    for (j = 0; j < 100; j++) {
      val = LRUCounter_incr(c, app_ids[j]);
      success = success && (i + 1 == val);
    }
  }
  if (success) {
    printf("Exactly 100 individual counters incremented 10 times each: SUCCESS\n");
  } else {
    printf("Exactly 100 individual counters incremented 10 times each: FAIL\n\
             Did you clear the counter state before running the test?\n");
    return ERROR;
  }

  return OKAY;
}

/* Alternate between incrementing the counter for the same site and incrementing
 * the counter for a site that's different every time. The frequently accessed
 * site should never be evicted. */
static int ctr_tests4(LRUCounter c) {
  int i, val_changing, expected_changing, val_stable, expected_stable, success;
  uint8_t app_id_changing[U2F_APPID_SIZE];
  uint8_t app_id_stable[U2F_APPID_SIZE];

  set_app_id(1001, app_id_stable);
  success = 1;
  for (i = 0; i < 1000; i++) {
    val_stable = LRUCounter_incr(c, app_id_stable);
    expected_stable = i + 1;
    if (val_stable != expected_stable) {
      printf("FAIL: for stable id, returned val %d, expected %d\n",
               val_stable, expected_stable);
    }
    set_app_id(i, app_id_changing);
    val_changing = LRUCounter_incr(c, app_id_changing);
    expected_changing = (((i - 64) / 102) + 1);
    if (val_changing != expected_changing) {
      printf("FAIL: for changing id, returned val %d, expected %d\n",
               val_changing, expected_changing);
    }
    printf("i = %d, changing counter = %d, stable counter = %d\n", i,
             val_changing, val_stable);
    success = success && (val_stable == expected_stable) &&
        (val_changing == expected_changing);;
  }

  if (success) {
    printf("Stable and changing IDs: SUCCESS\n");
  } else {
    printf("Stable and changing IDs: FAIL\n\
             Did you clear the counter state before running the test?\n");
    return ERROR;
  }
  return OKAY;
}

/* Repeatedly resurrect counters that can't stay in table. Check that garbage
 * collection and calculation of the overflow counter are correct. */
static int ctr_tests3(LRUCounter c) {
  int i, j, total, val, success, expected;
  uint8_t app_id[U2F_APPID_SIZE];

  success = 1;
  total = 0;
  for (i = 1; i < 20; i++) {
    for (j = 1; j < 1000; j++) {
      set_app_id(j, app_id);
      val = LRUCounter_incr(c, app_id);
      expected = (((total / 128)) + 1);
      if (val != expected) {
        printf("FAIL: returned val %d, expected %d\n", val, expected);
      }
      printf("i = %d, j = %d\n", i, j);
      success = success && (val == expected);
      total++;
    }
  }
  if (success) {
    printf("Resurrecting counters repeatedly: SUCCESS\n");
  } else {
    printf("Resurrecting counters repeatedly: FAIL\n\
             Did you clear the counter state before running the test?\n");
    return ERROR;
  }

  return OKAY;
}

 /* which is incremented after each garbage collection. */
static int ctr_tests2(LRUCounter c) {
  int i;
  int val, expected;
  uint8_t app_id[U2F_APPID_SIZE];
  int success;

  success = 1;
  for (i = 0; i < 1000; i++) {
    set_app_id(i, app_id);
    val = LRUCounter_incr(c, app_id);
    expected = (i / 128) + 1;
    if (val != expected) {
      printf("FAIL: returned val %d, expected %d\n", val, expected);
    }
    printf("i = %d, val = %d\n", i, val);
    success = success && (val == expected);
  }
  if (success) {
    printf("1000 distinct IDs incremented by 1: SUCCESS\n");
  } else {
    printf("1000 distinct IDs incremented by 1: FAIL\n\
             Did you clear the counter state before running the test?");
    return ERROR;
  }

  return OKAY;
}

/* Increment two counters, 1000 times each. Should be exact counts. */
static int ctr_tests1(LRUCounter c) {
  int i;
  int val;
  uint8_t app_id[U2F_APPID_SIZE];

  set_app_id(1, app_id);
  for (i = 0; i < 1000; i++) {
    val = LRUCounter_incr(c, app_id);
    if (val != i + 1) {
      printf("FAIL: expected %d but got %d\n", i + 1, val);
      return ERROR;
    }
  }
  if (val == 1000) {
    printf("First counter to 1,000: SUCCESS\n");
  } else {
    printf("First counter to 1,000: FAIL (reported %d instead of 1000\n\
             Did you clear the counter state before running the test?", val);
    return ERROR;
  }

  set_app_id(2, app_id);
  for (i = 0; i < 1000; i++) {
    val = LRUCounter_incr(c, app_id);
    if (val != i + 1) {
      printf("FAIL: expected %d but got %d\n", i + 1, val);
      return ERROR;
    }
  }
  if (val == 1000) {
    printf("Second counter to 1,000: SUCCESS\n");
  } else {
    printf("Second counter to 1,000: FAIL (reported %d instead of 1000\n\
             Did you clear the counter state before running the test?", val);
    return ERROR;
  }

  return OKAY;
}

int main(int argc, char *argv[]) {
  LRUCounter c;

  c = LRUCounter_new(100, 512);
  CHECK_EQ(OKAY, ctr_tests1(c));
  LRUCounter_free(c);

  c = LRUCounter_new(100, 512);
  CHECK_EQ(OKAY, ctr_tests2(c));
  LRUCounter_free(c);

  c= LRUCounter_new(100, 512);
  CHECK_EQ(OKAY, ctr_tests3(c));
  LRUCounter_free(c);

  c = LRUCounter_new(100, 512);
  CHECK_EQ(OKAY, ctr_tests4(c));
  LRUCounter_free(c);

  c = LRUCounter_new(100, 512);
  CHECK_EQ(OKAY, ctr_tests5(c));
  LRUCounter_free(c);

  printf("Tests completed.\n");
}
