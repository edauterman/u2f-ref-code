#ifndef _COUNTER_H
#define _COUNTER_H

#ifdef __cplusplus
extern "C"{
#endif

#include <stdint.h>

typedef struct counter *LRUCounter;

LRUCounter LRUCounter_new(int num_counters, int page_words);
void LRUCounter_free(LRUCounter c);

void LRUCounter_write_to_storage(LRUCounter c, const char *path);
int LRUCounter_read_from_storage(LRUCounter c, const char *path);

uint64_t LRUCounter_incr(LRUCounter c, const uint8_t *app_id);

#ifdef __cplusplus
}
#endif
#endif

