#ifndef _H_KEYSTORE_QUEUE_H_
#define _H_KEYSTORE_QUEUE_H_

#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include "keystore_request.h"

#define QUEUE_FULL 0x1
#define QUEUE_SUCCESS 0x0
#define QUEUE_EMPTY 0x2

typedef struct request_queue {
    int capacity;
    int cur_start_idx;
    int end_idx;
    request_t requests[];
} request_queue_t;

#endif