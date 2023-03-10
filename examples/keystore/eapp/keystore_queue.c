#include "keystore_queue.h"

request_queue_t *new_request_queue(int capacity) {
    request_queue_t *queue = (request_queue_t *)malloc(sizeof(request_queue_t) + capacity * sizeof(request_t));
    queue->capacity = capacity;
    queue->cur_start_idx = queue->end_idx = 0;
    return queue;
}

int push_queue(request_queue_t *queue, request_t *request) {
    if ((queue->cur_start_idx + 1) % queue->capacity == queue->end_idx) {
        return QUEUE_FULL;
    }

    memcpy((void *)&queue->requests[queue->cur_start_idx], request, sizeof(request_t));
    queue->cur_start_idx = (queue->cur_start_idx + 1) % queue->capacity;

    return QUEUE_SUCCESS;
}

request_t *pop_queue(request_queue_t *queue) {
    if (queue->cur_start_idx == queue->end_idx) {
        return NULL;
    }

    request_t *ret = &queue->requests[queue->end_idx];
    queue->end_idx = (queue->end_idx + 1) % queue->capacity;

    return ret;
}