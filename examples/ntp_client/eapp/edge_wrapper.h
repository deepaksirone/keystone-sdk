#ifndef _EDGE_WRAPPER_H_
#define _EDGE_WRAPPER_H_
#include "edge_call.h"
#include "encl_message.h"
#include <stdint.h>

#define RUNTIME_SYSCALL_REGISTER_TIME       1008
#define RUNTIME_SYSCALL_GET_TIME            1009

void edge_init();

unsigned long ocall_print_buffer(char* data);
void ocall_print_value(unsigned long val);
void ocall_wait_for_message(struct edge_data *msg);
void ocall_wait_for_client_pubkey(unsigned char* pk, size_t len);
void ocall_send_report(char* buffer, size_t len);
void ocall_send_reply(unsigned char* data, size_t len);
int32_t ocall_init_connection(connection_data_t *data, size_t len);
int32_t ocall_init_connection_udp(connection_data_t *data, size_t len);
size_t ocall_send_buffer_fd(network_send_data_t *data, size_t size);
size_t ocall_recv_buffer_fd(network_recv_request_t *data, size_t size, struct edge_data *msg);
uint64_t runtime_set_unix_time(unsigned long unix_time);
uint64_t runtime_get_unix_time();
#endif /* _EDGE_WRAPPER_H_ */
