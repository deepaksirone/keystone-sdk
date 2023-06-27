#ifndef _EDGE_WRAPPER_H_
#define _EDGE_WRAPPER_H_
#include "edge_call.h"
#include "encl_message.h"

void edge_init();

unsigned long ocall_print_buffer(char* data);
void ocall_print_value(unsigned long val);
void ocall_wait_for_message(struct edge_data *msg);
void ocall_wait_for_client_pubkey(unsigned char* pk, size_t len);
void ocall_send_report(char* buffer, size_t len);
void ocall_send_reply(unsigned char* data, size_t len);
int32_t ocall_init_connection(connection_data_t *data, size_t len);
int32_t ocall_terminate_conn(int32_t fd);
size_t ocall_send_buffer_fd(network_send_data_t *data, size_t size);
size_t ocall_recv_buffer_fd(network_recv_request_t *data, size_t size, struct edge_data *msg);
size_t ocall_get_trigger_data(trigger_data_t *data, size_t size, struct edge_data *msg);
int32_t ocall_send_action_data(action_data_t *action_data, size_t action_data_sz);
#endif /* _EDGE_WRAPPER_H_ */
