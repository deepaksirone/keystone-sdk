#ifndef _EDGE_WRAPPER_H_
#define _EDGE_WRAPPER_H_

#include <edge_call.h>
#include "keystone.h"
#include "encl_message.h"

#define crypto_kx_PUBLICKEYBYTES 32


typedef struct encl_message_t {
  void* host_ptr;
  size_t len;
} encl_message_t;

int edge_init(Keystone::Enclave* enclave);

void print_buffer_wrapper(void* buffer);
unsigned long print_buffer(char* str);

void print_value_wrapper(void* buffer);
void print_value(unsigned long val);

void send_report_wrapper(void* buffer);
void send_report(void* shared_buffer, size_t len);

void wait_for_message_wrapper(void* buffer);
encl_message_t wait_for_message();

void send_reply_wrapper(void* buffer);
void send_reply(void* message, size_t len);

void wait_for_client_pubkey_wrapper(void* buffer);
void* wait_for_client_pubkey();

void init_connection_wrapper(void *buffer);
int32_t initiate_connection(char *hostname, int32_t port);

void init_connection_udp_wrapper(void *buffer);
int32_t initiate_connection_udp(char *hostname, int32_t port);

void send_message_fd_wrapper(void *buffer);
size_t send_message_fd(int32_t fd, void *buffer, size_t size);

void recv_message_fd_wrapper(void *buffer);
network_recv_data_t receive_message_fd(int32_t fd, size_t size);

#endif /* _EDGE_WRAPPER_H_ */
