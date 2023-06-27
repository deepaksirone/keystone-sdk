#include "app/eapp_utils.h"
#include "app/string.h"
#include "app/syscall.h"
#include "edge_wrapper.h"
#include "edge_defines.h"
#include "encl_message.h"

void edge_init(){
  /* Nothing for now, will probably register buffers/callsites
     later */
}

void ocall_print_value(unsigned long val) {

  unsigned long val_ = val;
  ocall(OCALL_PRINT_VALUE, &val_, sizeof(unsigned long), 0, 0);

  return;
}

void ocall_send_report(char* buffer, size_t len) {

  ocall(OCALL_SEND_REPORT, buffer, len, 0, 0);

  return;  
}

unsigned long ocall_print_buffer(char* data) {

  unsigned long retval;
  ocall(OCALL_PRINT_BUFFER, data, strlen(data)+1, &retval ,sizeof(unsigned long));

  return retval;
}

void ocall_wait_for_message(struct edge_data *msg) {

  ocall(OCALL_WAIT_FOR_MESSAGE, NULL, 0, msg, sizeof(struct edge_data));
}

void ocall_wait_for_client_pubkey(unsigned char* pk, size_t len) {
  ocall(OCALL_WAIT_FOR_CLIENT_PUBKEY, NULL, 0, pk, len);
  return;
}

void ocall_send_reply(unsigned char* data, size_t len){
  ocall(OCALL_SEND_REPLY, data, len, 0, 0);
  return;
}

int32_t ocall_init_connection(connection_data_t *data, size_t len) {
  int32_t fd;
  ocall(OCALL_INIT_CONN, data, len, &fd, sizeof(int32_t));

  return fd;
}


size_t ocall_send_buffer_fd(network_send_data_t *data, size_t size) {
  size_t retval;
  ocall(OCALL_SEND_FD, data, size, &retval, sizeof(size_t));

  return retval;
}

size_t ocall_recv_buffer_fd(network_recv_request_t *data, size_t size, struct edge_data *msg) {
  ocall(OCALL_RECV_FD, data, size, msg, sizeof(struct edge_data));

  return msg->size;
}

int32_t ocall_terminate_conn(int32_t fd) {
  int32_t retval;
  ocall(OCALL_TERM_FD, &fd, sizeof(int32_t), &retval, sizeof(int32_t));
  return retval;
}

size_t ocall_get_trigger_data(trigger_data_t *data, size_t size, struct edge_data *msg) {
  ocall(OCALL_GET_TRIGGER_DATA, data, size, msg, sizeof(struct edge_data));

  return msg->size;
}

int32_t ocall_send_action_data(action_data_t *action_data, size_t action_data_sz) {
  int32_t retval;
  ocall(OCALL_SEND_ACTION_DATA, action_data, action_data_sz, &retval, sizeof(int32_t));

  return retval;
}
