
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

size_t min(size_t a, size_t b) {
  return (a < b) ? a : b;
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

int32_t ocall_init_serv_connection(connection_data_t *data, size_t len) {
  int32_t fd;
  ocall(OCALL_INIT_SERV_CONN, data, len, &fd, sizeof(int32_t));

  return fd;
}

int32_t ocall_wait_for_conn(int32_t fd) {
  int32_t client_fd;
  ocall(OCALL_WAIT_FOR_CONN, &fd, sizeof(int32_t), &client_fd, sizeof(int32_t));

  return client_fd;
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

int32_t ocall_get_user_record(char *username, struct edge_data *msg) {
  get_user_record_request_t req;
  int32_t exists;
  memset(&req.username, 0, 20);
  memcpy(&req.username, username, min(strlen(username), 19));

  if (msg == NULL) {
    req.reply = 0;
    ocall(OCALL_GET_USER_RECORD, &req, sizeof(get_user_record_request_t), &exists, sizeof(int32_t));
  } else {
    req.reply = 1;
    ocall(OCALL_GET_USER_RECORD, &req, sizeof(get_user_record_request_t), msg, sizeof(struct edge_data));
    exists = (msg->size > 0) ? 1 : 0;
  }

  return exists;
}

int32_t ocall_set_user_record(char *username, struct enc_keystore_user enc_user) {
  set_user_record_request_t req;
  int32_t retval;
  memset(&req.username, 0, 20);
  memcpy(&req.username, username, min(strlen(username), 19));
  req.enc_user = enc_user;

  ocall(OCALL_SET_USER_RECORD, &req, sizeof(set_user_record_request_t), &retval, sizeof(int32_t));
  
  return retval;
}


int32_t ocall_get_rule_record(uintptr_t uid, uintptr_t rule_id, struct edge_data *msg) {
  get_rule_request_t req;
  int32_t exists;
  req.uid = uid;
  req.rule_id = rule_id;

  if (msg == NULL) {
    req.reply = 0;
    ocall(OCALL_GET_RULE_RECORD, &req, sizeof(get_rule_request_t), &exists, sizeof(int32_t));
  } else {
    req.reply = 1;
    ocall(OCALL_GET_RULE_RECORD, &req, sizeof(get_rule_request_t), msg, sizeof(struct edge_data));
    exists = (msg->size > 0) ? 1 : 0;
  }

  return exists;
}

int32_t ocall_set_rule_record(uintptr_t uid, uintptr_t rule_id, struct enc_keystore_rule enc_rule) {
  set_rule_request_t req;
  int32_t retval;
  req.uid = uid;
  req.rule_id = rule_id;
  req.enc_rule = enc_rule;

  ocall(OCALL_SET_RULE_RECORD, &req, sizeof(set_rule_request_t), &retval, sizeof(int32_t));

  return retval;
}