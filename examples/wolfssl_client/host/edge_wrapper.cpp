#include "encl_message.h"
#include "edge_wrapper.h"
#include "edge_defines.h"
#include <string.h>
/* Really all of this file should be autogenerated, that will happen
   eventually. */


int edge_init(Keystone::Enclave* enclave) {

  enclave->registerOcallDispatch(incoming_call_dispatch);
  register_call(OCALL_PRINT_BUFFER, print_buffer_wrapper);
  register_call(OCALL_PRINT_VALUE, print_value_wrapper);
  register_call(OCALL_SEND_REPORT, send_report_wrapper);
  register_call(OCALL_WAIT_FOR_MESSAGE, wait_for_message_wrapper);
  register_call(OCALL_WAIT_FOR_CLIENT_PUBKEY, wait_for_client_pubkey_wrapper);
  register_call(OCALL_SEND_REPLY, send_reply_wrapper);
  register_call(OCALL_INIT_CONN, init_connection_wrapper);
  register_call(OCALL_SEND_FD, send_message_fd_wrapper);
  register_call(OCALL_RECV_FD, recv_message_fd_wrapper);

  edge_call_init_internals((uintptr_t)enclave->getSharedBuffer(),
			   enclave->getSharedBufferSize());
}

void print_buffer_wrapper(void* buffer)
{
  /* For now we assume the call struct is at the front of the shared
   * buffer. This will have to change to allow nested calls. */
  struct edge_call* edge_call = (struct edge_call*)buffer;

  uintptr_t call_args;
  unsigned long ret_val;
  size_t args_len;
  if(edge_call_args_ptr(edge_call, &call_args, &args_len) != 0){
    edge_call->return_data.call_status = CALL_STATUS_BAD_OFFSET;
    return;
  }
  ret_val = print_buffer((char*)call_args);

  // We are done with the data section for args, use as return region
  // TODO safety check?
  uintptr_t data_section = edge_call_data_ptr();

  memcpy((void*)data_section, &ret_val, sizeof(unsigned long));

  if( edge_call_setup_ret(edge_call, (void*) data_section, sizeof(unsigned long))){
    edge_call->return_data.call_status = CALL_STATUS_BAD_PTR;
  }
  else{
    edge_call->return_data.call_status = CALL_STATUS_OK;
  }

  return;

}

void print_value_wrapper(void* buffer)
{
  /* For now we assume the call struct is at the front of the shared
   * buffer. This will have to change to allow nested calls. */
  struct edge_call* edge_call = (struct edge_call*)buffer;

  uintptr_t call_args;
  unsigned long ret_val;
  size_t args_len;
  if(edge_call_args_ptr(edge_call, &call_args, &args_len) != 0){
    edge_call->return_data.call_status = CALL_STATUS_BAD_OFFSET;
    return;
  }

  print_value(*(unsigned long*)call_args);

  edge_call->return_data.call_status = CALL_STATUS_OK;
  return;
}

void send_report_wrapper(void* buffer)
{

  /* For now we assume the call struct is at the front of the shared
   * buffer. This will have to change to allow nested calls. */
  struct edge_call* edge_call = (struct edge_call*)buffer;

  uintptr_t data_section;
  unsigned long ret_val;
  //TODO check the other side of this
  if(edge_call_get_ptr_from_offset(edge_call->call_arg_offset, sizeof(report_t),
				   &data_section) != 0) {
    edge_call->return_data.call_status = CALL_STATUS_BAD_OFFSET;
    return;
  }

  send_report((void*)data_section, sizeof(report_t));

  edge_call->return_data.call_status = CALL_STATUS_OK;

  return;
}

void wait_for_message_wrapper(void* buffer)
{

  /* For now we assume the call struct is at the front of the shared
   * buffer. This will have to change to allow nested calls. */
  struct edge_call* edge_call = (struct edge_call*)buffer;

  uintptr_t call_args;
  unsigned long ret_val;
  size_t args_len;
  if(edge_call_args_ptr(edge_call, &call_args, &args_len) != 0){
    edge_call->return_data.call_status = CALL_STATUS_BAD_OFFSET;
    return;
  }

  encl_message_t host_msg = wait_for_message();

  // This handles wrapping the data into an edge_data_t and storing it
  // in the shared region.
  if( edge_call_setup_wrapped_ret(edge_call, host_msg.host_ptr, host_msg.len)){
    edge_call->return_data.call_status = CALL_STATUS_BAD_PTR;
  }
  else{
    edge_call->return_data.call_status = CALL_STATUS_OK;
  }

  return;
}

void send_reply_wrapper(void* buffer)
{
  /* For now we assume the call struct is at the front of the shared
   * buffer. This will have to change to allow nested calls. */
  struct edge_call* edge_call = (struct edge_call*)buffer;

  uintptr_t call_args;
  unsigned long ret_val;
  size_t args_len;
  if(edge_call_args_ptr(edge_call, &call_args, &args_len) != 0){
    edge_call->return_data.call_status = CALL_STATUS_BAD_OFFSET;
    return;
  }

  send_reply((void*)call_args, edge_call->call_arg_size);
  edge_call->return_data.call_status = CALL_STATUS_OK;

  return;
}

void init_connection_wrapper(void *buffer) {
  struct edge_call* edge_call = (struct edge_call*)buffer;

  uintptr_t call_args;
  size_t args_len;

  if(edge_call_args_ptr(edge_call, &call_args, &args_len) != 0) {
    edge_call->return_data.call_status = CALL_STATUS_BAD_OFFSET;
    return;
  }

  connection_data_t *data = (connection_data_t *)call_args;
  int32_t portnumber = data->portnumber;
  
  // Assuming null terminated hostname
  unsigned char *hostname = data->hostname;

  int32_t fd = initiate_connection((char *)hostname, portnumber);
  
  uintptr_t data_section = edge_call_data_ptr();

  memcpy((void*)data_section, &fd, sizeof(int32_t));
  
  if (edge_call_setup_ret(edge_call, (void*) data_section, sizeof(unsigned long))) {
     edge_call->return_data.call_status = CALL_STATUS_BAD_PTR;
  }
  else {
     edge_call->return_data.call_status = CALL_STATUS_OK;
  }

  return;

}

void send_message_fd_wrapper(void *buffer) {
  struct edge_call *edge_call = (struct edge_call*)buffer;

  uintptr_t call_args;
  size_t args_len;

  if (edge_call_args_ptr(edge_call, &call_args, &args_len) != 0) {
    edge_call->return_data.call_status = CALL_STATUS_BAD_OFFSET;
    return;
  }

  network_send_data_t *send_data = (network_send_data_t *)call_args;
   
  size_t sent_bytes = send_message_fd(send_data->fd, send_data->data, send_data->data_len);

  uintptr_t data_section = edge_call_data_ptr();

  memcpy((void*)data_section, &sent_bytes, sizeof(size_t));
  
  if (edge_call_setup_ret(edge_call, (void*) data_section, sizeof(size_t))) {
     edge_call->return_data.call_status = CALL_STATUS_BAD_PTR;
  }
  else {
     edge_call->return_data.call_status = CALL_STATUS_OK;
  }

  return;

}


void recv_message_fd_wrapper(void *buffer) {
  struct edge_call *edge_call = (struct edge_call*)buffer;

  uintptr_t call_args;
  unsigned long ret_val;
  size_t args_len;

  if (edge_call_args_ptr(edge_call, &call_args, &args_len) != 0) {
    edge_call->return_data.call_status = CALL_STATUS_BAD_OFFSET;
    return;
  }

  network_recv_request_t *recv_req = (network_recv_request_t *) call_args;
  network_recv_data_t recv_data = receive_message_fd(recv_req->fd, recv_req->req_size);

  if( edge_call_setup_wrapped_ret(edge_call, recv_data.data, recv_data.size)){
    edge_call->return_data.call_status = CALL_STATUS_BAD_PTR;
  }
  else{
    edge_call->return_data.call_status = CALL_STATUS_OK;
  }

  return;
}

void wait_for_client_pubkey_wrapper(void* buffer){
  /* For now we assume the call struct is at the front of the shared
   * buffer. This will have to change to allow nested calls. */
  struct edge_call* edge_call = (struct edge_call*)buffer;

  unsigned long ret_val;

  void* pubkey = wait_for_client_pubkey();


  // We are done with the data section for args, use as return region
  // TODO safety check?
  uintptr_t data_section = edge_call_data_ptr();

  memcpy((void*)data_section, pubkey, crypto_kx_PUBLICKEYBYTES);

  if( edge_call_setup_ret(edge_call, (void*) data_section, sizeof(unsigned long))){
    edge_call->return_data.call_status = CALL_STATUS_BAD_PTR;
  }
  else{
    edge_call->return_data.call_status = CALL_STATUS_OK;
  }

  return;
}
