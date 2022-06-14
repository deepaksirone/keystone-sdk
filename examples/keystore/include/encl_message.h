#ifndef _ENCL_MESSAGE_H_
#define _ENCL_MESSAGE_H_
#include "edge_common.h"
#include "keystore_rule.h"
#include "keystore_user.h"

typedef unsigned char byte;

typedef struct network_message_t {
  size_t data_len;
  edge_data_offset offset;
} network_message_t;

typedef struct data_message_t {
  unsigned int msg_type;

  size_t data_len;

  unsigned char data[];

} edge_data_message_t;

typedef struct network_send_data_t {
	int32_t fd;
	size_t data_len;
	unsigned char data[];
} network_send_data_t;

typedef struct network_recv_request_t {
	int32_t fd;
	size_t req_size;
} network_recv_request_t;

typedef struct network_recv_data_t {
	size_t size;
	void *data;
} network_request_data_t;

typedef struct connection_data_t {
	int32_t portnumber;
	unsigned char hostname[];
} connection_data_t;

typedef struct get_user_record_request {
	// 0 : exists query, 1 : returns struct
	char reply;
	char username[20];
} get_user_record_request_t;

typedef struct set_rule_request {
	uintptr_t uid;
	uintptr_t rule_id;
	
	struct enc_keystore_rule enc_rule;
} set_rule_request_t;

typedef struct set_user_record_request {
	char username[20];
	struct enc_keystore_user enc_user; 
} set_user_record_request_t;

typedef struct get_rule_request {
	// 0 : exists query, 1 : returns struct
	char reply;
	uintptr_t uid;
	uintptr_t rule_id;
} get_rule_request_t;

#endif /* _ENCL_MESSAGE_H_ */
