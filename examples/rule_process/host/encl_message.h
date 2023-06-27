#ifndef _ENCL_MESSAGE_H_
#define _ENCL_MESSAGE_H_
#include "edge_common.h"
#include "report.h"

#define MAX_ACTION_PARAM_SIZE 1000

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

typedef struct trigger_data_t {
	char trigger_name[1000];
	int32_t trigger_name_size;
	uintptr_t nonce;
	char rule_params[];
} trigger_data_t;

typedef struct trigger_response_t {
	char iv[16];
	char tag[16];
	int32_t ciphertext_size;
	char ciphertext[];
} trigger_response_t;

typedef struct action_data_t {
	char iv[16];
	char tag[16];
	char action_params[MAX_ACTION_PARAM_SIZE];
	int32_t action_param_sz;
	int32_t ciphertext_size;
	char ciphertext[];
} action_data_t;


#endif /* _ENCL_MESSAGE_H_ */
