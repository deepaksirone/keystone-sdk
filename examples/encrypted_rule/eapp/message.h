#ifndef _H_MESSAGE_H_
#define _H_MESSAGE_H_
#include "keystore_report.h"
#include <stdint.h>

int send_key_retrieval_message(uintptr_t uid, uintptr_t rule_id, struct report_t *report, struct keystore_rule *rule);

#endif