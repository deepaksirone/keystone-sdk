#include <stdio.h>
#include "encl_message.h"
#include "edge_wrapper.h"
#include "rule_keystore.h"
#include "keystore_report.h"
#include "message.h"

struct keystore_rule rule;

void get_keys() {
    report_t report;
    attest_enclave((void *)&report, (void *)NULL, (size_t)0);

    if (send_key_retrieval_message(__user_id, __user_id, &report, &rule) != 0) {
        printf("Failed to retrieve keys\n");
    }
}


