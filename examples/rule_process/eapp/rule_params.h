#ifndef _H_RULE_PARAMS_H_
#define _H_RULE_PARAMS_H_

#ifndef NUM_RULE_TRIGGERS
    #define NUM_RULE_TRIGGERS 1
    #define RULE_PARAMS { "{ \\\"attrib1\\\" : \\\"val1\\\", \\\"attrib2\\\" : \\\"val2\\\" }",}
    #define RULE_PARAMS_UNESCAPED { "{ \"attrib1\" : \"val1\", \"attrib2\" : \"val2\" }",}
#endif

#ifndef NUM_RULE_ACTIONS
    #define NUM_RULE_ACTIONS 1
    #define RULE_ACTION_PARAMS { "{ \\\"attrib1\\\" : \\\"val1\\\", \\\"attrib2\\\" : \\\"val2\\\" }",}
    #define RULE_ACTION_PARAMS_UNESCAPED { "{ \"attrib1\" : \"val1\", \"attrib2\" : \"val2\", \"action_url\": \"http://node0.spigot1.cs799-serverless-pg0.wisc.cloudlab.us:80/action_data/\", \"action_id\": \"0\" }",}
#endif

#endif