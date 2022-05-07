add_wolfssl(${eapp_bin}-wolfssl
   "03deeea62b67e5543c3f29f2dd56f23e440d0f2f"
   "musl"
   "-DCUSTOM_RAND_GENERATE=rand_gen_keystone -DCUSTOM_RAND_TYPE=uintptr_t -DKEYSTONE"
)
