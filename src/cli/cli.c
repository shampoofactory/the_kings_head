#include "cli.h"

__attribute__((force_align_arg_pointer)) void _start()
{
    // PARAM
    // SECRET: GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
    // DIGITS: 8
    // PERIOD: 30
    // ALGORITHM: SHA1

    // KEY STRING: 12345678901234567890
    //     AS HEX: 3132333435363738393031323334353637383930
    //  AS BASE32: GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
    char *key = "12345678901234567890";
    uint32_t key_len = 20;
    uint32_t n_digits = 8;
    uint32_t period = 30;

    char buf[16] = {};
    buf[n_digits] = '\n';
    uint64_t t = sys_time() / period;
    uint32_t v = totp_sha1_gen((uint8_t *)key, key_len, t);
    totp_code_str(buf, v, n_digits);

    sys_print(buf, n_digits + 1);
    sys_exit(0);
    __builtin_unreachable();
}