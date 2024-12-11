#include <immintrin.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hmac_sha1.h"
#include "sys.h"
#include "totp_core.h"
#include "totp.h"

#define CMD "totpfoo"

extern const uint8_t _binary_build_obj_totp_blk_bin_start;
extern const uint8_t _binary_build_obj_totp_blk_bin_end;
extern const uint8_t _binary_build_obj_totp_blk_bin_size;

#define MAX_N_DIGITS 0x0F

void hex(void *ptr, size_t len)
{
    for (size_t i = 0; i < len; i++)
    {
        printf("%02x", *(((uint8_t *)ptr) + i));
    }
    printf("\n");
}

int main(int argc, char **argv)
{
    if ((size_t)&_binary_build_obj_totp_blk_bin_size != sizeof(TotpBlk))
    {
        // Build error
        fprintf(stderr, CMD ": internal error\n");
        return 1;
    }
    if (argc != 2)
    {
        // User error
        fprintf(stderr, CMD ": no password supplied\n");
        return 2;
    }
    char *pass = argv[1];
    TotpBlk *blk = (TotpBlk *)&_binary_build_obj_totp_blk_bin_start;
    TotpParam param = {};
    bool is_ok = totp_blk_decrypt(blk, &param, (uint8_t *)pass, strlen(pass));
    if (!is_ok)
    {
        // Unauthenticated
        fprintf(stderr, CMD ": cannot authenticate with supplied password\n");
        return 2;
    }
    if (param.n_digits > MAX_N_DIGITS)
    {
        // Digit overflow
        fprintf(stderr, CMD ": unsupported TOTP digit count: %u\n", param.n_digits);
        return 2;
    }
    // Init HMAC SHA1 with param key
    HMAC_SHA1_CTX ctx;
    hmac_sha1_init(&ctx, param.key, SHA1_MD_LEN);
    // Moving factor
    uint64_t t = sys_time() / param.period;
    // n_digits
    uint32_t n_digits = param.n_digits;
    // Wipe param
    totp_param_wipe(&param);
    // Generate code
    uint32_t code = totp_sha1_gen(&ctx, t);
    // Truncate code to param n_digits and print
    char code_str[MAX_N_DIGITS + 1] = {};
    totp_code_str(code_str, code, n_digits);
    printf("%s\n", code_str);
    // Wipe code
    memset(code_str, 0, sizeof(code_str));
    // OK
    return 0;
}
