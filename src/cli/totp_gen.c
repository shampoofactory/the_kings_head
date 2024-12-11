#include "totp_core.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CMD "totpgen"

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
    // TOTP PARAM
    // SECRET: "12345678901234567890"                       TEXT
    //       : 3132333435363738393031323334353637383930     AS HEX
    //       : GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ             AS BASE32
    // DIGITS: 8
    // PERIOD: 30
    // ALGORITHM: SHA1
    //
    // TEST ONLINE:
    // https://piellardj.github.io/totp-generator/?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8&period=30&algorithm=SHA-1

    // TOTP PARAM
    char *key = "12345678901234567890";
    uint32_t key_len = strlen(key);
    uint32_t n_digits = 8;
    uint32_t period = 30;

    // PBKDF2 ENCRYPT PARAM
    char *pass = "SaturnV";
    uint64_t iter = 1000000;

    // Create parameters
    TotpParam param = totp_param_with((uint8_t *)key, key_len, n_digits, period);
    // Generate unique cipher key
    TotpKeys keys = totp_keys_gen((uint8_t *)pass, strlen(pass), iter, NULL);
    // Encrypt parameters
    TotpBlk blk = totp_blk_encrypt(&param, &keys);
    totp_keys_wipe(&keys);
    totp_param_wipe(&param);
    // Decrypt parameters and validate
    bool is_ok = totp_blk_decrypt(&blk, &param, (uint8_t *)pass, strlen(pass)) &&
                 !memcmp(param.key, key, SHA1_MD_LEN) &&
                 param.n_digits == n_digits &&
                 param.period == period;
    totp_param_wipe(&param);
    if (is_ok)
    {
        // OK dump blk hex string
        hex(&blk, sizeof(blk));
    }
    else
    {
        // ERROR
        fprintf(stderr, CMD ": internal error\n");
    }
    totp_blk_wipe(&blk);
    return is_ok ? 0 : 1;
}
