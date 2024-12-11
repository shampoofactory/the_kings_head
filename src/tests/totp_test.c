#include "totp_test.h"

#include <stdlib.h>
#include <string.h>

#include "CUnit/Basic.h"

#include "hmac_sha1.h"
#include "totp.h"

#define MAX_DIGITS 0x10

static bool test_totp_sha1(char *ecode, char *key, uint64_t ts, uint32_t n_digits, uint32_t period)
{

    if (MAX_DIGITS < n_digits)
    {
        return false;
    }
    char code[MAX_DIGITS + 1] = {};
    HMAC_SHA1_CTX ctx;
    hmac_sha1_init(&ctx, (uint8_t *)key, strlen(key));
    uint32_t v = totp_sha1_gen(&ctx, ts / period);
    totp_code_str(code, v, n_digits);
    return !strcmp(code, ecode);
}

/*
IETF RFC 6238
Test Vectors
https://www.ietf.org/rfc/rfc6238.txt
*/

static void sha1_1() { CU_ASSERT(test_totp_sha1("94287082", "12345678901234567890", 59, 8, 30)); }
static void sha1_2() { CU_ASSERT(test_totp_sha1("07081804", "12345678901234567890", 1111111109, 8, 30)); }
static void sha1_3() { CU_ASSERT(test_totp_sha1("14050471", "12345678901234567890", 1111111111, 8, 30)); }
static void sha1_4() { CU_ASSERT(test_totp_sha1("89005924", "12345678901234567890", 1234567890, 8, 30)); }
static void sha1_5() { CU_ASSERT(test_totp_sha1("69279037", "12345678901234567890", 2000000000, 8, 30)); }
static void sha1_6() { CU_ASSERT(test_totp_sha1("65353130", "12345678901234567890", 20000000000, 8, 30)); }

static int init_suite(void)
{
    return 0;
}

static int clean_suite(void)
{
    return 0;
}

bool add_tests_totp()
{
    CU_pSuite pSuite = NULL;
    pSuite = CU_add_suite("SHA1", init_suite, clean_suite);
    return NULL != pSuite &&
           NULL != CU_add_test(pSuite, "TOTP_SHA1_1", sha1_1) &&
           NULL != CU_add_test(pSuite, "TOTP_SHA1_2", sha1_2) &&
           NULL != CU_add_test(pSuite, "TOTP_SHA1_3", sha1_3) &&
           NULL != CU_add_test(pSuite, "TOTP_SHA1_4", sha1_4) &&
           NULL != CU_add_test(pSuite, "TOTP_SHA1_5", sha1_5) &&
           NULL != CU_add_test(pSuite, "TOTP_SHA1_6", sha1_6);
}
