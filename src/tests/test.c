#include "test.h"

static bool totp_sha1(char *code, char *key, uint64_t ts, uint32_t n_digits, uint32_t period)
{
    static size_t BUF_LEN = 0x10;
    if (BUF_LEN < n_digits)
    {
        return false;
    }
    uint8_t buf[BUF_LEN];
    Bytes code_out = bytes_with(buf, n_digits);
    Bytes code_in = bytes_str(code);
    uint64_t t = ts / period;
    uint32_t v = totp_sha1_gen((uint8_t *)key, (uint32_t)strlen(key), t);
    totp_code_str((char *)code_out.ptr, v, n_digits);
    return bytes_equal(code_in, code_out);
}

static void test_totp_sha1(char *code, char *key, uint64_t ts, uint32_t n_digits, uint32_t period)
{
    CU_ASSERT(totp_sha1(code, key, ts, n_digits, period));
}

static int init_suite(void) { return 0; }

static int clean_suite(void) { return 0; }

static void sha1_1() { test_totp_sha1("94287082", "12345678901234567890", 59, 8, 30); }
static void sha1_2() { test_totp_sha1("07081804", "12345678901234567890", 1111111109, 8, 30); }
static void sha1_3() { test_totp_sha1("14050471", "12345678901234567890", 1111111111, 8, 30); }
static void sha1_4() { test_totp_sha1("89005924", "12345678901234567890", 1234567890, 8, 30); }
static void sha1_5() { test_totp_sha1("69279037", "12345678901234567890", 2000000000, 8, 30); }
static void sha1_6() { test_totp_sha1("65353130", "12345678901234567890", 20000000000, 8, 30); }

static bool add_tests_totp_sha1()
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

int main(int argc, char **argv)
{
    if (CUE_SUCCESS == CU_initialize_registry())
    {
        if (add_tests_totp_sha1())
        {
            CU_basic_set_mode(CU_BRM_VERBOSE);
            CU_basic_run_tests();
        }
        else
        {
            printf("Error: %d", CU_get_error());
        }
        CU_cleanup_registry();
    }
    return CU_get_error();
}
