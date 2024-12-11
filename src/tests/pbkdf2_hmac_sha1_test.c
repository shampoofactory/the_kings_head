#include "pbkdf2_hmac_sha1_test.h"

#include <stdlib.h>

#include "CUnit/Basic.h"

#include "bytes.h"
#include "pbkdf2_hmac_sha1.h"

#define MAX_BUF_LEN 0x1000

static bool pbkdf2_hmac_sha1_check_hex(char *pass_hex, char *salt_hex, uint64_t c, uint32_t dk_len, char *edk_hex)
{
    if (MAX_BUF_LEN < dk_len)
    {
        return false;
    }
    uint8_t pass_buf[MAX_BUF_LEN] = {};
    uint8_t salt_buf[MAX_BUF_LEN] = {};
    uint8_t edk_buf[MAX_BUF_LEN] = {};
    uint8_t dk_buf[MAX_BUF_LEN] = {};
    Bytes pass = bytes_with(pass_buf, MAX_BUF_LEN);
    Bytes salt = bytes_with(salt_buf, MAX_BUF_LEN);
    Bytes edk = bytes_with(edk_buf, dk_len);
    Bytes dk = bytes_with(dk_buf, dk_len);
    bytes_parse_hex(bytes_str(pass_hex), &pass);
    bytes_parse_hex(bytes_str(salt_hex), &salt);
    bytes_parse_hex(bytes_str(edk_hex), &edk);
    return pbkdf2_hmac_sha1(pass.ptr, pass.len, salt.ptr, salt.len, c, dk_len, dk.ptr) &&
           bytes_equal(dk, edk);
}

static bool pbkdf2_hmac_sha1_check_str(char *pass_str, char *salt_str, uint64_t c, uint32_t dk_len, char *edk_hex)
{
    if (dk_len > MAX_BUF_LEN)
    {
        return false;
    }
    Bytes pass = bytes_str(pass_str);
    Bytes salt = bytes_str(salt_str);
    uint8_t edk_buf[MAX_BUF_LEN] = {};
    uint8_t dk_buf[MAX_BUF_LEN] = {};
    Bytes edk = bytes_with(edk_buf, dk_len);
    Bytes dk = bytes_with(dk_buf, dk_len);
    bytes_parse_hex(bytes_str(edk_hex), &edk);
    return pbkdf2_hmac_sha1(pass.ptr, pass.len, salt.ptr, salt.len, c, dk_len, dk.ptr) &&
           bytes_equal(dk, edk);
}

static void test_pbkdf2_hmac_sha1_err()
{
    CU_ASSERT(!pbkdf2_hmac_sha1_check_str(
        "password",
        "salt",
        0,
        20,
        ""));
}

static void test_pbkdf2_hmac_sha1_0()
{
    CU_ASSERT(pbkdf2_hmac_sha1_check_str(
        "password",
        "salt",
        1,
        0,
        ""));
}

/*
IETF RFC 6070
PBKDF2 HMAC-SHA1 Test Vectors
https://www.ietf.org/rfc/rfc6070.txt
*/

static void test_pbkdf2_hmac_sha1_1()
{
    CU_ASSERT(pbkdf2_hmac_sha1_check_str(
        "password",
        "salt",
        1,
        20,
        "0c60c80f961f0e71f3a9b524af6012062fe037a6"));
}

static void test_pbkdf2_hmac_sha1_2()
{
    CU_ASSERT(pbkdf2_hmac_sha1_check_str(
        "password",
        "salt",
        2,
        20,
        "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"));
}

static void test_pbkdf2_hmac_sha1_3()
{
    CU_ASSERT(pbkdf2_hmac_sha1_check_str(
        "password",
        "salt",
        4096,
        20,
        "4b007901b765489abead49d926f721d065a429c1"));
}

static void test_pbkdf2_hmac_sha1_4()
{
    CU_ASSERT(pbkdf2_hmac_sha1_check_str(
        "password",
        "salt",
        16777216,
        20,
        "eefe3d61cd4da4e4e9945b3d6ba2158c2634e984"));
}

static void test_pbkdf2_hmac_sha1_5()
{
    CU_ASSERT(pbkdf2_hmac_sha1_check_str(
        "passwordPASSWORDpassword",
        "saltSALTsaltSALTsaltSALTsaltSALTsalt",
        4096,
        25,
        "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038"));
}

static void test_pbkdf2_hmac_sha1_6()
{
    CU_ASSERT(pbkdf2_hmac_sha1_check_hex(
        "7061737300776f7264",
        "7361006c74",
        4096,
        16,
        "56fa6aa75548099dcc37d7f03425e0c3"));
}

static int init_suite(void)
{
    return 0;
}

static int clean_suite(void)
{
    return 0;
}

bool add_tests_pbkdf2_hmac_sha1()
{
    CU_pSuite pSuite = NULL;
    pSuite = CU_add_suite("SHA1", init_suite, clean_suite);
    return NULL != pSuite &&
           NULL != CU_add_test(pSuite, "PBKDF2_HMAC_SHA1_E", test_pbkdf2_hmac_sha1_err) &&
           NULL != CU_add_test(pSuite, "PBKDF2_HMAC_SHA1_0", test_pbkdf2_hmac_sha1_0) &&
           NULL != CU_add_test(pSuite, "PBKDF2_HMAC_SHA1_1", test_pbkdf2_hmac_sha1_1) &&
           NULL != CU_add_test(pSuite, "PBKDF2_HMAC_SHA1_2", test_pbkdf2_hmac_sha1_2) &&
           NULL != CU_add_test(pSuite, "PBKDF2_HMAC_SHA1_3", test_pbkdf2_hmac_sha1_3) &&
           NULL != CU_add_test(pSuite, "PBKDF2_HMAC_SHA1_4", test_pbkdf2_hmac_sha1_4) &&
           NULL != CU_add_test(pSuite, "PBKDF2_HMAC_SHA1_5", test_pbkdf2_hmac_sha1_5) &&
           NULL != CU_add_test(pSuite, "PBKDF2_HMAC_SHA1_6", test_pbkdf2_hmac_sha1_6);
    ;
}
