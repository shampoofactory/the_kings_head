#include "hmac_sha1_test.h"

#include <stdlib.h>

#include "CUnit/Basic.h"

#include "bytes.h"
#include "hmac_sha1.h"

#define MAX_BUF_LEN 0x1000

static bool hmac_sha1_check(char *key_hex, char *msg_hex, char *emd_hex)
{
    uint8_t key_buf[MAX_BUF_LEN] = {};
    uint8_t msg_buf[MAX_BUF_LEN] = {};
    uint8_t emd_buf[SHA1_MD_LEN] = {};
    uint8_t md_buf[SHA1_MD_LEN] = {};
    Bytes key = bytes_with(key_buf, MAX_BUF_LEN);
    Bytes msg = bytes_with(msg_buf, MAX_BUF_LEN);
    Bytes emd = bytes_with(emd_buf, SHA1_MD_LEN);
    Bytes md = bytes_with(md_buf, SHA1_MD_LEN);
    bytes_parse_hex(bytes_str(key_hex), &key);
    bytes_parse_hex(bytes_str(msg_hex), &msg);
    bytes_parse_hex(bytes_str(emd_hex), &emd);
    HMAC_SHA1_CTX ctx;
    hmac_sha1_init(&ctx, key.ptr, key.len);
    hmac_sha1_update(&ctx, msg.ptr, msg.len);
    hmac_sha1_final(&ctx, md_buf);
    return bytes_equal(md, emd);
}

/*
IETF RFC 2202
Test Cases for HMAC-SHA-1
https://www.ietf.org/rfc/rfc2202.txt
*/

static void test_hmac_sha1_1()
{
    CU_ASSERT(hmac_sha1_check(
        "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
        "4869205468657265",
        "b617318655057264e28bc0b6fb378c8ef146be00"));
}

static void test_hmac_sha1_2()
{
    CU_ASSERT(hmac_sha1_check(
        "4a656665",
        "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
        "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"));
}

static void test_hmac_sha1_3()
{
    CU_ASSERT(hmac_sha1_check(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "dddddddddddddddddddddddddddddddddddddddddddddddddd"
        "dddddddddddddddddddddddddddddddddddddddddddddddddd",
        "125d7342b9ac11cd91a39af48aa17b4f63f175d3"));
}

static void test_hmac_sha1_4()
{
    CU_ASSERT(hmac_sha1_check(
        "0102030405060708090a0b0c0d0e0f10111213141516171819",
        "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
        "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
        "4c9007f4026250c6bc8414f9bf50c86c2d7235da"));
}

static void test_hmac_sha1_5()
{
    CU_ASSERT(hmac_sha1_check(
        "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
        "546573742057697468205472756e636174696f6e",
        "4c1a03424b55e07fe7f27be1d58bb9324a9a5a04"));
}

static void test_hmac_sha1_6()
{
    CU_ASSERT(hmac_sha1_check(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d20"
        "48617368204b6579204669727374",
        "aa4ae5e15272d00e95705637ce8a3b55ed402112"));
}

static void test_hmac_sha1_7()
{
    CU_ASSERT(hmac_sha1_check(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b657920616e"
        "64204c6172676572205468616e204f6e6520426c6f636b2d53697a652044617461",
        "e8e99d0f45237d786d6bbaa7965c7808bbff1a91"));
}

static int init_suite(void)
{
    return 0;
}

static int clean_suite(void)
{
    return 0;
}

bool add_tests_hmac_sha1()
{
    CU_pSuite pSuite = NULL;
    pSuite = CU_add_suite("SHA1", init_suite, clean_suite);
    return NULL != pSuite &&
           NULL != CU_add_test(pSuite, "HMAC_SHA1_1", test_hmac_sha1_1) &&
           NULL != CU_add_test(pSuite, "HMAC_SHA1_2", test_hmac_sha1_2) &&
           NULL != CU_add_test(pSuite, "HMAC_SHA1_3", test_hmac_sha1_3) &&
           NULL != CU_add_test(pSuite, "HMAC_SHA1_4", test_hmac_sha1_4) &&
           NULL != CU_add_test(pSuite, "HMAC_SHA1_5", test_hmac_sha1_5) &&
           NULL != CU_add_test(pSuite, "HMAC_SHA1_6", test_hmac_sha1_6) &&
           NULL != CU_add_test(pSuite, "HMAC_SHA1_7", test_hmac_sha1_7);
}
