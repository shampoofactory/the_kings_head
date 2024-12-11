#include "sha1_test.h"

#include <stdlib.h>

#include "CUnit/Basic.h"

#include "bytes.h"
#include "rsp.h"
#include "sha1_core.h"

#define CAVP "res/cavp/shabytetestvectors/"
#define RDR_LEN 0x100000

static void test_sha1_permutations()
{
    const size_t MSG_LEN = 163;
    char *msg_hex =
        "7c9c67323a1df1adbfe5ceb415eaef0155ece2820f4d50c1ec22cba4928ac656c83fe585db6a78ce"
        "40bc42757aba7e5a3f582428d6ca68d0c3978336a6efb729613e8d9979016204bfd921322fdd5222"
        "183554447de5e6e9bbe6edf76d7b71e18dc2e8d6dc89b7398364f652fafc734329aafa3dcd45d4f3"
        "1e388e4fafd7fc6495f37ca5cbab7f54d586463da4bfeaa3bae09f7b8e9239d832b4f0a733aa609c"
        "c1f8d4";
    char *emd_hex =
        "d8fd6a91ef3b6ced05b98358a99107c1fac8c807";
    uint8_t msg[MSG_LEN];
    Bytes msg_bytes = bytes_with(msg, MSG_LEN);
    bytes_parse_hex(bytes_str(msg_hex), &msg_bytes);
    uint8_t emd[SHA1_MD_LEN];
    Bytes emd_bytes = bytes_with(emd, SHA1_MD_LEN);
    bytes_parse_hex(bytes_str(emd_hex), &emd_bytes);
    SHA1_CTX ctx;
    sha1_init(&ctx);
    for (size_t i = 0; i <= MSG_LEN - 16; i++)
    {
        for (size_t j = 0; j <= 16; j++)
        {
            uint8_t md[SHA1_MD_LEN];
            Bytes md_bytes = bytes_with(md, SHA1_MD_LEN);
            CU_ASSERT(sha1_update(&ctx, msg, i));
            CU_ASSERT(sha1_update(&ctx, msg + i, j));
            CU_ASSERT(sha1_update(&ctx, msg + i + j, MSG_LEN - i - j));
            sha1_final(&ctx, md);
            CU_ASSERT(bytes_equal(md_bytes, emd_bytes));
        }
    }
}

static void sha1_check(char *filename)
{
    RSP rsp = rsp_create(RDR_LEN);
    SHA1Core core = sha1_core_create();
    CU_ASSERT(rsp_execute(&rsp, (RSPCore *)&core, filename));
    sha1_core_destroy(&core);
    rsp_destroy(&rsp);
}

static void test_sha1_short()
{
    sha1_check(CAVP "SHA1ShortMsg.rsp");
}

static void test_sha1_long()
{
    sha1_check(CAVP "SHA1LongMsg.rsp");
}

static int init_suite(void)
{
    return 0;
}

static int clean_suite(void)
{
    return 0;
}

bool add_tests_sha1()
{
    CU_pSuite pSuite = NULL;
    pSuite = CU_add_suite("SHA1", init_suite, clean_suite);
    return NULL != pSuite &&
           NULL != CU_add_test(pSuite, "SHA1_S", test_sha1_short) &&
           NULL != CU_add_test(pSuite, "SHA1_L", test_sha1_long) &&
           NULL != CU_add_test(pSuite, "SHA1_Permutations", test_sha1_permutations);
}
