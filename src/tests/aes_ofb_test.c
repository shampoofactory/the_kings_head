#include "aes_ofb_test.h"

#include <stdlib.h>

#include "CUnit/Basic.h"

#include "bytes.h"
#include "rsp.h"
#include "aes_core.h"

#define CAVP "res/cavp/aesmmt/"
#define KATG "res/katg/aesmmt/"
#define RDR_LEN 0x100000

static void sha_check(char *filename)
{
    RSP rsp = rsp_create(RDR_LEN);
    AESCore core = aes_core_256_ofb_create();
    CU_ASSERT(rsp_execute(&rsp, (RSPCore *)&core, filename));
    aes_core_destroy(&core);
    rsp_destroy(&rsp);
}

static void test_aes256_ofb() { sha_check(CAVP "OFBMMT256.rsp"); }
static void test_aes256_ofb_small() { sha_check(KATG "OFBMMT256SMALL.rsp"); }

static int
init_suite(void)
{
    return 0;
}

static int clean_suite(void)
{
    return 0;
}

bool add_tests_aes_ofb()
{
    CU_pSuite pSuite = NULL;
    pSuite = CU_add_suite("AESOFB", init_suite, clean_suite);
    return NULL != pSuite &&
           NULL != CU_add_test(pSuite, "AES256_OFB", test_aes256_ofb) &&
           NULL != CU_add_test(pSuite, "AES256_OFB_SMALL", test_aes256_ofb_small);
}
