#include <stdio.h>

#include <CUnit/Basic.h>

#include "aes_ofb_test.h"
#include "hmac_sha1_test.h"
#include "pbkdf2_hmac_sha1_test.h"
#include "sha1_test.h"
#include "totp_test.h"

int main(int argc, char **argv)
{
    if (CUE_SUCCESS == CU_initialize_registry())
    {
        if (add_tests_aes_ofb() &&
            add_tests_hmac_sha1() &&
            add_tests_pbkdf2_hmac_sha1() &&
            add_tests_sha1() &&
            add_tests_totp())
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
