/*
    Copyright (C) 2015 Red Hat

    SSSD tests: PAM tests

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <popt.h>
#include <libpamtest.h>

#include "util/util.h"
#include "tests/cmocka/common_mock.h"

static void test_pam_authenticate(void **state)
{
    enum pamtest_err perr;
    const char *testuser_authtoks[] = {
        "secret",
        NULL,
    };
    struct pamtest_case tests[] = {
        { PAMTEST_AUTHENTICATE, PAM_SUCCESS, 0, 0 },
        { PAMTEST_SENTINEL, 0, 0, 0 },
    };

    (void) state;	/* unused */

    perr = pamtest("test_pam_sss", "testuser", testuser_authtoks, tests);
    assert_int_equal(perr, PAMTEST_ERR_OK);
}

static void test_pam_authenticate_err(void **state)
{
    enum pamtest_err perr;
    const char *testuser_authtoks[] = {
        "wrong_secret",
        NULL,
    };
    struct pamtest_case tests[] = {
        { PAMTEST_AUTHENTICATE, PAM_AUTH_ERR, 0, 0 },
        { PAMTEST_SENTINEL, 0, 0, 0 },
    };

    (void) state;	/* unused */

    perr = pamtest("test_pam_sss", "testuser", testuser_authtoks, tests);
    assert_int_equal(perr, PAMTEST_ERR_OK);
}

int main(int argc, const char *argv[])
{
    poptContext pc;
    int opt;
    struct poptOption long_options[] = {
        POPT_AUTOHELP
        SSSD_DEBUG_OPTS
        POPT_TABLEEND
    };

    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_pam_authenticate),
        cmocka_unit_test(test_pam_authenticate_err),
    };

    /* Set debug level to invalid value so we can deside if -d 0 was used. */
    debug_level = SSSDBG_INVALID;

    pc = poptGetContext(argv[0], argc, argv, long_options, 0);
    while((opt = poptGetNextOpt(pc)) != -1) {
        switch(opt) {
        default:
            fprintf(stderr, "\nInvalid option %s: %s\n\n",
                    poptBadOption(pc, 0), poptStrerror(opt));
            poptPrintUsage(pc, stderr, 0);
            return 1;
        }
    }
    poptFreeContext(pc);

    DEBUG_CLI_INIT(debug_level);
    tests_set_cwd();

    return cmocka_run_group_tests(tests, NULL, NULL);
}
