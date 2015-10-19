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

static void assert_pam_test(enum pamtest_err perr,
                            const enum pamtest_err perr_exp,
                            struct pamtest_case *tests)
{
    const struct pamtest_case *tc;

    if (perr != perr_exp) {
        tc = pamtest_failed_case(tests);
        if (tc == NULL) {
            /* Probably pam_start/pam_end failed..*/
            fail_msg("PAM test with pamtest err %d\n", perr);
        }

        /* FIXME - would be nice to print index..*/
        fail_msg("PAM test expected %d returned %d\n",
                 tc->expected_rv, tc->op_rv);
    }
}

static char *service_arg(TALLOC_CTX *mem_ctx,
                         const char *src_file,
                         const char *dst_file,
                         const char *arg)
{
    TALLOC_CTX *tmp_ctx;
    const char *dir;
    char *dst;
    char *src;
    errno_t ret;
    struct stat sb;
    char *svc;
    int src_fd = -1;
    FILE *dst_f = NULL;
    ssize_t nb;
    char *line;
    size_t nlines = 0;
    size_t i;

    dir = getenv("PWRAP_TEST_CONF_DIR");
    if (dir == NULL) {
        return NULL;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return NULL;
    }

    src = talloc_asprintf(tmp_ctx, "%s/%s", dir, src_file);
    dst = talloc_asprintf(tmp_ctx, "%s/%s", dir, dst_file);
    if (dst == NULL || src == NULL) {
        goto fail;
    }

    ret = stat(src, &sb);
    if (ret == -1) {
        goto fail;
    }

    svc = talloc_size(tmp_ctx, sb.st_size); /* This is OK, the file is small..*/
    if (svc == NULL) {
        goto fail;
    }

    src_fd = open(src, O_RDONLY);
    if (src_fd == -1) {
        goto fail;
    }

    dst_f = fopen(dst, "w");
    if (dst_f == NULL) {
        goto fail;
    }

    nb = sss_atomic_read_s(src_fd, svc, sb.st_size);
    if (nb < sb.st_size) {
        goto fail;
    }

    line = strchr(svc, '\n');
    while (line != NULL) {
        *line = '\0';
        line++;
        nlines++;

        line = strchr(line, '\n');
    }

    line = svc;
    for (i = 0; i < nlines; i++) {
        nb = fprintf(dst_f, "%s %s\n", line, arg);
        if (nb < 0) {
            goto fail;
        }
        line += strlen(line) + 1;
    }

    ret = EOK;
    fflush(dst_f);
    fclose(dst_f);
    talloc_steal(mem_ctx, dst);
    return dst;
fail:
    if (dst_f) {
        fclose(dst_f);
    }
    talloc_free(tmp_ctx);
    return NULL;
}

struct test_svc {
    const char *svc_file;
};

static int setup_svc(void **state)
{
    struct test_svc *svc;

    svc = talloc_zero(NULL, struct test_svc);
    if (svc == NULL) {
        return 1;
    }

    *state = svc;
    return 0;
}

static int teardown_svc(void **state)
{
    struct test_svc *svc = talloc_get_type(*state, struct test_svc);

    if (svc != NULL && svc->svc_file != NULL) {
        unlink(svc->svc_file);
    }
    return 0;
}

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
    assert_pam_test(perr, PAMTEST_ERR_OK, tests);
}

static void test_pam_authenticate_root(void **state)
{
    enum pamtest_err perr;
    struct pamtest_case tests[] = {
        { PAMTEST_AUTHENTICATE, PAM_USER_UNKNOWN, 0, 0 },
        { PAMTEST_SENTINEL, 0, 0, 0 },
    };

    (void) state;	/* unused */

    perr = pamtest("test_pam_sss_ignore", "root", NULL, tests);
    assert_pam_test(perr, PAMTEST_ERR_OK, tests);
}

static void test_pam_authenticate_root_ignore(void **state)
{
    struct test_svc *svc = talloc_get_type(*state, struct test_svc);
    enum pamtest_err perr;
    struct pamtest_case tests[] = {
        { PAMTEST_AUTHENTICATE, PAM_IGNORE, 0, 0 },
        { PAMTEST_SENTINEL, 0, 0, 0 },
    };
    const char *svcname = "test_pam_sss_ignore_arg";

    /* Copy file from the previous test and just add an argument. The retval
     * will be different this time
     */
    svc->svc_file = service_arg(svc, "test_pam_sss_ignore",
                                svcname, "ignore_unknown_user");
    assert_non_null(svc->svc_file);

    perr = pamtest(svcname, "root", NULL, tests);
    assert_pam_test(perr, PAMTEST_ERR_OK, tests);
}

static void test_pam_authenticate_domains(void **state)
{
    struct test_svc *svc = talloc_get_type(*state, struct test_svc);
    enum pamtest_err perr;
    const char *authtoks[] = {
        "secret",
        NULL,
    };
    struct pamtest_case tests[] = {
        { PAMTEST_AUTHENTICATE, PAM_SUCCESS, 0, 0 },
        { PAMTEST_SENTINEL, 0, 0, 0 },
    };
    const char *svcname = "test_pam_sss_domains";

    /* Copy file from the previous test and just add an argument. The retval
     * will be different this time
     */
    svc->svc_file = service_arg(svc, "test_pam_sss",
                                svcname, "domains=mydomain");
    assert_non_null(svc->svc_file);

    perr = pamtest(svcname, "domtest", authtoks, tests);
    assert_pam_test(perr, PAMTEST_ERR_OK, tests);
}

static void test_pam_authenticate_domains_err(void **state)
{
    struct test_svc *svc = talloc_get_type(*state, struct test_svc);
    enum pamtest_err perr;
    struct pamtest_case tests[] = {
        { PAMTEST_AUTHENTICATE, PAM_SYSTEM_ERR, 0, 0 },
        { PAMTEST_SENTINEL, 0, 0, 0 },
    };
    const char *svcname = "test_pam_sss_domains_err";

    /* Copy file from the previous test and just add an argument. The retval
     * will be different this time
     */
    svc->svc_file = service_arg(svc, "test_pam_sss",
                                svcname, "domains=");
    assert_non_null(svc->svc_file);

    perr = pamtest(svcname, "domtest", NULL, tests);
    assert_pam_test(perr, PAMTEST_ERR_OK, tests);
}

static void test_pam_authenticate_retry(void **state)
{
    struct test_svc *svc = talloc_get_type(*state, struct test_svc);
    enum pamtest_err perr;
    const char *authtoks[] = {
        "wrong_secret",
        "retried_secret",
        NULL,
    };
    struct pamtest_case tests[] = {
        { PAMTEST_AUTHENTICATE, PAM_SUCCESS, 0, 0 },
        { PAMTEST_SENTINEL, 0, 0, 0 },
    };
    const char *svcname = "test_pam_sss_retry";

    /* Copy file from the previous test and just add an argument. The retval
     * will be different this time
     */
    svc->svc_file = service_arg(svc, "test_pam_sss",
                                svcname, "retry=1");
    assert_non_null(svc->svc_file);

    perr = pamtest(svcname, "retrytest", authtoks, tests);
    assert_pam_test(perr, PAMTEST_ERR_OK, tests);
}

static void test_pam_authenticate_retry_neg(void **state)
{
    struct test_svc *svc = talloc_get_type(*state, struct test_svc);
    enum pamtest_err perr;
    const char *authtoks[] = {
        "wrong_secret",
        "retried_secret",
        NULL,
    };
    struct pamtest_case tests[] = {
        { PAMTEST_AUTHENTICATE, PAM_AUTH_ERR, 0, 0 },
        { PAMTEST_SENTINEL, 0, 0, 0 },
    };
    const char *svcname = "test_pam_sss_retry";

    /* Copy file from the previous test and just add an argument. The retval
     * will be different this time
     */
    svc->svc_file = service_arg(svc, "test_pam_sss",
                                svcname, "retry=-1");
    assert_non_null(svc->svc_file);

    perr = pamtest(svcname, "retrytest", authtoks, tests);
    assert_pam_test(perr, PAMTEST_ERR_OK, tests);
}

static void test_pam_authenticate_retry_eparse(void **state)
{
    struct test_svc *svc = talloc_get_type(*state, struct test_svc);
    enum pamtest_err perr;
    const char *authtoks[] = {
        "wrong_secret",
        "retried_secret",
        NULL,
    };
    struct pamtest_case tests[] = {
        { PAMTEST_AUTHENTICATE, PAM_AUTH_ERR, 0, 0 },
        { PAMTEST_SENTINEL, 0, 0, 0 },
    };
    const char *svcname = "test_pam_sss_retry";

    /* Copy file from the previous test and just add an argument. The retval
     * will be different this time
     */
    svc->svc_file = service_arg(svc, "test_pam_sss",
                                svcname, "retry=");
    assert_non_null(svc->svc_file);

    perr = pamtest(svcname, "retrytest", authtoks, tests);
    assert_pam_test(perr, PAMTEST_ERR_OK, tests);
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
        cmocka_unit_test(test_pam_authenticate_root),
        cmocka_unit_test_setup_teardown(test_pam_authenticate_root_ignore,
                                        setup_svc,
                                        teardown_svc),
        cmocka_unit_test_setup_teardown(test_pam_authenticate_domains,
                                        setup_svc,
                                        teardown_svc),
        cmocka_unit_test_setup_teardown(test_pam_authenticate_domains_err,
                                        setup_svc,
                                        teardown_svc),
        cmocka_unit_test_setup_teardown(test_pam_authenticate_retry,
                                        setup_svc,
                                        teardown_svc),
        cmocka_unit_test_setup_teardown(test_pam_authenticate_retry_neg,
                                        setup_svc,
                                        teardown_svc),
        cmocka_unit_test_setup_teardown(test_pam_authenticate_retry_eparse,
                                        setup_svc,
                                        teardown_svc),
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

    setenv("PAM_WRAPPER", "1", 1);
    return cmocka_run_group_tests(tests, NULL, NULL);
}
