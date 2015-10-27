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

/* Correct testuser's authtok */
static const char *authtoks[] = {
    "secret",
    NULL,
};

/* Correct testuser's old and two new authtoks */
static const char *chauthtoks[] = {
    "secret",
    "new_secret",
    "new_secret",
    NULL,
};

static const char *wrong_authtoks[] = {
    "wrong_secret",
    NULL,
};

/* First authtok is wrong, second one is correct */
static const char *retry_authtoks[] = {
    "wrong_secret",
    "retried_secret",
    NULL,
};

static const char *otp_authtoks[] = {
    "secret",
    "1234",
    NULL,
};

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
        if (strstr(line, "pam_test_sss") != NULL && arg != NULL) {
            nb = fprintf(dst_f, "%s %s\n", line, arg);
        } else {
            nb = fprintf(dst_f, "%s\n", line);
        }
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

static char *copy_service(TALLOC_CTX *mem_ctx,
                          const char *src_file,
                          const char *dst_file)
{
    return service_arg(mem_ctx, src_file, dst_file, NULL);
}

struct test_svc {
    const char *svc_file;
};

static const char *find_string_in_list(char **list, const char *key)
{
    char key_eq[strlen(key)+1+1]; /* trailing NULL and '=' */

    if (list == NULL || key == NULL) {
        return NULL;
    }

    snprintf(key_eq, sizeof(key_eq), "%s=", key);
    for (size_t i = 0; list[i] != NULL; i++) {
        if (strncmp(list[i], key_eq, sizeof(key_eq)-1) == 0) {
            return list[i] + sizeof(key_eq)-1;
        }
    }

    return NULL;
}

static void assert_in_env(struct pamtest_case *test,
                          const char *key,
                          const char *val)
{
    const char *v;

    v = find_string_in_list(test->case_out.envlist, key);
    assert_non_null(v);
    assert_string_equal(v, val);
}

static void assert_not_in_env(struct pamtest_case *test,
                              const char *key)
{
    const char *v;

    v = find_string_in_list(test->case_out.envlist, key);
    assert_null(v);
}

enum pamtest_err pamtest_cloc(const char *service,
                              const char *user,
                              struct pamtest_conv_data *conv_data,
                              struct pamtest_case *test_cases)
{
    char *locale;
    enum pamtest_err perr;

    locale = setlocale(LC_ALL, NULL);
    setlocale(LC_ALL, "C");
    perr = pamtest(service, user, conv_data, test_cases);
    setlocale(LC_ALL, locale);

    return perr;
}

static void test_auth_conv(const char *svc,
                           const char *username,
                           int auth_opcode,
                           char *auth_info_msg)
{
    enum pamtest_err perr;
    struct pamtest_conv_data conv_data;
    char *info_arr[] = {
        auth_info_msg,
        NULL,
    };
    const char *authtoks[] = {
        "secret",
        NULL,
    };
    struct pamtest_case tests[] = {
        { PAMTEST_AUTHENTICATE, auth_opcode, PAMTEST_CASE_INIT },
        { PAMTEST_CASE_SENTINEL },
    };

    ZERO_STRUCT(conv_data);
    conv_data.in_echo_off = authtoks;
    conv_data.out_info = info_arr;

    perr = pamtest_cloc(svc, username, &conv_data, tests);
    assert_pam_test(perr, PAMTEST_ERR_OK, tests);
}

static void test_chpass_conv(const char *svc,
                             const char *username,
                             int exp_opcode,
                             char *chpass_info_msg)
{
    enum pamtest_err perr;
    struct pamtest_conv_data conv_data;
    char *info_arr[] = {
        chpass_info_msg,
        NULL,
    };
    struct pamtest_case tests[] = {
        { PAMTEST_CHAUTHTOK, exp_opcode, PAMTEST_CASE_INIT },
        { PAMTEST_CASE_SENTINEL },
    };

    ZERO_STRUCT(conv_data);
    conv_data.in_echo_off = chauthtoks;
    conv_data.out_info = info_arr;

    perr = pamtest_cloc(svc, username, &conv_data, tests);
    assert_pam_test(perr, PAMTEST_ERR_OK, tests);
}

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
    struct pamtest_conv_data conv_data;
    struct pamtest_case tests[] = {
        { PAMTEST_AUTHENTICATE, PAM_SUCCESS, PAMTEST_CASE_INIT },
        { PAMTEST_SETCRED, PAM_SUCCESS, PAMTEST_CASE_INIT },
        { PAMTEST_GETENVLIST, PAM_SUCCESS, PAMTEST_CASE_INIT },
        { PAMTEST_OPEN_SESSION, PAM_SUCCESS, PAMTEST_CASE_INIT },
        { PAMTEST_GETENVLIST, PAM_SUCCESS, PAMTEST_CASE_INIT },
        { PAMTEST_CLOSE_SESSION, PAM_SUCCESS, PAMTEST_CASE_INIT },
        { PAMTEST_GETENVLIST, PAM_SUCCESS, PAMTEST_CASE_INIT },
        { PAMTEST_CASE_SENTINEL },
    };

    (void) state;       /* unused */

    ZERO_STRUCT(conv_data);
    conv_data.in_echo_off = authtoks;

    perr = pamtest("test_pam_sss", "testuser", &conv_data, tests);
    assert_pam_test(perr, PAMTEST_ERR_OK, tests);

    assert_not_in_env(&tests[0], "CREDS");
    assert_not_in_env(&tests[0], "SESSION");

    assert_in_env(&tests[2], "CREDS", "set");
    assert_not_in_env(&tests[2], "SESSION");

    assert_in_env(&tests[4], "CREDS", "set");
    assert_in_env(&tests[4], "SESSION", "open");
}

static void test_pam_authenticate_offline(void **state)
{
    char auth_info_msg[PAM_MAX_MSG_SIZE] = { '\0' };

    (void) state;       /* unused */

    test_auth_conv("test_pam_sss", "offlineuser", PAM_SUCCESS, auth_info_msg);
    assert_string_equal(auth_info_msg,
                        "Authenticated with cached credentials, " \
                        "your cached password will expire at: " \
                        "Thu Jan  1 01:02:03 1970.");
}

static void test_pam_authenticate_offline_err(void **state)
{
    enum pamtest_err perr;
    struct pamtest_conv_data conv_data;
    char auth_info_msg[PAM_MAX_MSG_SIZE] = { '\0' };
    char *info_arr[] = {
        auth_info_msg,
        NULL,
    };
    struct pamtest_case tests[] = {
        { PAMTEST_AUTHENTICATE, PAM_AUTH_ERR, PAMTEST_CASE_INIT },
        { PAMTEST_CASE_SENTINEL },
    };

    (void) state;       /* unused */

    ZERO_STRUCT(conv_data);
    conv_data.in_echo_off = wrong_authtoks;
    conv_data.out_info = info_arr;

    perr = pamtest_cloc("test_pam_sss", "offlineuser", &conv_data, tests);
    assert_pam_test(perr, PAMTEST_ERR_OK, tests);

    assert_string_equal(auth_info_msg,
                        "Authentication is denied until: " \
                        "Thu Jan  1 01:07:36 1970.");
}

static void test_pam_chpass_offline_msg(void **state)
{
    char chpass_info_msg[PAM_MAX_MSG_SIZE] = { '\0' };

    (void) state;       /* unused */

    test_chpass_conv("test_pam_sss", "offlinechpass", PAM_AUTH_ERR, chpass_info_msg);
    assert_string_equal(chpass_info_msg,
                        "System is offline, password change not possible");
}

static void test_pam_chpass_srv_msg(void **state)
{
    char chpass_info_msg[PAM_MAX_MSG_SIZE] = { '\0' };

    (void) state;       /* unused */

    test_chpass_conv("test_pam_sss", "srvchpass", PAM_AUTH_ERR, chpass_info_msg);
    assert_string_equal(chpass_info_msg,
                        "Password change failed. Server message: Test server message");
}

static void test_pam_auth_grace_msg(void **state)
{
    char auth_info_msg[PAM_MAX_MSG_SIZE] = { '\0' };

    (void) state;       /* unused */

    test_auth_conv("test_pam_sss", "gracelogin", PAM_SUCCESS, auth_info_msg);
    assert_string_equal(auth_info_msg,
                        "Your password has expired. " \
                        "You have 1 grace login(s) remaining.");
}

static void test_pam_auth_expire_sec_msg(void **state)
{
    char auth_info_msg[PAM_MAX_MSG_SIZE] = { '\0' };

    (void) state;       /* unused */

    test_auth_conv("test_pam_sss", "expirelogin_sec", PAM_SUCCESS, auth_info_msg);
    assert_string_equal(auth_info_msg,
                        "Your password will expire in 1 second(s).");
}

static void test_pam_auth_expire_min_msg(void **state)
{
    char auth_info_msg[PAM_MAX_MSG_SIZE] = { '\0' };

    (void) state;       /* unused */

    test_auth_conv("test_pam_sss", "expirelogin_min", PAM_SUCCESS, auth_info_msg);
    assert_string_equal(auth_info_msg,
                        "Your password will expire in 1 minute(s).");
}

static void test_pam_auth_expire_hour_msg(void **state)
{
    char auth_info_msg[PAM_MAX_MSG_SIZE] = { '\0' };

    (void) state;       /* unused */

    test_auth_conv("test_pam_sss", "expirelogin_hour", PAM_SUCCESS, auth_info_msg);
    assert_string_equal(auth_info_msg,
                        "Your password will expire in 1 hour(s).");
}

static void test_pam_auth_expire_day_msg(void **state)
{
    char auth_info_msg[PAM_MAX_MSG_SIZE] = { '\0' };

    (void) state;       /* unused */

    test_auth_conv("test_pam_sss", "expirelogin_day", PAM_SUCCESS, auth_info_msg);
    assert_string_equal(auth_info_msg,
                        "Your password will expire in 1 day(s).");
}

static void test_pam_authenticate_err(void **state)
{
    enum pamtest_err perr;
    struct pamtest_conv_data conv_data;
    struct pamtest_case tests[] = {
        { PAMTEST_AUTHENTICATE, PAM_AUTH_ERR, PAMTEST_CASE_INIT },
        { PAMTEST_CASE_SENTINEL },
    };

    (void) state;       /* unused */

    ZERO_STRUCT(conv_data);
    conv_data.in_echo_off = wrong_authtoks;

    perr = pamtest("test_pam_sss", "testuser", &conv_data, tests);
    assert_pam_test(perr, PAMTEST_ERR_OK, tests);
}

static void test_pam_acct(void **state)
{
    enum pamtest_err perr;
    struct pamtest_case tests[] = {
        { PAMTEST_ACCOUNT, PAM_SUCCESS, PAMTEST_CASE_INIT },
        { PAMTEST_CASE_SENTINEL },
    };

    (void) state;       /* unused */

    perr = pamtest("test_pam_sss", "allowed_user", NULL, tests);
    assert_pam_test(perr, PAMTEST_ERR_OK, tests);
}

static void test_pam_acct_err(void **state)
{
    enum pamtest_err perr;
    struct pamtest_case tests[] = {
        { PAMTEST_ACCOUNT, PAM_PERM_DENIED, PAMTEST_CASE_INIT },
        { PAMTEST_CASE_SENTINEL },
    };

    (void) state;       /* unused */

    perr = pamtest("test_pam_sss", "denied_user", NULL, tests);
    assert_pam_test(perr, PAMTEST_ERR_OK, tests);
}

static void test_pam_chauthtok(void **state)
{
    enum pamtest_err perr;
    struct pamtest_conv_data conv_data;
    struct pamtest_case tests[] = {
        { PAMTEST_CHAUTHTOK, PAM_SUCCESS, PAMTEST_CASE_INIT },
        { PAMTEST_CASE_SENTINEL },
    };

    (void) state;       /* unused */

    ZERO_STRUCT(conv_data);
    conv_data.in_echo_off = chauthtoks;

    perr = pamtest("test_pam_sss", "testuser", &conv_data, tests);
    assert_pam_test(perr, PAMTEST_ERR_OK, tests);
}

static void test_pam_chauthtok_prelim_fail(void **state)
{
    enum pamtest_err perr;
    struct pamtest_conv_data conv_data;
    struct pamtest_case tests[] = {
        { PAMTEST_CHAUTHTOK, PAM_AUTH_ERR, PAMTEST_CASE_INIT },
        { PAMTEST_CASE_SENTINEL },
    };

    (void) state;       /* unused */

    ZERO_STRUCT(conv_data);
    conv_data.in_echo_off = wrong_authtoks;

    perr = pamtest("test_pam_sss", "testuser", &conv_data, tests);
    assert_pam_test(perr, PAMTEST_ERR_OK, tests);
}

static void test_pam_chauthtok_diff_authtoks(void **state)
{
    enum pamtest_err perr;
    struct pamtest_conv_data conv_data;
    const char *testuser_authtoks[] = {
        "secret",
        "new_secret",
        "different_secret",
        NULL,
    };
    struct pamtest_case tests[] = {
        { PAMTEST_CHAUTHTOK, PAM_CRED_ERR, PAMTEST_CASE_INIT },
        { PAMTEST_CASE_SENTINEL },
    };

    (void) state;       /* unused */

    ZERO_STRUCT(conv_data);
    conv_data.in_echo_off = testuser_authtoks;

    perr = pamtest("test_pam_sss", "testuser", &conv_data, tests);
    assert_pam_test(perr, PAMTEST_ERR_OK, tests);
}

static void test_pam_authenticate_root(void **state)
{
    enum pamtest_err perr;
    struct pamtest_case tests[] = {
        { PAMTEST_AUTHENTICATE, PAM_USER_UNKNOWN, PAMTEST_CASE_INIT },
        { PAMTEST_CASE_SENTINEL },
    };

    (void) state;       /* unused */

    perr = pamtest("test_pam_sss_ignore", "root", NULL, tests);
    assert_pam_test(perr, PAMTEST_ERR_OK, tests);
}

static void test_pam_authenticate_root_ignore(void **state)
{
    struct test_svc *svc = talloc_get_type(*state, struct test_svc);
    enum pamtest_err perr;
    struct pamtest_case tests[] = {
        { PAMTEST_AUTHENTICATE, PAM_IGNORE, PAMTEST_CASE_INIT },
        { PAMTEST_CASE_SENTINEL },
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
    struct pamtest_conv_data conv_data;
    struct pamtest_case tests[] = {
        { PAMTEST_AUTHENTICATE, PAM_SUCCESS, PAMTEST_CASE_INIT },
        { PAMTEST_CASE_SENTINEL },
    };
    const char *svcname = "test_pam_sss_domains";

    /* Copy file from the previous test and just add an argument. The retval
     * will be different this time
     */
    svc->svc_file = service_arg(svc, "test_pam_sss",
                                svcname, "domains=mydomain");
    assert_non_null(svc->svc_file);

    ZERO_STRUCT(conv_data);
    conv_data.in_echo_off = authtoks;

    perr = pamtest(svcname, "domtest", &conv_data, tests);
    assert_pam_test(perr, PAMTEST_ERR_OK, tests);
}

static void test_pam_authenticate_domains_err(void **state)
{
    struct test_svc *svc = talloc_get_type(*state, struct test_svc);
    enum pamtest_err perr;
    struct pamtest_case tests[] = {
        { PAMTEST_AUTHENTICATE, PAM_SYSTEM_ERR, PAMTEST_CASE_INIT },
        { PAMTEST_CASE_SENTINEL },
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
    struct pamtest_conv_data conv_data;
    struct pamtest_case tests[] = {
        { PAMTEST_AUTHENTICATE, PAM_SUCCESS, PAMTEST_CASE_INIT },
        { PAMTEST_CASE_SENTINEL },
    };
    const char *svcname = "test_pam_sss_retry";

    /* Copy file from the previous test and just add an argument. The retval
     * will be different this time
     */
    svc->svc_file = service_arg(svc, "test_pam_sss",
                                svcname, "retry=1");
    assert_non_null(svc->svc_file);

    ZERO_STRUCT(conv_data);
    conv_data.in_echo_off = retry_authtoks;

    perr = pamtest(svcname, "retrytest", &conv_data, tests);
    assert_pam_test(perr, PAMTEST_ERR_OK, tests);
}

static void test_pam_authenticate_retry_neg(void **state)
{
    struct test_svc *svc = talloc_get_type(*state, struct test_svc);
    enum pamtest_err perr;
    struct pamtest_conv_data conv_data;
    struct pamtest_case tests[] = {
        { PAMTEST_AUTHENTICATE, PAM_AUTH_ERR, PAMTEST_CASE_INIT },
        { PAMTEST_CASE_SENTINEL },
    };
    const char *svcname = "test_pam_sss_retry";

    /* Copy file from the previous test and just add an argument. The retval
     * will be different this time
     */
    svc->svc_file = service_arg(svc, "test_pam_sss",
                                svcname, "retry=-1");
    assert_non_null(svc->svc_file);

    ZERO_STRUCT(conv_data);
    conv_data.in_echo_off = retry_authtoks;

    perr = pamtest(svcname, "retrytest", &conv_data, tests);
    assert_pam_test(perr, PAMTEST_ERR_OK, tests);
}

static void test_pam_authenticate_retry_eparse(void **state)
{
    struct test_svc *svc = talloc_get_type(*state, struct test_svc);
    enum pamtest_err perr;
    struct pamtest_conv_data conv_data;
    struct pamtest_case tests[] = {
        { PAMTEST_AUTHENTICATE, PAM_AUTH_ERR, PAMTEST_CASE_INIT },
        { PAMTEST_CASE_SENTINEL },
    };
    const char *svcname = "test_pam_sss_retry";

    /* Copy file from the previous test and just add an argument. The retval
     * will be different this time
     */
    svc->svc_file = service_arg(svc, "test_pam_sss",
                                svcname, "retry=xxx");
    assert_non_null(svc->svc_file);

    ZERO_STRUCT(conv_data);
    conv_data.in_echo_off = retry_authtoks;

    perr = pamtest(svcname, "retrytest", &conv_data, tests);
    assert_pam_test(perr, PAMTEST_ERR_OK, tests);
}

static void test_pam_authenticate_ssh_expire(void **state)
{
    struct test_svc *svc = talloc_get_type(*state, struct test_svc);
    char auth_info_msg[PAM_MAX_MSG_SIZE] = { '\0' };
    const char *svcname = "sshd";

    /* This test only works with sshd service */
    svc->svc_file = copy_service(svc, "test_pam_sss", svcname);
    assert_non_null(svc->svc_file);

    test_auth_conv(svcname, "sshuser", PAM_ACCT_EXPIRED, auth_info_msg);
    assert_string_equal(auth_info_msg,
                        "Permission denied. Server message: " \
                        "SSH user is expired");
}

static void test_pam_authenticate_stack_forward_pass(void **state)
{
    struct test_svc *svc = talloc_get_type(*state, struct test_svc);
    enum pamtest_err perr;
    struct pamtest_conv_data conv_data;
    struct pamtest_case tests[] = {
        { PAMTEST_AUTHENTICATE, PAM_SUCCESS, PAMTEST_CASE_INIT },
        { PAMTEST_GETENVLIST, PAM_SUCCESS, PAMTEST_CASE_INIT },
        { PAMTEST_CASE_SENTINEL },
    };
    const char *svcname = "test_pam_sss_forward";

    /* Copy file from the previous test and just add an argument. The retval
     * will be different this time
     */
    svc->svc_file = service_arg(svc, "test_pam_sss_stack",
                                svcname, "forward_pass");
    assert_non_null(svc->svc_file);

    ZERO_STRUCT(conv_data);
    conv_data.in_echo_off = authtoks;

    /* No authtok passed on w/o forward_pass */
    perr = pamtest("test_pam_sss_stack", "testuser", &conv_data, tests);
    assert_pam_test(perr, PAMTEST_ERR_OK, tests);
    assert_not_in_env(&tests[1], "PAM_AUTHTOK");

    /* Authtok passed on with forward_pass */
    perr = pamtest(svcname, "testuser", &conv_data, tests);
    assert_pam_test(perr, PAMTEST_ERR_OK, tests);
    assert_in_env(&tests[1], "PAM_AUTHTOK", "secret");
}

static void test_pam_authenticate_stack_use_first_pass(void **state)
{
    struct test_svc *svc = talloc_get_type(*state, struct test_svc);
    enum pamtest_err perr;
    struct pamtest_conv_data conv_data;
    struct pamtest_case neg_tests[] = {
        { PAMTEST_AUTHENTICATE, PAM_AUTH_ERR, PAMTEST_CASE_INIT },
        { PAMTEST_CASE_SENTINEL },
    };
    struct pamtest_case tests[] = {
        { PAMTEST_AUTHENTICATE, PAM_SUCCESS, PAMTEST_CASE_INIT },
        { PAMTEST_GETENVLIST, PAM_SUCCESS, PAMTEST_CASE_INIT },
        { PAMTEST_CASE_SENTINEL },
    };
    const char *svcname = "test_pam_sss_use_first_pass";

    /* Copy file from the previous test and just add an argument. The retval
     * will be different this time
     */
    svc->svc_file = service_arg(svc, "test_pam_sss_stack",
                                svcname, "use_first_pass");
    assert_non_null(svc->svc_file);

    ZERO_STRUCT(conv_data);

    /* No authtok passed onto the stack, must error... */
    perr = pamtest(svcname, "testuser", &conv_data, neg_tests);
    assert_pam_test(perr, PAMTEST_ERR_OK, neg_tests);

    /* Authtok passed onto the stack, should be used.. */
    setenv("PAM_AUTHTOK", "secret", 1);
    perr = pamtest(svcname, "testuser", &conv_data, tests);
    unsetenv("PAM_AUTHTOK");
    assert_pam_test(perr, PAMTEST_ERR_OK, tests);
}

static void test_pam_chauthtok_stack_forward_pass(void **state)
{
    struct test_svc *svc = talloc_get_type(*state, struct test_svc);
    enum pamtest_err perr;
    struct pamtest_conv_data conv_data;
    struct pamtest_case tests[] = {
        { PAMTEST_CHAUTHTOK, PAM_SUCCESS, PAMTEST_CASE_INIT },
        { PAMTEST_GETENVLIST, PAM_SUCCESS, PAMTEST_CASE_INIT },
        { PAMTEST_CASE_SENTINEL },
    };
    const char *svcname = "test_pam_sss_forward";

    /* Copy file from the previous test and just add an argument. The retval
     * will be different this time
     */
    svc->svc_file = service_arg(svc, "test_pam_sss_stack",
                                svcname, "forward_pass");
    assert_non_null(svc->svc_file);

    ZERO_STRUCT(conv_data);
    conv_data.in_echo_off = chauthtoks;

    /* No authtok passed on w/o forward_pass */
    perr = pamtest("test_pam_sss_stack", "testuser", &conv_data, tests);
    assert_pam_test(perr, PAMTEST_ERR_OK, tests);
    assert_not_in_env(&tests[1], "PAM_AUTHTOK");

    /* Authtok passed on with forward_pass */
    perr = pamtest(svcname, "testuser", &conv_data, tests);
    assert_pam_test(perr, PAMTEST_ERR_OK, tests);
    assert_in_env(&tests[1], "PAM_AUTHTOK", "new_secret");
}

static void test_pam_chauthtok_stack_use_authtok(void **state)
{
    struct test_svc *svc = talloc_get_type(*state, struct test_svc);
    enum pamtest_err perr;
    struct pamtest_conv_data conv_data;
    struct pamtest_case neg_tests[] = {
        { PAMTEST_CHAUTHTOK, PAM_AUTH_ERR, PAMTEST_CASE_INIT },
        { PAMTEST_CASE_SENTINEL },
    };
    struct pamtest_case tests[] = {
        { PAMTEST_CHAUTHTOK, PAM_SUCCESS, PAMTEST_CASE_INIT },
        { PAMTEST_GETENVLIST, PAM_SUCCESS, PAMTEST_CASE_INIT },
        { PAMTEST_CASE_SENTINEL },
    };
    const char *svcname = "test_pam_sss_use_authtok";

    /* Copy file from the previous test and just add an argument. The retval
     * will be different this time
     */
    svc->svc_file = service_arg(svc, "test_pam_sss_stack",
                                svcname, "use_authtok");
    assert_non_null(svc->svc_file);

    ZERO_STRUCT(conv_data);
    conv_data.in_echo_off = authtoks;

    /* No authtok passed onto the stack, must error... */
    perr = pamtest(svcname, "testuser", &conv_data, neg_tests);
    assert_pam_test(perr, PAMTEST_ERR_OK, tests);

    /* Authtok passed onto the stack, should be used.. */
    setenv("PAM_OLDAUTHTOK", "secret", 1);
    setenv("PAM_AUTHTOK", "new_secret", 1);
    perr = pamtest(svcname, "testuser", &conv_data, tests);
    unsetenv("PAM_AUTHTOK");
    unsetenv("PAM_OLDAUTHTOK");
    assert_pam_test(perr, PAMTEST_ERR_OK, tests);
}

static int setup_otp(void **state)
{
    struct test_svc *svc;
    int rv;
    int fd;
    const char *file = PAM_PREAUTH_INDICATOR;

    rv = setup_svc((void **) &svc);
    if (rv != 0) {
        return rv;
    }

    fd = open(file, O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW,
              0644);
    if (fd < 0) {
        return 1;
    }

    *state = svc;
    return 0;
}

static int teardown_otp(void **state)
{
    struct test_svc *svc = talloc_get_type(*state, struct test_svc);
    int rv;

    rv = teardown_svc((void **) &svc);
    if (rv != 0) {
        return rv;
    }

    unlink(PAM_PREAUTH_INDICATOR);
    return 0;
}

static void test_pam_authenticate_otp_auth(void **state)
{
    struct test_svc *svc = talloc_get_type(*state, struct test_svc);
    enum pamtest_err perr;
    struct pamtest_conv_data conv_data;
    struct pamtest_case tests[] = {
        { PAMTEST_AUTHENTICATE, PAM_SUCCESS, PAMTEST_CASE_INIT },
        { PAMTEST_GETENVLIST, PAM_SUCCESS, PAMTEST_CASE_INIT },
        { PAMTEST_CASE_SENTINEL },
    };
    const char *svcname = "test_pam_sss_otp_auth";

    /* Copy file from the previous test and just add an argument. The retval
     * will be different this time
     */
    svc->svc_file = service_arg(svc, "test_pam_sss",
                                svcname, "use_2fa");
    assert_non_null(svc->svc_file);

    ZERO_STRUCT(conv_data);
    conv_data.in_echo_off = otp_authtoks;

    perr = pamtest(svcname, "otpuser", &conv_data, tests);
    assert_pam_test(perr, PAMTEST_ERR_OK, tests);
    assert_not_in_env(&tests[1], "PAM_AUTHTOK");
}

static void test_pam_authenticate_otp_auth_forward_pass(void **state)
{
    struct test_svc *svc = talloc_get_type(*state, struct test_svc);
    enum pamtest_err perr;
    struct pamtest_conv_data conv_data;
    struct pamtest_case tests[] = {
        { PAMTEST_AUTHENTICATE, PAM_SUCCESS, PAMTEST_CASE_INIT },
        { PAMTEST_GETENVLIST, PAM_SUCCESS, PAMTEST_CASE_INIT },
        { PAMTEST_CASE_SENTINEL },
    };
    const char *svcname = "test_pam_sss_otp_auth";

    /* Copy file from the previous test and just add an argument. The retval
     * will be different this time
     */
    svc->svc_file = service_arg(svc, "test_pam_sss_stack",
                                svcname, "use_2fa forward_pass");
    assert_non_null(svc->svc_file);

    ZERO_STRUCT(conv_data);
    conv_data.in_echo_off = otp_authtoks;

    perr = pamtest(svcname, "otpuser", &conv_data, tests);
    assert_pam_test(perr, PAMTEST_ERR_OK, tests);
    /* Only first factor must be forwarded */
    assert_in_env(&tests[1], "PAM_AUTHTOK", "secret");
}

#if 0
static void test_pam_authenticate_otp_chpass_msg(void **state)
{
    struct test_svc *svc = talloc_get_type(*state, struct test_svc);
    enum pamtest_err perr;
    struct pamtest_conv_data conv_data;
    struct pamtest_case tests[] = {
        { PAMTEST_CHAUTHTOK, PAM_SUCCESS, PAMTEST_CASE_INIT },
        { PAMTEST_GETENVLIST, PAM_SUCCESS, PAMTEST_CASE_INIT },
        { PAMTEST_CASE_SENTINEL },
    };
    const char *svcname = "test_pam_sss_otp_auth";

    /* Copy file from the previous test and just add an argument. The retval
     * will be different this time
     */
    svc->svc_file = service_arg(svc, "test_pam_sss",
                                svcname, "use_2fa");
    assert_non_null(svc->svc_file);

    ZERO_STRUCT(conv_data);
    conv_data.in_echo_off = otp_authtoks;

    perr = pamtest(svcname, "otpuser", &conv_data, tests);
    assert_pam_test(perr, PAMTEST_ERR_OK, tests);
}
#endif

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
        cmocka_unit_test(test_pam_authenticate_offline),
        cmocka_unit_test(test_pam_authenticate_offline_err),
        cmocka_unit_test(test_pam_auth_expire_sec_msg),
        cmocka_unit_test(test_pam_auth_expire_min_msg),
        cmocka_unit_test(test_pam_auth_expire_hour_msg),
        cmocka_unit_test(test_pam_auth_expire_day_msg),
        cmocka_unit_test(test_pam_auth_grace_msg),
        cmocka_unit_test(test_pam_chpass_offline_msg),
        cmocka_unit_test(test_pam_chpass_srv_msg),
        cmocka_unit_test(test_pam_acct),
        cmocka_unit_test(test_pam_acct_err),
        cmocka_unit_test(test_pam_chauthtok),
        cmocka_unit_test(test_pam_chauthtok_prelim_fail),
        cmocka_unit_test(test_pam_chauthtok_diff_authtoks),
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
        cmocka_unit_test_setup_teardown(test_pam_authenticate_ssh_expire,
                                        setup_svc,
                                        teardown_svc),
        cmocka_unit_test_setup_teardown(test_pam_authenticate_stack_forward_pass,
                                        setup_svc,
                                        teardown_svc),
        cmocka_unit_test_setup_teardown(test_pam_authenticate_stack_use_first_pass,
                                        setup_svc,
                                        teardown_svc),
        cmocka_unit_test_setup_teardown(test_pam_chauthtok_stack_forward_pass,
                                        setup_svc,
                                        teardown_svc),
        cmocka_unit_test_setup_teardown(test_pam_chauthtok_stack_use_authtok,
                                        setup_svc,
                                        teardown_svc),
        cmocka_unit_test_setup_teardown(test_pam_authenticate_otp_auth,
                                        setup_otp,
                                        teardown_otp),
        cmocka_unit_test_setup_teardown(test_pam_authenticate_otp_auth_forward_pass,
                                        setup_otp,
                                        teardown_otp),
#if 0
        cmocka_unit_test_setup_teardown(test_pam_authenticate_otp_chpass_msg,
                                        setup_otp,
                                        teardown_otp),
#endif
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
