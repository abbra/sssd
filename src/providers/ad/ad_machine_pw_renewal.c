/*
    SSSD

    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2016 Red Hat

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


#include "util/util.h"
#include "util/strtonum.h"
#include "providers/dp_ptask.h"
#include "providers/ad/ad_common.h"

#ifndef RENEWAL_PROG_PATH
#define RENEWAL_PROG_PATH "/usr/sbin/adcli"
#endif

struct renewal_data {
    char *ad_domain;
    char *ad_hostname;
    char *ad_keytab;
    size_t pw_lifetime_in_days;
    size_t period;
    size_t initial_delay;
    char *prog_path;
    const char **extra_args;
};

static errno_t get_adcli_extra_args(struct renewal_data *renewal_data)
{
    const char **args;
    size_t c = 0;

    renewal_data->prog_path = talloc_strdup(renewal_data, RENEWAL_PROG_PATH);
    if (renewal_data->prog_path == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
        return ENOMEM;
    }

    args = talloc_array(renewal_data, const char *, 7);
    if (args == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_array failed.\n");
        return ENOMEM;
    }

    /* extra_args are added in revers order */
    args[c++] = talloc_asprintf(args, "--computer-password-lifetime=%zu",
                                renewal_data->pw_lifetime_in_days);
    args[c++] = talloc_asprintf(args, "--host-fqdn=%s",
                                renewal_data->ad_hostname);
    args[c++] = talloc_asprintf(args, "--host-keytab=%s",
                                renewal_data->ad_keytab);
    args[c++] = talloc_asprintf(args, "--domain=%s", renewal_data->ad_domain);
    if (DEBUG_IS_SET(SSSDBG_TRACE_LIBS)) {
        args[c++] = talloc_strdup(args, "--verbose");
    }
    args[c++] = talloc_strdup(args, "update");
    args[c] = NULL;

    do {
        if (args[--c] == NULL) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "talloc failed while copying  arguments.\n");
            talloc_free(args);
            return ENOMEM;
        }
    } while (c != 0);

    renewal_data->extra_args = args;

    return EOK;
}

struct renewal_state {
    int child_status;
    struct sss_child_ctx_old *child_ctx;
    struct tevent_timer *timeout_handler;
    struct tevent_context *ev;

    int write_to_child_fd;
    int read_from_child_fd;
};

static void ad_machine_account_password_renewal_done(struct tevent_req *subreq);
static void
ad_machine_account_password_renewal_timeout(struct tevent_context *ev,
                                            struct tevent_timer *te,
                                            struct timeval tv, void *pvt);

static struct tevent_req *
ad_machine_account_password_renewal_send(TALLOC_CTX *mem_ctx,
                                  struct tevent_context *ev,
                                  struct be_ctx *be_ctx,
                                  struct be_ptask *be_ptask,
                                  void *pvt)
{
    struct renewal_data *renewal_data;
    struct renewal_state *state;
    struct tevent_req *req;
    struct tevent_req *subreq;
    pid_t child_pid;
    struct timeval tv;
    int pipefd_to_child[2];
    int pipefd_from_child[2];
    int ret;

    req = tevent_req_create(mem_ctx, &state, struct renewal_state);
    if (req == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "tevent_req_create failed.\n");
        return NULL;
    }

    renewal_data = talloc_get_type(pvt, struct renewal_data);

    state->ev = ev;
    state->child_status = EFAULT;
    state->read_from_child_fd = -1;
    state->write_to_child_fd = -1;

    ret = pipe(pipefd_from_child);
    if (ret == -1) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "pipe failed [%d][%s].\n", ret, strerror(ret));
        goto done;
    }
    ret = pipe(pipefd_to_child);
    if (ret == -1) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "pipe failed [%d][%s].\n", ret, strerror(ret));
        goto done;
    }

    child_pid = fork();
    if (child_pid == 0) { /* child */
        ret = exec_child_ex(state, pipefd_to_child, pipefd_from_child,
                            renewal_data->prog_path, -1,
                            renewal_data->extra_args, true,
                            STDIN_FILENO, STDERR_FILENO);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Could not exec renewal child: [%d][%s].\n",
                                       ret, strerror(ret));
            goto done;
        }
    } else if (child_pid > 0) { /* parent */

        state->read_from_child_fd = pipefd_from_child[0];
        close(pipefd_from_child[1]);
        sss_fd_nonblocking(state->read_from_child_fd);

        state->write_to_child_fd = pipefd_to_child[1];
        close(pipefd_to_child[0]);
        sss_fd_nonblocking(state->write_to_child_fd);

        /* Set up SIGCHLD handler */
        ret = child_handler_setup(ev, child_pid, NULL, NULL, &state->child_ctx);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Could not set up child handlers [%d]: %s\n",
                ret, sss_strerror(ret));
            ret = ERR_RENEWAL_CHILD;
            goto done;
        }

        /* Set up timeout handler */
        tv = tevent_timeval_current_ofs(be_ptask_get_period(be_ptask), 0);
        state->timeout_handler = tevent_add_timer(ev, req, tv,
                                    ad_machine_account_password_renewal_timeout,
                                    req);
        if(state->timeout_handler == NULL) {
            ret = ERR_RENEWAL_CHILD;
            goto done;
        }

        subreq = read_pipe_send(state, ev, state->read_from_child_fd);
        if (subreq == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "read_pipe_send failed.\n");
            ret = ERR_RENEWAL_CHILD;
            goto done;
        }
        tevent_req_set_callback(subreq,
                                ad_machine_account_password_renewal_done, req);

        /* Now either wait for the timeout to fire or the child
         * to finish
         */
    } else { /* error */
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE, "fork failed [%d][%s].\n",
                                   ret, sss_strerror(ret));
        goto done;
    }

    ret = EOK;

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }
    return req;
}

static void ad_machine_account_password_renewal_done(struct tevent_req *subreq)
{
    uint8_t *buf;
    ssize_t buf_len;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct renewal_state *state = tevent_req_data(req, struct renewal_state);
    int ret;

    talloc_zfree(state->timeout_handler);

    ret = read_pipe_recv(subreq, state, &buf, &buf_len);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    DEBUG(SSSDBG_TRACE_LIBS, "--- adcli output start---\n"
                             "%.*s"
                             "---adcli output end---\n",
                             buf_len, buf);

    close(state->read_from_child_fd);
    state->read_from_child_fd = -1;


    tevent_req_done(req);
    return;
}

static void
ad_machine_account_password_renewal_timeout(struct tevent_context *ev,
                                            struct tevent_timer *te,
                                            struct timeval tv, void *pvt)
{
    struct tevent_req *req = talloc_get_type(pvt, struct tevent_req);
    struct renewal_state *state = tevent_req_data(req, struct renewal_state);

    DEBUG(SSSDBG_CRIT_FAILURE, "Timeout reached for AD renewal child.\n");
    child_handler_destroy(state->child_ctx);
    state->child_ctx = NULL;
    state->child_status = ETIMEDOUT;
    tevent_req_error(req, ERR_RENEWAL_CHILD);
}

static errno_t
ad_machine_account_password_renewal_recv(struct tevent_req *req)
{

    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

errno_t ad_machine_account_password_renewal_init(struct be_ctx *be_ctx,
                                                 struct dp_option *opts)
{
    int ret;
    struct renewal_data *renewal_data;
    int lifetime;
    const char *dummy;
    char **opt_list;
    int opt_list_size;
    char *endptr;

    lifetime = dp_opt_get_int(opts, AD_MAXIMUM_MACHINE_ACCOUNT_PASSWORD_AGE);

    if (lifetime == 0) {
        DEBUG(SSSDBG_CONF_SETTINGS, "Automatic machine account renewal disabled.\n");
        return EOK;
    }

    if (lifetime < 0) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Illegal value [%d] for password lifetime.\n", lifetime);
        return EINVAL;
    }

    renewal_data = talloc(be_ctx, struct renewal_data);
    if (renewal_data == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc failed.\n");
        return ENOMEM;
    }

    dummy = dp_opt_get_cstring(opts, AD_MACHINE_ACCOUNT_PASSWORD_RENEWAL_OPTS);
    ret = split_on_separator(renewal_data, dummy, ':', true, false,
                             &opt_list, &opt_list_size);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "split_on_separator failed.\n");
        goto done;
    }

    if (opt_list_size != 2) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Wrong number of renewal options.\n");
        ret = EINVAL;
        goto done;
    }

    errno = 0;
    renewal_data->period = strtouint32(opt_list[0], &endptr, 10);
    if (errno != 0 || *endptr != '\0' || opt_list[0] == endptr) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to parse first renewal option.\n");
        ret = EINVAL;
        goto done;
    }

    errno = 0;
    renewal_data->initial_delay = strtouint32(opt_list[1], &endptr, 10);
    if (errno != 0 || *endptr != '\0' || opt_list[0] == endptr) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to parse second renewal option.\n");
        ret = EINVAL;
        goto done;
    }

    renewal_data->pw_lifetime_in_days = lifetime;
    renewal_data->ad_domain = talloc_strdup(renewal_data,
                                            dp_opt_get_string(opts, AD_DOMAIN));

    renewal_data->ad_hostname = talloc_strdup(renewal_data,
                                              dp_opt_get_string(opts,
                                                                AD_HOSTNAME));
    renewal_data->ad_keytab = talloc_strdup(renewal_data,
                                            dp_opt_get_string(opts, AD_KEYTAB));
    if (renewal_data->ad_domain == NULL || renewal_data->ad_hostname == NULL
            || renewal_data->ad_keytab == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Missing AD domain or hostname.\n");
        ret = EINVAL;
        goto done;
    }

    ret = get_adcli_extra_args(renewal_data);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "get_adcli_extra_args failed.\n");
        goto done;
    }

    ret = be_ptask_create(be_ctx, be_ctx, renewal_data->period,
                          renewal_data->initial_delay, 0, 0, 60,
                          BE_PTASK_OFFLINE_DISABLE, 0,
                          ad_machine_account_password_renewal_send,
                          ad_machine_account_password_renewal_recv,
                          renewal_data,
                          "AD machine account password renewal", NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "be_ptask_create failed.\n");
        goto done;
    }

    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(renewal_data);
    }

    return ret;
}
