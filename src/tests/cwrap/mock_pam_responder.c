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

#include <stdint.h>
#include <errno.h>
#include <sys/types.h>
#include "sss_cli.h"

#include "responder/pam/pamsrv.h"
#include "responder/common/responder_packet.h"
#include "providers/data_provider.h"

/* FIXME - move the definition to a private header */
struct sss_packet {
    size_t memsize;

    /* Structure of the buffer:
    * Bytes    Content
    * ---------------------------------
    * 0-15     packet header
    * 0-3      packet length (uint32_t)
    * 4-7      command type (uint32_t)
    * 8-11     status (uint32_t)
    * 12-15    reserved
    * 16+      packet body */
    uint8_t *buffer;

    /* io pointer */
    size_t iop;
};

/* Make linker happy */
int __wrap_sss_parse_name_for_domains(TALLOC_CTX *memctx,
                                      struct sss_domain_info *domains,
                                      const char *default_domain,
                                      const char *orig,
                                      char **domain, char **name)
{
    char *atsign;

    atsign = strrchr(orig, '@');
    if (atsign == NULL) {
        *domain = NULL;
        *name = talloc_strdup(memctx, orig);
        if (*name == NULL) {
            return ENOMEM;
        }
        return EOK;
    }

    *name = talloc_strndup(memctx, orig, atsign - orig);
    *domain = talloc_strdup(memctx, atsign+1);
    if (*name == NULL || *domain == NULL) {
        return ENOMEM;
    }

    return EOK;
}

void __wrap_sss_packet_get_body(struct sss_packet *packet, uint8_t **body, size_t *blen)
{
    *body = packet->buffer;
    *blen = packet->memsize;
}

static struct cli_ctx *
mock_pam_cctx(TALLOC_CTX *mem_ctx,
              enum sss_cli_command cmd,
              int cli_protocol_version,
              struct sss_cli_req_data *rd)
{
    struct cli_ctx *cctx = NULL;
    int ret;

    cctx = talloc_zero(mem_ctx, struct cli_ctx);
    if (!cctx) goto fail;

    cctx->creq = talloc_zero(cctx, struct cli_request);
    if (cctx->creq == NULL) goto fail;

    cctx->cli_protocol_version = talloc_zero(cctx,
                                             struct cli_protocol_version);
    if (cctx->cli_protocol_version == NULL) goto fail;

    cctx->cli_protocol_version->version = cli_protocol_version;

    cctx->creq = talloc_zero(cctx, struct cli_request);
    if (cctx->creq == NULL) goto fail;

    ret = sss_packet_new(cctx->creq, 0, cmd, &cctx->creq->in);
    if (ret != EOK) goto fail;

    cctx->rctx = talloc_zero(cctx, struct resp_ctx);
    if (cctx->rctx == NULL) goto fail;

    cctx->creq->in->buffer = discard_const(rd->data);
    cctx->creq->in->memsize = rd->len;

    return cctx;

fail:
    talloc_free(cctx);
    return NULL;
}

static struct pam_data *
mock_pam_data(TALLOC_CTX *mem_ctx, enum sss_cli_command cmd)
{
    struct pam_data *pd = NULL;

    pd = talloc_zero(mem_ctx, struct pam_data);
    if (pd == NULL) goto fail;

    pd->cmd = cmd;
    pd->authtok = sss_authtok_new(pd);
    pd->newauthtok = sss_authtok_new(pd);
    if (pd->authtok == NULL || pd->newauthtok == NULL) goto fail;

    return pd;

fail:
    talloc_free(pd);
    return NULL;
}

static int test_auth(struct pam_data *pd, const char *exp_pass)
{
    const char *password;
    size_t pwlen;
    int ret;

    ret = sss_authtok_get_password(pd->authtok, &password, &pwlen);
    if (ret != EOK) {
        return EINVAL;
    }

    if (strncmp(password, exp_pass, pwlen) == 0) {
        pd->pam_status = PAM_SUCCESS;
    } else {
        pd->pam_status = PAM_AUTH_ERR;
    }

    return EOK;
}

/* Receives a packed response and returns a mock reply */
int __wrap_sss_pam_make_request(enum sss_cli_command cmd,
                                struct sss_cli_req_data *rd,
                                uint8_t **repbuf, size_t *replen,
                                int *errnop)
{
    errno_t ret;
    TALLOC_CTX *test_ctx;
    struct cli_ctx *cctx;
    struct pam_data *pd;

    test_ctx = talloc_new(NULL);
    if (test_ctx == NULL) {
        return ENOMEM;
    }

    /* The PAM responder functions expect both cctx and pd to be talloc
     * contexts
     */
    cctx = mock_pam_cctx(test_ctx, cmd, 3, rd);
    pd = mock_pam_data(test_ctx, cmd);
    if (cctx == NULL || pd == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = pam_forwarder_parse_data(cctx, pd);
    if (ret != EOK) {
        goto done;
    }

    if (cmd == SSS_PAM_AUTHENTICATE) {
        if (strcmp(pd->user, "testuser") == 0) {
            ret = test_auth(pd, "secret");
        } else if (strcmp(pd->user, "domtest") == 0) {
            pd->pam_status = PAM_AUTH_ERR;
            if (pd->requested_domains[0] != NULL
                    && strcmp(pd->requested_domains[0], "mydomain") == 0
                    && pd->requested_domains[1] == NULL) {
                pd->pam_status = PAM_SUCCESS;
            }
        } else if (strcmp(pd->user, "retrytest") == 0) {
            ret = test_auth(pd, "retried_secret");
        }
    }

    if (ret != EOK) {
        goto done;
    }

    ret = pamsrv_reply_packet(cctx->creq, pd, cmd, &cctx->creq->out);
    if (ret != EOK) {
        goto done;
    }

    *repbuf = malloc(cctx->creq->out->memsize);
    memcpy(*repbuf, cctx->creq->out->buffer, cctx->creq->out->memsize);
    *replen = cctx->creq->out->memsize;

    ret = EOK;
done:
    return ret;
}
