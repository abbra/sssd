/*
   SSSD

   PAM Responder

   Copyright (C) Red Hat 2015

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
#include "providers/data_provider.h"
#include "responder/pam/pamsrv.h"
#include "responder/common/responder_packet.h"

static errno_t pack_user_info_account_expired(TALLOC_CTX *mem_ctx,
                                              const char *user_error_message,
                                              size_t *resp_len,
                                              uint8_t **_resp);

errno_t pamsrv_exp_warn(struct pam_data *pd,
                        int pam_verbosity,
                        const char *exp_msg)
{
    size_t msg_len;
    uint8_t *msg;
    errno_t ret;

    if (pd->pam_status == PAM_ACCT_EXPIRED &&
        ((pd->service != NULL && strcasecmp(pd->service, "sshd") == 0) ||
         pam_verbosity >= PAM_VERBOSITY_INFO)) {

        ret = pack_user_info_account_expired(pd, exp_msg, &msg_len, &msg);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                "pack_user_info_account_expired failed.\n");
            return ret;
        } else {
            ret = pam_add_response(pd, SSS_PAM_USER_INFO, msg_len, msg);
            if (ret != EOK) {
                DEBUG(SSSDBG_CRIT_FAILURE, "pam_add_response failed.\n");
                return ret;
            }
        }
    }

    return EOK;
}

static errno_t pack_user_info_account_expired(TALLOC_CTX *mem_ctx,
                                              const char *user_error_message,
                                              size_t *resp_len,
                                              uint8_t **_resp)
{
    uint32_t resp_type = SSS_PAM_USER_INFO_ACCOUNT_EXPIRED;
    size_t err_len;
    uint8_t *resp;
    size_t p;

    err_len = strlen(user_error_message);
    *resp_len = 2 * sizeof(uint32_t) + err_len;
    resp = talloc_size(mem_ctx, *resp_len);
    if (resp == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_size failed.\n");
        return ENOMEM;
    }

    p = 0;
    SAFEALIGN_SET_UINT32(&resp[p], resp_type, &p);
    SAFEALIGN_SET_UINT32(&resp[p], err_len, &p);
    safealign_memcpy(&resp[p], user_error_message, err_len, &p);
    if (p != *resp_len) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Size mismatch\n");
    }

    *_resp = resp;
    return EOK;
}

errno_t pamsrv_reply_packet(TALLOC_CTX *mem_ctx,
                            struct pam_data *pd,
                            enum sss_cli_command cmd,
                            struct sss_packet **_out)
{
    errno_t ret;
    uint8_t *body;
    size_t blen;
    int32_t resp_c;
    int32_t resp_size;
    struct response_data *resp;
    int p;
    struct sss_packet *out;

    ret = sss_packet_new(mem_ctx, 0, cmd, &out);
    if (ret != EOK) {
        goto done;
    }

    resp_c = 0;
    resp_size = 0;
    resp = pd->resp_list;
    while(resp != NULL) {
        if (!resp->do_not_send_to_client) {
            resp_c++;
            resp_size += resp->len;
        }
        resp = resp->next;
    }

    ret = sss_packet_grow(out, sizeof(int32_t) + sizeof(int32_t) +
                          resp_c * 2 * sizeof(int32_t) + resp_size);
    if (ret != EOK) {
        goto done;
    }

    sss_packet_get_body(out, &body, &blen);
    DEBUG(SSSDBG_FUNC_DATA, "blen: %zu\n", blen);
    p = 0;

    memcpy(&body[p], &pd->pam_status, sizeof(int32_t));
    p += sizeof(int32_t);

    memcpy(&body[p], &resp_c, sizeof(int32_t));
    p += sizeof(int32_t);

    resp = pd->resp_list;
    while(resp != NULL) {
        if (!resp->do_not_send_to_client) {
            memcpy(&body[p], &resp->type, sizeof(int32_t));
            p += sizeof(int32_t);
            memcpy(&body[p], &resp->len, sizeof(int32_t));
            p += sizeof(int32_t);
            memcpy(&body[p], resp->data, resp->len);
            p += resp->len;
        }

        resp = resp->next;
    }

    *_out = out;
    ret = EOK;

done:
    return ret;
}
