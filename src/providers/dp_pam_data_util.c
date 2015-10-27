/*
    SSSD

    Utilities to for tha pam_data structure

    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2009 Red Hat

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

#include "providers/data_provider.h"
#include "util/sss_cli_cmd.h"

#define PAM_SAFE_ITEM(item) item ? item : "not set"

int pam_data_destructor(void *ptr)
{
    struct pam_data *pd = talloc_get_type(ptr, struct pam_data);

    /* make sure to wipe any password from memory before freeing */
    sss_authtok_wipe_password(pd->authtok);
    sss_authtok_wipe_password(pd->newauthtok);

    return 0;
}

struct pam_data *create_pam_data(TALLOC_CTX *mem_ctx)
{
    struct pam_data *pd;

    pd = talloc_zero(mem_ctx, struct pam_data);
    if (pd == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_zero failed.\n");
        goto failed;
    }

    pd->authtok = sss_authtok_new(pd);
    if (pd->authtok == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_zero failed.\n");
        goto failed;
    }

    pd->newauthtok = sss_authtok_new(pd);
    if (pd->newauthtok == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_zero failed.\n");
        goto failed;
    }

    talloc_set_destructor((TALLOC_CTX *) pd, pam_data_destructor);

    return pd;

failed:
    talloc_free(pd);
    return NULL;
}

errno_t copy_pam_data(TALLOC_CTX *mem_ctx, struct pam_data *src,
                      struct pam_data **dst)
{
    struct pam_data *pd = NULL;
    errno_t ret;

    pd = create_pam_data(mem_ctx);
    if (pd == NULL) {
        ret =  ENOMEM;
        goto failed;
    }

    pd->cmd  = src->cmd;
    pd->priv = src->priv;

    pd->domain = talloc_strdup(pd, src->domain);
    if (pd->domain == NULL && src->domain != NULL) {
        ret =  ENOMEM;
        goto failed;
    }
    pd->user = talloc_strdup(pd, src->user);
    if (pd->user == NULL && src->user != NULL) {
        ret =  ENOMEM;
        goto failed;
    }
    pd->service = talloc_strdup(pd, src->service);
    if (pd->service == NULL && src->service != NULL) {
        ret =  ENOMEM;
        goto failed;
    }
    pd->tty = talloc_strdup(pd, src->tty);
    if (pd->tty == NULL && src->tty != NULL) {
        ret =  ENOMEM;
        goto failed;
    }
    pd->ruser = talloc_strdup(pd, src->ruser);
    if (pd->ruser == NULL && src->ruser != NULL) {
        ret =  ENOMEM;
        goto failed;
    }
    pd->rhost = talloc_strdup(pd, src->rhost);
    if (pd->rhost == NULL && src->rhost != NULL) {
        ret =  ENOMEM;
        goto failed;
    }

    pd->cli_pid = src->cli_pid;

    /* if structure pam_data was allocated on stack and zero initialized,
     * than src->authtok and src->newauthtok are NULL, therefore
     * instead of copying, new empty authtok will be created.
     */
    if (src->authtok) {
        ret = sss_authtok_copy(src->authtok, pd->authtok);
        if (ret) {
            goto failed;
        }
    } else {
        pd->authtok = sss_authtok_new(pd);
        if (pd->authtok == NULL) {
            ret = ENOMEM;
            goto failed;
        }
    }

    if (src->newauthtok) {
        ret = sss_authtok_copy(src->newauthtok, pd->newauthtok);
        if (ret) {
            goto failed;
        }
    } else {
        pd->newauthtok = sss_authtok_new(pd);
        if (pd->newauthtok == NULL) {
            ret = ENOMEM;
            goto failed;
        }
    }

    *dst = pd;

    return EOK;

failed:
    talloc_free(pd);
    DEBUG(SSSDBG_CRIT_FAILURE,
          "copy_pam_data failed: (%d) %s.\n", ret, strerror(ret));
    return ret;
}

void pam_print_data(int l, struct pam_data *pd)
{
    DEBUG(l, "command: %s\n", sss_cmd2str(pd->cmd));
    DEBUG(l, "domain: %s\n", PAM_SAFE_ITEM(pd->domain));
    DEBUG(l, "user: %s\n", PAM_SAFE_ITEM(pd->user));
    DEBUG(l, "service: %s\n", PAM_SAFE_ITEM(pd->service));
    DEBUG(l, "tty: %s\n", PAM_SAFE_ITEM(pd->tty));
    DEBUG(l, "ruser: %s\n", PAM_SAFE_ITEM(pd->ruser));
    DEBUG(l, "rhost: %s\n", PAM_SAFE_ITEM(pd->rhost));
    DEBUG(l, "authtok type: %d\n", sss_authtok_get_type(pd->authtok));
    DEBUG(l, "newauthtok type: %d\n", sss_authtok_get_type(pd->newauthtok));
    DEBUG(l, "priv: %d\n", pd->priv);
    DEBUG(l, "cli_pid: %d\n", pd->cli_pid);
    DEBUG(l, "logon name: %s\n", PAM_SAFE_ITEM(pd->logon_name));
}

int pam_add_response(struct pam_data *pd, enum response_type type,
                     int len, const uint8_t *data)
{
    struct response_data *new;

    new = talloc(pd, struct response_data);
    if (new == NULL) return ENOMEM;

    new->type = type;
    new->len = len;
    new->data = talloc_memdup(pd, data, len);
    if (new->data == NULL) return ENOMEM;
    new->do_not_send_to_client = false;
    new->next = pd->resp_list;
    pd->resp_list = new;

    return EOK;
}

static void pam_resp_add_pwexpire(struct pam_data *pd,
                                  uint32_t key,
                                  uint32_t value)
{
    uint32_t *data;
    errno_t ret;

    data = talloc_size(pd, 2 * sizeof(uint32_t));
    if (data == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_size failed.\n");
        return;
    }

    data[0] = key;
    data[1] = value;

    ret = pam_add_response(pd, SSS_PAM_USER_INFO, 2 * sizeof(uint32_t),
                           (uint8_t*)data);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "pam_add_response failed.\n");
    }
}

void pam_resp_grace_login(struct pam_data *pd, uint32_t grace)
{
    pam_resp_add_pwexpire(pd, SSS_PAM_USER_INFO_GRACE_LOGIN, grace);
}

void pam_resp_expired_login(struct pam_data *pd, uint32_t expire)
{
    pam_resp_add_pwexpire(pd, SSS_PAM_USER_INFO_EXPIRE_WARN, expire);
}

static errno_t pack_user_info_chpass_error(TALLOC_CTX *mem_ctx,
                                           const char *user_error_message,
                                           size_t *resp_len,
                                           uint8_t **_resp)
{
    uint32_t resp_type = SSS_PAM_USER_INFO_CHPASS_ERROR;
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

void pam_resp_srv_msg(struct pam_data *pd, const char *str_msg)
{
    int ret;
    size_t msg_len;
    uint8_t *msg;

    ret = pack_user_info_chpass_error(pd, str_msg, &msg_len, &msg);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "pack_user_info_chpass_error failed.\n");
    } else {
        ret = pam_add_response(pd, SSS_PAM_USER_INFO, msg_len, msg);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "pam_add_response failed.\n");
        }
    }
}

errno_t pam_resp_otp_info(struct pam_data *pd,
                          const char *otp_vendor,
                          const char *otp_token_id,
                          const char *otp_challenge)
{
    uint8_t *msg = NULL;
    size_t msg_len;
    int ret;
    size_t vendor_len = 0;
    size_t token_id_len = 0;
    size_t challenge_len = 0;
    size_t idx = 0;

    msg_len = 3; /* Length of the components */

    if (otp_vendor != NULL) {
        vendor_len = strlen(otp_vendor);
        msg_len += vendor_len;
    }

    if (otp_token_id != NULL) {
        token_id_len = strlen(otp_token_id);
        msg_len += token_id_len;
    }

    if (otp_challenge != NULL) {
        challenge_len = strlen(otp_challenge);
        msg_len += challenge_len;
    }

    msg = talloc_zero_size(pd, msg_len);
    if (msg == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_size failed.\n");
        return ENOMEM;
    }

    if (otp_vendor != NULL) {
        memcpy(msg, otp_vendor, vendor_len);
    }
    idx += vendor_len +1;

    if (otp_token_id != NULL) {
        memcpy(msg + idx, otp_token_id, token_id_len);
    }
    idx += token_id_len +1;

    if (otp_challenge != NULL) {
        memcpy(msg + idx, otp_challenge, challenge_len);
    }

    ret = pam_add_response(pd, SSS_PAM_OTP_INFO, msg_len, msg);
    talloc_zfree(msg);

    return ret;
}

void pam_resp_otp_chpass(struct pam_data *pd)
{
    errno_t ret;
    uint32_t user_info_type;

    user_info_type = SSS_PAM_USER_INFO_OTP_CHPASS;
    ret = pam_add_response(pd, SSS_PAM_USER_INFO, sizeof(uint32_t),
                           (const uint8_t *) &user_info_type);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "pam_add_response failed.\n");
        /* Not fatal */
    }
}

