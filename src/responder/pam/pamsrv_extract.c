/*
   SSSD

   PAM Responder

   Copyright (C) Simo Sorce <ssorce@redhat.com>	2009
   Copyright (C) Sumit Bose <sbose@redhat.com>	2009

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

static int pam_parse_in_data(struct pam_data *pd,
                             uint8_t *body, size_t blen);
static int pam_parse_in_data_v2(struct pam_data *pd,
                                uint8_t *body, size_t blen);
static int pam_parse_in_data_v3(struct pam_data *pd,
                                uint8_t *body, size_t blen);

errno_t pam_forwarder_parse_data(struct cli_ctx *cctx, struct pam_data *pd)
{
    uint8_t *body;
    size_t blen;
    errno_t ret;
    uint32_t terminator;

    sss_packet_get_body(cctx->creq->in, &body, &blen);
    if (blen >= sizeof(uint32_t)) {
        SAFEALIGN_COPY_UINT32(&terminator,
                              body + blen - sizeof(uint32_t),
                              NULL);
        if (terminator != SSS_END_OF_PAM_REQUEST) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Received data not terminated.\n");
            ret = EINVAL;
            goto done;
        }
    }

    switch (cctx->cli_protocol_version->version) {
        case 1:
            ret = pam_parse_in_data(pd, body, blen);
            break;
        case 2:
            ret = pam_parse_in_data_v2(pd, body, blen);
            break;
        case 3:
            ret = pam_parse_in_data_v3(pd, body, blen);
            break;
        default:
            DEBUG(SSSDBG_CRIT_FAILURE, "Illegal protocol version [%d].\n",
                      cctx->cli_protocol_version->version);
            ret = EINVAL;
    }
    if (ret != EOK) {
        goto done;
    }

    if (pd->logon_name != NULL) {
        ret = sss_parse_name_for_domains(pd, cctx->rctx->domains,
                                         cctx->rctx->default_domain,
                                         pd->logon_name,
                                         &pd->domain, &pd->user);
    } else {
        /* Only SSS_PAM_PREAUTH request may have a missing name, e.g. if the
         * name is determined with the help of a certificate */
        if (pd->cmd == SSS_PAM_PREAUTH
                && may_do_cert_auth(talloc_get_type(cctx->rctx->pvt_ctx,
                                                    struct pam_ctx), pd)) {
            ret = EOK;
        } else {
            DEBUG(SSSDBG_CRIT_FAILURE, "Missing logon name in PAM request.\n");
            ret = ERR_NO_CREDS;
            goto done;
        }
    }

    DEBUG_PAM_DATA(SSSDBG_CONF_SETTINGS, pd);

done:
    return ret;
}

static int extract_authtok_v1(struct sss_auth_token *tok,
                              uint8_t *body, size_t blen, size_t *c);
static int extract_authtok_v2(struct sss_auth_token *tok,
                              size_t data_size, uint8_t *body, size_t blen,
                              size_t *c);
static int extract_string(char **var, size_t size, uint8_t *body, size_t blen,
                          size_t *c);
static int extract_uint32_t(uint32_t *var, size_t size, uint8_t *body,
                            size_t blen, size_t *c);

static int pam_parse_in_data(struct pam_data *pd,
                             uint8_t *body, size_t blen)
{
    size_t start;
    size_t end;
    size_t last;
    int ret;

    last = blen - 1;
    end = 0;

    /* user name */
    for (start = end; end < last; end++) if (body[end] == '\0') break;
    if (body[end++] != '\0') return EINVAL;
    pd->logon_name = (char *) &body[start];

    for (start = end; end < last; end++) if (body[end] == '\0') break;
    if (body[end++] != '\0') return EINVAL;
    pd->service = (char *) &body[start];

    for (start = end; end < last; end++) if (body[end] == '\0') break;
    if (body[end++] != '\0') return EINVAL;
    pd->tty = (char *) &body[start];

    for (start = end; end < last; end++) if (body[end] == '\0') break;
    if (body[end++] != '\0') return EINVAL;
    pd->ruser = (char *) &body[start];

    for (start = end; end < last; end++) if (body[end] == '\0') break;
    if (body[end++] != '\0') return EINVAL;
    pd->rhost = (char *) &body[start];

    ret = extract_authtok_v1(pd->authtok, body, blen, &end);
    if (ret) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid auth token\n");
        return ret;
    }
    ret = extract_authtok_v1(pd->newauthtok, body, blen, &end);
    if (ret) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid new auth token\n");
        return ret;
    }

    DEBUG_PAM_DATA(SSSDBG_CONF_SETTINGS, pd);

    return EOK;
}

static int pam_parse_in_data_v2(struct pam_data *pd,
                                uint8_t *body, size_t blen)
{
    size_t c;
    uint32_t type;
    uint32_t size;
    int ret;
    uint32_t start;
    uint32_t terminator;
    char *requested_domains;

    if (blen < 4*sizeof(uint32_t)+2) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Received data is invalid.\n");
        return EINVAL;
    }

    SAFEALIGN_COPY_UINT32(&start, body, NULL);
    SAFEALIGN_COPY_UINT32(&terminator, body + blen - sizeof(uint32_t), NULL);

    if (start != SSS_START_OF_PAM_REQUEST
        || terminator != SSS_END_OF_PAM_REQUEST) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Received data is invalid.\n");
        return EINVAL;
    }

    c = sizeof(uint32_t);
    do {
        SAFEALIGN_COPY_UINT32_CHECK(&type, &body[c], blen, &c);

        if (type == SSS_END_OF_PAM_REQUEST) {
            if (c != blen) return EINVAL;
        } else {
            SAFEALIGN_COPY_UINT32_CHECK(&size, &body[c], blen, &c);
            /* the uint32_t end maker SSS_END_OF_PAM_REQUEST does not count to
             * the remaining buffer */
            if (size > (blen - c - sizeof(uint32_t))) {
                DEBUG(SSSDBG_CRIT_FAILURE, "Invalid data size.\n");
                return EINVAL;
            }

            switch(type) {
                case SSS_PAM_ITEM_USER:
                    ret = extract_string(&pd->logon_name, size, body, blen, &c);
                    if (ret != EOK) return ret;
                    break;
                case SSS_PAM_ITEM_SERVICE:
                    ret = extract_string(&pd->service, size, body, blen, &c);
                    if (ret != EOK) return ret;
                    break;
                case SSS_PAM_ITEM_TTY:
                    ret = extract_string(&pd->tty, size, body, blen, &c);
                    if (ret != EOK) return ret;
                    break;
                case SSS_PAM_ITEM_RUSER:
                    ret = extract_string(&pd->ruser, size, body, blen, &c);
                    if (ret != EOK) return ret;
                    break;
                case SSS_PAM_ITEM_RHOST:
                    ret = extract_string(&pd->rhost, size, body, blen, &c);
                    if (ret != EOK) return ret;
                    break;
                case SSS_PAM_ITEM_REQUESTED_DOMAINS:
                    ret = extract_string(&requested_domains, size, body, blen,
                                         &c);
                    if (ret != EOK) return ret;

                    ret = split_on_separator(pd, requested_domains, ',', true,
                                             true, &pd->requested_domains,
                                             NULL);
                    if (ret != EOK) {
                        DEBUG(SSSDBG_CRIT_FAILURE,
                              "Failed to parse requested_domains list!\n");
                        return ret;
                    }
                    break;
                case SSS_PAM_ITEM_CLI_PID:
                    ret = extract_uint32_t(&pd->cli_pid, size,
                                           body, blen, &c);
                    if (ret != EOK) return ret;
                    break;
                case SSS_PAM_ITEM_AUTHTOK:
                    ret = extract_authtok_v2(pd->authtok,
                                             size, body, blen, &c);
                    if (ret != EOK) return ret;
                    break;
                case SSS_PAM_ITEM_NEWAUTHTOK:
                    ret = extract_authtok_v2(pd->newauthtok,
                                             size, body, blen, &c);
                    if (ret != EOK) return ret;
                    break;
                default:
                    DEBUG(SSSDBG_CRIT_FAILURE,
                          "Ignoring unknown data type [%d].\n", type);
                    c += size;
            }
        }

    } while(c < blen);

    return EOK;

}

static int pam_parse_in_data_v3(struct pam_data *pd,
                                uint8_t *body, size_t blen)
{
    int ret;

    ret = pam_parse_in_data_v2(pd, body, blen);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "pam_parse_in_data_v2 failed.\n");
        return ret;
    }

    if (pd->cli_pid == 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Missing client PID.\n");
        return EINVAL;
    }

    return EOK;
}

static int extract_string(char **var, size_t size, uint8_t *body, size_t blen,
                          size_t *c)
{
    uint8_t *str;

    if (*c+size > blen || SIZE_T_OVERFLOW(*c, size)) return EINVAL;

    str = body+(*c);

    if (str[size-1]!='\0') return EINVAL;

    /* If the string isn't valid UTF-8, fail */
    if (!sss_utf8_check(str, size-1)) {
        return EINVAL;
    }

    *c += size;

    *var = (char *) str;

    return EOK;
}

static int extract_uint32_t(uint32_t *var, size_t size, uint8_t *body,
                            size_t blen, size_t *c)
{

    if (size != sizeof(uint32_t)
            || *c+size > blen
            || SIZE_T_OVERFLOW(*c, size)) {
        return EINVAL;
    }

    SAFEALIGN_COPY_UINT32_CHECK(var, &body[*c], blen, c);

    return EOK;
}

static int extract_authtok_v1(struct sss_auth_token *tok,
                              uint8_t *body, size_t blen, size_t *c)
{
    uint32_t auth_token_type;
    uint32_t auth_token_length;
    uint8_t *auth_token_data;
    int ret = EOK;

    SAFEALIGN_COPY_UINT32_CHECK(&auth_token_type, &body[*c], blen, c);
    SAFEALIGN_COPY_UINT32_CHECK(&auth_token_length, &body[*c], blen, c);
    auth_token_data = body+(*c);

    switch (auth_token_type) {
    case SSS_AUTHTOK_TYPE_EMPTY:
        sss_authtok_set_empty(tok);
        break;
    case SSS_AUTHTOK_TYPE_PASSWORD:
        ret = sss_authtok_set_password(tok, (const char *)auth_token_data,
                                       auth_token_length);
        break;
    default:
        return EINVAL;
    }

    *c += auth_token_length;

    return ret;
}

static int extract_authtok_v2(struct sss_auth_token *tok,
                              size_t data_size, uint8_t *body, size_t blen,
                              size_t *c)
{
    uint32_t auth_token_type;
    uint32_t auth_token_length;
    uint8_t *auth_token_data;
    int ret = EOK;

    if (data_size < sizeof(uint32_t) || *c+data_size > blen ||
        SIZE_T_OVERFLOW(*c, data_size)) return EINVAL;

    SAFEALIGN_COPY_UINT32_CHECK(&auth_token_type, &body[*c], blen, c);
    auth_token_length = data_size - sizeof(uint32_t);
    auth_token_data = body+(*c);

    switch (auth_token_type) {
    case SSS_AUTHTOK_TYPE_EMPTY:
        sss_authtok_set_empty(tok);
        break;
    case SSS_AUTHTOK_TYPE_PASSWORD:
        if (auth_token_length == 0) {
            sss_authtok_set_empty(tok);
        } else {
            ret = sss_authtok_set_password(tok, (const char *)auth_token_data,
                                           auth_token_length);
        }
        break;
    case SSS_AUTHTOK_TYPE_2FA:
        ret = sss_authtok_set(tok, SSS_AUTHTOK_TYPE_2FA,
                              auth_token_data, auth_token_length);
        break;
    case SSS_AUTHTOK_TYPE_SC_PIN:
        ret = sss_authtok_set_sc_pin(tok, (const char *) auth_token_data,
                                     auth_token_length);
        break;
    case SSS_AUTHTOK_TYPE_SC_KEYPAD:
        sss_authtok_set_sc_keypad(tok);
        break;
    default:
        return EINVAL;
    }

    *c += auth_token_length;

    return ret;
}
