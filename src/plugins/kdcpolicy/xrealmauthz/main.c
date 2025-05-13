/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* plugins/kdcpolicy/xrealmauthz/main.c - xrealmauthz module implementation */
/*
 * Copyright (C) 2025 by Red Hat, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "k5-int.h"
#include <kdb.h>
#include <krb5/plugin.h>
#include <krb5/kdcpolicy_plugin.h>
#include <profile.h>

/* Prefix used for cross-realm authorization attributes */
#define ATTR_PREFIX "xr:"

struct xrealmauthz_data {
    int enforcing;  /* Whether to actually enforce restrictions */
    krb5_data *allowed_realms;
    size_t num_allowed_realms;
};

/* Typedef for pointer to the structure */
typedef struct xrealmauthz_data *xrealmauthz_moddata;

static void
free_moddata(xrealmauthz_moddata data)
{
    size_t i;

    if (data == NULL)
        return;
    for (i = 0; i < data->num_allowed_realms; i++)
        free(data->allowed_realms[i].data);
    free(data->allowed_realms);
    free(data);
}

static krb5_error_code
xrealmauthz_init(krb5_context context, krb5_kdcpolicy_moddata *moddata_out)
{
    krb5_error_code ret;
    int enforcing = 1;
    xrealmauthz_moddata data = NULL;
    profile_t profile = NULL;
    char **realmlist = NULL;
    size_t count, i;
    const char *section[] = { "kdcdefaults", "xrealmauthz_allowed_realms",
        NULL };

    *moddata_out = NULL;

    ret = krb5_get_profile(context, &profile);
    if (ret)
        goto cleanup;

    /* Check if enforcing mode is disabled in config, default to TRUE */
    profile_get_boolean(profile, "kdcdefaults", "xrealmauthz_enforcing",
                        NULL, TRUE, &enforcing);

    data = k5alloc(sizeof(*data), &ret);
    if (data == NULL)
        goto cleanup;

    /* Get array of allowed realms from config. */
    ret = profile_get_values(profile, section, &realmlist);
    if (ret && ret != PROF_NO_RELATION)
        goto cleanup;
    ret = 0;

    if (realmlist != NULL) {
        /* Count and allocate realm entries. */
        for (count = 0; realmlist[count] != NULL; count++);
        data->allowed_realms = k5calloc(count, sizeof(krb5_data), &ret);
        if (data->allowed_realms == NULL)
            goto cleanup;
        data->num_allowed_realms = count;

        /* Transfer ownership of the strings from the profile realmlist. */
        for (i = 0; i < count; i++)
            data->allowed_realms[i] = string2data(realmlist[i]);
        free(realmlist);
        realmlist = NULL;
    }

    data->enforcing = enforcing;

    com_err("", 0,
            _("xrealmauthz cross-realm authorization module loaded "
              "(enforcing mode: %s, pre-approved realms: %d)"),
            enforcing ? _("enabled") : _("disabled"),
            (int)data->num_allowed_realms);

    *moddata_out = (krb5_kdcpolicy_moddata)data;
    data = NULL;

cleanup:
    free_moddata(data);
    profile_free_list(realmlist);
    profile_release(profile);
    return ret;
}

static krb5_error_code
xrealmauthz_fini(krb5_context context, krb5_kdcpolicy_moddata moddata)
{
    free_moddata((xrealmauthz_moddata)moddata);
    return 0;
}

static krb5_boolean
is_realm_preapproved(xrealmauthz_moddata data, const krb5_data *client_realm)
{
    for (size_t i = 0; i < data->num_allowed_realms; i++) {
        if (data_eq(data->allowed_realms[i], *client_realm))
            return TRUE;
    }
    return FALSE;
}

/* Set *result_out to true if tgt has a string attribute for attr_key with any
 * value. */
static krb5_error_code
check_attr(krb5_context context, krb5_db_entry *tgt, const char *key,
           krb5_boolean *result_out)
{
    krb5_error_code ret;
    char *value;

    *result_out = FALSE;

    ret = krb5_dbe_get_string(context, tgt, key, &value);
    if (!ret && value != NULL) {
        *result_out = TRUE;
        krb5_dbe_free_string(context, value);
    }

    return ret;
}

/* Set *result_out to true if tgt has an ACL attribute for realm
 * ("xr:@realm"). */
static krb5_error_code
check_realm_attr(krb5_context context, krb5_db_entry *tgt,
                 const krb5_data *realm, krb5_boolean *result_out)
{
    krb5_error_code ret;
    char *key;

    if (asprintf(&key, "%s@%.*s", ATTR_PREFIX,
                 (int)realm->length, realm->data) < 0)
        return ENOMEM;
    ret = check_attr(context, tgt, key, result_out);
    free(key);
    return ret;
}

/* Set *result_out to true if tgt has an ACL attribute for princ ("xr:princ",
 * with the realm omitted if princ is in tgt's realm. */
static krb5_error_code
check_princ_attr(krb5_context context, krb5_db_entry *tgt,
                 krb5_const_principal princ, krb5_boolean *result_out)
{
    krb5_error_code ret;
    int flags = 0, r;
    char *princstr, *key;

    /* Omit the realm if princ is in tgt's realm. */
    if (krb5_realm_compare(context, tgt->princ, princ))
        flags |= KRB5_PRINCIPAL_UNPARSE_NO_REALM;
    ret = krb5_unparse_name_flags(context, princ, flags, &princstr);
    if (ret)
        return ret;

    r = asprintf(&key, "%s%s", ATTR_PREFIX, princstr);
    krb5_free_unparsed_name(context, princstr);
    if (r < 0)
        return ENOMEM;

    ret = check_attr(context, tgt, key, result_out);
    free(key);
    return ret;
}

/* Check if cross-realm auth is allowed based on client realm or principal */
static krb5_error_code
check_cross_realm_auth(krb5_context context, krb5_const_principal client,
                       krb5_const_principal tgtname,
                       const krb5_kdc_req *request, xrealmauthz_moddata data,
                       const char **status_out)
{
    krb5_error_code ret;
    char *cpstr = NULL, *spstr = NULL;
    krb5_boolean is_allowed = FALSE;
    krb5_db_entry *tgt_entry = NULL;

    *status_out = NULL;

    /* Check pre-approved realms first. */
    if (is_realm_preapproved(data, &client->realm))
        return 0;

    /* Get TGT principal entry once for both checks. */
    ret = krb5_db_get_principal(context, tgtname, 0, &tgt_entry);
    if (ret) {
        *status_out = "XREALMAUTHZ_GET_TGT";
        goto cleanup;
    }

    /* Check if client realm is allowed. */
    ret = check_realm_attr(context, tgt_entry, &client->realm, &is_allowed);
    if (ret || is_allowed)
        goto cleanup;

    /* Check if client principal is allowed. */
    ret = check_princ_attr(context, tgt_entry, client, &is_allowed);
    if (ret || is_allowed)
        goto cleanup;

    if (data->enforcing) {
        /* The authentication is denied.  KDC logging of the error will include
         * the client and service principal names. */
        *status_out = "XREALMAUTHZ";
        ret = KRB5KDC_ERR_POLICY;
        k5_setmsg(context, ret, _("xrealmauthz module denied from %.*s"),
                  (int)tgtname->realm.length, tgtname->realm.data);
        goto cleanup;
    }

    /* The authentication would be denied if enforcement were turned on.
     * Generate a log message including the client and service names. */
    ret = krb5_unparse_name(context, client, &cpstr);
    if (ret)
        goto cleanup;
    ret = krb5_unparse_name(context, request->server, &spstr);
    if (ret)
        goto cleanup;
    com_err("", 0, _("xrealmauthz module would deny %s for %s from %.*s"),
            cpstr, spstr, (int)tgtname->realm.length, tgtname->realm.data);

cleanup:
    krb5_db_free_principal(context, tgt_entry);
    krb5_free_unparsed_name(context, cpstr);
    krb5_free_unparsed_name(context, spstr);
    return ret;
}

static krb5_error_code
xrealmauthz_check(krb5_context context, krb5_kdcpolicy_moddata moddata,
                  const krb5_kdc_req *request,
                  const struct _krb5_db_entry_new *server,
                  const krb5_ticket *ticket,
                  const char *const *auth_indicators, const char **status_out,
                  krb5_deltat *lifetime_out, krb5_deltat *renew_lifetime_out)
{
    xrealmauthz_moddata data = (xrealmauthz_moddata)moddata;

    *status_out = NULL;
    *lifetime_out = *renew_lifetime_out = 0;

    /* Only check cross-realm requests. */
    if (krb5_realm_compare(context, server->princ, ticket->enc_part2->client))
        return 0;

    return check_cross_realm_auth(context, ticket->enc_part2->client,
                                  ticket->server, request, data, status_out);
}

krb5_error_code
kdcpolicy_xrealmauthz_initvt(krb5_context context, int maj_ver, int min_ver,
                             krb5_plugin_vtable vtable);

krb5_error_code
kdcpolicy_xrealmauthz_initvt(krb5_context context, int maj_ver, int min_ver,
                             krb5_plugin_vtable vtable)
{
    krb5_kdcpolicy_vtable vt;

    if (maj_ver != 1)
        return KRB5_PLUGIN_VER_NOTSUPP;

    vt = (krb5_kdcpolicy_vtable)vtable;
    vt->name = "xrealmauthz";
    vt->init = xrealmauthz_init;
    vt->fini = xrealmauthz_fini;
    vt->check_tgs = xrealmauthz_check;
    return 0;
}
