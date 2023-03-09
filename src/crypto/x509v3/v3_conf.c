/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
 * 1999.
 */
/* ====================================================================
 * Copyright (c) 1999-2002 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com). */

/* extension creation utilities */

#include <ctype.h>
#include <stdio.h>
#include <string.h>

#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/mem.h>
#include <openssl/obj.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "../internal.h"
#include "../x509/internal.h"
#include "internal.h"

static int v3_check_critical(const char **value);
static int v3_check_generic(const char **value);
static X509_EXTENSION *do_ext_nconf(const CONF *conf, const X509V3_CTX *ctx,
                                    int ext_nid, int crit, const char *value);
static X509_EXTENSION *v3_generic_extension(const char *ext, const char *value,
                                            int crit, int type,
<<<<<<< HEAD   (0a931c Snap for 8740412 from 2bbd592adbcc2fef5eb979af85d1e7b091f346)
                                            X509V3_CTX *ctx);
static X509_EXTENSION *do_ext_i2d(const X509V3_EXT_METHOD *method,
                                  int ext_nid, int crit, void *ext_struc);
static unsigned char *generic_asn1(const char *value, X509V3_CTX *ctx,
=======
                                            const X509V3_CTX *ctx);
static X509_EXTENSION *do_ext_i2d(const X509V3_EXT_METHOD *method, int ext_nid,
                                  int crit, void *ext_struc);
static unsigned char *generic_asn1(const char *value, const X509V3_CTX *ctx,
>>>>>>> CHANGE (34340c external/boringssl: Sync to 8aa51ddfcf1fbf2e5f976762657e21c7)
                                   long *ext_len);
<<<<<<< HEAD   (0a931c Snap for 8740412 from 2bbd592adbcc2fef5eb979af85d1e7b091f346)
/* CONF *conf:  Config file    */
/* char *name:  Name    */
/* char *value:  Value    */
X509_EXTENSION *X509V3_EXT_nconf(CONF *conf, X509V3_CTX *ctx, const char *name,
                                 const char *value)
{
    int crit;
    int ext_type;
    X509_EXTENSION *ret;
    crit = v3_check_critical(&value);
    if ((ext_type = v3_check_generic(&value)))
        return v3_generic_extension(name, value, crit, ext_type, ctx);
    ret = do_ext_nconf(conf, ctx, OBJ_sn2nid(name), crit, value);
    if (!ret) {
        OPENSSL_PUT_ERROR(X509V3, X509V3_R_ERROR_IN_EXTENSION);
        ERR_add_error_data(4, "name=", name, ", value=", value);
    }
    return ret;
=======

X509_EXTENSION *X509V3_EXT_nconf(const CONF *conf, const X509V3_CTX *ctx,
                                 const char *name, const char *value) {
  // If omitted, fill in an empty |X509V3_CTX|.
  X509V3_CTX ctx_tmp;
  if (ctx == NULL) {
    X509V3_set_ctx(&ctx_tmp, NULL, NULL, NULL, NULL, 0);
    X509V3_set_nconf(&ctx_tmp, conf);
    ctx = &ctx_tmp;
  }

  int crit = v3_check_critical(&value);
  int ext_type = v3_check_generic(&value);
  if (ext_type != 0) {
    return v3_generic_extension(name, value, crit, ext_type, ctx);
  }
  X509_EXTENSION *ret = do_ext_nconf(conf, ctx, OBJ_sn2nid(name), crit, value);
  if (!ret) {
    OPENSSL_PUT_ERROR(X509V3, X509V3_R_ERROR_IN_EXTENSION);
    ERR_add_error_data(4, "name=", name, ", value=", value);
  }
  return ret;
>>>>>>> CHANGE (34340c external/boringssl: Sync to 8aa51ddfcf1fbf2e5f976762657e21c7)
}

<<<<<<< HEAD   (0a931c Snap for 8740412 from 2bbd592adbcc2fef5eb979af85d1e7b091f346)
/* CONF *conf:  Config file    */
/* char *value:  Value    */
X509_EXTENSION *X509V3_EXT_nconf_nid(CONF *conf, X509V3_CTX *ctx, int ext_nid,
                                     const char *value)
{
    int crit;
    int ext_type;
    crit = v3_check_critical(&value);
    if ((ext_type = v3_check_generic(&value)))
        return v3_generic_extension(OBJ_nid2sn(ext_nid),
                                    value, crit, ext_type, ctx);
    return do_ext_nconf(conf, ctx, ext_nid, crit, value);
=======
X509_EXTENSION *X509V3_EXT_nconf_nid(const CONF *conf, const X509V3_CTX *ctx,
                                     int ext_nid, const char *value) {
  // If omitted, fill in an empty |X509V3_CTX|.
  X509V3_CTX ctx_tmp;
  if (ctx == NULL) {
    X509V3_set_ctx(&ctx_tmp, NULL, NULL, NULL, NULL, 0);
    X509V3_set_nconf(&ctx_tmp, conf);
    ctx = &ctx_tmp;
  }

  int crit = v3_check_critical(&value);
  int ext_type = v3_check_generic(&value);
  if (ext_type != 0) {
    return v3_generic_extension(OBJ_nid2sn(ext_nid), value, crit, ext_type,
                                ctx);
  }
  return do_ext_nconf(conf, ctx, ext_nid, crit, value);
>>>>>>> CHANGE (34340c external/boringssl: Sync to 8aa51ddfcf1fbf2e5f976762657e21c7)
}

<<<<<<< HEAD   (0a931c Snap for 8740412 from 2bbd592adbcc2fef5eb979af85d1e7b091f346)
/* CONF *conf:  Config file    */
/* char *value:  Value    */
static X509_EXTENSION *do_ext_nconf(CONF *conf, X509V3_CTX *ctx, int ext_nid,
                                    int crit, const char *value)
{
    const X509V3_EXT_METHOD *method;
    X509_EXTENSION *ext;
    STACK_OF(CONF_VALUE) *nval;
    void *ext_struc;
    if (ext_nid == NID_undef) {
        OPENSSL_PUT_ERROR(X509V3, X509V3_R_UNKNOWN_EXTENSION_NAME);
        return NULL;
    }
    if (!(method = X509V3_EXT_get_nid(ext_nid))) {
        OPENSSL_PUT_ERROR(X509V3, X509V3_R_UNKNOWN_EXTENSION);
        return NULL;
    }
    /* Now get internal extension representation based on type */
    if (method->v2i) {
        if (*value == '@')
            nval = NCONF_get_section(conf, value + 1);
        else
            nval = X509V3_parse_list(value);
        if (nval == NULL || sk_CONF_VALUE_num(nval) <= 0) {
            OPENSSL_PUT_ERROR(X509V3, X509V3_R_INVALID_EXTENSION_STRING);
            ERR_add_error_data(4, "name=", OBJ_nid2sn(ext_nid), ",section=",
                               value);
            if (*value != '@')
                sk_CONF_VALUE_pop_free(nval, X509V3_conf_free);
            return NULL;
        }
        ext_struc = method->v2i(method, ctx, nval);
        if (*value != '@')
            sk_CONF_VALUE_pop_free(nval, X509V3_conf_free);
        if (!ext_struc)
            return NULL;
    } else if (method->s2i) {
        if (!(ext_struc = method->s2i(method, ctx, value)))
            return NULL;
    } else if (method->r2i) {
        if (!ctx->db || !ctx->db_meth) {
            OPENSSL_PUT_ERROR(X509V3, X509V3_R_NO_CONFIG_DATABASE);
            return NULL;
        }
        if (!(ext_struc = method->r2i(method, ctx, value)))
            return NULL;
=======
// CONF *conf:  Config file
// char *value:  Value
static X509_EXTENSION *do_ext_nconf(const CONF *conf, const X509V3_CTX *ctx,
                                    int ext_nid, int crit, const char *value) {
  const X509V3_EXT_METHOD *method;
  X509_EXTENSION *ext;
  const STACK_OF(CONF_VALUE) *nval;
  STACK_OF(CONF_VALUE) *nval_owned = NULL;
  void *ext_struc;
  if (ext_nid == NID_undef) {
    OPENSSL_PUT_ERROR(X509V3, X509V3_R_UNKNOWN_EXTENSION_NAME);
    return NULL;
  }
  if (!(method = X509V3_EXT_get_nid(ext_nid))) {
    OPENSSL_PUT_ERROR(X509V3, X509V3_R_UNKNOWN_EXTENSION);
    return NULL;
  }
  // Now get internal extension representation based on type
  if (method->v2i) {
    if (*value == '@') {
      // TODO(davidben): This is the only place where |X509V3_EXT_nconf|'s
      // |conf| parameter is used. All other codepaths use the copy inside
      // |ctx|. Should this be switched and then the parameter ignored?
      if (conf == NULL) {
        OPENSSL_PUT_ERROR(X509V3, X509V3_R_NO_CONFIG_DATABASE);
        return NULL;
      }
      nval = NCONF_get_section(conf, value + 1);
>>>>>>> CHANGE (34340c external/boringssl: Sync to 8aa51ddfcf1fbf2e5f976762657e21c7)
    } else {
<<<<<<< HEAD   (0a931c Snap for 8740412 from 2bbd592adbcc2fef5eb979af85d1e7b091f346)
        OPENSSL_PUT_ERROR(X509V3, X509V3_R_EXTENSION_SETTING_NOT_SUPPORTED);
        ERR_add_error_data(2, "name=", OBJ_nid2sn(ext_nid));
        return NULL;
=======
      nval_owned = X509V3_parse_list(value);
      nval = nval_owned;
>>>>>>> CHANGE (34340c external/boringssl: Sync to 8aa51ddfcf1fbf2e5f976762657e21c7)
    }
<<<<<<< HEAD   (0a931c Snap for 8740412 from 2bbd592adbcc2fef5eb979af85d1e7b091f346)

    ext = do_ext_i2d(method, ext_nid, crit, ext_struc);
    if (method->it)
        ASN1_item_free(ext_struc, ASN1_ITEM_ptr(method->it));
    else
        method->ext_free(ext_struc);
    return ext;

}

static X509_EXTENSION *do_ext_i2d(const X509V3_EXT_METHOD *method,
                                  int ext_nid, int crit, void *ext_struc)
{
    unsigned char *ext_der;
    int ext_len;
    ASN1_OCTET_STRING *ext_oct;
    X509_EXTENSION *ext;
    /* Convert internal representation to DER */
    if (method->it) {
        ext_der = NULL;
        ext_len =
            ASN1_item_i2d(ext_struc, &ext_der, ASN1_ITEM_ptr(method->it));
        if (ext_len < 0)
            goto merr;
    } else {
        unsigned char *p;
        ext_len = method->i2d(ext_struc, NULL);
        if (!(ext_der = OPENSSL_malloc(ext_len)))
            goto merr;
        p = ext_der;
        method->i2d(ext_struc, &p);
=======
    if (nval == NULL || sk_CONF_VALUE_num(nval) <= 0) {
      OPENSSL_PUT_ERROR(X509V3, X509V3_R_INVALID_EXTENSION_STRING);
      ERR_add_error_data(4, "name=", OBJ_nid2sn(ext_nid), ",section=", value);
      sk_CONF_VALUE_pop_free(nval_owned, X509V3_conf_free);
      return NULL;
>>>>>>> CHANGE (34340c external/boringssl: Sync to 8aa51ddfcf1fbf2e5f976762657e21c7)
    }
<<<<<<< HEAD   (0a931c Snap for 8740412 from 2bbd592adbcc2fef5eb979af85d1e7b091f346)
    if (!(ext_oct = ASN1_OCTET_STRING_new()))
        goto merr;
    ext_oct->data = ext_der;
    ext_oct->length = ext_len;

    ext = X509_EXTENSION_create_by_NID(NULL, ext_nid, crit, ext_oct);
    if (!ext)
        goto merr;
    ASN1_OCTET_STRING_free(ext_oct);

    return ext;

 merr:
    OPENSSL_PUT_ERROR(X509V3, ERR_R_MALLOC_FAILURE);
=======
    ext_struc = method->v2i(method, ctx, nval);
    sk_CONF_VALUE_pop_free(nval_owned, X509V3_conf_free);
    if (!ext_struc) {
      return NULL;
    }
  } else if (method->s2i) {
    if (!(ext_struc = method->s2i(method, ctx, value))) {
      return NULL;
    }
  } else if (method->r2i) {
    // TODO(davidben): Should this check be removed? This matches OpenSSL, but
    // r2i-based extensions do not necessarily require a config database. The
    // two built-in extensions only use it some of the time, and already handle
    // |X509V3_get_section| returning NULL.
    if (!ctx->db) {
      OPENSSL_PUT_ERROR(X509V3, X509V3_R_NO_CONFIG_DATABASE);
      return NULL;
    }
    if (!(ext_struc = method->r2i(method, ctx, value))) {
      return NULL;
    }
  } else {
    OPENSSL_PUT_ERROR(X509V3, X509V3_R_EXTENSION_SETTING_NOT_SUPPORTED);
    ERR_add_error_data(2, "name=", OBJ_nid2sn(ext_nid));
>>>>>>> CHANGE (34340c external/boringssl: Sync to 8aa51ddfcf1fbf2e5f976762657e21c7)
    return NULL;

}

/* Given an internal structure, nid and critical flag create an extension */

X509_EXTENSION *X509V3_EXT_i2d(int ext_nid, int crit, void *ext_struc)
{
    const X509V3_EXT_METHOD *method;
    if (!(method = X509V3_EXT_get_nid(ext_nid))) {
        OPENSSL_PUT_ERROR(X509V3, X509V3_R_UNKNOWN_EXTENSION);
        return NULL;
    }
<<<<<<< HEAD   (0a931c Snap for 8740412 from 2bbd592adbcc2fef5eb979af85d1e7b091f346)
    return do_ext_i2d(method, ext_nid, crit, ext_struc);
=======
  } else {
    unsigned char *p;
    ext_len = method->i2d(ext_struc, NULL);
    if (!(ext_der = OPENSSL_malloc(ext_len))) {
      goto merr;
    }
    p = ext_der;
    method->i2d(ext_struc, &p);
  }
  if (!(ext_oct = ASN1_OCTET_STRING_new())) {
    goto merr;
  }
  ext_oct->data = ext_der;
  ext_oct->length = ext_len;

  ext = X509_EXTENSION_create_by_NID(NULL, ext_nid, crit, ext_oct);
  if (!ext) {
    goto merr;
  }
  ASN1_OCTET_STRING_free(ext_oct);

  return ext;

merr:
  return NULL;
>>>>>>> CHANGE (34340c external/boringssl: Sync to 8aa51ddfcf1fbf2e5f976762657e21c7)
}

/* Check the extension string for critical flag */
static int v3_check_critical(const char **value)
{
    const char *p = *value;
    if ((strlen(p) < 9) || strncmp(p, "critical,", 9))
        return 0;
    p += 9;
    while (isspace((unsigned char)*p))
        p++;
    *value = p;
    return 1;
}

<<<<<<< HEAD   (0a931c Snap for 8740412 from 2bbd592adbcc2fef5eb979af85d1e7b091f346)
/* Check extension string for generic extension and return the type */
static int v3_check_generic(const char **value)
{
    int gen_type = 0;
    const char *p = *value;
    if ((strlen(p) >= 4) && !strncmp(p, "DER:", 4)) {
        p += 4;
        gen_type = 1;
    } else if ((strlen(p) >= 5) && !strncmp(p, "ASN1:", 5)) {
        p += 5;
        gen_type = 2;
    } else
        return 0;

    while (isspace((unsigned char)*p))
        p++;
    *value = p;
    return gen_type;
=======
// Check the extension string for critical flag
static int v3_check_critical(const char **value) {
  const char *p = *value;
  if ((strlen(p) < 9) || strncmp(p, "critical,", 9)) {
    return 0;
  }
  p += 9;
  while (OPENSSL_isspace((unsigned char)*p)) {
    p++;
  }
  *value = p;
  return 1;
>>>>>>> CHANGE (34340c external/boringssl: Sync to 8aa51ddfcf1fbf2e5f976762657e21c7)
}

<<<<<<< HEAD   (0a931c Snap for 8740412 from 2bbd592adbcc2fef5eb979af85d1e7b091f346)
/* Create a generic extension: for now just handle DER type */
=======
// Check extension string for generic extension and return the type
static int v3_check_generic(const char **value) {
  int gen_type = 0;
  const char *p = *value;
  if ((strlen(p) >= 4) && !strncmp(p, "DER:", 4)) {
    p += 4;
    gen_type = 1;
  } else if ((strlen(p) >= 5) && !strncmp(p, "ASN1:", 5)) {
    p += 5;
    gen_type = 2;
  } else {
    return 0;
  }

  while (OPENSSL_isspace((unsigned char)*p)) {
    p++;
  }
  *value = p;
  return gen_type;
}

// Create a generic extension: for now just handle DER type
>>>>>>> CHANGE (34340c external/boringssl: Sync to 8aa51ddfcf1fbf2e5f976762657e21c7)
static X509_EXTENSION *v3_generic_extension(const char *ext, const char *value,
                                            int crit, int gen_type,
<<<<<<< HEAD   (0a931c Snap for 8740412 from 2bbd592adbcc2fef5eb979af85d1e7b091f346)
                                            X509V3_CTX *ctx)
{
    unsigned char *ext_der = NULL;
    long ext_len = 0;
    ASN1_OBJECT *obj = NULL;
    ASN1_OCTET_STRING *oct = NULL;
    X509_EXTENSION *extension = NULL;
    if (!(obj = OBJ_txt2obj(ext, 0))) {
        OPENSSL_PUT_ERROR(X509V3, X509V3_R_EXTENSION_NAME_ERROR);
        ERR_add_error_data(2, "name=", ext);
        goto err;
    }
=======
                                            const X509V3_CTX *ctx) {
  unsigned char *ext_der = NULL;
  long ext_len = 0;
  ASN1_OBJECT *obj = NULL;
  ASN1_OCTET_STRING *oct = NULL;
  X509_EXTENSION *extension = NULL;
  if (!(obj = OBJ_txt2obj(ext, 0))) {
    OPENSSL_PUT_ERROR(X509V3, X509V3_R_EXTENSION_NAME_ERROR);
    ERR_add_error_data(2, "name=", ext);
    goto err;
  }
>>>>>>> CHANGE (34340c external/boringssl: Sync to 8aa51ddfcf1fbf2e5f976762657e21c7)

    if (gen_type == 1)
        ext_der = x509v3_hex_to_bytes(value, &ext_len);
    else if (gen_type == 2)
        ext_der = generic_asn1(value, ctx, &ext_len);

    if (ext_der == NULL) {
        OPENSSL_PUT_ERROR(X509V3, X509V3_R_EXTENSION_VALUE_ERROR);
        ERR_add_error_data(2, "value=", value);
        goto err;
    }

<<<<<<< HEAD   (0a931c Snap for 8740412 from 2bbd592adbcc2fef5eb979af85d1e7b091f346)
    if (!(oct = ASN1_OCTET_STRING_new())) {
        OPENSSL_PUT_ERROR(X509V3, ERR_R_MALLOC_FAILURE);
        goto err;
    }
=======
  if (!(oct = ASN1_OCTET_STRING_new())) {
    goto err;
  }
>>>>>>> CHANGE (34340c external/boringssl: Sync to 8aa51ddfcf1fbf2e5f976762657e21c7)

    oct->data = ext_der;
    oct->length = ext_len;
    ext_der = NULL;

    extension = X509_EXTENSION_create_by_OBJ(NULL, obj, crit, oct);

 err:
    ASN1_OBJECT_free(obj);
    ASN1_OCTET_STRING_free(oct);
    if (ext_der)
        OPENSSL_free(ext_der);
    return extension;

}

<<<<<<< HEAD   (0a931c Snap for 8740412 from 2bbd592adbcc2fef5eb979af85d1e7b091f346)
static unsigned char *generic_asn1(const char *value, X509V3_CTX *ctx,
                                   long *ext_len)
{
    ASN1_TYPE *typ;
    unsigned char *ext_der = NULL;
    typ = ASN1_generate_v3(value, ctx);
    if (typ == NULL)
        return NULL;
    *ext_len = i2d_ASN1_TYPE(typ, &ext_der);
    ASN1_TYPE_free(typ);
    return ext_der;
=======
static unsigned char *generic_asn1(const char *value, const X509V3_CTX *ctx,
                                   long *ext_len) {
  ASN1_TYPE *typ;
  unsigned char *ext_der = NULL;
  typ = ASN1_generate_v3(value, ctx);
  if (typ == NULL) {
    return NULL;
  }
  *ext_len = i2d_ASN1_TYPE(typ, &ext_der);
  ASN1_TYPE_free(typ);
  return ext_der;
>>>>>>> CHANGE (34340c external/boringssl: Sync to 8aa51ddfcf1fbf2e5f976762657e21c7)
}

/*
 * This is the main function: add a bunch of extensions based on a config
 * file section to an extension STACK.
 */

<<<<<<< HEAD   (0a931c Snap for 8740412 from 2bbd592adbcc2fef5eb979af85d1e7b091f346)
int X509V3_EXT_add_nconf_sk(CONF *conf, X509V3_CTX *ctx, const char *section,
                            STACK_OF(X509_EXTENSION) **sk)
{
    X509_EXTENSION *ext;
    STACK_OF(CONF_VALUE) *nval;
    CONF_VALUE *val;
    size_t i;
    if (!(nval = NCONF_get_section(conf, section)))
        return 0;
    for (i = 0; i < sk_CONF_VALUE_num(nval); i++) {
        val = sk_CONF_VALUE_value(nval, i);
        if (!(ext = X509V3_EXT_nconf(conf, ctx, val->name, val->value)))
            return 0;
        if (sk)
            X509v3_add_ext(sk, ext, -1);
        X509_EXTENSION_free(ext);
=======
int X509V3_EXT_add_nconf_sk(const CONF *conf, const X509V3_CTX *ctx,
                            const char *section,
                            STACK_OF(X509_EXTENSION) **sk) {
  const STACK_OF(CONF_VALUE) *nval = NCONF_get_section(conf, section);
  if (nval == NULL) {
    return 0;
  }
  for (size_t i = 0; i < sk_CONF_VALUE_num(nval); i++) {
    const CONF_VALUE *val = sk_CONF_VALUE_value(nval, i);
    X509_EXTENSION *ext = X509V3_EXT_nconf(conf, ctx, val->name, val->value);
    int ok = ext != NULL &&  //
             (sk == NULL || X509v3_add_ext(sk, ext, -1) != NULL);
    X509_EXTENSION_free(ext);
    if (!ok) {
      return 0;
>>>>>>> CHANGE (34340c external/boringssl: Sync to 8aa51ddfcf1fbf2e5f976762657e21c7)
    }
<<<<<<< HEAD   (0a931c Snap for 8740412 from 2bbd592adbcc2fef5eb979af85d1e7b091f346)
    return 1;
=======
  }
  return 1;
>>>>>>> CHANGE (34340c external/boringssl: Sync to 8aa51ddfcf1fbf2e5f976762657e21c7)
}

/*
 * Convenience functions to add extensions to a certificate, CRL and request
 */

<<<<<<< HEAD   (0a931c Snap for 8740412 from 2bbd592adbcc2fef5eb979af85d1e7b091f346)
int X509V3_EXT_add_nconf(CONF *conf, X509V3_CTX *ctx, const char *section,
                         X509 *cert)
{
    STACK_OF(X509_EXTENSION) **sk = NULL;
    if (cert)
        sk = &cert->cert_info->extensions;
    return X509V3_EXT_add_nconf_sk(conf, ctx, section, sk);
=======
int X509V3_EXT_add_nconf(const CONF *conf, const X509V3_CTX *ctx,
                         const char *section, X509 *cert) {
  STACK_OF(X509_EXTENSION) **sk = NULL;
  if (cert) {
    sk = &cert->cert_info->extensions;
  }
  return X509V3_EXT_add_nconf_sk(conf, ctx, section, sk);
>>>>>>> CHANGE (34340c external/boringssl: Sync to 8aa51ddfcf1fbf2e5f976762657e21c7)
}

/* Same as above but for a CRL */

<<<<<<< HEAD   (0a931c Snap for 8740412 from 2bbd592adbcc2fef5eb979af85d1e7b091f346)
int X509V3_EXT_CRL_add_nconf(CONF *conf, X509V3_CTX *ctx, const char *section,
                             X509_CRL *crl)
{
    STACK_OF(X509_EXTENSION) **sk = NULL;
    if (crl)
        sk = &crl->crl->extensions;
    return X509V3_EXT_add_nconf_sk(conf, ctx, section, sk);
=======
int X509V3_EXT_CRL_add_nconf(const CONF *conf, const X509V3_CTX *ctx,
                             const char *section, X509_CRL *crl) {
  STACK_OF(X509_EXTENSION) **sk = NULL;
  if (crl) {
    sk = &crl->crl->extensions;
  }
  return X509V3_EXT_add_nconf_sk(conf, ctx, section, sk);
>>>>>>> CHANGE (34340c external/boringssl: Sync to 8aa51ddfcf1fbf2e5f976762657e21c7)
}

/* Add extensions to certificate request */

<<<<<<< HEAD   (0a931c Snap for 8740412 from 2bbd592adbcc2fef5eb979af85d1e7b091f346)
int X509V3_EXT_REQ_add_nconf(CONF *conf, X509V3_CTX *ctx, const char *section,
                             X509_REQ *req)
{
    STACK_OF(X509_EXTENSION) *extlist = NULL, **sk = NULL;
    int i;
    if (req)
        sk = &extlist;
    i = X509V3_EXT_add_nconf_sk(conf, ctx, section, sk);
    if (!i || !sk)
        return i;
    i = X509_REQ_add_extensions(req, extlist);
    sk_X509_EXTENSION_pop_free(extlist, X509_EXTENSION_free);
=======
int X509V3_EXT_REQ_add_nconf(const CONF *conf, const X509V3_CTX *ctx,
                             const char *section, X509_REQ *req) {
  STACK_OF(X509_EXTENSION) *extlist = NULL, **sk = NULL;
  int i;
  if (req) {
    sk = &extlist;
  }
  i = X509V3_EXT_add_nconf_sk(conf, ctx, section, sk);
  if (!i || !sk) {
>>>>>>> CHANGE (34340c external/boringssl: Sync to 8aa51ddfcf1fbf2e5f976762657e21c7)
    return i;
}

/* Config database functions */

<<<<<<< HEAD   (0a931c Snap for 8740412 from 2bbd592adbcc2fef5eb979af85d1e7b091f346)
char *X509V3_get_string(X509V3_CTX *ctx, const char *name, const char *section)
{
    if (!ctx->db || !ctx->db_meth || !ctx->db_meth->get_string) {
        OPENSSL_PUT_ERROR(X509V3, X509V3_R_OPERATION_NOT_DEFINED);
        return NULL;
    }
    if (ctx->db_meth->get_string)
        return ctx->db_meth->get_string(ctx->db, name, section);
=======
const STACK_OF(CONF_VALUE) *X509V3_get_section(const X509V3_CTX *ctx,
                                               const char *section) {
  if (ctx->db == NULL) {
    OPENSSL_PUT_ERROR(X509V3, X509V3_R_OPERATION_NOT_DEFINED);
>>>>>>> CHANGE (34340c external/boringssl: Sync to 8aa51ddfcf1fbf2e5f976762657e21c7)
    return NULL;
<<<<<<< HEAD   (0a931c Snap for 8740412 from 2bbd592adbcc2fef5eb979af85d1e7b091f346)
=======
  }
  return NCONF_get_section(ctx->db, section);
>>>>>>> CHANGE (34340c external/boringssl: Sync to 8aa51ddfcf1fbf2e5f976762657e21c7)
}

<<<<<<< HEAD   (0a931c Snap for 8740412 from 2bbd592adbcc2fef5eb979af85d1e7b091f346)
STACK_OF(CONF_VALUE) *X509V3_get_section(X509V3_CTX *ctx, const char *section)
{
    if (!ctx->db || !ctx->db_meth || !ctx->db_meth->get_section) {
        OPENSSL_PUT_ERROR(X509V3, X509V3_R_OPERATION_NOT_DEFINED);
        return NULL;
    }
    if (ctx->db_meth->get_section)
        return ctx->db_meth->get_section(ctx->db, section);
    return NULL;
}

void X509V3_string_free(X509V3_CTX *ctx, char *str)
{
    if (!str)
        return;
    if (ctx->db_meth->free_string)
        ctx->db_meth->free_string(ctx->db, str);
}

void X509V3_section_free(X509V3_CTX *ctx, STACK_OF(CONF_VALUE) *section)
{
    if (!section)
        return;
    if (ctx->db_meth->free_section)
        ctx->db_meth->free_section(ctx->db, section);
}

static char *nconf_get_string(void *db, const char *section, const char *value)
{
    /* TODO(fork): This returns a non-const pointer because |X509V3_CONF_METHOD|
     * allows |get_string| to return caller-owned pointers, provided they're
     * freed by |free_string|. |nconf_method| leaves |free_string| NULL, and
     * there are no other implementations of |X509V3_CONF_METHOD|, so this can
     * be simplified if we make it private. */
    return (char *)NCONF_get_string(db, section, value);
}

static STACK_OF(CONF_VALUE) *nconf_get_section(void *db, const char *section)
{
    return NCONF_get_section(db, section);
}

static const X509V3_CONF_METHOD nconf_method = {
    nconf_get_string,
    nconf_get_section,
    NULL,
    NULL
};

void X509V3_set_nconf(X509V3_CTX *ctx, CONF *conf)
{
    ctx->db_meth = &nconf_method;
    ctx->db = conf;
=======
void X509V3_set_nconf(X509V3_CTX *ctx, const CONF *conf) {
  ctx->db = conf;
>>>>>>> CHANGE (34340c external/boringssl: Sync to 8aa51ddfcf1fbf2e5f976762657e21c7)
}

<<<<<<< HEAD   (0a931c Snap for 8740412 from 2bbd592adbcc2fef5eb979af85d1e7b091f346)
void X509V3_set_ctx(X509V3_CTX *ctx, X509 *issuer, X509 *subj, X509_REQ *req,
                    X509_CRL *crl, int flags)
{
    ctx->issuer_cert = issuer;
    ctx->subject_cert = subj;
    ctx->crl = crl;
    ctx->subject_req = req;
    ctx->flags = flags;
=======
void X509V3_set_ctx(X509V3_CTX *ctx, const X509 *issuer, const X509 *subj,
                    const X509_REQ *req, const X509_CRL *crl, int flags) {
  OPENSSL_memset(ctx, 0, sizeof(*ctx));
  ctx->issuer_cert = issuer;
  ctx->subject_cert = subj;
  ctx->crl = crl;
  ctx->subject_req = req;
  ctx->flags = flags;
>>>>>>> CHANGE (34340c external/boringssl: Sync to 8aa51ddfcf1fbf2e5f976762657e21c7)
}
