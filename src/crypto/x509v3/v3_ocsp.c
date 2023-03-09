/*
 * Copyright 2000-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/x509v3.h>

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/nid.h>

/*
 * OCSP extensions and a couple of CRL entry extensions
 */

static int i2r_ocsp_acutoff(const X509V3_EXT_METHOD *method, void *nonce,
                            BIO *out, int indent);

<<<<<<< HEAD   (0a931c Snap for 8740412 from 2bbd592adbcc2fef5eb979af85d1e7b091f346)
static int i2r_ocsp_nocheck(const X509V3_EXT_METHOD *method,
                            void *nocheck, BIO *out, int indent);
static void *s2i_ocsp_nocheck(const X509V3_EXT_METHOD *method,
                              X509V3_CTX *ctx, const char *str);
=======
static int i2r_ocsp_nocheck(const X509V3_EXT_METHOD *method, void *nocheck,
                            BIO *out, int indent);
static void *s2i_ocsp_nocheck(const X509V3_EXT_METHOD *method,
                              const X509V3_CTX *ctx, const char *str);
>>>>>>> CHANGE (34340c external/boringssl: Sync to 8aa51ddfcf1fbf2e5f976762657e21c7)

const X509V3_EXT_METHOD v3_crl_invdate = {
    NID_invalidity_date, 0, ASN1_ITEM_ref(ASN1_GENERALIZEDTIME),
    0, 0, 0, 0,
    0, 0,
    0, 0,
    i2r_ocsp_acutoff, 0,
    NULL
};

const X509V3_EXT_METHOD v3_ocsp_nocheck = {
    NID_id_pkix_OCSP_noCheck, 0, ASN1_ITEM_ref(ASN1_NULL),
    0, 0, 0, 0,
    0, s2i_ocsp_nocheck,
    0, 0,
    i2r_ocsp_nocheck, 0,
    NULL
};

static int i2r_ocsp_acutoff(const X509V3_EXT_METHOD *method, void *cutoff,
                            BIO *bp, int ind)
{
    if (BIO_printf(bp, "%*s", ind, "") <= 0)
        return 0;
    if (!ASN1_GENERALIZEDTIME_print(bp, cutoff))
        return 0;
    return 1;
}

/* Nocheck is just a single NULL. Don't print anything and always set it */

static int i2r_ocsp_nocheck(const X509V3_EXT_METHOD *method, void *nocheck,
                            BIO *out, int indent)
{
    return 1;
}

static void *s2i_ocsp_nocheck(const X509V3_EXT_METHOD *method,
<<<<<<< HEAD   (0a931c Snap for 8740412 from 2bbd592adbcc2fef5eb979af85d1e7b091f346)
                              X509V3_CTX *ctx, const char *str)
{
    return ASN1_NULL_new();
=======
                              const X509V3_CTX *ctx, const char *str) {
  return ASN1_NULL_new();
>>>>>>> CHANGE (34340c external/boringssl: Sync to 8aa51ddfcf1fbf2e5f976762657e21c7)
}
