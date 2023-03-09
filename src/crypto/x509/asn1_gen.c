/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.] */

#include <openssl/x509.h>

#include <assert.h>
#include <ctype.h>
#include <limits.h>
#include <string.h>

#include <openssl/asn1.h>
#include <openssl/bytestring.h>
#include <openssl/err.h>
#include <openssl/obj.h>
#include <openssl/x509v3.h>

#include "../internal.h"
#include "../x509v3/internal.h"
#include "internal.h"

<<<<<<< HEAD   (0a931c Snap for 8740412 from 2bbd592adbcc2fef5eb979af85d1e7b091f346)
/*
 * Although this file is in crypto/x509 for layering purposes, it emits
 * errors from the ASN.1 module for OpenSSL compatibility.
 */
=======

// Although this file is in crypto/x509 for layering purposes, it emits
// errors from the ASN.1 module for OpenSSL compatibility.
>>>>>>> CHANGE (34340c external/boringssl: Sync to 8aa51ddfcf1fbf2e5f976762657e21c7)

<<<<<<< HEAD   (0a931c Snap for 8740412 from 2bbd592adbcc2fef5eb979af85d1e7b091f346)
#define ASN1_GEN_FLAG           0x10000
#define ASN1_GEN_FLAG_IMP       (ASN1_GEN_FLAG|1)
#define ASN1_GEN_FLAG_EXP       (ASN1_GEN_FLAG|2)
#define ASN1_GEN_FLAG_TAG       (ASN1_GEN_FLAG|3)
#define ASN1_GEN_FLAG_BITWRAP   (ASN1_GEN_FLAG|4)
#define ASN1_GEN_FLAG_OCTWRAP   (ASN1_GEN_FLAG|5)
#define ASN1_GEN_FLAG_SEQWRAP   (ASN1_GEN_FLAG|6)
#define ASN1_GEN_FLAG_SETWRAP   (ASN1_GEN_FLAG|7)
#define ASN1_GEN_FLAG_FORMAT    (ASN1_GEN_FLAG|8)
=======
// ASN1_GEN_MAX_DEPTH is the maximum number of nested TLVs allowed.
#define ASN1_GEN_MAX_DEPTH 50
>>>>>>> CHANGE (34340c external/boringssl: Sync to 8aa51ddfcf1fbf2e5f976762657e21c7)

<<<<<<< HEAD   (0a931c Snap for 8740412 from 2bbd592adbcc2fef5eb979af85d1e7b091f346)
#define ASN1_GEN_STR(str,val)   {str, sizeof(str) - 1, val}
=======
// ASN1_GEN_MAX_OUTPUT is the maximum output, in bytes, allowed. This limit is
// necessary because the SEQUENCE and SET section reference mechanism allows the
// output length to grow super-linearly with the input length.
#define ASN1_GEN_MAX_OUTPUT (64 * 1024)
>>>>>>> CHANGE (34340c external/boringssl: Sync to 8aa51ddfcf1fbf2e5f976762657e21c7)

<<<<<<< HEAD   (0a931c Snap for 8740412 from 2bbd592adbcc2fef5eb979af85d1e7b091f346)
#define ASN1_FLAG_EXP_MAX       20
/* Maximum number of nested sequences */
#define ASN1_GEN_SEQ_MAX_DEPTH  50

/* Input formats */

/* ASCII: default */
#define ASN1_GEN_FORMAT_ASCII   1
/* UTF8 */
#define ASN1_GEN_FORMAT_UTF8    2
/* Hex */
#define ASN1_GEN_FORMAT_HEX     3
/* List of bits */
=======
// ASN1_GEN_FORMAT_* are the values for the format modifiers.
#define ASN1_GEN_FORMAT_ASCII 1
#define ASN1_GEN_FORMAT_UTF8 2
#define ASN1_GEN_FORMAT_HEX 3
>>>>>>> CHANGE (34340c external/boringssl: Sync to 8aa51ddfcf1fbf2e5f976762657e21c7)
#define ASN1_GEN_FORMAT_BITLIST 4

<<<<<<< HEAD   (0a931c Snap for 8740412 from 2bbd592adbcc2fef5eb979af85d1e7b091f346)
struct tag_name_st {
    const char *strnam;
    int len;
    int tag;
};
=======
// generate_v3 converts |str| into an ASN.1 structure and writes the result to
// |cbb|. It returns one on success and zero on error. |depth| bounds recursion,
// and |format| specifies the current format modifier.
//
// If |tag| is non-zero, the structure is implicitly tagged with |tag|. |tag|
// must not have the constructed bit set.
static int generate_v3(CBB *cbb, const char *str, const X509V3_CTX *cnf,
                       CBS_ASN1_TAG tag, int format, int depth);
>>>>>>> CHANGE (34340c external/boringssl: Sync to 8aa51ddfcf1fbf2e5f976762657e21c7)

<<<<<<< HEAD   (0a931c Snap for 8740412 from 2bbd592adbcc2fef5eb979af85d1e7b091f346)
typedef struct {
    int exp_tag;
    int exp_class;
    int exp_constructed;
    int exp_pad;
    long exp_len;
} tag_exp_type;

typedef struct {
    int imp_tag;
    int imp_class;
    int utype;
    int format;
    const char *str;
    tag_exp_type exp_list[ASN1_FLAG_EXP_MAX];
    int exp_count;
} tag_exp_arg;

static ASN1_TYPE *generate_v3(const char *str, X509V3_CTX *cnf, int depth,
                              int *perr);
static int bitstr_cb(const char *elem, int len, void *bitstr);
static int asn1_cb(const char *elem, int len, void *bitstr);
static int append_exp(tag_exp_arg *arg, int exp_tag, int exp_class,
                      int exp_constructed, int exp_pad, int imp_ok);
static int parse_tagging(const char *vstart, int vlen, int *ptag,
                         int *pclass);
static ASN1_TYPE *asn1_multi(int utype, const char *section, X509V3_CTX *cnf,
                             int depth, int *perr);
static ASN1_TYPE *asn1_str2type(const char *str, int format, int utype);
static int asn1_str2tag(const char *tagstr, int len);
=======
static int bitstr_cb(const char *elem, size_t len, void *bitstr);
>>>>>>> CHANGE (34340c external/boringssl: Sync to 8aa51ddfcf1fbf2e5f976762657e21c7)

<<<<<<< HEAD   (0a931c Snap for 8740412 from 2bbd592adbcc2fef5eb979af85d1e7b091f346)
ASN1_TYPE *ASN1_generate_v3(const char *str, X509V3_CTX *cnf)
{
    int err = 0;
    ASN1_TYPE *ret = generate_v3(str, cnf, 0, &err);
    if (err)
        OPENSSL_PUT_ERROR(ASN1, err);
    return ret;
}

static ASN1_TYPE *generate_v3(const char *str, X509V3_CTX *cnf, int depth,
                              int *perr)
{
    ASN1_TYPE *ret;
    tag_exp_arg asn1_tags;
    tag_exp_type *etmp;

    int i, len;

    unsigned char *orig_der = NULL, *new_der = NULL;
    const unsigned char *cpy_start;
    unsigned char *p;
    const unsigned char *cp;
    int cpy_len;
    long hdr_len = 0;
    int hdr_constructed = 0, hdr_tag, hdr_class;
    int r;

    asn1_tags.imp_tag = -1;
    asn1_tags.imp_class = -1;
    asn1_tags.format = ASN1_GEN_FORMAT_ASCII;
    asn1_tags.exp_count = 0;
    if (CONF_parse_list(str, ',', 1, asn1_cb, &asn1_tags) != 0) {
        *perr = ASN1_R_UNKNOWN_TAG;
        return NULL;
    }

    if ((asn1_tags.utype == V_ASN1_SEQUENCE)
        || (asn1_tags.utype == V_ASN1_SET)) {
        if (!cnf) {
            *perr = ASN1_R_SEQUENCE_OR_SET_NEEDS_CONFIG;
            return NULL;
        }
        if (depth >= ASN1_GEN_SEQ_MAX_DEPTH) {
            *perr = ASN1_R_ILLEGAL_NESTED_TAGGING;
            return NULL;
        }
        ret = asn1_multi(asn1_tags.utype, asn1_tags.str, cnf, depth, perr);
    } else
        ret = asn1_str2type(asn1_tags.str, asn1_tags.format, asn1_tags.utype);

    if (!ret)
        return NULL;

    /* If no tagging return base type */
    if ((asn1_tags.imp_tag == -1) && (asn1_tags.exp_count == 0))
        return ret;

    /* Generate the encoding */
    cpy_len = i2d_ASN1_TYPE(ret, &orig_der);
    ASN1_TYPE_free(ret);
    ret = NULL;
    /* Set point to start copying for modified encoding */
    cpy_start = orig_der;

    /* Do we need IMPLICIT tagging? */
    if (asn1_tags.imp_tag != -1) {
        /* If IMPLICIT we will replace the underlying tag */
        /* Skip existing tag+len */
        r = ASN1_get_object(&cpy_start, &hdr_len, &hdr_tag, &hdr_class,
                            cpy_len);
        if (r & 0x80)
            goto err;
        /* Update copy length */
        cpy_len -= cpy_start - orig_der;
        /*
         * For IMPLICIT tagging the length should match the original length
         * and constructed flag should be consistent.
         */
        hdr_constructed = r & V_ASN1_CONSTRUCTED;
        /*
         * Work out new length with IMPLICIT tag: ignore constructed because
         * it will mess up if indefinite length
         */
        len = ASN1_object_size(0, hdr_len, asn1_tags.imp_tag);
    } else
        len = cpy_len;

    /* Work out length in any EXPLICIT, starting from end */

    for (i = 0, etmp = asn1_tags.exp_list + asn1_tags.exp_count - 1;
         i < asn1_tags.exp_count; i++, etmp--) {
        /* Content length: number of content octets + any padding */
        len += etmp->exp_pad;
        etmp->exp_len = len;
        /* Total object length: length including new header */
        len = ASN1_object_size(0, len, etmp->exp_tag);
    }

    /* Allocate buffer for new encoding */
=======
ASN1_TYPE *ASN1_generate_v3(const char *str, const X509V3_CTX *cnf) {
  CBB cbb;
  if (!CBB_init(&cbb, 0) ||  //
      !generate_v3(&cbb, str, cnf, /*tag=*/0, ASN1_GEN_FORMAT_ASCII,
                   /*depth=*/0)) {
    CBB_cleanup(&cbb);
    return NULL;
  }

  // While not strictly necessary to avoid a DoS (we rely on any super-linear
  // checks being performed internally), cap the overall output to
  // |ASN1_GEN_MAX_OUTPUT| so the externally-visible behavior is consistent.
  if (CBB_len(&cbb) > ASN1_GEN_MAX_OUTPUT) {
    OPENSSL_PUT_ERROR(ASN1, ASN1_R_TOO_LONG);
    CBB_cleanup(&cbb);
    return NULL;
  }
>>>>>>> CHANGE (34340c external/boringssl: Sync to 8aa51ddfcf1fbf2e5f976762657e21c7)

<<<<<<< HEAD   (0a931c Snap for 8740412 from 2bbd592adbcc2fef5eb979af85d1e7b091f346)
    new_der = OPENSSL_malloc(len);
    if (!new_der)
        goto err;

    /* Generate tagged encoding */

    p = new_der;

    /* Output explicit tags first */

    for (i = 0, etmp = asn1_tags.exp_list; i < asn1_tags.exp_count;
         i++, etmp++) {
        ASN1_put_object(&p, etmp->exp_constructed, etmp->exp_len,
                        etmp->exp_tag, etmp->exp_class);
        if (etmp->exp_pad)
            *p++ = 0;
    }

    /* If IMPLICIT, output tag */

    if (asn1_tags.imp_tag != -1) {
        if (asn1_tags.imp_class == V_ASN1_UNIVERSAL
            && (asn1_tags.imp_tag == V_ASN1_SEQUENCE
                || asn1_tags.imp_tag == V_ASN1_SET))
            hdr_constructed = V_ASN1_CONSTRUCTED;
        ASN1_put_object(&p, hdr_constructed, hdr_len,
                        asn1_tags.imp_tag, asn1_tags.imp_class);
    }

    /* Copy across original encoding */
    OPENSSL_memcpy(p, cpy_start, cpy_len);

    cp = new_der;

    /* Obtain new ASN1_TYPE structure */
    ret = d2i_ASN1_TYPE(NULL, &cp, len);

 err:
    if (orig_der)
        OPENSSL_free(orig_der);
    if (new_der)
        OPENSSL_free(new_der);

    return ret;

=======
  const uint8_t *der = CBB_data(&cbb);
  ASN1_TYPE *ret = d2i_ASN1_TYPE(NULL, &der, CBB_len(&cbb));
  CBB_cleanup(&cbb);
  return ret;
>>>>>>> CHANGE (34340c external/boringssl: Sync to 8aa51ddfcf1fbf2e5f976762657e21c7)
}

<<<<<<< HEAD   (0a931c Snap for 8740412 from 2bbd592adbcc2fef5eb979af85d1e7b091f346)
static int asn1_cb(const char *elem, int len, void *bitstr)
{
    tag_exp_arg *arg = bitstr;
    int i;
    int utype;
    int vlen = 0;
    const char *p, *vstart = NULL;

    int tmp_tag, tmp_class;

    if (elem == NULL)
        return -1;

    for (i = 0, p = elem; i < len; p++, i++) {
        /* Look for the ':' in name value pairs */
        if (*p == ':') {
            vstart = p + 1;
            vlen = len - (vstart - elem);
            len = p - elem;
            break;
        }
    }

    utype = asn1_str2tag(elem, len);

    if (utype == -1) {
        OPENSSL_PUT_ERROR(ASN1, ASN1_R_UNKNOWN_TAG);
        ERR_add_error_data(2, "tag=", elem);
        return -1;
    }

    /* If this is not a modifier mark end of string and exit */
    if (!(utype & ASN1_GEN_FLAG)) {
        arg->utype = utype;
        arg->str = vstart;
        /* If no value and not end of string, error */
        if (!vstart && elem[len]) {
            OPENSSL_PUT_ERROR(ASN1, ASN1_R_MISSING_VALUE);
            return -1;
        }
        return 0;
    }

    switch (utype) {

    case ASN1_GEN_FLAG_IMP:
        /* Check for illegal multiple IMPLICIT tagging */
        if (arg->imp_tag != -1) {
            OPENSSL_PUT_ERROR(ASN1, ASN1_R_ILLEGAL_NESTED_TAGGING);
            return -1;
        }
        if (!parse_tagging(vstart, vlen, &arg->imp_tag, &arg->imp_class))
            return -1;
        break;

    case ASN1_GEN_FLAG_EXP:

        if (!parse_tagging(vstart, vlen, &tmp_tag, &tmp_class))
            return -1;
        if (!append_exp(arg, tmp_tag, tmp_class, 1, 0, 0))
            return -1;
        break;

    case ASN1_GEN_FLAG_SEQWRAP:
        if (!append_exp(arg, V_ASN1_SEQUENCE, V_ASN1_UNIVERSAL, 1, 0, 1))
            return -1;
        break;

    case ASN1_GEN_FLAG_SETWRAP:
        if (!append_exp(arg, V_ASN1_SET, V_ASN1_UNIVERSAL, 1, 0, 1))
            return -1;
        break;

    case ASN1_GEN_FLAG_BITWRAP:
        if (!append_exp(arg, V_ASN1_BIT_STRING, V_ASN1_UNIVERSAL, 0, 1, 1))
            return -1;
        break;

    case ASN1_GEN_FLAG_OCTWRAP:
        if (!append_exp(arg, V_ASN1_OCTET_STRING, V_ASN1_UNIVERSAL, 0, 0, 1))
            return -1;
        break;

    case ASN1_GEN_FLAG_FORMAT:
        if (!vstart) {
            OPENSSL_PUT_ERROR(ASN1, ASN1_R_UNKNOWN_FORMAT);
            return -1;
        }
        if (!strncmp(vstart, "ASCII", 5))
            arg->format = ASN1_GEN_FORMAT_ASCII;
        else if (!strncmp(vstart, "UTF8", 4))
            arg->format = ASN1_GEN_FORMAT_UTF8;
        else if (!strncmp(vstart, "HEX", 3))
            arg->format = ASN1_GEN_FORMAT_HEX;
        else if (!strncmp(vstart, "BITLIST", 7))
            arg->format = ASN1_GEN_FORMAT_BITLIST;
        else {
            OPENSSL_PUT_ERROR(ASN1, ASN1_R_UNKNOWN_FORMAT);
            return -1;
        }
=======
static int cbs_str_equal(const CBS *cbs, const char *str) {
  return CBS_len(cbs) == strlen(str) &&
         OPENSSL_memcmp(CBS_data(cbs), str, strlen(str)) == 0;
}

// parse_tag decodes a tag specifier in |cbs|. It returns the tag on success or
// zero on error.
static CBS_ASN1_TAG parse_tag(const CBS *cbs) {
  CBS copy = *cbs;
  uint64_t num;
  if (!CBS_get_u64_decimal(&copy, &num) ||
      num > CBS_ASN1_TAG_NUMBER_MASK) {
    OPENSSL_PUT_ERROR(ASN1, ASN1_R_INVALID_NUMBER);
    return 0;
  }

  CBS_ASN1_TAG tag_class = CBS_ASN1_CONTEXT_SPECIFIC;
  // The tag may be suffixed by a class.
  uint8_t c;
  if (CBS_get_u8(&copy, &c)) {
    switch (c) {
      case 'U':
        tag_class = CBS_ASN1_UNIVERSAL;
>>>>>>> CHANGE (34340c external/boringssl: Sync to 8aa51ddfcf1fbf2e5f976762657e21c7)
        break;
<<<<<<< HEAD   (0a931c Snap for 8740412 from 2bbd592adbcc2fef5eb979af85d1e7b091f346)

    }

    return 1;

}

static int parse_tagging(const char *vstart, int vlen, int *ptag, int *pclass)
{
    char erch[2];
    long tag_num;
    char *eptr;
    if (!vstart)
        return 0;
    tag_num = strtoul(vstart, &eptr, 10);
    /* Check we haven't gone past max length: should be impossible */
    if (eptr && *eptr && (eptr > vstart + vlen))
        return 0;
    if (tag_num < 0) {
        OPENSSL_PUT_ERROR(ASN1, ASN1_R_INVALID_NUMBER);
        return 0;
    }
    *ptag = tag_num;
    /* If we have non numeric characters, parse them */
    if (eptr)
        vlen -= eptr - vstart;
    else
        vlen = 0;
    if (vlen) {
        switch (*eptr) {

        case 'U':
            *pclass = V_ASN1_UNIVERSAL;
            break;

        case 'A':
            *pclass = V_ASN1_APPLICATION;
            break;

        case 'P':
            *pclass = V_ASN1_PRIVATE;
            break;

        case 'C':
            *pclass = V_ASN1_CONTEXT_SPECIFIC;
            break;

        default:
            erch[0] = *eptr;
            erch[1] = 0;
            OPENSSL_PUT_ERROR(ASN1, ASN1_R_INVALID_MODIFIER);
            ERR_add_error_data(2, "Char=", erch);
            return 0;
            break;

        }
    } else
        *pclass = V_ASN1_CONTEXT_SPECIFIC;

    return 1;

}

/* Handle multiple types: SET and SEQUENCE */

static ASN1_TYPE *asn1_multi(int utype, const char *section, X509V3_CTX *cnf,
                             int depth, int *perr)
{
    ASN1_TYPE *ret = NULL;
    STACK_OF(ASN1_TYPE) *sk = NULL;
    STACK_OF(CONF_VALUE) *sect = NULL;
    unsigned char *der = NULL;
    int derlen;
    size_t i;
    sk = sk_ASN1_TYPE_new_null();
    if (!sk)
        goto bad;
    if (section) {
        if (!cnf)
            goto bad;
        sect = X509V3_get_section(cnf, (char *)section);
        if (!sect)
            goto bad;
        for (i = 0; i < sk_CONF_VALUE_num(sect); i++) {
            ASN1_TYPE *typ =
                generate_v3(sk_CONF_VALUE_value(sect, i)->value, cnf,
                            depth + 1, perr);
            if (!typ)
                goto bad;
            if (!sk_ASN1_TYPE_push(sk, typ))
                goto bad;
        }
=======
      case 'A':
        tag_class = CBS_ASN1_APPLICATION;
        break;
      case 'P':
        tag_class = CBS_ASN1_PRIVATE;
        break;
      case 'C':
        tag_class = CBS_ASN1_CONTEXT_SPECIFIC;
        break;
      default: {
        OPENSSL_PUT_ERROR(ASN1, ASN1_R_INVALID_MODIFIER);
        return 0;
      }
>>>>>>> CHANGE (34340c external/boringssl: Sync to 8aa51ddfcf1fbf2e5f976762657e21c7)
    }
<<<<<<< HEAD   (0a931c Snap for 8740412 from 2bbd592adbcc2fef5eb979af85d1e7b091f346)
=======
    if (CBS_len(&copy) != 0) {
      OPENSSL_PUT_ERROR(ASN1, ASN1_R_INVALID_MODIFIER);
      return 0;
    }
  }
>>>>>>> CHANGE (34340c external/boringssl: Sync to 8aa51ddfcf1fbf2e5f976762657e21c7)

<<<<<<< HEAD   (0a931c Snap for 8740412 from 2bbd592adbcc2fef5eb979af85d1e7b091f346)
    /*
     * Now we has a STACK of the components, convert to the correct form
     */

    if (utype == V_ASN1_SET)
        derlen = i2d_ASN1_SET_ANY(sk, &der);
    else
        derlen = i2d_ASN1_SEQUENCE_ANY(sk, &der);

    if (derlen < 0)
        goto bad;

    if (!(ret = ASN1_TYPE_new()))
        goto bad;

    if (!(ret->value.asn1_string = ASN1_STRING_type_new(utype)))
        goto bad;

    ret->type = utype;

    ret->value.asn1_string->data = der;
    ret->value.asn1_string->length = derlen;

    der = NULL;

 bad:

    if (der)
        OPENSSL_free(der);

    if (sk)
        sk_ASN1_TYPE_pop_free(sk, ASN1_TYPE_free);
    if (sect)
        X509V3_section_free(cnf, sect);

    return ret;
}

static int append_exp(tag_exp_arg *arg, int exp_tag, int exp_class,
                      int exp_constructed, int exp_pad, int imp_ok)
{
    tag_exp_type *exp_tmp;
    /* Can only have IMPLICIT if permitted */
    if ((arg->imp_tag != -1) && !imp_ok) {
        OPENSSL_PUT_ERROR(ASN1, ASN1_R_ILLEGAL_IMPLICIT_TAG);
        return 0;
=======
  // Tag [UNIVERSAL 0] is reserved for indefinite-length end-of-contents. We
  // also use zero in this file to indicator no explicit tagging.
  if (tag_class == CBS_ASN1_UNIVERSAL && num == 0) {
    OPENSSL_PUT_ERROR(ASN1, ASN1_R_INVALID_NUMBER);
    return 0;
  }

  return tag_class | (CBS_ASN1_TAG)num;
}

static int generate_wrapped(CBB *cbb, const char *str, const X509V3_CTX *cnf,
                            CBS_ASN1_TAG tag, int padding, int format,
                            int depth) {
  CBB child;
  return CBB_add_asn1(cbb, &child, tag) &&
         (!padding || CBB_add_u8(&child, 0)) &&
         generate_v3(&child, str, cnf, /*tag=*/0, format, depth + 1) &&
         CBB_flush(cbb);
}

static int generate_v3(CBB *cbb, const char *str, const X509V3_CTX *cnf,
                       CBS_ASN1_TAG tag, int format, int depth) {
  assert((tag & CBS_ASN1_CONSTRUCTED) == 0);
  if (depth > ASN1_GEN_MAX_DEPTH) {
    OPENSSL_PUT_ERROR(ASN1, ASN1_R_ILLEGAL_NESTED_TAGGING);
    return 0;
  }

  // Process modifiers. This function uses a mix of NUL-terminated strings and
  // |CBS|. Several functions only work with NUL-terminated strings, so we need
  // to keep track of when a slice spans the whole buffer.
  for (;;) {
    // Skip whitespace.
    while (*str != '\0' && OPENSSL_isspace((unsigned char)*str)) {
      str++;
>>>>>>> CHANGE (34340c external/boringssl: Sync to 8aa51ddfcf1fbf2e5f976762657e21c7)
    }

<<<<<<< HEAD   (0a931c Snap for 8740412 from 2bbd592adbcc2fef5eb979af85d1e7b091f346)
    if (arg->exp_count == ASN1_FLAG_EXP_MAX) {
        OPENSSL_PUT_ERROR(ASN1, ASN1_R_DEPTH_EXCEEDED);
        return 0;
    }

    exp_tmp = &arg->exp_list[arg->exp_count++];

    /*
     * If IMPLICIT set tag to implicit value then reset implicit tag since it
     * has been used.
     */
    if (arg->imp_tag != -1) {
        exp_tmp->exp_tag = arg->imp_tag;
        exp_tmp->exp_class = arg->imp_class;
        arg->imp_tag = -1;
        arg->imp_class = -1;
    } else {
        exp_tmp->exp_tag = exp_tag;
        exp_tmp->exp_class = exp_class;
    }
    exp_tmp->exp_constructed = exp_constructed;
    exp_tmp->exp_pad = exp_pad;

    return 1;
}

static int asn1_str2tag(const char *tagstr, int len)
{
    unsigned int i;
    static const struct tag_name_st *tntmp, tnst[] = {
        ASN1_GEN_STR("BOOL", V_ASN1_BOOLEAN),
        ASN1_GEN_STR("BOOLEAN", V_ASN1_BOOLEAN),
        ASN1_GEN_STR("NULL", V_ASN1_NULL),
        ASN1_GEN_STR("INT", V_ASN1_INTEGER),
        ASN1_GEN_STR("INTEGER", V_ASN1_INTEGER),
        ASN1_GEN_STR("ENUM", V_ASN1_ENUMERATED),
        ASN1_GEN_STR("ENUMERATED", V_ASN1_ENUMERATED),
        ASN1_GEN_STR("OID", V_ASN1_OBJECT),
        ASN1_GEN_STR("OBJECT", V_ASN1_OBJECT),
        ASN1_GEN_STR("UTCTIME", V_ASN1_UTCTIME),
        ASN1_GEN_STR("UTC", V_ASN1_UTCTIME),
        ASN1_GEN_STR("GENERALIZEDTIME", V_ASN1_GENERALIZEDTIME),
        ASN1_GEN_STR("GENTIME", V_ASN1_GENERALIZEDTIME),
        ASN1_GEN_STR("OCT", V_ASN1_OCTET_STRING),
        ASN1_GEN_STR("OCTETSTRING", V_ASN1_OCTET_STRING),
        ASN1_GEN_STR("BITSTR", V_ASN1_BIT_STRING),
        ASN1_GEN_STR("BITSTRING", V_ASN1_BIT_STRING),
        ASN1_GEN_STR("UNIVERSALSTRING", V_ASN1_UNIVERSALSTRING),
        ASN1_GEN_STR("UNIV", V_ASN1_UNIVERSALSTRING),
        ASN1_GEN_STR("IA5", V_ASN1_IA5STRING),
        ASN1_GEN_STR("IA5STRING", V_ASN1_IA5STRING),
        ASN1_GEN_STR("UTF8", V_ASN1_UTF8STRING),
        ASN1_GEN_STR("UTF8String", V_ASN1_UTF8STRING),
        ASN1_GEN_STR("BMP", V_ASN1_BMPSTRING),
        ASN1_GEN_STR("BMPSTRING", V_ASN1_BMPSTRING),
        ASN1_GEN_STR("VISIBLESTRING", V_ASN1_VISIBLESTRING),
        ASN1_GEN_STR("VISIBLE", V_ASN1_VISIBLESTRING),
        ASN1_GEN_STR("PRINTABLESTRING", V_ASN1_PRINTABLESTRING),
        ASN1_GEN_STR("PRINTABLE", V_ASN1_PRINTABLESTRING),
        ASN1_GEN_STR("T61", V_ASN1_T61STRING),
        ASN1_GEN_STR("T61STRING", V_ASN1_T61STRING),
        ASN1_GEN_STR("TELETEXSTRING", V_ASN1_T61STRING),
        ASN1_GEN_STR("GeneralString", V_ASN1_GENERALSTRING),
        ASN1_GEN_STR("GENSTR", V_ASN1_GENERALSTRING),
        ASN1_GEN_STR("NUMERIC", V_ASN1_NUMERICSTRING),
        ASN1_GEN_STR("NUMERICSTRING", V_ASN1_NUMERICSTRING),

        /* Special cases */
        ASN1_GEN_STR("SEQUENCE", V_ASN1_SEQUENCE),
        ASN1_GEN_STR("SEQ", V_ASN1_SEQUENCE),
        ASN1_GEN_STR("SET", V_ASN1_SET),
        /* type modifiers */
        /* Explicit tag */
        ASN1_GEN_STR("EXP", ASN1_GEN_FLAG_EXP),
        ASN1_GEN_STR("EXPLICIT", ASN1_GEN_FLAG_EXP),
        /* Implicit tag */
        ASN1_GEN_STR("IMP", ASN1_GEN_FLAG_IMP),
        ASN1_GEN_STR("IMPLICIT", ASN1_GEN_FLAG_IMP),
        /* OCTET STRING wrapper */
        ASN1_GEN_STR("OCTWRAP", ASN1_GEN_FLAG_OCTWRAP),
        /* SEQUENCE wrapper */
        ASN1_GEN_STR("SEQWRAP", ASN1_GEN_FLAG_SEQWRAP),
        /* SET wrapper */
        ASN1_GEN_STR("SETWRAP", ASN1_GEN_FLAG_SETWRAP),
        /* BIT STRING wrapper */
        ASN1_GEN_STR("BITWRAP", ASN1_GEN_FLAG_BITWRAP),
        ASN1_GEN_STR("FORM", ASN1_GEN_FLAG_FORMAT),
        ASN1_GEN_STR("FORMAT", ASN1_GEN_FLAG_FORMAT),
    };

    if (len == -1)
        len = strlen(tagstr);

    tntmp = tnst;
    for (i = 0; i < sizeof(tnst) / sizeof(struct tag_name_st); i++, tntmp++) {
        if ((len == tntmp->len) && !strncmp(tntmp->strnam, tagstr, len))
            return tntmp->tag;
    }

    return -1;
}

static ASN1_TYPE *asn1_str2type(const char *str, int format, int utype)
{
    ASN1_TYPE *atmp = NULL;

    CONF_VALUE vtmp;

    unsigned char *rdata;
    long rdlen;

    int no_unused = 1;

    if (!(atmp = ASN1_TYPE_new())) {
        OPENSSL_PUT_ERROR(ASN1, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    if (!str)
        str = "";

    switch (utype) {

    case V_ASN1_NULL:
        if (str && *str) {
            OPENSSL_PUT_ERROR(ASN1, ASN1_R_ILLEGAL_NULL_VALUE);
            goto bad_form;
        }
        break;
=======
    // Modifiers end at commas.
    const char *comma = strchr(str, ',');
    if (comma == NULL) {
      break;
    }
>>>>>>> CHANGE (34340c external/boringssl: Sync to 8aa51ddfcf1fbf2e5f976762657e21c7)

<<<<<<< HEAD   (0a931c Snap for 8740412 from 2bbd592adbcc2fef5eb979af85d1e7b091f346)
    case V_ASN1_BOOLEAN:
        if (format != ASN1_GEN_FORMAT_ASCII) {
            OPENSSL_PUT_ERROR(ASN1, ASN1_R_NOT_ASCII_FORMAT);
            goto bad_form;
        }
        vtmp.name = NULL;
        vtmp.section = NULL;
        vtmp.value = (char *)str;
        if (!X509V3_get_value_bool(&vtmp, &atmp->value.boolean)) {
            OPENSSL_PUT_ERROR(ASN1, ASN1_R_ILLEGAL_BOOLEAN);
            goto bad_str;
        }
        break;
=======
    // Remove trailing whitespace.
    CBS modifier;
    CBS_init(&modifier, (const uint8_t *)str, comma - str);
    for (;;) {
      uint8_t v;
      CBS copy = modifier;
      if (!CBS_get_last_u8(&copy, &v) || !OPENSSL_isspace(v)) {
        break;
      }
      modifier = copy;
    }

    // Advance the string past the modifier, but save the original value. We
    // will need to rewind if this is not a recognized modifier.
    const char *str_old = str;
    str = comma + 1;

    // Each modifier is either NAME:VALUE or NAME.
    CBS name;
    int has_value = CBS_get_until_first(&modifier, &name, ':');
    if (has_value) {
      CBS_skip(&modifier, 1);  // Skip the colon.
    } else {
      name = modifier;
      CBS_init(&modifier, NULL, 0);
    }

    if (cbs_str_equal(&name, "FORMAT") || cbs_str_equal(&name, "FORM")) {
      if (cbs_str_equal(&modifier, "ASCII")) {
        format = ASN1_GEN_FORMAT_ASCII;
      } else if (cbs_str_equal(&modifier, "UTF8")) {
        format = ASN1_GEN_FORMAT_UTF8;
      } else if (cbs_str_equal(&modifier, "HEX")) {
        format = ASN1_GEN_FORMAT_HEX;
      } else if (cbs_str_equal(&modifier, "BITLIST")) {
        format = ASN1_GEN_FORMAT_BITLIST;
      } else {
        OPENSSL_PUT_ERROR(ASN1, ASN1_R_UNKNOWN_FORMAT);
        return 0;
      }
    } else if (cbs_str_equal(&name, "IMP") ||
               cbs_str_equal(&name, "IMPLICIT")) {
      if (tag != 0) {
        OPENSSL_PUT_ERROR(ASN1, ASN1_R_ILLEGAL_NESTED_TAGGING);
        return 0;
      }
      tag = parse_tag(&modifier);
      if (tag == 0) {
        return 0;
      }
    } else if (cbs_str_equal(&name, "EXP") ||
               cbs_str_equal(&name, "EXPLICIT")) {
      // It would actually be supportable, but OpenSSL does not allow wrapping
      // an explicit tag in an implicit tag.
      if (tag != 0) {
        OPENSSL_PUT_ERROR(ASN1, ASN1_R_ILLEGAL_NESTED_TAGGING);
        return 0;
      }
      tag = parse_tag(&modifier);
      return tag != 0 &&
             generate_wrapped(cbb, str, cnf, tag | CBS_ASN1_CONSTRUCTED,
                              /*padding=*/0, format, depth);
    } else if (cbs_str_equal(&name, "OCTWRAP")) {
      tag = tag == 0 ? CBS_ASN1_OCTETSTRING : tag;
      return generate_wrapped(cbb, str, cnf, tag, /*padding=*/0, format, depth);
    } else if (cbs_str_equal(&name, "BITWRAP")) {
      tag = tag == 0 ? CBS_ASN1_BITSTRING : tag;
      return generate_wrapped(cbb, str, cnf, tag, /*padding=*/1, format, depth);
    } else if (cbs_str_equal(&name, "SEQWRAP")) {
      tag = tag == 0 ? CBS_ASN1_SEQUENCE : (tag | CBS_ASN1_CONSTRUCTED);
      tag |= CBS_ASN1_CONSTRUCTED;
      return generate_wrapped(cbb, str, cnf, tag, /*padding=*/0, format, depth);
    } else if (cbs_str_equal(&name, "SETWRAP")) {
      tag = tag == 0 ? CBS_ASN1_SET : (tag | CBS_ASN1_CONSTRUCTED);
      return generate_wrapped(cbb, str, cnf, tag, /*padding=*/0, format, depth);
    } else {
      // If this was not a recognized modifier, rewind |str| to before splitting
      // on the comma. The type itself consumes all remaining input.
      str = str_old;
      break;
    }
  }

  // The final element is, like modifiers, NAME:VALUE or NAME, but VALUE spans
  // the length of the string, including any commas.
  const char *colon = strchr(str, ':');
  CBS name;
  const char *value;
  int has_value = colon != NULL;
  if (has_value) {
    CBS_init(&name, (const uint8_t *)str, colon - str);
    value = colon + 1;
  } else {
    CBS_init(&name, (const uint8_t *)str, strlen(str));
    value = "";  // Most types treat missing and empty value equivalently.
  }

  static const struct {
    const char *name;
    CBS_ASN1_TAG type;
  } kTypes[] = {
      {"BOOL", CBS_ASN1_BOOLEAN},
      {"BOOLEAN", CBS_ASN1_BOOLEAN},
      {"NULL", CBS_ASN1_NULL},
      {"INT", CBS_ASN1_INTEGER},
      {"INTEGER", CBS_ASN1_INTEGER},
      {"ENUM", CBS_ASN1_ENUMERATED},
      {"ENUMERATED", CBS_ASN1_ENUMERATED},
      {"OID", CBS_ASN1_OBJECT},
      {"OBJECT", CBS_ASN1_OBJECT},
      {"UTCTIME", CBS_ASN1_UTCTIME},
      {"UTC", CBS_ASN1_UTCTIME},
      {"GENERALIZEDTIME", CBS_ASN1_GENERALIZEDTIME},
      {"GENTIME", CBS_ASN1_GENERALIZEDTIME},
      {"OCT", CBS_ASN1_OCTETSTRING},
      {"OCTETSTRING", CBS_ASN1_OCTETSTRING},
      {"BITSTR", CBS_ASN1_BITSTRING},
      {"BITSTRING", CBS_ASN1_BITSTRING},
      {"UNIVERSALSTRING", CBS_ASN1_UNIVERSALSTRING},
      {"UNIV", CBS_ASN1_UNIVERSALSTRING},
      {"IA5", CBS_ASN1_IA5STRING},
      {"IA5STRING", CBS_ASN1_IA5STRING},
      {"UTF8", CBS_ASN1_UTF8STRING},
      {"UTF8String", CBS_ASN1_UTF8STRING},
      {"BMP", CBS_ASN1_BMPSTRING},
      {"BMPSTRING", CBS_ASN1_BMPSTRING},
      {"PRINTABLESTRING", CBS_ASN1_PRINTABLESTRING},
      {"PRINTABLE", CBS_ASN1_PRINTABLESTRING},
      {"T61", CBS_ASN1_T61STRING},
      {"T61STRING", CBS_ASN1_T61STRING},
      {"TELETEXSTRING", CBS_ASN1_T61STRING},
      {"SEQUENCE", CBS_ASN1_SEQUENCE},
      {"SEQ", CBS_ASN1_SEQUENCE},
      {"SET", CBS_ASN1_SET},
  };
  CBS_ASN1_TAG type = 0;
  for (size_t i = 0; i < OPENSSL_ARRAY_SIZE(kTypes); i++) {
    if (cbs_str_equal(&name, kTypes[i].name)) {
      type = kTypes[i].type;
      break;
    }
  }
  if (type == 0) {
    OPENSSL_PUT_ERROR(ASN1, ASN1_R_UNKNOWN_TAG);
    return 0;
  }

  // If there is an implicit tag, use the constructed bit from the base type.
  tag = tag == 0 ? type : (tag | (type & CBS_ASN1_CONSTRUCTED));
  CBB child;
  if (!CBB_add_asn1(cbb, &child, tag)) {
    return 0;
  }

  switch (type) {
    case CBS_ASN1_NULL:
      if (*value != '\0') {
        OPENSSL_PUT_ERROR(ASN1, ASN1_R_ILLEGAL_NULL_VALUE);
        return 0;
      }
      return CBB_flush(cbb);

    case CBS_ASN1_BOOLEAN: {
      if (format != ASN1_GEN_FORMAT_ASCII) {
        OPENSSL_PUT_ERROR(ASN1, ASN1_R_NOT_ASCII_FORMAT);
        return 0;
      }
      ASN1_BOOLEAN boolean;
      if (!X509V3_bool_from_string(value, &boolean)) {
        OPENSSL_PUT_ERROR(ASN1, ASN1_R_ILLEGAL_BOOLEAN);
        return 0;
      }
      return CBB_add_u8(&child, boolean ? 0xff : 0x00) && CBB_flush(cbb);
    }
>>>>>>> CHANGE (34340c external/boringssl: Sync to 8aa51ddfcf1fbf2e5f976762657e21c7)

<<<<<<< HEAD   (0a931c Snap for 8740412 from 2bbd592adbcc2fef5eb979af85d1e7b091f346)
    case V_ASN1_INTEGER:
    case V_ASN1_ENUMERATED:
        if (format != ASN1_GEN_FORMAT_ASCII) {
            OPENSSL_PUT_ERROR(ASN1, ASN1_R_INTEGER_NOT_ASCII_FORMAT);
            goto bad_form;
        }
        if (!(atmp->value.integer = s2i_ASN1_INTEGER(NULL, (char *)str))) {
            OPENSSL_PUT_ERROR(ASN1, ASN1_R_ILLEGAL_INTEGER);
            goto bad_str;
        }
        break;
=======
    case CBS_ASN1_INTEGER:
    case CBS_ASN1_ENUMERATED: {
      if (format != ASN1_GEN_FORMAT_ASCII) {
        OPENSSL_PUT_ERROR(ASN1, ASN1_R_INTEGER_NOT_ASCII_FORMAT);
        return 0;
      }
      ASN1_INTEGER *obj = s2i_ASN1_INTEGER(NULL, value);
      if (obj == NULL) {
        OPENSSL_PUT_ERROR(ASN1, ASN1_R_ILLEGAL_INTEGER);
        return 0;
      }
      int len = i2c_ASN1_INTEGER(obj, NULL);
      uint8_t *out;
      int ok = len > 0 &&  //
               CBB_add_space(&child, &out, len) &&
               i2c_ASN1_INTEGER(obj, &out) == len &&
               CBB_flush(cbb);
      ASN1_INTEGER_free(obj);
      return ok;
    }
>>>>>>> CHANGE (34340c external/boringssl: Sync to 8aa51ddfcf1fbf2e5f976762657e21c7)

<<<<<<< HEAD   (0a931c Snap for 8740412 from 2bbd592adbcc2fef5eb979af85d1e7b091f346)
    case V_ASN1_OBJECT:
        if (format != ASN1_GEN_FORMAT_ASCII) {
            OPENSSL_PUT_ERROR(ASN1, ASN1_R_OBJECT_NOT_ASCII_FORMAT);
            goto bad_form;
        }
        if (!(atmp->value.object = OBJ_txt2obj(str, 0))) {
            OPENSSL_PUT_ERROR(ASN1, ASN1_R_ILLEGAL_OBJECT);
            goto bad_str;
        }
        break;
=======
    case CBS_ASN1_OBJECT: {
      if (format != ASN1_GEN_FORMAT_ASCII) {
        OPENSSL_PUT_ERROR(ASN1, ASN1_R_OBJECT_NOT_ASCII_FORMAT);
        return 0;
      }
      ASN1_OBJECT *obj = OBJ_txt2obj(value, /*dont_search_names=*/0);
      if (obj == NULL || obj->length == 0) {
        OPENSSL_PUT_ERROR(ASN1, ASN1_R_ILLEGAL_OBJECT);
        return 0;
      }
      int ok = CBB_add_bytes(&child, obj->data, obj->length) && CBB_flush(cbb);
      ASN1_OBJECT_free(obj);
      return ok;
    }
>>>>>>> CHANGE (34340c external/boringssl: Sync to 8aa51ddfcf1fbf2e5f976762657e21c7)

<<<<<<< HEAD   (0a931c Snap for 8740412 from 2bbd592adbcc2fef5eb979af85d1e7b091f346)
    case V_ASN1_UTCTIME:
    case V_ASN1_GENERALIZEDTIME:
        if (format != ASN1_GEN_FORMAT_ASCII) {
            OPENSSL_PUT_ERROR(ASN1, ASN1_R_TIME_NOT_ASCII_FORMAT);
            goto bad_form;
        }
        if (!(atmp->value.asn1_string = ASN1_STRING_new())) {
            OPENSSL_PUT_ERROR(ASN1, ERR_R_MALLOC_FAILURE);
            goto bad_str;
        }
        if (!ASN1_STRING_set(atmp->value.asn1_string, str, -1)) {
            OPENSSL_PUT_ERROR(ASN1, ERR_R_MALLOC_FAILURE);
            goto bad_str;
        }
        atmp->value.asn1_string->type = utype;
        if (!ASN1_TIME_check(atmp->value.asn1_string)) {
            OPENSSL_PUT_ERROR(ASN1, ASN1_R_ILLEGAL_TIME_VALUE);
            goto bad_str;
        }
=======
    case CBS_ASN1_UTCTIME:
    case CBS_ASN1_GENERALIZEDTIME: {
      if (format != ASN1_GEN_FORMAT_ASCII) {
        OPENSSL_PUT_ERROR(ASN1, ASN1_R_TIME_NOT_ASCII_FORMAT);
        return 0;
      }
      CBS value_cbs;
      CBS_init(&value_cbs, (const uint8_t*)value, strlen(value));
      int ok = type == CBS_ASN1_UTCTIME
                   ? CBS_parse_utc_time(&value_cbs, NULL,
                                        /*allow_timezone_offset=*/0)
                   : CBS_parse_generalized_time(&value_cbs, NULL,
                                                /*allow_timezone_offset=*/0);
      if (!ok) {
        OPENSSL_PUT_ERROR(ASN1, ASN1_R_ILLEGAL_TIME_VALUE);
        return 0;
      }
      return CBB_add_bytes(&child, (const uint8_t *)value, strlen(value)) &&
             CBB_flush(cbb);
    }
>>>>>>> CHANGE (34340c external/boringssl: Sync to 8aa51ddfcf1fbf2e5f976762657e21c7)

<<<<<<< HEAD   (0a931c Snap for 8740412 from 2bbd592adbcc2fef5eb979af85d1e7b091f346)
        break;

    case V_ASN1_BMPSTRING:
    case V_ASN1_PRINTABLESTRING:
    case V_ASN1_IA5STRING:
    case V_ASN1_T61STRING:
    case V_ASN1_UTF8STRING:
    case V_ASN1_VISIBLESTRING:
    case V_ASN1_UNIVERSALSTRING:
    case V_ASN1_GENERALSTRING:
    case V_ASN1_NUMERICSTRING:

        if (format == ASN1_GEN_FORMAT_ASCII)
            format = MBSTRING_ASC;
        else if (format == ASN1_GEN_FORMAT_UTF8)
            format = MBSTRING_UTF8;
        else {
            OPENSSL_PUT_ERROR(ASN1, ASN1_R_ILLEGAL_FORMAT);
            goto bad_form;
        }
=======
    case CBS_ASN1_UNIVERSALSTRING:
    case CBS_ASN1_IA5STRING:
    case CBS_ASN1_UTF8STRING:
    case CBS_ASN1_BMPSTRING:
    case CBS_ASN1_PRINTABLESTRING:
    case CBS_ASN1_T61STRING: {
      int encoding;
      if (format == ASN1_GEN_FORMAT_ASCII) {
        encoding = MBSTRING_ASC;
      } else if (format == ASN1_GEN_FORMAT_UTF8) {
        encoding = MBSTRING_UTF8;
      } else {
        OPENSSL_PUT_ERROR(ASN1, ASN1_R_ILLEGAL_FORMAT);
        return 0;
      }
>>>>>>> CHANGE (34340c external/boringssl: Sync to 8aa51ddfcf1fbf2e5f976762657e21c7)

<<<<<<< HEAD   (0a931c Snap for 8740412 from 2bbd592adbcc2fef5eb979af85d1e7b091f346)
        if (ASN1_mbstring_copy(&atmp->value.asn1_string, (unsigned char *)str,
                               -1, format, ASN1_tag2bit(utype)) <= 0) {
            OPENSSL_PUT_ERROR(ASN1, ERR_R_MALLOC_FAILURE);
            goto bad_str;
        }
=======
      // |maxsize| is measured in code points, rather than bytes, but pass it in
      // as a loose cap so fuzzers can exit from excessively long inputs
      // earlier. This limit is not load-bearing because |ASN1_mbstring_ncopy|'s
      // output is already linear in the input.
      ASN1_STRING *obj = NULL;
      if (ASN1_mbstring_ncopy(&obj, (const uint8_t *)value, -1, encoding,
                              ASN1_tag2bit(type), /*minsize=*/0,
                              /*maxsize=*/ASN1_GEN_MAX_OUTPUT) <= 0) {
        return 0;
      }
      int ok = CBB_add_bytes(&child, obj->data, obj->length) && CBB_flush(cbb);
      ASN1_STRING_free(obj);
      return ok;
    }
>>>>>>> CHANGE (34340c external/boringssl: Sync to 8aa51ddfcf1fbf2e5f976762657e21c7)

<<<<<<< HEAD   (0a931c Snap for 8740412 from 2bbd592adbcc2fef5eb979af85d1e7b091f346)
        break;

    case V_ASN1_BIT_STRING:

    case V_ASN1_OCTET_STRING:

        if (!(atmp->value.asn1_string = ASN1_STRING_new())) {
            OPENSSL_PUT_ERROR(ASN1, ERR_R_MALLOC_FAILURE);
            goto bad_form;
=======
    case CBS_ASN1_BITSTRING:
      if (format == ASN1_GEN_FORMAT_BITLIST) {
        ASN1_BIT_STRING *obj = ASN1_BIT_STRING_new();
        if (obj == NULL) {
          return 0;
>>>>>>> CHANGE (34340c external/boringssl: Sync to 8aa51ddfcf1fbf2e5f976762657e21c7)
        }
<<<<<<< HEAD   (0a931c Snap for 8740412 from 2bbd592adbcc2fef5eb979af85d1e7b091f346)

        if (format == ASN1_GEN_FORMAT_HEX) {

            if (!(rdata = x509v3_hex_to_bytes((char *)str, &rdlen))) {
                OPENSSL_PUT_ERROR(ASN1, ASN1_R_ILLEGAL_HEX);
                goto bad_str;
            }

            atmp->value.asn1_string->data = rdata;
            atmp->value.asn1_string->length = rdlen;
            atmp->value.asn1_string->type = utype;

        } else if (format == ASN1_GEN_FORMAT_ASCII)
            ASN1_STRING_set(atmp->value.asn1_string, str, -1);
        else if ((format == ASN1_GEN_FORMAT_BITLIST)
                 && (utype == V_ASN1_BIT_STRING)) {
            if (!CONF_parse_list
                (str, ',', 1, bitstr_cb, atmp->value.bit_string)) {
                OPENSSL_PUT_ERROR(ASN1, ASN1_R_LIST_ERROR);
                goto bad_str;
            }
            no_unused = 0;

        } else {
            OPENSSL_PUT_ERROR(ASN1, ASN1_R_ILLEGAL_BITSTRING_FORMAT);
            goto bad_form;
=======
        if (!CONF_parse_list(value, ',', 1, bitstr_cb, obj)) {
          OPENSSL_PUT_ERROR(ASN1, ASN1_R_LIST_ERROR);
          ASN1_BIT_STRING_free(obj);
          return 0;
>>>>>>> CHANGE (34340c external/boringssl: Sync to 8aa51ddfcf1fbf2e5f976762657e21c7)
        }
<<<<<<< HEAD   (0a931c Snap for 8740412 from 2bbd592adbcc2fef5eb979af85d1e7b091f346)

        if ((utype == V_ASN1_BIT_STRING) && no_unused) {
            atmp->value.asn1_string->flags
                &= ~(ASN1_STRING_FLAG_BITS_LEFT | 0x07);
            atmp->value.asn1_string->flags |= ASN1_STRING_FLAG_BITS_LEFT;
        }
=======
        int len = i2c_ASN1_BIT_STRING(obj, NULL);
        uint8_t *out;
        int ok = len > 0 &&  //
                 CBB_add_space(&child, &out, len) &&
                 i2c_ASN1_BIT_STRING(obj, &out) == len &&  //
                 CBB_flush(cbb);
        ASN1_BIT_STRING_free(obj);
        return ok;
      }
>>>>>>> CHANGE (34340c external/boringssl: Sync to 8aa51ddfcf1fbf2e5f976762657e21c7)

<<<<<<< HEAD   (0a931c Snap for 8740412 from 2bbd592adbcc2fef5eb979af85d1e7b091f346)
        break;
=======
      // The other formats are the same as OCTET STRING, but with the leading
      // zero bytes.
      if (!CBB_add_u8(&child, 0)) {
        return 0;
      }
      OPENSSL_FALLTHROUGH;

    case CBS_ASN1_OCTETSTRING:
      if (format == ASN1_GEN_FORMAT_ASCII) {
        return CBB_add_bytes(&child, (const uint8_t *)value, strlen(value)) &&
               CBB_flush(cbb);
      }
      if (format == ASN1_GEN_FORMAT_HEX) {
        long len;
        uint8_t *data = x509v3_hex_to_bytes(value, &len);
        if (data == NULL) {
          OPENSSL_PUT_ERROR(ASN1, ASN1_R_ILLEGAL_HEX);
          return 0;
        }
        int ok = CBB_add_bytes(&child, data, len) && CBB_flush(cbb);
        OPENSSL_free(data);
        return ok;
      }

      OPENSSL_PUT_ERROR(ASN1, ASN1_R_ILLEGAL_BITSTRING_FORMAT);
      return 0;

    case CBS_ASN1_SEQUENCE:
    case CBS_ASN1_SET:
      if (has_value) {
        if (cnf == NULL) {
          OPENSSL_PUT_ERROR(ASN1, ASN1_R_SEQUENCE_OR_SET_NEEDS_CONFIG);
          return 0;
        }
        const STACK_OF(CONF_VALUE) *section = X509V3_get_section(cnf, value);
        if (section == NULL) {
          OPENSSL_PUT_ERROR(ASN1, ASN1_R_SEQUENCE_OR_SET_NEEDS_CONFIG);
          return 0;
        }
        for (size_t i = 0; i < sk_CONF_VALUE_num(section); i++) {
          const CONF_VALUE *conf = sk_CONF_VALUE_value(section, i);
          if (!generate_v3(&child, conf->value, cnf, /*tag=*/0,
                           ASN1_GEN_FORMAT_ASCII, depth + 1)) {
            return 0;
          }
          // This recursive call, by referencing |section|, is the one place
          // where |generate_v3|'s output can be super-linear in the input.
          // Check bounds here.
          if (CBB_len(&child) > ASN1_GEN_MAX_OUTPUT) {
            OPENSSL_PUT_ERROR(ASN1, ASN1_R_TOO_LONG);
            return 0;
          }
        }
      }
      if (type == CBS_ASN1_SET) {
        // The SET type here is a SET OF and must be sorted.
        return CBB_flush_asn1_set_of(&child) && CBB_flush(cbb);
      }
      return CBB_flush(cbb);
>>>>>>> CHANGE (34340c external/boringssl: Sync to 8aa51ddfcf1fbf2e5f976762657e21c7)

    default:
<<<<<<< HEAD   (0a931c Snap for 8740412 from 2bbd592adbcc2fef5eb979af85d1e7b091f346)
        OPENSSL_PUT_ERROR(ASN1, ASN1_R_UNSUPPORTED_TYPE);
        goto bad_str;
        break;
    }

    atmp->type = utype;
    return atmp;

 bad_str:
    ERR_add_error_data(2, "string=", str);
 bad_form:

    ASN1_TYPE_free(atmp);
    return NULL;

=======
      OPENSSL_PUT_ERROR(ASN1, ERR_R_INTERNAL_ERROR);
      return 0;
  }
>>>>>>> CHANGE (34340c external/boringssl: Sync to 8aa51ddfcf1fbf2e5f976762657e21c7)
}

<<<<<<< HEAD   (0a931c Snap for 8740412 from 2bbd592adbcc2fef5eb979af85d1e7b091f346)
static int bitstr_cb(const char *elem, int len, void *bitstr)
{
    long bitnum;
    char *eptr;
    if (!elem)
        return 0;
    bitnum = strtoul(elem, &eptr, 10);
    if (eptr && *eptr && (eptr != elem + len))
        return 0;
    if (bitnum < 0) {
        OPENSSL_PUT_ERROR(ASN1, ASN1_R_INVALID_NUMBER);
        return 0;
    }
    if (!ASN1_BIT_STRING_set_bit(bitstr, bitnum, 1)) {
        OPENSSL_PUT_ERROR(ASN1, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    return 1;
=======
static int bitstr_cb(const char *elem, size_t len, void *bitstr) {
  CBS cbs;
  CBS_init(&cbs, (const uint8_t *)elem, len);
  uint64_t bitnum;
  if (!CBS_get_u64_decimal(&cbs, &bitnum) || CBS_len(&cbs) != 0 ||
      // Cap the highest allowed bit so this mechanism cannot be used to create
      // extremely large allocations with short inputs. The highest named bit in
      // RFC 5280 is 8, so 256 should give comfortable margin but still only
      // allow a 32-byte allocation.
      //
      // We do not consider this function to be safe with untrusted inputs (even
      // without bugs, it is prone to string injection vulnerabilities), so DoS
      // is not truly a concern, but the limit is necessary to keep fuzzing
      // effective.
      bitnum > 256) {
    OPENSSL_PUT_ERROR(ASN1, ASN1_R_INVALID_NUMBER);
    return 0;
  }
  if (!ASN1_BIT_STRING_set_bit(bitstr, (int)bitnum, 1)) {
    return 0;
  }
  return 1;
>>>>>>> CHANGE (34340c external/boringssl: Sync to 8aa51ddfcf1fbf2e5f976762657e21c7)
}
