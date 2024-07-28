/* Copyright (c) 2023, Google LLC
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

#ifndef OPENSSL_HEADER_DILITHIUM_H
#define OPENSSL_HEADER_DILITHIUM_H

#include <openssl/base.h>

#if defined(__cplusplus)
extern "C" {
#endif


#if defined(OPENSSL_UNSTABLE_EXPERIMENTAL_DILITHIUM)
// This header implements experimental, draft versions of not-yet-standardized
// primitives. When the standard is complete, these functions will be removed
// and replaced with the final, incompatible standard version. They are
// available now for short-lived experiments, but must not be deployed anywhere
// durable, such as a long-lived key store. To use these functions define
// OPENSSL_UNSTABLE_EXPERIMENTAL_DILITHIUM.

// Dilithium3.


// DILITHIUM_private_key contains a Dilithium3 private key. The contents of this
// object should never leave the address space since the format is unstable.
struct DILITHIUM_private_key {
  union {
    uint8_t bytes[32 + 32 + 64 + 256 * 4 * (5 + 6 + 6)];
    uint32_t alignment;
  } opaque;
};

// DILITHIUM_public_key contains a Dilithium3 public key. The contents of this
// object should never leave the address space since the format is unstable.
struct DILITHIUM_public_key {
  union {
    uint8_t bytes[32 + 64 + 256 * 4 * 6];
    uint32_t alignment;
  } opaque;
};

// DILITHIUM_PRIVATE_KEY_BYTES is the number of bytes in an encoded Dilithium3
// private key.
#define DILITHIUM_PRIVATE_KEY_BYTES 4032

// DILITHIUM_PUBLIC_KEY_BYTES is the number of bytes in an encoded Dilithium3
// public key.
#define DILITHIUM_PUBLIC_KEY_BYTES 1952

// DILITHIUM_SIGNATURE_BYTES is the number of bytes in an encoded Dilithium3
// signature.
#define DILITHIUM_SIGNATURE_BYTES 3309

// DILITHIUM_generate_key generates a random public/private key pair, writes the
// encoded public key to |out_encoded_public_key| and sets |out_private_key| to
// the private key. Returns 1 on success and 0 on failure.
OPENSSL_EXPORT int DILITHIUM_generate_key(
    uint8_t out_encoded_public_key[DILITHIUM_PUBLIC_KEY_BYTES],
    struct DILITHIUM_private_key *out_private_key);

// DILITHIUM_public_from_private sets |*out_public_key| to the public key that
// corresponds to |private_key|. Returns 1 on success and 0 on failure.
OPENSSL_EXPORT int DILITHIUM_public_from_private(
    struct DILITHIUM_public_key *out_public_key,
    const struct DILITHIUM_private_key *private_key);

// DILITHIUM_sign generates a signature for the message |msg| of length
// |msg_len| using |private_key| following the randomized algorithm, and writes
// the encoded signature to |out_encoded_signature|. Returns 1 on success and 0
// on failure.
OPENSSL_EXPORT int DILITHIUM_sign(
    uint8_t out_encoded_signature[DILITHIUM_SIGNATURE_BYTES],
    const struct DILITHIUM_private_key *private_key, const uint8_t *msg,
    size_t msg_len);

// DILITHIUM_verify verifies that |encoded_signature| constitutes a valid
// signature for the message |msg| of length |msg_len| using |public_key|.
OPENSSL_EXPORT int DILITHIUM_verify(
    const struct DILITHIUM_public_key *public_key,
    const uint8_t encoded_signature[DILITHIUM_SIGNATURE_BYTES],
    const uint8_t *msg, size_t msg_len);


// Serialisation of keys.

// DILITHIUM_marshal_public_key serializes |public_key| to |out| in the standard
// format for Dilithium public keys. It returns one on success or zero on
// allocation error.
OPENSSL_EXPORT int DILITHIUM_marshal_public_key(
    CBB *out, const struct DILITHIUM_public_key *public_key);

// DILITHIUM_parse_public_key parses a public key, in the format generated by
// |DILITHIUM_marshal_public_key|, from |in| and writes the result to
// |out_public_key|. It returns one on success or zero on parse error or if
// there are trailing bytes in |in|.
OPENSSL_EXPORT int DILITHIUM_parse_public_key(
    struct DILITHIUM_public_key *public_key, CBS *in);

// DILITHIUM_marshal_private_key serializes |private_key| to |out| in the
// standard format for Dilithium private keys. It returns one on success or zero
// on allocation error.
OPENSSL_EXPORT int DILITHIUM_marshal_private_key(
    CBB *out, const struct DILITHIUM_private_key *private_key);

// DILITHIUM_parse_private_key parses a private key, in the format generated by
// |DILITHIUM_marshal_private_key|, from |in| and writes the result to
// |out_private_key|. It returns one on success or zero on parse error or if
// there are trailing bytes in |in|.
OPENSSL_EXPORT int DILITHIUM_parse_private_key(
    struct DILITHIUM_private_key *private_key, CBS *in);

#endif  // OPENSSL_UNSTABLE_EXPERIMENTAL_DILITHIUM


#if defined(__cplusplus)
}  // extern C
#endif

#endif  // OPENSSL_HEADER_DILITHIUM_H
