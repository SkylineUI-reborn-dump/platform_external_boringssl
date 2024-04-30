# Copyright (c) 2015, Google Inc.
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
# SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
# OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
# CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

# This file is created by generate_build_files.py. Do not edit manually.

crypto_sources := \
  src/crypto/asn1/a_bitstr.c\
  src/crypto/asn1/a_bool.c\
  src/crypto/asn1/a_d2i_fp.c\
  src/crypto/asn1/a_dup.c\
  src/crypto/asn1/a_gentm.c\
  src/crypto/asn1/a_i2d_fp.c\
  src/crypto/asn1/a_int.c\
  src/crypto/asn1/a_mbstr.c\
  src/crypto/asn1/a_object.c\
  src/crypto/asn1/a_octet.c\
  src/crypto/asn1/a_strex.c\
  src/crypto/asn1/a_strnid.c\
  src/crypto/asn1/a_time.c\
  src/crypto/asn1/a_type.c\
  src/crypto/asn1/a_utctm.c\
  src/crypto/asn1/asn1_lib.c\
  src/crypto/asn1/asn1_par.c\
  src/crypto/asn1/asn_pack.c\
  src/crypto/asn1/f_int.c\
  src/crypto/asn1/f_string.c\
  src/crypto/asn1/posix_time.c\
  src/crypto/asn1/tasn_dec.c\
  src/crypto/asn1/tasn_enc.c\
  src/crypto/asn1/tasn_fre.c\
  src/crypto/asn1/tasn_new.c\
  src/crypto/asn1/tasn_typ.c\
  src/crypto/asn1/tasn_utl.c\
  src/crypto/base64/base64.c\
  src/crypto/bio/bio.c\
  src/crypto/bio/bio_mem.c\
  src/crypto/bio/connect.c\
  src/crypto/bio/errno.c\
  src/crypto/bio/fd.c\
  src/crypto/bio/file.c\
  src/crypto/bio/hexdump.c\
  src/crypto/bio/pair.c\
  src/crypto/bio/printf.c\
  src/crypto/bio/socket.c\
  src/crypto/bio/socket_helper.c\
  src/crypto/blake2/blake2.c\
  src/crypto/bn_extra/bn_asn1.c\
  src/crypto/bn_extra/convert.c\
  src/crypto/buf/buf.c\
  src/crypto/bytestring/asn1_compat.c\
  src/crypto/bytestring/ber.c\
  src/crypto/bytestring/cbb.c\
  src/crypto/bytestring/cbs.c\
  src/crypto/bytestring/unicode.c\
  src/crypto/chacha/chacha.c\
  src/crypto/cipher_extra/cipher_extra.c\
  src/crypto/cipher_extra/derive_key.c\
  src/crypto/cipher_extra/e_aesctrhmac.c\
  src/crypto/cipher_extra/e_aesgcmsiv.c\
  src/crypto/cipher_extra/e_chacha20poly1305.c\
  src/crypto/cipher_extra/e_des.c\
  src/crypto/cipher_extra/e_null.c\
  src/crypto/cipher_extra/e_rc2.c\
  src/crypto/cipher_extra/e_rc4.c\
  src/crypto/cipher_extra/e_tls.c\
  src/crypto/cipher_extra/tls_cbc.c\
  src/crypto/conf/conf.c\
  src/crypto/cpu_aarch64_apple.c\
  src/crypto/cpu_aarch64_fuchsia.c\
  src/crypto/cpu_aarch64_linux.c\
  src/crypto/cpu_aarch64_openbsd.c\
  src/crypto/cpu_aarch64_sysreg.c\
  src/crypto/cpu_aarch64_win.c\
  src/crypto/cpu_arm_freebsd.c\
  src/crypto/cpu_arm_linux.c\
  src/crypto/cpu_intel.c\
  src/crypto/crypto.c\
  src/crypto/curve25519/curve25519.c\
  src/crypto/curve25519/curve25519_64_adx.c\
  src/crypto/curve25519/spake25519.c\
  src/crypto/des/des.c\
  src/crypto/dh_extra/dh_asn1.c\
  src/crypto/dh_extra/params.c\
  src/crypto/digest_extra/digest_extra.c\
  src/crypto/dsa/dsa.c\
  src/crypto/dsa/dsa_asn1.c\
  src/crypto/ec_extra/ec_asn1.c\
  src/crypto/ec_extra/ec_derive.c\
  src/crypto/ec_extra/hash_to_curve.c\
  src/crypto/ecdh_extra/ecdh_extra.c\
  src/crypto/ecdsa_extra/ecdsa_asn1.c\
  src/crypto/engine/engine.c\
  src/crypto/err/err.c\
  src/crypto/evp/evp.c\
  src/crypto/evp/evp_asn1.c\
  src/crypto/evp/evp_ctx.c\
  src/crypto/evp/p_dh.c\
  src/crypto/evp/p_dh_asn1.c\
  src/crypto/evp/p_dsa_asn1.c\
  src/crypto/evp/p_ec.c\
  src/crypto/evp/p_ec_asn1.c\
  src/crypto/evp/p_ed25519.c\
  src/crypto/evp/p_ed25519_asn1.c\
  src/crypto/evp/p_hkdf.c\
  src/crypto/evp/p_rsa.c\
  src/crypto/evp/p_rsa_asn1.c\
  src/crypto/evp/p_x25519.c\
  src/crypto/evp/p_x25519_asn1.c\
  src/crypto/evp/pbkdf.c\
  src/crypto/evp/print.c\
  src/crypto/evp/scrypt.c\
  src/crypto/evp/sign.c\
  src/crypto/ex_data.c\
  src/crypto/fipsmodule/bcm.c\
  src/crypto/fipsmodule/fips_shared_support.c\
  src/crypto/hpke/hpke.c\
  src/crypto/hrss/hrss.c\
  src/crypto/keccak/keccak.c\
  src/crypto/kyber/kyber.c\
  src/crypto/lhash/lhash.c\
  src/crypto/mem.c\
  src/crypto/obj/obj.c\
  src/crypto/obj/obj_xref.c\
  src/crypto/pem/pem_all.c\
  src/crypto/pem/pem_info.c\
  src/crypto/pem/pem_lib.c\
  src/crypto/pem/pem_oth.c\
  src/crypto/pem/pem_pk8.c\
  src/crypto/pem/pem_pkey.c\
  src/crypto/pem/pem_x509.c\
  src/crypto/pem/pem_xaux.c\
  src/crypto/pkcs7/pkcs7.c\
  src/crypto/pkcs7/pkcs7_x509.c\
  src/crypto/pkcs8/p5_pbev2.c\
  src/crypto/pkcs8/pkcs8.c\
  src/crypto/pkcs8/pkcs8_x509.c\
  src/crypto/poly1305/poly1305.c\
  src/crypto/poly1305/poly1305_arm.c\
  src/crypto/poly1305/poly1305_vec.c\
  src/crypto/pool/pool.c\
  src/crypto/rand_extra/deterministic.c\
  src/crypto/rand_extra/forkunsafe.c\
  src/crypto/rand_extra/getentropy.c\
  src/crypto/rand_extra/ios.c\
  src/crypto/rand_extra/passive.c\
  src/crypto/rand_extra/rand_extra.c\
  src/crypto/rand_extra/trusty.c\
  src/crypto/rand_extra/windows.c\
  src/crypto/rc4/rc4.c\
  src/crypto/refcount.c\
  src/crypto/rsa_extra/rsa_asn1.c\
  src/crypto/rsa_extra/rsa_crypt.c\
  src/crypto/rsa_extra/rsa_print.c\
  src/crypto/siphash/siphash.c\
  src/crypto/spx/address.c\
  src/crypto/spx/fors.c\
  src/crypto/spx/merkle.c\
  src/crypto/spx/spx.c\
  src/crypto/spx/spx_util.c\
  src/crypto/spx/thash.c\
  src/crypto/spx/wots.c\
  src/crypto/stack/stack.c\
  src/crypto/thread.c\
  src/crypto/thread_none.c\
  src/crypto/thread_pthread.c\
  src/crypto/thread_win.c\
  src/crypto/trust_token/pmbtoken.c\
  src/crypto/trust_token/trust_token.c\
  src/crypto/trust_token/voprf.c\
  src/crypto/x509/a_digest.c\
  src/crypto/x509/a_sign.c\
  src/crypto/x509/a_verify.c\
  src/crypto/x509/algorithm.c\
  src/crypto/x509/asn1_gen.c\
  src/crypto/x509/by_dir.c\
  src/crypto/x509/by_file.c\
  src/crypto/x509/i2d_pr.c\
  src/crypto/x509/name_print.c\
  src/crypto/x509/policy.c\
  src/crypto/x509/rsa_pss.c\
  src/crypto/x509/t_crl.c\
  src/crypto/x509/t_req.c\
  src/crypto/x509/t_x509.c\
  src/crypto/x509/t_x509a.c\
  src/crypto/x509/v3_akey.c\
  src/crypto/x509/v3_akeya.c\
  src/crypto/x509/v3_alt.c\
  src/crypto/x509/v3_bcons.c\
  src/crypto/x509/v3_bitst.c\
  src/crypto/x509/v3_conf.c\
  src/crypto/x509/v3_cpols.c\
  src/crypto/x509/v3_crld.c\
  src/crypto/x509/v3_enum.c\
  src/crypto/x509/v3_extku.c\
  src/crypto/x509/v3_genn.c\
  src/crypto/x509/v3_ia5.c\
  src/crypto/x509/v3_info.c\
  src/crypto/x509/v3_int.c\
  src/crypto/x509/v3_lib.c\
  src/crypto/x509/v3_ncons.c\
  src/crypto/x509/v3_ocsp.c\
  src/crypto/x509/v3_pcons.c\
  src/crypto/x509/v3_pmaps.c\
  src/crypto/x509/v3_prn.c\
  src/crypto/x509/v3_purp.c\
  src/crypto/x509/v3_skey.c\
  src/crypto/x509/v3_utl.c\
  src/crypto/x509/x509.c\
  src/crypto/x509/x509_att.c\
  src/crypto/x509/x509_cmp.c\
  src/crypto/x509/x509_d2.c\
  src/crypto/x509/x509_def.c\
  src/crypto/x509/x509_ext.c\
  src/crypto/x509/x509_lu.c\
  src/crypto/x509/x509_obj.c\
  src/crypto/x509/x509_req.c\
  src/crypto/x509/x509_set.c\
  src/crypto/x509/x509_trs.c\
  src/crypto/x509/x509_txt.c\
  src/crypto/x509/x509_v3.c\
  src/crypto/x509/x509_vfy.c\
  src/crypto/x509/x509_vpm.c\
  src/crypto/x509/x509cset.c\
  src/crypto/x509/x509name.c\
  src/crypto/x509/x509rset.c\
  src/crypto/x509/x509spki.c\
  src/crypto/x509/x_algor.c\
  src/crypto/x509/x_all.c\
  src/crypto/x509/x_attrib.c\
  src/crypto/x509/x_crl.c\
  src/crypto/x509/x_exten.c\
  src/crypto/x509/x_name.c\
  src/crypto/x509/x_pubkey.c\
  src/crypto/x509/x_req.c\
  src/crypto/x509/x_sig.c\
  src/crypto/x509/x_spki.c\
  src/crypto/x509/x_val.c\
  src/crypto/x509/x_x509.c\
  src/crypto/x509/x_x509a.c\
  src/gen/crypto/err_data.c\

crypto_sources_asm := \
  src/crypto/curve25519/asm/x25519-asm-arm.S\
  src/crypto/hrss/asm/poly_rq_mul.S\
  src/crypto/poly1305/poly1305_arm_asm.S\
  src/gen/bcm/aesni-gcm-x86_64-apple.S\
  src/gen/bcm/aesni-gcm-x86_64-linux.S\
  src/gen/bcm/aesni-x86-apple.S\
  src/gen/bcm/aesni-x86-linux.S\
  src/gen/bcm/aesni-x86_64-apple.S\
  src/gen/bcm/aesni-x86_64-linux.S\
  src/gen/bcm/aesv8-armv7-linux.S\
  src/gen/bcm/aesv8-armv8-apple.S\
  src/gen/bcm/aesv8-armv8-linux.S\
  src/gen/bcm/aesv8-armv8-win.S\
  src/gen/bcm/aesv8-gcm-armv8-apple.S\
  src/gen/bcm/aesv8-gcm-armv8-linux.S\
  src/gen/bcm/aesv8-gcm-armv8-win.S\
  src/gen/bcm/armv4-mont-linux.S\
  src/gen/bcm/armv8-mont-apple.S\
  src/gen/bcm/armv8-mont-linux.S\
  src/gen/bcm/armv8-mont-win.S\
  src/gen/bcm/bn-586-apple.S\
  src/gen/bcm/bn-586-linux.S\
  src/gen/bcm/bn-armv8-apple.S\
  src/gen/bcm/bn-armv8-linux.S\
  src/gen/bcm/bn-armv8-win.S\
  src/gen/bcm/bsaes-armv7-linux.S\
  src/gen/bcm/co-586-apple.S\
  src/gen/bcm/co-586-linux.S\
  src/gen/bcm/ghash-armv4-linux.S\
  src/gen/bcm/ghash-neon-armv8-apple.S\
  src/gen/bcm/ghash-neon-armv8-linux.S\
  src/gen/bcm/ghash-neon-armv8-win.S\
  src/gen/bcm/ghash-ssse3-x86-apple.S\
  src/gen/bcm/ghash-ssse3-x86-linux.S\
  src/gen/bcm/ghash-ssse3-x86_64-apple.S\
  src/gen/bcm/ghash-ssse3-x86_64-linux.S\
  src/gen/bcm/ghash-x86-apple.S\
  src/gen/bcm/ghash-x86-linux.S\
  src/gen/bcm/ghash-x86_64-apple.S\
  src/gen/bcm/ghash-x86_64-linux.S\
  src/gen/bcm/ghashv8-armv7-linux.S\
  src/gen/bcm/ghashv8-armv8-apple.S\
  src/gen/bcm/ghashv8-armv8-linux.S\
  src/gen/bcm/ghashv8-armv8-win.S\
  src/gen/bcm/md5-586-apple.S\
  src/gen/bcm/md5-586-linux.S\
  src/gen/bcm/md5-x86_64-apple.S\
  src/gen/bcm/md5-x86_64-linux.S\
  src/gen/bcm/p256-armv8-asm-apple.S\
  src/gen/bcm/p256-armv8-asm-linux.S\
  src/gen/bcm/p256-armv8-asm-win.S\
  src/gen/bcm/p256-x86_64-asm-apple.S\
  src/gen/bcm/p256-x86_64-asm-linux.S\
  src/gen/bcm/p256_beeu-armv8-asm-apple.S\
  src/gen/bcm/p256_beeu-armv8-asm-linux.S\
  src/gen/bcm/p256_beeu-armv8-asm-win.S\
  src/gen/bcm/p256_beeu-x86_64-asm-apple.S\
  src/gen/bcm/p256_beeu-x86_64-asm-linux.S\
  src/gen/bcm/rdrand-x86_64-apple.S\
  src/gen/bcm/rdrand-x86_64-linux.S\
  src/gen/bcm/rsaz-avx2-apple.S\
  src/gen/bcm/rsaz-avx2-linux.S\
  src/gen/bcm/sha1-586-apple.S\
  src/gen/bcm/sha1-586-linux.S\
  src/gen/bcm/sha1-armv4-large-linux.S\
  src/gen/bcm/sha1-armv8-apple.S\
  src/gen/bcm/sha1-armv8-linux.S\
  src/gen/bcm/sha1-armv8-win.S\
  src/gen/bcm/sha1-x86_64-apple.S\
  src/gen/bcm/sha1-x86_64-linux.S\
  src/gen/bcm/sha256-586-apple.S\
  src/gen/bcm/sha256-586-linux.S\
  src/gen/bcm/sha256-armv4-linux.S\
  src/gen/bcm/sha256-armv8-apple.S\
  src/gen/bcm/sha256-armv8-linux.S\
  src/gen/bcm/sha256-armv8-win.S\
  src/gen/bcm/sha256-x86_64-apple.S\
  src/gen/bcm/sha256-x86_64-linux.S\
  src/gen/bcm/sha512-586-apple.S\
  src/gen/bcm/sha512-586-linux.S\
  src/gen/bcm/sha512-armv4-linux.S\
  src/gen/bcm/sha512-armv8-apple.S\
  src/gen/bcm/sha512-armv8-linux.S\
  src/gen/bcm/sha512-armv8-win.S\
  src/gen/bcm/sha512-x86_64-apple.S\
  src/gen/bcm/sha512-x86_64-linux.S\
  src/gen/bcm/vpaes-armv7-linux.S\
  src/gen/bcm/vpaes-armv8-apple.S\
  src/gen/bcm/vpaes-armv8-linux.S\
  src/gen/bcm/vpaes-armv8-win.S\
  src/gen/bcm/vpaes-x86-apple.S\
  src/gen/bcm/vpaes-x86-linux.S\
  src/gen/bcm/vpaes-x86_64-apple.S\
  src/gen/bcm/vpaes-x86_64-linux.S\
  src/gen/bcm/x86-mont-apple.S\
  src/gen/bcm/x86-mont-linux.S\
  src/gen/bcm/x86_64-mont-apple.S\
  src/gen/bcm/x86_64-mont-linux.S\
  src/gen/bcm/x86_64-mont5-apple.S\
  src/gen/bcm/x86_64-mont5-linux.S\
  src/gen/crypto/aes128gcmsiv-x86_64-apple.S\
  src/gen/crypto/aes128gcmsiv-x86_64-linux.S\
  src/gen/crypto/chacha-armv4-linux.S\
  src/gen/crypto/chacha-armv8-apple.S\
  src/gen/crypto/chacha-armv8-linux.S\
  src/gen/crypto/chacha-armv8-win.S\
  src/gen/crypto/chacha-x86-apple.S\
  src/gen/crypto/chacha-x86-linux.S\
  src/gen/crypto/chacha-x86_64-apple.S\
  src/gen/crypto/chacha-x86_64-linux.S\
  src/gen/crypto/chacha20_poly1305_armv8-apple.S\
  src/gen/crypto/chacha20_poly1305_armv8-linux.S\
  src/gen/crypto/chacha20_poly1305_armv8-win.S\
  src/gen/crypto/chacha20_poly1305_x86_64-apple.S\
  src/gen/crypto/chacha20_poly1305_x86_64-linux.S\
  src/gen/test_support/trampoline-armv4-linux.S\
  src/gen/test_support/trampoline-armv8-apple.S\
  src/gen/test_support/trampoline-armv8-linux.S\
  src/gen/test_support/trampoline-armv8-win.S\
  src/gen/test_support/trampoline-x86-apple.S\
  src/gen/test_support/trampoline-x86-linux.S\
  src/gen/test_support/trampoline-x86_64-apple.S\
  src/gen/test_support/trampoline-x86_64-linux.S\
  src/third_party/fiat/asm/fiat_curve25519_adx_mul.S\
  src/third_party/fiat/asm/fiat_curve25519_adx_square.S\
  src/third_party/fiat/asm/fiat_p256_adx_mul.S\
  src/third_party/fiat/asm/fiat_p256_adx_sqr.S\

crypto_sources_nasm := \
  src/gen/bcm/aesni-gcm-x86_64-win.asm\
  src/gen/bcm/aesni-x86-win.asm\
  src/gen/bcm/aesni-x86_64-win.asm\
  src/gen/bcm/bn-586-win.asm\
  src/gen/bcm/co-586-win.asm\
  src/gen/bcm/ghash-ssse3-x86-win.asm\
  src/gen/bcm/ghash-ssse3-x86_64-win.asm\
  src/gen/bcm/ghash-x86-win.asm\
  src/gen/bcm/ghash-x86_64-win.asm\
  src/gen/bcm/md5-586-win.asm\
  src/gen/bcm/md5-x86_64-win.asm\
  src/gen/bcm/p256-x86_64-asm-win.asm\
  src/gen/bcm/p256_beeu-x86_64-asm-win.asm\
  src/gen/bcm/rdrand-x86_64-win.asm\
  src/gen/bcm/rsaz-avx2-win.asm\
  src/gen/bcm/sha1-586-win.asm\
  src/gen/bcm/sha1-x86_64-win.asm\
  src/gen/bcm/sha256-586-win.asm\
  src/gen/bcm/sha256-x86_64-win.asm\
  src/gen/bcm/sha512-586-win.asm\
  src/gen/bcm/sha512-x86_64-win.asm\
  src/gen/bcm/vpaes-x86-win.asm\
  src/gen/bcm/vpaes-x86_64-win.asm\
  src/gen/bcm/x86-mont-win.asm\
  src/gen/bcm/x86_64-mont-win.asm\
  src/gen/bcm/x86_64-mont5-win.asm\
  src/gen/crypto/aes128gcmsiv-x86_64-win.asm\
  src/gen/crypto/chacha-x86-win.asm\
  src/gen/crypto/chacha-x86_64-win.asm\
  src/gen/crypto/chacha20_poly1305_x86_64-win.asm\
  src/gen/test_support/trampoline-x86-win.asm\
  src/gen/test_support/trampoline-x86_64-win.asm\

ssl_sources := \
  src/ssl/bio_ssl.cc\
  src/ssl/d1_both.cc\
  src/ssl/d1_lib.cc\
  src/ssl/d1_pkt.cc\
  src/ssl/d1_srtp.cc\
  src/ssl/dtls_method.cc\
  src/ssl/dtls_record.cc\
  src/ssl/encrypted_client_hello.cc\
  src/ssl/extensions.cc\
  src/ssl/handoff.cc\
  src/ssl/handshake.cc\
  src/ssl/handshake_client.cc\
  src/ssl/handshake_server.cc\
  src/ssl/s3_both.cc\
  src/ssl/s3_lib.cc\
  src/ssl/s3_pkt.cc\
  src/ssl/ssl_aead_ctx.cc\
  src/ssl/ssl_asn1.cc\
  src/ssl/ssl_buffer.cc\
  src/ssl/ssl_cert.cc\
  src/ssl/ssl_cipher.cc\
  src/ssl/ssl_credential.cc\
  src/ssl/ssl_file.cc\
  src/ssl/ssl_key_share.cc\
  src/ssl/ssl_lib.cc\
  src/ssl/ssl_privkey.cc\
  src/ssl/ssl_session.cc\
  src/ssl/ssl_stat.cc\
  src/ssl/ssl_transcript.cc\
  src/ssl/ssl_versions.cc\
  src/ssl/ssl_x509.cc\
  src/ssl/t1_enc.cc\
  src/ssl/tls13_both.cc\
  src/ssl/tls13_client.cc\
  src/ssl/tls13_enc.cc\
  src/ssl/tls13_server.cc\
  src/ssl/tls_method.cc\
  src/ssl/tls_record.cc\

tool_sources := \
  src/tool/args.cc\
  src/tool/ciphers.cc\
  src/tool/client.cc\
  src/tool/const.cc\
  src/tool/digest.cc\
  src/tool/fd.cc\
  src/tool/file.cc\
  src/tool/generate_ech.cc\
  src/tool/generate_ed25519.cc\
  src/tool/genrsa.cc\
  src/tool/pkcs12.cc\
  src/tool/rand.cc\
  src/tool/server.cc\
  src/tool/sign.cc\
  src/tool/speed.cc\
  src/tool/tool.cc\
  src/tool/transport_common.cc\

