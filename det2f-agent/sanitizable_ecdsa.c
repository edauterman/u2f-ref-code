// Copyright 2018 Google Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

#include <stdio.h>
#include <openssl/rand.h>

#include "common.h"
#include "sanitizable_ecdsa.h"

/* Check that signature is valid ECDSA signature and is sanitizable, meaning
 * that ev verifies and signature is of the form (r,s) and not (r,-s). */
int
SanitizableEcdsa_verify_sanitize(const_Params params, const uint8_t *message,
                                 int messagelen, const BIGNUM *K_x,
                                 const EC_POINT *pk, BIGNUM *sig_r,
                                 BIGNUM *sig_s, const_PedersenStatement st,
                                 const_PedersenEvidence ev) {
  int rv = ERROR;
  BIGNUM *zero = NULL;
  EC_KEY *vk = NULL;
  ECDSA_SIG *sig = NULL;
  uint8_t rand;
  BIGNUM *r_copy = NULL;
  BIGNUM *s_copy = NULL;

  CHECK_A (zero = BN_new());
  BN_zero(zero);
  CHECK_A (vk = EC_KEY_new());
  CHECK_A (sig = ECDSA_SIG_new());

  /* Check proof for generation of nonce. */
  CHECK_C (PedersenEvidence_verify(params, ev, st));

  /* Check that r != 0 and s != 0. */
  CHECK_C (!BN_is_zero(sig_r));
  CHECK_C (!BN_is_zero(sig_s));

  /* Randomize whether signature is of form (r,s) or (r,-s). */
/*  if (BN_cmp(sig_s, zero) < 0) {
    BN_mod_sub(sig_s, zero, sig_s, Params_order(params), Params_ctx(params));
  }
  CHECK_C (RAND_bytes(&rand, 1));
  if (rand & 1) {
    BN_mod_sub(sig_s, zero, sig_s, Params_order(params), Params_ctx(params));
  }*/

  /* Check that nonce is used in signature, i.e. K_x = sig_r. */
  CHECK_C (BN_cmp(sig_r, K_x) == 0);

  /* Run ECDSA signature verification. */
  CHECK_C (EC_KEY_set_group(vk, Params_group(params)));
  CHECK_C (EC_KEY_set_public_key(vk, pk));
  CHECK_A (r_copy = BN_dup(sig_r));
  CHECK_A (s_copy = BN_dup(sig_s));
  CHECK_C (ECDSA_SIG_set0(sig, r_copy, s_copy));
  CHECK_C (ECDSA_do_verify(message, messagelen, sig, vk));

cleanup:
  if (zero) BN_clear_free(zero);
  if (vk) EC_KEY_free(vk);
  if (sig) ECDSA_SIG_free(sig);
  return rv;
}
