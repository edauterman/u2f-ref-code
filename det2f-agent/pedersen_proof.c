// Copyright 2018 Google Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

#include <stdlib.h>
#include <string.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include "common.h"
#include "params.h"
#include "pedersen_proof.h"

BIGNUM *commit(const_Params params, const EC_POINT *R, const EC_POINT *V);

PedersenStatement
PedersenStatement_new(const_Params params, const BIGNUM *x_prime,
                      const EC_POINT *commit_x, const EC_POINT *pk)
{
  int rv = ERROR;
  PedersenStatement st = malloc(sizeof *st);
  CHECK_A (st->x_prime = BN_dup(x_prime));
  CHECK_A (st->commit_x = EC_POINT_dup(commit_x, Params_group(params)));
  CHECK_A (st->pk = EC_POINT_dup(pk, Params_group(params)));

cleanup:
  if (rv == ERROR) {
    if (st->x_prime) BN_clear_free(st->x_prime);
    if (st->commit_x) EC_POINT_clear_free(st->commit_x);
    if (st->pk) EC_POINT_clear_free(st->pk);
    free(st);
  }
  return rv == OKAY ? st : NULL;
}

void
PedersenStatement_free(PedersenStatement st)
{
  if (st->x_prime) BN_clear_free(st->x_prime);
  if (st->commit_x) EC_POINT_clear_free(st->commit_x);
  if (st->pk) EC_POINT_clear_free(st->pk);
  free(st);
}

PedersenEvidence
PedersenEvidence_new(const_Params params)
{
  int rv = ERROR;
  PedersenEvidence ev = malloc(sizeof *ev);
  if (!ev)
    return NULL;

  CHECK_A (ev->c = BN_new());
  CHECK_A (ev->z = BN_new());
  CHECK_A (ev->R = Params_point_new(params));
cleanup:
  if (rv == ERROR) {
    if (ev->c) BN_clear_free(ev->c);
    if (ev->z) BN_clear_free(ev->z);
    if (ev->R) EC_POINT_clear_free(ev->R);
    free(ev);
  }
  return rv == OKAY ? ev : NULL;
}

void
PedersenEvidence_free(PedersenEvidence ev)
{
  if (ev->c) BN_clear_free(ev->c);
  if (ev->z) BN_clear_free(ev->z);
  if (ev->R) EC_POINT_clear_free(ev->R);
  free(ev);
}

/* Verify that R = h^r and check that pk was derived from x (from commitment)
 * and x'. */
int
PedersenEvidence_verify(const_Params params, const_PedersenEvidence ev,
                     const_PedersenStatement st)
{
  int rv = ERROR;
  BIGNUM *calc_c = NULL;
  EC_POINT *calc_R = NULL;
  EC_POINT *calc_V = NULL;
  EC_POINT *h_to_the_z = NULL;
  EC_POINT *R_to_the_c = NULL;

  CHECK_A (calc_c = BN_new());
  CHECK_A (calc_R = Params_point_new(params));
  CHECK_A (calc_V = Params_point_new(params));
  CHECK_A (h_to_the_z = Params_point_new(params));
  CHECK_A (R_to_the_c = Params_point_new(params));

  // V = h^z /R^c
  // h_to_the_z = h^z
  CHECK_C (Params_exp_base_h(params, h_to_the_z, ev->z));
  // R_to_the_c = R^c
  CHECK_C (Params_exp_base(params, R_to_the_c, ev->R, ev->c));
  // calc_V = h^z / R^c
  CHECK_C (Params_div(params, calc_V, h_to_the_z, R_to_the_c));

  // c ?= Hash(g,h,R,V)
  CHECK_A (calc_c = commit(params, ev->R, calc_V));

  // commit_x.g^x' / pk ?= R (where C is commit)
  // = g^x'
  CHECK_C (Params_exp_base_g(params, calc_R, st->x_prime));
  // = commit_x.g^x'
  CHECK_C (Params_mul(params, calc_R, st->commit_x, calc_R));
  // = commit_x.g^x' / pk
  CHECK_C (Params_div(params, calc_R, calc_R, st->pk));

  // Check calc_c ?= ev->c and calc_R ?= ev->R
  rv = ((BN_cmp(ev->c, calc_c) == 0)
        && (EC_POINT_cmp(Params_group(params), ev->R, calc_R,
                         Params_ctx(params)) == 0));

cleanup:
  if (calc_c) BN_clear_free(calc_c);
  if (calc_R) EC_POINT_clear_free(calc_R);
  if (calc_V) EC_POINT_clear_free(calc_V);
  if (h_to_the_z) EC_POINT_clear_free(h_to_the_z);
  if (R_to_the_c) EC_POINT_clear_free(R_to_the_c);
  return rv;
}

/* Generate commit value c = SHA256(g,h,R,V) where g and h are generators and R
   and V are EC points. Return NULL on error. */
BIGNUM *
commit(const_Params params, const EC_POINT *R, const EC_POINT *V)
{

  int rv = ERROR;
  const uint8_t tag_g[] = "g";
  const uint8_t tag_h[] = "h";
  const uint8_t tag_R[] = "R";
  const uint8_t tag_V[] = "V";

  uint8_t buf[SHA256_DIGEST_LENGTH];
  EVP_MD_CTX *mdctx = NULL;
  BIGNUM *result = NULL;

  CHECK_A (mdctx = EVP_MD_CTX_create());
  CHECK_A (result = BN_new());

  CHECK_C (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL));
  CHECK_C (Params_hash_point (params, mdctx, tag_g, sizeof tag_g, Params_g(params)));
  CHECK_C (Params_hash_point (params, mdctx, tag_h, sizeof tag_h, Params_h(params)));
  CHECK_C (Params_hash_point (params, mdctx, tag_R, sizeof tag_R, R));
  CHECK_C (Params_hash_point (params, mdctx, tag_V, sizeof tag_V, V));
  CHECK_C (EVP_DigestFinal_ex(mdctx, buf, NULL));

  CHECK_C (BN_bin2bn (buf, SHA256_DIGEST_LENGTH, result) != NULL);
  CHECK_C (BN_mod (result, result, Params_order(params), Params_ctx(params)));

cleanup:
  if (mdctx) EVP_MD_CTX_destroy(mdctx);
  if (rv == ERROR) {
    BN_clear_free(result);
    return NULL;
  }
  return result;
}
