// Copyright 2018 Google Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

#ifndef _PEDERSEN_PROOF_H
#define _PEDERSEN_PROOF_H

#include "params.h"

#ifdef __cplusplus
extern "C"{
#endif

/**
 * Pedersen Proof is a NIZKPoK used to ensure that the device incorporates the
 * randomness from the entropy authority (x') and the randomness committed to
 * by the device (x). The device has also already chosen a random r and used
 * that value in its commitment.
 *
 * Given commitment C_x = g^x.h^r and pk = g^{x+x'}, checks that:
 *      C_x.g^x' / pk = h^r
 *    = g^x.h^r.g^x' / g^{x+x'} = h^r
 *
 * r cannot be sent from the prover to the verifier directly, and so we use the
 * Schnorr protocol to prove that R = h^r without revealing r. We make the
 * Schnorr protocol non-interactive by choosing a challenge that is the hash of
 * generators g and h and points h^r and h^v.
 *
 * Using publicly known generators g,h of order q
 *
 * Prover(g,h,r)                          Verifier(g,h,C_x,pk)
 * ------                                 --------
 * R = h^r
 * random v
 * V = h^v
 * c = Hash(g,h,R,V)
 * z = v + cr (mod q)
 *                   c,z,R
 *        ------------------------------>
 *                                        V* = h^z / R^c
 *                                        c ?= Hash(g,h,R,V*)
 *                                        C*g^x' / pk ?= R
 */

struct pedersen_statement {
  // Randomness contributed by entropy authority.
  BIGNUM *x_prime;
  // Commitment to randomness from device.
  EC_POINT *commit_x;
  // Public key generated, g^{x+x'}.
  EC_POINT *pk;
};

struct pedersen_evidence {
  // Commit value. c = Hash(g,h,R,V)
  BIGNUM *c;
  // Part of Schnorr protocol. z = v + cr (mod q)
  BIGNUM *z;
  // R = h^r
  EC_POINT *R;
};

/* Statement to be proven. */
typedef struct pedersen_statement *PedersenStatement;
typedef const struct pedersen_statement *const_PedersenStatement;

/* Proof of statement. */
typedef struct pedersen_evidence *PedersenEvidence;
typedef const struct pedersen_evidence *const_PedersenEvidence;

PedersenStatement PedersenStatement_new(const_Params params,
                                        const BIGNUM *x_prime,
                                        const EC_POINT *commit_x,
                                        const EC_POINT *pk);
void PedersenStatement_free(PedersenStatement st);

PedersenEvidence PedersenEvidence_new(const_Params params);
void PedersenEvidence_free(PedersenEvidence ev);

/* Completed by verifier. */
int PedersenEvidence_verify(const_Params params, const_PedersenEvidence ev,
                         const_PedersenStatement st);

#ifdef __cplusplus
}
#endif
#endif

