
// Copyright 2018 Google Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

#ifndef _S_ECDSA_H
#define _S_ECDSA_H

#include <openssl/ec.h>
#include "params.h"
#include "pedersen_proof.h"

#ifdef __cplusplus
extern "C"{
#endif

/* Check that ECDSA signature is valid and sanitizable, meaning that ev verifies
 * and the signature is of the form (r,s) and not (r,-s). */
int
SanitizableEcdsa_verify_sanitize(const_Params params, const uint8_t *message,
                                 int messagelen, const BIGNUM *K_x,
                                 const EC_POINT *pk, BIGNUM *sig_r,
                                 BIGNUM *sig_s, const_PedersenStatement st,
                                 const_PedersenEvidence ev);

#ifdef __cplusplus
}
#endif
#endif

