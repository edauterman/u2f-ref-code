// Copyright 2018 Google Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

#include "common.h"
#include "params.h"
#include "vif.h"
#include "vrf.h"

VIFProof
VIFProof_new(const_Params params)
{
  int rv = ERROR;
  VIFProof proof = NULL;
  CHECK_A (proof = malloc(sizeof *proof));

  proof->val = NULL;
  proof->vrf_proof = NULL;
  CHECK_A (proof->val = BN_new());
  CHECK_A (proof->vrf_proof = VRFProof_new(params));

cleanup:
  if (rv == ERROR) {
    VIFProof_free(proof);
    return NULL;
  }
  return proof;
}

void
VIFProof_free(VIFProof proof)
{
  if (proof->val) BN_clear_free(proof->val);
  if (proof->vrf_proof) VRFProof_free(proof->vrf_proof);
  free(proof);
}

/* Use mpk and pk_vrf to verify that pk is derived from input. */
int
VIF_verify (const_Params params,
            const EC_POINT *mpk, const EC_POINT *pk_vrf, const uint8_t *input,
            int inputlen, const EC_POINT *pk, const_VIFProof proof)
{
  int rv = ERROR;
  EC_POINT *calc_pk = NULL;
  CHECK_A (calc_pk = Params_point_new(params));

  // VRF.Verify(pk_vrf, input, proof) --> {0,1}
  CHECK_C (VRF_verify(params, pk_vrf, input, inputlen, proof->val,
                      proof->vrf_proof));

  // Check that pk = mpk^{g^val}
  //CHECK_C (Params_exp(params, calc_pk, proof->val));
  //CHECK_C (Params_mul(params, calc_pk, mpk, calc_pk));
  CHECK_C (Params_exp_base(params, calc_pk, mpk, proof->val));
  CHECK_C (!EC_POINT_cmp(Params_group(params), calc_pk, pk,
                         Params_ctx(params)));

cleanup:
  if (calc_pk) EC_POINT_clear_free(calc_pk);
  return rv;
}


