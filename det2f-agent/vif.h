// Copyright 2018 Google Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

#ifndef _VIF_H
#define _VIF_H

#include <openssl/ec.h>
#include "params.h"
#include "vrf.h"

#ifdef __cplusplus
extern "C"{
#endif

struct vif_proof {
  BIGNUM *val;          // value produced by VRF.Eval
  VRFProof vrf_proof;   // proof produced by VRF.Eval
};

typedef struct vif_proof *VIFProof;
typedef const struct vif_proof *const_VIFProof;

VIFProof VIFProof_new(const_Params params);
void VIFProof_free(VIFProof proof);

/* Use mpk and pk_vrf to verify that pk is derived from input. */
int VIF_verify (const_Params params,
                const EC_POINT *mpk, const EC_POINT *pk_vrf,
                const uint8_t *input, int inputlen, const EC_POINT *pk,
                const_VIFProof proof);

#ifdef __cplusplus
}
#endif
#endif

