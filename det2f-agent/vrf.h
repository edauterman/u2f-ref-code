#ifndef _VRF_H
#define _VRF_H

/*
 * Copyright (c) 2018, Henry Corrigan-Gibbs
 * 
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND
 * FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

#include <openssl/ec.h>
#include "params.h"
#include "ddh.h"

#ifdef __cplusplus
extern "C"{
#endif

struct vrf_proof {
  EC_POINT *val_pt;     /* Point corresponding to output value. */
  DDHProof ddh_proof;   /* DDH proof. */
};

typedef struct vrf_proof *VRFProof;
typedef const struct vrf_proof *const_VRFProof;

VRFProof VRFProof_new(const_Params params);
void VRFProof_free(VRFProof proof);

/* Verify using pk that val was derived from input. */
int VRF_verify (const_Params params,
    const EC_POINT *pk, const uint8_t *input, int inputlen,
    const BIGNUM *val, const_VRFProof proof);

#ifdef __cplusplus
}
#endif
#endif

