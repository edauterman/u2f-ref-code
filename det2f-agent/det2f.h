// Copyright 2018 Google Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

/**
 * This header provides definitions for the protocol layer for deterministically
 * seeded U2F. Official FIDO-compliant definitions located in "u2f.h".
 */
#ifndef __DET2F_H_INCLUDED__
#define __DET2F_H_INCLUDED__

#include "u2f.h"

#ifdef __cplusplus
extern "C" {
#endif

#define VRF_OPTIMIZED
#define HASH2PT_OPTIMIZED

typedef struct {
  uint8_t c[P256_SCALAR_SIZE];
  uint8_t z[P256_SCALAR_SIZE];
  P256_POINT R;
} DET2F_PED_PROOF;

typedef struct {
  uint8_t val[P256_SCALAR_SIZE];
  P256_POINT val_pt;
  uint8_t c[P256_SCALAR_SIZE];
  uint8_t v[P256_SCALAR_SIZE];
} DET2F_VIF_PROOF;


// Non-spec det2f commands.

#define DET2F_INIT_START 0x70
#define DET2F_INIT_FINISH 0x71
#define DET2F_INIT_DIRECT 0x72
#define DET2F_REG_REQ 0x73
#define DET2F_AUTH_START 0x74
#define DET2F_AUTH_FINISH 0x75

#define U2F_CTR_SIZE 4
#define NUM_ROOTS 32

typedef struct {
  P256_POINT commit_mpk;                 // commit for mpk
  P256_POINT commit_vrf;                 // commit for pk_vrf
} DET2F_INITIALIZE_1;

typedef struct {
  uint8_t entropy_mpk[P256_SCALAR_SIZE];     // randomness for mpk
  uint8_t entropy_vrf[P256_SCALAR_SIZE];     // randomness for pk_vrf
} DET2F_INITIALIZE_2;

typedef struct {
  P256_POINT mpk;                     // master public key
  P256_POINT pk_vrf;                  // VRF public key
  DET2F_PED_PROOF proof_mpk;            // proof for mpk
  DET2F_PED_PROOF proof_vrf;            // proof for pk_vrf
} DET2F_INITIALIZE_3;

typedef struct {
  uint8_t msk[P256_SCALAR_SIZE];    // master secret key
  uint8_t sk_vrf[P256_SCALAR_SIZE]; // VRF secret key
} DET2F_INITIALIZE_DIRECT;

typedef struct {
  uint8_t key_handle_len;             // Length of key handle
  uint8_t key_handle[MAX_KH_SIZE];    // Key handle
#ifdef HASH2PT_OPTIMIZED
  uint8_t roots[NUM_ROOTS][P256_SCALAR_SIZE];
#endif
} DET2F_REGISTRATION_REQ;

typedef struct {
  uint8_t registerId;             // Registration ID (U2F_REGISTER_ID)
  P256_POINT pk;                  // Generated public key
  DET2F_VIF_PROOF proof;          // Proof for generation of public key
#ifdef VRF_OPTIMIZED
  uint8_t vrf_kh[P256_SCALAR_SIZE];     // VRF(key_handle)
  uint8_t vrf_kh_mac[P256_SCALAR_SIZE]; // MAC for VRF(key_handle)
#endif
} DET2F_REGISTRATION_RESP;

#ifdef VRF_OPTIMIZED
typedef struct {
  uint8_t vrf_kh[P256_SCALAR_SIZE];     // VRF(key_handle)
  uint8_t vrf_kh_mac[P256_SCALAR_SIZE]; // MAC for VRF(key_handle)
} DET2F_AUTHENTICATION_0;
#endif

typedef struct {
  P256_POINT commit_k;                  // Commit for k
} DET2F_AUTHENTICATION_1;

typedef struct {
  uint8_t entropy_k[P256_SCALAR_SIZE];    // Entropy for generating k
  uint8_t challenge[U2F_NONCE_SIZE];      // Challenge
  uint8_t app_id[U2F_APPID_SIZE];         // Application ID
  uint8_t key_handle_len;                 // Length of key handle
  uint8_t key_handle[MAX_KH_SIZE];        // Key handle
#if defined(HASH2PT_OPTIMIZED) && !defined(VRF_OPTIMIZED)
  uint8_t roots[NUM_ROOTS][P256_SCALAR_SIZE];
#endif
} DET2F_AUTHENTICATION_2;

typedef struct {
  P256_POINT K;                 // K = g^k used in signature
  DET2F_PED_PROOF proof_k;      // proof for k
  uint8_t flags;                // U2F_AUTH_FLAG_ values
  uint8_t ctr[U2F_CTR_SIZE]; //in big endian, need to do this
  uint8_t sig[MAX_ECDSA_SIG_SIZE]; // ECDSA signature.
} DET2F_AUTHENTICATION_3;

#ifdef __cplusplus
}
#endif

#endif  // __DET2F_H_INCLUDED__
