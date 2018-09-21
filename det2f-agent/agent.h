// Copyright 2018 Google Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

#ifndef _AGENT_H
#define _AGENT_H

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <map>

#include "det2f.h"
#include "params.h"
#include "u2f.h"
#include "counter.h"

using namespace std;

/* Wrapper for storing key handles in a map. Allows lookup in map by key handle
 * value instead of by address of pointer. */
class KeyHandle {
  public:
  uint8_t data[MAX_KH_SIZE];
  KeyHandle(const uint8_t *data);
  bool operator<(const KeyHandle &src) const;
};

#ifdef VRF_OPTIMIZED
typedef struct {
  uint8_t vrf_kh[P256_SCALAR_SIZE];
  uint8_t vrf_kh_mac[P256_SCALAR_SIZE];
} cached_vrf;
#endif

typedef struct {
  /* Representation of fob used for HID transport. */
  struct U2Fob *device;
  /* P256 parameters. */
  Params params;
  /* Root public keys used for auditing device. */
  EC_POINT *mpk, *pk_vrf;
  /* Map of key handles to public keys. */
  map<KeyHandle, EC_POINT*> pk_map;
#ifdef VRF_OPTIMIZED
  /* Map of key handles to cached VRFs with MAC tags. */
  map<KeyHandle, cached_vrf*> vrf_map;
#endif
  /* LRU Counter. */
  LRUCounter counter;
} Agent;

int Agent_init(Agent *a);
void Agent_destroy(Agent *a);

/* Run initialization using collaborative key generation. */
int Initialize_CollabKeygen(Agent *a);

/* Run initialization by loading secret keys directly. */
int Initialize_Direct(Agent *a, BIGNUM *msk, BIGNUM *sk_vrf);

/* Run registration with origin specified by app_id. Outputs the key handle and
 * public key, and generates a self-signed cert and corresponding batch
 * signature (created entirely at the agent). Returns sum of length of
 * attestation certificate and batch signature, or 0 on failure.*/
int Register(Agent *a, const uint8_t *app_id, const uint8_t *challenge,
             uint8_t *key_handle_out, P256_POINT *pk_out, uint8_t *cert_sig_out);

/* Authenticate at origin specified by app_id given a challenge from the origin
 * and a key handle obtained from registration. Outputs the flags, counter, and
 * sanitized signature from the device. Returns the length of the signature, or
 * 0 on failure. */
int Authenticate(Agent *a, const uint8_t *app_id, const uint8_t *challenge,
                 const uint8_t *key_handle, uint8_t *flags_out, uint32_t *ctr_out,
                 uint8_t *sig_out, bool checkOnly = false);

#endif

