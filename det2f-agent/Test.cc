// Copyright 2018 Google Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <map>

#include <iostream>
#include <iomanip>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#ifdef __OS_WIN
#include <winsock2.h> // ntohl, htonl
#else
#include <arpa/inet.h> // ntohl, htonl
#endif

#include "agent.h"
#include "common.h"
#include "ddh.h"
#include "det2f.h"
#include "sig_parse.h"
#include "params.h"
#include "pedersen_proof.h"
#include "sanitizable_ecdsa.h"
#include "u2f.h"
#include "u2f_util.h"
#include "vif.h"
#include "vrf.h"

using namespace std;

static
void AbortOrNot() {
  abort();
}

int main(int argc, char *argv[]) {
  Agent a;
  uint8_t app_id[U2F_APPID_SIZE];
  uint8_t challenge[U2F_NONCE_SIZE];
  uint8_t key_handle[MAX_KH_SIZE];
  uint8_t cert_sig[MAX_CERT_SIZE + MAX_ECDSA_SIG_SIZE];
  uint8_t sig[MAX_ECDSA_SIG_SIZE];
  uint8_t flags;
  uint32_t ctr;
  P256_POINT pk;

  srand((unsigned int) time(NULL));

  printf("Starting test...\n");

  Agent_init(&a);

  CHECK_EQ(OKAY, Initialize_CollabKeygen(&a));

  for (size_t i = 0; i < sizeof app_id; i++) {
    app_id[i] = rand();
  }
  for (size_t i = 0; i < sizeof challenge; i++) {
    challenge[i] = rand();
  }

  CHECK_EQ(OKAY, Register(&a, app_id, challenge, key_handle, &pk, cert_sig) > 0);

  for (size_t i = 0; i < sizeof challenge; i++) {
    challenge[i] = rand();
  }
  CHECK_EQ(OKAY, Authenticate(&a, app_id, challenge, key_handle, &flags, &ctr, sig) > 0);

  printf("... successfully completed test.\n");
  Agent_destroy(&a);

  return 0;
}
