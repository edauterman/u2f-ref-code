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
#include <openssl/ecdsa.h>
#include <openssl/x509.h>

#ifdef __OS_WIN
#include <winsock2.h> // ntohl, htonl
#else
#include <arpa/inet.h> // ntohl, htonl
#endif

#include "agent.h"
#include "asn1.h"
#include "params.h"
#include "common.h"
#include "ddh.h"
#include "det2f.h"
#include "hidapi.h"
#include "sig_parse.h"
#include "params.h"
#include "pedersen_proof.h"
#include "sanitizable_ecdsa.h"
#include "u2f.h"
#include "u2f_util.h"
#include "vif.h"
#include "vrf.h"
#include "x509.h"

#define EXPECTED_RET_VAL 0x9000

#define VENDOR_ID 0x18d1
#define PRODUCT_ID 0x5026

#define NUM_COUNTERS 100
#define LOG_WORDS 512

#define PK_FILE "storage/pk"
#define KH_FILE "storage/kh"
#define VRF_FILE "storage/vrf"
#define CTR_FILE "storage/ctr"

using namespace std;

/* Wrapper for storing key handles in a map. Allows lookup in map by key handle
 * value instead of by address of pointer. */
KeyHandle::KeyHandle(const uint8_t *data)
{
  memcpy(this->data, data, MAX_KH_SIZE);
}

bool KeyHandle::operator<(const KeyHandle &src) const
{
  return memcmp(this->data, src.data, MAX_KH_SIZE) < 0;
}

/* Convert buffers containing x and y coordinates to EC_POINT. */
void bufs_to_pt(const_Params params, const uint8_t *x, const uint8_t *y,
                EC_POINT *pt) {
  uint8_t buf[65];
  buf[0] = 4;
  memcpy(buf + 1, x, 32);
  memcpy(buf + 1 + 32, y, 32);
  EC_POINT_oct2point(Params_group(params), pt, buf, 65, Params_ctx(params));
}

/* Convert EC_POINT to buffers containing x and y coordinates (uncompressed). */
void pt_to_bufs(const_Params params, const EC_POINT *pt, uint8_t *x,
                uint8_t *y) {
  uint8_t buf[65];
  EC_POINT_point2oct(Params_group(params), pt, POINT_CONVERSION_UNCOMPRESSED,
                     buf, 65, Params_ctx(params));
  memcpy(x, buf + 1, 32);
  memcpy(y, buf + 1 + 32, 32);
}

/* Write agent state to file, including root public keys and map of key handles
 * to public keys. Should be called when creating a new agent. */
// TODO: error checking
void write_to_storage(Agent *a) {
  /* Write mpk and pk_vrf. */
  uint8_t mpk_buf[33];
  uint8_t pk_vrf_buf[33];
  FILE *pk_file = fopen(PK_FILE, "w");
  EC_POINT_point2oct(Params_group(a->params), a->mpk,
                     POINT_CONVERSION_COMPRESSED, mpk_buf, 33,
                     Params_ctx(a->params));
  EC_POINT_point2oct(Params_group(a->params), a->pk_vrf,
                     POINT_CONVERSION_COMPRESSED, pk_vrf_buf, 33,
                     Params_ctx(a->params));
  fwrite(mpk_buf, 33, 1, pk_file);
  fwrite(pk_vrf_buf, 33, 1, pk_file);
  fclose(pk_file);

  /* Write map of key handles to public keys. */
  FILE *kh_file = fopen(KH_FILE, "w");
  uint8_t pt[33];
  for (map<KeyHandle, EC_POINT*>::iterator it = a->pk_map.begin();
       it != a->pk_map.end(); it++) {
    EC_POINT_point2oct(Params_group(a->params), it->second,
                       POINT_CONVERSION_COMPRESSED, pt, 33,
                       Params_ctx(a->params));
    fwrite(it->first.data, MAX_KH_SIZE, 1, kh_file);
    fwrite(pt, 33, 1, kh_file);
  }
  fclose(kh_file);

#ifdef VRF_OPTIMIZED
  FILE *vrf_file = fopen(VRF_FILE, "w");
  for (map<KeyHandle, cached_vrf*>::iterator it = a->vrf_map.begin();
       it != a->vrf_map.end(); it++) {
    fwrite(it->first.data, MAX_KH_SIZE, 1, vrf_file);
    fwrite(it->second->vrf_kh, P256_SCALAR_SIZE, 1, vrf_file);
    fwrite(it->second->vrf_kh_mac, P256_SCALAR_SIZE, 1, vrf_file);
  }
  fclose(vrf_file);
#endif

  LRUCounter_write_to_storage(a->counter, CTR_FILE);
}

/* Read agent state from file, including root public keys and map of key handles
 * to public keys. Should be called when destroying an old agent. */
void read_from_storage(Agent *a) {
  /* Read mpk and pk_vrf. */
  uint8_t mpk_buf[33];
  uint8_t pk_vrf_buf[33];
  FILE *pk_file = fopen(PK_FILE, "r");
  if (pk_file != NULL) {
    if (fread(mpk_buf, P256_SCALAR_SIZE + 1, 1, pk_file) != 1) {
      fprintf(stderr, "ERROR: can't read mpk from file\n");
    }
    if (fread(pk_vrf_buf, P256_SCALAR_SIZE + 1, 1, pk_file) != 1) {
      fprintf(stderr, "ERROR: can't read pk_vrf from file\n");
    }
    if ((EC_POINT_oct2point(Params_group(a->params), a->mpk, mpk_buf, 33,
                           Params_ctx(a->params)) != OKAY) ||
        (EC_POINT_oct2point(Params_group(a->params), a->pk_vrf, pk_vrf_buf, 33,
                          Params_ctx(a->params)) != OKAY)) {
      fprintf(stderr, "ERROR: public key in invalid format\n");
    }
    fclose(pk_file);
  }

  /* Read map of key handles to public keys. */
  FILE *kh_file = fopen(KH_FILE, "r");
  if (kh_file != NULL) {
    uint8_t pt_buf[33];
    uint8_t kh[MAX_KH_SIZE];
    EC_POINT *pt;
    while (fread(kh, MAX_KH_SIZE, 1, kh_file) == 1) {
      if (fread(pt_buf, 33, 1, kh_file) != 1) {
        fprintf(stderr, "ERROR: no corresponding pk for key handle");
      }
      pt = Params_point_new(a->params);
      if (EC_POINT_oct2point(Params_group(a->params), pt, pt_buf, 33,
                             Params_ctx(a->params)) != OKAY) {
        fprintf(stderr, "ERROR: public key in invalid format\n");
      }
      a->pk_map[KeyHandle(kh)] = pt;
    }
    fclose(kh_file);
  }

#ifdef VRF_OPTIMIZED
  FILE *vrf_file = fopen(VRF_FILE, "r");
  if (vrf_file != NULL) {
    uint8_t kh[MAX_KH_SIZE];
    cached_vrf *vrf;
    while (fread(kh, MAX_KH_SIZE, 1, vrf_file) == 1) {
      vrf = (cached_vrf *)malloc(sizeof(cached_vrf));
      if ((fread(vrf->vrf_kh, P256_SCALAR_SIZE, 1, vrf_file) != 1) ||
          (fread(vrf->vrf_kh_mac, P256_SCALAR_SIZE, 1, vrf_file) != 1)) {
        fprintf(stderr, "ERROR: no corresponding VRF and MAC for key handle.\n");
      }
      a->vrf_map[KeyHandle(kh)] = vrf;
    }
    fclose(vrf_file);
  }
#endif

  if (LRUCounter_read_from_storage(a->counter, CTR_FILE) != OKAY) {
    fprintf(stderr, "ERROR: Can't read counter from file\n");
  }
}

/* Given the path to the U2F device, initialize the agent. */
int create_agent(Agent *a, char *deviceName) {
  int rv = ERROR;

  CHECK_A (a->device = U2Fob_create());
  CHECK_A (a->params = Params_new(P256));
  CHECK_A (a->mpk = Params_point_new(a->params));
  CHECK_A (a->pk_vrf = Params_point_new(a->params));
  CHECK_A (a->counter = LRUCounter_new(NUM_COUNTERS, LOG_WORDS));

  CHECK_C (!U2Fob_open(a->device, deviceName));
  CHECK_C (!U2Fob_init(a->device));

  read_from_storage(a);
cleanup:
  if (rv == ERROR) {
    Agent_destroy(a);
  }
  return rv;
}

/* Find a U2F device and initialize the agent. */
int Agent_init(Agent *a) {
  int rv = ERROR;
  struct hid_device_info *devs, *cur_dev;

  hid_init();
  devs = hid_enumerate(0x0, 0x0);
  cur_dev = devs;
  while (cur_dev) {
    if ((cur_dev->vendor_id == VENDOR_ID) &&
        (cur_dev->product_id == PRODUCT_ID)) {
      //fprintf(stderr, "det2f: found at %s\n", cur_dev->path);
      CHECK_C(create_agent(a, cur_dev->path));
      break;
    }
    cur_dev = cur_dev->next;
  }

cleanup:
  hid_exit();
  return rv;
}

/* Destroy current agent, including writing state to storage. */
void Agent_destroy(Agent *a) {

  write_to_storage(a);

  if (a->device) U2Fob_destroy(a->device);
  if (a->params) Params_free(a->params);
  if (a->mpk) EC_POINT_clear_free(a->mpk);
  if (a->pk_vrf) EC_POINT_clear_free(a->pk_vrf);
  if (a->counter) LRUCounter_free(a->counter);

  map<KeyHandle, EC_POINT*>::iterator it;
  for (it = a->pk_map.begin(); it != a->pk_map.end(); it++) {
    EC_POINT_clear_free(it->second);
  }
}

/* Run initialization using collaborative key generation. */
int Initialize_CollabKeygen(Agent *a) {
  int rv = ERROR;
  string rsp1, rsp2;
  BIGNUM *entropy_mpk, *entropy_vrf;
  EC_POINT *commit_mpk, *commit_vrf;
  PedersenStatement st_mpk, st_vrf;
  PedersenEvidence ev_mpk, ev_vrf;
  DET2F_INITIALIZE_1 in1;
  DET2F_INITIALIZE_2 out;
  DET2F_INITIALIZE_3 in2;

  CHECK_A (entropy_mpk = BN_new());
  CHECK_A (entropy_vrf = BN_new());
  CHECK_A (commit_mpk = Params_point_new(a->params));
  CHECK_A (commit_vrf = Params_point_new(a->params));
  CHECK_A (ev_mpk = PedersenEvidence_new(a->params));
  CHECK_A (ev_vrf = PedersenEvidence_new(a->params));

  /* Tell device to start initialization. */
  CHECK_C(EXPECTED_RET_VAL == U2Fob_apdu(a->device, 0, DET2F_INIT_START, 0, 0, "",
                                         &rsp1));

  /* Read in commits from device. */
  memcpy(&in1, rsp1.data(), rsp1.size());
  bufs_to_pt(a->params, in1.commit_mpk.x, in1.commit_mpk.y, commit_mpk);
  bufs_to_pt(a->params, in1.commit_vrf.x, in1.commit_vrf.y, commit_vrf);

  /* Sample random values for generating mpk and pk_vrf. */
  CHECK_C (Params_rand_exponent(a->params, entropy_mpk));
  CHECK_C (Params_rand_exponent(a->params, entropy_vrf));
  BN_bn2bin(entropy_mpk, out.entropy_mpk);
  BN_bn2bin(entropy_vrf, out.entropy_vrf);

  /* Send entropy to device. */
  CHECK_C(EXPECTED_RET_VAL == U2Fob_apdu(a->device, 0, DET2F_INIT_FINISH, 0, 0,
                                         string(reinterpret_cast<char*>(&out),
                                                sizeof(out)), &rsp2));
  memcpy(&in2, rsp2.data(), rsp2.size());

  /* Read in generated public keys. */
  bufs_to_pt(a->params, in2.mpk.x, in2.mpk.y, a->mpk);
  bufs_to_pt(a->params, in2.pk_vrf.x, in2.pk_vrf.y, a->pk_vrf);

   /* Read in proofs. */
  BN_bin2bn(in2.proof_mpk.c, P256_SCALAR_SIZE, ev_mpk->c);
  BN_bin2bn(in2.proof_mpk.z, P256_SCALAR_SIZE, ev_mpk->z);
  bufs_to_pt(a->params, in2.proof_mpk.R.x, in2.proof_mpk.R.y, ev_mpk->R);
  BN_bin2bn(in2.proof_vrf.c, P256_SCALAR_SIZE, ev_vrf->c);
  BN_bin2bn(in2.proof_vrf.z, P256_SCALAR_SIZE, ev_vrf->z);
  bufs_to_pt(a->params, in2.proof_vrf.R.x, in2.proof_vrf.R.y, ev_vrf->R);

  CHECK_A (st_mpk = PedersenStatement_new(a->params, entropy_mpk, commit_mpk,
                                          a->mpk));
  CHECK_A (st_vrf = PedersenStatement_new(a->params, entropy_vrf, commit_vrf,
                                          a->pk_vrf));

  /* Check proofs. */
  CHECK_C(PedersenEvidence_verify(a->params, ev_mpk, st_mpk));
  CHECK_C(PedersenEvidence_verify(a->params, ev_vrf, st_vrf));

cleanup:
  if (entropy_mpk) BN_clear_free(entropy_mpk);
  if (entropy_vrf) BN_clear_free(entropy_vrf);
  if (commit_mpk) EC_POINT_clear_free(commit_mpk);
  if (commit_vrf) EC_POINT_clear_free(commit_vrf);
  if (st_mpk) PedersenStatement_free(st_mpk);
  if (st_vrf) PedersenStatement_free(st_vrf);
  if (ev_mpk) PedersenEvidence_free(ev_mpk);
  if (ev_vrf) PedersenEvidence_free(ev_vrf);
  return rv;
}

/* Run initialization by loading secret keys directly. */
int Initialize_Direct(Agent *a, BIGNUM *msk, BIGNUM *sk_vrf) {
  int rv = ERROR;
  DET2F_INITIALIZE_DIRECT req;
  string resp_str;

  BN_bn2bin(msk, req.msk);
  BN_bn2bin(sk_vrf, req.sk_vrf);

  CHECK_C(EXPECTED_RET_VAL == U2Fob_apdu(a->device, 0, DET2F_INIT_DIRECT, 0, 0,
                                         string(reinterpret_cast<char*>(&req),
                                                sizeof(req)), &resp_str));
  CHECK_C(Params_exp(a->params, a->mpk, msk));
  CHECK_C(Params_exp(a->params, a->pk_vrf, sk_vrf));
cleanup:
  return rv;
}

/* Generate key handle using app_id and randomness. */
int
generate_key_handle(const uint8_t *app_id, int app_id_len, uint8_t *key_handle,
                    int key_handle_len)
{
  int rv = ERROR;
  memcpy(key_handle, app_id, app_id_len);
  CHECK_C (RAND_bytes(key_handle + app_id_len, key_handle_len - app_id_len));

cleanup:
  return rv;
}

/* Run registration with origin specified by app_id. Returns sum of lengths of
 * attestation certificate and batch signature. */
int Register(Agent *a, const uint8_t *app_id, const uint8_t *challenge,
             uint8_t *key_handle_out, P256_POINT *pk_out, uint8_t *cert_sig_out) {
  int rv = ERROR;
  EC_POINT *pk;
  VIFProof proof;
  DET2F_REGISTRATION_REQ req;
  DET2F_REGISTRATION_RESP resp;
  string resp_str;
  X509 *cert;
  EC_KEY *anon_key;
  EVP_MD_CTX *evpctx;
  int cert_len = 0;
  int sig_len = 0;
  uint8_t reg_id = U2F_REGISTER_HASH_ID;
  const BIGNUM *r = NULL;
  const BIGNUM *s = NULL;
  uint8_t signed_data[1 + U2F_APPID_SIZE + U2F_NONCE_SIZE + MAX_KH_SIZE +
      P256_POINT_SIZE];
  EVP_PKEY *anon_pkey;
  string str;
#ifdef VRF_OPTIMIZED
  cached_vrf *vrf;
#endif
#ifdef HASH2PT_OPTIMIZED
  int num_roots;
#endif

  CHECK_A(pk = Params_point_new(a->params));
  CHECK_A(proof = VIFProof_new(a->params));
  CHECK_A(cert = X509_new());
  CHECK_A(anon_key = EC_KEY_new());
  CHECK_A(evpctx = EVP_MD_CTX_create());
  CHECK_A(r = BN_new());
  CHECK_A(s = BN_new());
  CHECK_A(anon_pkey = EVP_PKEY_new());

  /* Generate key handle. */
  generate_key_handle(app_id, U2F_APPID_SIZE, req.key_handle, MAX_KH_SIZE);
  req.key_handle_len = MAX_KH_SIZE;

#ifdef HASH2PT_OPTIMIZED
  memset(req.roots, 0, 32 * NUM_ROOTS);
  num_roots = Params_fill_roots(a->params, req.key_handle, MAX_KH_SIZE, req.roots, NUM_ROOTS);
  /* Send request to fob and wait for response. */
  CHECK_C(EXPECTED_RET_VAL == U2Fob_apdu(a->device, 0, DET2F_REG_REQ, 0, 0,
                                         string(reinterpret_cast<char*>(&req),
                                                sizeof(uint8_t) + MAX_KH_SIZE + (num_roots * P256_SCALAR_SIZE)), &resp_str));
#else
  CHECK_C(EXPECTED_RET_VAL == U2Fob_apdu(a->device, 0, DET2F_REG_REQ, 0, 0,
                                         string(reinterpret_cast<char*>(&req),
                                                sizeof(req)), &resp_str));
#endif
  memcpy(&resp, resp_str.data(), resp_str.size());

  /* Read in message. */
  bufs_to_pt(a->params, resp.pk.x, resp.pk.y, pk);
  BN_bin2bn(resp.proof.val, P256_SCALAR_SIZE, proof->val);
  bufs_to_pt(a->params, resp.proof.val_pt.x, resp.proof.val_pt.y,
             proof->vrf_proof->val_pt);
  BN_bin2bn(resp.proof.c, P256_SCALAR_SIZE, proof->vrf_proof->ddh_proof->c);
  BN_bin2bn(resp.proof.v, P256_SCALAR_SIZE, proof->vrf_proof->ddh_proof->v);

  /* Verify proof. */
  CHECK_C(VIF_verify(a->params, a->mpk, a->pk_vrf, req.key_handle, MAX_KH_SIZE,
                     pk, proof));

  /* Save pk with key handle. */
  a->pk_map[KeyHandle(req.key_handle)] = pk;

#ifdef VRF_OPTIMIZED
  /* Save VRF with key handle. */
  CHECK_A (vrf = (cached_vrf *)malloc(sizeof(cached_vrf)));
  memcpy(vrf->vrf_kh, resp.vrf_kh, P256_SCALAR_SIZE);
  memcpy(vrf->vrf_kh_mac, resp.vrf_kh_mac, P256_SCALAR_SIZE);
  a->vrf_map[KeyHandle(req.key_handle)] = vrf;
#endif

  /* Output result. */
  pk_out->format = UNCOMPRESSED_POINT;
  memcpy(pk_out->x, resp.pk.x, P256_SCALAR_SIZE);
  memcpy(pk_out->y, resp.pk.y, P256_SCALAR_SIZE);
  memcpy(key_handle_out, req.key_handle, MAX_KH_SIZE);

  /* Randomly choose key for attestation. */
  CHECK_C (EC_KEY_set_group(anon_key, Params_group(a->params)));
  CHECK_C (EC_KEY_generate_key(anon_key));

  /* Generate self-signed cert. */
  cert_len = generate_cert(a->params, anon_key, cert_sig_out);

  /* Sign hash of U2F_REGISTER_ID, app_id, challenge, kh, and pk with key from
   * self-signed attestation cert. */
  memcpy(signed_data, &reg_id, 1);
  memcpy(signed_data + 1, app_id, U2F_APPID_SIZE);
  memcpy(signed_data + 1 + U2F_APPID_SIZE, challenge, U2F_NONCE_SIZE);
  memcpy(signed_data + 1 + U2F_APPID_SIZE + U2F_NONCE_SIZE, key_handle_out,
         MAX_KH_SIZE);
  memcpy(signed_data + 1 + U2F_APPID_SIZE + U2F_NONCE_SIZE + MAX_KH_SIZE,
         pk_out, P256_POINT_SIZE);
  CHECK_C(EVP_PKEY_assign_EC_KEY(anon_pkey, anon_key));
  CHECK_C(EVP_SignInit(evpctx, EVP_sha256()));
  CHECK_C(EVP_SignUpdate(evpctx, signed_data, 1 + U2F_APPID_SIZE +
                         U2F_NONCE_SIZE + MAX_KH_SIZE + P256_POINT_SIZE));
  CHECK_C(EVP_SignFinal(evpctx, cert_sig_out + cert_len,
                        (unsigned int *)&sig_len, anon_pkey));

cleanup:
  if (rv == ERROR && pk) EC_POINT_clear_free(pk);
  if (proof) VIFProof_free(proof);
  if (cert) X509_free(cert);
  if (anon_pkey) EVP_PKEY_free(anon_pkey);
  if (evpctx) EVP_MD_CTX_destroy(evpctx);
  return cert_len + sig_len;
}

/* Authenticate at origin specified by app_id given a challenge from the origin
 * and a key handle obtained from registration. Returns length of signature. */
int Authenticate(Agent *a, const uint8_t *app_id, const uint8_t *challenge,
                 const uint8_t *key_handle, uint8_t *flags_out, uint32_t *ctr_out,
                 uint8_t *sig_out, bool checkOnly) {
  int rv = ERROR;
#ifdef VRF_OPTIMIZED
  DET2F_AUTHENTICATION_0 msg0;
#endif
  DET2F_AUTHENTICATION_1 msg1;
  DET2F_AUTHENTICATION_2 msg2;
  DET2F_AUTHENTICATION_3 msg3;
  string resp_str1, resp_str2;
  EC_POINT *commit_k = NULL;
  EC_POINT *K = NULL;
  BIGNUM *entropy_k = NULL;
  PedersenStatement st = NULL;
  PedersenEvidence ev = NULL;
  BIGNUM *K_x = NULL;
  BIGNUM *k = NULL;
  BIGNUM *r = NULL;
  BIGNUM *s = NULL;
  EVP_MD_CTX *mdctx;
  uint8_t message[SHA256_DIGEST_LENGTH];
  ECDSA_SIG *sig = NULL;
  int sig_len = 0;
  uint32_t ctr;
  uint64_t calc_ctr;
  int num_roots = 0;

  CHECK_A (commit_k = Params_point_new(a->params));
  CHECK_A (K = Params_point_new(a->params));
  CHECK_A (K_x = BN_new());
  CHECK_A (k = BN_new());
  CHECK_A (entropy_k = BN_new());
  CHECK_A (ev = PedersenEvidence_new(a->params));
  CHECK_A (r = BN_new());
  CHECK_A (s = BN_new());
  CHECK_A (mdctx = EVP_MD_CTX_create());
  CHECK_A (sig = ECDSA_SIG_new());

#ifdef VRF_OPTIMIZED
  memcpy(msg0.vrf_kh, a->vrf_map[KeyHandle(key_handle)]->vrf_kh, P256_SCALAR_SIZE);
  memcpy(msg0.vrf_kh_mac, a->vrf_map[KeyHandle(key_handle)]->vrf_kh_mac, P256_SCALAR_SIZE);
  /* Ask device to commit to value for generating signing nonce. */
  CHECK_C(EXPECTED_RET_VAL == U2Fob_apdu(a->device, 0, DET2F_AUTH_START, 0, 0,
                                         string(reinterpret_cast<char*>(&msg0),
                                                sizeof(msg0)), &resp_str1));
#else
  CHECK_C(EXPECTED_RET_VAL == U2Fob_apdu(a->device, 0, DET2F_AUTH_START, 0, 0, "",
                                         &resp_str1));
#endif

 memcpy(&msg1, resp_str1.data(), resp_str1.size());
  bufs_to_pt(a->params, msg1.commit_k.x, msg1.commit_k.y, commit_k);
  /* Sample random value for generating signing nonce. */
  CHECK_C (Params_rand_exponent(a->params, entropy_k));

  /* Construct message to device. */
  BN_bn2bin(entropy_k, msg2.entropy_k);
  memcpy(msg2.challenge, challenge, U2F_NONCE_SIZE);
  memcpy(msg2.app_id, app_id, U2F_APPID_SIZE);
  msg2.key_handle_len = MAX_KH_SIZE;
  memcpy(msg2.key_handle, key_handle, MAX_KH_SIZE);

#if defined(HASH2PT_OPTIMIZED) && !defined(VRF_OPTIMIZED)
  memset(msg2.roots, 0, 32 * NUM_ROOTS);
  num_roots = Params_fill_roots(a->params, msg2.key_handle, MAX_KH_SIZE, msg2.roots, NUM_ROOTS);
#endif

  if (P256_SCALAR_SIZE + U2F_NONCE_SIZE + U2F_APPID_SIZE + sizeof(uint8_t) + MAX_KH_SIZE + (num_roots * P256_SCALAR_SIZE) != sizeof(msg2)) {
    fprintf(stderr, "warning: lens don't match\n");
  }

  /* Send entropy and signing information to device. */
  CHECK_C(EXPECTED_RET_VAL == U2Fob_apdu(a->device, 0, DET2F_AUTH_FINISH,
                                         checkOnly ? U2F_AUTH_CHECK_ONLY :
                                         U2F_AUTH_ENFORCE, 0,
                                         string(reinterpret_cast<char*>(&msg2),
                                                P256_SCALAR_SIZE + U2F_NONCE_SIZE + U2F_APPID_SIZE + sizeof(uint8_t) + MAX_KH_SIZE + (num_roots * P256_SCALAR_SIZE)), &resp_str2));
  memcpy(&msg3, resp_str2.data(), resp_str2.size());

  /* Read in message. */
  BN_bin2bn(msg3.proof_k.c, P256_SCALAR_SIZE, ev->c);
  BN_bin2bn(msg3.proof_k.z, P256_SCALAR_SIZE, ev->z);
  bufs_to_pt(a->params, msg3.proof_k.R.x, msg3.proof_k.R.y, ev->R);
  bufs_to_pt(a->params, msg3.K.x, msg3.K.y, K);
  BN_bin2bn(msg3.K.x, P256_SCALAR_SIZE, K_x);
  sig_len = resp_str2.size() - sizeof(msg3.K) - sizeof(msg3.proof_k) -
      sizeof(msg3.flags) - sizeof(msg3.ctr);
  CHECK_C(dsa_sig_unpack(msg3.sig, sig_len, r, s));
  ctr = (msg3.ctr[0] >> 24) + (msg3.ctr[1] >> 16) + (msg3.ctr[2] >> 8) + (msg3.ctr[3]);

  CHECK_A (st = PedersenStatement_new(a->params, entropy_k, commit_k,
                                      K));

  /* Check counter value. */
  calc_ctr = LRUCounter_incr(a->counter, app_id);
  CHECK_C(((calc_ctr << 32) >> 32) == ctr);

  /* Compute signed message: hash of appId, user presence, counter, and
   * challenge. */
  CHECK_C (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL));
  CHECK_C (EVP_DigestUpdate(mdctx, app_id, U2F_APPID_SIZE));
  CHECK_C (EVP_DigestUpdate(mdctx, &msg3.flags, sizeof(msg3.flags)));
  CHECK_C (EVP_DigestUpdate(mdctx, msg3.ctr, sizeof(msg3.ctr)));
  CHECK_C (EVP_DigestUpdate(mdctx, challenge, U2F_NONCE_SIZE));
  CHECK_C (EVP_DigestFinal_ex(mdctx, message, NULL));

  /* Run ECDSA verification. */
  CHECK_C (SanitizableEcdsa_verify_sanitize(a->params, message,
                                            SHA256_DIGEST_LENGTH, K_x,
                                            a->pk_map[KeyHandle(key_handle)],
                                            r, s, st, ev));
  /* Output signature. */
  asn1_sigp(sig_out, r, s);

  /* Output message from device. */
  *flags_out = msg3.flags;
  memcpy(ctr_out, msg3.ctr, sizeof(uint32_t));

cleanup:
  if (commit_k) EC_POINT_clear_free(commit_k);
  if (K) EC_POINT_clear_free(K);
  if (K_x) BN_clear_free(K_x);
  if (entropy_k) BN_clear_free(entropy_k);
  if (k) BN_clear_free(k);
  if (ev) PedersenEvidence_free(ev);
  if (st) PedersenStatement_free(st);
  if (mdctx) EVP_MD_CTX_destroy(mdctx);
  return rv == OKAY ? sig_len : ERROR;
}
