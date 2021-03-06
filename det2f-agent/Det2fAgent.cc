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
#include <json.hpp>
#include <string>

#include "agent.h"
#include "common.h"
#include "base64.h"

// Used to define JSON messages.
#define ID "agent-det2f"
#define AUTH_REQ "sign_helper_request"
#define AUTH_RESP "sign_helper_reply"
#define REG_REQ "enroll_helper_request"
#define REG_RESP "enroll_helper_reply"
#define TYPE "type"
#define CODE "code"
#define VERSION "version"
#define ENROLL_CHALLENGES "enrollChallenges"
#define APP_ID "appIdHash"
#define CHALLENGE "challengeHash"
#define KEY_HANDLE "keyHandle"
#define ENROLL_DATA "enrollData"
#define SIGN_DATA "signData"
#define RESPONSE_DATA "responseData"
#define SIGNATURE "signatureData"
#define DEVICE_OK 0
#define DEVICE_ERR 0x6984
#define U2F_V2 "U2F_V2"

using namespace std;
using namespace nlohmann;

struct message_t {
  string content;
  uint32_t length;
};

/* Read a message from stdin and decode it. */
json get_message() {
  char raw_length[4];
  fread(raw_length, 4, sizeof(char), stdin);
  uint32_t message_length = *reinterpret_cast<uint32_t*>(raw_length);
  if(!message_length) {
    fprintf(stderr, "ERROR: bad message length\n");
    return json::array();
  }

  char message[message_length];
  fread(message, message_length, sizeof(char), stdin);
  string m( message, message + sizeof message / sizeof message[0] );
  return json::parse(m);
}

/* Encode a message for transmission, given its content. */
message_t encode_message(json content) {
  string encoded_content = content.dump();
  message_t m;
  m.content = encoded_content;
  m.length = (uint32_t) encoded_content.length();
  return m;
}

/* Send an encoded message to stdout. */
void send_message(message_t encoded_message) {
  char* raw_length = reinterpret_cast<char*>(&encoded_message.length);
  fwrite (raw_length , 4, sizeof(char), stdout);
  fwrite (encoded_message.content.c_str(), encoded_message.length,
          sizeof(char), stdout);
  fflush(stdout);
}

/* Handle registration request and send response. */
void handle_registration(Agent *a, json request) {
  json response;
  string app_id_str, challenge_str, key_handle_str;
  U2F_REGISTER_RESP u2f_resp;
  u2f_resp.keyHandleLen = MAX_KH_SIZE;
  uint8_t resp_buf[sizeof(U2F_REGISTER_RESP)];
  uint8_t app_id[U2F_APPID_SIZE + 1];
  uint8_t challenge[U2F_NONCE_SIZE + 1];

  fprintf(stderr, "det2f: handling registration request\n");

  /* Set base fields. */
  response[TYPE] = REG_RESP;
  response[VERSION] = U2F_V2;

  /* Decode app id. */
  app_id_str = request[ENROLL_CHALLENGES][0][APP_ID];
  fprintf(stderr, "det2f: app_id %s\n", app_id_str.c_str());
  int app_id_size = decode_base64(app_id, app_id_str.c_str());
  if (app_id_size != U2F_APPID_SIZE + 1) // extra 1 for null terminator
    fprintf(stderr, "det2f: ERROR: decoded enroll data that's not of length\
            U2F_APPID_SIZE: %d\n", app_id_size);

  /* Decode challenge. */
  challenge_str = request[ENROLL_CHALLENGES][0][CHALLENGE];
  fprintf(stderr, "det2f: challenge %s\n", challenge_str.c_str());
  int challenge_size = decode_base64(challenge, challenge_str.c_str());
  if (challenge_size != U2F_NONCE_SIZE + 1) // extra 1 for null terminator
    fprintf(stderr, "det2f: ERROR: decoded enroll data that's not of length\
            U2F_APPID_SIZE: %d\n", challenge_size);

  /* Register with device. */
  uint8_t *cert_sig_ptr = u2f_resp.keyHandleCertSig + MAX_KH_SIZE;
  int cert_sig_len = Register(a, app_id, challenge, u2f_resp.keyHandleCertSig,
                              &u2f_resp.pubKey, cert_sig_ptr);
  if (cert_sig_len > 0) {
    /* Successful registration. */
    fprintf(stderr, "det2f: successful register\n");

    /* Set additional response fields. */
    response[CODE] = DEVICE_OK;
    u2f_resp.keyHandleLen = MAX_KH_SIZE;
    u2f_resp.registerId = U2F_REGISTER_ID;

    /* Encode response as websafe base64 string. */
    int resp_size = sizeof(U2F_REGISTER_RESP) -
        (MAX_CERT_SIZE + MAX_ECDSA_SIG_SIZE) + cert_sig_len;
    memcpy(resp_buf, &u2f_resp, resp_size);
    char *encoded_enroll = encode_base64(resp_size, resp_buf);
    response[ENROLL_DATA] = string(encoded_enroll);
    free(encoded_enroll);
  } else {
    /* Unsuccessful. Report error. */
    fprintf(stderr, "det2f: unsuccessful register\n");
    response[CODE] = DEVICE_ERR;
  }
  fprintf(stderr, "det2f: sending %s\n", response.dump().c_str());
  send_message(encode_message(response));
}

/* Handle authentication request and send response. */
void handle_authentication(Agent *a, json request) {
  json response;
  string app_id_str, challenge_str, key_handle_str;
  U2F_AUTHENTICATE_RESP u2f_resp;
  uint8_t resp_buf[sizeof(U2F_AUTHENTICATE_RESP)];
  uint8_t app_id[U2F_APPID_SIZE + 1];
  uint8_t challenge[U2F_NONCE_SIZE + 1];
  uint8_t key_handle[MAX_KH_SIZE + 1];

  fprintf(stderr, "det2f: handling authentication request\n");

  /* Set base field. */
  response[TYPE] = AUTH_RESP;

  /* Decode app id. */
  app_id_str = request[SIGN_DATA][0][APP_ID];
  fprintf(stderr, "det2f: app_id %s\n", app_id_str.c_str());
  int app_id_size = decode_base64(app_id, app_id_str.c_str());
  if (app_id_size != U2F_APPID_SIZE + 1)
    fprintf(stderr, "det2f: ERROR decoded sign data that's not of length\
            U2F_APPID_SIZE: %d\n", app_id_size);

  /* Decode challenge. */
  challenge_str = request[SIGN_DATA][0][CHALLENGE];
  fprintf(stderr, "det2f: challenge %s\n", challenge_str.c_str());
  int challenge_size = decode_base64(challenge, challenge_str.c_str());
  if (challenge_size != U2F_NONCE_SIZE + 1)
    fprintf(stderr, "det2f: ERROR decoded sign data that's not of length\
            U2F_NONCE_SIZE: %d\n", challenge_size);

  /* Decode key handle. */
  key_handle_str = request[SIGN_DATA][0][KEY_HANDLE];
  fprintf(stderr, "det2f: key handle %s\n", key_handle_str.c_str());
  int key_handle_size = decode_base64(key_handle, key_handle_str.c_str());
  if (key_handle_size != MAX_KH_SIZE + 1)
    fprintf(stderr, "det2f: ERROR decoded sign data that's not of length\
            MAX_KH_SIZE: %d\n", key_handle_size);

  /* Authenticate with device. */
  int sig_len = Authenticate(a, app_id, challenge, key_handle, &u2f_resp.flags,
                             &u2f_resp.ctr, u2f_resp.sig);
  if (sig_len > 0) {
    /* Successful authentication. */
    fprintf(stderr, "det2f: successful authentication\n");

    /* Set response fields. */
    response[CODE] = DEVICE_OK;
    json responseData;
    responseData[VERSION] = U2F_V2;
    responseData[APP_ID] = request[SIGN_DATA][0][APP_ID];
    responseData[CHALLENGE] = request[SIGN_DATA][0][CHALLENGE];
    responseData[KEY_HANDLE] = request[SIGN_DATA][0][KEY_HANDLE];

    /* Encode signature as websafe base64 string. */
    int msg_len = sizeof(U2F_AUTHENTICATE_RESP) - MAX_ECDSA_SIG_SIZE + sig_len;
    memcpy(resp_buf, &u2f_resp, msg_len);
    char *encoded_sig = encode_base64(msg_len, resp_buf);
    responseData[SIGNATURE] = string(encoded_sig);
    response[RESPONSE_DATA] = responseData;
    free(encoded_sig);
  } else {
    /* Unsuccessful. Report error. */
    fprintf(stderr, "det2f: unsuccessful authentication\n");
    response[CODE] = DEVICE_ERR;
  }
  fprintf(stderr, "det2f: sending %s\n", response.dump().c_str());
  send_message(encode_message(response));
}

int main(int argc, char *argv[]) {

  Agent a;
  if (Agent_init(&a) != OKAY) return 0;
  fprintf(stderr, "det2f: STARTUP\n");

  json request = get_message();
  fprintf(stderr, "det2f: RECEIVED: %s\n", request.dump().c_str());

  string type = request[TYPE];
  fprintf(stderr, "det2f: type: %s\n", type.c_str());

  json response;
  string app_id_str, challenge_str, key_handle_str;

  if (type.compare(REG_REQ) == 0) {
    /* Registration. */
    handle_registration(&a, request);
  } else if (type.compare(AUTH_REQ) == 0) {
    /* Authentication. */
    handle_authentication(&a, request);
  } else {
    /* Unknown message type. */
    fprintf(stderr, "det2f ERROR: unrecognized msg type: %s\n", type.c_str());
  }

  Agent_destroy(&a);
  return 0;
}
