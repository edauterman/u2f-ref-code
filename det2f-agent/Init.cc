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

#include "agent.h"
#include "common.h"

using namespace std;

int main(int argc, char *argv[]) {

  Agent a;
  if (Agent_init(&a) != OKAY) {
    printf("No device found. Exiting.\n");
    return 0;
  }

  Initialize_CollabKeygen(&a);
  Agent_destroy(&a);

  printf("Initialization completed. \n");

  return 0;
}
