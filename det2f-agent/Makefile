# Copyright 2014 Google Inc. All rights reserved.
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

all: list CounterTest Test Det2fAgent Init

CC ?= gcc
CXX ?= g++
PKG_CONFIG ?= pkg-config

UNAME := $(shell uname)

ifeq ($(UNAME), Linux)

HIDAPI_PKG:=hidapi-hidraw
HIDAPI_LDLIBS:=$(shell $(PKG_CONFIG) --libs $(HIDAPI_PKG))
ifeq ($(HIDAPI_LDLIBS),)
# Use local source code
HIDAPI:=hid.o
HIDAPI_CPPFLAGS:=-Ihidapi/hidapi
hid.o: hidapi/linux/hid.c
	$(CC) -c $(CPPFLAGS) $(CFLAGS) -o hid.o hidapi/linux/hid.c

else
# Use hidapi library
HIDAPI:=
HIDAPI_CPPFLAGS:=$(shell $(PKG_CONFIG) --cflags-only-I $(HIDAPI_PKG))
endif # hidapi library

CPPFLAGS+=$(HIDAPI_CPPFLAGS) -D__OS_LINUX
LDLIBS+=-lrt -ludev $(HIDAPI_LDLIBS)
endif  # Linux

ifeq ($(UNAME), Darwin)

CPPFLAGS+=-Ihidapi/hidapi -D__OS_MAC
LDLIBS+=-framework IOKit -framework CoreFoundation
HIDAPI=hid.o
hid.o: hidapi/mac/hid.c
	$(CC) -c $(CPPFLAGS) $(CFLAGS) -o hid.o hidapi/mac/hid.c

endif  # Darwin

# utility tools.
u2f_util.o: u2f_util.cc u2f_util.h u2f.h u2f_hid.h
	$(CXX) -c $(CPPFLAGS) $(CFLAGS) -Wall -o u2f_util.o u2f_util.cc

# crypto for det2f
params.o: params.c params.h common.h
	$(CC) -c $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -Wall -o params.o params.c -lssl -lcrypto

ddh.o: ddh.c ddh.h
	$(CC) -c $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -Wall -o ddh.o ddh.c -lssl -lcrypto

pedersen_proof.o: pedersen_proof.c pedersen_proof.h
	$(CC) -c $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -Wall -o pedersen_proof.o pedersen_proof.c -lssl -lcrypto

sanitizable_ecdsa.o: sanitizable_ecdsa.c sanitizable_ecdsa.h
	$(CC) -c $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -Wall -o sanitizable_ecdsa.o sanitizable_ecdsa.c -lssl -lcrypto

vif.o: vif.c vif.h
	$(CC) -c $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -Wall -o vif.o vif.c -lssl -lcrypto

vrf.o: vrf.c vrf.h
	$(CC) -c $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -Wall -o vrf.o vrf.c -lssl -lcrypto

# signature parsing
sig_parse.o: sig_parse.c sig_parse.h
	$(CC) -c $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -Wall -o sig_parse.o sig_parse.c -lssl -lcrypto

asn1.o: asn1.c asn1.h
	$(CXX) -c $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -Wall -o asn1.o asn1.c -lssl -lcrypto

x509.o: x509.c x509.h
	$(CXX) -c $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -Wall -o x509.o x509.c -lssl -lcrypto

base64.o: base64.c base64.h
	$(CXX) -c $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -Wall -o base64.o base64.c -lssl -lcrypto

counter.o: counter.c counter.h
	$(CXX) -c $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -Wall -o counter.o counter.c -lssl -lcrypto

agent.o: agent.cc agent.h $(HIDAPI)
	$(CXX) -c $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -Wall -o agent.o agent.cc -lssl -lcrypto

# simple hidapi tool to list devices to see paths.
list: list.c $(HIDAPI)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -Wall -o $@ $^ $(LDLIBS)

# Test counter
CounterTest: CounterTest.cc counter.o $(HIDAPI)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(LDFLAGS) -Wall -o $@ $^ $(LDLIBS) -lssl -lcrypto

Test: Test.cc agent.o u2f_util.o params.o ddh.o vrf.o vif.o pedersen_proof.o sig_parse.o sanitizable_ecdsa.o x509.o asn1.o counter.o $(HIDAPI)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(LDFLAGS) -Wall -o $@ $^ $(LDLIBS) -lssl -lcrypto

Init: Init.cc agent.o base64.o u2f_util.o params.o ddh.o vrf.o vif.o pedersen_proof.o sig_parse.o sanitizable_ecdsa.o x509.o asn1.o counter.o $(HIDAPI)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(LDFLAGS) -Wall -o $@ $^ $(LDLIBS) -lssl -lcrypto

# interface to extension
Det2fAgent: Det2fAgent.cc agent.o base64.o u2f_util.o params.o ddh.o vrf.o vif.o pedersen_proof.o sig_parse.o sanitizable_ecdsa.o x509.o asn1.o counter.o $(HIDAPI)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(LDFLAGS) -Wall -o $@ $^ $(LDLIBS) -lssl -lcrypto
