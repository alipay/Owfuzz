/**************************************************************************
* Copyright (C) 2020-2021 by Hongjian Cao <haimohk@gmail.com>
* *
* This file is part of owfuzz.
* *
* Owfuzz is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
* *
* Owfuzz is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
* *
* You should have received a copy of the GNU General Public License
* along with owfuzz.  If not, see <https://www.gnu.org/licenses/>.
****************************************************************************/

#ifndef IEEE80211_PACKET_COMMON_H
#define IEEE80211_PACKET_COMMON_H

#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <inttypes.h>
#include "ieee80211_def.h"
#include "../common/include.h"
#include "../common/log.h"
#include "../common/mac_addr.h"
#include "./management/ieee80211_ie.h"
#include "osdep_wifi_transmit.h"

struct ieee_hdr {
  uint8_t type;
  uint8_t flags;
  uint16_t duration;
  struct ether_addr addr1;
  struct ether_addr addr2;
  struct ether_addr addr3;
  uint16_t frag_seq;
} __attribute__((packed));


struct llc_hdr{
  uint8_t dsap;
  uint8_t ssap;
  uint8_t ctrl;
  uint8_t oui[3];
  uint16_t type;

}__attribute__((packed));


struct ieee8021x_auth {
  uint8_t version;
  uint8_t type;
  uint16_t length;
  uint8_t descriptor;
  uint16_t key_info;
  uint16_t key_length;
  uint64_t replay_counter;
  uint8_t nonce[32];
  uint8_t key_iv[16];
  uint64_t key_rsc;
  uint64_t key_id;
  uint8_t key_mic[16];
  uint16_t wpa_length;
} __attribute__((packed));

struct wep_param{
  uint8_t init_vector[3];
  uint8_t key_index;
}__attribute__((packed));

struct SAE_Commit{
  uint16_t message_type;
  uint16_t group_id;
  uint8_t scalar[32];
  uint8_t finite_field_element[64]; 
}__attribute__((packed));

struct SAE_Confirm{
  uint16_t message_type;
  uint16_t send_confirm;
  uint8_t confirm[32];

}__attribute__((packed));


#pragma pack(1)
// all bits 1
struct ieee2012_ie_extended_capabilities
{
    uint16_t ec_16;
    uint16_t ec_32;
    uint16_t ec_48;
};

struct ieee2016_ie_extended_capabilities
{
    uint16_t ec_16;
    uint16_t ec_32;
    uint16_t ec_48;
    uint16_t ec_64;
    uint16_t ec_80;
};

#pragma pack(1)



//dsflags: 'a' = AdHoc, Beacon   'f' = From DS   't' = To DS   'w' = WDS (intra DS)
//Set recv to SE_NULLMAC if you don't create WDS packets. (its ignored anyway)
void create_ieee_hdr(struct packet *pkt, uint8_t type, char dsflags, uint16_t duration, struct ether_addr destination, struct ether_addr source, struct ether_addr bssid_or_transm, struct ether_addr recv, uint8_t fragment);

void increase_seqno(struct packet *pkt);

uint16_t get_seqno(struct packet *pkt);

uint8_t get_fragno(struct packet *pkt);

uint16_t get_next_seqno();

void set_seqno(struct packet *pkt, uint16_t seq);

void set_fragno(struct packet *pkt, uint8_t frag, int last_frag);

struct ether_addr *get_addr(struct packet *pkt, char type); 

struct ether_addr *get_bssid(struct packet *pkt);

struct ether_addr *get_source(struct packet *pkt);

struct ether_addr *get_destination(struct packet *pkt);

struct ether_addr *get_transmitter(struct packet *pkt);

struct ether_addr *get_receiver(struct packet *pkt);

unsigned long long ntohll(unsigned long long val);

unsigned long long htonll(unsigned long long val);

void generate_random_data(uint8_t *data, uint32_t length, FUZZING_VALUE_TYPE value_type);
void dumphex(uint8_t *data, uint32_t length);
void print_interaction_status(struct ether_addr bssid, struct ether_addr smac, struct ether_addr dmac,char *recv_frame, char *response_frame);

#endif