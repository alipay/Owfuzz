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

struct ieee_hdr
{
  uint8_t type;
  uint8_t flags;
  uint16_t duration;
  struct ether_addr addr1;
  struct ether_addr addr2;
  struct ether_addr addr3;
  uint16_t frag_seq;
} __attribute__((packed));

struct llc_h
{
  uint8_t dsap;
  uint8_t ssap;
  uint8_t ctrl;
} __attribute__((packed));

struct llc_hdr
{
  uint8_t dsap;
  uint8_t ssap;
  uint8_t ctrl;
  uint8_t oui[3];
  uint16_t type;

} __attribute__((packed));

struct ieee8021x_auth
{
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

struct wep_param
{
  uint8_t init_vector[3];
  uint8_t key_index;
} __attribute__((packed));

struct SAE_Commit
{
  uint16_t message_type;
  uint16_t group_id;
  uint8_t scalar[32];
  uint8_t finite_field_element[64];
} __attribute__((packed));

struct SAE_Confirm
{
  uint16_t message_type;
  uint16_t send_confirm;
  uint8_t confirm[32];

} __attribute__((packed));

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

#define MAX_SFS_COUNT 16

struct sniffed_ie
{
  uint8_t id;
  uint8_t ext_id;
  uint8_t len;
  uint8_t value[255];
};

struct sniffed_frame
{
  uint8_t frame_type;
  uint8_t bset;
  int ie_cnt;
  struct sniffed_ie sies[50];
};

struct ie_status
{
  uint8_t type;
  uint8_t enabled;
};

typedef struct _fuzzing_option
{
  struct osdep_instance ois[11];
  unsigned char ois_cnt;

  pthread_t fthread;
  int thread_id;
  char interface[64];
  uint8_t channel;

  char mode[5];
  int fuzz_work_mode;

  uint8_t current_frame;
  uint8_t current_ie;
  uint8_t current_ie_ext;
  uint8_t fuzzing_step;
  uint8_t fuzzing_value_step;

  struct ether_addr source_addr;
  char szsource_addr[50];
  struct ether_addr target_addr;
  char sztarget_addr[50];
  struct ether_addr bssid;
  char szbssid[50];

  // mitm
  volatile uint8_t mitm_state;
  uint8_t mitm_ap_channel;
  struct packet mitm_ap_bcn;
  struct packet real_ap_bcn;

  // p2p
  uint8_t p2p_frame_test;
  uint8_t p2p_status;
  struct ether_addr p2p_source_addr;
  struct ether_addr p2p_target_addr;
  struct ether_addr p2p_bssid;

  struct ether_addr p2p_intened_source_addr;
  struct ether_addr p2p_intened_target_addr;

  int source_group_owner_intent;
  int target_group_owner_intent;

  uint8_t p2p_source_listen_channel;
  uint8_t p2p_source_operating_channel;
  uint8_t p2p_target_listen_channel;
  uint8_t p2p_target_operating_channel;
  uint8_t p2p_operating_channel;

  int p2p_operating_interface_id;

  char target_ssid[33];
  char target_ip[20];
  uint8_t enable_check_alive;
  int ping_sockfd;
  struct sockaddr_in ping_dst_addr;

  enum AP_AUTH_TYPE auth_type;
  enum wpa_states wpa_s;
  uint16_t seq_ctrl;
  uint16_t recv_seq_ctrl;
  uint16_t data_seq_ctrl;
  uint16_t recv_data_seq_ctrl;
  time_t last_recv_pkt_time;
  uint8_t target_alive;

  // uint8_t test_type;
  enum TEST_TYPE test_type;

  uint32_t fuzz_pkt_num;
  uint32_t fuzz_exp_pkt_cnt;
  struct packet fuzz_pkt;

  uint8_t *owfuzz_frames;
  uint32_t owfuzz_frames_cnt;

  int log_level;
  char log_file[256];

  struct sniffed_frame sfs[MAX_SFS_COUNT];
  volatile int cur_sfs_cnt;

  volatile uint8_t sniff_frames;

  struct ie_status ies_status[255];
  struct ie_status ext_ies_status[255];

  unsigned long seed;
} fuzzing_option;

#pragma pack(1)

void print_options(fuzzing_option *fo);

// dsflags: 'a' = AdHoc, Beacon   'f' = From DS   't' = To DS   'w' = WDS (intra DS)
// Set recv to SE_NULLMAC if you don't create WDS packets. (its ignored anyway)
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

uint8_t *get_elemet(struct packet *pkt, uint8_t id);

void generate_random_data(uint8_t *data, uint32_t length, FUZZING_VALUE_TYPE value_type);
void dumphex(uint8_t *data, uint32_t length);
void print_interaction_status(struct ether_addr bssid, struct ether_addr smac, struct ether_addr dmac, char *recv_frame, char *response_frame);

#endif