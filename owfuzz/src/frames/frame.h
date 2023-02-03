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

#ifndef FRAME_H
#define FRAME_H

#include "../common/include.h"
#include "common/ieee802_11_defs.h"

// management
#include "management/action.h"
#include "management/action_no_ack.h"
#include "management/association_request.h"
#include "management/association_response.h"
#include "management/atim.h"
#include "management/authentication.h"
#include "management/beacon.h"
#include "management/deauthentication.h"
#include "management/disassociation.h"
#include "management/probe_request.h"
#include "management/probe_response.h"
#include "management/reassociation_request.h"
#include "management/reassociation_response.h"
#include "management/timing_advertisement.h"
#include "management/atim.h"

// control
#include "control/acknowledgement.h"
#include "control/beamforming_report_poll.h"
#include "control/block_ack_request.h"
#include "control/block_ack.h"
#include "control/cf_end_cf_ack.h"
#include "control/cf_end.h"
#include "control/control_frame_extension.h"
#include "control/control_wrapper.h"
#include "control/cts.h"
#include "control/ps_poll.h"
#include "control/rts.h"
#include "control/vht_ndp_announcement.h"

// data
#include "data/d_cf_ack.h"
#include "data/d_cf_poll.h"
#include "data/d_cf_ack_poll.h"
#include "data/data.h"
#include "data/data_null.h"
#include "data/data_cf_ack.h"
#include "data/data_cf_poll.h"
#include "data/data_cf_ack_poll.h"
#include "data/qos_data.h"
#include "data/qos_null.h"
#include "data/qos_cf_ack.h"
#include "data/qos_cf_poll.h"
#include "data/qos_cf_ack_poll.h"
#include "data/qos_data_cf_ack.h"
#include "data/qos_data_cf_poll.h"
#include "data/qos_data_cf_ack_poll.h"

struct packet get_frame(uint8_t frame_type, struct ether_addr bssid, struct ether_addr smac, struct ether_addr dmac, struct packet *recv_pkt);
struct packet get_default_frame(uint8_t frame_type, struct ether_addr bssid, struct ether_addr smac, struct ether_addr dmac, struct packet *recv_pkt);

int init_ping_sock();
int check_alive_by_ping();
int check_alive_by_deauth(struct packet *pkt);
int check_alive_by_disassoc(struct packet *pkt);
int check_alive_by_pkts(struct ether_addr smac);

void hex_to_ascii(unsigned char *phex, unsigned char *pascii, unsigned int len);
void hex_to_ascii_hex(unsigned char *phex, char *pascii, unsigned int len);
int str_to_hex(char *pascii, unsigned char *phex, unsigned int len);
void log_pkt(int log_level, struct packet *pkt);
void save_fuzzing_state();
void load_fuzzing_state();

#endif