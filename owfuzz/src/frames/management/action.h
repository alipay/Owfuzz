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

#ifndef ACTION_H
#define ACTION_H

#include "../80211_packet_common.h"

struct action_fixed
{
    uint8_t category_code;
    uint8_t action_code;
} __attribute__((packed));

void save_action_state();
void load_action_state();

struct packet create_action(struct ether_addr bssid, struct ether_addr smac, struct ether_addr dmac, char adhoc, struct packet *recv_pkt);
void create_action_ies(struct packet *pkt);

void handle_action_spectrum(struct packet *pkt, struct packet *recv_pkt);
void handle_action_qos(struct packet *pkt, struct packet *recv_pkt);
void handle_action_dls(struct packet *pkt, struct packet *recv_pkt);
void handle_action_block_ack(struct packet *pkt, struct packet *recv_pkt);
void handle_action_public(struct packet *pkt, struct packet *recv_pkt);
void handle_action_radio_measurement(struct packet *pkt, struct packet *recv_pkt);
void handle_action_ft(struct packet *pkt, struct packet *recv_pkt);
void handle_action_ht(struct packet *pkt, struct packet *recv_pkt);
void handle_action_sa_query(struct packet *pkt, struct packet *recv_pkt);
void handle_action_protected_dual(struct packet *pkt, struct packet *recv_pkt);
void handle_action_wnm(struct packet *pkt, struct packet *recv_pkt);
void handle_action_unprotected_wnm(struct packet *pkt, struct packet *recv_pkt);
void handle_action_tdls(struct packet *pkt, struct packet *recv_pkt);
void handle_action_mesh(struct packet *pkt, struct packet *recv_pkt);
void handle_action_multihop(struct packet *pkt, struct packet *recv_pkt);
void handle_action_self_protected(struct packet *pkt, struct packet *recv_pkt);
void handle_action_dmg(struct packet *pkt, struct packet *recv_pkt);
void handle_action_wmm(struct packet *pkt, struct packet *recv_pkt);
void handle_action_fst(struct packet *pkt, struct packet *recv_pkt);
void handle_action_robust_av_streaming(struct packet *pkt, struct packet *recv_pkt);
void handle_action_unprotected_dmg(struct packet *pkt, struct packet *recv_pkt);
void handle_action_vht(struct packet *pkt, struct packet *recv_pkt);
void handle_action_fils(struct packet *pkt, struct packet *recv_pkt);
void handle_action_vendor_specific_protected(struct packet *pkt, struct packet *recv_pkt);
void handle_action_vendor_specific(struct packet *pkt, struct packet *recv_pkt);

#endif