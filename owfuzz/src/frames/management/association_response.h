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

#ifndef ASSOCIAtION_RESPONSE_H
#define ASSOCIAtION_RESPONSE_H

#include "../80211_packet_common.h"

struct association_response_fixed
{
  uint16_t capabilities;
  uint16_t status_code;
  uint16_t aid;
} __attribute__((packed));

struct association_response_body
{
  struct association_response_fixed arf;
  uint8_t *ies_buffer;

} __attribute__((packed));

void save_association_response_state();
void load_association_response_state();

struct packet create_association_response(struct ether_addr bssid, struct ether_addr smac, struct ether_addr dmac, char adhoc, struct packet *recv_pkt);
struct packet create_ap_association_response(struct ether_addr bssid, struct ether_addr smac, struct ether_addr dmac, char adhoc);

#endif