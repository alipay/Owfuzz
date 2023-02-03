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

#ifndef BEACON_H
#define BEACON_H

#include "../80211_packet_common.h"

#define DEFAULT_BEACON_INTERVAL 0x64

struct beacon_fixed
{
  uint64_t timestamp;
  uint16_t interval;
  uint16_t capabilities;
} __attribute__((packed));

struct beacon_body
{
  struct beacon_fixed bf;
  uint8_t *ies_buffer;

} __attribute__((packed));

// encryption: 'n' = None   'w' = WEP   't' = TKIP (WPA)   'a' = AES (WPA2)  'x' WPA3
// If bitrate is 54, you'll get an bg network, b only otherwise
// struct packet create_beacon(struct ether_addr bssid, char *ssid, uint8_t channel, char encryption, unsigned char bitrate, char adhoc);
void save_beacon_state();
void load_beacon_state();

struct packet create_beacon(struct ether_addr bssid, char adhoc, char *ssid);
struct packet create_ap_beacon(struct ether_addr bssid, char adhoc, enum AP_AUTH_TYPE auth_type);
void create_beacon_fuzzing_ies(struct packet *pkt);

#endif
