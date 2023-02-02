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

#ifndef PROBE_RESPONSE_H
#define PROBE_RESPONSE_H

#include "../80211_packet_common.h"
#include "beacon.h"

void save_probe_response_state();
void load_probe_response_state();

struct packet create_ap_probe_response(struct ether_addr bssid, char adhoc, enum AP_AUTH_TYPE auth_type);
struct packet create_probe_response(struct ether_addr bssid, struct ether_addr dmac, char adhoc, char *ssid,
                                    uint8_t *request_elements, int request_elements_len);

void create_probe_response_fuzzing_ies(struct packet *pkt);

#endif
