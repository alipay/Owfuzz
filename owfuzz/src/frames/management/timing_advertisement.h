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

#ifndef TIMING_ADVERTISEMENT_H
#define TIMING_ADVERTISEMENT_H

#include "../80211_packet_common.h"

struct timing_advertisement_fixed
{
    uint64_t timestamp;
    uint16_t capabilities;
} __attribute__((packed));

struct timing_advertisement_body
{
    struct timing_advertisement_fixed taf;
    uint8_t *ies_buffer;

} __attribute__((packed));

void save_timing_advertisement_state();
void load_timing_advertisement_state();

struct packet create_timing_advertisement(struct ether_addr bssid, struct ether_addr dmac, char adhoc);

#endif
