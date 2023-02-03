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

#include "atim.h"

void save_atim_state()
{
}

void load_atim_state()
{
}

struct packet create_atim(struct ether_addr bssid, struct ether_addr smac, struct ether_addr dmac, char adhoc, struct packet *recv_pkt)
{
    struct packet pkt = {0};
    uint8_t rlen = 0;

    create_ieee_hdr(&pkt, IEEE80211_TYPE_ATIM, 'a', 0x013A, dmac, smac, bssid, SE_NULLMAC, 0);

    rlen = random() % (0xff + 1);
    memset(pkt.data + pkt.len, random() % (0xff + 1), rlen);
    pkt.len += rlen;

    return pkt;
}
