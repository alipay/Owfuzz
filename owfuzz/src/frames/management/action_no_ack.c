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

#include "action_no_ack.h"
#include "action.h"

void save_action_no_ack_state()
{
}

void load_action_no_ack_state()
{
}

struct packet create_action_no_ack(struct ether_addr bssid, struct ether_addr smac, struct ether_addr dmac, char adhoc, struct packet *recv_pkt)
{
    struct ieee_hdr *hdr = NULL;
    struct packet pkt = {0};

    pkt = create_action(bssid, smac, dmac, 0, recv_pkt);
    hdr = (struct ieee_hdr *)pkt.data;
    hdr->type = IEEE80211_TYPE_ACTIONNOACK;

    return pkt;
}
