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

#include "disassociation.h"
#include "ies_creator.h"

void save_disassociation_state()
{
}

void load_disassociation_state()
{
}

struct packet create_disassociation(struct ether_addr bssid, struct ether_addr smac, struct ether_addr dmac, char adhoc, struct packet *recv_pkt)
{
    struct packet disassociation = {0};
    struct disassociation_fixed *df;
    uint8_t rlen;

    create_ieee_hdr(&disassociation, IEEE80211_TYPE_DISASSOC, 'a', 0x013A, dmac, bssid, bssid, SE_NULLMAC, 0);

    df = (struct disassociation_fixed *)(disassociation.data + disassociation.len);

    df->reason_code = 1;

    disassociation.len += sizeof(struct disassociation_fixed);

    rlen = random() % (0xff + 1);
    memset(disassociation.data + disassociation.len, random() % (0xff + 1), rlen);
    disassociation.len += rlen;

    // fuzz_logger_log(FUZZ_LOG_DEBUG, "disassociation testing ==> ...");

    return disassociation;
}

void create_disassociation_ies(struct packet *pkt)
{
}
