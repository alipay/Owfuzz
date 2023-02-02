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

#include "deauthentication.h"
#include "ies_creator.h"

void save_deauthentication_state()
{
}

void load_deauthentication_state()
{
}

struct packet create_deauthentication(struct ether_addr bssid, struct ether_addr smac, struct ether_addr dmac, char adhoc, struct packet *recv_pkt)
{
    struct packet deauthentication = {0};
    struct deauthentication_fixed *df;
    uint8_t rlen;

    create_ieee_hdr(&deauthentication, IEEE80211_TYPE_DEAUTH, 'a', 0x013A, dmac, bssid, bssid, SE_NULLMAC, 0);

    df = (struct deauthentication_fixed *)(deauthentication.data + deauthentication.len);

    df->reason_code = 1;

    deauthentication.len += sizeof(struct deauthentication_fixed);

    rlen = random() % (0xff + 1);
    memset(deauthentication.data + deauthentication.len, random() % (0xff + 1), rlen);
    deauthentication.len += rlen;

    // fuzz_logger_log(FUZZ_LOG_INFO, "deauthentication testing ==> ...");

    return deauthentication;
}

void create_deauthentication_ies(struct packet *pkt)
{
}
