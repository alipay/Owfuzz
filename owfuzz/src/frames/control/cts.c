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

#include "cts.h"

struct packet create_cts(struct ether_addr bssid, struct ether_addr smac, struct ether_addr dmac)
{
    struct packet pkt = {0};
    struct ieee_hdr *hdr;
    uint8_t rlen = 0;

    hdr = (struct ieee_hdr *)pkt.data;
    hdr->type = IEEE80211_TYPE_CTS;
    hdr->flags = 0x00;
    hdr->duration = htole16(0x013A);
    MAC_COPY(hdr->addr1, dmac);

    pkt.len = 1 + 1 + 2 + 6;

    rlen = random() % (1024 + 1);
    generate_random_data(pkt.data + pkt.len, rlen, VALUE_RANDOM);
    pkt.len += rlen;

    // fuzz_logger_log(FUZZ_LOG_DEBUG, "CTS testing");

    return pkt;
}
