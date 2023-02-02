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

#include "qos_cf_ack_poll.h"

extern fuzzing_option fuzzing_opt;

struct packet create_qos_cf_ack_poll(struct ether_addr bssid, struct ether_addr smac, struct ether_addr dmac, char adhoc, struct packet *recv_pkt)
{
    struct packet pkt = {0};
    uint8_t rlen = 0;
    char dsflag = 'a';

    if (fuzzing_opt.fuzz_work_mode == FUZZ_WORK_MODE_AP)
        dsflag = 'f';
    else if (fuzzing_opt.fuzz_work_mode == FUZZ_WORK_MODE_STA)
        dsflag = 't';

    create_ieee_hdr(&pkt, IEEE80211_TYPE_QOSCFACKPOLL, dsflag, 0x013A, dmac, smac, bssid, SE_NULLMAC, 0);

    rlen = random() % (1024 + 1);
    generate_random_data(pkt.data + pkt.len, rlen, VALUE_RANDOM);
    pkt.len += rlen;

    return pkt;
}
