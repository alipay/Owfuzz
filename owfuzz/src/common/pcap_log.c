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

#include <string.h>
#include "pcap_log.h"
#include "log.h"

pcap_dumper_t *pcap_fp = NULL;

int open_pcap()
{
    pcap_t *p = NULL;
    char owfuzz_path[256] = {0};
    char *ptr;

    if (readlink("/proc/self/exe", owfuzz_path, sizeof(owfuzz_path)) <= 0)
        return 0;

    ptr = strrchr(owfuzz_path, '/');
    if (!ptr)
        return 0;

    ptr[1] = '\0';
    strcat(owfuzz_path, "poc.pcap");

    p = pcap_open_dead(DLT_IEEE802_11, 0x0000ffff);
    if (NULL == p)
    {
        fuzz_logger_log(FUZZ_LOG_ERR, "pcap_open_dead failed.");
        return 0;
    }

    pcap_fp = pcap_dump_open_append(p, owfuzz_path);
    if (NULL == pcap_fp)
    {
        fuzz_logger_log(FUZZ_LOG_ERR, "pcap_dump_open failed");
        return 0;
    }

    return 1;
}

int write_pcap(unsigned char *pkt, int pkt_len)
{
    struct pcap_pkthdr h;

    if (pcap_fp)
    {
        gettimeofday(&h.ts, NULL);
        h.caplen = pkt_len;
        h.len = pkt_len;

        pcap_dump((uint8_t *)pcap_fp, &h, pkt);
        pcap_dump_flush(pcap_fp);
    }

    return 0;
}

void close_pcap()
{
    if (pcap_fp)
    {
        pcap_dump_close(pcap_fp);
        pcap_fp = NULL;
    }
}
