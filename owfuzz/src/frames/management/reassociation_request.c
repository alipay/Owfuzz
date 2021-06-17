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

#include "reassociation_request.h"

extern fuzzing_option fuzzing_opt;

uint8_t reassociation_request_ie_ieee1999[10] = {0, 1, 0};
uint8_t reassociation_request_ie_ieee2007[30] = {0, 1, 50, 33, 36, 48, 46, 221, 0};
uint8_t reassociation_request_ie_ieee2012[80] = {0, 1, 50, 33, 36, 48, 46, 70, 54, 59, 45, 72, 127, 89, 94, 107, 221, 0};
uint8_t reassociation_request_ie_ieee2016[100] = {0, 1, 50, 33, 36, 48, 46, 70, 54, 59, 45, 72, 127, 89, 94, 107, 158, 148, 170, 191, 199, 221, 0};

static FUZZING_VALUE_TYPE fuzzing_value_step = VALUE_ALL_BITS_ZERO;
static FUZZING_TYPE fuzzing_step = NOT_PRESENT;

static int ieee1999 = 0;
static int ieee1999_id = 0;

static int ieee2007 = 0;
static int ieee2007_id = 0;

static int ieee2012 = 0;
static int ieee2012_id = 0;

static int ieee2016 = 0;
static int ieee2016_id = 0;

void save_reassociation_request_state()
{

}

void load_reassociation_request_state()
{
    
}

struct packet create_reassociation_request(struct ether_addr bssid, struct ether_addr smac, struct ether_addr dmac,char adhoc, struct packet *recv_pkt)
{
    struct packet pkt;
    uint16_t *capabilities;
    uint16_t *interval;
    struct ether_addr *ap_addr;

    create_ieee_hdr(&pkt, IEEE80211_TYPE_REASSOCREQ, 'a', 0x013A, dmac, smac, bssid, SE_NULLMAC, 0);

    capabilities = (uint16_t*)(pkt.data + pkt.len);
    interval = (uint16_t*)(pkt.data + pkt.len + 2);
    *capabilities = 0xFFF0;
    *capabilities |= 0x0002; 
    *capabilities |= 0x0010;
    *interval = htole16(0x64);
    pkt.len += 4;

    ap_addr = (struct ether_addr *)(pkt.data + pkt.len);
    memcpy(ap_addr, &fuzzing_opt.target_addr, sizeof(fuzzing_opt.target_addr));
    pkt.len += sizeof(fuzzing_opt.target_addr);

    add_ie_data(&pkt, 0, SPECIFIC_VALUE, fuzzing_opt.target_ssid, strlen(fuzzing_opt.target_ssid));
    add_default_ie_data(&pkt, 1);

    create_frame_fuzzing_ies(&pkt, "Reassociation Request", 
        reassociation_request_ie_ieee1999, 
        reassociation_request_ie_ieee2007, 
        reassociation_request_ie_ieee2012, 
        reassociation_request_ie_ieee2016,
        &ieee1999, 
        &ieee1999_id, 
        &ieee2007, 
        &ieee2007_id, 
        &ieee2012, 
        &ieee2012_id, 
        &ieee2016, 
        &ieee2016_id, 
        &fuzzing_step, 
        &fuzzing_value_step);

    return pkt;
}