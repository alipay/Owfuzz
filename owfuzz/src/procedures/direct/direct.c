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

#include "direct.h"
#include "../../linux_wifi/control/kismet_wifi_control.h"
#include "../../fuzz_control.h"
#include "../../frames/frame.h"
#include "../../frames/management/ies_creator.h"

#define P2P_BEACON_SSID "DIRECT-owf-fuzzing"

#define VENDOR_SPECIFIC_P2P (uint8_t *)"\x50\x6f\x9a\x09\x02\x02\x00\x25\x00\x0d\x1b\x00\x66\xf6\x5c\x49\x1e\xb4\x01\x88\x00\x0a\x00\x50\xf2\x04\x00\x05\x00\x10\x11\x00\x06\x4e\x45\x58\x20\x33\x54"
#define VENDOR_SPECIFIC_P2P_LEN 39

extern fuzzing_option fuzzing_opt;

static FUZZING_TYPE g_fuzzing_type = ALL_BITS_ZERO;
static FUZZING_VALUE_TYPE g_value_type = VALUE_ALL_BITS_ZERO;

static int p2p_attribute_range[30][3] = {
    {0, 1, 1},
    {1, 1, 1},
    {2, 2, 2},
    {3, 6, 6},
    {4, 1, 1},
    {5, 2, 2},
    {6, 5, 5},
    {7, 6, 6},
    {8, 4, 4},
    {9, 6, 6},
    {10, 1, 1},
    {11, 1, 254},
    {12, 1, 254},
    {13, 1, 254},
    {14, 1, 254},
    {15, 6, 38},
    {16, 1, 254},
    {17, 5, 5},
    {18, 1, 1},
    {19, 6, 6},
    {21, 1, 254},
    {22, 1, 254},
    {23, 1, 1},
    {24, 10, 10},
    {25, 1, 254},
    {26, 10, 10},
    {27, 1, 254},
    {28, 1, 254},
    {-1, 0, 0}};

uint8_t p2p_beacon_p2p_ie_att[30] = {2, 3, 12, 0};
uint8_t p2p_probe_request_p2p_ie_att[30] = {2, 3, 6, 8, 13, 17, 21, 0}; // wsc
uint8_t p2p_probe_response_p2p_ie_att[30] = {2, 8, 12, 13, 14, 25, 0};
uint8_t p2p_association_request_p2p_ie_att[30] = {2, 8, 13, 16, 0};
uint8_t p2p_association_response_p2p_ie_att[30] = {0, 8, 0};
uint8_t p2p_deauthentication_p2p_ie_att[30] = {1, 0};
uint8_t p2p_disassociation_p2p_ie_att[30] = {1, 0};
uint8_t p2p_action_go_negotiation_request_p2p_ie_att[30] = {2, 4, 5, 6, 8, 9, 11, 13, 17, 0};   // wsc
uint8_t p2p_action_go_negotiation_response_p2p_ie_att[30] = {0, 2, 4, 5, 17, 9, 11, 13, 15, 0}; // wsc
uint8_t p2p_action_go_negotiation_confirmation_p2p_ie_att[30] = {0, 2, 17, 11, 15, 0};
uint8_t p2p_action_invitation_request_p2p_ie_att[30] = {0, 5, 18, 17, 7, 11, 15, 13, 0}; // wsc
uint8_t p2p_action_invitation_response_p2p_ie_att[30] = {0, 5, 17, 7, 11, 0};
uint8_t p2p_action_device_discoverability_request_p2p_ie_att[30] = {3, 15, 0};
uint8_t p2p_action_device_discoverability_response_p2p_ie_att[30] = {0, 0};
uint8_t p2p_action_provision_discovery_request_p2p_ie_att[30] = {2, 13, 15, 9, 0, 17, 11, 22, 23, 24, 5, 6, 26, 27, 28, 0};
uint8_t p2p_action_provision_discovery_response_p2p_ie_att[30] = {0, 2, 13, 15, 9, 17, 11, 23, 24, 5, 26, 27, 28, 22, 0};
uint8_t p2p_fst_action_p2p_ie_att[30] = {2, 0};

char p2p_action_hdr[6] = {0x04, 0x09, 0x50, 0x6F, 0x9A, 0x09};
char p2p_oui[3] = {0x50, 0x6F, 0x9A};

static int g_aid = 0x0001;

struct ie_data get_p2p_attribute_by_fuzzing_type(uint8_t id,
                                                 FUZZING_TYPE fuzzing_type,
                                                 FUZZING_VALUE_TYPE value_type,
                                                 uint8_t *specific_data,
                                                 int specific_data_len)
{
    struct ie_data ie_d = {0};
    struct attribute_tlv att = {0};
    uint8_t max_len, min_len;
    static int swch = 1;
    int rlen = 0;

    att.type = id;

    min_len = p2p_attribute_range[id][1];
    max_len = p2p_attribute_range[id][2];

    switch (fuzzing_type)
    {
    case NOT_PRESENT:
        break;
    case REPEATED:
        break;
    case ALL_BITS_ZERO:
        att.length = 0x00;
        break;
    case MIN_SUB_1:
        if (min_len > 0)
            att.length = min_len - 1;
        else
            att.length = min_len;
        break;
    case MIN:
        att.length = min_len;
        break;
    case MIN_ADD_1:
        att.length = min_len + 1;
        break;
    case RANDOM_VALUE:
        if (0 == fuzzing_opt.seed)
            srandom(time(NULL) + swch);

        att.length = min_len + (random() % (max_len - min_len + 1));
        break;
    case SPECIFIC_VALUE:
        att.length = specific_data_len;
        break;
    case MAX_SUB_1:
        if (max_len > 0)
            att.length = max_len - 1;
        else
            att.length = max_len;
        break;
    case MAX:
        att.length = max_len;
        break;
    case MAX_ADD_1:
        if (max_len < 248)
            att.length = max_len + 1;
        else
            att.length = max_len;
        break;
    case ALL_BITS_ONE:
        att.length = 0xFF - 3 - 4;
        break;
    default:
        break;
    }

    swch++;
    if (swch >= 5)
        swch = 1;

    if (fuzzing_type != RANDOM_VALUE)
    {
        if (0 == fuzzing_opt.seed)
            srandom(time(NULL));

        rlen = random() % 256;
        generate_random_data(att.value, rlen, value_type);
    }
    else
        generate_random_data(att.value, att.length, value_type);

    ie_d.length = 1 + 2 + att.length;
    memcpy(ie_d.data, &att.type, 1);
    memcpy(ie_d.data + 1, &att.length, 2);
    if (fuzzing_type == SPECIFIC_VALUE)
    {
        memcpy(ie_d.data + 3, specific_data, att.length);
    }
    else
    {
        if (fuzzing_type == RANDOM_VALUE)
            memcpy(ie_d.data + 3, att.value, rlen);
        else
            memcpy(ie_d.data + 3, att.value, att.length);
    }

    fuzz_logger_log(FUZZ_LOG_DEBUG, "get_p2p_attribute_by_fuzzing_type -> id: %d, iedata.length = %d, fuzzing_type: %d, fuzzing_value_type: %d", id, ie_d.length, fuzzing_type, value_type);

    return ie_d;
}

struct ie_data create_frame_p2p_fuzzing_attribute(struct packet *pkt, char *frame_name, uint8_t attr_id)
{
    struct ie_data iedata = {0};

    iedata = get_p2p_attribute_by_fuzzing_type(attr_id, g_fuzzing_type, g_value_type, NULL, 0);

    if (g_fuzzing_type + 1 == SPECIFIC_VALUE)
        g_fuzzing_type = ALL_BITS_ZERO;
    else
        g_fuzzing_type++;

    if (g_value_type == FUZZING_VALUE_END)
        g_value_type = VALUE_ALL_BITS_ZERO;
    else
        g_value_type++;

    return iedata;
}

void p2p_ie_fuzzing(struct packet *pkt, char *frame_name, uint8_t p2p_attrs[])
{
    uint8_t attr_id = 0;
    struct p2p_ie p2pie = {0};
    struct ie_data attrdata;

    // P2P fuzzing
    p2pie.id = 0xDD;
    p2pie.length = 4;
    p2pie.oui[0] = 0x00;
    p2pie.oui[1] = 0x50;
    p2pie.oui[2] = 0xF2;
    p2pie.oui_type = 0x04;

    /*p = pkt->data + pkt->len;
    memcpy(pkt->data + pkt->len, &p2pie, sizeof(p2pie));
    pkt->len += sizeof(p2pie);

    if (0 == fuzzing_opt.seed) srandom(time(NULL));
    add_attribute_tlv_fuzzing_data(pkt, p, p2p_attrs[random() % sizeof(p2p_attrs)/sizeof(p2p_attrs[0])]);*/

    while (!(p2p_attrs[attr_id] == 0 && attr_id != 0))
    {
        p2pie.length = 4;
        memset(&attrdata, 0, sizeof(attrdata));
        attrdata = create_frame_p2p_fuzzing_attribute(NULL, frame_name, p2p_attrs[attr_id]);
        p2pie.length += attrdata.length;
        memcpy(pkt->data + pkt->len, &p2pie, sizeof(p2pie));
        pkt->len += sizeof(p2pie);

        memcpy(pkt->data + pkt->len, attrdata.data, attrdata.length);
        pkt->len += attrdata.length;

        attr_id++;
    }

    fuzz_logger_log(FUZZ_LOG_DEBUG, "%s p2p ie attribute fuzzing", frame_name);
}

void wps_ie_fuzzing(struct packet *pkt, char *frame_name)
{
    struct wps_ie wpsie = {0};
    unsigned char *p = NULL;

    uint16_t data_element_type[] = {WPS_VERSION, WPS_REQUEST_TYPE, WPS_CONFIG_METHODS, WPS_UUID_E, WPS_PRIMARY_DEVICE_TYPE, WPS_RF_BANDS,
                                    WPS_ASSOCIATION_STATE, WPS_CONFIGURATION_ERROR, WPS_DEVICE_PASSWORD_ID, WPS_MANUFACTURER, WPS_MODEL_NAME, WPS_MODEL_NUMBER, WPS_DEVICE_NAME, WPS_VENDOR_EXTENSION};

    wpsie.id = 0xDD;
    wpsie.length = 4;
    wpsie.oui[0] = 0x50;
    wpsie.oui[1] = 0x6F;
    wpsie.oui[2] = 0x9A;
    wpsie.oui_type = 0x09;

    p = pkt->data + pkt->len;
    memcpy(pkt->data + pkt->len, &wpsie, sizeof(wpsie));
    pkt->len += sizeof(wpsie);

    if (0 == fuzzing_opt.seed)
        srandom(time(NULL));

    add_data_element_tlv_fuzzing_data(pkt, (struct vendor_specific_ie *)p, data_element_type[random() % (sizeof(data_element_type) / sizeof(data_element_type[0]))]);

    /*for(i=0; i< sizeof(data_element_type)/sizeof(data_element_type[0]); i++)
    {
        p = pkt->data + pkt->len;
        memcpy(pkt->data + pkt->len, &wpsie, sizeof(wpsie));
        pkt->len += sizeof(wpsie);
        add_data_element_tlv_fuzzing_data(pkt, p, data_element_type[i]);
    }*/

    fuzz_logger_log(FUZZ_LOG_DEBUG, "%s wps ie data element fuzzing", frame_name);
}

struct packet create_p2p_beacon(struct ether_addr bssid, struct ether_addr smac, struct ether_addr dmac, char adhoc, struct packet *recv_pkt)
{
    struct packet beacon = {0};
    struct beacon_fixed *bf;
    static uint64_t internal_timestamp = 0;
    uint8_t *ie_data;
    uint8_t ie_len;
    uint8_t ie_id;

    create_ieee_hdr(&beacon, IEEE80211_TYPE_BEACON, 'a', 0, dmac, smac, bssid, SE_NULLMAC, 0);

    bf = (struct beacon_fixed *)(beacon.data + beacon.len);

    internal_timestamp += 0x400 * DEFAULT_BEACON_INTERVAL;
    bf->timestamp = htole64(internal_timestamp);
    bf->interval = htole16(DEFAULT_BEACON_INTERVAL);
    if (0 == fuzzing_opt.seed)
        srandom(time(NULL));

    bf->capabilities = random() % 0xffff;
    if (adhoc)
    {
        bf->capabilities |= 0x0002;
    }
    else
    {
        bf->capabilities |= 0x0001;
    }

    bf->capabilities |= 0x0010;

    beacon.len += sizeof(struct beacon_fixed);

    add_ie_data(&beacon, 0, SPECIFIC_VALUE, (uint8_t *)P2P_BEACON_SSID, strlen(P2P_BEACON_SSID));

    if (fuzzing_opt.channel <= 14)
    {
        ie_data = (uint8_t *)IE_1_SUPPORTTED_RATES_B;
        ie_id = ie_data[0];
        ie_len = ie_data[1];
        add_ie_data(&beacon, ie_id, SPECIFIC_VALUE, ie_data + 2, ie_len);
    }
    else
    {
        ie_data = (uint8_t *)IE_1_SUPPORTTED_RATES_N_AC;
        ie_id = ie_data[0];
        ie_len = ie_data[1];
        add_ie_data(&beacon, ie_id, SPECIFIC_VALUE, ie_data + 2, ie_len);
    }

    add_default_ie_data(&beacon, 5);

    if (fuzzing_opt.channel <= 14)
    {
        add_ie_data(&beacon, 3, SPECIFIC_VALUE, &fuzzing_opt.channel, 1);
    }
    else
    {
        add_default_ie_data(&beacon, 45);
        ie_data = (uint8_t *)malloc(strlen(IE_61_HT_INFORMATION));
        if (ie_data)
        {
            memcpy(ie_data, IE_61_HT_INFORMATION, strlen(IE_61_HT_INFORMATION));
            ie_data[2] = fuzzing_opt.channel;
            ie_id = ie_data[0];
            ie_len = ie_data[1];
            add_ie_data(&beacon, ie_id, SPECIFIC_VALUE, ie_data + 2, ie_len);
            free(ie_data);
        }
    }

    // P2P fuzzing
    p2p_ie_fuzzing(&beacon, "p2p_beacon", p2p_beacon_p2p_ie_att);
    wps_ie_fuzzing(&beacon, "p2p_beacon");

    //
    create_beacon_fuzzing_ies(&beacon);

    return beacon;
}

struct packet create_p2p_association_request(struct ether_addr bssid, struct ether_addr smac, struct ether_addr dmac, char adhoc, struct packet *recv_pkt)
{
    struct packet pkt = {0};
    uint16_t *capabilities;
    uint16_t *interval;
    uint8_t *ie_data;
    uint8_t ie_len;
    uint8_t ie_id;

    create_ieee_hdr(&pkt, IEEE80211_TYPE_ASSOCREQ, 'a', 0, dmac, smac, bssid, SE_NULLMAC, 0);
    capabilities = (uint16_t *)(pkt.data + pkt.len);
    interval = (uint16_t *)(pkt.data + pkt.len + 2);

    *capabilities = 0xFFF0;
    *capabilities |= 0x0002;
    *capabilities |= 0x0010;

    *interval = htole16(0x64);

    pkt.len += 4;

    add_ie_data(&pkt, 0, SPECIFIC_VALUE, (uint8_t *)fuzzing_opt.target_ssid, strlen(fuzzing_opt.target_ssid));
    // add_default_ie_data(&pkt, 1);

    if (fuzzing_opt.channel <= 14)
    {
        ie_data = (uint8_t *)IE_1_SUPPORTTED_RATES_B;
        ie_id = ie_data[0];
        ie_len = ie_data[1];
        add_ie_data(&pkt, ie_id, SPECIFIC_VALUE, ie_data + 2, ie_len);

        add_default_ie_data(&pkt, 45);
    }
    else
    {
        ie_data = (uint8_t *)IE_1_SUPPORTTED_RATES_N_AC;
        ie_id = ie_data[0];
        ie_len = ie_data[1];
        add_ie_data(&pkt, ie_id, SPECIFIC_VALUE, ie_data + 2, ie_len);

        add_default_ie_data(&pkt, 45);
        ie_data = (uint8_t *)malloc(strlen(IE_61_HT_INFORMATION));
        if (ie_data)
        {
            memcpy(ie_data, IE_61_HT_INFORMATION, strlen(IE_61_HT_INFORMATION));
            ie_data[2] = fuzzing_opt.channel;
            ie_id = ie_data[0];
            ie_len = ie_data[1];
            add_ie_data(&pkt, ie_id, SPECIFIC_VALUE, ie_data + 2, ie_len);
            free(ie_data);
        }
    }

    add_default_ie_data(&pkt, 50);

    if (fuzzing_opt.auth_type == WPA3)
    {
        add_default_ie_data(&pkt, 32);
        ie_data = (uint8_t *)IE_48_RSN_WPA3_AES_ASSOCREQ;
        ie_id = ie_data[0];
        ie_len = ie_data[1];
        add_ie_data(&pkt, ie_id, SPECIFIC_VALUE, ie_data + 2, ie_len);
        add_default_ie_data(&pkt, 127);
    }
    else if (fuzzing_opt.auth_type == WPA2_PSK_TKIP_AES || fuzzing_opt.auth_type == WPA2_PSK_AES || fuzzing_opt.auth_type == WPA2_PSK_TKIP ||
             fuzzing_opt.auth_type == WPA_PSK_TKIP_AES || fuzzing_opt.auth_type == WPA_PSK_AES || fuzzing_opt.auth_type == WPA_PSK_TKIP)
    {
        add_default_ie_data(&pkt, 32);
    }
    else if (fuzzing_opt.auth_type == SHARE_WEP)
    {
    }
    else if (fuzzing_opt.auth_type == OPEN_WEP || fuzzing_opt.auth_type == OPEN_NONE)
    {
    }

    p2p_ie_fuzzing(&pkt, "p2p_association_request", p2p_association_request_p2p_ie_att);
    wps_ie_fuzzing(&pkt, "p2p_association_request");

    return pkt;
}

struct packet create_p2p_association_response(struct ether_addr bssid, struct ether_addr smac, struct ether_addr dmac, char adhoc, struct packet *recv_pkt)
{
    struct packet pkt = {0};
    struct association_response_fixed *arf;

    create_ieee_hdr(&pkt, IEEE80211_TYPE_ASSOCRES, 'a', 0, dmac, smac, bssid, SE_NULLMAC, 0);
    arf = (struct association_response_fixed *)(pkt.data + pkt.len);

    arf->capabilities = 0x0000;
    if (adhoc)
    {
        arf->capabilities |= 0x0002;
    }
    else
    {
        arf->capabilities |= 0x0001;
    }

    if (fuzzing_opt.auth_type > OPEN_NONE)
        arf->capabilities |= 0x0010;

    arf->capabilities |= 0x0400;
    arf->capabilities |= 0x0100;
    arf->capabilities |= 0x8000;
    arf->status_code = 0x0000;
    arf->aid = g_aid++;

    pkt.len += sizeof(struct association_response_fixed);

    add_default_ie_data(&pkt, 1);

    p2p_ie_fuzzing(&pkt, "p2p_association_response", p2p_association_response_p2p_ie_att);
    wps_ie_fuzzing(&pkt, "p2p_association_response");

    return pkt;
}

struct packet create_default_p2p_probe_request(struct ether_addr bssid, struct ether_addr smac, struct ether_addr dmac, char adhoc, struct packet *recv_pkt)
{
    struct packet pkt = {0};

    create_ieee_hdr(&pkt, IEEE80211_TYPE_PROBEREQ, 'a', 0, SE_BROADCASTMAC, smac, SE_BROADCASTMAC, SE_NULLMAC, 0);

    add_ie_data(&pkt, 0, SPECIFIC_VALUE, (uint8_t *)"DIRECT-", strlen("DIRECT-"));

    add_default_ie_data(&pkt, 1); // supported rates

    add_ie_data(&pkt, 221, SPECIFIC_VALUE, VENDOR_SPECIFIC_P2P, VENDOR_SPECIFIC_P2P_LEN); // p2p
    memcpy(pkt.data + (pkt.len - VENDOR_SPECIFIC_P2P_LEN - 2) + 12 + 2, fuzzing_opt.source_addr.ether_addr_octet, 6);

    return pkt;
}

struct packet create_p2p_probe_request(struct ether_addr bssid, struct ether_addr smac, struct ether_addr dmac, char adhoc, struct packet *recv_pkt)
{
    struct packet pkt = {0};

    create_ieee_hdr(&pkt, IEEE80211_TYPE_PROBEREQ, 'a', 0, SE_BROADCASTMAC, smac, SE_BROADCASTMAC, SE_NULLMAC, 0);

    add_ie_data(&pkt, 0, SPECIFIC_VALUE, (uint8_t *)"DIRECT-", strlen("DIRECT-"));

    add_default_ie_data(&pkt, 1);

    p2p_ie_fuzzing(&pkt, "p2p_probe_request", p2p_probe_request_p2p_ie_att);
    wps_ie_fuzzing(&pkt, "p2p_probe_request");

    create_probe_request_fuzzing_ies(&pkt);

    return pkt;
}

struct packet create_p2p_probe_response(struct ether_addr bssid, struct ether_addr smac, struct ether_addr dmac, char adhoc, struct packet *recv_pkt)
{
    struct packet pkt = {0};
    struct beacon_fixed *bf;
    static uint64_t internal_timestamp = 0;
    uint8_t *ie_data;
    uint8_t ie_len;
    uint8_t ie_id;

    create_ieee_hdr(&pkt, IEEE80211_TYPE_PROBERES, 'a', 0x013A, dmac, smac, smac, SE_NULLMAC, 0);

    bf = (struct beacon_fixed *)(pkt.data + pkt.len);

    if (0 == fuzzing_opt.seed)
        srandom(time(NULL));

    internal_timestamp += random();
    bf->timestamp = htole64(internal_timestamp);
    bf->interval = htole16(DEFAULT_BEACON_INTERVAL);
    bf->capabilities = 0xFFF0;
    if (adhoc)
    {
        bf->capabilities |= 0x0002;
    }
    else
    {
        bf->capabilities |= 0x0001;
    }

    bf->capabilities |= 0x0010;
    pkt.len += sizeof(struct beacon_fixed);

    add_ie_data(&pkt, 0, SPECIFIC_VALUE, (uint8_t *)"DIRECT-", strlen("DIRECT-")); // ssid

    add_default_ie_data(&pkt, 1); // supported rates

    if (fuzzing_opt.p2p_frame_test)
    {
        if (fuzzing_opt.ois[0].channel <= 14)
        {
            add_ie_data(&pkt, 3, SPECIFIC_VALUE, &fuzzing_opt.ois[0].channel, 1);
        }
        else
        {
            add_default_ie_data(&pkt, 45);
            ie_data = (uint8_t *)malloc(strlen(IE_61_HT_INFORMATION));
            if (ie_data)
            {
                memcpy(ie_data, IE_61_HT_INFORMATION, strlen(IE_61_HT_INFORMATION));
                ie_data[2] = fuzzing_opt.ois[0].channel;
                ie_id = ie_data[0];
                ie_len = ie_data[1];
                add_ie_data(&pkt, ie_id, SPECIFIC_VALUE, ie_data + 2, ie_len);
                free(ie_data);
            }
        }
    }
    else
    {
        if (recv_pkt)
            add_ie_data(&pkt, 3, SPECIFIC_VALUE, &recv_pkt->channel, 1); // 1,6 11  // ds parameter set: current channel
    }

    if (!fuzzing_opt.p2p_frame_test)
    {
        add_ie_data(&pkt, 221, SPECIFIC_VALUE, VENDOR_SPECIFIC_P2P, VENDOR_SPECIFIC_P2P_LEN); // p2p
        memcpy(pkt.data + (pkt.len - VENDOR_SPECIFIC_P2P_LEN - 2) + 12 + 2, fuzzing_opt.source_addr.ether_addr_octet, 6);
    }

    wps_ie_fuzzing(&pkt, "p2p_probe_response");
    p2p_ie_fuzzing(&pkt, "p2p_probe_response", p2p_probe_response_p2p_ie_att);

    create_probe_response_fuzzing_ies(&pkt);

    return pkt;
}

struct packet create_p2p_action_invitation_request(struct ether_addr bssid, struct ether_addr smac, struct ether_addr dmac, char adhoc, struct packet *recv_pkt)
{
    struct packet pkt = {0};
    struct action_fixed *af;

    create_ieee_hdr(&pkt, IEEE80211_TYPE_ACTION, 'a', 0x013A, dmac, smac, bssid, SE_NULLMAC, 0);

    af = (struct action_fixed *)(pkt.data + pkt.len);
    af->category_code = WLAN_ACTION_PUBLIC;
    af->action_code = WLAN_PA_VENDOR_SPECIFIC;
    pkt.len += sizeof(struct action_fixed);

    // OUI: Wi-Fi Alliance
    pkt.data[pkt.len] = 0x50;
    pkt.data[pkt.len + 1] = 0x6f;
    pkt.data[pkt.len + 2] = 0x9a;
    pkt.len += 3;

    // WFA subtype: P2P
    pkt.data[pkt.len] = 0x09;
    pkt.len += 1;

    // P2P Public Action Subtype: P2P Invitation Request
    pkt.data[pkt.len] = P2P_INVITATION_REQUEST;
    pkt.len += 1;

    // P2P Public Action Dialog Token: 58
    pkt.data[pkt.len] = 0x3A;
    pkt.len += 1;

    p2p_ie_fuzzing(&pkt, "p2p_action_invitation_request", p2p_action_invitation_request_p2p_ie_att);
    wps_ie_fuzzing(&pkt, "p2p_action_invitation_request");

    return pkt;
}

struct packet create_p2p_action_invitation_response(struct ether_addr bssid, struct ether_addr smac, struct ether_addr dmac, char adhoc, struct packet *recv_pkt)
{
    struct packet pkt = {0};
    struct action_fixed *af;

    create_ieee_hdr(&pkt, IEEE80211_TYPE_ACTION, 'a', 0x013A, dmac, smac, bssid, SE_NULLMAC, 0);

    af = (struct action_fixed *)(pkt.data + pkt.len);
    af->category_code = WLAN_ACTION_PUBLIC;
    af->action_code = WLAN_PA_VENDOR_SPECIFIC;
    pkt.len += sizeof(struct action_fixed);

    // OUI: Wi-Fi Alliance
    pkt.data[pkt.len] = 0x50;
    pkt.data[pkt.len + 1] = 0x6f;
    pkt.data[pkt.len + 2] = 0x9a;
    pkt.len += 3;

    // WFA subtype: P2P
    pkt.data[pkt.len] = 0x09;
    pkt.len += 1;

    // P2P Public Action Subtype: P2P Invitation Response
    pkt.data[pkt.len] = P2P_INVITATION_RESPONSE;
    pkt.len += 1;

    // P2P Public Action Dialog Token: 58
    pkt.data[pkt.len] = 0x3A;
    pkt.len += 1;

    p2p_ie_fuzzing(&pkt, "p2p_action_invitation_response", p2p_action_invitation_response_p2p_ie_att);
    wps_ie_fuzzing(&pkt, "p2p_action_invitation_response");

    return pkt;
}

struct packet create_p2p_action_device_discoverability_request(struct ether_addr bssid, struct ether_addr smac, struct ether_addr dmac, char adhoc, struct packet *recv_pkt)
{
    struct packet pkt = {0};
    struct action_fixed *af;

    create_ieee_hdr(&pkt, IEEE80211_TYPE_ACTION, 'a', 0x013A, dmac, smac, bssid, SE_NULLMAC, 0);

    af = (struct action_fixed *)(pkt.data + pkt.len);
    af->category_code = WLAN_ACTION_PUBLIC;
    af->action_code = WLAN_PA_VENDOR_SPECIFIC;
    pkt.len += sizeof(struct action_fixed);

    // OUI: Wi-Fi Alliance
    pkt.data[pkt.len] = 0x50;
    pkt.data[pkt.len + 1] = 0x6f;
    pkt.data[pkt.len + 2] = 0x9a;
    pkt.len += 3;

    // WFA subtype: P2P
    pkt.data[pkt.len] = 0x09;
    pkt.len += 1;

    // P2P Public Action Subtype: Device discoverability request
    pkt.data[pkt.len] = P2P_DEVICE_DISCOVERABILITY_REQUEST;
    pkt.len += 1;

    // P2P Public Action Dialog Token: 2
    pkt.data[pkt.len] = 0x02;
    pkt.len += 1;

    p2p_ie_fuzzing(&pkt, "p2p_action_device_discoverability_request", p2p_action_device_discoverability_request_p2p_ie_att);
    wps_ie_fuzzing(&pkt, "p2p_action_device_discoverability_request");

    return pkt;
}

struct packet create_p2p_action_device_discoverability_response(struct ether_addr bssid, struct ether_addr smac, struct ether_addr dmac, char adhoc, struct packet *recv_pkt)
{
    struct packet pkt = {0};
    struct action_fixed *af;

    create_ieee_hdr(&pkt, IEEE80211_TYPE_ACTION, 'a', 0x013A, dmac, smac, bssid, SE_NULLMAC, 0);

    af = (struct action_fixed *)(pkt.data + pkt.len);
    af->category_code = WLAN_ACTION_PUBLIC;
    af->action_code = WLAN_PA_VENDOR_SPECIFIC;
    pkt.len += sizeof(struct action_fixed);

    // OUI: Wi-Fi Alliance
    pkt.data[pkt.len] = 0x50;
    pkt.data[pkt.len + 1] = 0x6f;
    pkt.data[pkt.len + 2] = 0x9a;
    pkt.len += 3;

    // WFA subtype: P2P
    pkt.data[pkt.len] = 0x09;
    pkt.len += 1;

    // P2P Public Action Subtype: Device discoverability response
    pkt.data[pkt.len] = P2P_DEVICE_DISCOVERABILITY_RESPONSE;
    pkt.len += 1;

    // P2P Public Action Dialog Token: 2
    pkt.data[pkt.len] = 0x02;
    pkt.len += 1;

    p2p_ie_fuzzing(&pkt, "p2p_action_device_discoverability_response", p2p_action_device_discoverability_response_p2p_ie_att);
    wps_ie_fuzzing(&pkt, "p2p_action_device_discoverability_response");

    return pkt;
}

struct packet create_p2p_action_provision_discovery_request(struct ether_addr bssid, struct ether_addr smac, struct ether_addr dmac, char adhoc, struct packet *recv_pkt)
{
    struct packet pkt = {0};
    struct action_fixed *af;

    struct vendor_specific_ie vs_ie_wps = {0};

    create_ieee_hdr(&pkt, IEEE80211_TYPE_ACTION, 'a', 0x013A, dmac, smac, bssid, SE_NULLMAC, 0);

    af = (struct action_fixed *)(pkt.data + pkt.len);
    af->category_code = WLAN_ACTION_PUBLIC;
    af->action_code = WLAN_PA_VENDOR_SPECIFIC;
    pkt.len += sizeof(struct action_fixed);

    // OUI: Wi-Fi Alliance
    pkt.data[pkt.len] = 0x50;
    pkt.data[pkt.len + 1] = 0x6f;
    pkt.data[pkt.len + 2] = 0x9a;
    pkt.len += 3;

    // WFA subtype: P2P
    pkt.data[pkt.len] = 0x09;
    pkt.len += 1;

    // P2P Public Action Subtype: Provision Discovery Request
    pkt.data[pkt.len] = P2P_PROVISION_DISCOVERY_REQUEST;
    pkt.len += 1;

    // P2P Public Action Dialog Token: 1
    pkt.data[pkt.len] = 0x01;
    pkt.len += 1;

    p2p_ie_fuzzing(&pkt, "p2p_action_provision_discovery_request", p2p_action_provision_discovery_request_p2p_ie_att);
    wps_ie_fuzzing(&pkt, "p2p_action_provision_discovery_request");

    // WPS ie
    vs_ie_wps.id = IE_221_VENDOR_SPECIFIC;
    if (0 == fuzzing_opt.seed)
        srandom(time(NULL) + pkt.len);

    vs_ie_wps.length = 4 + random() % 252;
    vs_ie_wps.oui[0] = 0x00;
    vs_ie_wps.oui[1] = 0x50;
    vs_ie_wps.oui[2] = 0xf2;
    vs_ie_wps.oui_type = 0x04;
    memcpy(pkt.data + pkt.len, &vs_ie_wps, sizeof(vs_ie_wps));
    pkt.len += sizeof(vs_ie_wps);

    // config methods
    add_data_element_tlv_fuzzing_data(&pkt, (struct vendor_specific_ie *)(pkt.data + pkt.len), 0x1008);

    return pkt;
}

struct packet create_p2p_action_provision_discovery_response(struct ether_addr bssid, struct ether_addr smac, struct ether_addr dmac, char adhoc, struct packet *recv_pkt)
{
    struct packet pkt = {0};
    struct action_fixed *af;

    create_ieee_hdr(&pkt, IEEE80211_TYPE_ACTION, 'a', 0x013A, dmac, smac, bssid, SE_NULLMAC, 0);

    af = (struct action_fixed *)(pkt.data + pkt.len);
    af->category_code = WLAN_ACTION_PUBLIC;
    af->action_code = WLAN_PA_VENDOR_SPECIFIC;
    pkt.len += sizeof(struct action_fixed);

    // OUI: Wi-Fi Alliance
    pkt.data[pkt.len] = 0x50;
    pkt.data[pkt.len + 1] = 0x6f;
    pkt.data[pkt.len + 2] = 0x9a;
    pkt.len += 3;

    // WFA subtype: P2P
    pkt.data[pkt.len] = 0x09;
    pkt.len += 1;

    // P2P Public Action Subtype: Provision Discovery Response
    pkt.data[pkt.len] = P2P_PROVISION_DISCOVERY_RESPONSE;
    pkt.len += 1;

    // P2P Public Action Dialog Token: 1
    pkt.data[pkt.len] = 0x01;
    pkt.len += 1;

    p2p_ie_fuzzing(&pkt, "p2p_action_provision_discovery_response", p2p_action_provision_discovery_response_p2p_ie_att);
    wps_ie_fuzzing(&pkt, "p2p_action_provision_discovery_response");

    return pkt;
}

struct packet create_p2p_action_go_negotiation_request(struct ether_addr bssid, struct ether_addr smac, struct ether_addr dmac, char adhoc, struct packet *recv_pkt)
{
    struct packet pkt = {0};
    struct action_fixed *af;

    create_ieee_hdr(&pkt, IEEE80211_TYPE_ACTION, 'a', 0x013A, dmac, smac, bssid, SE_NULLMAC, 0);

    af = (struct action_fixed *)(pkt.data + pkt.len);
    af->category_code = WLAN_ACTION_PUBLIC;
    af->action_code = WLAN_PA_VENDOR_SPECIFIC;
    pkt.len += sizeof(struct action_fixed);

    // OUI: Wi-Fi Alliance
    pkt.data[pkt.len] = 0x50;
    pkt.data[pkt.len + 1] = 0x6f;
    pkt.data[pkt.len + 2] = 0x9a;
    pkt.len += 3;

    // WFA subtype: P2P
    pkt.data[pkt.len] = 0x09;
    pkt.len += 1;

    // P2P Public Action Subtype: GO Negotiation Request
    pkt.data[pkt.len] = P2P_GO_NEGOTIATION_REQUEST;
    pkt.len += 1;

    // P2P Public Action Dialog Token: 2
    pkt.data[pkt.len] = 0x02;
    pkt.len += 1;

    p2p_ie_fuzzing(&pkt, "p2p_action_go_negotiation_request", p2p_action_go_negotiation_request_p2p_ie_att);
    wps_ie_fuzzing(&pkt, "p2p_action_go_negotiation_request");

    return pkt;
}

struct packet create_p2p_action_go_negotiation_response(struct ether_addr bssid, struct ether_addr smac, struct ether_addr dmac, char adhoc, struct packet *recv_pkt)
{
    struct packet pkt = {0};
    struct action_fixed *af;

    create_ieee_hdr(&pkt, IEEE80211_TYPE_ACTION, 'a', 0x013A, dmac, smac, bssid, SE_NULLMAC, 0);

    af = (struct action_fixed *)(pkt.data + pkt.len);
    af->category_code = WLAN_ACTION_PUBLIC;
    af->action_code = WLAN_PA_VENDOR_SPECIFIC;
    pkt.len += sizeof(struct action_fixed);

    // OUI: Wi-Fi Alliance
    pkt.data[pkt.len] = 0x50;
    pkt.data[pkt.len + 1] = 0x6f;
    pkt.data[pkt.len + 2] = 0x9a;
    pkt.len += 3;

    // WFA subtype: P2P
    pkt.data[pkt.len] = 0x09;
    pkt.len += 1;

    // P2P Public Action Subtype: GO Negotiation Response
    pkt.data[pkt.len] = P2P_GO_NEGOTIATION_RESPONSE;
    pkt.len += 1;

    // P2P Public Action Dialog Token: 2
    pkt.data[pkt.len] = 0x02;
    pkt.len += 1;

    p2p_ie_fuzzing(&pkt, "p2p_action_go_negotiation_response", p2p_action_go_negotiation_response_p2p_ie_att);
    wps_ie_fuzzing(&pkt, "p2p_action_go_negotiation_response");

    return pkt;
}

struct packet create_p2p_action_go_negotiation_confirmation(struct ether_addr bssid, struct ether_addr smac, struct ether_addr dmac, char adhoc, struct packet *recv_pkt)
{
    struct packet pkt = {0};
    struct action_fixed *af;

    create_ieee_hdr(&pkt, IEEE80211_TYPE_ACTION, 'a', 0x013A, dmac, smac, bssid, SE_NULLMAC, 0);

    af = (struct action_fixed *)(pkt.data + pkt.len);
    af->category_code = WLAN_ACTION_PUBLIC;
    af->action_code = WLAN_PA_VENDOR_SPECIFIC;
    pkt.len += sizeof(struct action_fixed);

    // OUI: Wi-Fi Alliance
    pkt.data[pkt.len] = 0x50;
    pkt.data[pkt.len + 1] = 0x6f;
    pkt.data[pkt.len + 2] = 0x9a;
    pkt.len += 3;

    // WFA subtype: P2P
    pkt.data[pkt.len] = 0x09;
    pkt.len += 1;

    // P2P Public Action Subtype: GO Negotiation Confirmation
    pkt.data[pkt.len] = P2P_GO_NEGOTIATION_CONFIRMATION;
    pkt.len += 1;

    // P2P Public Action Dialog Token: 2
    pkt.data[pkt.len] = 0x02;
    pkt.len += 1;

    p2p_ie_fuzzing(&pkt, "p2p_action_go_negotiation_confirmation", p2p_action_go_negotiation_confirmation_p2p_ie_att);
    wps_ie_fuzzing(&pkt, "p2p_action_go_negotiation_confirmation");

    return pkt;
}

/*
    Return whether a pkt is a P2P beacon
*/
int is_p2p_beacon(struct packet *pkt)
{
    struct ieee_hdr *hdr = NULL;
    char *pie = NULL;

    hdr = (struct ieee_hdr *)pkt->data;
    if (IEEE80211_TYPE_BEACON == hdr->type)
    {
        if (pkt->len < sizeof(struct ieee_hdr) + 12 + 2)
            return 0;

        pie = (char *)(pkt->data + sizeof(struct ieee_hdr) + 12);
        if (pie[0] != 0)
            return 0;

        if (strstr(pie + 2, "DIRECT-"))
            return 1;
    }

    return 0;
}

/*
    Return whether a pkt is a P2P probe
*/
int is_p2p_probe(struct packet *pkt)
{
    struct ieee_hdr *hdr = NULL;
    char *pie = NULL;

    hdr = (struct ieee_hdr *)pkt->data;
    if (hdr->type == IEEE80211_TYPE_PROBEREQ)
    {
        if (pkt->len < sizeof(struct ieee_hdr) + 2)
            return 0;

        pie = (char *)(pkt->data + sizeof(struct ieee_hdr));
        if (pie[0] != 0)
            return 0;

        if (strstr(pie + 2, "DIRECT-"))
            return 1;
    }
    else if (hdr->type == IEEE80211_TYPE_PROBERES)
    {
        if (pkt->len < sizeof(struct ieee_hdr) + 12 + 2)
            return 0;

        pie = (char *)pkt->data + sizeof(struct ieee_hdr) + 12;
        if (pie[0] != 0)
            return 0;

        if (strstr(pie + 2, "DIRECT-"))
            return 1;
    }

    return 0;
}

/*
    Return whether a pkt is a P2P action
*/
int is_p2p_action(struct packet *pkt)
{
    struct ieee_hdr *hdr = NULL;
    unsigned char *action = NULL;

    hdr = (struct ieee_hdr *)pkt->data;
    if (hdr->type == IEEE80211_TYPE_ACTION)
    {
        if (pkt->len > sizeof(struct ieee_hdr) + 2)
        {
            action = pkt->data + sizeof(struct ieee_hdr);
            if (action[0] == 0x04 && action[1] == 0x09 && action[5] == 0x09)
                return 1;
        }
    }

    return 0;
}

/*
    Return whether a pkt is a P2P
*/
int is_p2p_frame(struct packet *pkt)
{
    return (is_p2p_action(pkt) || is_p2p_beacon(pkt) || is_p2p_probe(pkt));
}

/*
    Check for P2P Attributes
*/
void check_p2p_attributes(struct packet *pkt, struct ether_addr bssid, struct ether_addr smac, struct ether_addr dmac)
{
    struct ieee_hdr *hdr = NULL;
    struct p2p_action *act = NULL;
    struct p2p_ie *p2pie = NULL;
    struct attribete_tlv_hdr *ath = NULL;
    uint8_t *ies = NULL;
    int attlen = 0;
    int left = 0;

    hdr = (struct ieee_hdr *)pkt->data;
    if (IEEE80211_TYPE_ACTION == hdr->type)
    {
        act = (struct p2p_action *)(pkt->data + sizeof(struct ieee_hdr));
        if (0 == memcmp(act, p2p_action_hdr, sizeof(p2p_action_hdr)))
        {

            ies = pkt->data + sizeof(struct ieee_hdr) + sizeof(struct p2p_action);
            left = pkt->len - sizeof(struct ieee_hdr) - sizeof(struct p2p_action);
        }
    }
    
    if (IEEE80211_TYPE_PROBEREQ == hdr->type)
    {
        ies = pkt->data + sizeof(struct ieee_hdr);
        left = pkt->len - sizeof(struct ieee_hdr);
    }
    
    if (IEEE80211_TYPE_PROBERES == hdr->type)
    {
        ies = pkt->data + sizeof(struct ieee_hdr) + 12;
        left = pkt->len - sizeof(struct ieee_hdr) - 12;
    }

    if (left == 0) {
        // fuzz_logger_log(FUZZ_LOG_INFO, "***P2P ACTION not: IEEE80211_TYPE_ACTION, IEEE80211_TYPE_PROBEREQ, IEEE80211_TYPE_PROBERES");
        return;
    }

    while (left > 0)
    {
        if (ies[0] == IE_221_VENDOR_SPECIFIC)
        {
            fuzz_logger_log(FUZZ_LOG_DEBUG, "***P2P ACTION");
            p2pie = (struct p2p_ie *)ies;
            if ((0 == memcmp(p2pie->oui, p2p_oui, 3)) && (p2pie->oui_type == 0x09))
            {
                attlen = p2pie->length - 4;
                ath = (struct attribete_tlv_hdr *)(ies + sizeof(struct p2p_ie));
                ies = (uint8_t *)ath;
                while (attlen > 0 && (ath->length < attlen))
                {
                    switch (ath->type)
                    {
                    case P2P_ATTRIBUTE_STATUS:
                        fuzz_logger_log(FUZZ_LOG_DEBUG, "***P2P_ATTRIBUTE_STATUS: %d", ies[3]);
                        fuzzing_opt.p2p_status = ies[3];
                        break;
                    case P2P_ATTRIBUTE_MINOR_REASON_CODE:
                        fuzz_logger_log(FUZZ_LOG_DEBUG, "***P2P_ATTRIBUTE_MINOR_REASON_CODE");
                        break;
                    case P2P_ATTRIBUTE_P2P_CAPABILITY:
                        fuzz_logger_log(FUZZ_LOG_DEBUG, "***P2P_ATTRIBUTE_P2P_CAPABILITY");
                        break;
                    case P2P_ATTRIBUTE_P2P_DEVICE_ID:
                        fuzz_logger_log(FUZZ_LOG_DEBUG, "***P2P_ATTRIBUTE_P2P_DEVICE_ID");
                        break;
                    case P2P_ATTRIBUTE_GROUP_OWNER_INTENT:
                        if (MAC_MATCHES(smac, fuzzing_opt.target_addr))
                        {
                            fuzzing_opt.target_group_owner_intent = (ies[3] & 0xFE) >> 1;
                        }
                        else if (MAC_MATCHES(smac, fuzzing_opt.source_addr))
                        {
                            fuzzing_opt.source_group_owner_intent = (ies[3] & 0xFE) >> 1;
                        }
                        fuzz_logger_log(FUZZ_LOG_DEBUG, "***P2P_ATTRIBUTE_GROUP_OWNER_INTENT: %d", (ies[3] & 0xFE) >> 1);
                        break;
                    case P2P_ATTRIBUTE_CONFIGURATION_TIMEOUT:
                        fuzz_logger_log(FUZZ_LOG_DEBUG, "***P2P_ATTRIBUTE_CONFIGURATION_TIMEOUT");
                        break;
                    case P2P_ATTRIBUTE_LISTEN_CHANNEL:
                        if (MAC_MATCHES(smac, fuzzing_opt.target_addr))
                        {
                            fuzzing_opt.p2p_target_listen_channel = *(ies + 7);
                        }
                        else if (MAC_MATCHES(smac, fuzzing_opt.source_addr))
                        {
                            fuzzing_opt.p2p_target_listen_channel = *(ies + 7);
                        }
                        fuzz_logger_log(FUZZ_LOG_DEBUG, "***P2P_ATTRIBUTE_LISTEN_CHANNEL: %d", *(ies + 7));
                        break;
                    case P2P_ATTRIBUTE_P2P_GROUP_BSSID:
                        fuzz_logger_log(FUZZ_LOG_DEBUG, "***P2P_ATTRIBUTE_P2P_GROUP_BSSID: %02X:%02X:%02X:%02X:%02X:%02X", ies[3 + 0], ies[3 + 1], ies[3 + 2], ies[3 + 3], ies[3 + 4], ies[3 + 5]);
                        if (MAC_MATCHES(smac, fuzzing_opt.target_addr))
                        {
                            memcpy(fuzzing_opt.p2p_target_addr.ether_addr_octet, ies + 3, 6);
                            memcpy(fuzzing_opt.p2p_bssid.ether_addr_octet, ies + 3, 6);
                        }
                        else if (MAC_MATCHES(smac, fuzzing_opt.source_addr))
                        {
                            memcpy(fuzzing_opt.p2p_source_addr.ether_addr_octet, ies + 3, 6);
                            memcpy(fuzzing_opt.p2p_bssid.ether_addr_octet, ies + 3, 6);
                        }
                        break;
                    case P2P_ATTRIBUTE_EXTENDED_LISTEN_TIMING:
                        fuzz_logger_log(FUZZ_LOG_DEBUG, "***P2P_ATTRIBUTE_EXTENDED_LISTEN_TIMING");
                        break;
                    case P2P_ATTRIBUTE_INTENDED_P2P_INTERFACE_ADDRESS:
                        if (MAC_MATCHES(smac, fuzzing_opt.target_addr))
                        {
                            memcpy(fuzzing_opt.p2p_intened_target_addr.ether_addr_octet, ies + 3, 6);
                        }
                        else if (MAC_MATCHES(smac, fuzzing_opt.source_addr))
                        {
                            memcpy(fuzzing_opt.p2p_intened_source_addr.ether_addr_octet, ies + 3, 6);
                        }
                        fuzz_logger_log(FUZZ_LOG_DEBUG, "***P2P_ATTRIBUTE_INTENDED_P2P_INTERFACE_ADDRESS: %02X:%02X:%02X:%02X:%02X:%02X", ies[3 + 0], ies[3 + 1], ies[3 + 2], ies[3 + 3], ies[3 + 4], ies[3 + 5]);
                        break;
                    case P2P_ATTRIBUTE_P2P_MANAGEABILITY:
                        fuzz_logger_log(FUZZ_LOG_DEBUG, "***P2P_ATTRIBUTE_P2P_MANAGEABILITY");
                        break;
                    case P2P_ATTRIBUTE_CHANNEL_LIST:
                        fuzz_logger_log(FUZZ_LOG_DEBUG, "***P2P_ATTRIBUTE_CHANNEL_LIST");
                        break;
                    case P2P_ATTRIBUTE_NOTICE_OF_ABSENCE:
                        fuzz_logger_log(FUZZ_LOG_DEBUG, "***P2P_ATTRIBUTE_NOTICE_OF_ABSENCE");
                        break;
                    case P2P_ATTRIBUTE_P2P_DEVICE_INFO:
                        fuzz_logger_log(FUZZ_LOG_DEBUG, "***P2P_ATTRIBUTE_P2P_DEVICE_INFO: %02X:%02X:%02X:%02X:%02X:%02X", ies[3 + 0], ies[3 + 1], ies[3 + 2], ies[3 + 3], ies[3 + 4], ies[3 + 5]);
                        /*if(MAC_MATCHES(smac,fuzzing_opt.target_addr))
                        {
                            memcpy(fuzzing_opt.p2p_target_addr.ether_addr_octet,ies+3, 6);
                        }
                        else if(MAC_MATCHES(smac, fuzzing_opt.source_addr))
                        {
                            memcpy(fuzzing_opt.p2p_source_addr.ether_addr_octet,ies+3, 6);
                        }*/
                        break;
                    case P2P_ATTRIBUTE_P2P_GROUP_INFO:
                        fuzz_logger_log(FUZZ_LOG_DEBUG, "***P2P_ATTRIBUTE_P2P_GROUP_INFO");
                        break;
                    case P2P_ATTRIBUTE_P2P_GROUP_ID:
                        fuzz_logger_log(FUZZ_LOG_DEBUG, "***P2P_ATTRIBUTE_P2P_GROUP_ID: %02X:%02X:%02X:%02X:%02X:%02X", ies[3 + 0], ies[3 + 1], ies[3 + 2], ies[3 + 3], ies[3 + 4], ies[3 + 5]);
                        break;
                    case P2P_ATTRIBUTE_P2P_INTERFACE:
                        fuzz_logger_log(FUZZ_LOG_DEBUG, "***P2P_ATTRIBUTE_P2P_INTERFACE: %02X:%02X:%02X:%02X:%02X:%02X", ies[3 + 0], ies[3 + 1], ies[3 + 2], ies[3 + 3], ies[3 + 4], ies[3 + 5]);
                        break;
                    case P2P_ATTRIBUTE_OPERATING_CHANNEL:
                        if (MAC_MATCHES(smac, fuzzing_opt.target_addr))
                        {
                            fuzzing_opt.p2p_target_operating_channel = *(ies + 7);
                            fuzzing_opt.p2p_operating_channel = *(ies + 7);
                        }
                        else if (MAC_MATCHES(smac, fuzzing_opt.source_addr))
                        {
                            fuzzing_opt.p2p_source_operating_channel = *(ies + 7);
                            fuzzing_opt.p2p_operating_channel = *(ies + 7);
                        }

                        fuzz_logger_log(FUZZ_LOG_DEBUG, "***P2P_ATTRIBUTE_OPERATING_CHANNEL: %d", *(ies + 7));
                        break;
                    case P2P_ATTRIBUTE_INVITATION_FLAGS:
                        fuzz_logger_log(FUZZ_LOG_DEBUG, "***P2P_ATTRIBUTE_INVITATION_FLAGS");
                        break;
                    case P2P_ATTRIBUTE_OUT_OF_BAND_GROUP_OWNER_NEGOTIATION_CHANNEL:
                        fuzz_logger_log(FUZZ_LOG_DEBUG, "***P2P_ATTRIBUTE_OUT_OF_BAND_GROUP_OWNER_NEGOTIATION_CHANNEL");
                        break;
                    case P2P_ATTRIBUTE_SERVICE_HASH:
                        fuzz_logger_log(FUZZ_LOG_DEBUG, "***P2P_ATTRIBUTE_SERVICE_HASH");
                        break;
                    case P2P_ATTRIBUTE_SESSION_INFORMATION:
                        fuzz_logger_log(FUZZ_LOG_DEBUG, "***P2P_ATTRIBUTE_SESSION_INFORMATION");
                        break;
                    case P2P_ATTRIBUTE_CONNECTION_CAPABILITY_INFO:
                        fuzz_logger_log(FUZZ_LOG_DEBUG, "***P2P_ATTRIBUTE_CONNECTION_CAPABILITY_INFO");
                        break;
                    case P2P_ATTRIBUTE_ADVERTISEMENT_ID_INFO:
                        fuzz_logger_log(FUZZ_LOG_DEBUG, "***P2P_ATTRIBUTE_ADVERTISEMENT_ID_INFO");
                        break;
                    case P2P_ATTRIBUTE_ADVERTISED_SERVICE_INFO:
                        fuzz_logger_log(FUZZ_LOG_DEBUG, "***P2P_ATTRIBUTE_ADVERTISED_SERVICE_INFO");
                        break;
                    case P2P_ATTRIBUTE_SESSION_ID_INFO:
                        fuzz_logger_log(FUZZ_LOG_DEBUG, "***P2P_ATTRIBUTE_SESSION_ID_INFO");
                        break;
                    case P2P_ATTRIBUTE_FEATURE_CAPABILITY_INFO:
                        fuzz_logger_log(FUZZ_LOG_DEBUG, "***P2P_ATTRIBUTE_FEATURE_CAPABILITY_INFO");
                        break;
                    case P2P_ATTRIBUTE_PERSISTENT_GROUP_INFO:
                        fuzz_logger_log(FUZZ_LOG_DEBUG, "***P2P_ATTRIBUTE_PERSISTENT_GROUP_INFO");
                        break;
                    default:
                        break;
                    }

                    fuzz_logger_log(FUZZ_LOG_DEBUG, "*****1****attlen: %d*******ath->length: %d sizeof attribete_tlv_hdr: %d \n", attlen, ath->length, sizeof(struct attribete_tlv_hdr));
                    attlen -= (ath->length + sizeof(struct attribete_tlv_hdr));
                    ath = (struct attribete_tlv_hdr *)(ies + ath->length + sizeof(struct attribete_tlv_hdr));
                    ies = (uint8_t *)ath;
                    fuzz_logger_log(FUZZ_LOG_DEBUG, "*****2****attlen: %d*******ath->length: %d\n", attlen, ath->length);
                }

                break;
            }
            else
            {
                left -= (ies[1] + 2);
                ies += (2 + ies[1]);
                continue;
            }
        }
        else
        {
            left -= (ies[1] + 2);
            ies += (2 + ies[1]);
        }
    }
}

/*
    Handle P2P WiFi Fuzzing
*/
void handle_p2p(struct packet *pkt, struct ether_addr bssid, struct ether_addr smac, struct ether_addr dmac, fuzzing_option *fuzzing_opt)
{
    struct ieee_hdr *hdr = NULL;
    struct packet fuzz_pkt = {0};
    unsigned char *action = NULL;
    struct ether_addr resp_mac = {0};
    struct ether_addr resp_bssid = {0};
    char szerr[256] = {0};
    int i = 0;

    // if(fuzzing_opt->test_type == TEST_INTERACTIVE && MAC_MATCHES(smac, fuzzing_opt->source_addr))
    //{// 1,6,11
    //     return;
    // }

    if (MAC_MATCHES(smac, fuzzing_opt->target_addr))
        MAC_COPY(resp_mac, fuzzing_opt->source_addr);
    else
        MAC_COPY(resp_mac, fuzzing_opt->target_addr);

    if (MAC_IS_BCAST(bssid))
        MAC_COPY(resp_bssid, resp_mac);
    else
        MAC_COPY(resp_bssid, bssid);

    check_p2p_attributes(pkt, bssid, smac, dmac);

    hdr = (struct ieee_hdr *)pkt->data;

    int p2p_action = is_p2p_action(pkt);

    if (IEEE80211_TYPE_ACTION == hdr->type && p2p_action)
    {
        action = pkt->data + sizeof(struct ieee_hdr);
        switch (action[6])
        {
        case P2P_GO_NEGOTIATION_REQUEST:
            fuzz_logger_log(FUZZ_LOG_DEBUG, "channel: %d -> p2p_action_go_negotiation_request, P2P Device: %02X:%02X:%02X:%02X:%02X:%02X", pkt->channel, smac.ether_addr_octet[0], smac.ether_addr_octet[1], smac.ether_addr_octet[2], smac.ether_addr_octet[3], smac.ether_addr_octet[4], smac.ether_addr_octet[5]);
            if (fuzzing_opt->test_type == TEST_INTERACTIVE)
                fuzz_pkt = create_p2p_action_go_negotiation_response(resp_bssid, resp_mac, smac, 0, pkt);
            else
            {
                if (MAC_MATCHES(fuzzing_opt->source_addr, smac))
                {
                    for (i = 0; i < fuzzing_opt->ois_cnt; i++)
                    {
                        if (fuzzing_opt->ois[i].channel == fuzzing_opt->p2p_source_operating_channel)
                        {
                            fuzzing_opt->p2p_operating_interface_id = i;
                            break;
                        }
                        else
                        {
                            fuzzing_opt->p2p_operating_interface_id = 0;
                        }
                    }
                }
                else if (MAC_MATCHES(fuzzing_opt->target_addr, smac))
                {
                    for (i = 0; i < fuzzing_opt->ois_cnt; i++)
                    {
                        if (fuzzing_opt->ois[i].channel == fuzzing_opt->p2p_target_operating_channel)
                        {
                            fuzzing_opt->p2p_operating_interface_id = i;
                            break;
                        }
                        else
                        {
                            fuzzing_opt->p2p_operating_interface_id = 0;
                        }
                    }
                }
            }
            break;
        case P2P_GO_NEGOTIATION_RESPONSE:
            fuzz_logger_log(FUZZ_LOG_DEBUG, "channel: %d -> p2p_action_go_negotiation_response, P2P Device: %02X:%02X:%02X:%02X:%02X:%02X", pkt->channel, smac.ether_addr_octet[0], smac.ether_addr_octet[1], smac.ether_addr_octet[2], smac.ether_addr_octet[3], smac.ether_addr_octet[4], smac.ether_addr_octet[5]);
            if (fuzzing_opt->test_type == TEST_INTERACTIVE)
                fuzz_pkt = create_p2p_action_go_negotiation_confirmation(resp_bssid, resp_mac, smac, 0, pkt);
            break;
        case P2P_GO_NEGOTIATION_CONFIRMATION:
            fuzz_logger_log(FUZZ_LOG_DEBUG, "channel: %d -> p2p_action_go_negotiation_confirmation, P2P Device: %02X:%02X:%02X:%02X:%02X:%02X", pkt->channel, smac.ether_addr_octet[0], smac.ether_addr_octet[1], smac.ether_addr_octet[2], smac.ether_addr_octet[3], smac.ether_addr_octet[4], smac.ether_addr_octet[5]);
            if (fuzzing_opt->test_type == TEST_INTERACTIVE)
            {
                fuzz_pkt = create_p2p_action_invitation_request(resp_bssid, resp_mac, smac, 0, pkt);
            }
            else
            {
                if (fuzzing_opt->p2p_status == 0)
                {
                    if (fuzzing_opt->source_group_owner_intent > fuzzing_opt->target_group_owner_intent)
                    {
                        MAC_COPY(fuzzing_opt->p2p_bssid, fuzzing_opt->p2p_intened_source_addr);
                        fuzzing_opt->channel = fuzzing_opt->ois[fuzzing_opt->p2p_operating_interface_id].channel;
                        fuzzing_opt->ois[fuzzing_opt->p2p_operating_interface_id].channel = fuzzing_opt->p2p_operating_channel;

                        MAC_COPY(fuzzing_opt->target_addr, fuzzing_opt->p2p_intened_target_addr);
                        MAC_COPY(fuzzing_opt->source_addr, fuzzing_opt->p2p_intened_source_addr);
                        MAC_COPY(fuzzing_opt->bssid, fuzzing_opt->p2p_bssid);

                        MAC_COPY(fuzzing_opt->p2p_target_addr, fuzzing_opt->p2p_intened_target_addr);
                        MAC_COPY(fuzzing_opt->p2p_source_addr, fuzzing_opt->p2p_intened_source_addr);
                        MAC_COPY(fuzzing_opt->p2p_bssid, fuzzing_opt->p2p_bssid);

                        kismet_set_channel(fuzzing_opt->ois[fuzzing_opt->p2p_operating_interface_id].osdep_iface_out, fuzzing_opt->ois[fuzzing_opt->p2p_operating_interface_id].channel, szerr);

                        fuzz_logger_log(FUZZ_LOG_INFO, "switch to channel: %d", fuzzing_opt->ois[fuzzing_opt->p2p_operating_interface_id].channel);

                        print_options(fuzzing_opt);

                        sleep(1);

                        // if(fuzzing_opt->fuzz_work_mode == FUZZ_WORK_MODE_P2P) fuzzing_opt->p2p_frame_test = 1;
                    }
                    else if (fuzzing_opt->source_group_owner_intent < fuzzing_opt->target_group_owner_intent)
                    {
                        MAC_COPY(fuzzing_opt->p2p_bssid, fuzzing_opt->p2p_intened_target_addr);
                        fuzzing_opt->channel = fuzzing_opt->ois[fuzzing_opt->p2p_operating_interface_id].channel;
                        fuzzing_opt->ois[fuzzing_opt->p2p_operating_interface_id].channel = fuzzing_opt->p2p_operating_channel;

                        MAC_COPY(fuzzing_opt->target_addr, fuzzing_opt->p2p_intened_target_addr);
                        MAC_COPY(fuzzing_opt->source_addr, fuzzing_opt->p2p_intened_source_addr);
                        MAC_COPY(fuzzing_opt->bssid, fuzzing_opt->p2p_bssid);

                        MAC_COPY(fuzzing_opt->p2p_target_addr, fuzzing_opt->p2p_intened_target_addr);
                        MAC_COPY(fuzzing_opt->p2p_source_addr, fuzzing_opt->p2p_intened_source_addr);
                        MAC_COPY(fuzzing_opt->p2p_bssid, fuzzing_opt->p2p_bssid);

                        kismet_set_channel(fuzzing_opt->ois[fuzzing_opt->p2p_operating_interface_id].osdep_iface_out, fuzzing_opt->ois[fuzzing_opt->p2p_operating_interface_id].channel, szerr);

                        fuzz_logger_log(FUZZ_LOG_INFO, "switch to channel: %d", fuzzing_opt->ois[fuzzing_opt->p2p_operating_interface_id].channel);

                        print_options(fuzzing_opt);

                        sleep(1);

                        // if(fuzzing_opt->fuzz_work_mode == FUZZ_WORK_MODE_P2P) fuzzing_opt->p2p_frame_test = 1;
                    }
                }
            }
            break;
        case P2P_INVITATION_REQUEST:
            fuzz_logger_log(FUZZ_LOG_DEBUG, "channel: %d -> p2p_action_invitation_request, P2P Device: %02X:%02X:%02X:%02X:%02X:%02X", pkt->channel, smac.ether_addr_octet[0], smac.ether_addr_octet[1], smac.ether_addr_octet[2], smac.ether_addr_octet[3], smac.ether_addr_octet[4], smac.ether_addr_octet[5]);
            if (fuzzing_opt->test_type == TEST_INTERACTIVE)
                fuzz_pkt = create_p2p_action_invitation_response(resp_bssid, resp_mac, smac, 0, pkt);
            else
            {
                if (MAC_MATCHES(fuzzing_opt->source_addr, smac))
                {
                    for (i = 0; i < fuzzing_opt->ois_cnt; i++)
                    {
                        if (fuzzing_opt->ois[i].channel != fuzzing_opt->p2p_source_operating_channel)
                        {
                            fuzzing_opt->p2p_operating_interface_id = i;
                            break;
                        }
                    }
                }
                else if (MAC_MATCHES(fuzzing_opt->target_addr, smac))
                {
                    for (i = 0; i < fuzzing_opt->ois_cnt; i++)
                    {
                        if (fuzzing_opt->ois[i].channel != fuzzing_opt->p2p_target_operating_channel)
                        {
                            fuzzing_opt->p2p_operating_interface_id = i;
                            break;
                        }
                    }
                }
            }
            break;
        case P2P_INVITATION_RESPONSE:
            fuzz_logger_log(FUZZ_LOG_DEBUG, "channel: %d -> p2p_action_invitation_response, P2P Device: %02X:%02X:%02X:%02X:%02X:%02X", pkt->channel, smac.ether_addr_octet[0], smac.ether_addr_octet[1], smac.ether_addr_octet[2], smac.ether_addr_octet[3], smac.ether_addr_octet[4], smac.ether_addr_octet[5]);
            if (fuzzing_opt->test_type == TEST_INTERACTIVE)
                fuzz_pkt = create_p2p_action_device_discoverability_request(resp_bssid, resp_mac, smac, 0, pkt);
            else
            {
                if (fuzzing_opt->p2p_status == 0)
                {
                    if (MAC_MATCHES(fuzzing_opt->source_addr, smac))
                    {
                        MAC_COPY(fuzzing_opt->target_addr, fuzzing_opt->p2p_target_addr);
                        MAC_COPY(fuzzing_opt->source_addr, fuzzing_opt->p2p_source_addr);
                        MAC_COPY(fuzzing_opt->bssid, fuzzing_opt->p2p_bssid);

                        fuzzing_opt->channel = fuzzing_opt->ois[fuzzing_opt->p2p_operating_interface_id].channel;
                        fuzzing_opt->ois[fuzzing_opt->p2p_operating_interface_id].channel = fuzzing_opt->p2p_source_operating_channel;
                    }
                    else if (MAC_MATCHES(fuzzing_opt->target_addr, smac))
                    {
                        MAC_COPY(fuzzing_opt->target_addr, fuzzing_opt->p2p_target_addr);
                        MAC_COPY(fuzzing_opt->source_addr, fuzzing_opt->p2p_source_addr);
                        MAC_COPY(fuzzing_opt->bssid, fuzzing_opt->p2p_bssid);

                        fuzzing_opt->channel = fuzzing_opt->ois[fuzzing_opt->p2p_operating_interface_id].channel;
                        fuzzing_opt->ois[fuzzing_opt->p2p_operating_interface_id].channel = fuzzing_opt->p2p_target_operating_channel;
                    }

                    kismet_set_channel(fuzzing_opt->ois[fuzzing_opt->p2p_operating_interface_id].osdep_iface_out, fuzzing_opt->ois[fuzzing_opt->p2p_operating_interface_id].channel, szerr);

                    fuzz_logger_log(FUZZ_LOG_INFO, "switch to channel: %d", fuzzing_opt->ois[fuzzing_opt->p2p_operating_interface_id].channel);

                    print_options(fuzzing_opt);

                    sleep(1);

                    // if(fuzzing_opt->fuzz_work_mode == FUZZ_WORK_MODE_P2P) fuzzing_opt->p2p_frame_test = 1;
                }
            }
            break;
        case P2P_DEVICE_DISCOVERABILITY_REQUEST:
            fuzz_logger_log(FUZZ_LOG_DEBUG, "channel: %d -> p2p_action_device_discoverability_request, P2P Device: %02X:%02X:%02X:%02X:%02X:%02X", pkt->channel, smac.ether_addr_octet[0], smac.ether_addr_octet[1], smac.ether_addr_octet[2], smac.ether_addr_octet[3], smac.ether_addr_octet[4], smac.ether_addr_octet[5]);
            if (fuzzing_opt->test_type == TEST_INTERACTIVE)
                fuzz_pkt = create_p2p_action_device_discoverability_response(resp_bssid, resp_mac, smac, 0, pkt);
            break;
        case P2P_DEVICE_DISCOVERABILITY_RESPONSE:
            fuzz_logger_log(FUZZ_LOG_DEBUG, "channel: %d -> p2p_action_device_discoverability_response, P2P Device: %02X:%02X:%02X:%02X:%02X:%02X", pkt->channel, smac.ether_addr_octet[0], smac.ether_addr_octet[1], smac.ether_addr_octet[2], smac.ether_addr_octet[3], smac.ether_addr_octet[4], smac.ether_addr_octet[5]);
            if (fuzzing_opt->test_type == TEST_INTERACTIVE)
                fuzz_pkt = create_p2p_action_device_discoverability_request(resp_bssid, resp_mac, smac, 0, pkt);
            break;
        case P2P_PROVISION_DISCOVERY_REQUEST:
            fuzz_logger_log(FUZZ_LOG_DEBUG, "channel: %d -> p2p_action_provision_discovery_request, P2P Device: %02X:%02X:%02X:%02X:%02X:%02X", pkt->channel, smac.ether_addr_octet[0], smac.ether_addr_octet[1], smac.ether_addr_octet[2], smac.ether_addr_octet[3], smac.ether_addr_octet[4], smac.ether_addr_octet[5]);
            if (fuzzing_opt->test_type == TEST_INTERACTIVE)
                fuzz_pkt = create_p2p_action_provision_discovery_response(resp_bssid, resp_mac, smac, 0, pkt);
            break;
        case P2P_PROVISION_DISCOVERY_RESPONSE:
            fuzz_logger_log(FUZZ_LOG_DEBUG, "channel: %d -> p2p_action_provision_discovery_response, P2P Device: %02X:%02X:%02X:%02X:%02X:%02X", pkt->channel, smac.ether_addr_octet[0], smac.ether_addr_octet[1], smac.ether_addr_octet[2], smac.ether_addr_octet[3], smac.ether_addr_octet[4], smac.ether_addr_octet[5]);
            if (fuzzing_opt->test_type == TEST_INTERACTIVE)
                fuzz_pkt = create_p2p_action_go_negotiation_request(resp_bssid, resp_mac, smac, 0, pkt);
            break;
        default:
            break;
        }
    }
    
    if (IEEE80211_TYPE_PROBERES == hdr->type)
    {
        fuzz_logger_log(FUZZ_LOG_DEBUG, "channel: %d -> p2p_probe_response, p2p device: %02X:%02X:%02X:%02X:%02X:%02X", pkt->channel,
                        smac.ether_addr_octet[0],
                        smac.ether_addr_octet[1],
                        smac.ether_addr_octet[2],
                        smac.ether_addr_octet[3],
                        smac.ether_addr_octet[4],
                        smac.ether_addr_octet[5]);

        if (fuzzing_opt->test_type == TEST_INTERACTIVE)
        {
            fuzz_pkt = get_frame(IEEE80211_TYPE_ACK, resp_bssid, resp_mac, smac, pkt);
            fuzz_pkt.channel = pkt->channel;
            send_packet_ex(&fuzz_pkt);
            fuzz_pkt = create_p2p_action_provision_discovery_request(resp_bssid, resp_mac, smac, 0, pkt);
        }
    }
    
    if (IEEE80211_TYPE_PROBEREQ == hdr->type)
    {
        fuzz_logger_log(FUZZ_LOG_DEBUG, "channel: %d -> p2p_probe_request, p2p device: %02X:%02X:%02X:%02X:%02X:%02X", pkt->channel,
                        smac.ether_addr_octet[0],
                        smac.ether_addr_octet[1],
                        smac.ether_addr_octet[2],
                        smac.ether_addr_octet[3],
                        smac.ether_addr_octet[4],
                        smac.ether_addr_octet[5]);

        if (TEST_INTERACTIVE == fuzzing_opt->test_type)
        {
            fuzz_pkt = create_p2p_probe_request(SE_BROADCASTMAC, fuzzing_opt->source_addr, SE_BROADCASTMAC, 0, pkt);
            fuzz_pkt.channel = pkt->channel;
            send_packet_ex(&fuzz_pkt);

            fuzz_pkt = create_p2p_probe_response(resp_bssid, resp_mac, smac, 0, pkt);
        }
    }
    
    if (IEEE80211_TYPE_BEACON == hdr->type)
    {
        // BEACON are not fuzzed here
        fuzz_logger_log(FUZZ_LOG_DEBUG, "channel: %d -> p2p_beacon, p2p device: %02X:%02X:%02X:%02X:%02X:%02X", pkt->channel,
                        smac.ether_addr_octet[0],
                        smac.ether_addr_octet[1],
                        smac.ether_addr_octet[2],
                        smac.ether_addr_octet[3],
                        smac.ether_addr_octet[4],
                        smac.ether_addr_octet[5]);
    }

    if (TEST_INTERACTIVE == fuzzing_opt->test_type && fuzz_pkt.len > 0)
    {
        // fuzz_logger_log(FUZZ_LOG_INFO, "[handle_p2p] hdr->type: %d (%s), p2p_action: %d", hdr->type, return_frame_name(hdr->type), p2p_action);

        fuzz_pkt.channel = pkt->channel;
        fuzzing_opt->fuzz_pkt_num++;
        fuzzing_opt->fuzz_pkt = fuzz_pkt;
        send_packet_ex(&fuzz_pkt);
    }
}

/*
    Create a P2P action
*/
struct packet create_p2p_action(struct ether_addr bssid, struct ether_addr smac, struct ether_addr dmac, char adhoc, struct packet *recv_pkt)
{
    struct packet pkt = {0};
    static uint8_t action_types[] = {P2P_GO_NEGOTIATION_REQUEST, P2P_GO_NEGOTIATION_RESPONSE, P2P_GO_NEGOTIATION_CONFIRMATION,
                                     P2P_INVITATION_REQUEST, P2P_INVITATION_RESPONSE,
                                     P2P_DEVICE_DISCOVERABILITY_REQUEST, P2P_DEVICE_DISCOVERABILITY_RESPONSE,
                                     P2P_PROVISION_DISCOVERY_REQUEST, P2P_PROVISION_DISCOVERY_RESPONSE};

    if (0 == fuzzing_opt.seed)
        srandom(time(NULL));

    switch (random() % (sizeof(action_types) / sizeof(action_types[0])))
    {
    case P2P_GO_NEGOTIATION_REQUEST:
        pkt = create_p2p_action_go_negotiation_request(bssid, smac, dmac, adhoc, recv_pkt);
        break;
    case P2P_GO_NEGOTIATION_RESPONSE:
        pkt = create_p2p_action_go_negotiation_response(bssid, smac, dmac, adhoc, recv_pkt);
        break;
    case P2P_GO_NEGOTIATION_CONFIRMATION:
        pkt = create_p2p_action_go_negotiation_confirmation(bssid, smac, dmac, adhoc, recv_pkt);
        break;
    case P2P_INVITATION_REQUEST:
        pkt = create_p2p_action_invitation_request(bssid, smac, dmac, adhoc, recv_pkt);
        break;
    case P2P_INVITATION_RESPONSE:
        pkt = create_p2p_action_invitation_response(bssid, smac, dmac, adhoc, recv_pkt);
        break;
    case P2P_DEVICE_DISCOVERABILITY_REQUEST:
        pkt = create_p2p_action_device_discoverability_request(bssid, smac, dmac, adhoc, recv_pkt);
        break;
    case P2P_DEVICE_DISCOVERABILITY_RESPONSE:
        pkt = create_p2p_action_device_discoverability_response(bssid, smac, dmac, adhoc, recv_pkt);
        break;
    case P2P_PROVISION_DISCOVERY_REQUEST:
        pkt = create_p2p_action_provision_discovery_request(bssid, smac, dmac, adhoc, recv_pkt);
        break;
    case P2P_PROVISION_DISCOVERY_RESPONSE:
        pkt = create_p2p_action_provision_discovery_response(bssid, smac, dmac, adhoc, recv_pkt);
        break;
    default:
        break;
    }

    if (recv_pkt)
    {
        pkt.channel = recv_pkt->channel;
    }

    return pkt;
}

/*
    Retrieve a P2P action
*/
struct packet get_p2p_frame(uint8_t frame_type, struct ether_addr bssid, struct ether_addr smac, struct ether_addr dmac, struct packet *recv_pkt)
{
    struct packet pkt = {0};

    fuzzing_opt.fuzz_pkt_num++;

    switch (frame_type)
    {
    case IEEE80211_TYPE_BEACON:
        pkt = create_p2p_beacon(bssid, smac, dmac, 1, recv_pkt);
        break;
    case IEEE80211_TYPE_PROBEREQ:
        pkt = create_p2p_probe_request(bssid, smac, dmac, 1, recv_pkt);
        break;
    case IEEE80211_TYPE_PROBERES:
        pkt = create_p2p_probe_response(bssid, smac, dmac, 1, recv_pkt);
        break;
    case IEEE80211_TYPE_ASSOCREQ:
        pkt = create_p2p_association_request(bssid, smac, dmac, 1, recv_pkt);
        break;
    case IEEE80211_TYPE_ASSOCRES:
        pkt = create_p2p_association_response(bssid, smac, dmac, 1, recv_pkt);
        break;
    case IEEE80211_TYPE_ACTION:
        pkt = create_p2p_action(bssid, smac, dmac, 1, recv_pkt);
        break;
    default:
        break;
    }
    if (recv_pkt)
    {
        pkt.channel = recv_pkt->channel;
    }
    return pkt;
}
