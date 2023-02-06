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

#include <assert.h>
#include <stdio.h>
#include "beacon.h"
#include "ies_creator.h"
#include "../../procedures/awdl/wire.h"

extern fuzzing_option fuzzing_opt;

uint8_t beacon_ie_ieee1999[10] = {0, 1, 2, 3, 4, 6, 5, 0};
uint8_t beacon_ie_ieee2007[30] = {0, 1, 2, 3, 4, 6, 5, 7, 8, 9, 32, 37, 40, 41, 35, 42, 50, 48, 11, 12, 46, 221, 0};
uint8_t beacon_ie_ieee2012[80] = {0, 1, 2, 3, 4, 6, 5, 7, 8, 9, 32, 37, 40, 41, 35, 42, 50, 48, 11, 12, 46, 51, 63, 64, 67, 68, 66, 71, 70, 54, 58, 60, 59,
								  45, 61, 72, 74, 127, 86, 89, 69, 107, 108, 111, 112, 114, 113, 119, 120, 174, 123, 118, 221, 0};
uint8_t beacon_ie_ieee2016[100] = {0, 1, 3, 4, 6, 5, 7, 32, 37, 40, 41, 35, 42, 50, 48, 11, 12, 46, 51, 63, 64, 67, 68, 66, 71, 70, 54, 58, 60, 59,
								   45, 61, 72, 74, 127, 86, 89, 69, 107, 108, 111, 112, 114, 113, 119, 120, 174, 123, 118, 181, 186, 187, 158, 191,
								   192, 195, 196, 193, 198, 199, 201, 202, 221, 0};
uint8_t beacon_ie_ieee2020[100] = {0, 1, 3, 4, 6, 5, 7, 32, 37, 40, 41, 35, 42, 50, 48, 11, 12, 46, 51, 63, 64, 67, 68, 66, 71, 70, 54, 58, 60, 59,
								   45, 61, 72, 74, 127, 86, 89, 69, 107, 108, 111, 112, 114, 113, 119, 120, 174, 123, 118, 181, 186, 187, 158, 191,
								   192, 195, 196, 193, 198, 199, 201, 202,
								   255,
								   255,
								   237,
								   240,
								   239,
								   241,
								   255,
								   255,
								   255,
								   255,
								   244,
								   221,
								   0};

static int ie_extension_id = 0;
static uint8_t ie_extension[50] = {
	IE_EXT_11_ESTIMATED_SERVICE_PARAMETERS_INBOUND,
	IE_EXT_14_FUTURE_CHANNEL_GUIDANCE,
	IE_EXT_52_MAX_CHNNEL_SWITCH_TIME,
	IE_EXT_53_ESTIMATED_SERVICE_PARAMETERS_OUTBOUND,
	IE_EXT_15_SERVICE_HINT,
	IE_EXT_16_SERVICE_HASH,
	0};

static FUZZING_VALUE_TYPE fuzzing_value_step = VALUE_ALL_BITS_ZERO;
static FUZZING_TYPE fuzzing_step = NOT_PRESENT;

static int ieee2020 = 0;
static int ieee2020_id = 0;

void save_beacon_state()
{
}

void load_beacon_state()
{
}

struct packet create_ap_beacon(struct ether_addr bssid, char adhoc, enum AP_AUTH_TYPE auth_type)
{
	struct packet beacon = {0};
	struct beacon_fixed *bf;
	static uint64_t internal_timestamp = 0;
	struct ether_addr bc;
	uint8_t *ie_data;
	uint8_t ie_len;
	uint8_t ie_id;

	MAC_SET_BCAST(bc);
	create_ieee_hdr(&beacon, IEEE80211_TYPE_BEACON, 'a', 0, bc, bssid, bssid, SE_NULLMAC, 0);

	bf = (struct beacon_fixed *)(beacon.data + beacon.len);

	internal_timestamp += 0x400 * DEFAULT_BEACON_INTERVAL; // can't set, always 0
	bf->timestamp = htole64(internal_timestamp);
	bf->interval = htole16(DEFAULT_BEACON_INTERVAL);
	bf->capabilities = 0x0000;
	if (adhoc)
	{
		bf->capabilities |= 0x0002;
	}
	else
	{
		bf->capabilities |= 0x0001;
	}

	if (fuzzing_opt.auth_type > OPEN_NONE)
		bf->capabilities |= 0x0010;

	bf->capabilities |= 0x0400;
	bf->capabilities |= 0x0100;
	bf->capabilities |= 0x8000;

	beacon.len += sizeof(struct beacon_fixed);

	ie_len = strlen(fuzzing_opt.target_ssid);
	if (ie_len)
	{
		beacon.data[beacon.len] = 0;
		beacon.data[beacon.len + 1] = ie_len;
		memcpy(beacon.data + beacon.len + 2, fuzzing_opt.target_ssid, ie_len);
		beacon.len += (2 + ie_len);
	}
	else
	{
		add_default_ie_data(&beacon, 0);
	}

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

	add_default_ie_data(&beacon, 50);
	add_default_ie_data(&beacon, 42);

	ie_data = (uint8_t *)IE_74_OVERLAPPING_BSS_SCAN_PARAMETERS_DATA;
	ie_id = ie_data[0];
	ie_len = ie_data[1];
	add_ie_data(&beacon, ie_id, SPECIFIC_VALUE, ie_data + 2, ie_len);

	// add_default_ie_data(&beacon, 11); //BSS Load
	// add_default_ie_data(&beacon, 45); //HT
	// add_default_ie_data(&beacon, 61);

	switch (auth_type)
	{
	case OPEN_NONE:
		break;
	case OPEN_WEP:
		break;
	case SHARE_WEP:
		break;
	case WPA_PSK_TKIP:
		ie_data = (uint8_t *)IE_221_VENDOR_SPECIFIC_WPA_TKIP;
		ie_id = ie_data[0];
		ie_len = ie_data[1];
		add_ie_data(&beacon, ie_id, SPECIFIC_VALUE, ie_data + 2, ie_len);
		break;
	case WPA_PSK_AES:
		ie_data = (uint8_t *)IE_221_VENDOR_SPECIFIC_WPA_AES;
		ie_id = ie_data[0];
		ie_len = ie_data[1];
		add_ie_data(&beacon, ie_id, SPECIFIC_VALUE, ie_data + 2, ie_len);
		break;
	case WPA_PSK_TKIP_AES:
		ie_data = (uint8_t *)IE_221_VENDOR_SPECIFIC_WPA_TKIP_AES;
		ie_id = ie_data[0];
		ie_len = ie_data[1];
		add_ie_data(&beacon, ie_id, SPECIFIC_VALUE, ie_data + 2, ie_len);
		break;
	case WPA2_PSK_TKIP:
		ie_data = (uint8_t *)IE_48_RSN_WPA2_TKIP;
		ie_id = ie_data[0];
		ie_len = ie_data[1];
		add_ie_data(&beacon, ie_id, SPECIFIC_VALUE, ie_data + 2, ie_len);
		break;
	case WPA2_PSK_AES:
		ie_data = (uint8_t *)IE_48_RSN_WPA2_AES;
		ie_id = ie_data[0];
		ie_len = ie_data[1];
		add_ie_data(&beacon, ie_id, SPECIFIC_VALUE, ie_data + 2, ie_len);
		break;
	case WPA2_PSK_TKIP_AES:
		ie_data = (uint8_t *)IE_48_RSN_WPA2_TKIP_AES;
		ie_id = ie_data[0];
		ie_len = ie_data[1];
		add_ie_data(&beacon, ie_id, SPECIFIC_VALUE, ie_data + 2, ie_len);
		break;
	case EAP_8021X:
		ie_data = (uint8_t *)IE_48_RSN_8021X_BEACON;
		ie_id = ie_data[0];
		ie_len = ie_data[1];
		add_ie_data(&beacon, ie_id, SPECIFIC_VALUE, ie_data + 2, ie_len);
		break;
	case WPA3:
		ie_data = (uint8_t *)IE_48_RSN_WPA3_AES_BEACON;
		ie_id = ie_data[0];
		ie_len = ie_data[1];
		add_ie_data(&beacon, ie_id, SPECIFIC_VALUE, ie_data + 2, ie_len);
		break;
	default:
		break;
	}

	/*ie_data = IE_221_VENDOR_SPECIFIC_HUAWEI_1;
	ie_id = ie_data[0];
	ie_len = ie_data[1];
	add_ie_data(&beacon, ie_id, SPECIFIC_VALUE, ie_data + 2, ie_len);*/

	/*
		ie_data = IE_221_VENDOR_SPECIFIC_WPS;
		ie_id = ie_data[0];
		ie_len = ie_data[1];
		add_ie_data(&beacon, ie_id, SPECIFIC_VALUE, ie_data + 2, ie_len);*/

	ie_data = (uint8_t *)IE_221_VENDOR_SPECIFIC_WMM_WME;
	ie_id = ie_data[0];
	ie_len = ie_data[1];
	add_ie_data(&beacon, ie_id, SPECIFIC_VALUE, ie_data + 2, ie_len);

	/*ie_data = IE_221_VENDOR_SPECIFIC_HUAWEI_2;
	ie_id = ie_data[0];
	ie_len = ie_data[1];
	add_ie_data(&beacon, ie_id, SPECIFIC_VALUE, ie_data + 2, ie_len);*/

	// add_default_ie_data(&beacon, 221);

	// fuzz_logger_log(FUZZ_LOG_INFO, "Beacon testing ==> pkg length %d", beacon.len);

	return beacon;
}

struct packet create_beacon(struct ether_addr bssid, char adhoc, char *ssid)
{
	struct packet beacon = {0};
	struct beacon_fixed *bf;
	static uint64_t internal_timestamp = 0;
	struct ether_addr bc;
	uint8_t *ie_data;
	uint8_t ie_len;
	uint8_t ie_id;
	int i, j;

	// bssid.ether_addr_octet[5] += 1;

	MAC_SET_BCAST(bc);
	create_ieee_hdr(&beacon, IEEE80211_TYPE_BEACON, 'a', 0, bc, bssid, bssid, SE_NULLMAC, 0);

	bf = (struct beacon_fixed *)(beacon.data + beacon.len);

	internal_timestamp += 0x400 * DEFAULT_BEACON_INTERVAL;
	bf->timestamp = htole64(internal_timestamp);
	bf->interval = htole16(DEFAULT_BEACON_INTERVAL);
	if (0 == fuzzing_opt.seed)
		srandom(time(NULL));

	bf->capabilities = random() % 0xffff;
	/*bf->capabilities = 0x0000;
	if (adhoc) {
		bf->capabilities |= 0x0002;
	}else{
		bf->capabilities |= 0x0001;
	}

	bf->capabilities |= 0x0010;*/

	beacon.len += sizeof(struct beacon_fixed);

	for (i = 0; i < fuzzing_opt.cur_sfs_cnt; i++)
	{
		if (fuzzing_opt.sfs[i].frame_type == IEEE80211_TYPE_BEACON && fuzzing_opt.sfs[i].bset == 1)
		{
			for (j = 0; j < fuzzing_opt.sfs[i].ie_cnt; j++)
			{
				add_ie_data(&beacon, fuzzing_opt.sfs[i].sies[j].id, SPECIFIC_VALUE, fuzzing_opt.sfs[i].sies[j].value, fuzzing_opt.sfs[i].sies[j].len);
			}
			break;
		}
	}

	if (fuzzing_opt.sfs[i].frame_type != IEEE80211_TYPE_BEACON)
	{
		add_ie_data(&beacon, 0, SPECIFIC_VALUE, (uint8_t *)fuzzing_opt.target_ssid, strlen(fuzzing_opt.target_ssid));

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
	}

	create_frame_fuzzing_ie(&beacon, "Beacon", beacon_ie_ieee2020, &ieee2020, &ieee2020_id, ie_extension, &ie_extension_id, &fuzzing_step, &fuzzing_value_step);

	/*create_frame_fuzzing_ies(&beacon, "Beacon",
		beacon_ie_ieee1999,
		beacon_ie_ieee2007,
		beacon_ie_ieee2012,
		beacon_ie_ieee2016,
		&ieee1999,
		&ieee1999_id,
		&ieee2007,
		&ieee2007_id,
		&ieee2012,
		&ieee2012_id,
		&ieee2016,
		&ieee2016_id,
		&fuzzing_step,
		&fuzzing_value_step);*/

	return beacon;
}

void create_beacon_fuzzing_ies(struct packet *pkt)
{
	create_frame_fuzzing_ie(pkt, "Beacon", beacon_ie_ieee2020, &ieee2020, &ieee2020_id, ie_extension, &ie_extension_id, &fuzzing_step, &fuzzing_value_step);
}
