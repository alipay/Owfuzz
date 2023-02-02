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

#include "probe_response.h"
#include "ies_creator.h"

extern fuzzing_option fuzzing_opt;

uint8_t probe_response_ie_ieee1999[10] = {0, 1, 2, 3, 4, 6, 0};
uint8_t probe_response_ie_ieee2007[30] = {0, 1, 2, 3, 4, 6, 7, 8, 9, 32, 37, 40, 41, 35, 42, 50, 48, 11, 12, 221, 0};
uint8_t probe_response_ie_ieee2012[80] = {0, 1, 2, 3, 4, 6, 7, 8, 9, 32, 37, 40, 41, 35, 42, 50, 48, 11, 12, 51, 63, 64, 67, 68, 66, 71, 70, 54, 58, 60, 59,
										  45, 61, 72, 74, 127, 86, 89, 97, 69, 98, 107, 108, 111, 112, 114, 113, 119, 120, 174, 123, 118, 221, 0};
uint8_t probe_response_ie_ieee2016[100] = {0, 1, 3, 4, 6, 7, 32, 37, 40, 41, 35, 42, 50, 48, 11, 12, 46, 51, 63, 64, 67, 68, 66, 71, 70, 54, 58, 60, 59,
										   45, 61, 72, 74, 127, 86, 89, 69, 107, 108, 111, 112, 114, 113, 119, 120, 174, 123, 118, 181, 186, 158, 148, 151, 170,
										   190, 191, 192, 195, 196, 193, 198, 199, 201, 202, 255, 167, 221, 0};
uint8_t probe_response_ie_ieee2020[100] = {0, 1, 3, 4, 6, 5, 7, 32, 37, 40, 41, 35, 42, 50, 48, 11, 12, 46, 51, 63, 64, 67, 68, 66, 71, 70, 54, 58, 60, 59,
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

void save_probe_response_state()
{
}

void load_probe_response_state()
{
}

struct packet create_ap_probe_response(struct ether_addr bssid, char adhoc, enum AP_AUTH_TYPE auth_type)
{
	return create_ap_beacon(bssid, adhoc, auth_type);
}

struct packet create_probe_response(struct ether_addr bssid, struct ether_addr dmac, char adhoc, char *ssid,
									uint8_t *request_elements, int request_elements_len)
{
	struct packet beacon = {0};
	struct beacon_fixed *bf;
	static uint64_t internal_timestamp = 0;
	uint8_t *ie_data;
	uint8_t ie_len;
	uint8_t ie_id;
	int i, j;

	create_ieee_hdr(&beacon, IEEE80211_TYPE_PROBERES, 'a', 0x013A, dmac, bssid, bssid, SE_NULLMAC, 0);

	bf = (struct beacon_fixed *)(beacon.data + beacon.len);

	internal_timestamp += 0x400 * DEFAULT_BEACON_INTERVAL;
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

	beacon.len += sizeof(struct beacon_fixed);

	for (i = 0; i < fuzzing_opt.cur_sfs_cnt; i++)
	{
		if (fuzzing_opt.sfs[i].frame_type == IEEE80211_TYPE_PROBERES && fuzzing_opt.sfs[i].bset == 1)
		{
			for (j = 0; j < fuzzing_opt.sfs[i].ie_cnt; j++)
			{
				add_ie_data(&beacon, fuzzing_opt.sfs[i].sies[j].id, SPECIFIC_VALUE, fuzzing_opt.sfs[i].sies[j].value, fuzzing_opt.sfs[i].sies[j].len);
			}
			break;
		}
	}

	if (fuzzing_opt.sfs[i].frame_type != IEEE80211_TYPE_PROBERES)
	{
		if (request_elements != NULL && request_elements_len != 0)
		{
			memcpy(beacon.data + beacon.len, request_elements, request_elements_len);
			beacon.len += request_elements_len;
		}
		else
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
	}

	create_frame_fuzzing_ie(&beacon, "Probe Response", probe_response_ie_ieee2020, &ieee2020, &ieee2020_id, ie_extension, &ie_extension_id, &fuzzing_step, &fuzzing_value_step);

	/*create_frame_fuzzing_ies(&beacon, "Probe response",
		probe_response_ie_ieee1999,
		probe_response_ie_ieee2007,
		probe_response_ie_ieee2012,
		probe_response_ie_ieee2016,
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

void create_probe_response_fuzzing_ies(struct packet *pkt)
{
	create_frame_fuzzing_ie(pkt, "Probe Response", probe_response_ie_ieee2020, &ieee2020, &ieee2020_id, ie_extension, &ie_extension_id, &fuzzing_step, &fuzzing_value_step);
}
