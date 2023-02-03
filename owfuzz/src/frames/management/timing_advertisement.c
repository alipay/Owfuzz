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

#include "timing_advertisement.h"
#include "ies_creator.h"

extern fuzzing_option fuzzing_opt;

uint8_t timing_advertisement_ie_ieee1999[10] = {0xff, 0};
uint8_t timing_advertisement_ie_ieee2007[10] = {0xff, 0};
uint8_t timing_advertisement_ie_ieee2012[30] = {7, 32, 69, 127, 221, 0};
uint8_t timing_advertisement_ie_ieee2016[30] = {7, 32, 69, 127, 221, 0};
uint8_t timing_advertisement_ie_ieee2020[30] = {7, 32, 69, 127, 221, 0};

static int ie_extension_id = 0;
static uint8_t ie_extension[50] = {
	0xff, 0};

static FUZZING_VALUE_TYPE fuzzing_value_step = VALUE_ALL_BITS_ZERO;
static FUZZING_TYPE fuzzing_step = NOT_PRESENT;

static int ieee2020 = 0;
static int ieee2020_id = 0;

void save_timing_advertisement_state()
{
}

void load_timing_advertisement_state()
{
}

struct packet create_timing_advertisement(struct ether_addr bssid, struct ether_addr dmac, char adhoc)
{
	struct packet timing_advertisement = {0};
	struct timing_advertisement_fixed *taf;
	static uint64_t internal_timestamp = 0;
	struct ether_addr bc;
	int i, j;

	MAC_SET_BCAST(bc);
	create_ieee_hdr(&timing_advertisement, IEEE80211_TYPE_TIMADVERT, 'a', 0, bc, bssid, bssid, SE_NULLMAC, 0);

	taf = (struct beacon_fixed *)(timing_advertisement.data + timing_advertisement.len);
	internal_timestamp += 0x400 * 0x64;
	taf->timestamp = htole64(internal_timestamp);
	taf->capabilities = 0x0000;

	timing_advertisement.len += sizeof(struct timing_advertisement_fixed);

	for (i = 0; i < fuzzing_opt.cur_sfs_cnt; i++)
	{
		if (fuzzing_opt.sfs[i].frame_type == IEEE80211_TYPE_TIMADVERT && fuzzing_opt.sfs[i].bset == 1)
		{
			for (j = 0; j < fuzzing_opt.sfs[i].ie_cnt; j++)
			{
				add_ie_data(&timing_advertisement, fuzzing_opt.sfs[i].sies[j].id, SPECIFIC_VALUE, fuzzing_opt.sfs[i].sies[j].value, fuzzing_opt.sfs[i].sies[j].len);
			}
			break;
		}
	}

	if (fuzzing_opt.sfs[i].frame_type != IEEE80211_TYPE_TIMADVERT)
	{
	}

	create_frame_fuzzing_ie(&timing_advertisement, "Timing advertisement", timing_advertisement_ie_ieee2020, &ieee2020, &ieee2020_id, ie_extension, &ie_extension_id, &fuzzing_step, &fuzzing_value_step);

	/*create_frame_fuzzing_ies(&timing_advertisement, "Timing advertisement",
		timing_advertisement_ie_ieee1999,
		timing_advertisement_ie_ieee2007,
		timing_advertisement_ie_ieee2012,
		timing_advertisement_ie_ieee2016,
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

	return timing_advertisement;
}