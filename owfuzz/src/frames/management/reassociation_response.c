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

#include "ies_creator.h"
#include "reassociation_response.h"

extern fuzzing_option fuzzing_opt;

uint8_t reassociation_response_ie_ieee1999[10] = {1, 0};
uint8_t reassociation_response_ie_ieee2007[10] = {1, 50, 12, 221, 0};
uint8_t reassociation_response_ie_ieee2012[30] = {1, 50, 12, 53, 65, 70, 54, 55, 58, 56, 45, 61, 72, 74, 127, 90, 95, 110, 221, 0};
uint8_t reassociation_response_ie_ieee2016[50] = {
	1, 50, 12, 53, 65, 70, 54, 55, 58, 56, 45,		  // 10
	61, 72, 74, 127, 90, 95, 110, 181, 158, 148, 151, // 20
	170, 52, 191, 192, 199, 255, 221, 0};

uint8_t reassociation_response_ie_ieee2020[54] = {
	1, 50, 12, 53, 65, 70, 54, 55, 58, 56,			  // 10
	45, 61, 72, 74, 127, 90, 95, 110, 181, 158,		  // 20
	148, 151, 170, 52, 191, 192, 199, 255, 255, 255,  // 30
	255, 255, 255, 255, 212, 216, 223, 217, 232, 211, // 40
	231, 224, 233, 234, 235, 236, 255, 255, 255, 255, // 50
	244, 255, 221, 0};

static int ie_extension_id = 0;
static uint8_t ie_extension[50] = {
	IE_EXT_14_FUTURE_CHANNEL_GUIDANCE,
	IE_EXT_4_FILS_SESSION,
	IE_EXT_12_FILS_PUBLIC_KEY,
	IE_EXT_3_FILS_KEY_CONFIRMATION,
	IE_EXT_5_FILS_HLP_CONTAINER,
	IE_EXT_6_FILS_IP_ADDRESS_ASSIGNMENT,
	IE_EXT_7_KEY_DELIVERY,
	IE_EXT_17_CDMG_CAPABILITIES,
	IE_EXT_27_CMMG_CAPABILITIES,
	IE_EXT_28_CMMG_OPERATION,
	IE_EXT_34_GLK_GCR_PARAMETER_SET,
	IE_EXT_88_MSCS_DESCRIPTOR,
	0};

static FUZZING_VALUE_TYPE fuzzing_value_step = VALUE_ALL_BITS_ZERO;
static FUZZING_TYPE fuzzing_step = NOT_PRESENT;

static int ieee2020 = 0;
static int ieee2020_id = 0;

static int g_aid = 0x0001;

void save_reassociation_response_state()
{
}

void load_reassociation_response_state()
{
}

struct packet create_reassociation_response(struct ether_addr bssid, struct ether_addr dmac, char adhoc)
{
	struct packet association_response = {0};
	struct association_response_fixed *arf;

	create_ieee_hdr(&association_response, IEEE80211_TYPE_REASSOCRES, 'a', 0x013A, dmac, bssid, bssid, SE_NULLMAC, 0);

	arf = (struct association_response_fixed *)(association_response.data + association_response.len);

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

	association_response.len += sizeof(struct association_response_fixed);

	add_default_ie_data(&association_response, 1);

	create_frame_fuzzing_ie(&association_response, "Reassociation Response", reassociation_response_ie_ieee2020, &ieee2020, &ieee2020_id, ie_extension, &ie_extension_id, &fuzzing_step, &fuzzing_value_step);

	/*create_frame_fuzzing_ies(&association_response,
					"Reassociation response",
					reassociation_response_ie_ieee1999,
					reassociation_response_ie_ieee2007,
					reassociation_response_ie_ieee2012,
					reassociation_response_ie_ieee2016,
					&ieee1999,
					&ieee1999_id,
					&ieee2007,
					&ieee2007_id,
					&ieee2012,
					&ieee2012_id,
					&ieee2016,
					&ieee2016_id,
					&fuzzing_step,
					&fuzzing_value_step
					);*/

	return association_response;
}
