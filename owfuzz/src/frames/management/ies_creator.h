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

#ifndef IES_CREATOR_H
#define IES_CREATOR_H

#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include "ieee80211_ie.h"
#include "../80211_packet_common.h"

typedef void (*PF_IE_CREATOR)(struct packet *pkt, FUZZING_TYPE fuzzing_type, uint8_t *specific_data, int specific_data_len);

struct ie_creator
{
	uint8_t id;
	PF_IE_CREATOR pf_ie_creator;
} __attribute__((packed));

struct ie_range
{
	uint8_t id;
	int max_length;
	int min_length;
} __attribute__((packed));

typedef enum _IEEE_80211_VERSION
{
	IEEE_80211_1999,
	IEEE_80211_2007,
	IEEE_80211_2012,
	IEEE_80211_2016,
	IEEE_80211_2020,
	IEEE_80211_UNKNOWN
} IEEE_80211_VERSION;

#define DEFAULT_SSID "wf_testing"

#define IE_221_VENDOR_SPECIFIC_WPA_TKIP "\xdd\x18\x00\x50\xf2\x01\x01\x00\x00\x50\xf2\x02\x01\x00\x00\x50\xf2\x02\x01\x00\x00\x50\xf2\x02\x0c\x00"
#define IE_221_VENDOR_SPECIFIC_WPA_AES "\xdd\x18\x00\x50\xf2\x01\x01\x00\x00\x50\xf2\x04\x01\x00\x00\x50\xf2\x04\x01\x00\x00\x50\xf2\x02\x0c\x00"
#define IE_221_VENDOR_SPECIFIC_WPA_TKIP_AES "\xdd\x1c\x00\x50\xf2\x01\x01\x00\x00\x50\xf2\x02\x02\x00\x00\x50\xf2\x04\x00\x50\xf2\x02\x01\x00\x00\x50\xf2\x02\x0c\x00"

#define IE_48_RSN_WPA2_TKIP "\x30\x14\x01\x00\x00\x0f\xac\x02\x01\x00\x00\x0f\xac\x02\x01\x00\x00\x0f\xac\x02\x0c\x00"
#define IE_48_RSN_WPA2_AES "\x30\x14\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x02\x0c\x00"
#define IE_48_RSN_WPA2_TKIP_AES "\x30\x18\x01\x00\x00\x0f\xac\x02\x02\x00\x00\x0f\xac\x04\x00\x0f\xac\x02\x01\x00\x00\x0f\xac\x02\x0c\x00"

#define IE_48_RSN_WPA3_AES_ASSOCREQ "\x30\x1a\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x08\xc0\x00\x00\x00\x00\x0f\xac\x06"
#define IE_48_RSN_WPA3_AES_BEACON "\x30\x14\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x08\xc0\x00"
#define IE_48_RSN_8021X_BEACON "\x30\x14\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x01\x00\x00"

#define IE_74_OVERLAPPING_BSS_SCAN_PARAMETERS_DATA "\x4a\x0e\x14\x00\x0a\x00\x2c\x01\xc8\x00\x14\x00\x05\x00\x19\x00"

#define IE_221_VENDOR_SPECIFIC_WPS "\xdd\x23\x00\x50\xf2\x04\x10\x4a\x00\x01\x10\x10\x44\x00\x01\x02\x10\x08\x00\x02\x07\x80\x10\x3c\x00\x01\x01\x10\x49\x00\x06\x00\x37\x2a\x00\x01\x20"

#define IE_221_VENDOR_SPECIFIC_WMM_WME "\xdd\x18\x00\x50\xf2\x02\x01\x01\x00\x00\x03\xa4\x00\x00\x27\xa4\x00\x00\x42\x43\x5e\x00\x62\x32\x2f\x00"

#define IE_221_VENDOR_SPECIFIC_HUAWEI_1 "\xdd\x08\xac\x85\x3d\x82\x01\x00\x00\x00"
#define IE_221_VENDOR_SPECIFIC_HUAWEI_2 "\xdd\x4d\x00\xe0\xfc\x40\x00\x00\x00\x01\x00\xfe\x3c\x09\x00\x00\x0d\x0d\x00\x12\x14\x00\x19\x1b\x00\x23\x28\x00\x28\x37\x00\x2f\x3f\x00\x37\x48\x00\x5d\x51\x00\x5d\x58\x00\x5d\x58\x00\x5d\x58\x00\x5d\x58\x00\x5d\x58\x00\x5d\x58\x00\x5d\x58\x00\x5d\x58\x00\x5d\x58\x00\x5d\x58\x00\x64\x58\x00\xfd\x04\xa8\x00\x00\xa8"

#define IE_1_SUPPORTTED_RATES_B "\x01\x08\x82\x84\x8b\x96\x12\x24\x48\x6c"
#define IE_1_SUPPORTTED_RATES_G "\x01\x04\x12\x24\x48\x6c"
#define IE_1_SUPPORTTED_RATES_N_AC "\x01\x08\x8c\x12\x98\x24\xb0\x48\x60\x6c"
#define IE_1_SUPPORTTED_RATES_AC ""

#define IE_61_HT_INFORMATION "\x3d\x16\x30\x07\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

void init_ie_creator();
void add_ie_data(struct packet *pkt, uint8_t id, FUZZING_TYPE fuzzing_type, uint8_t *specific_data, int specific_data_len);
void add_default_ie_data(struct packet *pkt, uint8_t id);
struct ie_data get_ie_data_by_fuzzing_type(IEEE_80211_VERSION ieee80211_version,
										   uint8_t id,
										   FUZZING_TYPE fuzzing_type,
										   FUZZING_VALUE_TYPE value_type,
										   uint8_t *specific_data,
										   int specific_data_len);

struct ie_data get_ie_ex_data_by_fuzzing_type(IEEE_80211_VERSION ieee80211_version,
											  uint8_t id,
											  uint8_t ex_id,
											  FUZZING_TYPE fuzzing_type,
											  FUZZING_VALUE_TYPE value_type,
											  uint8_t *specific_data,
											  int specific_data_len);

void create_frame_ies(struct packet *pkt,
					  char *frame_name,
					  uint8_t frame_ie_ieee1999[],
					  uint8_t frame_ie_ieee2007[],
					  uint8_t frame_ie_ieee2012[],
					  uint8_t frame_ie_ieee2016[],
					  int *ieee1999,
					  int *ieee1999_id,
					  int *ieee2007,
					  int *ieee2007_id,
					  int *ieee2012,
					  int *ieee2012_id,
					  int *ieee2016,
					  int *ieee2016_id,
					  FUZZING_TYPE *fuzzing_step,
					  FUZZING_VALUE_TYPE *fuzzing_value_step);

void create_frame_fuzzing_ie(struct packet *pkt,
							 char *frame_name,
							 uint8_t frame_ies[],
							 int *ieee_ver,
							 int *ieee_id,
							 uint8_t frame_ies_ext[],
							 int *ies_ext_id,
							 FUZZING_TYPE *fuzzing_step,
							 FUZZING_VALUE_TYPE *fuzzing_value_step);

void create_radom_ie(struct packet *pkt,
					 IEEE_80211_VERSION ieee80211_version,
					 int ieee_ie_id);

void create_frame_fuzzing_ies(struct packet *pkt,
							  char *frame_name,
							  uint8_t frame_ie_ieee1999[],
							  uint8_t frame_ie_ieee2007[],
							  uint8_t frame_ie_ieee2012[],
							  uint8_t frame_ie_ieee2016[],
							  int *ieee1999,
							  int *ieee1999_id,
							  int *ieee2007,
							  int *ieee2007_id,
							  int *ieee2012,
							  int *ieee2012_id,
							  int *ieee2016,
							  int *ieee2016_id,
							  FUZZING_TYPE *fuzzing_step,
							  FUZZING_VALUE_TYPE *fuzzing_value_step);

int add_attribute_tlv_fuzzing_data(struct packet *pkt, struct vendor_specific_ie *vsi, uint8_t id);
int add_data_element_tlv_fuzzing_data(struct packet *pkt, struct vendor_specific_ie *vsi, uint16_t id);

uint8_t get_ie_status(uint8_t ie_type, uint8_t is_ext);

#endif
