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

#include "authentication.h"
#include "ies_creator.h"
#include <stdio.h>
#include <time.h>

extern fuzzing_option fuzzing_opt;

uint8_t authentication_ie_ieee1999[10] = {16, 0};
uint8_t authentication_ie_ieee2007[10] = {16, 221, 0};
uint8_t authentication_ie_ieee2012[30] = {16, 48, 54, 55, 56, 75, 221, 0};
uint8_t authentication_ie_ieee2016[50] = {16, 48, 54, 55, 56, 75, 158, 52, 221, 0};
uint8_t authentication_ie_ieee2020[50] = {
	16, 48, 54, 55, 56, 75, 57, 158, 52,
	255,
	255,
	255,
	255,
	255,
	255,
	255,
	221,
	0};

static int ie_extension_id = 0;
static uint8_t ie_extension[50] = {
	IE_EXT_13_FILS_NONCE,
	IE_EXT_4_FILS_SESSION,
	IE_EXT_8_FILS_WRAPPED_DATA,
	IE_EXT_1_ASSOCIATION_DELAY_INFO,
	IE_EXT_33_PASSWORD_IDENTIFIER,
	IE_EXT_92_REJECTED_GROUPS,
	IE_EXT_93_ANTI_CLOGGING_TOKEN_CONTAINER,
	0};

static FUZZING_VALUE_TYPE fuzzing_value_step = VALUE_ALL_BITS_ZERO;
static FUZZING_TYPE fuzzing_step = NOT_PRESENT;

static int ieee2020 = 0;
static int ieee2020_id = 0;

void save_authentication_state()
{
}

void load_authentication_state()
{
}

// algorithm
// 0 open system
// 1 shared key
// 2 fast bss transition
// 3 simultaneous authentication of equals
struct packet create_authentication(struct ether_addr bssid, struct ether_addr smac, struct ether_addr dmac, char adhoc, struct packet *recv_pkt)
{
	struct packet authentication = {0};
	struct authentication_fixed *af, *raf;
	struct wep_param *wp;
	struct SAE_Commit *sae_commit, *rsae_commit;
	struct SAE_Confirm *sae_confirm, *rsae_confirm;
	int rlen = 0;

	create_ieee_hdr(&authentication, IEEE80211_TYPE_AUTH, 'a', 0x013A, dmac, smac, bssid, SE_NULLMAC, 0);

	af = (struct authentication_fixed *)(authentication.data + authentication.len);

	if (recv_pkt) // received auth pkt:2,3,4
	{
		raf = (struct authentication_fixed *)(recv_pkt->data + sizeof(struct ieee_hdr));
		if (fuzzing_opt.auth_type == WPA3) // 3 simultaneous authentication of equals(SAE)
		{
			af->algorithm = raf->algorithm;
			af->seq = raf->seq;
			af->status_code = 0x0000;
			authentication.len += sizeof(struct authentication_fixed);

			if (af->seq == 1) // commit
			{
				print_interaction_status(bssid, dmac, smac, "SAE-Auth1-Commit-1", "SAE-Auth1-Commit-2");
				rsae_commit = (struct SAE_Commit *)(recv_pkt->data + sizeof(struct ieee_hdr) + sizeof(struct authentication_fixed));
				sae_commit = (struct SAE_Commit *)(authentication.data + authentication.len);
				sae_commit->message_type = rsae_commit->message_type;
				sae_commit->group_id = rsae_commit->group_id;
				generate_random_data(sae_commit->scalar, sizeof(sae_commit->scalar), VALUE_RANDOM);
				generate_random_data(sae_commit->finite_field_element, sizeof(sae_commit->finite_field_element), VALUE_RANDOM);
				authentication.len += sizeof(struct SAE_Commit);
			}
			else if (af->seq == 2) // confirm
			{
				print_interaction_status(bssid, dmac, smac, "SAE-Auth2-Confirm-1", "SAE-Auth2-Confirm-2");
				rsae_confirm = (struct SAE_Confirm *)(recv_pkt->data + sizeof(struct ieee_hdr) + sizeof(struct authentication_fixed));
				sae_confirm = (struct SAE_Confirm *)(authentication.data + authentication.len);
				sae_confirm->message_type = rsae_confirm->message_type;
				sae_confirm->send_confirm = rsae_confirm->send_confirm;
				generate_random_data(sae_confirm->confirm, sizeof(sae_confirm->confirm), VALUE_RANDOM);
				authentication.len += sizeof(struct SAE_Confirm);

				fuzzing_opt.wpa_s = WPA_ASSOCIATING;
			}
		}
		else if (fuzzing_opt.auth_type == EAP_8021X || fuzzing_opt.auth_type == WPA2_PSK_TKIP_AES || fuzzing_opt.auth_type == WPA2_PSK_AES || fuzzing_opt.auth_type == WPA2_PSK_TKIP ||
				 fuzzing_opt.auth_type == WPA_PSK_TKIP_AES || fuzzing_opt.auth_type == WPA_PSK_AES || fuzzing_opt.auth_type == WPA_PSK_TKIP ||
				 fuzzing_opt.auth_type == OPEN_NONE) // 0 open system
		{
			if (raf->seq == 1)
			{
				print_interaction_status(bssid, dmac, smac, "Open-Auth1", "Open-Auth2");
				af->algorithm = raf->algorithm;
				af->seq = raf->seq + 1;
				af->status_code = 0x0000;
				authentication.len += sizeof(struct authentication_fixed);

				create_frame_fuzzing_ie(&authentication, "Authentication", authentication_ie_ieee2020, &ieee2020, &ieee2020_id, ie_extension, &ie_extension_id, &fuzzing_step, &fuzzing_value_step);

				/*create_frame_fuzzing_ies(&authentication, "Authentication",
					authentication_ie_ieee1999,
					authentication_ie_ieee2007,
					authentication_ie_ieee2012,
					authentication_ie_ieee2016,
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

				// fuzzing_opt.wpa_s = WPA_ASSOCIATING;
			}
			else if (raf->seq == 2)
			{
				print_interaction_status(bssid, dmac, smac, "Open-Auth2", "");
				fuzzing_opt.wpa_s = WPA_ASSOCIATING;
			}
		}
		else if (fuzzing_opt.auth_type == OPEN_WEP || fuzzing_opt.auth_type == SHARE_WEP) // 1 shared key
		{
			af->algorithm = raf->algorithm;
			af->seq = raf->seq + 1;
			af->status_code = 0x0000;

			if (af->seq == 2)
			{
				authentication.len += sizeof(struct authentication_fixed);
				print_interaction_status(bssid, dmac, smac, "WEP-Auth1", "WEP-Auth2");
				add_ie_data(&authentication, 16, RANDOM_VALUE, NULL, 0);

				create_frame_fuzzing_ie(&authentication, "Authentication", authentication_ie_ieee2020, &ieee2020, &ieee2020_id, ie_extension, &ie_extension_id, &fuzzing_step, &fuzzing_value_step);

				/*create_frame_fuzzing_ies(&authentication, "Authentication",
					authentication_ie_ieee1999,
					authentication_ie_ieee2007,
					authentication_ie_ieee2012,
					authentication_ie_ieee2016,
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
			}
			else if (af->seq == 3)
			{
				print_interaction_status(bssid, dmac, smac, "WEP-Auth2", "WEP-Auth3(Data)");
				// TODO: add WEP Parameters
				// Initialization
				// Key Index
				wp = (struct wep_param *)(authentication.data + authentication.len);
				generate_random_data(wp->init_vector, sizeof(wp->init_vector), VALUE_RANDOM);
				wp->key_index = 0;
				authentication.len += sizeof(struct wep_param);
				if (0 == fuzzing_opt.seed)
					srandom(time(NULL));

				rlen = random() % 256;
				generate_random_data(authentication.data + authentication.len, rlen, VALUE_RANDOM);
				authentication.len += rlen;
				// WEP ICV， 4bytes
				generate_random_data(authentication.data + authentication.len, 4, VALUE_RANDOM);
				authentication.len += 4;
			}
			else /* if(af->seq == 4)*/
			{
				af->algorithm = 1;
				af->seq = 4;
				af->status_code = 0x0000;
				authentication.len += sizeof(struct authentication_fixed);
				print_interaction_status(bssid, dmac, smac, "WEP-Auth3(Data)", "WEP-Auth4");

				create_frame_fuzzing_ie(&authentication, "Authentication", authentication_ie_ieee2020, &ieee2020, &ieee2020_id, ie_extension, &ie_extension_id, &fuzzing_step, &fuzzing_value_step);

				/*create_frame_fuzzing_ies(&authentication, "Authentication",
					authentication_ie_ieee1999,
					authentication_ie_ieee2007,
					authentication_ie_ieee2012,
					authentication_ie_ieee2016,
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

				fuzzing_opt.wpa_s = WPA_ASSOCIATING;
			}
		}
	}
	else
	{
		fuzzing_opt.wpa_s = WPA_AUTHENTICATING;

		if (fuzzing_opt.auth_type == WPA3) // 3 simultaneous authentication of equals(SAE)
		{
			print_interaction_status(bssid, dmac, smac, "Probe Response", "SAE-Auth1-Commit");
			af->algorithm = 3;
			af->seq = 1;
			af->status_code = 0x0000;
			authentication.len += sizeof(struct authentication_fixed);

			if (af->seq == 1) // commit
			{
				sae_commit = (struct SAE_Commit *)(authentication.data + authentication.len);
				sae_commit->message_type = 0x01;
				if (0 == fuzzing_opt.seed)
					srandom(time(NULL));

				sae_commit->group_id = random() % (0xFFFF + 1);
				generate_random_data(sae_commit->scalar, sizeof(sae_commit->scalar), VALUE_RANDOM);
				generate_random_data(sae_commit->finite_field_element, sizeof(sae_commit->finite_field_element), VALUE_RANDOM);
				authentication.len += sizeof(struct SAE_Commit);
			}
		}
		else if (fuzzing_opt.auth_type == EAP_8021X || fuzzing_opt.auth_type == WPA2_PSK_TKIP_AES || fuzzing_opt.auth_type == WPA2_PSK_AES || fuzzing_opt.auth_type == WPA2_PSK_TKIP ||
				 fuzzing_opt.auth_type == WPA_PSK_TKIP_AES || fuzzing_opt.auth_type == WPA_PSK_AES || fuzzing_opt.auth_type == WPA_PSK_TKIP ||
				 fuzzing_opt.auth_type == OPEN_NONE) // 0 open system
		{
			print_interaction_status(bssid, dmac, smac, "Probe Response", "Open-Auth1");
			af->algorithm = 0;
			af->seq = 1;
			af->status_code = 0x0000;
			authentication.len += sizeof(struct authentication_fixed);

			create_frame_fuzzing_ie(&authentication, "Authentication", authentication_ie_ieee2020, &ieee2020, &ieee2020_id, ie_extension, &ie_extension_id, &fuzzing_step, &fuzzing_value_step);

			/*create_frame_fuzzing_ies(&authentication, "Authentication",
				authentication_ie_ieee1999,
				authentication_ie_ieee2007,
				authentication_ie_ieee2012,
				authentication_ie_ieee2016,
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
		}
		else if (fuzzing_opt.auth_type == OPEN_WEP || fuzzing_opt.auth_type == SHARE_WEP) // 1 shared key
		{
			print_interaction_status(bssid, dmac, smac, "Probe Response", "WEP-Auth1");
			af->algorithm = 1;
			af->seq = 1;
			af->status_code = 0x0000;
			authentication.len += sizeof(struct authentication_fixed);
		}
	}

	// fuzz_logger_log(FUZZ_LOG_INFO, "Authentication testing ==> ");

	return authentication;
}
