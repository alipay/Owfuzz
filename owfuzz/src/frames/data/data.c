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
#include "data.h"
#include "qos_data.h"
#include "common/wpa_common.h"
#include "crypto/aes.h"
#include "common/eapol_common.h"
#include "eap_common/eap_defs.h"

extern fuzzing_option fuzzing_opt;

struct packet create_data(struct ether_addr bssid, struct ether_addr smac, struct ether_addr dmac, char adhoc, struct packet *recv_pkt)
{
	struct packet data = {0};
	// struct ieee_hdr *hdr;
	struct ieee_hdr *hdr_new;
	struct llc_hdr *llc_h, llc;
	struct ieee802_1x_hdr *ieee8021x_hdr, ieee8021xdhr;
	struct eap_hdr *eaphdr, eap;
	struct ieee8021x_auth *wpa_auth;
	uint8_t eap_type = EAP_TYPE_NONE;
	struct wep_param wp = {0};
	char dsflag = 'a';
	int dlen;

	if (fuzzing_opt.fuzz_work_mode == FUZZ_WORK_MODE_AP)
		dsflag = 'f';
	else if (fuzzing_opt.fuzz_work_mode == FUZZ_WORK_MODE_STA)
		dsflag = 't';

	create_ieee_hdr(&data, IEEE80211_TYPE_DATA, dsflag, 0x013A, dmac, smac, bssid, SE_NULLMAC, 0);
	hdr_new = (struct ieee_hdr *)data.data;

	if (recv_pkt)
	{
		// hdr = (struct ieee_hdr *) recv_pkt->data;

		if (fuzzing_opt.auth_type >= WPA_PSK_TKIP)
		{
			llc_h = (struct llc_hdr *)(recv_pkt->data + sizeof(struct ieee_hdr));
			if (llc_h->type == htons(0x888e) && llc_h->ssap == 0xaa && llc_h->dsap == 0xaa)
			{
				ieee8021x_hdr = (struct ieee802_1x_hdr *)(recv_pkt->data + sizeof(struct ieee_hdr) + sizeof(struct llc_hdr));
				if (ieee8021x_hdr->type == 0x03) // key; m2,m3,m4
				{
					wpa_auth = (struct ieee8021x_auth *)(recv_pkt->data + sizeof(struct ieee_hdr) + sizeof(struct llc_hdr));
					if (fuzzing_opt.wpa_s == WPA_4WAY_HANDSHAKE)
					{
						if (wpa_auth->version == 0x01 || wpa_auth->version == 0x02)
						{
							// fuzz_logger_log(FUZZ_LOG_INFO, "data 4way_handshake ......");
							if (strcmp(fuzzing_opt.mode, AP_MODE) == 0)
							{
								print_interaction_status(bssid, dmac, smac, "M2", "M3");
								create_eapol_m3(&data);
							}
							else if (strcmp(fuzzing_opt.mode, STA_MODE) == 0)
							{
								print_interaction_status(bssid, dmac, smac, "M3", "M4");
								create_eapol_m4(&data);
							}

							fuzzing_opt.wpa_s = WPA_COMPLETED;
						}
					}
					else if (fuzzing_opt.wpa_s == WPA_ASSOCIATED)
					{
						if (strcmp(fuzzing_opt.mode, STA_MODE) == 0)
						{
							print_interaction_status(bssid, dmac, smac, "M1", "M2");
							create_eapol_m2(&data);
						}
					}
					else
					{
						if (0 == fuzzing_opt.seed)
							srandom(time(NULL));

						dlen = random() % 1024;
						generate_random_data(data.data + data.len, dlen, VALUE_RANDOM);
						data.len += dlen;
					}
				}
				else if (ieee8021x_hdr->type == 0x00 || ieee8021x_hdr->type == 0x01 || ieee8021x_hdr->type == 0x02) // eap packet
				{
					print_interaction_status(bssid, dmac, smac, "EAP", "EAP");

					if (recv_pkt->len > (sizeof(struct ieee_hdr) + sizeof(struct llc_hdr) + sizeof(struct ieee802_1x_hdr)))
					{
						eaphdr = (struct eap_hdr *)(recv_pkt->data + sizeof(struct ieee_hdr) + sizeof(struct llc_hdr) + sizeof(struct ieee802_1x_hdr));
						if (recv_pkt->len > (sizeof(struct ieee_hdr) + sizeof(struct llc_hdr) + sizeof(struct ieee802_1x_hdr) + sizeof(struct eap_hdr)))
							eap_type = *(uint8_t *)((uint8_t *)eaphdr + 1);
						else
							eap_type = random() % 0xFF;
					}
					else
					{
						eaphdr = &eap;
						eaphdr->identifier = random() % 0xFF;
						eap_type = random() % 0xFF;
					}

					memcpy(data.data + data.len, llc_h, sizeof(struct llc_hdr));
					data.len += sizeof(struct llc_hdr);

					ieee8021x_hdr->version = random() % 0xFF;
					ieee8021x_hdr->type = random() % 0xFF; // type
					if (0 == fuzzing_opt.seed)
						srandom(time(NULL));

					ieee8021x_hdr->length = htons(random() % 512);
					memcpy(data.data + data.len, ieee8021x_hdr, sizeof(struct ieee802_1x_hdr));
					data.len += sizeof(struct ieee802_1x_hdr);

					if (0 == fuzzing_opt.seed)
						srandom(time(NULL) + ieee8021x_hdr->length);

					eaphdr->code = random() % 6 + 1;
					// eaphdr->identifier = 0x00;
					if (0 == fuzzing_opt.seed)
						srandom(time(NULL) + eaphdr->code);

					eaphdr->length = htons(random() % 512);
					memcpy(data.data + data.len, eaphdr, sizeof(struct eap_hdr));
					data.len += sizeof(struct eap_hdr);

					// type
					data.data[data.len] = eap_type;
					data.len += 1;
					// type data
					if (0 == fuzzing_opt.seed)
						srandom(time(NULL) + eap_type);

					dlen = random() % 1024;
					generate_random_data(data.data + data.len, dlen, VALUE_RANDOM);
					data.len += dlen;

					if (eaphdr->code == EAP_CODE_REQUEST) // Request
					{
					}
					else if (eaphdr->code == EAP_CODE_RESPONSE)
					{
					}
					else if (eaphdr->code == EAP_CODE_SUCCESS)
					{
					}
					else if (eaphdr->code == EAP_CODE_FAILURE)
					{
					}
					else if (eaphdr->code == EAP_CODE_INITIATE)
					{
					}
					else if (eaphdr->code == EAP_CODE_FINISH)
					{
					}
				}
			}
		}
		else if (fuzzing_opt.auth_type == SHARE_WEP)
		{
			memset(wp.init_vector, random() % (0xff + 1), 3);
			wp.key_index = 0;
			memcpy(data.data, &wp, sizeof(wp));
			data.len += sizeof(wp);

			hdr_new->flags |= 0x40;
			if (0 == fuzzing_opt.seed)
				srandom(time(NULL));

			dlen = random() % 1024;
			generate_random_data(data.data + data.len, dlen, VALUE_RANDOM);
			data.len += dlen;
		}
		else if (fuzzing_opt.auth_type == OPEN_WEP)
		{
			if (0 == fuzzing_opt.seed)
				srandom(time(NULL));

			dlen = random() % 1024;
			generate_random_data(data.data + data.len, dlen, VALUE_RANDOM);
			data.len += dlen;
		}
		else
		{
			if (0 == fuzzing_opt.seed)
				srandom(time(NULL));

			dlen = random() % 1024;
			generate_random_data(data.data + data.len, dlen, VALUE_RANDOM);
			data.len += dlen;
		}
	}
	else
	{
		if (fuzzing_opt.wpa_s == WPA_4WAY_HANDSHAKE) // m1
		{
			if (strcmp(fuzzing_opt.mode, AP_MODE) == 0)
			{
				print_interaction_status(bssid, dmac, smac, "", "M1");
				create_eapol_m1(&data);
			}
		}
		else if (fuzzing_opt.wpa_s == WPA_EAP_HANDSHAKE)
		{
			print_interaction_status(bssid, dmac, smac, "", "EAP");
			llc.dsap = 0xaa;
			llc.ssap = 0xaa;
			llc.ctrl = 0x03;
			llc.oui[0] = 0x00;
			llc.oui[1] = 0x00;
			llc.oui[2] = 0x00;
			llc.type = htons(0x888e);
			memcpy(data.data + data.len, &llc, sizeof(struct llc_hdr));
			data.len += sizeof(struct llc_hdr);

			ieee8021xdhr.version = 0x02;
			ieee8021xdhr.type = 0x00;
			if (0 == fuzzing_opt.seed)
				srandom(time(NULL));

			ieee8021xdhr.length = htons(5);
			memcpy(data.data + data.len, &ieee8021xdhr, sizeof(struct ieee802_1x_hdr));
			data.len += sizeof(struct ieee802_1x_hdr);

			eap.code = EAP_CODE_REQUEST;
			eap.identifier = random() % 0xFF;
			if (0 == fuzzing_opt.seed)
				srandom(time(NULL) + eap.identifier);

			eap.length = htons(5);
			memcpy(data.data + data.len, &eap, sizeof(struct eap_hdr));
			data.len += sizeof(struct eap_hdr);

			data.data[data.len] = 1;
			data.len += 1;
		}
		else
		{
			if (fuzzing_opt.auth_type == SHARE_WEP)
			{
				memset(wp.init_vector, random() % (0xff + 1), 3);
				wp.key_index = 0;
				memcpy(data.data, &wp, sizeof(wp));
				data.len += sizeof(wp);

				hdr_new->flags |= 0x40;
			}

			if (0 == fuzzing_opt.seed)
				srandom(time(NULL));

			dlen = random() % 1024;
			generate_random_data(data.data + data.len, dlen, VALUE_RANDOM);
			data.len += dlen;
		}
	}
	return data;
}
