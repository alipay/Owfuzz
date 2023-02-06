/*
 * OWL: an open Apple Wireless Direct Link (AWDL) implementation
 * Copyright (C) 2018  The Open Wireless Link Project (https://owlink.org)
 * Copyright (C) 2018  Milan Stute
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "awdl_frame.h"
#include "wire.h"
#include "../../frames/management/ies_creator.h"

extern fuzzing_option fuzzing_opt;

uint8_t awdl_ies[30] = {0, 1, 2, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24};

const char *awdl_frame_as_str(uint8_t type)
{
	switch (type)
	{
	case AWDL_ACTION_PSF:
		return "PSF";
	case AWDL_ACTION_MIF:
		return "MIF";
	default:
		return "Unknown";
	}
}

const char *awdl_tlv_as_str(uint8_t type)
{
	switch (type)
	{
	case AWDL_SSTH_REQUEST_TLV:
		return "SSTH Request";
	case AWDL_SERVICE_REQUEST_TLV:
		return "Service Request";
	case AWDL_SERVICE_RESPONSE_TLV:
		return "Service Response";
	case AWDL_SYNCHRONIZATON_PARAMETERS_TLV:
		return "Synchronization Parameters";
	case AWDL_ELECTION_PARAMETERS_TLV:
		return "Election Parameters";
	case AWDL_SERVICE_PARAMETERS_TLV:
		return "Service Parameters";
	case AWDL_ENHANCED_DATA_RATE_CAPABILITIES_TLV:
		return "HT Capabilities";
	case AWDL_ENHANCED_DATA_RATE_OPERATION_TLV:
		return "HT Operation";
	case AWDL_INFRA_TLV:
		return "Infra";
	case AWDL_INVITE_TLV:
		return "Invite";
	case AWDL_DBG_STRING_TLV:
		return "Debug String";
	case AWDL_DATA_PATH_STATE_TLV:
		return "Data Path State";
	case AWDL_ENCAPSULATED_IP_TLV:
		return "Encapsulated IP";
	case AWDL_DATAPATH_DEBUG_PACKET_LIVE_TLV:
		return "Datapath Debug Packet Live";
	case AWDL_DATAPATH_DEBUG_AF_LIVE_TLV:
		return "Datapath Debug AF Live";
	case AWDL_ARPA_TLV:
		return "Arpa";
	case AWDL_IEEE80211_CNTNR_TLV:
		return "VHT Capabilities";
	case AWDL_CHAN_SEQ_TLV:
		return "Channel Sequence";
	case AWDL_SYNCTREE_TLV:
		return "Synchronization Tree";
	case AWDL_VERSION_TLV:
		return "Version";
	case AWDL_BLOOM_FILTER_TLV:
		return "Bloom Filter";
	case AWDL_NAN_SYNC_TLV:
		return "NAN Sync";
	case AWDL_ELECTION_PARAMETERS_V2_TLV:
		return "Election Parameters v2";
	default:
		return "Unknown";
	}
}

struct packet create_action_awdl(struct ether_addr bssid, struct ether_addr smac, struct ether_addr dmac, struct packet *recv_pkt)
{
	struct packet pkt = {0};
	// struct ieee_hdr *hdr;
	struct awdl_action *aa, *a;
	// struct buf abuf = {0};
	// uint8_t *tlvs;
	// int tlvs_len;
	// uint8_t tlv_type;
	// uint16_t tlv_len;
	// uint8_t tlv_value[255];
	// int offset;
	// int nread;
	int i;

	// hdr = (struct ieee_hdr *) recv_pkt->data;
	aa = (struct awdl_action *)(recv_pkt->data + sizeof(struct ieee_hdr));
	// tlvs = recv_pkt->data + sizeof(struct ieee_hdr) + sizeof(struct awdl_action);
	// tlvs_len = recv_pkt->len - sizeof(struct ieee_hdr) - sizeof(struct awdl_action);
	// abuf.data = tlvs;
	// abuf.len = tlvs_len;

	create_ieee_hdr(&pkt, IEEE80211_TYPE_ACTION, 'a', 0x013A, dmac, smac, bssid, SE_NULLMAC, 0);

	a = (struct awdl_action *)(pkt.data + sizeof(struct ieee_hdr));
	a->category = 127;
	memcpy(a->oui.byte, AWDL_OUI.byte, 3);
	a->reserved = 0;
	a->type = AWDL_TYPE;
	a->subtype = aa->subtype;
	a->version = aa->version;
	a->target_tx = aa->phy_tx + 10;
	a->phy_tx = aa->target_tx + 9;

	pkt.len += sizeof(struct awdl_action);

	i = 0;
	do
	{
		if (0 == fuzzing_opt.seed)
			srandom(time(NULL) + i);

		i = random() % (sizeof(awdl_ies) / sizeof(awdl_ies[0]));
		add_attribute_tlv_fuzzing_data(&pkt, NULL, awdl_ies[i]);

	} while (pkt.len < 1500);

	pkt.channel = recv_pkt->channel;

	return pkt;
}
