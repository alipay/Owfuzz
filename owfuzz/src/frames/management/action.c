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

#include "action.h"
#include "ies_creator.h"
#include "common/ieee802_11_defs.h"

extern fuzzing_option fuzzing_opt;

uint8_t action_ie_ieee1999[10] = {0xff, 0};
uint8_t action_ie_ieee2007[10] = {221, 0};
uint8_t action_ie_ieee2012[10] = {221, 76, 0};
uint8_t action_ie_ieee2016[10] = {221, 76, 139, 0};
uint8_t action_ie_ieee2020[10] = {221, 76, 139, 0};

static int ie_extension_id = 0;
static uint8_t ie_extension[50] = {
	0xff, 0};

static FUZZING_VALUE_TYPE fuzzing_value_step = VALUE_ALL_BITS_ZERO;
static FUZZING_TYPE fuzzing_step = NOT_PRESENT;

static int ieee2020 = 0;
static int ieee2020_id = 0;

uint8_t action_category[25] = {
	WLAN_ACTION_SPECTRUM_MGMT, WLAN_ACTION_QOS, WLAN_ACTION_DLS, WLAN_ACTION_BLOCK_ACK, WLAN_ACTION_PUBLIC, WLAN_ACTION_RADIO_MEASUREMENT, WLAN_ACTION_FT, // 7
	WLAN_ACTION_HT, WLAN_ACTION_SA_QUERY, WLAN_ACTION_PROTECTED_DUAL, WLAN_ACTION_WNM, WLAN_ACTION_UNPROTECTED_WNM, WLAN_ACTION_TDLS, WLAN_ACTION_MESH,	   // 7
	WLAN_ACTION_MULTIHOP, WLAN_ACTION_SELF_PROTECTED, WLAN_ACTION_DMG, WLAN_ACTION_WMM, WLAN_ACTION_FST, WLAN_ACTION_ROBUST_AV_STREAMING,				   // 6
	WLAN_ACTION_UNPROTECTED_DMG, WLAN_ACTION_VHT, WLAN_ACTION_FILS, WLAN_ACTION_VENDOR_SPECIFIC_PROTECTED, WLAN_ACTION_VENDOR_SPECIFIC					   // 5
};

void save_action_state()
{
}

void load_action_state()
{
}

struct packet create_action(struct ether_addr bssid, struct ether_addr smac, struct ether_addr dmac, char adhoc, struct packet *recv_pkt)
{
	struct packet action = {0};
	struct ieee80211_mgmt *m_action, *mgmt_action;
	uint8_t rlen = 0;
	struct action_fixed *af;

	create_ieee_hdr(&action, IEEE80211_TYPE_ACTION, 'a', 0x013A, dmac, smac, bssid, SE_NULLMAC, 0);
	m_action = (struct ieee80211_mgmt *)action.data;
	af = (struct action_fixed *)(action.data + action.len);
	action.len += sizeof(struct action_fixed);

	if (recv_pkt)
	{
		mgmt_action = (struct ieee80211_mgmt *)recv_pkt->data;
		af->category_code = mgmt_action->u.action.category;
		// af->action_code = *((uint8_t*)&mgmt_action->u.action.category + 1);
	}
	else
	{
		if (0 == fuzzing_opt.seed)
			srandom(time(NULL));

		af->category_code = action_category[random() % (sizeof(action_category) / sizeof(action_category[0]))];
	}

	switch (m_action->u.action.category)
	{
	case WLAN_ACTION_SPECTRUM_MGMT:
#ifdef DEBUG_LOG
		fuzz_logger_log(FUZZ_LOG_DEBUG, "Action: spectrum_mgmt testing ==> ...");
#endif
		handle_action_spectrum(&action, recv_pkt);
		break;
	case WLAN_ACTION_QOS:
#ifdef DEBUG_LOG
		fuzz_logger_log(FUZZ_LOG_DEBUG, "Action: qos testing ==> ...");
#endif
		handle_action_qos(&action, recv_pkt);
		break;
	case WLAN_ACTION_DLS:
#ifdef DEBUG_LOG
		fuzz_logger_log(FUZZ_LOG_DEBUG, "Action: dls testing ==> ...");
#endif
		handle_action_dls(&action, recv_pkt);
		break;
	case WLAN_ACTION_BLOCK_ACK:
#ifdef DEBUG_LOG
		fuzz_logger_log(FUZZ_LOG_DEBUG, "Action: block_ack testing ==> ...");
#endif
		handle_action_block_ack(&action, recv_pkt);
		break;
	case WLAN_ACTION_PUBLIC:
#ifdef DEBUG_LOG
		fuzz_logger_log(FUZZ_LOG_DEBUG, "Action: public testing ==> ...");
#endif
		handle_action_public(&action, recv_pkt);
		break;
	case WLAN_ACTION_RADIO_MEASUREMENT:
#ifdef DEBUG_LOG
		fuzz_logger_log(FUZZ_LOG_DEBUG, "Action: radio_measurement testing ==> ...");
#endif
		handle_action_radio_measurement(&action, recv_pkt);
		break;
	case WLAN_ACTION_FT:
#ifdef DEBUG_LOG
		fuzz_logger_log(FUZZ_LOG_DEBUG, "Action: ft testing ==> ...");
#endif
		handle_action_ft(&action, recv_pkt);
		break;
	case WLAN_ACTION_HT:
#ifdef DEBUG_LOG
		fuzz_logger_log(FUZZ_LOG_DEBUG, "Action: ht testing ==> ...");
#endif
		handle_action_ht(&action, recv_pkt);
		break;
	case WLAN_ACTION_SA_QUERY:
#ifdef DEBUG_LOG
		fuzz_logger_log(FUZZ_LOG_DEBUG, "Action: sa_query testing ==> ...");
#endif
		handle_action_sa_query(&action, recv_pkt);
		break;
	case WLAN_ACTION_PROTECTED_DUAL:
#ifdef DEBUG_LOG
		fuzz_logger_log(FUZZ_LOG_DEBUG, "Action: protected_dual testing ==> ...");
#endif
		handle_action_protected_dual(&action, recv_pkt);
		break;
	case WLAN_ACTION_WNM:
#ifdef DEBUG_LOG
		fuzz_logger_log(FUZZ_LOG_DEBUG, "Action: wnm testing ==> ...");
#endif
		handle_action_wnm(&action, recv_pkt);
		break;
	case WLAN_ACTION_UNPROTECTED_WNM:
#ifdef DEBUG_LOG
		fuzz_logger_log(FUZZ_LOG_DEBUG, "Action: unprotected_wnm testing ==> ...");
#endif
		handle_action_unprotected_wnm(&action, recv_pkt);
		break;
	case WLAN_ACTION_TDLS:
#ifdef DEBUG_LOG
		fuzz_logger_log(FUZZ_LOG_DEBUG, "Action: tdls testing ==> ...");
#endif
		handle_action_tdls(&action, recv_pkt);
		break;
	case WLAN_ACTION_MESH:
#ifdef DEBUG_LOG
		fuzz_logger_log(FUZZ_LOG_DEBUG, "Action: mesh testing ==> ...");
#endif
		handle_action_mesh(&action, recv_pkt);
		break;
	case WLAN_ACTION_MULTIHOP:
#ifdef DEBUG_LOG
		fuzz_logger_log(FUZZ_LOG_DEBUG, "Action: multihop testing ==> ...");
#endif
		handle_action_multihop(&action, recv_pkt);
		break;
	case WLAN_ACTION_SELF_PROTECTED:
#ifdef DEBUG_LOG
		fuzz_logger_log(FUZZ_LOG_DEBUG, "Action: protected testing ==> ...");
#endif
		handle_action_self_protected(&action, recv_pkt);
		break;
	case WLAN_ACTION_DMG:
#ifdef DEBUG_LOG
		fuzz_logger_log(FUZZ_LOG_DEBUG, "Action: dmg testing ==> ...");
#endif
		handle_action_dmg(&action, recv_pkt);
		break;
	case WLAN_ACTION_WMM:
#ifdef DEBUG_LOG
		fuzz_logger_log(FUZZ_LOG_DEBUG, "Action: wmm testing ==> ...");
#endif
		handle_action_wmm(&action, recv_pkt);
		break;
	case WLAN_ACTION_FST:
#ifdef DEBUG_LOG
		fuzz_logger_log(FUZZ_LOG_DEBUG, "Action: fst testing ==> ...");
#endif
		handle_action_fst(&action, recv_pkt);
		break;
	case WLAN_ACTION_ROBUST_AV_STREAMING:
#ifdef DEBUG_LOG
		fuzz_logger_log(FUZZ_LOG_DEBUG, "Action: robust_av_streaming testing ==> ...");
#endif
		handle_action_robust_av_streaming(&action, recv_pkt);
		break;
	case WLAN_ACTION_UNPROTECTED_DMG:
#ifdef DEBUG_LOG
		fuzz_logger_log(FUZZ_LOG_DEBUG, "Action: unprotected testing ==> ...");
#endif
		handle_action_unprotected_dmg(&action, recv_pkt);
		break;
	case WLAN_ACTION_VHT:
#ifdef DEBUG_LOG
		fuzz_logger_log(FUZZ_LOG_DEBUG, "Action: vht testing ==> ...");
#endif
		handle_action_vht(&action, recv_pkt);
		break;
	case WLAN_ACTION_FILS:
#ifdef DEBUG_LOG
		fuzz_logger_log(FUZZ_LOG_DEBUG, "Action: fils testing ==> ...");
#endif
		handle_action_fils(&action, recv_pkt);
		break;
	case WLAN_ACTION_VENDOR_SPECIFIC_PROTECTED:
#ifdef DEBUG_LOG
		fuzz_logger_log(FUZZ_LOG_DEBUG, "Action: vendor_specific_protected testing ==> ...");
#endif
		handle_action_vendor_specific_protected(&action, recv_pkt);
		break;
	case WLAN_ACTION_VENDOR_SPECIFIC:
#ifdef DEBUG_LOG
		fuzz_logger_log(FUZZ_LOG_DEBUG, "Action: vendor_specific testing ==> ...");
#endif
		handle_action_vendor_specific(&action, recv_pkt);
		break;
	default:
		break;
	}

	// TODO:
	if (0 == fuzzing_opt.seed)
		srandom(time(NULL) + af->category_code);

	rlen = random() % (0xff + 1);
	generate_random_data(action.data + action.len, rlen, VALUE_RANDOM);
	action.len += rlen;

	create_frame_fuzzing_ie(&action, "Action", action_ie_ieee2020, &ieee2020, &ieee2020_id, ie_extension, &ie_extension_id, &fuzzing_step, &fuzzing_value_step);

	/*create_frame_fuzzing_ies(&action, "Action",
		action_ie_ieee1999,
		action_ie_ieee2007,
		action_ie_ieee2012,
		action_ie_ieee2016,
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

	// dumphex(action.data, action.len);

	return action;
}

void create_action_ies(struct packet *pkt)
{
}

void handle_action_spectrum(struct packet *pkt, struct packet *recv_pkt)
{
	static enum action_code { Measurement_Request,
							  Measurement_Report,
							  TPC_Request,
							  TPC_Report,
							  Channel_Switch_Announcement };
	struct ieee80211_mgmt *m_action, *mgmt_action;
	static uint8_t action_codes[5] = {Measurement_Request, Measurement_Report, TPC_Request, TPC_Report /*, Channel_Switch_Announcement*/};

	m_action = (struct ieee80211_mgmt *)pkt->data;
	if (recv_pkt)
	{
		mgmt_action = (struct ieee80211_mgmt *)recv_pkt->data;
		*((uint8_t *)&m_action->u.action.category + 1) = *((uint8_t *)&mgmt_action->u.action.category + 1) + 1;
	}
	else
	{
		if (0 == fuzzing_opt.seed)
			srandom(time(NULL));

		*((uint8_t *)&m_action->u.action.category + 1) = action_codes[random() % (sizeof(action_codes) / sizeof(action_codes[0]))];
	}

	/*switch( *((uint8_t*)&m_action->u.action.category + 1))
	{
	case Measurement_Request:
	break;
	case Measurement_Report:
	break;
	case TPC_Request:
	break;
	case TPC_Report:
	break;
	case Channel_Switch_Announcement:
	break;
	// 5-255 Reserved
	}*/
}

void handle_action_qos(struct packet *pkt, struct packet *recv_pkt)
{
	static enum action_code { ADDTS_Request,
							  ADDTS_Response,
							  DELTS,
							  Schedule,
							  QoS_Map_Configure,
							  ADDTS_Reserve_Request,
							  ADDTS_Reserve_Response };
	struct ieee80211_mgmt *m_action, *mgmt_action;
	static uint8_t action_codes[7] = {ADDTS_Request, ADDTS_Response, DELTS, Schedule, QoS_Map_Configure, ADDTS_Reserve_Request, ADDTS_Reserve_Response};

	m_action = (struct ieee80211_mgmt *)pkt->data;
	if (recv_pkt)
	{
		mgmt_action = (struct ieee80211_mgmt *)recv_pkt->data;
		*((uint8_t *)&m_action->u.action.category + 1) = *((uint8_t *)&mgmt_action->u.action.category + 1) + 1;
	}
	else
	{
		if (0 == fuzzing_opt.seed)
			srandom(time(NULL));

		*((uint8_t *)&m_action->u.action.category + 1) = action_codes[random() % (sizeof(action_codes) / sizeof(action_codes[0]))];
	}

	/*switch(*((uint8_t*)&m_action->u.action.category + 1))
	{
	case ADDTS_Request:
	break;
	case ADDTS_Response:
	break;
	case DELTS:
	break;
	case Schedule:
	break;
	case QoS_Map_Configure:
	break;
	case ADDTS_Reserve_Request:
	break;
	case ADDTS_Reserve_Response:
	break;
	// 7-255 Reserved
	}*/
}

void handle_action_dls(struct packet *pkt, struct packet *recv_pkt)
{
	static enum action_code { DLS_Request,
							  DLS_Response,
							  DLS_Teardown };
	struct ieee80211_mgmt *m_action, *mgmt_action;
	static uint8_t action_codes[3] = {DLS_Request, DLS_Response, DLS_Teardown};

	m_action = (struct ieee80211_mgmt *)pkt->data;
	if (recv_pkt)
	{
		mgmt_action = (struct ieee80211_mgmt *)recv_pkt->data;
		*((uint8_t *)&m_action->u.action.category + 1) = *((uint8_t *)&mgmt_action->u.action.category + 1) + 1;
	}
	else
	{
		if (0 == fuzzing_opt.seed)
			srandom(time(NULL));

		*((uint8_t *)&m_action->u.action.category + 1) = action_codes[random() % (sizeof(action_codes) / sizeof(action_codes[0]))];
	}

	/*switch( *((uint8_t*)&m_action->u.action.category + 1))
	{
		case DLS_Request:
		break;
		case DLS_Response:
		break;
		case DLS_Teardown:
		break;
		// 3-255 Reserved
	}*/
}

void handle_action_block_ack(struct packet *pkt, struct packet *recv_pkt)
{
	static enum action_code { ADDBA_Request,
							  ADDBA_Response,
							  DELBA };
	struct ieee80211_mgmt *m_action, *mgmt_action;
	static uint8_t action_codes[3] = {ADDBA_Request, ADDBA_Response, DELBA};

	m_action = (struct ieee80211_mgmt *)pkt->data;
	if (recv_pkt)
	{
		mgmt_action = (struct ieee80211_mgmt *)recv_pkt->data;
		*((uint8_t *)&m_action->u.action.category + 1) = *((uint8_t *)&mgmt_action->u.action.category + 1) + 1;
	}
	else
	{
		if (0 == fuzzing_opt.seed)
			srandom(time(NULL));

		*((uint8_t *)&m_action->u.action.category + 1) = action_codes[random() % (sizeof(action_codes) / sizeof(action_codes[0]))];
	}

	/*switch( *((uint8_t*)&m_action->u.action.category + 1))
	{
		case ADDBA_Request:
		break;
		case ADDBA_Response:
		break;
		case DELBA:
		break;
		// 3-255 Reserved
	}*/
}

void handle_action_public(struct packet *pkt, struct packet *recv_pkt)
{
	static enum action_code { x20_40_BSS_Coexistence_Management,
							  DSE_enablement,
							  DSE_deenablement,
							  DSE_Registered_Location_Announcement,
							  Extended_Channel_Switch_Announcement,
							  DSE_measurement_request,
							  DSE_measurement_report,
							  Measurement_Pilot,
							  DSE_power_constraint,
							  Vendor_Specific,
							  GAS_Initial_Request,
							  GAS_Initial_Response,
							  GAS_Comeback_Request,
							  GAS_Comeback_Response,
							  TDLS_Discovery_Response,
							  Location_Track_Notification,
							  QAB_Request_frame,
							  QAB_Response_frame,
							  QMF_Policy,
							  QMF_Policy_Change,
							  QLoad_Request,
							  QLoad_Report,
							  HCCA_TXOP_Advertisement,
							  HCCA_TXOP_Response,
							  Public_Key,
							  Channel_Availability_Query,
							  Channel_Schedule_Management,
							  Contact_Verification_Signal,
							  GDD_Enablement_Request,
							  GDD_Enablement_Response,
							  Network_Channel_Control,
							  White_Space_Map_Announcement,
							  Fine_Timing_Measurement_Request,
							  Fine_Timing_Measurement };

	struct ieee80211_mgmt *m_action, *mgmt_action;
	static uint8_t action_codes[34] = {x20_40_BSS_Coexistence_Management, DSE_enablement, DSE_deenablement, DSE_Registered_Location_Announcement, Extended_Channel_Switch_Announcement,
									   DSE_measurement_request, DSE_measurement_report, Measurement_Pilot, DSE_power_constraint, Vendor_Specific, GAS_Initial_Request, GAS_Initial_Response,
									   GAS_Comeback_Request, GAS_Comeback_Response, TDLS_Discovery_Response, Location_Track_Notification, QAB_Request_frame, QAB_Response_frame, QMF_Policy,
									   QMF_Policy_Change, QLoad_Request, QLoad_Report, HCCA_TXOP_Advertisement, HCCA_TXOP_Response, Public_Key, Channel_Availability_Query, Channel_Schedule_Management,
									   Contact_Verification_Signal, GDD_Enablement_Request, GDD_Enablement_Response, Network_Channel_Control, White_Space_Map_Announcement, Fine_Timing_Measurement_Request,
									   Fine_Timing_Measurement};

	m_action = (struct ieee80211_mgmt *)pkt->data;
	if (recv_pkt)
	{
		mgmt_action = (struct ieee80211_mgmt *)recv_pkt->data;
		*((uint8_t *)&m_action->u.action.category + 1) = *((uint8_t *)&mgmt_action->u.action.category + 1) + 1;
	}
	else
	{
		if (0 == fuzzing_opt.seed)
			srandom(time(NULL));

		*((uint8_t *)&m_action->u.action.category + 1) = action_codes[random() % (sizeof(action_codes) / sizeof(action_codes[0]))];
	}

	/*switch( *((uint8_t*)&m_action->u.action.category + 1))
	{
		case x20_40_BSS_Coexistence_Management:
		break;
		case DSE_enablement:
		break;
		case DSE_deenablement:
		break;
		case DSE_Registered_Location_Announcement:
		break;
		case Extended_Channel_Switch_Announcement:
		break;
		case DSE_measurement_request:
		break;
		case DSE_measurement_report:
		break;
		case Measurement_Pilot:
		break;
		case DSE_power_constraint:
		break;
		case Vendor_Specific:
		break;
		case GAS_Initial_Request:
		break;
		case GAS_Initial_Response:
		break;
		case GAS_Comeback_Request:
		break;
		case GAS_Comeback_Response:
		break;
		case TDLS_Discovery_Response:
		break;
		case Location_Track_Notification:
		break;
		case QAB_Request_frame:
		break;
		case QAB_Response_frame:
		break;
		case QMF_Policy:
		break;
		case QMF_Policy_Change:
		break;
		case QLoad_Request:
		break;
		case QLoad_Report:
		break;
		case HCCA_TXOP_Advertisement:
		break;
		case HCCA_TXOP_Response:
		break;
		case Public_Key:
		break;
		case Channel_Availability_Query:
		break;
		case Channel_Schedule_Management:
		break;
		case Contact_Verification_Signal:
		break;
		case GDD_Enablement_Request:
		break;
		case GDD_Enablement_Response:
		break;
		case Network_Channel_Control:
		break;
		case White_Space_Map_Announcement:
		break;
		case Fine_Timing_Measurement_Request:
		break;
		case Fine_Timing_Measurement:
		break;
		// 25-255 Reserved
	}*/
}

void handle_action_radio_measurement(struct packet *pkt, struct packet *recv_pkt)
{
	static enum action_code { Radio_Measurement_Request,
							  Radio_Measurement_Report,
							  Link_Measurement_Request,
							  Link_Measurement_Report,
							  Neighbor_Report_Request,
							  Neighbor_Report_Response };
	struct ieee80211_mgmt *m_action, *mgmt_action;
	static uint8_t action_codes[6] = {Radio_Measurement_Request, Radio_Measurement_Report, Link_Measurement_Request, Link_Measurement_Report, Neighbor_Report_Request,
									  Neighbor_Report_Response};

	m_action = (struct ieee80211_mgmt *)pkt->data;
	if (recv_pkt)
	{
		mgmt_action = (struct ieee80211_mgmt *)recv_pkt->data;
		*((uint8_t *)&m_action->u.action.category + 1) = *((uint8_t *)&mgmt_action->u.action.category + 1) + 1;
	}
	else
	{
		if (0 == fuzzing_opt.seed)
			srandom(time(NULL));

		*((uint8_t *)&m_action->u.action.category + 1) = action_codes[random() % (sizeof(action_codes) / sizeof(action_codes[0]))];
	}

	/*switch( *((uint8_t*)&m_action->u.action.category + 1))
	{
		case Radio_Measurement_Request:
		break;
		case Radio_Measurement_Report:
		break;
		case Link_Measurement_Request:
		break;
		case Link_Measurement_Report:
		break;
		case Neighbor_Report_Request:
		break;
		case Neighbor_Report_Response:
		break;
		// 6-255 Reserved
	}*/
}

void handle_action_ft(struct packet *pkt, struct packet *recv_pkt)
{
	static enum action_code { FT_Request_frames = 1,
							  FT_Response_frames,
							  FT_Confirm_frames,
							  FT_Ack_frames };
	struct ieee80211_mgmt *m_action, *mgmt_action;
	static uint8_t action_codes[4] = {FT_Request_frames, FT_Response_frames, FT_Confirm_frames, FT_Ack_frames};

	m_action = (struct ieee80211_mgmt *)pkt->data;
	if (recv_pkt)
	{
		mgmt_action = (struct ieee80211_mgmt *)recv_pkt->data;
		*((uint8_t *)&m_action->u.action.category + 1) = *((uint8_t *)&mgmt_action->u.action.category + 1) + 1;
	}
	else
	{
		if (0 == fuzzing_opt.seed)
			srandom(time(NULL));

		*((uint8_t *)&m_action->u.action.category + 1) = action_codes[random() % (sizeof(action_codes) / sizeof(action_codes[0]))];
	}

	/*switch( *((uint8_t*)&m_action->u.action.category + 1))
	{
		case FT_Request_frames:
		break;
		case FT_Response_frames:
		break;
		case FT_Confirm_frames:
		break;
		case FT_Ack_frames:
		break;
		// 0, 5-255 Reserved
	}*/
}

void handle_action_ht(struct packet *pkt, struct packet *recv_pkt)
{
	static enum action_code { Notify_Channel_Width,
							  SM_Power_Save,
							  PSMP,
							  Set_PCO_Phase,
							  CSI,
							  Noncompressed_Beamforming,
							  Compressed_Beamforming,
							  ASEL_Indices_Feedback };
	struct ieee80211_mgmt *m_action, *mgmt_action;
	static uint8_t action_codes[8] = {Notify_Channel_Width, SM_Power_Save, PSMP, Set_PCO_Phase, CSI, Noncompressed_Beamforming, Compressed_Beamforming, ASEL_Indices_Feedback};

	m_action = (struct ieee80211_mgmt *)pkt->data;
	if (recv_pkt)
	{
		mgmt_action = (struct ieee80211_mgmt *)recv_pkt->data;
		*((uint8_t *)&m_action->u.action.category + 1) = *((uint8_t *)&mgmt_action->u.action.category + 1) + 1;
	}
	else
	{
		if (0 == fuzzing_opt.seed)
			srandom(time(NULL));

		*((uint8_t *)&m_action->u.action.category + 1) = action_codes[random() % (sizeof(action_codes) / sizeof(action_codes[0]))];
	}

	/*switch( *((uint8_t*)&m_action->u.action.category + 1))
	{
		case Notify_Channel_Width:
		break;
		case SM_Power_Save:
		break;
		case PSMP:
		break;
		case Set_PCO_Phase:
		break;
		case CSI:
		break;
		case Noncompressed_Beamforming:
		break;
		case Compressed_Beamforming:
		break;
		case ASEL_Indices_Feedback:
		break;
		// 8-255 Reserved
	}*/
}

void handle_action_sa_query(struct packet *pkt, struct packet *recv_pkt)
{
	static enum action_code { SA_Query_Request,
							  SA_Query_Response };
	struct ieee80211_mgmt *m_action, *mgmt_action;
	static uint8_t action_codes[2] = {SA_Query_Request, SA_Query_Response};

	m_action = (struct ieee80211_mgmt *)pkt->data;
	if (recv_pkt)
	{
		mgmt_action = (struct ieee80211_mgmt *)recv_pkt->data;
		*((uint8_t *)&m_action->u.action.category + 1) = *((uint8_t *)&mgmt_action->u.action.category + 1) + 1;
	}
	else
	{
		if (0 == fuzzing_opt.seed)
			srandom(time(NULL));

		*((uint8_t *)&m_action->u.action.category + 1) = action_codes[random() % (sizeof(action_codes) / sizeof(action_codes[0]))];
	}

	/*switch( *((uint8_t*)&m_action->u.action.category + 1))
	{
		case SA_Query_Request:
		break;
		case SA_Query_Response:
		break;
	}*/
}

void handle_action_protected_dual(struct packet *pkt, struct packet *recv_pkt)
{
	static enum action_code { Protected_DSE_Enablement = 1,
							  Protected_DSE_Deenablement,
							  Protected_Extended_Channel_Switch_Announcement = 4,
							  Protected_Measurement_Request,
							  Protected_Measurement_Report,
							  Protected_DSE_Power_Constraint = 8,
							  Protected_Vendor_Specific,
							  Protected_GAS_Initial_Request,
							  Protected_GAS_Initial_Response,
							  Protected_GAS_Comeback_Request,
							  Protected_GAS_Comeback_Response,
							  QAB_Request = 16,
							  QAB_Response,
							  Protected_QMF_Policy,
							  Protected_QMF_Policy_Change,
							  Protected_QLoad_Request,
							  Protected_QLoad_Report,
							  Protected_HCCA_TXOP_Advertisement,
							  Protected_HCCA_TXOP_Response,
							  Protected_Channel_Availability_Query = 25,
							  Protected_Channel_Schedule_Management,
							  Protected_Contact_Verification_Signal,
							  Protected_GDD_Enablement_Request,
							  Protected_GDD_Enablement_Response,
							  Protected_Network_Channel_Control,
							  Protected_White_Space_Map_Announcement };
	struct ieee80211_mgmt *m_action, *mgmt_action;
	static uint8_t action_codes[26] = {Protected_DSE_Enablement, Protected_DSE_Deenablement, Protected_Extended_Channel_Switch_Announcement, Protected_Measurement_Request,
									   Protected_Measurement_Report, Protected_DSE_Power_Constraint, Protected_Vendor_Specific, Protected_GAS_Initial_Request, Protected_GAS_Initial_Response,
									   Protected_GAS_Comeback_Request, Protected_GAS_Comeback_Response, QAB_Request, QAB_Response, Protected_QMF_Policy, Protected_QMF_Policy_Change,
									   Protected_QLoad_Request, Protected_QLoad_Report, Protected_HCCA_TXOP_Advertisement, Protected_HCCA_TXOP_Response, Protected_Channel_Availability_Query,
									   Protected_Channel_Schedule_Management, Protected_Contact_Verification_Signal, Protected_GDD_Enablement_Request, Protected_GDD_Enablement_Response,
									   Protected_Network_Channel_Control, Protected_White_Space_Map_Announcement};

	m_action = (struct ieee80211_mgmt *)pkt->data;
	if (recv_pkt)
	{
		mgmt_action = (struct ieee80211_mgmt *)recv_pkt->data;
		*((uint8_t *)&m_action->u.action.category + 1) = *((uint8_t *)&mgmt_action->u.action.category + 1) + 1;
	}
	else
	{
		if (0 == fuzzing_opt.seed)
			srandom(time(NULL));

		*((uint8_t *)&m_action->u.action.category + 1) = action_codes[random() % (sizeof(action_codes) / sizeof(action_codes[0]))];
	}

	/*switch( *((uint8_t*)&m_action->u.action.category + 1))
	{
		case Protected_DSE_Enablement:
		break;
		case Protected_DSE_Deenablement:
		break;
		case Protected_Extended_Channel_Switch_Announcement:
		break;
		case Protected_Measurement_Request:
		break;
		case Protected_Measurement_Report:
		break;
		case Protected_DSE_Power_Constraint:
		break;
		case Protected_Vendor_Specific:
		break;
		case Protected_GAS_Initial_Request:
		break;
		case Protected_GAS_Initial_Response:
		break;
		case Protected_GAS_Comeback_Request:
		break;
		case Protected_GAS_Comeback_Response:
		break;
		case QAB_Request:
		break;
		case QAB_Response:
		break;
		case Protected_QMF_Policy:
		break;
		case Protected_QMF_Policy_Change:
		break;
		case Protected_QLoad_Request:
		break;
		case Protected_QLoad_Report:
		break;
		case Protected_HCCA_TXOP_Advertisement:
		break;
		case Protected_HCCA_TXOP_Response:
		break;
		case Protected_Channel_Availability_Query:
		break;
		case Protected_Channel_Schedule_Management:
		break;
		case Protected_Contact_Verification_Signal:
		break;
		case Protected_GDD_Enablement_Request:
		break;
		case Protected_GDD_Enablement_Response:
		break;
		case Protected_Network_Channel_Control:
		break;
		case Protected_White_Space_Map_Announcement:
		break;
		// 0,3,7,14-17,24,32-255 Reserved
	}*/
}

void handle_action_wnm(struct packet *pkt, struct packet *recv_pkt)
{
	static enum action_code { Event_Request,
							  Event_Report,
							  Diagnostic_Request,
							  Diagnostic_Report,
							  Location_Configuration_Request,
							  Location_Configuration_Response,
							  BSS_Transition_Management_Query,
							  BSS_Transition_Management_Request,
							  BSS_Transition_Management_Response,
							  FMS_Request,
							  FMS_Response,
							  Collocated_Interference_Request,
							  Collocated_Interference_Report,
							  TFS_Request,
							  TFS_Response,
							  TFS_Notify,
							  WNM_Sleep_Mode_Request,
							  WNM_Sleep_Mode_Response,
							  TIM_Broadcast_Request,
							  TIM_Broadcast_Response,
							  QoS_Traffic_Capability_Update,
							  Channel_Usage_Request,
							  Channel_Usage_Response,
							  DMS_Request,
							  DMS_Response,
							  Timing_Measurement_Request,
							  WNM_Notification_Request,
							  WNM_Notification_Response,
							  WNM_Notify_Response };

	struct ieee80211_mgmt *m_action, *mgmt_action;
	static uint8_t action_codes[29] = {Event_Request, Event_Report, Diagnostic_Request, Diagnostic_Report, Location_Configuration_Request, Location_Configuration_Response,
									   BSS_Transition_Management_Query, BSS_Transition_Management_Request, BSS_Transition_Management_Response, FMS_Request, FMS_Response, Collocated_Interference_Request,
									   Collocated_Interference_Report, TFS_Request, TFS_Response, TFS_Notify, WNM_Sleep_Mode_Request, WNM_Sleep_Mode_Response, TIM_Broadcast_Request, TIM_Broadcast_Response,
									   QoS_Traffic_Capability_Update, Channel_Usage_Request, Channel_Usage_Response, DMS_Request, DMS_Response, Timing_Measurement_Request, WNM_Notification_Request,
									   WNM_Notification_Response, WNM_Notify_Response};

	m_action = (struct ieee80211_mgmt *)pkt->data;
	if (recv_pkt)
	{
		mgmt_action = (struct ieee80211_mgmt *)recv_pkt->data;
		*((uint8_t *)&m_action->u.action.category + 1) = *((uint8_t *)&mgmt_action->u.action.category + 1) + 1;
	}
	else
	{
		if (0 == fuzzing_opt.seed)
			srandom(time(NULL));

		*((uint8_t *)&m_action->u.action.category + 1) = action_codes[random() % (sizeof(action_codes) / sizeof(action_codes[0]))];
	}

	/*switch( *((uint8_t*)&m_action->u.action.category + 1))
	{
		case Event_Request:
		break;
		case Event_Report:
		break;
		case Diagnostic_Request:
		break;
		case Diagnostic_Report:
		break;
		case Location_Configuration_Request:
		break;
		case Location_Configuration_Response:
		break;
		case BSS_Transition_Management_Query:
		break;
		case BSS_Transition_Management_Request:
		break;
		case BSS_Transition_Management_Response:
		break;
		case FMS_Request:
		break;
		case FMS_Response:
		break;
		case Collocated_Interference_Request:
		break;
		case Collocated_Interference_Report:
		break;
		case TFS_Request:
		break;
		case TFS_Response:
		break;
		case TFS_Notify:
		break;
		case WNM_Sleep_Mode_Request:
		break;
		case WNM_Sleep_Mode_Response:
		break;
		case TIM_Broadcast_Request:
		break;
		case TIM_Broadcast_Response:
		break;
		case QoS_Traffic_Capability_Update:
		break;
		case Channel_Usage_Request:
		break;
		case Channel_Usage_Response:
		break;
		case DMS_Request:
		break;
		case DMS_Response:
		break;
		case Timing_Measurement_Request:
		break;
		case WNM_Notification_Request:
		break;
		case WNM_Notification_Response:
		break;
		case WNM_Notify_Response:
		break;
		// 29-255 Reserved

	}*/
}

void handle_action_unprotected_wnm(struct packet *pkt, struct packet *recv_pkt)
{
	static enum action_code { TIM,
							  Timing_Measurement };
	struct ieee80211_mgmt *m_action, *mgmt_action;
	static uint8_t action_codes[2] = {TIM, Timing_Measurement};

	m_action = (struct ieee80211_mgmt *)pkt->data;
	if (recv_pkt)
	{
		mgmt_action = (struct ieee80211_mgmt *)recv_pkt->data;
		*((uint8_t *)&m_action->u.action.category + 1) = *((uint8_t *)&mgmt_action->u.action.category + 1) + 1;
	}
	else
	{
		if (0 == fuzzing_opt.seed)
			srandom(time(NULL));

		*((uint8_t *)&m_action->u.action.category + 1) = action_codes[random() % (sizeof(action_codes) / sizeof(action_codes[0]))];
	}

	/*switch( *((uint8_t*)&m_action->u.action.category + 1))
	{
		case TIM:
		break;
		case Timing_Measurement:
		break;
		// 2-255 Reserved

	}*/
}

void handle_action_tdls(struct packet *pkt, struct packet *recv_pkt)
{
	static enum action_code { TDLS_Setup_Request,
							  TDLS_Setup_Response,
							  TDLS_Setup_Confirm,
							  TDLS_Teardown,
							  TDLS_Peer_Traffic_Indication,
							  TDLS_Channel_Switch_Request,
							  TDLS_Channel_Switch_Response,
							  TDLS_Peer_PSM_Request,
							  TDLS_Peer_PSM_Response,
							  TDLS_Peer_Traffic_Response,
							  TDLS_Discovery_Request };
	struct ieee80211_mgmt *m_action, *mgmt_action;
	static uint8_t action_codes[10] = {TDLS_Setup_Request, TDLS_Setup_Response, TDLS_Setup_Confirm, TDLS_Teardown, TDLS_Peer_Traffic_Indication, TDLS_Channel_Switch_Request,
									   TDLS_Channel_Switch_Response, TDLS_Peer_PSM_Request, TDLS_Peer_PSM_Response, TDLS_Peer_Traffic_Response, TDLS_Discovery_Request};

	m_action = (struct ieee80211_mgmt *)pkt->data;
	if (recv_pkt)
	{
		mgmt_action = (struct ieee80211_mgmt *)recv_pkt->data;
		*((uint8_t *)&m_action->u.action.category + 1) = *((uint8_t *)&mgmt_action->u.action.category + 1) + 1;
	}
	else
	{
		if (0 == fuzzing_opt.seed)
			srandom(time(NULL));

		*((uint8_t *)&m_action->u.action.category + 1) = action_codes[random() % (sizeof(action_codes) / sizeof(action_codes[0]))];
	}

	/*switch( *((uint8_t*)&m_action->u.action.category + 1))
	{
		case TDLS_Setup_Request:
		break;
		case TDLS_Setup_Response:
		break;
		case TDLS_Setup_Confirm:
		break;
		case TDLS_Teardown:
		break;
		case TDLS_Peer_Traffic_Indication:
		break;
		case TDLS_Channel_Switch_Request:
		break;
		case TDLS_Channel_Switch_Response:
		break;
		case TDLS_Peer_PSM_Request:
		break;
		case TDLS_Peer_PSM_Response:
		break;
		case TDLS_Peer_Traffic_Response:
		break;
		case TDLS_Discovery_Request:
		break;
		// 11-255 Reserved

	}*/
}

void handle_action_mesh(struct packet *pkt, struct packet *recv_pkt)
{
	static enum action_code { Mesh_Link_Metric_Report,
							  HWMP_Mesh_Path_Selection,
							  Gate_Announcement,
							  Congestion_Control_Notification,
							  MCCA_Setup_Request,
							  MCCA_Setup_Reply,
							  MCCA_Advertisement_Request,
							  MCCA_Advertisement,
							  MCCA_Teardown,
							  TBTT_Adjustment_Request,
							  TBTT_Adjustment_Response };
	struct ieee80211_mgmt *m_action, *mgmt_action;
	static uint8_t action_codes[11] = {Mesh_Link_Metric_Report, HWMP_Mesh_Path_Selection, Gate_Announcement, Congestion_Control_Notification, MCCA_Setup_Request, MCCA_Setup_Reply,
									   MCCA_Advertisement_Request, MCCA_Advertisement, MCCA_Teardown, TBTT_Adjustment_Request, TBTT_Adjustment_Response};

	m_action = (struct ieee80211_mgmt *)pkt->data;
	if (recv_pkt)
	{
		mgmt_action = (struct ieee80211_mgmt *)recv_pkt->data;
		*((uint8_t *)&m_action->u.action.category + 1) = *((uint8_t *)&mgmt_action->u.action.category + 1) + 1;
	}
	else
	{
		if (0 == fuzzing_opt.seed)
			srandom(time(NULL));

		*((uint8_t *)&m_action->u.action.category + 1) = action_codes[random() % (sizeof(action_codes) / sizeof(action_codes[0]))];
	}

	/*switch( *((uint8_t*)&m_action->u.action.category + 1))
	{
		case Mesh_Link_Metric_Report:
		break;
		case HWMP_Mesh_Path_Selection:
		break;
		case Gate_Announcement:
		break;
		case Congestion_Control_Notification:
		break;
		case MCCA_Setup_Request:
		break;
		case MCCA_Setup_Reply:
		break;
		case MCCA_Advertisement_Request:
		break;
		case MCCA_Advertisement:
		break;
		case MCCA_Teardown:
		break;
		case TBTT_Adjustment_Request:
		break;
		case TBTT_Adjustment_Response:
		break;
		// 11-255 Reserved

	}*/
}

void handle_action_multihop(struct packet *pkt, struct packet *recv_pkt)
{
	static enum action_code { Proxy_Update,
							  Proxy_Update_Confirmation };
	struct ieee80211_mgmt *m_action, *mgmt_action;
	static uint8_t action_codes[2] = {Proxy_Update, Proxy_Update_Confirmation};

	m_action = (struct ieee80211_mgmt *)pkt->data;
	if (recv_pkt)
	{
		mgmt_action = (struct ieee80211_mgmt *)recv_pkt->data;
		*((uint8_t *)&m_action->u.action.category + 1) = *((uint8_t *)&mgmt_action->u.action.category + 1) + 1;
	}
	else
	{
		if (0 == fuzzing_opt.seed)
			srandom(time(NULL));

		*((uint8_t *)&m_action->u.action.category + 1) = action_codes[random() % (sizeof(action_codes) / sizeof(action_codes[0]))];
	}

	/*switch( *((uint8_t*)&m_action->u.action.category + 1))
	{
		case Proxy_Update:
		break;
		case Proxy_Update_Confirmation:
		break;
		// 2-255 Reserved
	}*/
}

void handle_action_self_protected(struct packet *pkt, struct packet *recv_pkt)
{
	static enum action_code { Mesh_Peering_Open,
							  Mesh_Peering_Confirm,
							  Mesh_Peering_Close,
							  Mesh_Group_Key_Inform,
							  Mesh_Group_Key_Acknowledge };
	struct ieee80211_mgmt *m_action, *mgmt_action;
	static uint8_t action_codes[5] = {Mesh_Peering_Open, Mesh_Peering_Confirm, Mesh_Peering_Close, Mesh_Group_Key_Inform, Mesh_Group_Key_Acknowledge};

	m_action = (struct ieee80211_mgmt *)pkt->data;
	if (recv_pkt)
	{
		mgmt_action = (struct ieee80211_mgmt *)recv_pkt->data;
		*((uint8_t *)&m_action->u.action.category + 1) = *((uint8_t *)&mgmt_action->u.action.category + 1) + 1;
	}
	else
	{
		if (0 == fuzzing_opt.seed)
			srandom(time(NULL));

		*((uint8_t *)&m_action->u.action.category + 1) = action_codes[random() % (sizeof(action_codes) / sizeof(action_codes[0]))];
	}

	/*switch( *((uint8_t*)&m_action->u.action.category + 1))
	{
		case Mesh_Peering_Open:
		break;
		case Mesh_Peering_Confirm:
		break;
		case Mesh_Peering_Close:
		break;
		case Mesh_Group_Key_Inform:
		break;
		case Mesh_Group_Key_Acknowledge:
		break;
	}*/
}

void handle_action_dmg(struct packet *pkt, struct packet *recv_pkt)
{
	static enum action_code { Power_Save_Configuration_Request,
							  Power_Save_Configuration_Response,
							  Information_Request,
							  Information_Response,
							  Handover_Request,
							  Handover_Response,
							  DTP_Request,
							  DTP_Response,
							  Relay_Search_Request,
							  Relay_Search_Response,
							  Multi_Relay_Channel_Measurement_Request,
							  Multi_Relay_Channel_Measurement_Report,
							  RLS_Request,
							  RLS_Response,
							  RLS_Announcement,
							  RLS_Teardown,
							  Relay_Ack_Request,
							  Relay_Ack_Response,
							  TPA_Request,
							  TPA_Response,
							  TPA_Report,
							  ROC_Request,
							  ROC_Response };
	struct ieee80211_mgmt *m_action, *mgmt_action;
	static uint8_t action_codes[23] = {Power_Save_Configuration_Request, Power_Save_Configuration_Response, Information_Request, Information_Response, Handover_Request, Handover_Response,
									   DTP_Request, DTP_Response, Relay_Search_Request, Relay_Search_Response, Multi_Relay_Channel_Measurement_Request, Multi_Relay_Channel_Measurement_Report,
									   RLS_Request, RLS_Response, RLS_Announcement, RLS_Teardown, Relay_Ack_Request, Relay_Ack_Response, TPA_Request, TPA_Response, TPA_Report, ROC_Request,
									   ROC_Response};

	m_action = (struct ieee80211_mgmt *)pkt->data;
	if (recv_pkt)
	{
		mgmt_action = (struct ieee80211_mgmt *)recv_pkt->data;
		*((uint8_t *)&m_action->u.action.category + 1) = *((uint8_t *)&mgmt_action->u.action.category + 1) + 1;
	}
	else
	{
		if (0 == fuzzing_opt.seed)
			srandom(time(NULL));

		*((uint8_t *)&m_action->u.action.category + 1) = action_codes[random() % (sizeof(action_codes) / sizeof(action_codes[0]))];
	}

	/*switch( *((uint8_t*)&m_action->u.action.category + 1))
	{
		case Power_Save_Configuration_Request:
		break;
		case Power_Save_Configuration_Response:
		break;
		case Information_Request:
		break;
		case Information_Response:
		break;
		case Handover_Request:
		break;
		case Handover_Response:
		break;
		case DTP_Request:
		break;
		case DTP_Response:
		break;
		case Relay_Search_Request:
		break;
		case Relay_Search_Response:
		break;
		case Multi_Relay_Channel_Measurement_Request:
		break;
		case Multi_Relay_Channel_Measurement_Report:
		break;
		case RLS_Request:
		break;
		case RLS_Response:
		break;
		case RLS_Announcement:
		break;
		case RLS_Teardown:
		break;
		case Relay_Ack_Request:
		break;
		case Relay_Ack_Response:
		break;
		case TPA_Request:
		break;
		case TPA_Response:
		break;
		case TPA_Report:
		break;
		case ROC_Request:
		break;
		case ROC_Response:
		break;
	}*/
}

void handle_action_wmm(struct packet *pkt, struct packet *recv_pkt)
{
	static enum action_code { a };
	struct ieee80211_mgmt *m_action, *mgmt_action;
	static uint8_t action_codes[7] = {0, 1, 2, 3, 4, 5, 6};

	m_action = (struct ieee80211_mgmt *)pkt->data;
	if (recv_pkt)
	{
		mgmt_action = (struct ieee80211_mgmt *)recv_pkt->data;
		*((uint8_t *)&m_action->u.action.category + 1) = *((uint8_t *)&mgmt_action->u.action.category + 1) + 1;
	}
	else
	{
		if (0 == fuzzing_opt.seed)
			srandom(time(NULL));

		*((uint8_t *)&m_action->u.action.category + 1) = action_codes[random() % (sizeof(action_codes) / sizeof(action_codes[0]))];
	}
}

void handle_action_fst(struct packet *pkt, struct packet *recv_pkt)
{
	static enum action_code { FST_Setup_Request,
							  FST_Setup_Response,
							  FST_Teardown,
							  FST_Ack_Request,
							  FST_Ack_Response,
							  On_channel_Tunnel_Request };
	struct ieee80211_mgmt *m_action, *mgmt_action;
	static uint8_t action_codes[6] = {FST_Setup_Request, FST_Setup_Response, FST_Teardown, FST_Ack_Request, FST_Ack_Response, On_channel_Tunnel_Request};

	m_action = (struct ieee80211_mgmt *)pkt->data;
	if (recv_pkt)
	{
		mgmt_action = (struct ieee80211_mgmt *)recv_pkt->data;
		*((uint8_t *)&m_action->u.action.category + 1) = *((uint8_t *)&mgmt_action->u.action.category + 1) + 1;
	}
	else
	{
		if (0 == fuzzing_opt.seed)
			srandom(time(NULL));

		*((uint8_t *)&m_action->u.action.category + 1) = action_codes[random() % (sizeof(action_codes) / sizeof(action_codes[0]))];
	}

	/*switch( *((uint8_t*)&m_action->u.action.category + 1))
	{
		case FST_Setup_Request:
		break;
		case FST_Setup_Response:
		break;
		case FST_Teardown:
		break;
		case FST_Ack_Request:
		break;
		case FST_Ack_Response:
		break;
		case On_channel_Tunnel_Request:
		break;
	}*/
}

void handle_action_robust_av_streaming(struct packet *pkt, struct packet *recv_pkt)
{
	static enum action_code { SCS_Request,
							  SCS_Response,
							  Group_Membership_Request,
							  Group_Membership_Response };
	struct ieee80211_mgmt *m_action, *mgmt_action;
	static uint8_t action_codes[4] = {SCS_Request, SCS_Response, Group_Membership_Request, Group_Membership_Response};

	m_action = (struct ieee80211_mgmt *)pkt->data;
	if (recv_pkt)
	{
		mgmt_action = (struct ieee80211_mgmt *)recv_pkt->data;
		*((uint8_t *)&m_action->u.action.category + 1) = *((uint8_t *)&mgmt_action->u.action.category + 1) + 1;
	}
	else
	{
		if (0 == fuzzing_opt.seed)
			srandom(time(NULL));

		*((uint8_t *)&m_action->u.action.category + 1) = action_codes[random() % (sizeof(action_codes) / sizeof(action_codes[0]))];
	}

	/*switch( *((uint8_t*)&m_action->u.action.category + 1))
	{
		case SCS_Request:
		break;
		case SCS_Response:
		break;
		case Group_Membership_Request:
		break;
		case Group_Membership_Response:
		break;
	}*/
}

void handle_action_unprotected_dmg(struct packet *pkt, struct packet *recv_pkt)
{
	static enum action_code { Announce,
							  BRP };
	struct ieee80211_mgmt *m_action, *mgmt_action;
	static uint8_t action_codes[2] = {Announce, BRP};

	m_action = (struct ieee80211_mgmt *)pkt->data;
	if (recv_pkt)
	{
		mgmt_action = (struct ieee80211_mgmt *)recv_pkt->data;
		*((uint8_t *)&m_action->u.action.category + 1) = *((uint8_t *)&mgmt_action->u.action.category + 1) + 1;
	}
	else
	{
		if (0 == fuzzing_opt.seed)
			srandom(time(NULL));

		*((uint8_t *)&m_action->u.action.category + 1) = action_codes[random() % (sizeof(action_codes) / sizeof(action_codes[0]))];
	}

	/*switch( *((uint8_t*)&m_action->u.action.category + 1))
	{
	case Announce:
		break;
	case BRP:
		break;

	default:
		break;
	}*/
}

void handle_action_vht(struct packet *pkt, struct packet *recv_pkt)
{
	static enum action_code { VHT_Compressed_Beamforming,
							  Group_ID_Management,
							  Operating_Mode_Notification };
	struct ieee80211_mgmt *m_action, *mgmt_action;
	static uint8_t action_codes[3] = {VHT_Compressed_Beamforming, Group_ID_Management, Operating_Mode_Notification};

	m_action = (struct ieee80211_mgmt *)pkt->data;
	if (recv_pkt)
	{
		mgmt_action = (struct ieee80211_mgmt *)recv_pkt->data;
		*((uint8_t *)&m_action->u.action.category + 1) = *((uint8_t *)&mgmt_action->u.action.category + 1) + 1;
	}
	else
	{
		if (0 == fuzzing_opt.seed)
			srandom(time(NULL));

		*((uint8_t *)&m_action->u.action.category + 1) = action_codes[random() % (sizeof(action_codes) / sizeof(action_codes[0]))];
	}

	/*switch( *((uint8_t*)&m_action->u.action.category + 1))
	{
	case VHT_Compressed_Beamforming:
		break;
	case Group_ID_Management:
		break;
	case Operating_Mode_Notification:
		break;
	default:
		break;
	}*/
}

void handle_action_fils(struct packet *pkt, struct packet *recv_pkt)
{
	static enum action_code { a };
	struct ieee80211_mgmt *m_action, *mgmt_action;
	static uint8_t action_codes[3] = {0, 1, 2};

	m_action = (struct ieee80211_mgmt *)pkt->data;
	if (recv_pkt)
	{
		mgmt_action = (struct ieee80211_mgmt *)recv_pkt->data;
		*((uint8_t *)&m_action->u.action.category + 1) = *((uint8_t *)&mgmt_action->u.action.category + 1) + 1;
	}
	else
	{
		if (0 == fuzzing_opt.seed)
			srandom(time(NULL));

		*((uint8_t *)&m_action->u.action.category + 1) = action_codes[random() % (sizeof(action_codes) / sizeof(action_codes[0]))];
	}
}

void handle_action_vendor_specific_protected(struct packet *pkt, struct packet *recv_pkt)
{
	static enum action_code { a };
	struct ieee80211_mgmt *m_action, *mgmt_action;
	static uint8_t action_codes[3] = {0, 1, 2};

	m_action = (struct ieee80211_mgmt *)pkt->data;
	if (recv_pkt)
	{
		mgmt_action = (struct ieee80211_mgmt *)recv_pkt->data;
		*((uint8_t *)&m_action->u.action.category + 1) = *((uint8_t *)&mgmt_action->u.action.category + 1) + 1;
	}
	else
	{
		if (0 == fuzzing_opt.seed)
			srandom(time(NULL));

		*((uint8_t *)&m_action->u.action.category + 1) = action_codes[random() % (sizeof(action_codes) / sizeof(action_codes[0]))];
	}
}

void handle_action_vendor_specific(struct packet *pkt, struct packet *recv_pkt)
{
	struct ieee80211_mgmt *m_action, *mgmt_action;
	static uint8_t action_codes[3] = {0, 1, 2};

	m_action = (struct ieee80211_mgmt *)pkt->data;
	if (recv_pkt)
	{
		mgmt_action = (struct ieee80211_mgmt *)recv_pkt->data;
		*((uint8_t *)&m_action->u.action.category + 1) = *((uint8_t *)&mgmt_action->u.action.category + 1) + 1;
	}
	else
	{
		if (0 == fuzzing_opt.seed)
			srandom(time(NULL));

		*((uint8_t *)&m_action->u.action.category + 1) = action_codes[random() % (sizeof(action_codes) / sizeof(action_codes[0]))];
	}
}
