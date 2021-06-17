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

#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <pthread.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/time.h>
#include "kismet_wifi_control.h"
#include "frames/frame.h"
#include "common/log.h" 
#include "common/pcap_log.h"
#include "fuzz_control.h"


struct packet bad_frame[300] = {
	{{0}, 0}
};

fuzzing_option fuzzing_opt = {0};

#define DEAUTH_TIME 10

uint8_t ap_frames[] = 
{
	// management
	IEEE80211_TYPE_ASSOCRES,
	IEEE80211_TYPE_REASSOCRES,
	IEEE80211_TYPE_PROBERES,
	IEEE80211_TYPE_TIMADVERT,
	////IEEE80211_TYPE_000111,
	IEEE80211_TYPE_BEACON,
	IEEE80211_TYPE_ATIM,
	////IEEE80211_TYPE_DISASSOC,
	IEEE80211_TYPE_AUTH,
	////IEEE80211_TYPE_DEAUTH,
	IEEE80211_TYPE_ACTION,
	IEEE80211_TYPE_ACTIONNOACK,
	////IEEE80211_TYPE_001111,

	// control DEAUTH_TIME 10
	IEEE80211_TYPE_BEAMFORMING,
	IEEE80211_TYPE_VHT,
	IEEE80211_TYPE_CTRLFRMEXT,
	IEEE80211_TYPE_CTRLWRAP,
	IEEE80211_TYPE_BLOCKACKREQ,
	IEEE80211_TYPE_BLOCKACK,
	IEEE80211_TYPE_PSPOLL,
	IEEE80211_TYPE_RTS,
	IEEE80211_TYPE_CTS,
	IEEE80211_TYPE_ACK,
	IEEE80211_TYPE_CFEND,
	IEEE80211_TYPE_CFENDACK,

	// data
	IEEE80211_TYPE_DATA,
	IEEE80211_TYPE_DATACFACK,
	IEEE80211_TYPE_DATACFPOLL,
	IEEE80211_TYPE_DATACFACKPOLL,
	IEEE80211_TYPE_NULL,
	IEEE80211_TYPE_CFACK,
	IEEE80211_TYPE_CFPOLL,
	IEEE80211_TYPE_CFACKPOLL,
	IEEE80211_TYPE_QOSDATA,
	IEEE80211_TYPE_QOSDATACFACK,
	IEEE80211_TYPE_QOSDATACFPOLL,
	IEEE80211_TYPE_QOSDATACFACKPOLL,
	IEEE80211_TYPE_QOSNULL,
	IEEE80211_TYPE_QOSCFACK,
	IEEE80211_TYPE_QOSCFPOLL,
	IEEE80211_TYPE_QOSCFACKPOLL,

};

uint8_t sta_frames[] = 
{
	// management
	//IEEE80211_TYPE_ASSOCREQ,
	//IEEE80211_TYPE_ASSOCRES,
	//IEEE80211_TYPE_REASSOCREQ,
	//IEEE80211_TYPE_REASSOCRES,
	IEEE80211_TYPE_PROBEREQ,
	//IEEE80211_TYPE_PROBERES,
	IEEE80211_TYPE_TIMADVERT,
	//IEEE80211_TYPE_000111,
	//IEEE80211_TYPE_BEACON,
	IEEE80211_TYPE_ATIM,
	//IEEE80211_TYPE_DISASSOC,
	//IEEE80211_TYPE_AUTH,
	//IEEE80211_TYPE_DEAUTH,
	IEEE80211_TYPE_ACTION,
	IEEE80211_TYPE_ACTIONNOACK,
	//IEEE80211_TYPE_001111,

	// control
	IEEE80211_TYPE_BEAMFORMING,
	IEEE80211_TYPE_VHT,
	IEEE80211_TYPE_CTRLFRMEXT,
	IEEE80211_TYPE_CTRLWRAP,
	IEEE80211_TYPE_BLOCKACKREQ,
	IEEE80211_TYPE_BLOCKACK,
	IEEE80211_TYPE_PSPOLL,
	IEEE80211_TYPE_RTS,
	IEEE80211_TYPE_CTS,
	IEEE80211_TYPE_ACK,
	IEEE80211_TYPE_CFEND,
	IEEE80211_TYPE_CFENDACK,

	// data
	IEEE80211_TYPE_DATA,
	IEEE80211_TYPE_DATACFACK,
	IEEE80211_TYPE_DATACFPOLL,
	IEEE80211_TYPE_DATACFACKPOLL,
	IEEE80211_TYPE_NULL,
	IEEE80211_TYPE_CFACK,
	IEEE80211_TYPE_CFPOLL,
	IEEE80211_TYPE_CFACKPOLL,
	IEEE80211_TYPE_QOSDATA,
	IEEE80211_TYPE_QOSDATACFACK,
	IEEE80211_TYPE_QOSDATACFPOLL,
	IEEE80211_TYPE_QOSDATACFACKPOLL,
	IEEE80211_TYPE_QOSNULL,
	IEEE80211_TYPE_QOSCFACK,
	IEEE80211_TYPE_QOSCFPOLL,
	IEEE80211_TYPE_QOSCFACKPOLL,

};

uint8_t all_frames[] = 
{
	// management
	IEEE80211_TYPE_ASSOCREQ,
	IEEE80211_TYPE_ASSOCRES,
	IEEE80211_TYPE_REASSOCREQ,
	IEEE80211_TYPE_REASSOCRES,
	IEEE80211_TYPE_PROBEREQ,
	IEEE80211_TYPE_PROBERES,
	IEEE80211_TYPE_TIMADVERT,
	//IEEE80211_TYPE_000111,
	IEEE80211_TYPE_BEACON,
	IEEE80211_TYPE_ATIM,
	//IEEE80211_TYPE_DISASSOC,
	IEEE80211_TYPE_AUTH,
	//IEEE80211_TYPE_DEAUTH,
	IEEE80211_TYPE_ACTION,
	IEEE80211_TYPE_ACTIONNOACK,
	//IEEE80211_TYPE_001111,

	// control
	IEEE80211_TYPE_BEAMFORMING,
	IEEE80211_TYPE_VHT,
	IEEE80211_TYPE_CTRLFRMEXT,
	IEEE80211_TYPE_CTRLWRAP,
	IEEE80211_TYPE_BLOCKACKREQ,
	IEEE80211_TYPE_BLOCKACK,
	IEEE80211_TYPE_PSPOLL,
	IEEE80211_TYPE_RTS,
	IEEE80211_TYPE_CTS,
	IEEE80211_TYPE_ACK,
	IEEE80211_TYPE_CFEND,
	IEEE80211_TYPE_CFENDACK,

	// data
	IEEE80211_TYPE_DATA,
	IEEE80211_TYPE_DATACFACK,
	IEEE80211_TYPE_DATACFPOLL,
	IEEE80211_TYPE_DATACFACKPOLL,
	IEEE80211_TYPE_NULL,
	IEEE80211_TYPE_CFACK,
	IEEE80211_TYPE_CFPOLL,
	IEEE80211_TYPE_CFACKPOLL,
	IEEE80211_TYPE_QOSDATA,
	IEEE80211_TYPE_QOSDATACFACK,
	IEEE80211_TYPE_QOSDATACFPOLL,
	IEEE80211_TYPE_QOSDATACFACKPOLL,
	IEEE80211_TYPE_QOSNULL,
	IEEE80211_TYPE_QOSCFACK,
	IEEE80211_TYPE_QOSCFPOLL,
	IEEE80211_TYPE_QOSCFACKPOLL,

};

void usage_help(char* name)
{
	printf("owfuzz usage:\n"
	    "\texample: sudo ./owfuzz -i wlan0 -m ap -c [channel] -t [target-mac] -b [ap-mac] -s [ap-mac] -T 2 -A WPA2_PSK_TKIP_AES -I [targe-ip]\n"
		"\t-i [interface]\n"
		"\t   Interface to use.\n"
		"\t-m [ap/sta]\n"
		"\t   Set the mode of fuzzer, default is ap.\n"
		"\t-c [channel]\n"
		"\t   Set the working channel of fuzzer, default is 1.\n"
		"\t-t [mac]\n"
		"\t   Target's MAC address.\n"
		"\t-S [SSID]\n"
		"\t   AP's SSID.\n"
		"\t-A [auth type]\n"
		"\t   Target's auth type: OPEN_NONE, OPEN_WEP, SHARE_WEP, WPA_PSK_TKIP, WPA_PSK_AES, WPA_PSK_TKIP_AES, WPA2_PSK_TKIP, WPA2_PSK_AES, WPA2_PSK_TKIP_AES, EAP_8021X, WPA3\n"
		"\t-I [IP address]\n"
		"\t   Target's IP address\n"
		"\t-b [BSSID]\n"
		"\t   AP's Mac address\n"
		"\t-s [mac]\n"
		"\t   Fuzzer's (source) Mac address.\n"
		"\t-T [test type]\n"
		"\t   Test type, default 1, 0: Poc test, 1: interactive test, 2: frames test, 3: interactive & frames test\n"
//		"\t-l [log level]\n"
//		"\t   Log level, 8:DEBUG, 7:INFO, 6:NOTICE, 5:WARN, 4:ERR, 3:CRIT, 2:ALERT, 1:EMERG, 0:STDERR\n"
		"\t-f [log file]\n"
		"\t   Log file path\n"
		"\t-h\n"
		"\t   Help.\n");
}

void* test_bad_frame(void *param)
{
	int i = 0;
	int cnt = sizeof(bad_frame) / sizeof(bad_frame[0]);
	fuzzing_option *fuzzing_opt = (fuzzing_option*)param;
	uint16_t next_seqno = 0;
	struct ieee_hdr *hdr;
	uint8_t dsflags;
	int t=0;

	load_payloads();

	sleep(2);

	while(1)
	{
		for(i = 0; i<cnt; i++ )
		{
			if(bad_frame[i].len != 0)
			{
				hdr = (struct ieee_hdr *)bad_frame[i].data;
				dsflags = hdr->flags & 0x03;
				if((hdr->type & 0x0F) != CONTROL_FRAME)
				{
					switch (dsflags) {
						case 0x00:
						MAC_COPY(hdr->addr1, fuzzing_opt->target_addr);
						MAC_COPY(hdr->addr2, fuzzing_opt->source_addr);
						MAC_COPY(hdr->addr3, fuzzing_opt->bssid);
						break;
						case 0x01:
						MAC_COPY(hdr->addr1, fuzzing_opt->bssid);
						MAC_COPY(hdr->addr2, fuzzing_opt->source_addr);
						MAC_COPY(hdr->addr3, fuzzing_opt->target_addr);
						break;
						case 0x02:
						MAC_COPY(hdr->addr1, fuzzing_opt->target_addr);
						MAC_COPY(hdr->addr2, fuzzing_opt->bssid);
						MAC_COPY(hdr->addr3, fuzzing_opt->source_addr);
						break;
						case 0x03:
						MAC_COPY(hdr->addr1, fuzzing_opt->bssid);
						MAC_COPY(hdr->addr2, fuzzing_opt->bssid);
						MAC_COPY(hdr->addr3, fuzzing_opt->target_addr);
						MAC_COPY(*(struct ether_addr*)(bad_frame[i].data + sizeof(struct ieee_hdr)), fuzzing_opt->source_addr);
						break;
					}

					if(hdr->type == IEEE80211_TYPE_BEACON)
					{
						memcpy(hdr->addr1.ether_addr_octet, BROADCAST, ETHER_ADDR_LEN);
					}

					if((hdr->type & 0x0F) == MANAGMENT_FRAME)
					{
						next_seqno = fuzzing_opt->seq_ctrl + 1;
						fuzz_logger_log(FUZZ_LOG_DEBUG, "test management frame payload seq = %d", next_seqno);
						set_seqno(&bad_frame[i], next_seqno);
						fuzzing_opt->seq_ctrl++;
					}
					else if((hdr->type & 0x0F) == DATA_FRAME)
					{
						next_seqno = fuzzing_opt->data_seq_ctrl + 1;
						fuzz_logger_log(FUZZ_LOG_DEBUG, "test data frame payload seq = %d", next_seqno);
						set_seqno(&bad_frame[i], next_seqno);
						fuzzing_opt->data_seq_ctrl++;
					}
				}
				else{
					switch(hdr->type)
					{
						// control addr1,(addr2)
						case IEEE80211_TYPE_BEAMFORMING:
						#ifdef DEBUG_LOG
							fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->(control)IEEE80211_TYPE_BEAMFORMING");
						#endif
							memcpy(hdr->addr1.ether_addr_octet, fuzzing_opt->target_addr.ether_addr_octet, ETHER_ADDR_LEN);
							memcpy(hdr->addr2.ether_addr_octet, fuzzing_opt->source_addr.ether_addr_octet, ETHER_ADDR_LEN);
							break;
						case IEEE80211_TYPE_VHT:
						#ifdef DEBUG_LOG
							fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->(control)IEEE80211_TYPE_VHT");
						#endif
							memcpy(hdr->addr1.ether_addr_octet, fuzzing_opt->target_addr.ether_addr_octet, ETHER_ADDR_LEN);
							memcpy(hdr->addr2.ether_addr_octet, fuzzing_opt->source_addr.ether_addr_octet, ETHER_ADDR_LEN);
							break;
						case IEEE80211_TYPE_CTRLFRMEXT:
						#ifdef DEBUG_LOG
							fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->(control)IEEE80211_TYPE_CTRLFRMEXT");
						#endif
							break;
						case IEEE80211_TYPE_CTRLWRAP:
						#ifdef DEBUG_LOG
							fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->(control)IEEE80211_TYPE_CTRLWRAP");
						#endif
							memcpy(hdr->addr1.ether_addr_octet, fuzzing_opt->target_addr.ether_addr_octet, ETHER_ADDR_LEN);
							break;
						case IEEE80211_TYPE_BLOCKACKREQ:
						#ifdef DEBUG_LOG
							fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->(control)IEEE80211_TYPE_BLOCKACKREQ");
						#endif
							memcpy(hdr->addr1.ether_addr_octet, fuzzing_opt->target_addr.ether_addr_octet, ETHER_ADDR_LEN);
							memcpy(hdr->addr2.ether_addr_octet, fuzzing_opt->source_addr.ether_addr_octet, ETHER_ADDR_LEN);
							break;
						case IEEE80211_TYPE_BLOCKACK:
						#ifdef DEBUG_LOG
							fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->(control)IEEE80211_TYPE_BLOCKACK");
						#endif
							memcpy(hdr->addr1.ether_addr_octet, fuzzing_opt->target_addr.ether_addr_octet, ETHER_ADDR_LEN);
							memcpy(hdr->addr2.ether_addr_octet, fuzzing_opt->source_addr.ether_addr_octet, ETHER_ADDR_LEN);
							break;
						case IEEE80211_TYPE_PSPOLL:
						#ifdef DEBUG_LOG
							fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->(control)IEEE80211_TYPE_PSPOLL");
						#endif
							memcpy(hdr->addr1.ether_addr_octet, fuzzing_opt->target_addr.ether_addr_octet, ETHER_ADDR_LEN);
							memcpy(hdr->addr2.ether_addr_octet, fuzzing_opt->source_addr.ether_addr_octet, ETHER_ADDR_LEN);
							break;
						case IEEE80211_TYPE_RTS:
						#ifdef DEBUG_LOG
							fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->(control)IEEE80211_TYPE_RTS");
						#endif
							memcpy(hdr->addr1.ether_addr_octet, fuzzing_opt->target_addr.ether_addr_octet, ETHER_ADDR_LEN);
							memcpy(hdr->addr2.ether_addr_octet, fuzzing_opt->source_addr.ether_addr_octet, ETHER_ADDR_LEN);
							break;
						case IEEE80211_TYPE_CTS:
						#ifdef DEBUG_LOG
							fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->(control)IEEE80211_TYPE_CTS");
						#endif
							memcpy(hdr->addr1.ether_addr_octet, fuzzing_opt->target_addr.ether_addr_octet, ETHER_ADDR_LEN);
							break;
						case IEEE80211_TYPE_ACK:
						#ifdef DEBUG_LOG
							fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->(control)IEEE80211_TYPE_ACK");
						#endif
							memcpy(hdr->addr1.ether_addr_octet, fuzzing_opt->target_addr.ether_addr_octet, ETHER_ADDR_LEN);
							break;
						case IEEE80211_TYPE_CFEND:
						#ifdef DEBUG_LOG
							fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->(control)IEEE80211_TYPE_CFEND");
						#endif
							memcpy(hdr->addr1.ether_addr_octet, fuzzing_opt->target_addr.ether_addr_octet, ETHER_ADDR_LEN);
							memcpy(hdr->addr2.ether_addr_octet, fuzzing_opt->source_addr.ether_addr_octet, ETHER_ADDR_LEN);
							break;
						case IEEE80211_TYPE_CFENDACK:
						#ifdef DEBUG_LOG
							fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->(control)IEEE80211_TYPE_CFENDACK");
						#endif
							memcpy(hdr->addr1.ether_addr_octet, fuzzing_opt->target_addr.ether_addr_octet, ETHER_ADDR_LEN);
							memcpy(hdr->addr2.ether_addr_octet, fuzzing_opt->source_addr.ether_addr_octet, ETHER_ADDR_LEN);
							break;
						default:
						#ifdef DEBUG_LOG
							fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->unknown frame!!!");
						#endif
							break;
					}
				}

				fuzz_logger_log(FUZZ_LOG_INFO, "sending payload...");

				send_frame(&bad_frame[i]);

				log_pkt(FUZZ_LOG_DEBUG, &bad_frame[i]);

				if(fuzzing_opt->enable_check_alive)
					if(!check_alive_by_ping())
						exit(-1);
			}
			
		}

		usleep(10000);
	}

}


int init(char *interface, int chan)
{
	char szerr[1024] = {0};
	int mode = 0;
	int channel = 0;

	kismet_interface_down(interface, szerr);
	sleep(1);
	kismet_set_mode(interface, szerr, 6);
	kismet_interface_up(interface, szerr);
	sleep(0.5);
	kismet_set_channel(interface, chan, szerr);
	kismet_get_mode(interface, szerr, &mode);
	channel = kismet_get_channel(interface, szerr);
	
	if(mode != 6 || channel != chan)
	{
		fuzz_logger_log(FUZZ_LOG_ERR, "init interface failed.");
		fuzz_logger_log(FUZZ_LOG_ERR, "\tinterface %s ,mode: %d , channel: %d", interface, mode, channel);
		return -1;
	}

	return env_init(interface);
}

void* fuzzing_thread(void *param)
{
	struct packet fuzz_pkt = {0};
	struct ether_addr fuzzer_mac = {0};

	struct timeval tv;
	uint64_t current_time;
	uint64_t pass_time;
	uint64_t fuzz_current_time;
	uint64_t fuzz_pass_time;
	uint32_t frame_idx = 0;
	uint32_t frame_array_size = 0;
	uint8_t *fuzz_frames;

	fuzzing_option *fuzzing_opt = (fuzzing_option*)param;
	memcpy(fuzzer_mac.ether_addr_octet, fuzzing_opt->source_addr.ether_addr_octet, 6);

 	gettimeofday(&tv,NULL);
	pass_time = tv.tv_sec*1000 + tv.tv_usec/1000;
	fuzz_pass_time = /*tv.tv_sec;*/tv.tv_sec*1000 + tv.tv_usec/1000;

	if(FUZZ_WORK_MODE_AP == fuzzing_opt->fuzz_work_mode)
	{
		//fuzz sta
		frame_array_size = sizeof(ap_frames)/sizeof(ap_frames[0]);
		fuzz_frames = ap_frames;

	}
	else if(FUZZ_WORK_MODE_STA == fuzzing_opt->fuzz_work_mode)
	{
		// fuzz ap
		frame_array_size = sizeof(sta_frames)/sizeof(sta_frames[0]);
		fuzz_frames = sta_frames;
	}

	//fuzz_frames = all_frames;
	//frame_array_size = sizeof(all_frames)/sizeof(all_frames[0]);

	fuzz_logger_log(FUZZ_LOG_DEBUG, "fuzzing frames count: %d", frame_array_size);

	print_status();

	sleep(2);

	while(1)
	{
		gettimeofday(&tv,NULL);
		current_time = tv.tv_sec*1000 + tv.tv_usec/1000;
		fuzz_current_time = tv.tv_sec*1000 + tv.tv_usec/1000;

		if(0 == strcmp(fuzzing_opt->mode, AP_MODE) && fuzzing_opt->test_type == 1)
		{
			if(current_time - pass_time >= 100)
			{
				// ap
				fuzz_pkt = get_default_frame(IEEE80211_TYPE_BEACON, fuzzer_mac, fuzzer_mac, SE_NULLMAC, NULL);
				send_frame(&fuzz_pkt);

				pass_time = current_time;
			}	

		}

		if(fuzzing_opt->test_type >= 2 && (fuzz_current_time - fuzz_pass_time >= 50))
		{
			frame_idx = 0;

			for(frame_idx = 0; frame_idx < frame_array_size; frame_idx++)
			{
				fuzz_logger_log(FUZZ_LOG_DEBUG, "fuzzing frame idx: %d", frame_idx);

				memset(&fuzz_pkt, 0, sizeof(fuzz_pkt));
				fuzz_pkt = get_frame(fuzz_frames[frame_idx], fuzzing_opt->bssid, fuzzing_opt->source_addr, fuzzing_opt->target_addr, NULL);
				send_frame(&fuzz_pkt);

				usleep(100000);

				if(fuzzing_opt->enable_check_alive)
					if(!check_alive_by_ping()){
						save_exp_payload(&fuzz_pkt);
						log_pkt(FUZZ_LOG_ERR, &fuzz_pkt);
						sleep(5);
					}

				print_status();
			}

			fuzz_pass_time = fuzz_current_time;
		}

		usleep(10);
	}
}

void handle_action(struct packet *pkt,struct ether_addr bssid, struct ether_addr smac, struct ether_addr dmac, fuzzing_option *fuzzing_opt)
{
	
}

void handle_sta_auth(struct packet *pkt,struct ether_addr bssid, struct ether_addr smac, struct ether_addr dmac, fuzzing_option *fuzzing_opt)
{
	struct ieee_hdr *hdr;
	struct packet fuzz_pkt;
	uint8_t frame_type = 0;

	hdr = (struct ieee_hdr *) pkt->data;
	frame_type = hdr->type;
	frame_type = frame_type & 0x0F;

	switch(hdr->type)
	{
	case IEEE80211_TYPE_PROBEREQ:
	{
		fuzz_pkt = get_frame(IEEE80211_TYPE_ACK, bssid, dmac, smac, NULL);
		send_frame(&fuzz_pkt);
		fuzz_pkt = get_frame(IEEE80211_TYPE_PROBERES, bssid, dmac, smac, pkt);
		send_frame(&fuzz_pkt);
		if(fuzzing_opt->wpa_s < WPA_SCANNING)
			fuzzing_opt->wpa_s = WPA_SCANNING;
		
		print_interaction_status(bssid, smac, dmac, "Probe Request", "Probe Response");
	}
	break;
	case IEEE80211_TYPE_AUTH:
	{
		fuzz_pkt = get_frame(IEEE80211_TYPE_ACK, bssid, dmac, smac, NULL);
		send_frame(&fuzz_pkt);
		fuzzing_opt->wpa_s = WPA_AUTHENTICATING;
		fuzz_pkt = get_frame(IEEE80211_TYPE_AUTH, bssid, dmac, smac, pkt);
		send_frame(&fuzz_pkt);
		
	}
	break;
	case IEEE80211_TYPE_ASSOCREQ:
	case IEEE80211_TYPE_REASSOCREQ:
	{
		fuzzing_opt->wpa_s = WPA_ASSOCIATING;
		fuzz_pkt = get_frame(IEEE80211_TYPE_ACK, bssid, dmac, smac, NULL);
		send_frame(&fuzz_pkt);
		fuzz_pkt = get_default_frame(IEEE80211_TYPE_ASSOCRES, bssid, dmac, smac, pkt);
		send_frame(&fuzz_pkt);

		fuzzing_opt->wpa_s = WPA_ASSOCIATED;

		print_interaction_status(bssid, smac, dmac, "Association Request", "Association Response");

		// 4-way-handshake m1
		if(fuzzing_opt->auth_type == WPA3 || fuzzing_opt->auth_type==WPA2_PSK_TKIP_AES || fuzzing_opt->auth_type==WPA2_PSK_AES || fuzzing_opt->auth_type==WPA2_PSK_TKIP || 
		fuzzing_opt->auth_type==WPA_PSK_TKIP_AES || fuzzing_opt->auth_type==WPA_PSK_AES || fuzzing_opt->auth_type==WPA_PSK_TKIP)
		{
			fuzzing_opt->wpa_s = WPA_4WAY_HANDSHAKE;
			fuzz_pkt = get_frame(IEEE80211_TYPE_QOSDATA, bssid, dmac, smac, NULL);
			send_frame(&fuzz_pkt);
		}
		else if(fuzzing_opt->auth_type == EAP_8021X)
		{
			fuzzing_opt->wpa_s = WPA_EAP_HANDSHAKE;
			fuzz_pkt = get_frame(IEEE80211_TYPE_QOSDATA, bssid, dmac, smac, NULL);
			send_frame(&fuzz_pkt);			
		}
		else
		{
			fuzzing_opt->wpa_s = WPA_COMPLETED;
		}
	}
	break;
	case IEEE80211_TYPE_DATA:
	{
		fuzz_pkt = get_frame(IEEE80211_TYPE_ACK, bssid, dmac, smac, NULL);
		send_frame(&fuzz_pkt);

		fuzz_pkt = get_frame(IEEE80211_TYPE_DATA, bssid, dmac, smac, pkt);
		send_frame(&fuzz_pkt);
	}
	break;
	case IEEE80211_TYPE_QOSDATA:
	{
		fuzz_pkt = get_frame(IEEE80211_TYPE_ACK, bssid, dmac, smac, NULL);
		send_frame(&fuzz_pkt);

		fuzz_pkt = get_frame(IEEE80211_TYPE_QOSDATA, bssid, dmac, smac, pkt);
		send_frame(&fuzz_pkt);
	}
	break;
	case IEEE80211_TYPE_DISASSOC:
		fuzzing_opt->wpa_s = WPA_DISCONNECTED;
		fuzz_pkt = get_frame(IEEE80211_TYPE_ACK, bssid, dmac, smac, pkt);
		send_frame(&fuzz_pkt);
		fuzz_pkt = get_frame(IEEE80211_TYPE_DISASSOC, bssid, dmac, smac, pkt);
		send_frame(&fuzz_pkt);
		break;
	case IEEE80211_TYPE_DEAUTH:
		fuzzing_opt->wpa_s = WPA_DISCONNECTED;
		fuzz_pkt = get_frame(IEEE80211_TYPE_ACK, bssid, dmac, smac, pkt);
		send_frame(&fuzz_pkt);
		fuzz_pkt = get_frame(IEEE80211_TYPE_DEAUTH, bssid, dmac, smac, pkt);
		send_frame(&fuzz_pkt);
		break;
	case IEEE80211_TYPE_ACTION:
		fuzz_pkt = get_frame(IEEE80211_TYPE_ACK, bssid, dmac, smac, pkt);
		send_frame(&fuzz_pkt);
		fuzz_pkt = get_frame(IEEE80211_TYPE_ACTION, bssid, dmac, smac, pkt);
		send_frame(&fuzz_pkt);
		break;
	default:
	break;
	}

}

void handle_ap_auth(struct packet *pkt,struct ether_addr bssid, struct ether_addr smac, struct ether_addr dmac, fuzzing_option *fuzzing_opt)
{
	struct ieee_hdr *hdr;
	struct packet fuzz_pkt = {0};
	uint8_t frame_type = 0;

	hdr = (struct ieee_hdr *) pkt->data;
	frame_type = hdr->type;
	frame_type = frame_type & 0x0F;

	if(FUZZ_WORK_MODE_STA == fuzzing_opt->fuzz_work_mode)
	{
		switch(hdr->type)
		{
		case IEEE80211_TYPE_BEACON:
			if(fuzzing_opt->wpa_s < WPA_SCANNING)
			{
				fuzz_pkt = get_frame(IEEE80211_TYPE_PROBEREQ, bssid, fuzzing_opt->source_addr, smac, pkt);
				send_frame(&fuzz_pkt);
				fuzzing_opt->wpa_s = WPA_SCANNING;
				print_interaction_status(bssid, smac, fuzzing_opt->source_addr, "Beacon", "Probe Request");
			}

			break;
		case IEEE80211_TYPE_PROBERES:
			fuzz_pkt = get_frame(IEEE80211_TYPE_ACK, bssid, dmac, smac, pkt);
			send_frame(&fuzz_pkt);

			//print_interaction_status(bssid, smac, dmac, "Probe Response", "");

			fuzz_pkt = get_frame(IEEE80211_TYPE_AUTH, bssid, dmac, smac, NULL);
			send_frame(&fuzz_pkt);
			break;
		case IEEE80211_TYPE_AUTH:
			fuzz_pkt = get_frame(IEEE80211_TYPE_ACK, bssid, dmac, smac, NULL);
			send_frame(&fuzz_pkt);	

			fuzz_pkt = get_frame(IEEE80211_TYPE_AUTH, bssid, dmac, smac, pkt);
			if(fuzz_pkt.len)
				send_frame(&fuzz_pkt);

			if(fuzzing_opt->wpa_s == WPA_ASSOCIATING)
			{
				fuzz_pkt = get_frame(IEEE80211_TYPE_ASSOCREQ, bssid, dmac, smac, pkt);
				send_frame(&fuzz_pkt);
				
				print_interaction_status(bssid, smac, dmac, "", "Association Request");
			}

			break;
		case IEEE80211_TYPE_ASSOCRES:
			fuzzing_opt->wpa_s = WPA_ASSOCIATED;
			fuzz_pkt = get_frame(IEEE80211_TYPE_ACK, bssid, dmac, smac, NULL);
			send_frame(&fuzz_pkt);

			print_interaction_status(bssid, smac, dmac, "Association Response", "");

			// recevice 4-way-handshake msg1 from ap
			if(fuzzing_opt->auth_type == WPA3 || fuzzing_opt->auth_type==WPA2_PSK_TKIP_AES || fuzzing_opt->auth_type==WPA2_PSK_AES || fuzzing_opt->auth_type==WPA2_PSK_TKIP || 
			fuzzing_opt->auth_type==WPA_PSK_TKIP_AES || fuzzing_opt->auth_type==WPA_PSK_AES || fuzzing_opt->auth_type==WPA_PSK_TKIP)
			{
				//fuzzing_opt->wpa_s = WPA_4WAY_HANDSHAKE;
				//fuzz_pkt = get_frame(IEEE80211_TYPE_QOSDATA, bssid, dmac, smac, NULL);
				//send_frame(&fuzz_pkt);
			}
			else if(fuzzing_opt->auth_type == EAP_8021X)
			{
				//fuzzing_opt->wpa_s = WPA_EAP_HANDSHAKE;
				//fuzz_pkt = get_frame(IEEE80211_TYPE_QOSDATA, bssid, dmac, smac, NULL);
				//send_frame(&fuzz_pkt);	
			}
			else
			{
				fuzzing_opt->wpa_s = WPA_COMPLETED;
			}

			break;
		case IEEE80211_TYPE_REASSOCRES:
			fuzzing_opt->wpa_s = WPA_ASSOCIATED;
			fuzz_pkt = get_frame(IEEE80211_TYPE_ACK, bssid, dmac, smac, NULL);
			send_frame(&fuzz_pkt);

			print_interaction_status(bssid, smac, dmac, "Reassociation Response", "");

			// recevice 4-way-handshake msg1 from ap
			if(fuzzing_opt->auth_type == WPA3 || fuzzing_opt->auth_type==WPA2_PSK_TKIP_AES || fuzzing_opt->auth_type==WPA2_PSK_AES || fuzzing_opt->auth_type==WPA2_PSK_TKIP || 
			fuzzing_opt->auth_type==WPA_PSK_TKIP_AES || fuzzing_opt->auth_type==WPA_PSK_AES || fuzzing_opt->auth_type==WPA_PSK_TKIP)
			{
				//fuzzing_opt->wpa_s = WPA_4WAY_HANDSHAKE;
				//fuzz_pkt = get_frame(IEEE80211_TYPE_QOSDATA, bssid, dmac, smac, NULL);
				//send_frame(&fuzz_pkt);	
			}
			else if(fuzzing_opt->auth_type == EAP_8021X)
			{
				//fuzzing_opt->wpa_s = WPA_EAP_HANDSHAKE;
				//fuzz_pkt = get_frame(IEEE80211_TYPE_QOSDATA, bssid, dmac, smac, NULL);
				//send_frame(&fuzz_pkt);
			}
			else
			{
				fuzzing_opt->wpa_s = WPA_COMPLETED;
			}
			break;
		case IEEE80211_TYPE_DEAUTH:
			fuzz_pkt = get_frame(IEEE80211_TYPE_ACK, bssid, dmac, smac, pkt);
			send_frame(&fuzz_pkt);
			fuzz_pkt = get_frame(IEEE80211_TYPE_DEAUTH, bssid, fuzzing_opt->source_addr, smac, pkt);
			send_frame(&fuzz_pkt);
			fuzzing_opt->wpa_s = WPA_DISCONNECTED;

			print_interaction_status(bssid, smac, dmac, "Deauth", "Probe Request");
			break;
		case IEEE80211_TYPE_DISASSOC:
			fuzz_pkt = get_frame(IEEE80211_TYPE_ACK, bssid, dmac, smac, pkt);
			send_frame(&fuzz_pkt);
			fuzz_pkt = get_frame(IEEE80211_TYPE_DISASSOC, bssid, fuzzing_opt->source_addr, smac, pkt);
			send_frame(&fuzz_pkt);
			fuzzing_opt->wpa_s = WPA_DISCONNECTED;
			print_interaction_status(bssid, smac, dmac, "Disassoc", "Probe Request");
			break;
		case IEEE80211_TYPE_ACTION:
			fuzz_pkt = get_frame(IEEE80211_TYPE_ACK, bssid, dmac, smac, pkt);
			send_frame(&fuzz_pkt);
			fuzz_pkt = get_frame(IEEE80211_TYPE_ACTION, bssid, dmac, smac, pkt);
			send_frame(&fuzz_pkt);
			break;
		case IEEE80211_TYPE_DATA:
			fuzz_pkt = get_frame(IEEE80211_TYPE_ACK, bssid, dmac, smac, pkt);
			send_frame(&fuzz_pkt);
			fuzz_pkt = get_frame(IEEE80211_TYPE_DATA, bssid, dmac, smac, pkt);
			send_frame(&fuzz_pkt);
			break;
		case IEEE80211_TYPE_QOSDATA:
			fuzz_pkt = get_frame(IEEE80211_TYPE_ACK, bssid, dmac, smac, pkt);
			send_frame(&fuzz_pkt);
			fuzz_pkt = get_frame(IEEE80211_TYPE_QOSDATA, bssid, dmac, smac, pkt);
			send_frame(&fuzz_pkt);
			break;
		default:
			break;
		}
	}
}

void* start_fuzzing(void *param)
{
	struct packet pkt;
	struct ieee_hdr *hdr;
	uint8_t dsflags;

	struct packet fuzz_pkt;

	struct ether_addr smac;
	struct ether_addr dmac;
	struct ether_addr bssid;
	struct ether_addr tmac;

	uint8_t frame_type = 0;
	uint16_t seq_ctrl = 0;
	uint16_t recv_seq_ctrl = 0;

	struct timeval tv;
	uint64_t current_time;
	uint64_t pass_time;
	uint64_t ping_pass_time;

	struct ether_addr fuzzer_mac = {0};

	fuzzing_option *fuzzing_opt = (fuzzing_option*)param;
	memcpy(fuzzer_mac.ether_addr_octet, fuzzing_opt->source_addr.ether_addr_octet, 6);


	fuzz_logger_log(FUZZ_LOG_DEBUG, "target MAC %02X:%02X:%02X:%02X:%02X:%02X", fuzzing_opt->target_addr.ether_addr_octet[0],
	fuzzing_opt->target_addr.ether_addr_octet[1],fuzzing_opt->target_addr.ether_addr_octet[2],
			fuzzing_opt->target_addr.ether_addr_octet[3],fuzzing_opt->target_addr.ether_addr_octet[4],fuzzing_opt->target_addr.ether_addr_octet[5]);

	fuzzing_opt->wpa_s = WPA_DISCONNECTED;

 	gettimeofday(&tv,NULL);
	pass_time = tv.tv_sec;
	ping_pass_time = tv.tv_sec;
	fuzzing_opt->last_recv_pkt_time = time(NULL);
	
	while(1)
	{
		frame_type = 0;
		memset(&smac, 0, 6);
		memset(&dmac, 0, 6);
		memcpy(&bssid.ether_addr_octet, fuzzer_mac.ether_addr_octet, 6);

		gettimeofday(&tv,NULL);
		current_time = tv.tv_sec;
		if((current_time - pass_time >= DEAUTH_TIME) && fuzzing_opt->test_type == 1)
		{
			fuzz_pkt = get_frame(IEEE80211_TYPE_DEAUTH, fuzzing_opt->bssid, fuzzing_opt->source_addr, fuzzing_opt->target_addr, NULL);
			send_frame(&fuzz_pkt);

			fuzz_pkt = get_frame(IEEE80211_TYPE_DISASSOC, fuzzing_opt->bssid, fuzzing_opt->source_addr, fuzzing_opt->target_addr, NULL);
			send_frame(&fuzz_pkt);

			fuzzing_opt->wpa_s = WPA_DISCONNECTED;

			pass_time = current_time;
		}

		pkt = osdep_read_packet();
		if (pkt.len == 0) {
			sleep(1);
			continue;
		}

		hdr = (struct ieee_hdr *) pkt.data;
		frame_type = hdr->type;
		frame_type = frame_type & 0x0F;
		dsflags = hdr->flags & 0x03;

		if((hdr->type & 0x0F) != CONTROL_FRAME)
		{
			switch (dsflags) {
				case 0x00: //Ad Hoc, Beacons:    ToDS 0 FromDS 0  Addr: DST, SRC, BSS
				memcpy(dmac.ether_addr_octet, hdr->addr1.ether_addr_octet, ETHER_ADDR_LEN);
				memcpy(smac.ether_addr_octet, hdr->addr2.ether_addr_octet, ETHER_ADDR_LEN);
				memcpy(bssid.ether_addr_octet, hdr->addr3.ether_addr_octet, ETHER_ADDR_LEN);
				break;
				case 0x01: 	//From station to AP: ToDS 1 FromDS 1  Addr: BSS, SRC, DST
				memcpy(bssid.ether_addr_octet, hdr->addr1.ether_addr_octet, ETHER_ADDR_LEN);
				memcpy(smac.ether_addr_octet, hdr->addr2.ether_addr_octet, ETHER_ADDR_LEN);
				memcpy(dmac.ether_addr_octet, hdr->addr3.ether_addr_octet, ETHER_ADDR_LEN);
				break;
				case 0x02: //From AP to station: ToDS 0 FromDS 1  Addr: DST, BSS, SRC
				memcpy(dmac.ether_addr_octet, hdr->addr1.ether_addr_octet, ETHER_ADDR_LEN);
				memcpy(bssid.ether_addr_octet, hdr->addr2.ether_addr_octet, ETHER_ADDR_LEN);
				memcpy(smac.ether_addr_octet, hdr->addr3.ether_addr_octet, ETHER_ADDR_LEN);
				break;
				case 0x03: //WDS:                ToDS 1 FromDS 1  Addr: RCV, TRN, DST ... SRC
				memcpy(bssid.ether_addr_octet, hdr->addr1.ether_addr_octet, ETHER_ADDR_LEN);
				memcpy(tmac.ether_addr_octet, hdr->addr2.ether_addr_octet, ETHER_ADDR_LEN);
				memcpy(dmac.ether_addr_octet, hdr->addr3.ether_addr_octet, ETHER_ADDR_LEN);
				memcpy(smac.ether_addr_octet, pkt.data + sizeof(struct ieee_hdr), ETHER_ADDR_LEN);
				break;
			}
		}else{
			switch(hdr->type)
			{
				/*// management   addr1,addr2,addr3
				case IEEE80211_TYPE_ASSOCRES:   // AP
				#ifdef DEBUG_LOG
					fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->(management)IEEE80211_TYPE_ASSOCRES");
				#endif
					break;
				case IEEE80211_TYPE_REASSOCRES:
				#ifdef DEBUG_LOG
					fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->(management)IEEE80211_TYPE_REASSOCRES");
				#endif
					break;
				case IEEE80211_TYPE_PROBERES:
				#ifdef DEBUG_LOG
					fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->(management)IEEE80211_TYPE_PROBERES");
				#endif
					break;
				case IEEE80211_TYPE_TIMADVERT:
				#ifdef DEBUG_LOG
					fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->(management)IEEE80211_TYPE_TIMADVERT");
				#endif
					break;
				case IEEE80211_TYPE_BEACON:
				#ifdef DEBUG_LOG
					fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->(management)IEEE80211_TYPE_BEACON");
				#endif
					break;
				case IEEE80211_TYPE_ATIM:
				#ifdef DEBUG_LOG
					fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->(management)IEEE80211_TYPE_ATIM");
				#endif
					break;
				case IEEE80211_TYPE_DISASSOC:
				#ifdef DEBUG_LOG
					fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->(management)IEEE80211_TYPE_DISASSOC");
				#endif
					break;
				case IEEE80211_TYPE_DEAUTH:
				#ifdef DEBUG_LOG
					fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->(management)IEEE80211_TYPE_DEAUTH");
				#endif
					break;
				case IEEE80211_TYPE_ACTION:
				#ifdef DEBUG_LOG
					fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->(management)IEEE80211_TYPE_ACTION");
				#endif
					break;
				case IEEE80211_TYPE_ACTIONNOACK:
				#ifdef DEBUG_LOG
					fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->(management)IEEE80211_TYPE_ACTIONNOACK");
				#endif
					break;
				case IEEE80211_TYPE_ASSOCREQ:    // STA
				#ifdef DEBUG_LOG
					fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->(management)IEEE80211_TYPE_ASSOCREQ");
				#endif
					break;
				case IEEE80211_TYPE_REASSOCREQ:
				#ifdef DEBUG_LOG
					fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->(management)IEEE80211_TYPE_REASSOCREQ");
				#endif
					break;
				case IEEE80211_TYPE_PROBEREQ:
				#ifdef DEBUG_LOG
					fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->(management)IEEE80211_TYPE_PROBEREQ");
				#endif
					break;
				case IEEE80211_TYPE_AUTH:
				#ifdef DEBUG_LOG
					fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->(management)IEEE80211_TYPE_AUTH");
				#endif
					break;*/

				// control addr1,(addr2)
				case IEEE80211_TYPE_BEAMFORMING:
				#ifdef DEBUG_LOG
					fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->(control)IEEE80211_TYPE_BEAMFORMING");
				#endif
					memcpy(dmac.ether_addr_octet, hdr->addr1.ether_addr_octet, ETHER_ADDR_LEN);
					memcpy(smac.ether_addr_octet, hdr->addr2.ether_addr_octet, ETHER_ADDR_LEN);
					break;
				case IEEE80211_TYPE_VHT:
				#ifdef DEBUG_LOG
					fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->(control)IEEE80211_TYPE_VHT");
				#endif
					memcpy(dmac.ether_addr_octet, hdr->addr1.ether_addr_octet, ETHER_ADDR_LEN);
					memcpy(smac.ether_addr_octet, hdr->addr2.ether_addr_octet, ETHER_ADDR_LEN);
					break;
				case IEEE80211_TYPE_CTRLFRMEXT:
				#ifdef DEBUG_LOG
					fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->(control)IEEE80211_TYPE_CTRLFRMEXT");
				#endif
					break;
				case IEEE80211_TYPE_CTRLWRAP:
				#ifdef DEBUG_LOG
					fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->(control)IEEE80211_TYPE_CTRLWRAP");
				#endif
					memcpy(dmac.ether_addr_octet, hdr->addr1.ether_addr_octet, ETHER_ADDR_LEN);
					break;
				case IEEE80211_TYPE_BLOCKACKREQ:
				#ifdef DEBUG_LOG
					fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->(control)IEEE80211_TYPE_BLOCKACKREQ");
				#endif
					memcpy(dmac.ether_addr_octet, hdr->addr1.ether_addr_octet, ETHER_ADDR_LEN);
					memcpy(smac.ether_addr_octet, hdr->addr2.ether_addr_octet, ETHER_ADDR_LEN);
					break;
				case IEEE80211_TYPE_BLOCKACK:
				#ifdef DEBUG_LOG
					fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->(control)IEEE80211_TYPE_BLOCKACK");
				#endif
					memcpy(dmac.ether_addr_octet, hdr->addr1.ether_addr_octet, ETHER_ADDR_LEN);
					memcpy(smac.ether_addr_octet, hdr->addr2.ether_addr_octet, ETHER_ADDR_LEN);
					break;
				case IEEE80211_TYPE_PSPOLL:
				#ifdef DEBUG_LOG
					fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->(control)IEEE80211_TYPE_PSPOLL");
				#endif
					memcpy(dmac.ether_addr_octet, hdr->addr1.ether_addr_octet, ETHER_ADDR_LEN);
					memcpy(bssid.ether_addr_octet, hdr->addr1.ether_addr_octet, ETHER_ADDR_LEN);
					memcpy(smac.ether_addr_octet, hdr->addr2.ether_addr_octet, ETHER_ADDR_LEN);
					break;
				case IEEE80211_TYPE_RTS:
				#ifdef DEBUG_LOG
					fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->(control)IEEE80211_TYPE_RTS");
				#endif
					memcpy(dmac.ether_addr_octet, hdr->addr1.ether_addr_octet, ETHER_ADDR_LEN);
					memcpy(smac.ether_addr_octet, hdr->addr2.ether_addr_octet, ETHER_ADDR_LEN);
					break;
				case IEEE80211_TYPE_CTS:
				#ifdef DEBUG_LOG
					fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->(control)IEEE80211_TYPE_CTS");
				#endif
					memcpy(dmac.ether_addr_octet, hdr->addr1.ether_addr_octet, ETHER_ADDR_LEN);
					break;
				case IEEE80211_TYPE_ACK:
				#ifdef DEBUG_LOG
					fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->(control)IEEE80211_TYPE_ACK");
				#endif
					memcpy(dmac.ether_addr_octet, hdr->addr1.ether_addr_octet, ETHER_ADDR_LEN);
					break;
				case IEEE80211_TYPE_CFEND:
				#ifdef DEBUG_LOG
					fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->(control)IEEE80211_TYPE_CFEND");
				#endif
					memcpy(dmac.ether_addr_octet, hdr->addr1.ether_addr_octet, ETHER_ADDR_LEN);
					memcpy(bssid.ether_addr_octet, hdr->addr2.ether_addr_octet, ETHER_ADDR_LEN);
					memcpy(smac.ether_addr_octet, hdr->addr2.ether_addr_octet, ETHER_ADDR_LEN);
					break;
				case IEEE80211_TYPE_CFENDACK:
				#ifdef DEBUG_LOG
					fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->(control)IEEE80211_TYPE_CFENDACK");
				#endif
					memcpy(dmac.ether_addr_octet, hdr->addr1.ether_addr_octet, ETHER_ADDR_LEN);
					memcpy(bssid.ether_addr_octet, hdr->addr2.ether_addr_octet, ETHER_ADDR_LEN);
					memcpy(smac.ether_addr_octet, hdr->addr2.ether_addr_octet, ETHER_ADDR_LEN);
					break;

				/*// data addr1,addr2,addr3,(addr4)
				case IEEE80211_TYPE_DATA:
				#ifdef DEBUG_LOG
					fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->(data)IEEE80211_TYPE_DATA");
				#endif
					break;
				case IEEE80211_TYPE_DATACFACK:
				#ifdef DEBUG_LOG
					fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->(data)IEEE80211_TYPE_DATACFACK");
				#endif
					break;
				case IEEE80211_TYPE_DATACFPOLL:
				#ifdef DEBUG_LOG
					fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->(data)IEEE80211_TYPE_DATACFPOLL");
				#endif
					break;
				case IEEE80211_TYPE_DATACFACKPOLL:
				#ifdef DEBUG_LOG
					fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->(data)IEEE80211_TYPE_DATACFACKPOLL");
				#endif
					break;
				case IEEE80211_TYPE_NULL:
				#ifdef DEBUG_LOG
					fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->(data)IEEE80211_TYPE_NULL");
				#endif
					break;
				case IEEE80211_TYPE_CFACK:
				#ifdef DEBUG_LOG
					fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->(data)IEEE80211_TYPE_CFACK");
				#endif
					break;
				case IEEE80211_TYPE_CFPOLL:
				#ifdef DEBUG_LOG
					fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->(data)IEEE80211_TYPE_CFPOLL");
				#endif
					break;
				case IEEE80211_TYPE_CFACKPOLL:
				#ifdef DEBUG_LOG
					fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->(data)IEEE80211_TYPE_CFACKPOLL");
				#endif
					break;
				case IEEE80211_TYPE_QOSDATA:
				#ifdef DEBUG_LOG
					fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->(data)IEEE80211_TYPE_QOSDATA");
				#endif
					break;
				case IEEE80211_TYPE_QOSDATACFACK:
				#ifdef DEBUG_LOG
					fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->(data)IEEE80211_TYPE_QOSDATACFACK");
				#endif
					break;
				case IEEE80211_TYPE_QOSDATACFPOLL:
				#ifdef DEBUG_LOG
					fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->(data)IEEE80211_TYPE_QOSDATACFPOLL");
				#endif
					break;
				case IEEE80211_TYPE_QOSDATACFACKPOLL:
				#ifdef DEBUG_LOG
					fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->(data)IEEE80211_TYPE_QOSDATACFACKPOLL");
				#endif
					break;
				case IEEE80211_TYPE_QOSNULL:
				#ifdef DEBUG_LOG
					fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->(data)IEEE80211_TYPE_QOSNULL");
				#endif
					break;
				case IEEE80211_TYPE_QOSCFPOLL:
				#ifdef DEBUG_LOG
					fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->(data)IEEE80211_TYPE_QOSCFPOLL");
				#endif
					break;
				case IEEE80211_TYPE_QOSCFACKPOLL:
				#ifdef DEBUG_LOG
					fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->(data)IEEE80211_TYPE_QOSCFACKPOLL");
				#endif
					break;

				// extension
				case IEEE80211_TYPE_DMGBEACON:
				#ifdef DEBUG_LOG
					fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->(extension)IEEE80211_TYPE_DMGBEACON");
				#endif
					memcpy(bssid.ether_addr_octet, hdr->addr1.ether_addr_octet, ETHER_ADDR_LEN);
					break;*/
				default:
				#ifdef DEBUG_LOG
					fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->unknown frame!!!");
				#endif
					break;
			}
		}

		fuzz_logger_log(FUZZ_LOG_DEBUG, "smac %02X:%02X:%02X:%02X:%02X:%02X", smac.ether_addr_octet[0],smac.ether_addr_octet[1],smac.ether_addr_octet[2],
			smac.ether_addr_octet[3],smac.ether_addr_octet[4],smac.ether_addr_octet[5]);

		fuzz_logger_log(FUZZ_LOG_DEBUG, "dmac %02X:%02X:%02X:%02X:%02X:%02X", dmac.ether_addr_octet[0],dmac.ether_addr_octet[1],dmac.ether_addr_octet[2],
			dmac.ether_addr_octet[3],dmac.ether_addr_octet[4],dmac.ether_addr_octet[5]);

		if(memcmp(&smac.ether_addr_octet,&fuzzing_opt->source_addr.ether_addr_octet, 6) == 0)  // source(fuzzer) packet seq number
		{
			seq_ctrl = get_seqno(&pkt);
			if((hdr->type & 0x0F) == MANAGMENT_FRAME)
			{
				if(seq_ctrl != fuzzing_opt->seq_ctrl)
				{
					fuzzing_opt->seq_ctrl = seq_ctrl;
					set_seqno(NULL, seq_ctrl);

					fuzz_logger_log(FUZZ_LOG_DEBUG, "source management frame seq = %d", fuzzing_opt->seq_ctrl);
				}
			}
			else if((hdr->type & 0x0F) == DATA_FRAME)
			{
				if(seq_ctrl != fuzzing_opt->data_seq_ctrl)
				{
					fuzzing_opt->data_seq_ctrl = seq_ctrl;
					//set_data_seqno(NULL, data_seq_ctrl);

					fuzz_logger_log(FUZZ_LOG_DEBUG, "source data frame seq = %d", fuzzing_opt->data_seq_ctrl);
				}
			}

		}

		if(memcmp(&smac.ether_addr_octet,&fuzzing_opt->target_addr.ether_addr_octet, 6) == 0 && (memcmp(&dmac.ether_addr_octet,&fuzzing_opt->source_addr.ether_addr_octet, 6) == 0 || 
		(dmac.ether_addr_octet[0] == 0xff && dmac.ether_addr_octet[1] == 0xff &&dmac.ether_addr_octet[2] == 0xff &&
		dmac.ether_addr_octet[3] == 0xff && dmac.ether_addr_octet[4] == 0xff &&dmac.ether_addr_octet[5] == 0xff))) 
		{
			recv_seq_ctrl = get_seqno(&pkt); 
			if((hdr->type & 0x0F) == MANAGMENT_FRAME)
			{
				// target's packet managment seq number
				if(recv_seq_ctrl != fuzzing_opt->recv_seq_ctrl)
				{
					fuzzing_opt->recv_seq_ctrl = recv_seq_ctrl;
				}
			}
			else if((hdr->type & 0x0F) == DATA_FRAME)
			{
				// target's packet data seq number
				if(recv_seq_ctrl != fuzzing_opt->recv_data_seq_ctrl)
				{
					fuzzing_opt->recv_data_seq_ctrl = recv_seq_ctrl;
				}
			}

			fuzzing_opt->last_recv_pkt_time = time(NULL);

			fuzz_logger_log(FUZZ_LOG_DEBUG, "receive from target %02X:%02X:%02X:%02X:%02X:%02X", smac.ether_addr_octet[0],smac.ether_addr_octet[1],smac.ether_addr_octet[2],
			smac.ether_addr_octet[3],smac.ether_addr_octet[4],smac.ether_addr_octet[5]);

			if(fuzzing_opt->test_type == 1 || fuzzing_opt->test_type == 3)
			{
				if(FUZZ_WORK_MODE_AP == fuzzing_opt->fuzz_work_mode){
					handle_sta_auth(&pkt,bssid, smac, dmac, fuzzing_opt);
				}else if(FUZZ_WORK_MODE_STA == fuzzing_opt->fuzz_work_mode){
					handle_ap_auth(&pkt,bssid, smac, dmac, fuzzing_opt);
				}

				if(fuzzing_opt->enable_check_alive){
					if(!check_alive_by_ping()){
						save_exp_payload(&fuzz_pkt);
						fuzz_logger_log(FUZZ_LOG_INFO, "Target is dead or disconnected...");
						log_pkt(FUZZ_LOG_ERR, &fuzz_pkt);
						sleep(5);
					}
				}
			}
				
		}
	}

	pthread_exit(NULL);
}

int check_alive_by_pkt()
{
	time_t  current_time = 0;

	current_time = time(NULL);
	if(current_time - fuzzing_opt.last_recv_pkt_time > CHECK_ALIVE_TIME)
	{
		fuzzing_opt.target_alive = 0;
		return 0;
	}

	fuzzing_opt.target_alive = 1;

	return 1;
}

void load_payloads()
{
	FILE *fp = NULL;
	int i=0;
	char str_line[8192] = {0};

	fp = fopen("poc.txt", "r");
	if(!fp)
	{
		fuzz_logger_log(FUZZ_LOG_ERR, "fopen poc.txt failed.\n", i);
		return;
	}

	while(!feof(fp) && (i< sizeof(bad_frame)/sizeof(bad_frame[0])))
	{
		memset(str_line, 0, sizeof(str_line));
		if(fgets(str_line, sizeof(str_line), fp))
		{
			bad_frame[i].len = str_to_hex(str_line, bad_frame[i].data, sizeof(bad_frame[i].data));
			i++;
		}
	}

	fclose(fp);
	fuzz_logger_log(FUZZ_LOG_INFO, "load %d pocs.\n", i);
}

void save_exp_payload(struct packet *pkt)
{
	int fd = -1;
	int len = 0;
	char buf[MAX_PRINT_BUF_LEN*5] = {0};

	if(!pkt)
		return; 

	fuzzing_opt.fuzz_exp_pkt_cnt++;

	write_pcap(pkt->data, pkt->len);

	fd = open("poc_log.txt", O_RDWR|O_CREAT|O_APPEND|O_SYNC, 0);
	if(pkt->len){
		hex_to_ascii_hex(pkt->data, buf, pkt->len);
		len = strlen(buf);
		write(fd, buf, len);
		write(fd, "\r\n", 2);
	}
	else{
		fuzz_logger_log(FUZZ_LOG_ERR, "Payload len: %d.\n", pkt->len);
	}
		
	close(fd);
}

int fuzzing(int argc, char* argv[])
{
	int ret;
	unsigned char c = 0;
	struct packet pkt;
	char *fuzz_mode = NULL;
	char *interface = NULL;
	char *target_ssid = NULL;
	char *auth_type = NULL;
	char *target_mac_str = NULL;
	struct ether_addr target_mac;
	char *fuzzer_mac_str = NULL;
	struct ether_addr fuzzer_mac;
	char *ap_bssid_str = NULL;
	struct ether_addr ap_bssid;
	char *channel_str = NULL;
	char *target_ip = NULL;
	int channel = 0;
	int seq_num = 0;
	int tid;
	int test_type = -1;
	int log_level = -1;
	char *file_log_path = NULL;
	pthread_t fthread;

	while ((c = getopt(argc, argv, "m:i:t:s:b:I:c:hS:A:T:l:f")) < 255) {
		switch (c) {
		case 'm':
			fuzz_mode = strdup(optarg);
			break;
		case 'i':
			interface = strdup(optarg);
			break;
		case 't':
			target_mac_str = strdup(optarg);
			target_mac = parse_mac(target_mac_str);
			break;
		case 's':
			fuzzer_mac_str = strdup(optarg);
			fuzzer_mac = parse_mac(fuzzer_mac_str);
			break;
		case 'b':
			ap_bssid_str = strdup(optarg);
			ap_bssid = parse_mac(ap_bssid_str);
			break;
		case 'c':
			channel_str = strdup(optarg);
			channel = atoi(channel_str);
			break;
		case 'I':
			target_ip = strdup(optarg);
			break;
		case 'h':
			usage_help(argv[0]);
			return -1;
		case 'S':
			target_ssid = strdup(optarg);
			break;
		case 'A':
			auth_type = strdup(optarg);
			break;
		case 'T':
			test_type = atoi(strdup(optarg));
			break;
		case 'l':
			log_level = atoi(strdup(optarg));
			break;
		case 'f':
			file_log_path = strdup(optarg);
		default:
			fuzz_logger_log(FUZZ_LOG_ERR, "Unknow option %c!", c);
			usage_help(argv[0]);
			return -1;
		}
	}

	if(interface == NULL)
	{
		fuzz_logger_log(FUZZ_LOG_ERR, "Interface not set!");
		usage_help(argv[0]);
		return -1;
	}

	if(fuzz_mode == NULL)
		fuzz_mode = AP_MODE;

	if(channel_str == NULL)
	{
		channel_str = "1";
		channel = 1;
	}

	if(test_type == -1)
	{
		test_type = 1;
	}

	if(log_level != -1)
	{
		fuzzing_opt.log_level = log_level;
	}
	else
	{
		fuzzing_opt.log_level = FUZZ_LOG_INFO;
	}

	fuzz_logger_init(log_level, file_log_path);

	if(strcmp(fuzz_mode, AP_MODE) != 0 && strcmp(fuzz_mode, STA_MODE) != 0)
	{
		fuzz_logger_log(FUZZ_LOG_ERR, "fuzzing mode: %s", fuzz_mode);
		usage_help(argv[0]);
		return -1;
	}

	if(target_mac_str == NULL)
	{
		fuzz_logger_log(FUZZ_LOG_ERR, "no set fuzzing target's MAC");
		usage_help(argv[0]);
		return -1;
	}

	if(fuzzer_mac_str == NULL)
	{
		fuzz_logger_log(FUZZ_LOG_ERR, "no set fuzzing source MAC address");
		usage_help(argv[0]);
		return -1;
	}

	if(ap_bssid_str == NULL)
	{
		memcpy(ap_bssid.ether_addr_octet, fuzzer_mac.ether_addr_octet, 6);
	}

	if(auth_type == NULL)
	{
		fuzz_logger_log(FUZZ_LOG_ERR, "no set fuzzing target's auth type.");
		usage_help(argv[0]);
		return -1;
	}

	if(strcmp(auth_type, "OPEN_NONE") == 0){
		fuzzing_opt.auth_type = OPEN_NONE;
	}else if(strcmp(auth_type, "OPEN_WEP") == 0){
		fuzzing_opt.auth_type = OPEN_WEP;
	}else if(strcmp(auth_type, "SHARE_WEP") == 0){
		fuzzing_opt.auth_type = SHARE_WEP;
	}else if(strcmp(auth_type, "WPA_PSK_TKIP") == 0){
		fuzzing_opt.auth_type = WPA_PSK_TKIP;
	}else if(strcmp(auth_type, "WPA_PSK_AES") == 0){
		fuzzing_opt.auth_type = WPA_PSK_AES;
	}else if(strcmp(auth_type, "WPA_PSK_TKIP_AES") == 0){
		fuzzing_opt.auth_type = WPA_PSK_TKIP_AES;
	}else if(strcmp(auth_type, "WPA2_PSK_TKIP") == 0){
		fuzzing_opt.auth_type = WPA2_PSK_TKIP;
	}else if(strcmp(auth_type, "WPA2_PSK_AES") == 0){
		fuzzing_opt.auth_type = WPA2_PSK_AES;
	}else if(strcmp(auth_type, "WPA2_PSK_TKIP_AES") == 0){
		fuzzing_opt.auth_type = WPA2_PSK_TKIP_AES;
	}else if(strcmp(auth_type, "EAP_8021X") == 0){
		fuzzing_opt.auth_type = EAP_8021X;
	}else if(strcmp(auth_type, "WPA3") == 0){
		fuzzing_opt.auth_type = WPA3;
	}else{
		fuzz_logger_log(FUZZ_LOG_ERR, "Fuzzing target's auth type is wrong.");
		usage_help(argv[0]);
		return -1;
	}

	if(strcmp(fuzz_mode, STA_MODE) == 0)
	{
		if(target_ssid == NULL || strlen(target_ssid) == 0)
		{
			fuzz_logger_log(FUZZ_LOG_ERR, "no set fuzzing target's SSID");
			usage_help(argv[0]);
			return -1;
		}

		if(strlen(target_ssid)>32)
		{
			fuzz_logger_log(FUZZ_LOG_ERR, "ERROR: target's SSID is too long, limit 32 bytes.");
			usage_help(argv[0]);
			return -1;
		}

		strncpy(fuzzing_opt.target_ssid, target_ssid, sizeof(fuzzing_opt.target_ssid)-1);
		fuzzing_opt.fuzz_work_mode = FUZZ_WORK_MODE_STA;
	}
	else
	{
		if(target_ssid == NULL || strlen(target_ssid) == 0)
		{
			strncpy(fuzzing_opt.target_ssid, "wf_testing", sizeof(fuzzing_opt.target_ssid)-1);
		}
		else if(strlen(target_ssid)>32)
		{
			fuzz_logger_log(FUZZ_LOG_ERR, "ERROR: AP's SSID is too long, limit 32 bytes.");
			usage_help(argv[0]);
			return -1;
		}
		else
		{
			strncpy(fuzzing_opt.target_ssid, target_ssid, sizeof(fuzzing_opt.target_ssid)-1);
		}

		fuzzing_opt.fuzz_work_mode = FUZZ_WORK_MODE_AP;

	}
	

	if(0 != init(interface, channel))
	{
		fuzz_logger_log(FUZZ_LOG_ERR, "Init fuzzer failed.");
		return -1;
	}

	fuzz_logger_log(FUZZ_LOG_DEBUG, "Interface name: %s", interface);
	fuzz_logger_log(FUZZ_LOG_DEBUG, "Fuzzing mode: %s", fuzz_mode);
	fuzz_logger_log(FUZZ_LOG_DEBUG, "Working channel: %s", channel_str);
	fuzz_logger_log(FUZZ_LOG_DEBUG, "Fuzzing target %02X:%02X:%02X:%02X:%02X:%02X", target_mac.ether_addr_octet[0],target_mac.ether_addr_octet[1],
						target_mac.ether_addr_octet[2],target_mac.ether_addr_octet[3],target_mac.ether_addr_octet[4],target_mac.ether_addr_octet[5]);
	if(strcmp(fuzz_mode, STA_MODE) == 0)
	{
		fuzz_logger_log(FUZZ_LOG_DEBUG,"Fuzzing target's SSID: %s", fuzzing_opt.target_ssid);
	}

	if(target_ip)
	{
		if(inet_addr(target_ip) == INADDR_NONE)
		{
			fuzz_logger_log(FUZZ_LOG_ERR, "Target's IP is error: %s", target_ip);
			return -1;
		}

		strncpy(fuzzing_opt.target_ip, target_ip, sizeof(fuzzing_opt.target_ip) -1);
		fuzz_logger_log(FUZZ_LOG_DEBUG, "Target IP: %s", fuzzing_opt.target_ip);
		fuzzing_opt.enable_check_alive = 1;
		init_ping_sock(&fuzzing_opt);
	}

	strncpy(fuzzing_opt.interface, interface, sizeof(fuzzing_opt.interface));
	strncpy(fuzzing_opt.mode, fuzz_mode, sizeof(fuzzing_opt.mode));
	memcpy(fuzzing_opt.source_addr.ether_addr_octet, fuzzer_mac.ether_addr_octet, 6);
	memcpy(fuzzing_opt.target_addr.ether_addr_octet, target_mac.ether_addr_octet, 6);
	memcpy(fuzzing_opt.bssid.ether_addr_octet, ap_bssid.ether_addr_octet, 6);

	if(test_type > 3)
	{
		fuzz_logger_log(FUZZ_LOG_ERR, "Test type is error: %s", test_type);
		return -1;
	}
	
	fuzzing_opt.test_type = test_type;
	fuzzing_opt.channel = channel;
	if(fuzzing_opt.test_type == 1){
		fuzzing_opt.wpa_s = WPA_DISCONNECTED;
	}else{
		fuzzing_opt.wpa_s = WPA_COMPLETED;
	}
	
	fuzzing_opt.target_alive = 1;
	if(fuzzing_opt.test_type == 0)
	{
		if((tid = pthread_create(&fthread, NULL, test_bad_frame, &fuzzing_opt)) != 0)
		{
			fuzz_logger_log(FUZZ_LOG_ERR, "Create test_bad_frame thread failed.");
			return -1;
		}
	}
	else if(fuzzing_opt.test_type > 0)
	{
		open_pcap();

		if((tid = pthread_create(&fthread, NULL, fuzzing_thread, &fuzzing_opt)) != 0)
		{
			fuzz_logger_log(FUZZ_LOG_ERR, "Create beacon_thread failed.");
			return -1;
		}
	}

	start_fuzzing(&fuzzing_opt);

	//close_pcap();
	
	return 0;

}

void print_status()
{
	printf("\033c");
	printf("\033[0;0H");
	printf("\t\t\t\t\t\t\t\n");
	printf("\t\t\t\033[22;33mWiFi(IEEE802.11) Protocol Fuzzing Test\033[22;39m\n");
	printf("__________________________________________________________________________________________\n\n");
	printf("\tInterface: %s\t\tWorking Channel: %d\n", fuzzing_opt.interface, fuzzing_opt.channel);
	printf("\tTarget MAC: %02X:%02X:%02X:%02X:%02X:%02X\t\tFuzzing MAC: %02X:%02X:%02X:%02X:%02X:%02X\n", fuzzing_opt.target_addr.ether_addr_octet[0],fuzzing_opt.target_addr.ether_addr_octet[1],
						fuzzing_opt.target_addr.ether_addr_octet[2],fuzzing_opt.target_addr.ether_addr_octet[3],fuzzing_opt.target_addr.ether_addr_octet[4],fuzzing_opt.target_addr.ether_addr_octet[5],
						fuzzing_opt.source_addr.ether_addr_octet[0],fuzzing_opt.source_addr.ether_addr_octet[1],
						fuzzing_opt.source_addr.ether_addr_octet[2],fuzzing_opt.source_addr.ether_addr_octet[3],fuzzing_opt.source_addr.ether_addr_octet[4],fuzzing_opt.source_addr.ether_addr_octet[5]);
	printf("\tBSSID: %02X:%02X:%02X:%02X:%02X:%02X\n", fuzzing_opt.bssid.ether_addr_octet[0],fuzzing_opt.bssid.ether_addr_octet[1],
						fuzzing_opt.bssid.ether_addr_octet[2],fuzzing_opt.bssid.ether_addr_octet[3],fuzzing_opt.bssid.ether_addr_octet[4],fuzzing_opt.bssid.ether_addr_octet[5]);
	printf("\tFuzzing Mode: %s\t\t", fuzzing_opt.mode);

	if(fuzzing_opt.test_type == 3)
	{
		printf("\tFuzzing Type: %d (Interactive & Frame testing)\n", fuzzing_opt.test_type);
	}
	else if(fuzzing_opt.test_type == 1)
	{
		printf("\tFuzzing Type: %d (Interactive)\n", fuzzing_opt.test_type);
	}
	else if(fuzzing_opt.test_type == 2)
	{
		printf("\tFuzzing Type: %d (Frame testing)\n", fuzzing_opt.test_type);
	}

	printf("\tAP SSID: %s\t\t", fuzzing_opt.target_ssid);

	if(strlen(fuzzing_opt.target_ip))
	{
		printf("\tTarget IP: %s\n", fuzzing_opt.target_ip);
	}
	else
	{
		printf("\n");
	}

	if(fuzzing_opt.test_type >= 2)
	{
		printf("\tFuzzing Frame Count: %lu\t\tPoC Count: \033[22;31m%lu\033[22;39m\n", fuzzing_opt.fuzz_pkt_num, fuzzing_opt.fuzz_exp_pkt_cnt);
	}

	printf("__________________________________________________________________________________________\n");
	printf("\033[?25l");
	
}