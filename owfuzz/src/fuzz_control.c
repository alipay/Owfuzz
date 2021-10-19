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
#include "common/config.h"
#include "common/queue.h"
#include "fuzz_control.h"
#include "procedures/direct/direct.h"
#include "procedures/awdl/awdl.h"

struct packet bad_frame[300] = {
	{{0}, 0}
};

#define MITM_ACTION_ECSA "\xD0\x00\x3A\x01\x0C\x7A\x15\x87\x3E\x49\x04\xD9\xF5\x26\xFF\xC0\x04\xD9\xF5\x26\xFF\xC0\x90\x50\x04\x04\x01\x51\x01\x03"

fuzzing_option fuzzing_opt = {0};

struct ow_queue owq;
pthread_mutex_t owq_mutex = PTHREAD_MUTEX_INITIALIZER;

#define DEAUTH_TIME 10

uint8_t owfuzz_frames[64] = {0};

uint8_t p2p_frames[]={
	IEEE80211_TYPE_BEACON,
	IEEE80211_TYPE_PROBEREQ,
	IEEE80211_TYPE_PROBERES,
	IEEE80211_TYPE_AUTH,
	//IEEE80211_TYPE_ASSOCREQ,
	IEEE80211_TYPE_ASSOCRES,
	IEEE80211_TYPE_ACTION
};
uint8_t ap_frames[] = {};
uint8_t sta_frames[] = {};

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
	//IEEE80211_TYPE_010000,
	//IEEE80211_TYPE_010001,
	//IEEE80211_TYPE_010010,
	//IEEE80211_TYPE_010011,
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

	// extension
	//IEEE80211_TYPE_DMGBEACON,
	/*IEEE80211_TYPE_110001,
	IEEE80211_TYPE_110010,
	IEEE80211_TYPE_110011,
	IEEE80211_TYPE_110100,
	IEEE80211_TYPE_110101,
	IEEE80211_TYPE_110110,
	IEEE80211_TYPE_110111,
	IEEE80211_TYPE_111000,
	IEEE80211_TYPE_111001,
	IEEE80211_TYPE_111010,
	IEEE80211_TYPE_111011,
	IEEE80211_TYPE_111100,
	IEEE80211_TYPE_111101,
	IEEE80211_TYPE_111110,
	IEEE80211_TYPE_111111*/

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

				//if(hdr->type != IEEE80211_TYPE_ACTION)
				//	continue;
				//if(bad_frame[i].data[sizeof(struct ieee_hdr)] == 0x00 && bad_frame[i].data[sizeof(struct ieee_hdr) + 1] == 0x04)
				//	continue;

				fuzz_logger_log(FUZZ_LOG_INFO, "sending payload...");

				send_packet_ex(&bad_frame[i]);

				log_pkt(FUZZ_LOG_INFO, &bad_frame[i]);

				if(fuzzing_opt->enable_check_alive)
					if(!check_alive_by_ping())
						exit(-1);
			}
			
		}

		usleep(10000);
	}

}

void* oi_receive_thread(void *param)
{
	struct osdep_instance *oi = (struct osdep_instance *)param;
	struct packet pkt = {0};

	while(1)
	{
		memset(&pkt, 0, sizeof(struct packet));
		pkt = osdep_read_packet_ex(oi);
		if (pkt.len) {
			pthread_mutex_lock(&owq_mutex);
			ow_queue_push(&owq, &pkt);
			//printf("recv from channel: %d, pkt.len: %d\n", pkt.channel, pkt.len);
			pthread_mutex_unlock(&owq_mutex);
		}
		//usleep(10);
	}

	pthread_exit(NULL);

}

void* oi_receive_thread_ex(void *param)
{
	fuzzing_option *fo = (fuzzing_option*)param;
	struct packet pkt;
	int i;

	while(1)
	{
		for(i=0; i<fo->ois_cnt; i++)
		{
			memset(&pkt, 0, sizeof(struct packet));
			pkt = osdep_read_packet_ex(&fo->ois[i]);
			if (pkt.len) {
				pthread_mutex_lock(&owq_mutex);
				ow_queue_push(&owq, &pkt);
				pthread_mutex_unlock(&owq_mutex);
			}
		}
	}

	pthread_exit(NULL);

}

int init_ex()
{
	int i= 0;
	char szerr[256];

	ow_queue_init(&owq);
	pthread_mutex_init(&owq_mutex, NULL);
	
	for(i=0; i<fuzzing_opt.ois_cnt; i++)
	{
		fuzz_logger_log(FUZZ_LOG_DEBUG, "interface: %s, channel: %d\n", fuzzing_opt.ois[i].osdep_iface_in, fuzzing_opt.ois[i].channel);
		oi_init(&fuzzing_opt.ois[i]);
		if((fuzzing_opt.ois[i].thread_id = pthread_create(&fuzzing_opt.ois[i].fthread, NULL, oi_receive_thread, &fuzzing_opt.ois[i])) != 0)
		{
			fuzz_logger_log(FUZZ_LOG_ERR, "create oi_receive_thread-[%d] failed.", i);
			exit(-1);
		}
	}

	return 0;
}

struct packet read_packet_ex()
{
	struct packet pkt = {0};
	if(!ow_queue_empty(&owq))
	{
		pthread_mutex_lock(&owq_mutex);
		ow_queue_pop(&owq, &pkt);
		pthread_mutex_unlock(&owq_mutex);
	}

	return pkt;
}

int send_packet_ex(struct packet *pkt)
{
	int i = 0;

	if(pkt){
		//fuzzing_opt.fuzz_pkt = *pkt;
		fuzz_logger_log(FUZZ_LOG_DEBUG, "channel: %d --> send packet: %d", pkt->channel, pkt->len);
		log_pkt(FUZZ_LOG_DEBUG, pkt);
		if(fuzzing_opt.test_type != 0 && fuzzing_opt.fuzz_work_mode != FUZZ_WORK_MODE_MITM)
			save_packet(pkt);

		if(pkt->channel != 0)
		{
			for(i=0; i<fuzzing_opt.ois_cnt; i++)
			{
				if(fuzzing_opt.ois[i].channel == pkt->channel)
				{
					fuzzing_opt.fuzz_pkt_num++;
					return osdep_send_packet_ex(&fuzzing_opt.ois[i], pkt);
				}
			}
		}
		else
		{
			fuzzing_opt.fuzz_pkt_num++;
			return osdep_send_packet_ex(&fuzzing_opt.ois[0], pkt);
		}
	}

	return -1;
}

int oi_init(struct osdep_instance *oi)
{
	char szerr[1024] = {0};
	int mode = 0;
	int channel = 0;

	strncpy(oi->osdep_iface_in, oi->osdep_iface_out, sizeof(oi->osdep_iface_in)-1);

	kismet_interface_down(oi->osdep_iface_out, szerr);
	sleep(0.5);
	kismet_set_mode(oi->osdep_iface_out, szerr, 6);
	kismet_interface_up(oi->osdep_iface_out, szerr);
	sleep(0.5);
	kismet_set_channel(oi->osdep_iface_out, oi->channel, szerr);
	kismet_get_mode(oi->osdep_iface_out, szerr, &mode);
	channel = kismet_get_channel(oi->osdep_iface_out, szerr);
	
	if(mode != 6 || channel != oi->channel)
	{
		fuzz_logger_log(FUZZ_LOG_ERR, "init_oi failed, interface: %s, mode: %d, channel: %d\n", oi->osdep_iface_out, mode, channel);
		exit(-1);
	}

	if(0 != osdep_start_ex(oi)){
		fuzz_logger_log(FUZZ_LOG_ERR, "osdep_start_ex failed!");
		exit(-1);
	}

	sleep(1);

	return 0;
}

int init(char *interface, int chan)
{
	char szerr[256] = {0};
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

	if(0 != osdep_start(interface, interface))
	{
		fuzz_logger_log(FUZZ_LOG_ERR, "osdep_start error");
		return -1;
	}

	return 0;
}

int reinit(char *interface, int chan)
{
	char szerr[512] = {0};	

	osdep_stop();

	kismet_interface_down(interface, szerr);
	usleep(100);
	kismet_set_mode(interface, szerr, 6);
	kismet_interface_up(interface, szerr);
	usleep(100);
	kismet_set_channel(interface, chan, szerr);

	if(0 != osdep_start(interface, interface))
	{
		fuzz_logger_log(FUZZ_LOG_ERR, "osdep_start error");
		return -1;
	}

	return 0;
}

int send_frame(struct packet *pkt)
{
	int times = 0;
	int send_time = 0;

	if(pkt->len == 0)
	{
		fuzz_logger_log(FUZZ_LOG_DEBUG,"sending frame error, packet length: %d", pkt->len); 
		return -1;
	}

	if(pkt->len > MAX_IEEE_PACKET_SIZE)
	{
		dumphex(pkt->data, MAX_IEEE_PACKET_SIZE);
	}

	if(fuzzing_opt.test_type == 1)
	{
		times = 3;
	}
	else
	{
		times =1;
	}

	//fuzz_logger_log(FUZZ_LOG_DEBUG,"sending frame, packet length: %d", pkt->len); 

	while(send_time < times)
	{
		if(-1 == osdep_send_packet(pkt))
		{
			fuzz_logger_log(FUZZ_LOG_ERR, "sending frame error, packet length: %d", pkt->len); 
			log_pkt(FUZZ_LOG_ERR, pkt);
		}
		send_time++;
		//usleep(1);
	}

	//log_pkt(FUZZ_LOG_DEBUG, pkt);

	return 0;
}


void frame_fuzzing()
{
	struct packet fuzz_pkt = {0};
	uint32_t frame_idx = 0;

	srandom(time(NULL));
	frame_idx = random() % fuzzing_opt.owfuzz_frames_cnt;
	
	memset(&fuzz_pkt, 0, sizeof(fuzz_pkt));
	fuzz_pkt = get_frame(fuzzing_opt.owfuzz_frames[frame_idx], fuzzing_opt.bssid, fuzzing_opt.source_addr, fuzzing_opt.target_addr, NULL);
	send_packet_ex(&fuzz_pkt);
}

void p2p_frame_fuzzing()
{
	struct packet fuzz_pkt = {0};
	uint32_t frame_idx = 0;

	srandom(time(NULL));
	frame_idx = random() % (sizeof(p2p_frames) / sizeof(p2p_frames[0]));
	
	memset(&fuzz_pkt, 0, sizeof(fuzz_pkt));
	fuzz_pkt = get_frame(p2p_frames[frame_idx], fuzzing_opt.bssid, fuzzing_opt.source_addr, fuzzing_opt.target_addr, NULL);
	send_packet_ex(&fuzz_pkt);
}

void* fuzzing_thread(void *param)
{
	struct packet fuzz_pkt = {0};
	struct timeval tv;
	uint64_t current_time;
	uint64_t pass_time;
	uint64_t fuzz_current_time;
	uint64_t fuzz_pass_time;
	uint32_t frame_idx = 0;
	uint32_t frame_array_size = 0;
	uint8_t *fuzz_frames;

	fuzzing_option *fuzzing_opt = (fuzzing_option*)param;

 	gettimeofday(&tv,NULL);
	pass_time = tv.tv_sec*1000 + tv.tv_usec/1000;
	fuzz_pass_time = /*tv.tv_sec;*/tv.tv_sec*1000 + tv.tv_usec/1000;

	if(FUZZ_WORK_MODE_AP == fuzzing_opt->fuzz_work_mode)
	{
		fuzz_logger_log(FUZZ_LOG_DEBUG, "Getting AP frames");
		owfuzz_config_get_ap_frames(owfuzz_frames, &frame_array_size);
		fuzz_frames = owfuzz_frames;

	}
	else if(FUZZ_WORK_MODE_STA == fuzzing_opt->fuzz_work_mode)
	{
		fuzz_logger_log(FUZZ_LOG_DEBUG, "Getting STA frames");
		owfuzz_config_get_sta_frames(owfuzz_frames, &frame_array_size);
		fuzz_frames = owfuzz_frames;
	}

	fuzzing_opt->owfuzz_frames = owfuzz_frames;
	fuzzing_opt->owfuzz_frames_cnt = frame_array_size;


	fuzz_logger_log(FUZZ_LOG_DEBUG, "fuzzing frames count: %d", frame_array_size);

	sleep(1);

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
				fuzz_pkt = get_default_frame(IEEE80211_TYPE_BEACON, fuzzing_opt->source_addr, fuzzing_opt->source_addr, SE_BROADCASTMAC, NULL);
				send_packet_ex(&fuzz_pkt);

				pass_time = current_time;
			}	

		}
		else if(0 == strcmp(fuzzing_opt->mode, STA_MODE) && fuzzing_opt->test_type == 1){
			if(current_time - pass_time >= 100)
			{
				//fuzz_pkt = create_p2p_probe_request(SE_BROADCASTMAC, fuzzing_opt->source_addr, SE_BROADCASTMAC, 0, NULL);
				//send_packet_ex(&fuzz_pkt);
				pass_time = current_time;
			}
		}

		if(fuzzing_opt->test_type == 2 && (fuzz_current_time - fuzz_pass_time >= 50))
		{
			frame_idx = 0;

			for(frame_idx = 0; frame_idx < frame_array_size; frame_idx++)
			{
				fuzz_logger_log(FUZZ_LOG_DEBUG, "fuzzing frame idx: %d", frame_idx);

				memset(&fuzz_pkt, 0, sizeof(fuzz_pkt));
				fuzz_pkt = get_frame(fuzz_frames[frame_idx], fuzzing_opt->bssid, fuzzing_opt->source_addr, fuzzing_opt->target_addr, NULL);
				fuzz_pkt.channel = fuzzing_opt->ois[0].channel;
				fuzzing_opt->fuzz_pkt = fuzz_pkt;
			
				send_packet_ex(&fuzz_pkt);

				print_status(NULL);

				usleep(10000);
			}
		}
		else if(fuzzing_opt->test_type == 3 && fuzzing_opt->p2p_frame_test == 1 && (fuzz_current_time - fuzz_pass_time >= 50))
		{
			for(frame_idx = 0; frame_idx < (sizeof(p2p_frames) / sizeof(p2p_frames[0])); frame_idx++)
			{
				fuzz_logger_log(FUZZ_LOG_DEBUG, "fuzzing p2p frame idx: %d", frame_idx);
				memset(&fuzz_pkt, 0, sizeof(fuzz_pkt));
				fuzz_pkt = get_p2p_frame(p2p_frames[frame_idx], fuzzing_opt->p2p_bssid, fuzzing_opt->p2p_source_addr, fuzzing_opt->p2p_target_addr, NULL);
				fuzz_pkt.channel = fuzzing_opt->ois[fuzzing_opt->p2p_operating_interface_id].channel;
				fuzzing_opt->fuzz_pkt = fuzz_pkt;
			
				send_packet_ex(&fuzz_pkt);

				usleep(10000);
			}

			fuzz_pass_time = fuzz_current_time;
		}
		else{
			usleep(10000);
		}
	}
}

void handle_action(struct packet *pkt,struct ether_addr bssid, struct ether_addr smac, struct ether_addr dmac, fuzzing_option *fuzzing_opt)
{
	
}

void handle_sta_auth(struct packet *pkt,struct ether_addr bssid, struct ether_addr smac, struct ether_addr dmac, fuzzing_option *fuzzing_opt)
{
	struct ieee_hdr *hdr;
	struct packet fuzz_pkt = {0};
	uint8_t frame_type = 0;

	hdr = (struct ieee_hdr *) pkt->data;
	frame_type = hdr->type;
	frame_type = frame_type & 0x0F;

	switch(hdr->type)
	{
	case IEEE80211_TYPE_BEACON:
	{
		if(is_p2p_beacon(pkt))
		{
			handle_p2p(pkt, bssid, smac,dmac,fuzzing_opt);
		}

	}
	break;
	case IEEE80211_TYPE_PROBEREQ:
	{
		if(is_p2p_probe(pkt))
		{
			handle_p2p(pkt, bssid, smac,dmac,fuzzing_opt);
		}
		else
		{
			if(fuzzing_opt->test_type == 1)
			{
				print_interaction_status(bssid, smac, dmac, "Probe Request", "Probe Response");

				fuzz_pkt = get_frame(IEEE80211_TYPE_ACK, bssid, dmac, smac, pkt);
				send_packet_ex(&fuzz_pkt);
				fuzz_pkt = get_frame(IEEE80211_TYPE_PROBERES, bssid, dmac, smac, pkt);
				fuzzing_opt->fuzz_pkt = fuzz_pkt;
				send_packet_ex(&fuzz_pkt);
				if(fuzzing_opt->wpa_s < WPA_SCANNING)
					fuzzing_opt->wpa_s = WPA_SCANNING;
			}
		}
	}
	break;
	case IEEE80211_TYPE_PROBERES:
	{
		if(is_p2p_probe(pkt))
		{
			handle_p2p(pkt, bssid, smac,dmac,fuzzing_opt);
		}
	}
	break;
	case IEEE80211_TYPE_AUTH:
	{
		if(fuzzing_opt->test_type == 1)
		{
			fuzz_pkt = get_frame(IEEE80211_TYPE_ACK, bssid, dmac, smac, pkt);
			send_packet_ex(&fuzz_pkt);
			fuzzing_opt->wpa_s = WPA_AUTHENTICATING;
			fuzz_pkt = get_frame(IEEE80211_TYPE_AUTH, bssid, dmac, smac, pkt);
			fuzzing_opt->fuzz_pkt = fuzz_pkt;
			send_packet_ex(&fuzz_pkt);
		}
	}
	break;
	case IEEE80211_TYPE_ASSOCREQ:
	case IEEE80211_TYPE_REASSOCREQ:
	{
		if(fuzzing_opt->test_type == 1)
		{
			print_interaction_status(bssid, smac, dmac, "Association Request", "Association Response");

			fuzzing_opt->wpa_s = WPA_ASSOCIATING;
			fuzz_pkt = get_frame(IEEE80211_TYPE_ACK, bssid, dmac, smac, pkt);
			send_packet_ex(&fuzz_pkt);
			fuzz_pkt = get_default_frame(IEEE80211_TYPE_ASSOCRES, bssid, dmac, smac, pkt);
			fuzzing_opt->fuzz_pkt = fuzz_pkt;
			send_packet_ex(&fuzz_pkt);

			fuzzing_opt->wpa_s = WPA_ASSOCIATED;

			// 4-way-handshake m1
			if(fuzzing_opt->auth_type == WPA3 || fuzzing_opt->auth_type==WPA2_PSK_TKIP_AES || fuzzing_opt->auth_type==WPA2_PSK_AES || fuzzing_opt->auth_type==WPA2_PSK_TKIP || 
			fuzzing_opt->auth_type==WPA_PSK_TKIP_AES || fuzzing_opt->auth_type==WPA_PSK_AES || fuzzing_opt->auth_type==WPA_PSK_TKIP)
			{
				fuzzing_opt->wpa_s = WPA_4WAY_HANDSHAKE;
				fuzz_pkt = get_frame(IEEE80211_TYPE_QOSDATA, bssid, dmac, smac, pkt);
				fuzzing_opt->fuzz_pkt = fuzz_pkt;
				send_packet_ex(&fuzz_pkt);
			}
			else if(fuzzing_opt->auth_type == EAP_8021X)
			{
				fuzzing_opt->wpa_s = WPA_EAP_HANDSHAKE;
				fuzz_pkt = get_frame(IEEE80211_TYPE_QOSDATA, bssid, dmac, smac, pkt);
				fuzzing_opt->fuzz_pkt = fuzz_pkt;
				send_packet_ex(&fuzz_pkt);			
			}
			else
			{
				fuzzing_opt->wpa_s = WPA_COMPLETED;
			}
		}

	}
	break;
	case IEEE80211_TYPE_DATA:
	{
		if(fuzzing_opt->test_type == 1)
		{
			fuzz_pkt = get_frame(IEEE80211_TYPE_ACK, bssid, dmac, smac, pkt);
			send_packet_ex(&fuzz_pkt);

			fuzz_pkt = get_frame(IEEE80211_TYPE_DATA, bssid, dmac, smac, pkt);
			fuzzing_opt->fuzz_pkt = fuzz_pkt;
			send_packet_ex(&fuzz_pkt);
		}

	}
	break;
	case IEEE80211_TYPE_QOSDATA:
	{
		if(fuzzing_opt->test_type == 1)
		{
			fuzz_pkt = get_frame(IEEE80211_TYPE_ACK, bssid, dmac, smac, pkt);
			send_packet_ex(&fuzz_pkt);

			fuzz_pkt = get_frame(IEEE80211_TYPE_QOSDATA, bssid, dmac, smac, pkt);
			fuzzing_opt->fuzz_pkt = fuzz_pkt;
			send_packet_ex(&fuzz_pkt);
		}

	}
	break;
	case IEEE80211_TYPE_DISASSOC:
		if(fuzzing_opt->test_type == 1)
		{
			fuzzing_opt->wpa_s = WPA_DISCONNECTED;
			fuzz_pkt = get_frame(IEEE80211_TYPE_ACK, bssid, dmac, smac, pkt);
			send_packet_ex(&fuzz_pkt);

		}		
		break;
	case IEEE80211_TYPE_DEAUTH:
		if(fuzzing_opt->test_type == 1)
		{
			fuzzing_opt->wpa_s = WPA_DISCONNECTED;
			fuzz_pkt = get_frame(IEEE80211_TYPE_ACK, bssid, dmac, smac, pkt);
			send_packet_ex(&fuzz_pkt);
		}
		break;
	case IEEE80211_TYPE_ACTION:
		if(is_p2p_action(pkt))
		{
			handle_p2p(pkt, bssid, smac,dmac,fuzzing_opt);
		}
		else if(is_awdl_frame(pkt))
		{
			handle_awdl(pkt, bssid, smac,dmac,fuzzing_opt);
		}
		else
		{
			if(fuzzing_opt->test_type == 1)
			{
				fuzz_pkt = get_frame(IEEE80211_TYPE_ACK, bssid, dmac, smac, pkt);
				send_packet_ex(&fuzz_pkt);
				fuzz_pkt = get_frame(IEEE80211_TYPE_ACTION, bssid, dmac, smac, pkt);
				fuzzing_opt->fuzz_pkt = fuzz_pkt;
				send_packet_ex(&fuzz_pkt);
			}
		}
		break;
	default:
	break;
	}

}

// ap, p2p, 
void handle_ap_auth(struct packet *pkt,struct ether_addr bssid, struct ether_addr smac, struct ether_addr dmac, fuzzing_option *fuzzing_opt)
{
	struct ieee_hdr *hdr;
	struct packet fuzz_pkt = {0};
	uint8_t frame_type = 0;

	hdr = (struct ieee_hdr *) pkt->data;
	frame_type = hdr->type;
	frame_type = frame_type & 0x0F;

	if(pkt){
		fuzz_pkt.channel = pkt->channel;
	}

	if(FUZZ_WORK_MODE_STA == fuzzing_opt->fuzz_work_mode)
	{
		switch(hdr->type)
		{
		case IEEE80211_TYPE_BEACON:
			if(is_p2p_beacon(pkt))
			{
				handle_p2p(pkt, bssid, smac,dmac,fuzzing_opt);
			}
			else
			{
				if(fuzzing_opt->test_type ==1)
				{
					if(fuzzing_opt->wpa_s < WPA_SCANNING)
					{
						fuzz_pkt = get_frame(IEEE80211_TYPE_PROBEREQ, bssid, fuzzing_opt->source_addr, smac, pkt);
						fuzzing_opt->fuzz_pkt = fuzz_pkt;
						send_packet_ex(&fuzz_pkt);
						fuzzing_opt->wpa_s = WPA_SCANNING;
						print_interaction_status(bssid, smac, fuzzing_opt->source_addr, "Beacon", "Probe Request");
					}
				}
			}
			break;
		case IEEE80211_TYPE_PROBEREQ:
			if(is_p2p_probe(pkt))
			{
				handle_p2p(pkt, bssid, smac,dmac,fuzzing_opt);
			}
			break;
		case IEEE80211_TYPE_PROBERES:
			if(is_p2p_probe(pkt))
			{
				handle_p2p(pkt, bssid, smac,dmac,fuzzing_opt);
			}
			else
			{
				if(fuzzing_opt->test_type ==1)
				{
					fuzz_pkt = get_frame(IEEE80211_TYPE_ACK, bssid, dmac, smac, pkt);
					send_packet_ex(&fuzz_pkt);

					//print_interaction_status(bssid, smac, dmac, "Probe Response", "");

					fuzz_pkt = get_frame(IEEE80211_TYPE_AUTH, bssid, dmac, smac, pkt);
					fuzzing_opt->fuzz_pkt = fuzz_pkt;
					send_packet_ex(&fuzz_pkt);
				}
			}
			break;
		case IEEE80211_TYPE_AUTH:
			if(fuzzing_opt->test_type ==1)
			{
				fuzz_pkt = get_frame(IEEE80211_TYPE_ACK, bssid, dmac, smac, pkt);
				send_packet_ex(&fuzz_pkt);	

				fuzz_pkt = get_frame(IEEE80211_TYPE_AUTH, bssid, dmac, smac, pkt);
				fuzzing_opt->fuzz_pkt = fuzz_pkt;
				if(fuzz_pkt.len){
					send_packet_ex(&fuzz_pkt);
				}
				
				if(fuzzing_opt->wpa_s == WPA_ASSOCIATING)
				{
					fuzz_pkt = get_frame(IEEE80211_TYPE_ASSOCREQ, bssid, dmac, smac, pkt);
					fuzzing_opt->fuzz_pkt = fuzz_pkt;
					send_packet_ex(&fuzz_pkt);
					
					print_interaction_status(bssid, smac, dmac, "", "Association Request");
				}
			}
			break;
		case IEEE80211_TYPE_ASSOCRES:
			if(fuzzing_opt->test_type ==1)
			{
				print_interaction_status(bssid, smac, dmac, "Association Response", "");

				fuzzing_opt->wpa_s = WPA_ASSOCIATED;
				fuzz_pkt = get_frame(IEEE80211_TYPE_ACK, bssid, dmac, smac, pkt);
				send_packet_ex(&fuzz_pkt);

				// recevice 4-way-handshake msg1 from ap
				if(fuzzing_opt->auth_type == WPA3 || fuzzing_opt->auth_type==WPA2_PSK_TKIP_AES || fuzzing_opt->auth_type==WPA2_PSK_AES || fuzzing_opt->auth_type==WPA2_PSK_TKIP || 
				fuzzing_opt->auth_type==WPA_PSK_TKIP_AES || fuzzing_opt->auth_type==WPA_PSK_AES || fuzzing_opt->auth_type==WPA_PSK_TKIP)
				{

				}
				else if(fuzzing_opt->auth_type == EAP_8021X)
				{

				}
				else
				{
					fuzzing_opt->wpa_s = WPA_COMPLETED;
				}
			}
			break;
		case IEEE80211_TYPE_REASSOCRES:
			if(fuzzing_opt->test_type ==1)
			{
				print_interaction_status(bssid, smac, dmac, "Reassociation Response", "");

				fuzzing_opt->wpa_s = WPA_ASSOCIATED;
				fuzz_pkt = get_frame(IEEE80211_TYPE_ACK, bssid, dmac, smac, pkt);
				send_packet_ex(&fuzz_pkt);

				// recevice 4-way-handshake msg1 from ap
				if(fuzzing_opt->auth_type == WPA3 || fuzzing_opt->auth_type==WPA2_PSK_TKIP_AES || fuzzing_opt->auth_type==WPA2_PSK_AES || fuzzing_opt->auth_type==WPA2_PSK_TKIP || 
				fuzzing_opt->auth_type==WPA_PSK_TKIP_AES || fuzzing_opt->auth_type==WPA_PSK_AES || fuzzing_opt->auth_type==WPA_PSK_TKIP)
				{

				}
				else if(fuzzing_opt->auth_type == EAP_8021X)
				{

				}
				else
				{
					fuzzing_opt->wpa_s = WPA_COMPLETED;
				}
			}

			break;
		case IEEE80211_TYPE_DEAUTH:
			if(fuzzing_opt->test_type ==1)
			{
				print_interaction_status(bssid, smac, dmac, "Deauth", "");

				fuzz_pkt = get_frame(IEEE80211_TYPE_ACK, bssid, dmac, smac, pkt);
				send_packet_ex(&fuzz_pkt);

				fuzzing_opt->wpa_s = WPA_DISCONNECTED;
			}
			
			break;
		case IEEE80211_TYPE_DISASSOC:
			if(fuzzing_opt->test_type ==1)
			{
				print_interaction_status(bssid, smac, dmac, "Disassoc", "");

				fuzz_pkt = get_frame(IEEE80211_TYPE_ACK, bssid, dmac, smac, pkt);
				send_packet_ex(&fuzz_pkt);

				fuzzing_opt->wpa_s = WPA_DISCONNECTED;
			}
			break;
		case IEEE80211_TYPE_ACTION:
			if(is_p2p_action(pkt))
			{
				handle_p2p(pkt, bssid, smac,dmac,fuzzing_opt);
			}
			else if(is_awdl_frame(pkt))
			{
				handle_awdl(pkt, bssid, smac,dmac,fuzzing_opt);
			}
			else
			{
				if(fuzzing_opt->test_type ==1)
				{
					fuzz_pkt = get_frame(IEEE80211_TYPE_ACK, bssid, dmac, smac, pkt);
					send_packet_ex(&fuzz_pkt);
					fuzz_pkt = get_frame(IEEE80211_TYPE_ACTION, bssid, dmac, smac, pkt);
					fuzzing_opt->fuzz_pkt = fuzz_pkt;
					send_packet_ex(&fuzz_pkt);
				}
			}

			break;
		case IEEE80211_TYPE_DATA:
			if(fuzzing_opt->test_type ==1)
			{
				fuzz_pkt = get_frame(IEEE80211_TYPE_ACK, bssid, dmac, smac, pkt);
				send_packet_ex(&fuzz_pkt);
				fuzz_pkt = get_frame(IEEE80211_TYPE_DATA, bssid, dmac, smac, pkt);
				fuzzing_opt->fuzz_pkt = fuzz_pkt;
				send_packet_ex(&fuzz_pkt);
			}
			break;
		case IEEE80211_TYPE_QOSDATA:
			if(fuzzing_opt->test_type ==1)
			{
				fuzz_pkt = get_frame(IEEE80211_TYPE_ACK, bssid, dmac, smac, pkt);
				send_packet_ex(&fuzz_pkt);
				fuzz_pkt = get_frame(IEEE80211_TYPE_QOSDATA, bssid, dmac, smac, pkt);
				fuzzing_opt->fuzz_pkt = fuzz_pkt;
				send_packet_ex(&fuzz_pkt);
			}
			break;
		default:
			break;
		}
	}
}

int is_target_beacon(struct packet *pkt, struct ether_addr bssid, fuzzing_option *fuzzing_opt)
{
    struct ieee_hdr *hdr;
    char *ies;
    int left = 0;

    hdr = (struct ieee_hdr *) pkt->data;
    if(hdr->type == IEEE80211_TYPE_BEACON)
    {
        ies = pkt->data + sizeof(struct ieee_hdr) + sizeof(struct beacon_fixed);
        left = pkt->len - sizeof(struct ieee_hdr) - sizeof(struct beacon_fixed);
        if(MAC_MATCHES(bssid, fuzzing_opt->target_addr))
        {
            while(left>0)
            {
                if(ies[0] == IE_0_SSID)
                {
                    if(!memcmp(ies+2, fuzzing_opt->target_ssid, ies[1]))
                    {
                        return 1;
                    }
                }
                else
                {
                    left -= (ies[1] + 2);
                    ies += (2 + ies[1]);
                }
            }
        }
    }

    return 0;
}

int clone_ap(struct packet *pkt, fuzzing_option *fuzzing_opt)
{
    struct ieee_hdr *hdr;
    char *ies;
    int left = 0;

    hdr = (struct ieee_hdr *) pkt->data;
    if(hdr->type == IEEE80211_TYPE_BEACON)
    {
        fuzzing_opt->mitm_ap_bcn.channel = fuzzing_opt->mitm_ap_channel;
        fuzzing_opt->mitm_ap_bcn.len = pkt->len;
        memcpy(fuzzing_opt->mitm_ap_bcn.data, pkt->data, pkt->len);

        ies = fuzzing_opt->mitm_ap_bcn.data + sizeof(struct ieee_hdr) + sizeof(struct beacon_fixed);
        left = fuzzing_opt->mitm_ap_bcn.len - sizeof(struct ieee_hdr) - sizeof(struct beacon_fixed);
        while(left>0)
        {
            if(ies[0] == IE_3_DSSS_PARAMETER_SET || ies[0] == IE_61_HT_OPERATION)
            {
                ies[2] = fuzzing_opt->mitm_ap_channel;
            }

            left -= (ies[1] + 2);
            ies += (2 + ies[1]);
        }

        send_packet_ex(&fuzzing_opt->mitm_ap_bcn);
    }

    return 0;
}


void send_mitm_beacon_csa(fuzzing_option *fuzzing_opt)
{
	struct packet beacon_csa = {0};
	int i;
	uint16_t next_seqno = 0;

	beacon_csa.channel = fuzzing_opt->real_ap_bcn.channel;
	beacon_csa.len = fuzzing_opt->real_ap_bcn.len;
	memcpy(beacon_csa.data, fuzzing_opt->real_ap_bcn.data, fuzzing_opt->real_ap_bcn.len);

	beacon_csa.data[beacon_csa.len] = 0x25;
	beacon_csa.data[beacon_csa.len+1] = 0x03;
	beacon_csa.data[beacon_csa.len+2] = 0x01;
	beacon_csa.data[beacon_csa.len+3] = fuzzing_opt->mitm_ap_channel;
	beacon_csa.data[beacon_csa.len+4] = 0x01;

	beacon_csa.len += 5;

	next_seqno = fuzzing_opt->recv_seq_ctrl + 1;
	set_seqno(&beacon_csa, next_seqno);
	//fuzzing_opt->recv_seq_ctrl++;
	for(i=0; i< 3; i++)
	{

		send_packet_ex(&beacon_csa);
		fuzz_logger_log(FUZZ_LOG_INFO, "mitm --> Real AP channel [%d] send %d CSA(Beacon) to client %02X:%02X:%02X:%02X:%02X:%02X, from chnanel [%d] switch to channel [%d]", 
			fuzzing_opt->channel, 
			i+1,
			fuzzing_opt->source_addr.ether_addr_octet[0],
			fuzzing_opt->source_addr.ether_addr_octet[1],
			fuzzing_opt->source_addr.ether_addr_octet[2],
			fuzzing_opt->source_addr.ether_addr_octet[3],
			fuzzing_opt->source_addr.ether_addr_octet[4],
			fuzzing_opt->source_addr.ether_addr_octet[5], 
			beacon_csa.channel,
			fuzzing_opt->mitm_ap_channel);

		usleep(1000);
	}
}

void send_mitm_action_csa(fuzzing_option *fuzzing_opt)
{
	struct packet action_csa = {0};
	int i;
	uint16_t next_seqno = 0;

	create_ieee_hdr(&action_csa, IEEE80211_TYPE_ACTION, 'a', 0x013A, fuzzing_opt->source_addr, fuzzing_opt->target_addr, fuzzing_opt->target_addr, SE_NULLMAC, 0);

	action_csa.channel = fuzzing_opt->real_ap_bcn.channel;
	action_csa.data[action_csa.len] = 0x00;
	action_csa.data[action_csa.len+1] = 0x04;
	action_csa.data[action_csa.len+2] = 0x25; // ID
	action_csa.data[action_csa.len+3] = 0x03; // Length
	action_csa.data[action_csa.len+4] = 0x01; // Mode
	action_csa.data[action_csa.len+5] = fuzzing_opt->mitm_ap_channel; // new channel
	action_csa.data[action_csa.len+6] = 0x01; // count

	action_csa.len += 7;

	next_seqno = fuzzing_opt->recv_seq_ctrl + 1;
	set_seqno(&action_csa, next_seqno);
	//fuzzing_opt->recv_seq_ctrl++;
	for(i=0; i< 3; i++)
	{
		send_packet_ex(&action_csa);
		fuzz_logger_log(FUZZ_LOG_INFO, "mitm --> Real AP channel [%d] send %d CSA(Action) to client %02X:%02X:%02X:%02X:%02X:%02X, from chnanel [%d] switch to channel [%d]", 
			fuzzing_opt->channel, 
			i+1,
			fuzzing_opt->source_addr.ether_addr_octet[0],
			fuzzing_opt->source_addr.ether_addr_octet[1],
			fuzzing_opt->source_addr.ether_addr_octet[2],
			fuzzing_opt->source_addr.ether_addr_octet[3],
			fuzzing_opt->source_addr.ether_addr_octet[4],
			fuzzing_opt->source_addr.ether_addr_octet[5], 
			action_csa.channel,
			fuzzing_opt->mitm_ap_channel);

		usleep(1000);
	}
}

void send_mitm_beacon_ecsa(fuzzing_option *fuzzing_opt)
{
	struct packet beacon_ecsa = {0};
	int i;
	uint16_t next_seqno = 0;

	beacon_ecsa.channel = fuzzing_opt->real_ap_bcn.channel;
	beacon_ecsa.len = fuzzing_opt->real_ap_bcn.len;
	memcpy(beacon_ecsa.data, fuzzing_opt->real_ap_bcn.data, fuzzing_opt->real_ap_bcn.len);

	beacon_ecsa.data[beacon_ecsa.len] = 0x3C;
	beacon_ecsa.data[beacon_ecsa.len+1] = 0x04;
	beacon_ecsa.data[beacon_ecsa.len+2] = 0x01;

	// class, 81(0x61), 1,2,3,4,5,6,7,8,9,10,11 | 115(0x73), 36,40,44,48 | 124(0x7C), 149,153,157,161 
	if(fuzzing_opt->mitm_ap_channel >=1 && fuzzing_opt->mitm_ap_channel <=11)
	{
		beacon_ecsa.data[beacon_ecsa.len+3] = 0x51;
	}
	else if(fuzzing_opt->mitm_ap_channel >=36 && fuzzing_opt->mitm_ap_channel <=48)
	{
		beacon_ecsa.data[beacon_ecsa.len+3] = 0x73;
	}
	else if(fuzzing_opt->mitm_ap_channel >=149 && fuzzing_opt->mitm_ap_channel <=161)
	{
		beacon_ecsa.data[beacon_ecsa.len+3] = 0x7C;
	}
	
	beacon_ecsa.data[beacon_ecsa.len+4] = fuzzing_opt->mitm_ap_channel;
	beacon_ecsa.data[beacon_ecsa.len+5] = 0x01;

	beacon_ecsa.len += 6;

	next_seqno = fuzzing_opt->recv_seq_ctrl + 1;
	set_seqno(&beacon_ecsa, next_seqno);
	//fuzzing_opt->recv_seq_ctrl++;

	for(i=0; i< 3; i++)
	{

		send_packet_ex(&beacon_ecsa);
		fuzz_logger_log(FUZZ_LOG_INFO, "mitm --> Real AP channel [%d] send %d ECSA(Beacon) to client %02X:%02X:%02X:%02X:%02X:%02X, from chnanel [%d] switch to channel [%d]", 
			fuzzing_opt->channel, 
			i+1,
			fuzzing_opt->source_addr.ether_addr_octet[0],
			fuzzing_opt->source_addr.ether_addr_octet[1],
			fuzzing_opt->source_addr.ether_addr_octet[2],
			fuzzing_opt->source_addr.ether_addr_octet[3],
			fuzzing_opt->source_addr.ether_addr_octet[4],
			fuzzing_opt->source_addr.ether_addr_octet[5], 
			beacon_ecsa.channel,
			fuzzing_opt->mitm_ap_channel);

		usleep(1000);
	}
}


void send_mitm_action_ecsa(fuzzing_option *fuzzing_opt)
{
	struct packet action_ecsa = {0};
	int i;
	uint16_t next_seqno = 0;

	create_ieee_hdr(&action_ecsa, IEEE80211_TYPE_ACTION, 'a', 0x013A, fuzzing_opt->source_addr, fuzzing_opt->target_addr, fuzzing_opt->target_addr, SE_NULLMAC, 0);

	action_ecsa.channel = fuzzing_opt->real_ap_bcn.channel;
	action_ecsa.data[action_ecsa.len] = 0x04;
	action_ecsa.data[action_ecsa.len+1] = 0x04;
	action_ecsa.data[action_ecsa.len+2] = 0x01;

	// class, 81(0x61), 1,2,3,4,5,6,7,8,9,10,11 | 115(0x73), 36,40,44,48 | 124(0x7C), 149,153,157,161 
	if(fuzzing_opt->mitm_ap_channel >=1 && fuzzing_opt->mitm_ap_channel <=11)
	{
		action_ecsa.data[action_ecsa.len+3] = 0x51;
	}
	else if(fuzzing_opt->mitm_ap_channel >=36 && fuzzing_opt->mitm_ap_channel <=48)
	{
		action_ecsa.data[action_ecsa.len+3] = 0x73;
	}
	else if(fuzzing_opt->mitm_ap_channel >=149 && fuzzing_opt->mitm_ap_channel <=161)
	{
		action_ecsa.data[action_ecsa.len+3] = 0x7C;
	}

	action_ecsa.data[action_ecsa.len+4] = fuzzing_opt->mitm_ap_channel;
	action_ecsa.data[action_ecsa.len+5] = 0x01;

	action_ecsa.len += 6;

	next_seqno = fuzzing_opt->recv_seq_ctrl + 1;
	set_seqno(&action_ecsa, next_seqno);
	//fuzzing_opt->recv_seq_ctrl++;
	for(i=0; i< 3; i++)
	{
		send_packet_ex(&action_ecsa);
		fuzz_logger_log(FUZZ_LOG_INFO, "mitm --> Real AP channel [%d] send %d ECSA(Action) to client %02X:%02X:%02X:%02X:%02X:%02X, from chnanel [%d] switch to channel [%d]", 
			fuzzing_opt->channel, 
			i+1,
			fuzzing_opt->source_addr.ether_addr_octet[0],
			fuzzing_opt->source_addr.ether_addr_octet[1],
			fuzzing_opt->source_addr.ether_addr_octet[2],
			fuzzing_opt->source_addr.ether_addr_octet[3],
			fuzzing_opt->source_addr.ether_addr_octet[4],
			fuzzing_opt->source_addr.ether_addr_octet[5], 
			action_ecsa.channel,
			fuzzing_opt->mitm_ap_channel);

		usleep(1000);
	}
}

/*
		sta               mitm             real_ap

						(real channel)
							|
						copy real_ap
							|
				e-csa
		sta     <---- (real channel)


		sta               mitm_ap          real_ap
			(mitm channel)               (real channel)
		sta     ---->     mitm_ap ->  mon0  ---->   real_ap
			(mitm channel)               (real channel)
		sta     <----     mitm_ap <-  mon0  <----   real_ap


*/
void handle_mitm(struct packet *pkt,struct ether_addr bssid, struct ether_addr smac, struct ether_addr dmac, fuzzing_option *fuzzing_opt)
{
    struct ieee_hdr *hdr;

    hdr = (struct ieee_hdr *) pkt->data;
	struct packet ack_pkt;

	fuzz_logger_log(FUZZ_LOG_DEBUG, "mitm --> fuzzing_opt->mitm_state: %d..", fuzzing_opt->mitm_state);


	if(fuzzing_opt->mitm_state >= 1)
    {
		if(pkt->channel == fuzzing_opt->channel)
		{
			if(MAC_MATCHES(smac, fuzzing_opt->target_addr))
			{
				if(hdr->type != IEEE80211_TYPE_BEACON)
				{
					// transmit packet between client and real ap
					if(MAC_MATCHES(dmac, fuzzing_opt->source_addr) && fuzzing_opt->mitm_state > 1) // real channel
					{// real_ap --> mon0 --> client
					// transmit to client in mitm channel
						fuzz_logger_log(FUZZ_LOG_DEBUG, "mitm --> Real channel [%d], receive frame from %02X:%02X:%02X:%02X:%02X:%02X", pkt->channel,
													smac.ether_addr_octet[0],
													smac.ether_addr_octet[1],
													smac.ether_addr_octet[2],
													smac.ether_addr_octet[3],
													smac.ether_addr_octet[4],
													smac.ether_addr_octet[5]);
													
						pkt->channel = fuzzing_opt->mitm_ap_channel;
						send_packet_ex(pkt);
					}
				}
				else
				{
					if(is_target_beacon(pkt, bssid, fuzzing_opt))
					{
						clone_ap(pkt, fuzzing_opt);
					}
				}
			}
			else 
			{
				if(MAC_MATCHES(smac, fuzzing_opt->source_addr))
					fuzzing_opt->mitm_state == 0;
				else if(MAC_MATCHES(dmac, fuzzing_opt->source_addr))
				{
					if(fuzzing_opt->mitm_state == 2)
					{
						pkt->channel = fuzzing_opt->mitm_ap_channel;
						send_packet_ex(pkt);
					}
				}
			}
		}

		else if(pkt->channel == fuzzing_opt->mitm_ap_channel) // mitm channel
		{
			if(MAC_MATCHES(smac, fuzzing_opt->source_addr)) 
			{// client --> mitm_ap --> real_ap
				if(fuzzing_opt->mitm_state == 1 && hdr->type != IEEE80211_TYPE_PROBEREQ)
				{
					fuzzing_opt->mitm_state = 2;
					fuzz_logger_log(FUZZ_LOG_INFO, "mitm --> Client %02X:%02X:%02X:%02X:%02X:%02X switched to channel [%d]", 
											smac.ether_addr_octet[0],
											smac.ether_addr_octet[1],
											smac.ether_addr_octet[2],
											smac.ether_addr_octet[3],
											smac.ether_addr_octet[4],
											smac.ether_addr_octet[5],
											pkt->channel);
					//exit(0);
				}

				if(fuzzing_opt->mitm_state == 2)
				{
					fuzz_logger_log(FUZZ_LOG_DEBUG, "mitm --> MITM channel [%d], receive frame from %02X:%02X:%02X:%02X:%02X:%02X", pkt->channel, smac.ether_addr_octet[0],
								smac.ether_addr_octet[1],
								smac.ether_addr_octet[2],
								smac.ether_addr_octet[3],
								smac.ether_addr_octet[4],
								smac.ether_addr_octet[5]);

					pkt->channel = fuzzing_opt->channel;
					send_packet_ex(pkt);
				}
			}
			else if(MAC_MATCHES(dmac, fuzzing_opt->target_addr))
			{
				if(fuzzing_opt->mitm_state == 2)
				{
					pkt->channel = fuzzing_opt->channel;
					send_packet_ex(pkt);
				}
			}
		}
    }
	else if(fuzzing_opt->mitm_state == 0)
    {
        if(is_target_beacon(pkt, bssid, fuzzing_opt))
        {
			fuzzing_opt->real_ap_bcn.channel = pkt->channel;
			fuzzing_opt->real_ap_bcn.len = pkt->len;
			memcpy(fuzzing_opt->real_ap_bcn.data, pkt->data, pkt->len);

            fuzz_logger_log(FUZZ_LOG_INFO, "mitm --> Find target AP ssid: %s, bssid: %02X:%02X:%02X:%02X:%02X:%02X", fuzzing_opt->target_ssid, bssid.ether_addr_octet[0],
                            bssid.ether_addr_octet[1],
                            bssid.ether_addr_octet[2],
                            bssid.ether_addr_octet[3],
                            bssid.ether_addr_octet[4],
                            bssid.ether_addr_octet[5]);
            
            fuzz_logger_log(FUZZ_LOG_INFO, "mitm --> Starting MITM AP, ssid: %s, new channel: %d, bssid: %02X:%02X:%02X:%02X:%02X:%02X", fuzzing_opt->target_ssid, fuzzing_opt->mitm_ap_channel,
                                        fuzzing_opt->target_addr.ether_addr_octet[0],
                                        fuzzing_opt->target_addr.ether_addr_octet[1],
                                        fuzzing_opt->target_addr.ether_addr_octet[2],
                                        fuzzing_opt->target_addr.ether_addr_octet[3],
                                        fuzzing_opt->target_addr.ether_addr_octet[4],
                                        fuzzing_opt->target_addr.ether_addr_octet[5]);

            fuzzing_opt->mitm_state = 1;
        }
    }
	
	if(fuzzing_opt->mitm_state == 1)
	{
		if(pkt->channel == fuzzing_opt->channel)
		{
			if(MAC_MATCHES(bssid, fuzzing_opt->target_addr) && MAC_MATCHES(smac, fuzzing_opt->source_addr) && hdr->type != IEEE80211_TYPE_PROBEREQ)
			{// start mitm attack, send ecsa
				send_mitm_action_ecsa(fuzzing_opt);
				//fuzzing_opt->mitm_state = 2;
			}
		}
	}
}

void* start_fuzzing(void *param)
{
	struct packet pkt;
	struct ieee_hdr *hdr;
	uint8_t dsflags;
	char frame_name[64];

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

	char szerr[64] = {0};

	struct packet fuzz_pkt = {0};

	struct timeval tv2;
	uint64_t current_time2;
	uint64_t pass_time2;
	uint64_t fuzz_current_time2;
	uint64_t fuzz_pass_time2;
	uint32_t frame_idx = 0;
	uint32_t frame_array_size = 0;
	uint8_t *fuzz_frames;

	fuzzing_option *fuzzing_opt = (fuzzing_option*)param;
	fuzzing_opt->wpa_s = WPA_DISCONNECTED;

 	gettimeofday(&tv,NULL);
	pass_time = tv.tv_sec;
	ping_pass_time = tv.tv_sec;
	fuzzing_opt->last_recv_pkt_time = 0;

	if(fuzzing_opt->test_type == 2)
	{
		gettimeofday(&tv2,NULL);
		pass_time2 = tv2.tv_sec*1000 + tv2.tv_usec/1000;
		fuzz_pass_time2 = tv2.tv_sec*1000 + tv2.tv_usec/1000;

		if(FUZZ_WORK_MODE_AP == fuzzing_opt->fuzz_work_mode)
		{
			//fuzz sta
			fuzz_logger_log(FUZZ_LOG_DEBUG, "Getting AP frames");
			owfuzz_config_get_ap_frames(owfuzz_frames, &frame_array_size);
			fuzz_frames = owfuzz_frames;

		}
		else if(FUZZ_WORK_MODE_STA == fuzzing_opt->fuzz_work_mode)
		{
			// fuzz ap
			fuzz_logger_log(FUZZ_LOG_DEBUG, "Getting STA frames");
			owfuzz_config_get_sta_frames(owfuzz_frames, &frame_array_size);
			fuzz_frames = owfuzz_frames;
		}
		else if(FUZZ_WORK_MODE_MITM == fuzzing_opt->fuzz_work_mode)
		{
		}

		fuzzing_opt->owfuzz_frames = owfuzz_frames;
		fuzzing_opt->owfuzz_frames_cnt = frame_array_size;

		fuzz_logger_log(FUZZ_LOG_DEBUG, "fuzzing frames count: %d", frame_array_size);
	}
	
	while(1)
	{
		frame_type = 0;
		memset(&smac, 0, 6);
		memset(&dmac, 0, 6);
		memset(&bssid, 0, 6);
		memset(frame_name, 0, sizeof(frame_name));

		gettimeofday(&tv,NULL);
		current_time = tv.tv_sec;
		if((current_time - pass_time >= DEAUTH_TIME) && fuzzing_opt->test_type == 1)
		{
			fuzzing_opt->wpa_s = WPA_DISCONNECTED;

			pass_time = current_time;
		}

		pkt = read_packet_ex();//osdep_read_packet();
		if (pkt.len == 0) 
		{
			if(fuzzing_opt->fuzz_work_mode != FUZZ_WORK_MODE_MITM)
			{
				if((!check_alive_by_pkts(smac)) && fuzzing_opt->target_alive == 1)
				{
					save_exp_payload(&fuzzing_opt->fuzz_pkt);
					log_pkt(FUZZ_LOG_ERR, &fuzzing_opt->fuzz_pkt);
					fuzzing_opt->target_alive = 0;
					fuzzing_opt->last_recv_pkt_time = 0;

					fuzz_logger_log(FUZZ_LOG_INFO, "\t\033[22;31mTarget [%02X:%02X:%02X:%02X:%02X:%02X] is dead...\033[22;39m\n", 
						fuzzing_opt->target_addr.ether_addr_octet[0],
						fuzzing_opt->target_addr.ether_addr_octet[1],
						fuzzing_opt->target_addr.ether_addr_octet[2],
						fuzzing_opt->target_addr.ether_addr_octet[3],
						fuzzing_opt->target_addr.ether_addr_octet[4],
						fuzzing_opt->target_addr.ether_addr_octet[5]
						);
					
					if(fuzzing_opt->test_type == 3)
					{
						fuzzing_opt->p2p_frame_test = 0;
						owfuzz_config_get_channels(fuzzing_opt);
						owfuzz_config_get_macs(fuzzing_opt);
						kismet_set_channel(fuzzing_opt->ois[fuzzing_opt->p2p_operating_interface_id].osdep_iface_out, fuzzing_opt->ois[fuzzing_opt->p2p_operating_interface_id].channel, szerr);
						fuzzing_opt->target_alive = 1;
					}

					while(fuzzing_opt->enable_check_alive && !check_alive_by_ping())
					{
						sleep(1);
					}
				}
			}

			usleep(10);
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
				// extension
				case IEEE80211_TYPE_DMGBEACON:
				#ifdef DEBUG_LOG
					fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->(extension)IEEE80211_TYPE_DMGBEACON");
				#endif
					memcpy(bssid.ether_addr_octet, hdr->addr1.ether_addr_octet, ETHER_ADDR_LEN);
					break;
				default:
				#ifdef DEBUG_LOG
					fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->unknown control & extension frame!!!");
				#endif
					break;
			}
		}

		switch(hdr->type)
		{
			// management   addr1,addr2,addr3
			case IEEE80211_TYPE_ASSOCRES:   // AP
				fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->(management)IEEE80211_TYPE_ASSOCRES");
				strcpy(frame_name, "(management)IEEE80211_TYPE_ASSOCRES");
				break;
			case IEEE80211_TYPE_REASSOCRES:
				fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->(management)IEEE80211_TYPE_REASSOCRES");
				strcpy(frame_name, "(management)IEEE80211_TYPE_REASSOCRES");
				break;
			case IEEE80211_TYPE_PROBERES:
				fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->(management)IEEE80211_TYPE_PROBERES");
				strcpy(frame_name, "(management)IEEE80211_TYPE_PROBERES");
				break;
			case IEEE80211_TYPE_TIMADVERT:
				fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->(management)IEEE80211_TYPE_TIMADVERT");
				strcpy(frame_name, "(management)IEEE80211_TYPE_TIMADVERT");
				break;
			case IEEE80211_TYPE_BEACON:
				fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->(management)IEEE80211_TYPE_BEACON");
				strcpy(frame_name, "(management)IEEE80211_TYPE_BEACON");
				break;
			case IEEE80211_TYPE_ATIM:
				fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->(management)IEEE80211_TYPE_ATIM");
				strcpy(frame_name, "(management)IEEE80211_TYPE_ATIM");
				break;
			case IEEE80211_TYPE_DISASSOC:
				fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->(management)IEEE80211_TYPE_DISASSOC");
				strcpy(frame_name, "(management)IEEE80211_TYPE_DISASSOC");
				break;
			case IEEE80211_TYPE_DEAUTH:
				fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->(management)IEEE80211_TYPE_DEAUTH");
				strcpy(frame_name, "(management)IEEE80211_TYPE_DEAUTH");
				break;
			case IEEE80211_TYPE_ACTION:
				fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->(management)IEEE80211_TYPE_ACTION");
				strcpy(frame_name, "(management)IEEE80211_TYPE_ACTION");
				break;
			case IEEE80211_TYPE_ACTIONNOACK:
				fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->(management)IEEE80211_TYPE_ACTIONNOACK");
				strcpy(frame_name, "(management)IEEE80211_TYPE_ACTIONNOACK");
				break;
			case IEEE80211_TYPE_ASSOCREQ:    // STA
				fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->(management)IEEE80211_TYPE_ASSOCREQ");
				strcpy(frame_name, "(management)IEEE80211_TYPE_ASSOCREQ");
				break;
			case IEEE80211_TYPE_REASSOCREQ:
				fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->(management)IEEE80211_TYPE_REASSOCREQ");
				strcpy(frame_name, "(management)IEEE80211_TYPE_REASSOCREQ");
				break;
			case IEEE80211_TYPE_PROBEREQ:
				fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->(management)IEEE80211_TYPE_PROBEREQ");
				strcpy(frame_name, "(management)IEEE80211_TYPE_PROBEREQ");
				break;
			case IEEE80211_TYPE_AUTH:
				fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->(management)IEEE80211_TYPE_AUTH");
				strcpy(frame_name, "(management)IEEE80211_TYPE_AUTH");
				break;

			// control addr1,(addr2)
			case IEEE80211_TYPE_BEAMFORMING:
				fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->(control)IEEE80211_TYPE_BEAMFORMING");
				strcpy(frame_name, ">(control)IEEE80211_TYPE_BEAMFORMING");
				break;
			case IEEE80211_TYPE_VHT:
				fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->(control)IEEE80211_TYPE_VHT");
				strcpy(frame_name, "(control)IEEE80211_TYPE_VHT");
				break;
			case IEEE80211_TYPE_CTRLFRMEXT:
				fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->(control)IEEE80211_TYPE_CTRLFRMEXT");
				strcpy(frame_name, "(control)IEEE80211_TYPE_CTRLFRMEXT");
				break;
			case IEEE80211_TYPE_CTRLWRAP:
				fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->(control)IEEE80211_TYPE_CTRLWRAP");
				strcpy(frame_name, "(control)IEEE80211_TYPE_CTRLWRAP");
				break;
			case IEEE80211_TYPE_BLOCKACKREQ:
				fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->(control)IEEE80211_TYPE_BLOCKACKREQ");
				strcpy(frame_name, "(control)IEEE80211_TYPE_BLOCKACKREQ");
				break;
			case IEEE80211_TYPE_BLOCKACK:
				fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->(control)IEEE80211_TYPE_BLOCKACK");
				strcpy(frame_name, "(control)IEEE80211_TYPE_BLOCKACK");
				break;
			case IEEE80211_TYPE_PSPOLL:
				fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->(control)IEEE80211_TYPE_PSPOLL");
				strcpy(frame_name, "(control)IEEE80211_TYPE_PSPOLL");
				break;
			case IEEE80211_TYPE_RTS:
				fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->(control)IEEE80211_TYPE_RTS");
				strcpy(frame_name, "(control)IEEE80211_TYPE_RTS");
				break;
			case IEEE80211_TYPE_CTS:
				fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->(control)IEEE80211_TYPE_CTS");
				strcpy(frame_name, "(control)IEEE80211_TYPE_CTS");
				break;
			case IEEE80211_TYPE_ACK:
				fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->(control)IEEE80211_TYPE_ACK");
				strcpy(frame_name, "(control)IEEE80211_TYPE_ACK");
				break;
			case IEEE80211_TYPE_CFEND:
				fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->(control)IEEE80211_TYPE_CFEND");
				strcpy(frame_name, "(control)IEEE80211_TYPE_CFEND");
				break;
			case IEEE80211_TYPE_CFENDACK:
				fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->(control)IEEE80211_TYPE_CFENDACK");
				strcpy(frame_name, "(control)IEEE80211_TYPE_CFENDACK");
				break;

			// data addr1,addr2,addr3,(addr4)
			case IEEE80211_TYPE_DATA:
				fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->(data)IEEE80211_TYPE_DATA");
				strcpy(frame_name, "(data)IEEE80211_TYPE_DATA");
				break;
			case IEEE80211_TYPE_DATACFACK:
				fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->(data)IEEE80211_TYPE_DATACFACK");
				strcpy(frame_name, "(data)IEEE80211_TYPE_DATACFACK");
				break;
			case IEEE80211_TYPE_DATACFPOLL:
				fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->(data)IEEE80211_TYPE_DATACFPOLL");
				strcpy(frame_name, "(data)IEEE80211_TYPE_DATACFPOLL");
				break;
			case IEEE80211_TYPE_DATACFACKPOLL:
				fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->(data)IEEE80211_TYPE_DATACFACKPOLL");
				strcpy(frame_name, "(data)IEEE80211_TYPE_DATACFACKPOLL");
				break;
			case IEEE80211_TYPE_NULL:
				fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->(data)IEEE80211_TYPE_NULL");
				strcpy(frame_name, "(data)IEEE80211_TYPE_NULL");
				break;
			case IEEE80211_TYPE_CFACK:
				fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->(data)IEEE80211_TYPE_CFACK");
				strcpy(frame_name, "(data)IEEE80211_TYPE_CFACK");
				break;
			case IEEE80211_TYPE_CFPOLL:
				fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->(data)IEEE80211_TYPE_CFPOLL");
				strcpy(frame_name, "(data)IEEE80211_TYPE_CFPOLL");
				break;
			case IEEE80211_TYPE_CFACKPOLL:
				fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->(data)IEEE80211_TYPE_CFACKPOLL");
				strcpy(frame_name, "(data)IEEE80211_TYPE_CFACKPOLL");
				break;
			case IEEE80211_TYPE_QOSDATA:
				fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->(data)IEEE80211_TYPE_QOSDATA");
				strcpy(frame_name, "(data)IEEE80211_TYPE_QOSDATA");
				break;
			case IEEE80211_TYPE_QOSDATACFACK:
				fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->(data)IEEE80211_TYPE_QOSDATACFACK");
				strcpy(frame_name, "(data)IEEE80211_TYPE_QOSDATACFACK");
				break;
			case IEEE80211_TYPE_QOSDATACFPOLL:
				fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->(data)IEEE80211_TYPE_QOSDATACFPOLL");
				strcpy(frame_name, "(data)IEEE80211_TYPE_QOSDATACFPOLL");
				break;
			case IEEE80211_TYPE_QOSDATACFACKPOLL:
				fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->(data)IEEE80211_TYPE_QOSDATACFACKPOLL");
				strcpy(frame_name, "(data)IEEE80211_TYPE_QOSDATACFACKPOLL");
				break;
			case IEEE80211_TYPE_QOSNULL:
				fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->(data)IEEE80211_TYPE_QOSNULL");
				strcpy(frame_name, "(data)IEEE80211_TYPE_QOSNULL");
				break;
			case IEEE80211_TYPE_QOSCFPOLL:
				fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->(data)IEEE80211_TYPE_QOSCFPOLL");
				strcpy(frame_name, "(data)IEEE80211_TYPE_QOSCFPOLL");
				break;
			case IEEE80211_TYPE_QOSCFACKPOLL:
				fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->(data)IEEE80211_TYPE_QOSCFACKPOLL");
				strcpy(frame_name, "(data)IEEE80211_TYPE_QOSCFACKPOLL");
				break;

			// extension
			case IEEE80211_TYPE_DMGBEACON:
				fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->(extension)IEEE80211_TYPE_DMGBEACON");
				strcpy(frame_name, "(extension)IEEE80211_TYPE_DMGBEACON");
				break;
			default:
				fuzz_logger_log(FUZZ_LOG_DEBUG, "recv-->unknown frame!!!");
				strcpy(frame_name, "unknown frame");
				break;
		}

		if(fuzzing_opt->fuzz_work_mode != FUZZ_WORK_MODE_MITM)
		{
			if(!check_alive_by_pkts(smac) && fuzzing_opt->target_alive == 1){
				save_exp_payload(&fuzzing_opt->fuzz_pkt);
				log_pkt(FUZZ_LOG_ERR, &fuzzing_opt->fuzz_pkt);
				fuzzing_opt->target_alive = 0;
				fuzzing_opt->last_recv_pkt_time = 0;

				fuzz_logger_log(FUZZ_LOG_INFO, "\t\033[22;31mTarget [%02X:%02X:%02X:%02X:%02X:%02X] is dead...\033[22;39m\n", 
					fuzzing_opt->target_addr.ether_addr_octet[0],
					fuzzing_opt->target_addr.ether_addr_octet[1],
					fuzzing_opt->target_addr.ether_addr_octet[2],
					fuzzing_opt->target_addr.ether_addr_octet[3],
					fuzzing_opt->target_addr.ether_addr_octet[4],
					fuzzing_opt->target_addr.ether_addr_octet[5]
					);
				
				if(fuzzing_opt->test_type == 3)
				{
					fuzzing_opt->p2p_frame_test = 0;
					owfuzz_config_get_channels(fuzzing_opt);
					owfuzz_config_get_macs(fuzzing_opt);
					kismet_set_channel(fuzzing_opt->ois[fuzzing_opt->p2p_operating_interface_id].osdep_iface_out, fuzzing_opt->ois[fuzzing_opt->p2p_operating_interface_id].channel, szerr);
					fuzzing_opt->target_alive = 1;
				}	
				//sleep(2);

				while(fuzzing_opt->enable_check_alive && !check_alive_by_ping())
				{
					sleep(1);
				}
			}
		}

		if((memcmp(&dmac.ether_addr_octet,&fuzzing_opt->source_addr.ether_addr_octet, 6) == 0 || memcmp(&dmac.ether_addr_octet,&fuzzing_opt->target_addr.ether_addr_octet, 6) == 0) ||
		(memcmp(&smac.ether_addr_octet,&fuzzing_opt->source_addr.ether_addr_octet, 6) == 0 || memcmp(&smac.ether_addr_octet,&fuzzing_opt->target_addr.ether_addr_octet, 6) == 0))
		{
			if(pkt.channel == fuzzing_opt->mitm_ap_channel)
				fuzz_logger_log(FUZZ_LOG_DEBUG, "channel: %d ==> pkt.len = %d, owq size: %d frame type: %02X-%s, smac %02X:%02X:%02X:%02X:%02X:%02X, dmac %02X:%02X:%02X:%02X:%02X:%02X, bssid %02X:%02X:%02X:%02X:%02X:%02X, sent pkt num -> %d", 
				pkt.channel, pkt.len, owq.size, hdr->type, frame_name, 
				smac.ether_addr_octet[0],smac.ether_addr_octet[1],smac.ether_addr_octet[2],smac.ether_addr_octet[3],smac.ether_addr_octet[4],smac.ether_addr_octet[5],
				dmac.ether_addr_octet[0],dmac.ether_addr_octet[1],dmac.ether_addr_octet[2],dmac.ether_addr_octet[3],dmac.ether_addr_octet[4],dmac.ether_addr_octet[5],
				bssid.ether_addr_octet[0],bssid.ether_addr_octet[1],bssid.ether_addr_octet[2],bssid.ether_addr_octet[3],bssid.ether_addr_octet[4],bssid.ether_addr_octet[5], fuzzing_opt->fuzz_pkt_num);

			gettimeofday(&tv2,NULL);
			current_time2 = tv2.tv_sec*1000 + tv2.tv_usec/1000;
			fuzz_current_time2 = tv2.tv_sec*1000 + tv2.tv_usec/1000;


			if(current_time2 - pass_time2 >= 100)
			{
				if(fuzzing_opt->test_type == 1)
				{
					if(fuzzing_opt->fuzz_work_mode == FUZZ_WORK_MODE_AP)
					{
						// ap
						fuzz_pkt = get_default_frame(IEEE80211_TYPE_BEACON, fuzzing_opt->source_addr, fuzzing_opt->source_addr, SE_BROADCASTMAC, NULL);
						send_packet_ex(&fuzz_pkt);
					}
					else if(fuzzing_opt->fuzz_work_mode == FUZZ_WORK_MODE_STA){
			
					}
				}

				if(fuzzing_opt->fuzz_work_mode == FUZZ_WORK_MODE_MITM)
				{
					if(fuzzing_opt->mitm_state >= 1)
					{
						//send_packet_ex(&fuzzing_opt->mitm_ap_bcn);
					}
				}

				pass_time2 = current_time2;
			}
				
			if((memcmp(&dmac.ether_addr_octet,&fuzzing_opt->target_addr.ether_addr_octet, 6) == 0 && memcmp(&smac.ether_addr_octet,&fuzzing_opt->source_addr.ether_addr_octet, 6) == 0 ) ||
			(memcmp(&dmac.ether_addr_octet,&fuzzing_opt->source_addr.ether_addr_octet, 6) == 0 && memcmp(&smac.ether_addr_octet,&fuzzing_opt->target_addr.ether_addr_octet, 6) == 0))
			{
				if(!check_alive_by_deauth(&pkt)){
					save_exp_payload(&fuzzing_opt->fuzz_pkt);
					log_pkt(FUZZ_LOG_ERR, &fuzzing_opt->fuzz_pkt);
					//fuzzing_opt->target_alive = 0;
					fuzz_logger_log(FUZZ_LOG_INFO, "\t\033[22;31mTarget WiFi is disconnected(Deauth/Disassoc Dos from %02X:%02X:%02X:%02X:%02X:%02X)\033[22;39m\n", 
						smac.ether_addr_octet[0],
						smac.ether_addr_octet[1],
						smac.ether_addr_octet[2],
						smac.ether_addr_octet[3],
						smac.ether_addr_octet[4],
						smac.ether_addr_octet[5]);

					if(fuzzing_opt->fuzz_work_mode == FUZZ_WORK_MODE_MITM)
					{
						fuzzing_opt->mitm_state = 0;
					}

					while(fuzzing_opt->enable_check_alive && !check_alive_by_ping())
					{
						sleep(1);
					}
				}
			}

			if(FUZZ_WORK_MODE_MITM == fuzzing_opt->fuzz_work_mode){
				handle_mitm(&pkt, bssid, smac, dmac, fuzzing_opt);
			}

			if(memcmp(&smac.ether_addr_octet,&fuzzing_opt->source_addr.ether_addr_octet, 6) == 0 && memcmp(&dmac.ether_addr_octet,&fuzzing_opt->target_addr.ether_addr_octet, 6) == 0)  // source(fuzzer) packet seq number
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


				if(FUZZ_WORK_MODE_AP == fuzzing_opt->fuzz_work_mode)
				{
					if(is_p2p_frame(&pkt) || is_awdl_frame(&pkt))
					{
						handle_sta_auth(&pkt,bssid, smac, dmac, fuzzing_opt);
					}
				}
				else if(FUZZ_WORK_MODE_STA == fuzzing_opt->fuzz_work_mode)
				{
					if(is_p2p_frame(&pkt) || is_awdl_frame(&pkt))
					{
						handle_ap_auth(&pkt,bssid, smac, dmac, fuzzing_opt);
					}
				}
				/*else if(FUZZ_WORK_MODE_MITM == fuzzing_opt->fuzz_work_mode)
				{
					handle_mitm(&pkt, bssid, smac, dmac, fuzzing_opt);
				}*/
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
				fuzzing_opt->target_alive = 1;

				if(FUZZ_WORK_MODE_AP == fuzzing_opt->fuzz_work_mode){
					handle_sta_auth(&pkt,bssid, smac, dmac, fuzzing_opt);
				}else if(FUZZ_WORK_MODE_STA == fuzzing_opt->fuzz_work_mode){
					handle_ap_auth(&pkt,bssid, smac, dmac, fuzzing_opt);
				}/*else if(FUZZ_WORK_MODE_MITM == fuzzing_opt->fuzz_work_mode){
					handle_mitm(&pkt, bssid, smac, dmac, fuzzing_opt);
				}*/

			}

			if(fuzzing_opt->fuzz_work_mode != FUZZ_WORK_MODE_MITM)
			{
				if(fuzz_current_time2 - fuzz_pass_time2 >= 20)
				{
					if(fuzzing_opt->test_type == 2)
					{
						if(frame_idx >= frame_array_size)
							frame_idx = 0;


						fuzz_logger_log(FUZZ_LOG_DEBUG, "fuzzing frame idx: %d", frame_idx);

						memset(&fuzz_pkt, 0, sizeof(fuzz_pkt));

						fuzz_pkt = get_frame(fuzz_frames[frame_idx], fuzzing_opt->bssid, fuzzing_opt->source_addr, fuzzing_opt->target_addr, NULL);
						fuzz_pkt.channel = fuzzing_opt->ois[0].channel;
						fuzzing_opt->fuzz_pkt = fuzz_pkt;

						send_packet_ex(&fuzz_pkt);

						print_status(NULL);
						

						frame_idx++;
					}
					else if(fuzzing_opt->test_type == 3 && fuzzing_opt->p2p_frame_test == 1)
					{
						if(frame_idx >= (sizeof(p2p_frames) / sizeof(p2p_frames[0])))
							frame_idx = 0;

						fuzz_logger_log(FUZZ_LOG_DEBUG, "fuzzing p2p frame idx: %d", frame_idx);
						memset(&fuzz_pkt, 0, sizeof(fuzz_pkt));

						fuzz_pkt = get_p2p_frame(p2p_frames[frame_idx], fuzzing_opt->p2p_bssid, fuzzing_opt->p2p_source_addr, fuzzing_opt->p2p_target_addr, NULL);
						fuzz_pkt.channel = fuzzing_opt->ois[fuzzing_opt->p2p_operating_interface_id].channel;
						fuzzing_opt->fuzz_pkt = fuzz_pkt;

						send_packet_ex(&fuzz_pkt);
						
						frame_idx++;
					}

					fuzz_pass_time2 = fuzz_current_time2;
				}
			}
		}
	}

	pthread_exit(NULL);
}

void load_payloads()
{
	FILE *fp = NULL;
	int i=0;
	char str_line[8192] = {0};
	char owfuzz_path[256]={0};
	char *ptr;

	if(readlink("/proc/self/exe", owfuzz_path,sizeof(owfuzz_path)) <= 0)
		return;
    
	ptr = strrchr(owfuzz_path, '/');
	if(!ptr)
		return;

	ptr[1] = '\0';
	strcat(owfuzz_path, "poc.txt");

	fp = fopen(owfuzz_path, "r");
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
			if(str_line[0] != '#')
			{
				bad_frame[i].len = str_to_hex(str_line, bad_frame[i].data, sizeof(bad_frame[i].data));
				i++;
			}
		}
	}

	fclose(fp);
	fuzz_logger_log(FUZZ_LOG_INFO, "load %d pocs.\n", i);
}

void save_exp_payload(struct packet *pkt)
{
	int fd = -1;
	int len = 0;
	char owfuzz_path[256]={0};
	char buf[MAX_PRINT_BUF_LEN*5] = {0};
	char *ptr;

	if(!pkt || !pkt->len || (pkt->len * 4 > MAX_PRINT_BUF_LEN))
		return; 
	if(readlink("/proc/self/exe", owfuzz_path,sizeof(owfuzz_path)) <= 0)
		return;
    
	ptr = strrchr(owfuzz_path, '/');
	if(!ptr)
		return;

	ptr[1] = '\0';
	strcat(owfuzz_path, "poc_log.txt");

	fuzzing_opt.fuzz_exp_pkt_cnt++;

	write_pcap(pkt->data, pkt->len);

	fd = open(owfuzz_path, O_RDWR|O_CREAT|O_APPEND|O_SYNC, 0);
	if(pkt->len){
		hex_to_ascii_hex(pkt->data, buf, pkt->len);
		len = strlen(buf);
		write(fd, buf, len);
		write(fd, "\r\n", 2);
	}
		
	close(fd);
}

void save_packet(struct packet *pkt)
{
	int fd = -1;
	int len = 0;
	char owfuzz_path[256]={0};
	char buf[MAX_PRINT_BUF_LEN*5] = {0};
	char *ptr;

	if(!pkt || !pkt->len || (pkt->len * 4 > MAX_PRINT_BUF_LEN))
		return; 
	if(readlink("/proc/self/exe", owfuzz_path,sizeof(owfuzz_path)) <= 0)
		return;
    
	ptr = strrchr(owfuzz_path, '/');
	if(!ptr)
		return;

	ptr[1] = '\0';
	strcat(owfuzz_path, "fuzzing_pkts.txt");

	//fuzzing_opt.fuzz_exp_pkt_cnt++;

	write_pcap(pkt->data, pkt->len);

	fd = open(owfuzz_path, O_RDWR|O_CREAT|O_APPEND|O_SYNC, 0);
	if(pkt->len){
		hex_to_ascii_hex(pkt->data, buf, pkt->len);
		len = strlen(buf);
		write(fd, buf, len);
		write(fd, "\r\n", 2);
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
	char *source_mac_str = NULL;
	struct ether_addr source_mac;
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

	memset(&fuzzing_opt, 0, sizeof(fuzzing_opt));

	if(argc > 1)
	{
		while ((c = getopt(argc, argv, "m:i:t:s:b:I:c:hS:A:T:l:f")) < 255) {
			switch (c) {
			case 'm':
				fuzz_mode = strdup(optarg);
				strncpy(fuzzing_opt.mode, fuzz_mode, sizeof(fuzzing_opt.mode)-1);
				break;
			case 'i':
				interface = strdup(optarg);
				strncpy(fuzzing_opt.ois[0].osdep_iface_out, interface, sizeof(fuzzing_opt.ois[0].osdep_iface_out)-1);
				fuzzing_opt.ois_cnt = 1;
				strncpy(fuzzing_opt.interface, interface, sizeof(fuzzing_opt.interface)-1);
				break;
			case 't':
				target_mac_str = strdup(optarg);
				strncpy(fuzzing_opt.sztarget_addr, target_mac_str, sizeof(fuzzing_opt.sztarget_addr)-1);
				target_mac = parse_mac(target_mac_str);
				fuzzing_opt.target_addr = target_mac;
				break;
			case 's':
				source_mac_str = strdup(optarg);
				strncpy(fuzzing_opt.szsource_addr, source_mac_str, sizeof(fuzzing_opt.szsource_addr)-1);
				source_mac = parse_mac(source_mac_str);
				fuzzing_opt.source_addr = source_mac;
				break;
			case 'b':
				ap_bssid_str = strdup(optarg);
				strncpy(fuzzing_opt.szbssid, ap_bssid_str, sizeof(fuzzing_opt.szbssid)-1);
				ap_bssid = parse_mac(ap_bssid_str);
				fuzzing_opt.bssid = ap_bssid;
				break;
			case 'c':
				channel_str = strdup(optarg);
				channel = atoi(channel_str);
				fuzzing_opt.ois[0].channel = channel;
				fuzzing_opt.channel = channel;
				break;
			case 'I':
				target_ip = strdup(optarg);
				strncpy(fuzzing_opt.target_ip, target_ip, sizeof(fuzzing_opt.target_ip)-1);
				break;
			case 'h':
				usage_help(argv[0]);
				return -1;
			case 'S':
				target_ssid = strdup(optarg);
				if(strlen(target_ssid)>32)
				{
					fuzz_logger_log(FUZZ_LOG_ERR, "ERROR: target's SSID is too long, limit 32 bytes.");
					usage_help(argv[0]);
					return -1;
				}
				strncpy(fuzzing_opt.target_ssid, target_ssid, sizeof(fuzzing_opt.target_ssid)-1);
				break;
			case 'A':
				auth_type = strdup(optarg);
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
				break;
			case 'T':
				test_type = atoi(strdup(optarg));
				fuzzing_opt.test_type = test_type;
				break;
			case 'l':
				log_level = atoi(strdup(optarg));
				fuzzing_opt.log_level = log_level;
				break;
			case 'f':
				file_log_path = strdup(optarg);
				strncpy(fuzzing_opt.log_file, file_log_path, sizeof(fuzzing_opt.log_file)-1);
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

		if(target_mac_str == NULL)
		{
			fuzz_logger_log(FUZZ_LOG_ERR, "no set fuzzing target's MAC.");
			usage_help(argv[0]);
			return -1;
		}

		if(source_mac_str == NULL)
		{
			fuzz_logger_log(FUZZ_LOG_ERR, "no set fuzzing source MAC address.");
			usage_help(argv[0]);
			return -1;
		}

		if(ap_bssid_str == NULL)
		{
			fuzz_logger_log(FUZZ_LOG_ERR, "no set bssid.");
			usage_help(argv[0]);
			return -1;
		}

		if(auth_type == NULL)
		{
			fuzz_logger_log(FUZZ_LOG_ERR, "no set fuzzing target's auth type.");
			usage_help(argv[0]);
			return -1;
		}

		if(test_type > 3)
		{
			fuzz_logger_log(FUZZ_LOG_ERR, "Test type is error: %s", test_type);
			usage_help(argv[0]);
			return -1;
		}

		if(target_ip)
		{
			if(inet_addr(target_ip) == INADDR_NONE)
			{
				fuzz_logger_log(FUZZ_LOG_ERR, "Target's IP is error: %s", target_ip);
				usage_help(argv[0]);
				return -1;
			}
		}

		if(fuzz_mode == NULL)
		{
			fuzz_mode = AP_MODE;
			strncpy(fuzzing_opt.mode, fuzz_mode, sizeof(fuzzing_opt.mode)-1);
		}

		if(channel_str == NULL)
		{
			channel_str = "1";
			channel = 1;

			fuzzing_opt.ois[1].channel = channel;
			fuzzing_opt.channel = channel;
		}

		if(test_type == -1)
		{
			test_type = 1;
			fuzzing_opt.test_type = test_type;

		}

		if(log_level != -1)
		{
			fuzzing_opt.log_level = log_level;
		}
		else
		{
			fuzzing_opt.log_level = FUZZ_LOG_INFO;
		}
		
		if(strcmp(fuzzing_opt.mode, STA_MODE) == 0)
		{
			fuzzing_opt.fuzz_work_mode = FUZZ_WORK_MODE_STA;
		}
		else if(strcmp(fuzzing_opt.mode, AP_MODE) == 0)
		{
			fuzzing_opt.fuzz_work_mode = FUZZ_WORK_MODE_AP;
		}
		else if(strcmp(fuzzing_opt.mode, MITM_MODE) == 0)
		{
			fuzzing_opt.fuzz_work_mode = FUZZ_WORK_MODE_MITM;
		}
	}
	else
	{
		owfuzz_config_get_fuzzing_option(&fuzzing_opt);
		owfuzz_config_get_interfaces(&fuzzing_opt);
	}

	if(strcmp(fuzzing_opt.mode, AP_MODE) != 0 && strcmp(fuzzing_opt.mode, STA_MODE) != 0 && strcmp(fuzzing_opt.mode, MITM_MODE) != 0)
	{
		fuzz_logger_log(FUZZ_LOG_ERR, "fuzzing mode: %s error.", fuzzing_opt.mode);
		usage_help(argv[0]);
		return -1;
	}

	if(fuzzing_opt.fuzz_work_mode == FUZZ_WORK_MODE_MITM || fuzzing_opt.fuzz_work_mode == FUZZ_WORK_MODE_STA)
	{
		if(strlen(fuzzing_opt.target_ssid) == 0)
		{
			fuzz_logger_log(FUZZ_LOG_ERR, "ERROR: No set target's SSID!");
			usage_help(argv[0]);
			return -1;
		}

		if(fuzzing_opt.fuzz_work_mode == FUZZ_WORK_MODE_MITM)
		{
			fuzzing_opt.mitm_ap_channel = fuzzing_opt.ois[1].channel;
		}
	}
	else if(fuzzing_opt.fuzz_work_mode == FUZZ_WORK_MODE_AP)
	{
		if(strlen(fuzzing_opt.target_ssid) == 0)
		{
			strncpy(fuzzing_opt.target_ssid, "owfuzz", sizeof(fuzzing_opt.target_ssid)-1);
		}
	}

	int i;
	for(i=0; i< fuzzing_opt.ois_cnt; i++)
	{
		fuzz_logger_log(FUZZ_LOG_INFO, "Interface: %s, channel: %d", fuzzing_opt.ois[i].osdep_iface_out, fuzzing_opt.ois[i].channel);
	}

	fuzz_logger_log(FUZZ_LOG_INFO, "Fuzzing mode: %s", fuzzing_opt.mode);
	fuzz_logger_log(FUZZ_LOG_INFO, "Target mac: %02X:%02X:%02X:%02X:%02X:%02X", 
													fuzzing_opt.target_addr.ether_addr_octet[0],
													fuzzing_opt.target_addr.ether_addr_octet[1],
													fuzzing_opt.target_addr.ether_addr_octet[2],
													fuzzing_opt.target_addr.ether_addr_octet[3],
													fuzzing_opt.target_addr.ether_addr_octet[4],
													fuzzing_opt.target_addr.ether_addr_octet[5]);

	fuzz_logger_log(FUZZ_LOG_INFO, "Source mac: %02X:%02X:%02X:%02X:%02X:%02X", 
												fuzzing_opt.source_addr.ether_addr_octet[0],
												fuzzing_opt.source_addr.ether_addr_octet[1],
												fuzzing_opt.source_addr.ether_addr_octet[2],
												fuzzing_opt.source_addr.ether_addr_octet[3],
												fuzzing_opt.source_addr.ether_addr_octet[4],
												fuzzing_opt.source_addr.ether_addr_octet[5]);

	fuzz_logger_log(FUZZ_LOG_INFO, "Bssid: %02X:%02X:%02X:%02X:%02X:%02X", 
												fuzzing_opt.bssid.ether_addr_octet[0],
												fuzzing_opt.bssid.ether_addr_octet[1],
												fuzzing_opt.bssid.ether_addr_octet[2],
												fuzzing_opt.bssid.ether_addr_octet[3],
												fuzzing_opt.bssid.ether_addr_octet[4],
												fuzzing_opt.bssid.ether_addr_octet[5]);

	fuzz_logger_log(FUZZ_LOG_INFO,"Fuzzing target's SSID: %s", fuzzing_opt.target_ssid);
	fuzz_logger_log(FUZZ_LOG_INFO,"auth_type: %d", fuzzing_opt.auth_type);
	fuzz_logger_log(FUZZ_LOG_INFO,"test_type: %d", fuzzing_opt.test_type);

	init_ex();

	fuzz_logger_init(fuzzing_opt.log_level, fuzzing_opt.log_file);

	if(strlen(fuzzing_opt.target_ip))
	{
		fuzzing_opt.enable_check_alive = 1;
		init_ping_sock(&fuzzing_opt);
	}

	if(fuzzing_opt.test_type == 1){
		fuzzing_opt.wpa_s = WPA_DISCONNECTED;
	}else{
		fuzzing_opt.wpa_s = WPA_COMPLETED;
	}
	
	fuzzing_opt.target_alive = 1;
	fuzzing_opt.p2p_frame_test = 0;

	if(fuzzing_opt.test_type == 0)
	{
		if((tid = pthread_create(&fthread, NULL, test_bad_frame, &fuzzing_opt)) != 0)
		{
			fuzz_logger_log(FUZZ_LOG_ERR, "Create test_bad_frame thread failed.");
			return -1;
		}
	}

	start_fuzzing(&fuzzing_opt);

	//close_pcap();
	
	return 0;

}

void print_status(struct packet *pkt)
{
	int i;
	char szerr[256] = {0};

	printf("\033c");
	printf("\033[0;0H");
	printf("\t\t\t\t\t\t\t\n");
	printf("\t\t\t\033[22;33mWiFi(IEEE802.11) Protocol Fuzzing Test\033[22;39m\n");
	printf("__________________________________________________________________________________________\n\n");
	for(i=0; i<fuzzing_opt.ois_cnt;i++){
		printf("\tInterface: %s\t\tWorking Channel: %d\n", fuzzing_opt.ois[i].osdep_iface_out, fuzzing_opt.ois[i].channel);
	}
	
	printf("\tTarget MAC: %02X:%02X:%02X:%02X:%02X:%02X\t\tFuzzing MAC: %02X:%02X:%02X:%02X:%02X:%02X\n", fuzzing_opt.target_addr.ether_addr_octet[0],fuzzing_opt.target_addr.ether_addr_octet[1],
						fuzzing_opt.target_addr.ether_addr_octet[2],fuzzing_opt.target_addr.ether_addr_octet[3],fuzzing_opt.target_addr.ether_addr_octet[4],fuzzing_opt.target_addr.ether_addr_octet[5],
						fuzzing_opt.source_addr.ether_addr_octet[0],fuzzing_opt.source_addr.ether_addr_octet[1],
						fuzzing_opt.source_addr.ether_addr_octet[2],fuzzing_opt.source_addr.ether_addr_octet[3],fuzzing_opt.source_addr.ether_addr_octet[4],fuzzing_opt.source_addr.ether_addr_octet[5]);
	printf("\tBSSID: %02X:%02X:%02X:%02X:%02X:%02X\t\tFuzzing Mode: %s\n", fuzzing_opt.bssid.ether_addr_octet[0],fuzzing_opt.bssid.ether_addr_octet[1],
						fuzzing_opt.bssid.ether_addr_octet[2],fuzzing_opt.bssid.ether_addr_octet[3],fuzzing_opt.bssid.ether_addr_octet[4],fuzzing_opt.bssid.ether_addr_octet[5],fuzzing_opt.mode);
	
	if((fuzzing_opt.test_type == 3) && fuzzing_opt.p2p_frame_test)
	{
		// p2p
		printf("\t*p2p_target_addr: %02X:%02X:%02X:%02X:%02X:%02X\n", fuzzing_opt.p2p_target_addr.ether_addr_octet[0],
		fuzzing_opt.p2p_target_addr.ether_addr_octet[1],
		fuzzing_opt.p2p_target_addr.ether_addr_octet[2],
		fuzzing_opt.p2p_target_addr.ether_addr_octet[3],
		fuzzing_opt.p2p_target_addr.ether_addr_octet[4],
		fuzzing_opt.p2p_target_addr.ether_addr_octet[5]);

		printf("\t*p2p_source_addr: %02X:%02X:%02X:%02X:%02X:%02X\n", fuzzing_opt.p2p_source_addr.ether_addr_octet[0],
		fuzzing_opt.p2p_source_addr.ether_addr_octet[1],
		fuzzing_opt.p2p_source_addr.ether_addr_octet[2],
		fuzzing_opt.p2p_source_addr.ether_addr_octet[3],
		fuzzing_opt.p2p_source_addr.ether_addr_octet[4],
		fuzzing_opt.p2p_source_addr.ether_addr_octet[5]);

		printf("\t*p2p_bssid: %02X:%02X:%02X:%02X:%02X:%02X\n", fuzzing_opt.p2p_bssid.ether_addr_octet[0],
		fuzzing_opt.p2p_bssid.ether_addr_octet[1],
		fuzzing_opt.p2p_bssid.ether_addr_octet[2],
		fuzzing_opt.p2p_bssid.ether_addr_octet[3],
		fuzzing_opt.p2p_bssid.ether_addr_octet[4],
		fuzzing_opt.p2p_bssid.ether_addr_octet[5]);

		printf("\t*p2p_operating_interface_id: %d\n", fuzzing_opt.p2p_operating_interface_id);
	}


	if(fuzzing_opt.test_type == 3)
	{
		printf("\tFuzzing Type: %d (p2p frame testing)\t\tFrame types: %d\n", fuzzing_opt.test_type, sizeof(p2p_frames)/sizeof(p2p_frames[0]));
	}
	else if(fuzzing_opt.test_type == 1)
	{
		printf("\tFuzzing Type: %d (Interactive)\n", fuzzing_opt.test_type);
	}
	else if(fuzzing_opt.test_type == 2)
	{
		printf("\tFuzzing Type: %d (Frame testing)\t\tFrame types: %d\n", fuzzing_opt.test_type, fuzzing_opt.owfuzz_frames_cnt);
	}

	printf("\tAP SSID: %s\t\t\t", fuzzing_opt.target_ssid);

	if(strlen(fuzzing_opt.target_ip))
	{
		printf("\tTarget IP: %s\n", fuzzing_opt.target_ip);
	}
	else
	{
		printf("\n");
	}


	printf("\tFuzzing Frame Count: %lu\t\tPoC Count: \033[22;31m%lu\033[22;39m\n", fuzzing_opt.fuzz_pkt_num, fuzzing_opt.fuzz_exp_pkt_cnt);

	if(pkt){
		if(!check_alive_by_deauth(pkt)){
			save_exp_payload(&fuzzing_opt.fuzz_pkt);
			log_pkt(FUZZ_LOG_ERR, &fuzzing_opt.fuzz_pkt);
			
			printf("\t\033[22;31mTarget WiFi is disconnected(Deauth/Disassoc Dos)...\033[22;39m\n");
			printf("__________________________________________________________________________________________\n");
		    printf("\033[?25l");

			if(fuzzing_opt.enable_check_alive){
				while(!check_alive_by_ping())
				{
					sleep(1);
				}
			}
			else{
				sleep(5);
			}

		}
	}

	if(fuzzing_opt.enable_check_alive){
		if(!check_alive_by_ping()){
			save_exp_payload(&fuzzing_opt.fuzz_pkt);
			log_pkt(FUZZ_LOG_ERR, &fuzzing_opt.fuzz_pkt);
			fuzzing_opt.target_alive = 0;
			printf("\t\033[22;31mTarget's network is disconnected...\033[22;39m\n");
			printf("__________________________________________________________________________________________\n");
			printf("\033[?25l");
			
			//sleep(5);
			while(!check_alive_by_ping())
			{
				sleep(1);
			}
		}
	}

	if(!fuzzing_opt.target_alive){
		fuzzing_opt.target_alive = 1;
		
	}
	else{
		printf("__________________________________________________________________________________________\n");
		printf("\033[?25l");
	}
}

