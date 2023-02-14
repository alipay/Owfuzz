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
#include <ctype.h>
#include "ieee80211_def.h"
#include "frame.h"
#include "osdep_wifi_transmit.h"
#include "./management/ies_creator.h"
#include "../common/log.h"

extern fuzzing_option fuzzing_opt;

const char *return_frame_type(uint8_t frame_type)
{
	switch (frame_type)
	{
	// management
	case IEEE80211_TYPE_ASSOCRES: // AP
		return "IEEE80211_TYPE_ASSOCRES";
	case IEEE80211_TYPE_REASSOCRES:
		return "IEEE80211_TYPE_REASSOCRES";
	case IEEE80211_TYPE_PROBERES:
		return "IEEE80211_TYPE_PROBERES";
	case IEEE80211_TYPE_TIMADVERT:
		return "IEEE80211_TYPE_TIMADVERT";
	case IEEE80211_TYPE_BEACON:
		return "IEEE80211_TYPE_BEACON";
	case IEEE80211_TYPE_ATIM: // xx
		return "IEEE80211_TYPE_ATIM";
	case IEEE80211_TYPE_DISASSOC:
		return "IEEE80211_TYPE_DISASSOC";
	case IEEE80211_TYPE_DEAUTH:
		return "IEEE80211_TYPE_DEAUTH";
	case IEEE80211_TYPE_ACTION:
		return "IEEE80211_TYPE_ACTION";
	case IEEE80211_TYPE_ACTIONNOACK:
		return "IEEE80211_TYPE_ACTIONNOACK";
	case IEEE80211_TYPE_ASSOCREQ: // STA
		return "IEEE80211_TYPE_ASSOCREQ";
	case IEEE80211_TYPE_REASSOCREQ:
		return "IEEE80211_TYPE_REASSOCREQ";
	case IEEE80211_TYPE_PROBEREQ:
		return "IEEE80211_TYPE_PROBEREQ";
	case IEEE80211_TYPE_AUTH:
		return "IEEE80211_TYPE_AUTH";

	// control
	case IEEE80211_TYPE_ACK:
		return "IEEE80211_TYPE_ACK";
	case IEEE80211_TYPE_BEAMFORMING:
		return "IEEE80211_TYPE_BEAMFORMING";
	case IEEE80211_TYPE_VHT:
		return "IEEE80211_TYPE_VHT";
	case IEEE80211_TYPE_CTRLFRMEXT:
		return "IEEE80211_TYPE_CTRLFRMEXT";
	case IEEE80211_TYPE_CTRLWRAP:
		return "IEEE80211_TYPE_CTRLWRAP";
	case IEEE80211_TYPE_BLOCKACKREQ:
		return "IEEE80211_TYPE_BLOCKACKREQ";
	case IEEE80211_TYPE_BLOCKACK:
		return "IEEE80211_TYPE_BLOCKACK";
	case IEEE80211_TYPE_PSPOLL:
		return "IEEE80211_TYPE_PSPOLL";
	case IEEE80211_TYPE_RTS:
		return "IEEE80211_TYPE_RTS";
	case IEEE80211_TYPE_CTS:
		return "IEEE80211_TYPE_CTS";
	case IEEE80211_TYPE_CFEND:
		return "IEEE80211_TYPE_CFEND";
	case IEEE80211_TYPE_CFENDACK:
		return "IEEE80211_TYPE_CFENDACK";

	// data
	case IEEE80211_TYPE_QOSDATA:
		return "IEEE80211_TYPE_QOSDATA";
	case IEEE80211_TYPE_DATA:
		return "IEEE80211_TYPE_DATA";
	case IEEE80211_TYPE_DATACFACK:
		return "IEEE80211_TYPE_DATACFACK";
	case IEEE80211_TYPE_DATACFPOLL:
		return "IEEE80211_TYPE_DATACFPOLL";
	case IEEE80211_TYPE_DATACFACKPOLL:
		return "IEEE80211_TYPE_DATACFACKPOLL";
	case IEEE80211_TYPE_NULL:
		return "IEEE80211_TYPE_NULL";
	case IEEE80211_TYPE_CFACK:
		return "IEEE80211_TYPE_CFACK";
	case IEEE80211_TYPE_CFPOLL:
		return "IEEE80211_TYPE_CFPOLL";
	case IEEE80211_TYPE_CFACKPOLL:
		return "IEEE80211_TYPE_CFACKPOLL";
	case IEEE80211_TYPE_QOSDATACFACK:
		return "IEEE80211_TYPE_QOSDATACFACK";
	case IEEE80211_TYPE_QOSDATACFPOLL:
		return "IEEE80211_TYPE_QOSDATACFPOLL";
	case IEEE80211_TYPE_QOSDATACFACKPOLL:
		return "IEEE80211_TYPE_QOSDATACFACKPOLL";
	case IEEE80211_TYPE_QOSNULL:
		return "IEEE80211_TYPE_QOSNULL";
	case IEEE80211_TYPE_QOSCFACK:
		return "IEEE80211_TYPE_QOSCFACK";
	case IEEE80211_TYPE_QOSCFPOLL:
		return "IEEE80211_TYPE_QOSCFPOLL";
	case IEEE80211_TYPE_QOSCFACKPOLL:
		return "IEEE80211_TYPE_QOSCFACKPOLL";

	// extension
	case IEEE80211_TYPE_DMGBEACON:
		return "IEEE80211_TYPE_DMGBEACON";
	}

	return "UNKNOWN";
}

/*
	Return a pkt frame - fuzzed
*/
struct packet get_frame(uint8_t frame_type, struct ether_addr bssid, struct ether_addr smac, struct ether_addr dmac, struct packet *recv_pkt)
{
	struct packet pkt = {0};

	// fuzzing_opt.fuzz_pkt_num++;
	if (recv_pkt)
	{
		pkt.channel = recv_pkt->channel;
	}

	fuzzing_opt.current_frame = frame_type;

	// fuzz_logger_log(FUZZ_LOG_INFO, "[%s:%d] frame_type: %x (%s)", __FILE__, __LINE__, frame_type, return_frame_type(frame_type));
	switch (frame_type)
	{
	// management
	case IEEE80211_TYPE_ASSOCRES: // AP
		pkt = create_association_response(bssid, smac, dmac, 0, recv_pkt);
		break;
	case IEEE80211_TYPE_REASSOCRES:
		pkt = create_reassociation_response(bssid, dmac, 0);
		break;
	case IEEE80211_TYPE_PROBERES:
		if (recv_pkt)
			pkt = create_probe_response(bssid, dmac, 0, NULL, recv_pkt->data + sizeof(struct ieee_hdr), recv_pkt->len - sizeof(struct ieee_hdr));
		else
			pkt = create_probe_response(bssid, dmac, 0, NULL, NULL, 0);
		break;
	case IEEE80211_TYPE_TIMADVERT:
		pkt = create_timing_advertisement(bssid, dmac, 0);
		break;
	case IEEE80211_TYPE_BEACON:
		pkt = create_beacon(bssid, 0, NULL);
		break;
	case IEEE80211_TYPE_ATIM: // xx
		pkt = create_atim(bssid, smac, dmac, 0, recv_pkt);
		break;
	case IEEE80211_TYPE_DISASSOC:
		pkt = create_disassociation(bssid, smac, dmac, 0, recv_pkt);
		break;
	case IEEE80211_TYPE_DEAUTH:
		pkt = create_deauthentication(bssid, smac, dmac, 0, recv_pkt);
		break;
	case IEEE80211_TYPE_ACTION:
		pkt = create_action(bssid, smac, dmac, 0, recv_pkt);
		break;
	case IEEE80211_TYPE_ACTIONNOACK:
		pkt = create_action_no_ack(bssid, smac, dmac, 0, recv_pkt);
		break;
	case IEEE80211_TYPE_ASSOCREQ: // STA
		pkt = create_association_request(bssid, smac, dmac, 0, recv_pkt);
		break;
	case IEEE80211_TYPE_REASSOCREQ:
		pkt = create_reassociation_request(bssid, smac, dmac, 0, recv_pkt);
		break;
	case IEEE80211_TYPE_PROBEREQ:
		pkt = create_probe_request(bssid, smac, dmac, 0, recv_pkt);
		break;
	case IEEE80211_TYPE_AUTH:
		pkt = create_authentication(bssid, smac, dmac, 0, recv_pkt);
		break;
	// control
	case IEEE80211_TYPE_ACK:
		pkt = create_ack(dmac);
		break;
	case IEEE80211_TYPE_BEAMFORMING:
		pkt = create_beamforming_report_poll(bssid, smac, dmac);
		break;
	case IEEE80211_TYPE_VHT:
		pkt = create_vht_ndp_announcement(bssid, smac, dmac);
		break;
	case IEEE80211_TYPE_CTRLFRMEXT:
		pkt = create_control_frame_extension(bssid, smac, dmac);
		break;
	case IEEE80211_TYPE_CTRLWRAP:
		pkt = create_control_wrapper(bssid, smac, dmac);
		break;
	case IEEE80211_TYPE_BLOCKACKREQ:
		pkt = create_block_ack_request(bssid, smac, dmac);
		break;
	case IEEE80211_TYPE_BLOCKACK:
		pkt = create_block_ack(bssid, smac, dmac);
		break;
	case IEEE80211_TYPE_PSPOLL:
		pkt = create_ps_poll(bssid, smac, dmac);
		break;
	case IEEE80211_TYPE_RTS:
		pkt = create_rts(bssid, smac, dmac);
		break;
	case IEEE80211_TYPE_CTS:
		pkt = create_cts(bssid, smac, dmac);
		break;
	case IEEE80211_TYPE_CFEND:
		pkt = create_cf_end(bssid, smac, dmac);
		break;
	case IEEE80211_TYPE_CFENDACK:
		pkt = create_cf_end_cf_ack(bssid, smac, dmac);
		break;
	// data
	case IEEE80211_TYPE_QOSDATA:
		pkt = create_qos_data(bssid, smac, dmac, 0, recv_pkt);
		break;
	case IEEE80211_TYPE_DATA:
		pkt = create_data(bssid, smac, dmac, 0, recv_pkt);
		break;
	case IEEE80211_TYPE_DATACFACK:
		pkt = create_data_cf_ack(bssid, smac, dmac, 0, recv_pkt);
		break;
	case IEEE80211_TYPE_DATACFPOLL:
		pkt = create_data_cf_poll(bssid, smac, dmac, 0, recv_pkt);
		break;
	case IEEE80211_TYPE_DATACFACKPOLL:
		pkt = create_data_cf_ack_poll(bssid, smac, dmac, 0, recv_pkt);
		break;
	case IEEE80211_TYPE_NULL:
		pkt = create_data_null(bssid, smac, dmac, 0, recv_pkt);
		break;
	case IEEE80211_TYPE_CFACK:
		pkt = create_d_cf_ack(bssid, smac, dmac, 0, recv_pkt);
		break;
	case IEEE80211_TYPE_CFPOLL:
		pkt = create_d_cf_poll(bssid, smac, dmac, 0, recv_pkt);
		break;
	case IEEE80211_TYPE_CFACKPOLL:
		pkt = create_d_cf_ack_poll(bssid, smac, dmac, 0, recv_pkt);
		break;
	case IEEE80211_TYPE_QOSDATACFACK:
		pkt = create_qos_data_cf_ack(bssid, smac, dmac, 0, recv_pkt);
		break;
	case IEEE80211_TYPE_QOSDATACFPOLL:
		pkt = create_qos_data_cf_poll(bssid, smac, dmac, 0, recv_pkt);
		break;
	case IEEE80211_TYPE_QOSDATACFACKPOLL:
		pkt = create_qos_data_cf_ack_poll(bssid, smac, dmac, 0, recv_pkt);
		break;
	case IEEE80211_TYPE_QOSNULL:
		pkt = create_qos_null(bssid, smac, dmac, 0, recv_pkt);
		break;
	case IEEE80211_TYPE_QOSCFACK:
		pkt = create_qos_cf_ack(bssid, smac, dmac, 0, recv_pkt);
		break;
	case IEEE80211_TYPE_QOSCFPOLL:
		pkt = create_qos_cf_poll(bssid, smac, dmac, 0, recv_pkt);
		break;
	case IEEE80211_TYPE_QOSCFACKPOLL:
		pkt = create_qos_cf_ack_poll(bssid, smac, dmac, 0, recv_pkt);
		break;
	// extension
	case IEEE80211_TYPE_DMGBEACON:
		break;
	default:
		break;
	}

	return pkt;
}

struct packet get_default_frame(uint8_t frame_type, struct ether_addr bssid, struct ether_addr smac, struct ether_addr dmac, struct packet *recv_pkt)
{
	struct packet pkt = {0};
	struct ieee_hdr *hdr;

	switch (frame_type)
	{
	// management
	case IEEE80211_TYPE_ASSOCRES: // AP
		pkt = create_ap_association_response(bssid, smac, dmac, 0);
		break;
	case IEEE80211_TYPE_REASSOCRES:
		// pkt = create_reassociation_response(bssid, dmac, 0);
		break;
	case IEEE80211_TYPE_PROBERES:
		hdr = (struct ieee_hdr *)recv_pkt->data;
		if (hdr->type == IEEE80211_TYPE_PROBEREQ)
		{
			// pkt = create_probe_response(bssid, dmac, 0, NULL, recv_pkt->data + sizeof(struct ieee_hdr), recv_pkt->len - sizeof(struct ieee_hdr));
		}
		break;
	case IEEE80211_TYPE_TIMADVERT:
		// pkt = create_timing_advertisement(bssid, dmac, 0);
		break;
	case IEEE80211_TYPE_BEACON:
		pkt = create_ap_beacon(bssid, 0, fuzzing_opt.auth_type);
		break;
	case IEEE80211_TYPE_ATIM: // xx
		break;
	case IEEE80211_TYPE_DISASSOC:
		// pkt = create_disassociation(bssid, dmac, 0, recv_pkt);
		break;
	case IEEE80211_TYPE_DEAUTH:
		// pkt = create_deauthentication(bssid, dmac, 0, recv_pkt);
		break;
	case IEEE80211_TYPE_ACTION:
		// pkt = create_action(bssid, dmac, 0, recv_pkt);
		break;
	case IEEE80211_TYPE_ACTIONNOACK:
		break;
	case IEEE80211_TYPE_ASSOCREQ: // STA
		break;
	case IEEE80211_TYPE_REASSOCREQ:
		break;
	case IEEE80211_TYPE_PROBEREQ:
		break;
	case IEEE80211_TYPE_AUTH:
		// pkt = create_authentication(bssid, dmac, 0);
		break;
	// control
	// data
	default:
		break;
	}

	return pkt;
}

unsigned short calc_chksum(unsigned short *buff, int len)
{
	int blen = len;
	unsigned short *mid = (unsigned short *)buff;
	unsigned short te = 0;
	unsigned int sum = 0;

	while (blen > 1)
	{
		sum += *mid++;
		blen -= 2;
	}

	if (blen == 1)
	{
		te = *(unsigned char *)mid;
		te = (te << 8) & 0xff;
		sum += te;
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum += sum >> 16;
	return (unsigned short)(~sum);
}

/*
	Prepare the ICMP packet to be sent via the socket
*/
int pack_icmp(uint8_t *buff, int seq)
{
	int packsize = 0;
	struct icmphdr *icmp_h = NULL;
	struct timeval *tval = NULL;

	icmp_h = (struct icmphdr *)buff;
	icmp_h->type = ICMP_ECHO;
	icmp_h->code = 0;
	icmp_h->checksum = 0;

	icmp_h->un.echo.sequence = seq;
	icmp_h->un.echo.id = PING_ECHO_ID;

	packsize = 8 + 8 + 48;
	tval = (struct timeval *)(buff + sizeof(struct icmphdr));

	gettimeofday(tval, NULL);
	memcpy(buff + sizeof(struct icmphdr) + sizeof(struct timeval), PING_ECHO_DATA, PING_ECHO_DATA_LEN);
	icmp_h->checksum = calc_chksum((unsigned short *)buff, packsize);

	return packsize;
}

void tv_sub(struct timeval *out, struct timeval *in)
{
	if ((out->tv_usec -= in->tv_usec) < 0)
	{
		--out->tv_sec;
		out->tv_usec += 1000000;
	}

	out->tv_sec -= in->tv_sec;
}

/*
	Breakdown the ICMP response
*/
int unpack_icmp(uint8_t *buff, int len, struct timeval tvrecv)
{
	int iphdrlen = 0;
	struct iphdr *ip_h = NULL;
	struct icmphdr *icmp_h = NULL;
	struct timeval *tvsend = NULL;
	// double rtt;

	ip_h = (struct iphdr *)buff;
	iphdrlen = ip_h->ihl << 2;
	icmp_h = (struct icmphdr *)(buff + iphdrlen);
	len -= iphdrlen;

	if (len < 8)
	{
		fuzz_logger_log(FUZZ_LOG_DEBUG, "packets\'s length is less than 8");
		return 0;
	}

	if ((icmp_h->type == ICMP_ECHOREPLY) && (icmp_h->un.echo.id == PING_ECHO_ID))
	{
		tvsend = (struct timeval *)((uint8_t *)icmp_h + sizeof(struct icmphdr));
		tv_sub(&tvrecv, tvsend);
		// rtt = tvrecv.tv_sec * 1000 + tvrecv.tv_usec / 1000;

		return 1;
	}

	return 0;
}

/*
	Create a 'ping' socket
	This function tries to create the socket that will be later used, returns -1 if fails
	Set the value of 'ping_sockfd' to the created socket
*/
int init_ping_sock()
{
	int sockfd;
	in_addr_t inaddr = 0;
	int size = 1024;
	struct timeval tv_timeout = {0};

	if (0 != fuzzing_opt.ping_sockfd)
	{
		// If socket was previously openned, close it
		close(fuzzing_opt.ping_sockfd);
		fuzzing_opt.ping_sockfd = 0;
	}

	if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0)
	{
		fuzz_logger_log(FUZZ_LOG_INFO, "socket initialization error, errno = %d", errno);
		return -1;
	}

	tv_timeout.tv_sec = PING_MAX_WAIT_TIME;
	tv_timeout.tv_usec = 0;
	setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv_timeout, sizeof(tv_timeout));
	setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));

	bzero(&fuzzing_opt.ping_dst_addr, sizeof(fuzzing_opt.ping_dst_addr));
	inaddr = inet_addr(fuzzing_opt.target_ip);
	if (inaddr == INADDR_NONE)
	{
		fuzz_logger_log(FUZZ_LOG_INFO, "Unable to resolve Target's IP address");

		// Don't leave behind values
		fuzzing_opt.ping_dst_addr.sin_family = 0;
		fuzzing_opt.ping_dst_addr.sin_addr.s_addr = 0;
		fuzzing_opt.ping_sockfd = 0;

		return -1;
	}

	fuzzing_opt.ping_dst_addr.sin_family = AF_INET;
	fuzzing_opt.ping_dst_addr.sin_addr.s_addr = inaddr;

	fuzzing_opt.ping_sockfd = sockfd;

	return 0;
}

/*
	Perform an ICMP ping to the target IP address
	Returns 0 - target is unreachable (no ICMP reply)
			1 - target is reachable (got ICMP reply)
	Tries every 5s to send an ICMP echo packet
*/
int check_alive_by_ping()
{
	uint8_t sendpacket[PING_PACKET_SIZE] = {0};
	uint8_t recvpacket[PING_PACKET_SIZE] = {0};
	int nsend = 0, nreceived = 0;
	struct sockaddr_in from = {0};
	struct timeval tvrecv = {0};
	int packetsize = 0;
	int n = 0;
	socklen_t fromlen = 0;
	static uint16_t seq = 0;
	int ec = 0;

	if (fuzzing_opt.ping_sockfd <= 0)
	{
		// Socket is not open or invalid
		return 0;
	}

	while (nsend < PING_MAX_NO_PACKETS)
	{
		memset(sendpacket, 0, sizeof(sendpacket));
		packetsize = pack_icmp(sendpacket, seq++);
		if (sendto(fuzzing_opt.ping_sockfd, sendpacket, packetsize, 0, (struct sockaddr *)&fuzzing_opt.ping_dst_addr, sizeof(fuzzing_opt.ping_dst_addr)) <= 0)
		{
			fuzz_logger_log(FUZZ_LOG_INFO, "sendto error, errno = %d", errno);
			continue;
		}

		// dumphex(sendpacket, packetsize);
		nsend++;
		usleep(100);

		memset(recvpacket, 0, sizeof(recvpacket));
		memset(&from, 0, sizeof(from));
		fromlen = sizeof(from);
		if ((n = recvfrom(fuzzing_opt.ping_sockfd, recvpacket, sizeof(recvpacket), 0, (struct sockaddr *)&from, &fromlen)) <= 0)
		{
			fuzz_logger_log(FUZZ_LOG_DEBUG, "recvfrom error, n = %d, errno = %d", n, errno);
			// exit(-1);
		}
		else
		{
			nreceived++;
			gettimeofday(&tvrecv, NULL);
			if (1 == unpack_icmp(recvpacket, n, tvrecv))
			{
				ec++;
				break;
			}
			else
			{
				fuzz_logger_log(FUZZ_LOG_DEBUG, "recvfrom didn't return ICMP reply"); // not ECHO_REPLY
			}
		}

		usleep(5000);
	}

	if (ec)
	{
		// fuzz_logger_log(FUZZ_LOG_DEBUG, "Target is alive");
		return 1;
	}

	fuzz_logger_log(FUZZ_LOG_DEBUG, "Target is dead.");

	return 0;
}

/*
	Determine if a remote device is alive looking for DEAUTH packets
*/
int check_alive_by_deauth(struct packet *pkt)
{
	struct ieee_hdr *hdr;

	hdr = (struct ieee_hdr *)pkt->data;
	if (hdr->type == IEEE80211_TYPE_DEAUTH)
	{
		fuzz_logger_log(FUZZ_LOG_DEBUG, "Deauth Dos!!!.");
		return 0;
	}

	return 1;
}

/*
	Determine if a remote device is alive looking for DISASSOC packets
*/
int check_alive_by_disassoc(struct packet *pkt)
{
	struct ieee_hdr *hdr;

	hdr = (struct ieee_hdr *)pkt->data;
	if (hdr->type == IEEE80211_TYPE_DISASSOC)
	{
		fuzz_logger_log(FUZZ_LOG_DEBUG, "Disassoc Dos!!!.");
		return 0;
	}

	return 1;
}

/*
	Determine if a remote device is alive by examine the time elapsed since last packet
*/
int check_alive_by_pkts(struct ether_addr smac)
{
	time_t current_time = 0;

	if (fuzzing_opt.last_recv_pkt_time == 0)
	{
		return 1;
	}

	// if(MAC_MATCHES(smac, SE_NULLMAC)) return 1;

	if (MAC_MATCHES(smac, fuzzing_opt.target_addr))
	{
		return 1;
	}

	current_time = time(NULL);
	if (current_time - fuzzing_opt.last_recv_pkt_time > CHECK_ALIVE_TIME)
	{
		fuzz_logger_log(FUZZ_LOG_DEBUG, "Target is dead!!!.");
		return 0;
	}

	// fuzzing_opt.target_alive = 1;

	return 1;
}

/*
	Wrapper function to store the fuzzing state (TODO)
*/
void save_fuzzing_state()
{
	save_action_state();
	save_action_no_ack_state();
	save_association_request_state();
	save_association_response_state();
	save_atim_state();
	save_authentication_state();
	save_beacon_state();
	save_deauthentication_state();
	save_disassociation_state();
	save_probe_request_state();
	save_probe_response_state();
	save_reassociation_request_state();
	save_reassociation_response_state();
	save_timing_advertisement_state();
}

/*
	Wrapper function to load the fuzzing state (TODO)
*/
void load_fuzzing_state()
{
	load_action_state();
	load_action_no_ack_state();
	load_association_request_state();
	load_association_response_state();
	load_atim_state();
	load_authentication_state();
	load_beacon_state();
	load_deauthentication_state();
	load_disassociation_state();
	load_probe_request_state();
	load_probe_response_state();
	load_reassociation_request_state();
	load_reassociation_response_state();
	load_timing_advertisement_state();
}

/*
	Convert a provided phex array of length 'len' store it in pascii
	pascii should be of length / 2
*/
void hex_to_ascii(unsigned char *phex, unsigned char *pascii, unsigned int len)
{
	unsigned char nibble[2] = {0};
	unsigned int i = 0, j = 0;

	for (i = 0; i < len; i++)
	{
		nibble[0] = (phex[i] & 0xF0) >> 4;
		nibble[1] = phex[i] & 0x0F;
		for (j = 0; j < 2; j++)
		{
			if (nibble[j] < 10)
			{
				nibble[j] += 0x30;
			}
			else
			{
				if (nibble[j] < 16)
					nibble[j] = nibble[j] - 10 + 'A';
			}
			*pascii++ = nibble[j];
		}
	}
}

/*
	Convert a provided phex of length 'len' to a hex and stores it inside 'pascii'
	in the form of [\xXX], pascii should be length of 2 times phex (len * 2)
*/
void hex_to_ascii_hex(unsigned char *phex, char *pascii, unsigned int len)
{
	unsigned char nibble[2];
	unsigned int i, j;
	for (i = 0; i < len; i++)
	{
		*pascii++ = '\\';
		*pascii++ = 'x';
		nibble[0] = (phex[i] & 0xF0) >> 4;
		nibble[1] = phex[i] & 0x0F;
		for (j = 0; j < 2; j++)
		{
			if (nibble[j] < 10)
			{
				nibble[j] += 0x30;
			}
			else
			{
				if (nibble[j] < 16)
					nibble[j] = nibble[j] - 10 + 'A';
			}
			*pascii++ = nibble[j];
		}
	}
}

int str_to_hex(char *pascii, unsigned char *phex, unsigned int len)
{
	int i = 0;
	int str_len = 0;
	char h1 = 0, h2 = 0;
	unsigned char s1 = 0, s2 = 0;

	if (pascii == NULL || phex == NULL || len == 0)
		return 0;

	str_len = strlen(pascii) / 4;
	if (str_len)
	{
		for (i = 0; i < str_len; i++)
		{
			h1 = pascii[4 * i + 2];
			h2 = pascii[4 * i + 3];

			s1 = toupper(h1) - 0x30;
			if (s1 > 9)
				s1 -= 7;

			s2 = toupper(h2) - 0x30;
			if (s2 > 9)
				s2 -= 7;

			if (i < len)
				phex[i] = s1 * 16 + s2;
		}
	}

	return i;
}

/*
	Log a provided packet
*/
void log_pkt(int log_level, struct packet *pkt)
{
	struct ieee_hdr *hdr = NULL;
	char log_txt[256] = {0};
	int log_txt_len = 0, len = 0;
	char buf[MAX_PRINT_BUF_LEN * 5] = {0};

	if (log_level > fuzzing_opt.log_level)
	{
		return;
	}

	if (pkt->data[0] == 0 || pkt->len <= 0)
	{
		return;
	}

	hdr = (struct ieee_hdr *)pkt->data;
	switch (hdr->type)
	{
	// Management
	case IEEE80211_TYPE_ASSOCRES:
		strcpy(log_txt, "(management)IEEE80211_TYPE_ASSOCRES");
		break;
	case IEEE80211_TYPE_REASSOCRES:
		strcpy(log_txt, "(management)IEEE80211_TYPE_REASSOCRES");
		break;
	case IEEE80211_TYPE_PROBERES:
		strcpy(log_txt, "(management)IEEE80211_TYPE_PROBERES");
		break;
	case IEEE80211_TYPE_TIMADVERT:
		strcpy(log_txt, "(management)IEEE80211_TYPE_TIMADVERT");
		break;
	case IEEE80211_TYPE_BEACON:
		strcpy(log_txt, "(management)IEEE80211_TYPE_BEACON");
		break;
	case IEEE80211_TYPE_ATIM:
		strcpy(log_txt, "(management)IEEE80211_TYPE_ATIM");
		break;
	case IEEE80211_TYPE_DISASSOC:
		strcpy(log_txt, "(management)IEEE80211_TYPE_DISASSOC");
		break;
	case IEEE80211_TYPE_DEAUTH:
		strcpy(log_txt, "(management)IEEE80211_TYPE_DEAUTH");
		break;
	case IEEE80211_TYPE_ACTION:
		strcpy(log_txt, "(management)IEEE80211_TYPE_ACTION");
		break;
	case IEEE80211_TYPE_ACTIONNOACK:
		strcpy(log_txt, "(management)IEEE80211_TYPE_ACTIONNOACK");
		break;
	case IEEE80211_TYPE_ASSOCREQ:
		strcpy(log_txt, "(management)IEEE80211_TYPE_ASSOCREQ");
		break;
	case IEEE80211_TYPE_REASSOCREQ:
		strcpy(log_txt, "(management)IEEE80211_TYPE_REASSOCREQ");
		break;
	case IEEE80211_TYPE_PROBEREQ:
		strcpy(log_txt, "(management)IEEE80211_TYPE_PROBEREQ");
		break;
	case IEEE80211_TYPE_AUTH:
		strcpy(log_txt, "(management)IEEE80211_TYPE_AUTH");
		break;
	// Control
	case IEEE80211_TYPE_BEAMFORMING:
		strcpy(log_txt, "(control)IEEE80211_TYPE_BEAMFORMING");
		break;
	case IEEE80211_TYPE_VHT:
		strcpy(log_txt, "(control)IEEE80211_TYPE_VHT");
		break;
	case IEEE80211_TYPE_CTRLFRMEXT:
		strcpy(log_txt, "(control)IEEE80211_TYPE_CTRLFRMEXT");
		break;
	case IEEE80211_TYPE_CTRLWRAP:
		strcpy(log_txt, "(control)IEEE80211_TYPE_CTRLWRAP");
		break;
	case IEEE80211_TYPE_BLOCKACKREQ:
		strcpy(log_txt, "(control)IEEE80211_TYPE_BLOCKACKREQ");
		break;
	case IEEE80211_TYPE_BLOCKACK:
		strcpy(log_txt, "(control)IEEE80211_TYPE_BLOCKACK");
		break;
	case IEEE80211_TYPE_PSPOLL:
		strcpy(log_txt, "(control)IEEE80211_TYPE_PSPOLL");
		break;
	case IEEE80211_TYPE_RTS:
		strcpy(log_txt, "(control)IEEE80211_TYPE_RTS");
		break;
	case IEEE80211_TYPE_CTS:
		strcpy(log_txt, "(control)IEEE80211_TYPE_CTS");
		break;
	case IEEE80211_TYPE_ACK:
		strcpy(log_txt, "(control)IEEE80211_TYPE_ACK");
		break;
	case IEEE80211_TYPE_CFEND:
		strcpy(log_txt, "(control)IEEE80211_TYPE_CFEND");
		break;
	case IEEE80211_TYPE_CFENDACK:
		strcpy(log_txt, "(control)IEEE80211_TYPE_CFENDACK");
		break;

	// Data
	case IEEE80211_TYPE_DATA:
		strcpy(log_txt, "(data)IEEE80211_TYPE_DATA");
		break;
	case IEEE80211_TYPE_DATACFACK:
		strcpy(log_txt, "(data)IEEE80211_TYPE_DATACFACK");
		break;
	case IEEE80211_TYPE_DATACFPOLL:
		strcpy(log_txt, "(data)IEEE80211_TYPE_DATACFPOLL");
		break;
	case IEEE80211_TYPE_DATACFACKPOLL:
		strcpy(log_txt, "(data)IEEE80211_TYPE_DATACFACKPOLL");
		break;
	case IEEE80211_TYPE_NULL:
		strcpy(log_txt, "(data)IEEE80211_TYPE_NULL");
		break;
	case IEEE80211_TYPE_CFACK:
		strcpy(log_txt, "(data)IEEE80211_TYPE_CFACK");
		break;
	case IEEE80211_TYPE_CFPOLL:
		strcpy(log_txt, "(data)IEEE80211_TYPE_CFPOLL");
		break;
	case IEEE80211_TYPE_CFACKPOLL:
		strcpy(log_txt, "(data)IEEE80211_TYPE_CFACKPOLL");
		break;
	case IEEE80211_TYPE_QOSDATA:
		strcpy(log_txt, "(data)IEEE80211_TYPE_QOSDATA");
		break;
	case IEEE80211_TYPE_QOSDATACFACK:
		strcpy(log_txt, "(data)IEEE80211_TYPE_QOSDATACFACK");
		break;
	case IEEE80211_TYPE_QOSDATACFPOLL:
		strcpy(log_txt, "(data)IEEE80211_TYPE_QOSDATACFPOLL");
		break;
	case IEEE80211_TYPE_QOSDATACFACKPOLL:
		strcpy(log_txt, "(data)IEEE80211_TYPE_QOSDATACFACKPOLL");
		break;
	case IEEE80211_TYPE_QOSNULL:
		strcpy(log_txt, "(data)IEEE80211_TYPE_QOSNULL");
		break;
	case IEEE80211_TYPE_QOSCFACK:
		strcpy(log_txt, "(data)IEEE80211_TYPE_QOSCFACK");
		break;
	case IEEE80211_TYPE_QOSCFPOLL:
		strcpy(log_txt, "(data)IEEE80211_TYPE_QOSCFPOLL");
		break;
	case IEEE80211_TYPE_QOSCFACKPOLL:
		strcpy(log_txt, "(data)IEEE80211_TYPE_QOSCFACKPOLL");
		break;

	// extension
	case IEEE80211_TYPE_DMGBEACON:
		strcpy(log_txt, "(extension)IEEE80211_TYPE_DMGBEACON");
		break;
	default:
		strcpy(log_txt, "(unknown frame)");
		break;
	}

	strcat(log_txt, "-->");
	log_txt_len = strlen(log_txt);

	if (pkt->len > MAX_IEEE_PACKET_SIZE)
	{
		fuzz_logger_log(FUZZ_LOG_INFO, log_txt);
		dumphex(pkt->data, MAX_IEEE_PACKET_SIZE);
	}

	strncpy(buf, log_txt, log_txt_len);

	snprintf(log_txt, sizeof(log_txt), "(%d)", pkt->len);
	len = strlen(log_txt);
	strncat(buf, log_txt, len);

	if (pkt->len)
		hex_to_ascii_hex(pkt->data, buf + log_txt_len + len, pkt->len);

	fuzz_logger_log(FUZZ_LOG_INFO, buf);
}
