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
#include <stdlib.h>
#include <time.h>
#include "80211_packet_common.h"

extern fuzzing_option fuzzing_opt;

static uint16_t seqno = 0;

void create_ieee_hdr(struct packet *pkt, uint8_t type, char dsflags, uint16_t duration, struct ether_addr destination, struct ether_addr source, struct ether_addr bssid_or_transm, struct ether_addr recv, uint8_t fragment) {
  struct ieee_hdr *hdr = (struct ieee_hdr *) pkt->data;

  //If fragment, do not increase sequence
  if (!fragment) 
  	seqno++; 

  seqno %= 0x1000;

  if (fragment > 0x0F) {
    printf("WARNING: Fragment number exceeded maximum of 15, resetting to 0.\n");
    fragment = 0;
  }


  hdr->type = type;

  hdr->flags = 0x00;
  //if (wep) hdr->flags |= 0x40; //If somebody needs WEP, here it is :D

  switch (dsflags) {
    case 'a':	//Ad Hoc, Beacons:    ToDS 0 FromDS 0  Addr: DST, SRC, BSS
      MAC_COPY(hdr->addr1, destination);
      MAC_COPY(hdr->addr2, source);
      MAC_COPY(hdr->addr3, bssid_or_transm);
      break;
    case 'f':	//From AP to station: ToDS 0 FromDS 1  Addr: DST, BSS, SRC
      hdr->flags |= 0x02;
      MAC_COPY(hdr->addr1, destination);
      MAC_COPY(hdr->addr2, bssid_or_transm);
      MAC_COPY(hdr->addr3, source);
      break;
    case 't':	//From station to AP: ToDS 1 FromDS 0  Addr: BSS, SRC, DST
      hdr->flags |= 0x01;
      MAC_COPY(hdr->addr1, bssid_or_transm);
      MAC_COPY(hdr->addr2, source);
      MAC_COPY(hdr->addr3, destination);
      break;
    case 'w':	//WDS:                ToDS 1 FromDS 1  Addr: RCV, TRN, DST ... SRC
      hdr->flags |= 0x03;
      MAC_COPY(hdr->addr1, recv);
      MAC_COPY(hdr->addr2, bssid_or_transm);
      MAC_COPY(hdr->addr3, destination);
      memcpy((pkt->data) + (sizeof(struct ieee_hdr)), source.ether_addr_octet, ETHER_ADDR_LEN);
      break;
    default:
      printf("ERROR: DS Flags invalid, use only a, f, t or w! Frame will have no MAC adresses!\n");
  }

  hdr->duration = htole16(duration);

  hdr->frag_seq = htole16(fragment | (seqno << 4));

  pkt->len = sizeof(struct ieee_hdr);

  if( (hdr->type & 0x0F) == DATA_FRAME)
  {
    switch (hdr->type)
    {
    case IEEE80211_TYPE_QOSDATA:
    case IEEE80211_TYPE_QOSDATACFACK:
    case IEEE80211_TYPE_QOSDATACFPOLL:
    case IEEE80211_TYPE_QOSDATACFACKPOLL:
    case IEEE80211_TYPE_QOSNULL:
    case IEEE80211_TYPE_QOSCFACK:
    case IEEE80211_TYPE_QOSCFPOLL:
    case IEEE80211_TYPE_QOSCFACKPOLL:
      memset(pkt->data + sizeof(struct ieee_hdr), 0x00, 2);
      pkt->len += 2;
      break;
    default:
      break;
    }
  }

  
  if ((hdr->flags & 0x03) == 0x03) pkt->len += 6;	//Extra MAC in WDS packets
}

void increase_seqno(struct packet *pkt) {
  uint16_t frgseq;
  struct ieee_hdr *hdr = (struct ieee_hdr *) (pkt->data);

  frgseq = letoh16(hdr->frag_seq);

  frgseq += 0x10;	//Lower 4 bytes are fragment number

  hdr->frag_seq = htole16(frgseq);
}

uint16_t get_seqno(struct packet *pkt) {
  uint16_t seq;
  struct ieee_hdr *hdr = (struct ieee_hdr *) (pkt->data);

  seq = letoh16(hdr->frag_seq);
  seq >>= 4;

  return seq;
}

uint8_t get_fragno(struct packet *pkt) {
  uint16_t seq;
  struct ieee_hdr *hdr = (struct ieee_hdr *) (pkt->data);

  seq = letoh16(hdr->frag_seq);

  return (seq & 0xF);
}

uint16_t get_next_seqno()
{
  //return htole16(0 | ((++seqno) << 4));
  return ++seqno;
}

void set_seqno(struct packet *pkt, uint16_t seq) {
  struct ieee_hdr *hdr;
  uint16_t frgseq;

  if (!pkt) {
    seqno = seq;
    return;
  }

  hdr = (struct ieee_hdr *) (pkt->data);
  frgseq = letoh16(hdr->frag_seq);

  frgseq &= 0x000F;       //Clear seq, but keep fragment intact;
  frgseq |= (seq << 4); //Add seq

  hdr->frag_seq = htole16(frgseq);
}

void set_fragno(struct packet *pkt, uint8_t frag, int last_frag) {
  struct ieee_hdr *hdr = (struct ieee_hdr *) (pkt->data);
  uint16_t seq = letoh16(hdr->frag_seq);

  if (last_frag) hdr->flags &= 0xFB;
  else hdr->flags |= 0x04;

  seq &= 0xFFF0; //Clear frag bits
  seq |= frag;

  hdr->frag_seq = htole16(seq);
}

struct ether_addr *get_addr(struct packet *pkt, char type) {
  uint8_t dsflags;
  struct ieee_hdr *hdr;
  struct ether_addr *src = NULL, *dst = NULL, *bss = NULL, *trn = NULL;

  if(! pkt) {
    printf("BUG: Got NULL packet!\n");
    return NULL;
  }

  hdr = (struct ieee_hdr *) pkt->data;
  dsflags = hdr->flags & 0x03;

  switch (dsflags) {
    case 0x00:
      dst = &(hdr->addr1);
      src = &(hdr->addr2);
      bss = &(hdr->addr3);
      break;
    case 0x01:
      bss = &(hdr->addr1);
      src = &(hdr->addr2);
      dst = &(hdr->addr3);
      break;
    case 0x02:
      dst = &(hdr->addr1);
      bss = &(hdr->addr2);
      src = &(hdr->addr3);
      break;
    case 0x03:
      bss = &(hdr->addr1);
      trn = &(hdr->addr2);
      dst = &(hdr->addr3);
      src = (struct ether_addr *) &(pkt->data) + (sizeof(struct ieee_hdr));
      break;
  }

  switch (type) {
    case 'b':
      return bss;
    case 'd':
      return dst;
    case 's':
      return src;
    case 't':
      return trn;
  }

  return NULL;
}

struct ether_addr *get_bssid(struct packet *pkt) {
  return get_addr(pkt, 'b');
}

struct ether_addr *get_source(struct packet *pkt) {
  return get_addr(pkt, 's');
}

struct ether_addr *get_destination(struct packet *pkt) {
  return get_addr(pkt, 'd');
}

struct ether_addr *get_transmitter(struct packet *pkt) {
  return get_addr(pkt, 't');
}

struct ether_addr *get_receiver(struct packet *pkt) {
  return get_addr(pkt, 'b');
}

void generate_random_data(uint8_t *data, uint32_t length, FUZZING_VALUE_TYPE value_type)
{
  uint32_t i;
  struct timeval t;

  if(!data || length == 0)
  {
    return;
  }

  for(i=0; i<length; i++)
  {
    if(value_type == VALUE_ALL_BITS_ZERO)
    {
      *(data + i) = 0x00;
    }
    else if(value_type == VALUE__ALL_BITS_ONE)
    {
      *(data + i) = 0xFF;
    }
    else if(value_type == VALUE_RANDOM)
    {
      memset(&t,0, sizeof(t));
      gettimeofday(&t, NULL);
      srandom(t.tv_usec + *(data + i - 1));
      *(data + i) = random() % 256;
    }
    else if(value_type == VALUE_A)
    {
      *(data + i) = 0x41;
    }
  }
}

unsigned long long ntohll(unsigned long long val)
  {
    if (__BYTE_ORDER == __LITTLE_ENDIAN)
    {
      return (((unsigned long long )htonl((int)((val << 32) >> 32))) << 32) | (unsigned int)htonl((int)(val >> 32));
    }
    else if (__BYTE_ORDER == __BIG_ENDIAN)
    {
      return val;
    }
 }
 
unsigned long long htonll(unsigned long long val)
  {
    if (__BYTE_ORDER == __LITTLE_ENDIAN)
    {
      return (((unsigned long long )htonl((int)((val << 32) >> 32))) << 32) | (unsigned int)htonl((int)(val >> 32));
    }
    else if (__BYTE_ORDER == __BIG_ENDIAN)
    {
      return val;
    }
 }

void dumphex(uint8_t *data, uint32_t length)
{
  uint32_t i;

  for(i = 0; i< length; i++)
  {
    printf("%02x ", data[i]);
    
    if((i+1) % 16 == 0) 
    {
      printf("\n");
    }
  }  

  printf("\n");
}

void print_interaction_status(struct ether_addr bssid, struct ether_addr smac, struct ether_addr dmac,char *recv_frame, char *response_frame)
{
  if(1 == fuzzing_opt.test_type)
    {
    if(recv_frame != NULL && strlen(recv_frame) > 0)
    {
      fuzz_logger_log(FUZZ_LOG_INFO, "[%02X:%02X:%02X:%02X:%02X:%02X]\t\t ----> \t\t%s\t\t ----> \t\t[%02X:%02X:%02X:%02X:%02X:%02X]", smac.ether_addr_octet[0],smac.ether_addr_octet[1],smac.ether_addr_octet[2],
                          smac.ether_addr_octet[3],smac.ether_addr_octet[4],smac.ether_addr_octet[5], recv_frame, dmac.ether_addr_octet[0],dmac.ether_addr_octet[1],dmac.ether_addr_octet[2],
                          dmac.ether_addr_octet[3],dmac.ether_addr_octet[4],dmac.ether_addr_octet[5]);
    }

    if(response_frame != NULL && strlen(response_frame)>0)
    {
      fuzz_logger_log(FUZZ_LOG_INFO, "[%02X:%02X:%02X:%02X:%02X:%02X]\t\t ----> \t\t%s\t\t ----> \t\t[%02X:%02X:%02X:%02X:%02X:%02X]", dmac.ether_addr_octet[0],dmac.ether_addr_octet[1],dmac.ether_addr_octet[2],
                          dmac.ether_addr_octet[3],dmac.ether_addr_octet[4],dmac.ether_addr_octet[5], response_frame, smac.ether_addr_octet[0],smac.ether_addr_octet[1],smac.ether_addr_octet[2],
                          smac.ether_addr_octet[3],smac.ether_addr_octet[4],smac.ether_addr_octet[5]);    
    }
  }
}