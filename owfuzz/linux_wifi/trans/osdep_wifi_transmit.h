#ifndef OSDEP_WIFI_TRANSMIT_H
#define OSDEP_WIFI_TRANSMIT_H

#include "./osdep/byteorder.h"

#define MAX_IEEE_PACKET_SIZE 4096

struct packet {
  unsigned char data[MAX_IEEE_PACKET_SIZE];
  unsigned int len;
};


extern int osdep_start(char *interface1, char *interface2);

extern int osdep_send_packet(struct packet *pkt);

extern struct packet osdep_read_packet();

extern void osdep_stop();


#endif