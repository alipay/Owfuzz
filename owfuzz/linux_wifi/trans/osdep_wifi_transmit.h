#ifndef OSDEP_WIFI_TRANSMIT_H
#define OSDEP_WIFI_TRANSMIT_H

#include "./osdep/osdep.h"

#define MAX_IEEE_PACKET_SIZE 4096

struct packet {
  unsigned char data[MAX_IEEE_PACKET_SIZE];
  unsigned int len;
  unsigned char channel;
  struct rx_info ri;
  //struct tx_info ti;
};

struct devices
{
    int fd_in,  arptype_in;
    int fd_out, arptype_out;
    int fd_rtc;
};


struct osdep_instance{
  struct wif *_wi_in;
  struct wif *_wi_out;
  char osdep_iface_in[64];
  char osdep_iface_out[64];
  unsigned char channel;
  struct devices dev;

  pthread_t fthread;
  int thread_id;
};

extern int osdep_start(char *interface1, char *interface2);
extern int osdep_send_packet(struct packet *pkt);
extern struct packet osdep_read_packet();
extern void osdep_stop();

extern int osdep_start_ex(struct osdep_instance *oi);
extern int osdep_send_packet_ex(struct osdep_instance* oi, struct packet *pkt);
extern struct packet osdep_read_packet_ex(struct osdep_instance* oi);
extern void osdep_stop_ex(struct osdep_instance* oi);


#endif