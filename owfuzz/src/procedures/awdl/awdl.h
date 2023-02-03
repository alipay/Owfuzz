#ifndef AWDL_H
#define AWDL_H

#include "../../frames/frame.h"

int is_awdl_frame(struct packet *pkt);

void handle_awdl(struct packet *pkt, struct ether_addr bssid, struct ether_addr smac, struct ether_addr dmac, fuzzing_option *fuzzing_opt);

#endif