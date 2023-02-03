#ifndef MESH_H_
#define MESH_H_

#include "../../frames/frame.h"
#include "../awdl/wire.h"

// Spanning Tree Protocol
struct spanning_tree_protocol
{
    uint16_t identifier;
    uint8_t version_identifier;
    uint8_t bpdu_type;
    uint8_t bpdu_flag;
    uint8_t root_bridge_priority;
    uint8_t root_bridge_system_id_ext;
    uint8_t root_bridge_system_id[6];
    uint32_t root_path_cast;
    uint8_t bridge_identifier[6];
    uint16_t port_identifier;
    uint16_t message_age;
    uint16_t max_age;
    uint16_t hello_time;
    uint16_t forward_delay;
} __attribute__((packed));

// discovery, beacon/probe_response
void parse_beacon(struct packet *pkt);

// peering,

// security

void handle_mesh(struct packet *pkt, struct ether_addr bssid, struct ether_addr smac, struct ether_addr dmac, struct ether_addr tmac, fuzzing_option *fuzzing_opt);

#endif