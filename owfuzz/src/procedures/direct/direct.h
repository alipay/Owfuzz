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

#ifndef _DIRECT_H_
#define _DIRECT_H_

#include "../../frames/frame.h"

// P2P Public Action frames
#define P2P_GO_NEGOTIATION_REQUEST 0
#define P2P_GO_NEGOTIATION_RESPONSE 1
#define P2P_GO_NEGOTIATION_CONFIRMATION 2
#define P2P_INVITATION_REQUEST 3
#define P2P_INVITATION_RESPONSE 4
#define P2P_DEVICE_DISCOVERABILITY_REQUEST 5
#define P2P_DEVICE_DISCOVERABILITY_RESPONSE 6
#define P2P_PROVISION_DISCOVERY_REQUEST 7
#define P2P_PROVISION_DISCOVERY_RESPONSE 8
// 9-255 Reserved

// P2P Action frames
#define P2P_ACTION_NOTICE_OF_ABSENCE 0
#define P2P_ACTION_P2P_PRESENCE_REQUEST 1
#define P2P_ACTION_P2P_PRESENCE_RESPONSE 2
#define P2P_ACTION_GO_DISCOVERABILITY_REQUEST 3
// 4-255 Reserved

// attribute
#define P2P_ATTRIBUTE_STATUS 0
#define P2P_ATTRIBUTE_MINOR_REASON_CODE 1
#define P2P_ATTRIBUTE_P2P_CAPABILITY 2
#define P2P_ATTRIBUTE_P2P_DEVICE_ID 3
#define P2P_ATTRIBUTE_GROUP_OWNER_INTENT 4
#define P2P_ATTRIBUTE_CONFIGURATION_TIMEOUT 5
#define P2P_ATTRIBUTE_LISTEN_CHANNEL 6
#define P2P_ATTRIBUTE_P2P_GROUP_BSSID 7
#define P2P_ATTRIBUTE_EXTENDED_LISTEN_TIMING 8
#define P2P_ATTRIBUTE_INTENDED_P2P_INTERFACE_ADDRESS 9
#define P2P_ATTRIBUTE_P2P_MANAGEABILITY 10
#define P2P_ATTRIBUTE_CHANNEL_LIST 11
#define P2P_ATTRIBUTE_NOTICE_OF_ABSENCE 12
#define P2P_ATTRIBUTE_P2P_DEVICE_INFO 13
#define P2P_ATTRIBUTE_P2P_GROUP_INFO 14
#define P2P_ATTRIBUTE_P2P_GROUP_ID 15
#define P2P_ATTRIBUTE_P2P_INTERFACE 16
#define P2P_ATTRIBUTE_OPERATING_CHANNEL 17
#define P2P_ATTRIBUTE_INVITATION_FLAGS 18
#define P2P_ATTRIBUTE_OUT_OF_BAND_GROUP_OWNER_NEGOTIATION_CHANNEL 19
#define P2P_ATTRIBUTE_SERVICE_HASH 21
#define P2P_ATTRIBUTE_SESSION_INFORMATION 22
#define P2P_ATTRIBUTE_CONNECTION_CAPABILITY_INFO 23
#define P2P_ATTRIBUTE_ADVERTISEMENT_ID_INFO 24
#define P2P_ATTRIBUTE_ADVERTISED_SERVICE_INFO 25
#define P2P_ATTRIBUTE_SESSION_ID_INFO 26
#define P2P_ATTRIBUTE_FEATURE_CAPABILITY_INFO 27
#define P2P_ATTRIBUTE_PERSISTENT_GROUP_INFO 28

// P2P Service Protocol Types
#define P2P_SERVICE_ALL 0
#define P2P_SERVICE_BONJOUR 1
#define P2P_SERVICE_UPNP 2
#define P2P_SERVICE_WS_DISCOVERY 3
#define P2P_SERVICE_DISPLAY 4
#define P2P_SERVICE_WIGIG_DISPLAY_EXTENSION_OVER_MAC_TX 5
#define P2P_SERVICE_WIGIG_DISPLAY_EXTENSION_OVER_MAC_RX 6
#define P2P_SERVICE_WIGIG_DISPLAY_EXTENSION_OVER_MAC_HOST 7
#define P2P_SERVICE_WIGIG_DISPLAY_EXTENSION_OVER_MAC_DEVICE 8
#define P2P_SERVICE_WIGIG_BUS_EXTENSION_OVER_MAC 9
#define P2P_SERVICE_WIGIG_SD_EXTENSION_OVER_MAC 10
#define P2P_SERVICE_PEER_TO_PEER_SERVICES 11
// 12-254 Reserved
#define P2P_SERVICE_VENDOR_SPECIFIC 12

// Service Discovery Status Codes
#define P2P_SERVICE_SUCCESS 0
#define P2P_SERVICE_PROTOCOL_TYPE_NOT_AVAILABLE 1
#define P2P_SERVICE_REQUESTED_INFORMATION_NOT_AVAILABLE 2
#define P2P_SERVICE_BAD_REQUEST 3
// 4-255 Reserved

#define WPS_VERSION 0x104A
#define WPS_REQUEST_TYPE 0x103A
#define WPS_CONFIG_METHODS 0x1008
#define WPS_UUID_E 0x1047
#define WPS_PRIMARY_DEVICE_TYPE 0x01054
#define WPS_RF_BANDS 0x103C
#define WPS_ASSOCIATION_STATE 0x1002
#define WPS_CONFIGURATION_ERROR 0x0009
#define WPS_DEVICE_PASSWORD_ID 0x1012
#define WPS_MANUFACTURER 0x1021
#define WPS_MODEL_NAME 0x1023
#define WPS_MODEL_NUMBER 0x1024
#define WPS_DEVICE_NAME 0x1011
#define WPS_VENDOR_EXTENSION 0x1011

struct wps_ie
{
    uint8_t id;       // 0xDD
    uint8_t length;   //
    uint8_t oui[3];   // 0x00 0x50 0xF2
    uint8_t oui_type; // 0x04
    // WPS Data Element
} __attribute__((packed));

struct p2p_ie
{
    uint8_t id;       // 0xDD
    uint8_t length;   //
    uint8_t oui[3];   // 0x50 0x6F 0x9A
    uint8_t oui_type; // 0x09
    // P2P Attributes
} __attribute__((packed));

struct p2p_action
{
    uint8_t category;     // 0x04
    uint8_t action_field; // 0x09
    uint8_t oui[3];       // 0x50 0x6F 0x9A
    uint8_t oui_type;     // 0x09
    uint8_t oui_subtype;
    uint8_t dialog_token; // set to a nonzero value to identify the request response
    // elements P2P IE or other
} __attribute__((packed));

/*

STA1                                     STA2
probe request(P2P IE)
                                     probe response

//
action(p2p invitation request)
                                     action(p2p invitation response)

// GO or GC
action(p2p go negotiation request)

                                     action(p2p go negotiation response)
action(p2p go negotiation confirm)

// WSC
action(p2p provision discovery request)

                                     action(p2p provision discovery response)

*/

// scan
struct packet create_default_p2p_probe_request(struct ether_addr bssid, struct ether_addr smac, struct ether_addr dmac, char adhoc, struct packet *recv_pkt);
struct packet create_p2p_probe_request(struct ether_addr bssid, struct ether_addr smac, struct ether_addr dmac, char adhoc, struct packet *recv_pkt);
struct packet create_p2p_probe_response(struct ether_addr bssid, struct ether_addr smac, struct ether_addr dmac, char adhoc, struct packet *recv_pkt);

// service discovery
struct packet create_p2p_gas_initial_request(struct ether_addr bssid, struct ether_addr smac, struct ether_addr dmac, char adhoc, struct packet *recv_pkt);
struct packet create_p2p_gas_initial_response(struct ether_addr bssid, struct ether_addr smac, struct ether_addr dmac, char adhoc, struct packet *recv_pkt);

// group owner negotiation
struct packet create_p2p_action_go_negotiation_request(struct ether_addr bssid, struct ether_addr smac, struct ether_addr dmac, char adhoc, struct packet *recv_pkt);
struct packet create_p2p_action_go_negotiation_response(struct ether_addr bssid, struct ether_addr smac, struct ether_addr dmac, char adhoc, struct packet *recv_pkt);
struct packet create_p2p_action_go_negotiation_confirmation(struct ether_addr bssid, struct ether_addr smac, struct ether_addr dmac, char adhoc, struct packet *recv_pkt);

// invitation
struct packet create_p2p_action_invitation_request(struct ether_addr bssid, struct ether_addr smac, struct ether_addr dmac, char adhoc, struct packet *recv_pkt);
struct packet create_p2p_action_invitation_response(struct ether_addr bssid, struct ether_addr smac, struct ether_addr dmac, char adhoc, struct packet *recv_pkt);

// device discovery
struct packet create_p2p_action_device_discoverability_request(struct ether_addr bssid, struct ether_addr smac, struct ether_addr dmac, char adhoc, struct packet *recv_pkt);
struct packet create_p2p_action_device_discoverability_response(struct ether_addr bssid, struct ether_addr smac, struct ether_addr dmac, char adhoc, struct packet *recv_pkt);

//
struct packet create_p2p_action_provision_discovery_request(struct ether_addr bssid, struct ether_addr smac, struct ether_addr dmac, char adhoc, struct packet *recv_pkt);
struct packet create_p2p_action_provision_discovery_response(struct ether_addr bssid, struct ether_addr smac, struct ether_addr dmac, char adhoc, struct packet *recv_pkt);

// beacon
struct packet create_p2p_beacon(struct ether_addr bssid, struct ether_addr smac, struct ether_addr dmac, char adhoc, struct packet *recv_pkt);
struct packet create_p2p_association_request(struct ether_addr bssid, struct ether_addr smac, struct ether_addr dmac, char adhoc, struct packet *recv_pkt);
struct packet create_p2p_association_response(struct ether_addr bssid, struct ether_addr smac, struct ether_addr dmac, char adhoc, struct packet *recv_pkt);
struct packet create_p2p_action(struct ether_addr bssid, struct ether_addr smac, struct ether_addr dmac, char adhoc, struct packet *recv_pkt);

struct ie_data create_frame_p2p_fuzzing_attribute(struct packet *pkt,
                                                  char *frame_name,
                                                  uint8_t attr_id);

struct ie_data get_p2p_attribute_by_fuzzing_type(uint8_t id,
                                                 FUZZING_TYPE fuzzing_type,
                                                 FUZZING_VALUE_TYPE value_type,
                                                 uint8_t *specific_data,
                                                 int specific_data_len);

void p2p_ie_fuzzing(struct packet *pkt, char *frame_name, uint8_t p2p_attrs[]);
void wps_ie_fuzzing(struct packet *pkt, char *frame_name);

int is_p2p_beacon(struct packet *pkt);
int is_p2p_probe(struct packet *pkt);
int is_p2p_action(struct packet *pkt);

int is_p2p_frame(struct packet *pkt);

void check_p2p_attributes(struct packet *pkt, struct ether_addr bssid, struct ether_addr smac, struct ether_addr dmac);

void handle_p2p(struct packet *pkt, struct ether_addr bssid, struct ether_addr smac, struct ether_addr dmac, fuzzing_option *fuzzing_opt);
struct packet get_p2p_frame(uint8_t frame_type, struct ether_addr bssid, struct ether_addr smac, struct ether_addr dmac, struct packet *recv_pkt);

#endif