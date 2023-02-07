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

#ifndef _INCLUDE_H
#define _INCLUDE_H

#include <net/ethernet.h>
#include <endian.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>
#include <setjmp.h>
#include <errno.h>

#define AP_MODE "ap"
#define STA_MODE "sta"
#define MITM_MODE "mitm"
#define P2P_MODE "p2p"
#define AWDL_MODE "awdl"
#define MESH_MODE "mesh"

// #define TEST_UNKNOWN -1
// #define TEST_POC 0
// #define TEST_INTERACTIVE 1
// #define TEST_FRAME 2
// #define TEST_INTERACTIVE_FRAME 3

enum TEST_TYPE {
	TEST_POC = 0,
	TEST_INTERACTIVE = 1,
	TEST_FRAME = 2,
	TEST_INTERACTIVE_FRAME = 3
};

static const char *TEST_TYPE_NAME[] =
{
	"TEST_POC",
	"TEST_INTERACTIVE",
	"TEST_FRAME",
	"TEST_INTERACTIVE_FRAME"
};

#define FUZZ_WORK_MODE_AP 0
#define FUZZ_WORK_MODE_STA 1
#define FUZZ_WORK_MODE_MITM 2
#define FUZZ_WORK_MODE_P2P 3
#define FUZZ_WORK_MODE_AWDL 4
#define FUZZ_WORK_MODE_MESH 5

#define PRE_KEY "88888888"

#define PING_PACKET_SIZE 1024
#define PING_MAX_WAIT_TIME 1
#define PING_MAX_NO_PACKETS 3
#define PING_ECHO_ID 0xfbfa
#define PING_CHECK_TIME 1

#define PING_ECHO_DATA "\x49\xde\x05\x00\x00\x00\x00\x00\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37"
#define PING_ECHO_DATA_LEN 48

#define CHECK_ALIVE_TIME 15

enum AP_AUTH_TYPE
{
	OPEN_NONE,
	OPEN_WEP,
	SHARE_WEP,
	WPA_PSK_TKIP,
	WPA_PSK_AES,
	WPA_PSK_TKIP_AES,
	WPA2_PSK_TKIP,
	WPA2_PSK_AES,
	WPA2_PSK_TKIP_AES,
	EAP_8021X,
	WPA3
};

static const char *AP_AUTH_TYPE_NAME[] =
{
	"OPEN_NONE",
	"OPEN_WEP",
	"SHARE_WEP",
	"WPA_PSK_TKIP",
	"WPA_PSK_AES",
	"WPA_PSK_TKIP_AES",
	"WPA2_PSK_TKIP",
	"WPA2_PSK_AES",
	"WPA2_PSK_TKIP_AES",
	"EAP_8021X",
	"WPA3"
};

static const char *wpa_state_names[] = {
	"WPA_DISCONNECTED",
	"WPA_INTERFACE_DISABLED",
	"WPA_INACTIVE",
	"WPA_SCANNING",
	"WPA_AUTHENTICATING",
	"WPA_ASSOCIATING",
	"WPA_ASSOCIATED",
	"WPA_EAP_HANDSHAKE",
	"WPA_4WAY_HANDSHAKE",
	"WPA_GROUP_HANDSHAKE",
	"WPA_COMPLETED"
};

/**
 * enum wpa_states - wpa_supplicant state
 *
 * These enumeration values are used to indicate the current wpa_supplicant
 * state (wpa_s->wpa_state). The current state can be retrieved with
 * wpa_supplicant_get_state() function and the state can be changed by calling
 * wpa_supplicant_set_state(). In WPA state machine (wpa.c and preauth.c), the
 * wrapper functions wpa_sm_get_state() and wpa_sm_set_state() should be used
 * to access the state variable.
 */
enum wpa_states
{
	/**
	 * WPA_DISCONNECTED - Disconnected state
	 *
	 * This state indicates that client is not associated, but is likely to
	 * start looking for an access point. This state is entered when a
	 * connection is lost.
	 */
	WPA_DISCONNECTED,

	/**
	 * WPA_INTERFACE_DISABLED - Interface disabled
	 *
	 * This state is entered if the network interface is disabled, e.g.,
	 * due to rfkill. wpa_supplicant refuses any new operations that would
	 * use the radio until the interface has been enabled.
	 */
	WPA_INTERFACE_DISABLED,

	/**
	 * WPA_INACTIVE - Inactive state (wpa_supplicant disabled)
	 *
	 * This state is entered if there are no enabled networks in the
	 * configuration. wpa_supplicant is not trying to associate with a new
	 * network and external interaction (e.g., ctrl_iface call to add or
	 * enable a network) is needed to start association.
	 */
	WPA_INACTIVE,

	/**
	 * WPA_SCANNING - Scanning for a network
	 *
	 * This state is entered when wpa_supplicant starts scanning for a
	 * network.
	 */
	WPA_SCANNING,

	/**
	 * WPA_AUTHENTICATING - Trying to authenticate with a BSS/SSID
	 *
	 * This state is entered when wpa_supplicant has found a suitable BSS
	 * to authenticate with and the driver is configured to try to
	 * authenticate with this BSS. This state is used only with drivers
	 * that use wpa_supplicant as the SME.
	 */
	WPA_AUTHENTICATING,

	/**
	 * WPA_ASSOCIATING - Trying to associate with a BSS/SSID
	 *
	 * This state is entered when wpa_supplicant has found a suitable BSS
	 * to associate with and the driver is configured to try to associate
	 * with this BSS in ap_scan=1 mode. When using ap_scan=2 mode, this
	 * state is entered when the driver is configured to try to associate
	 * with a network using the configured SSID and security policy.
	 */
	WPA_ASSOCIATING,

	/**
	 * WPA_ASSOCIATED - Association completed
	 *
	 * This state is entered when the driver reports that association has
	 * been successfully completed with an AP. If IEEE 802.1X is used
	 * (with or without WPA/WPA2), wpa_supplicant remains in this state
	 * until the IEEE 802.1X/EAPOL authentication has been completed.
	 */
	WPA_ASSOCIATED,

	/**
	 * 802.1X EAP
	 */
	WPA_EAP_HANDSHAKE,

	/**
	 * WPA_4WAY_HANDSHAKE - WPA 4-Way Key Handshake in progress
	 *
	 * This state is entered when WPA/WPA2 4-Way Handshake is started. In
	 * case of WPA-PSK, this happens when receiving the first EAPOL-Key
	 * frame after association. In case of WPA-EAP, this state is entered
	 * when the IEEE 802.1X/EAPOL authentication has been completed.
	 */
	WPA_4WAY_HANDSHAKE,

	/**
	 * WPA_GROUP_HANDSHAKE - WPA Group Key Handshake in progress
	 *
	 * This state is entered when 4-Way Key Handshake has been completed
	 * (i.e., when the supplicant sends out message 4/4) and when Group
	 * Key rekeying is started by the AP (i.e., when supplicant receives
	 * message 1/2).
	 */
	WPA_GROUP_HANDSHAKE,

	/**
	 * WPA_COMPLETED - All authentication completed
	 *
	 * This state is entered when the full authentication process is
	 * completed. In case of WPA2, this happens when the 4-Way Handshake is
	 * successfully completed. With WPA, this state is entered after the
	 * Group Key Handshake; with IEEE 802.1X (non-WPA) connection is
	 * completed after dynamic keys are received (or if not used, after
	 * the EAP authentication has been completed). With static WEP keys and
	 * plaintext connections, this state is entered when an association
	 * has been completed.
	 *
	 * This state indicates that the supplicant has completed its
	 * processing for the association phase and that data connection is
	 * fully configured.
	 */
	WPA_COMPLETED
};

#endif
