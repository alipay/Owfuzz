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

#ifndef _IEEE80211_DEF_H
#define _IEEE80211_DEF_H

#define MANAGMENT_FRAME 0x00
#define CONTROL_FRAME 0x04
#define DATA_FRAME 0x08
#define EXTENSION_FRAME 0x0C

// management
#define IEEE80211_TYPE_ASSOCREQ 0x00    // association request
#define IEEE80211_TYPE_ASSOCRES 0x10    // association response
#define IEEE80211_TYPE_REASSOCREQ 0x20  // reassociation request
#define IEEE80211_TYPE_REASSOCRES 0x30  // reassociation response
#define IEEE80211_TYPE_PROBEREQ 0x40    // probe request
#define IEEE80211_TYPE_PROBERES 0x50    // probe response
#define IEEE80211_TYPE_TIMADVERT 0x60   // timing advertisement
#define IEEE80211_TYPE_000111 0x70      // reserved
#define IEEE80211_TYPE_BEACON 0x80      // beacon
#define IEEE80211_TYPE_ATIM 0x90        // ATIM
#define IEEE80211_TYPE_DISASSOC 0xA0    // disassociation
#define IEEE80211_TYPE_AUTH 0xB0        // authentication
#define IEEE80211_TYPE_DEAUTH 0xC0      // deauthentication
#define IEEE80211_TYPE_ACTION 0xD0      // action
#define IEEE80211_TYPE_ACTIONNOACK 0xE0 // action no ack
#define IEEE80211_TYPE_001111 0xF0      // reserved

// control
#define IEEE80211_TYPE_010000 0x04      // reserved
#define IEEE80211_TYPE_010001 0x14      // reserved
#define IEEE80211_TYPE_010010 0x24      // reserved
#define IEEE80211_TYPE_010011 0x34      // reserved
#define IEEE80211_TYPE_BEAMFORMING 0x44 // beamforming report poll
#define IEEE80211_TYPE_VHT 0x54         // vht ndp announcement
#define IEEE80211_TYPE_CTRLFRMEXT 0x64  // control frame extension
#define IEEE80211_TYPE_CTRLWRAP 0x74    // control wrapper
#define IEEE80211_TYPE_BLOCKACKREQ 0x84 // block ack request
#define IEEE80211_TYPE_BLOCKACK 0x94    // block ack
#define IEEE80211_TYPE_PSPOLL 0xA4      // ps-poll
#define IEEE80211_TYPE_RTS 0xB4         // rts
#define IEEE80211_TYPE_CTS 0xC4         // cts
#define IEEE80211_TYPE_ACK 0xD4         // ack
#define IEEE80211_TYPE_CFEND 0xE4       // cf-end
#define IEEE80211_TYPE_CFENDACK 0xF4    // cf-end + cf-ack

// data
#define IEEE80211_TYPE_DATA 0x08             // data
#define IEEE80211_TYPE_DATACFACK 0x18        // data + cf-ack
#define IEEE80211_TYPE_DATACFPOLL 0x28       // data + cf-poll
#define IEEE80211_TYPE_DATACFACKPOLL 0x38    // data + cf-ack + cf-poll
#define IEEE80211_TYPE_NULL 0x48             // null func
#define IEEE80211_TYPE_CFACK 0x58            // cf-ack
#define IEEE80211_TYPE_CFPOLL 0x68           // cf-poll
#define IEEE80211_TYPE_CFACKPOLL 0x78        // cf-ack + cf-poll
#define IEEE80211_TYPE_QOSDATA 0x88          // qos data
#define IEEE80211_TYPE_QOSDATACFACK 0x98     // qos data + cf-ack
#define IEEE80211_TYPE_QOSDATACFPOLL 0xA8    // qos data + cf-poll
#define IEEE80211_TYPE_QOSDATACFACKPOLL 0xB8 // qos data + cf-ack + cf-poll
#define IEEE80211_TYPE_QOSNULL 0xC8          // qos null func
#define IEEE80211_TYPE_QOSCFACK 0xD8         // qos cf-ack
#define IEEE80211_TYPE_QOSCFPOLL 0xE8        // qos cf-poll
#define IEEE80211_TYPE_QOSCFACKPOLL 0xF8     // qos cf-ack + cf-poll

// extension
#define IEEE80211_TYPE_DMGBEACON 0x0C // DMG beacon
#define IEEE80211_TYPE_110001 0x1C    // reserved
#define IEEE80211_TYPE_110010 0x2C    // reserved
#define IEEE80211_TYPE_110011 0x3C    // reserved
#define IEEE80211_TYPE_110100 0x4C    // reserved
#define IEEE80211_TYPE_110101 0x5C    // reserved
#define IEEE80211_TYPE_110110 0x6C    // reserved
#define IEEE80211_TYPE_110111 0x7C    // reserved
#define IEEE80211_TYPE_111000 0x8C    // reserved
#define IEEE80211_TYPE_111001 0x9C    // reserved
#define IEEE80211_TYPE_111010 0xAC    // reserved
#define IEEE80211_TYPE_111011 0xBC    // reserved
#define IEEE80211_TYPE_111100 0xCC    // reserved
#define IEEE80211_TYPE_111101 0xDC    // reserved
#define IEEE80211_TYPE_111110 0xEC    // reserved
#define IEEE80211_TYPE_111111 0xFC    // reserved

#define IEEE80211_BODY_LENGTH 8000

#endif