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

#include "ies.h"
#include "ies_creator.h"
#include "../80211_packet_common.h"

extern fuzzing_option fuzzing_opt;

// 802.11a/b
static int ie_ranges1999[10][3] = {
	{0, 0, 32},	  // SSID
	{1, 1, 8},	  // Supported rates
	{2, 5, 5},	  // FH Parameter Set
	{3, 1, 1},	  // DS Parameter Set
	{4, 6, 6},	  // CF Parameter Set
	{5, 4, 254},  // TIM
	{6, 2, 2},	  // IBSS Parameter Set
	{16, 1, 253}, // Challenge Text
	{-1, 0, 0}};

// 802.11g
static int ie_ranges2007[40][3] = {
	{0, 0, 32},	   // SSID
	{1, 1, 8},	   // Supported rates
	{2, 5, 5},	   // FH Parameter Set
	{3, 1, 1},	   // DS Parameter Set
	{4, 6, 6},	   // CF Parameter Set
	{5, 4, 254},   // TIM
	{6, 2, 2},	   // IBSS Parameter Set
	{7, 6, 254},   // Country
	{8, 2, 2},	   // Hopping Pattern Parameters
	{9, 4, 254},   // Hopping Pattern Table
	{10, 0, 254},  // Request
	{11, 5, 5},	   // BSS Load
	{12, 18, 18},  // EDCA Parameter Set
	{13, 55, 55},  // TSPEC
	{14, 0, 255},  // TCLAS
	{15, 14, 14},  // Schedule
	{16, 1, 253},  // Challenge text
	{32, 1, 1},	   // Power Constraint
	{33, 2, 2},	   // Power Capability
	{34, 0, 0},	   // TPC Request
	{35, 2, 2},	   // TPC Report
	{36, 2, 254},  // Supported Channels
	{37, 3, 3},	   // Channel Switch Announcement
	{38, 3, 14},   // Measurement Request
	{39, 3, 22},   // Measurement Report
	{40, 6, 6},	   // Quiet
	{41, 8, 253},  // IBSS DFS
	{42, 1, 1},	   // ERP Information
	{43, 4, 4},	   // TS Delay
	{44, 1, 1},	   // TCLAS Processing
	{46, 1, 1},	   // QoS Capability
	{48, 34, 254}, // RSN
	{50, 1, 255},  // Extended Supported Rates
	{127, 0, 255}, // Extened Capabilities
	{221, 1, 254}, // Vendor Specific
	{-1, 0, 0}};

// 802.11n
static int ie_ranges2012[180][3] = {
	{0, 0, 32},		// SSID
	{1, 1, 8},		// Supported rates
	{2, 5, 5},		// FH Parameter Set
	{3, 1, 1},		// DSSS Parameter Set
	{4, 6, 6},		// CF Parameter Set
	{5, 4, 254},	// TIM
	{6, 2, 2},		// IBSS Parameter Set
	{7, 6, 254},	// Country
	{8, 2, 2},		// Hopping Pattern Parameters
	{9, 4, 254},	// Hopping Pattern Table
	{10, 0, 254},	// Request
	{11, 5, 5},		// BSS Load
	{12, 18, 18},	// EDCA Parameter
	{13, 55, 55},	// TSPEC
	{14, 0, 255},	// TCLAS
	{15, 14, 14},	// Schedule
	{16, 1, 253},	// Challenge text
	{32, 1, 1},		// Power Constraint
	{33, 2, 2},		// Power Capability
	{34, 0, 0},		// TPC Request
	{35, 2, 2},		// TPC Report
	{36, 2, 254},	// Supported Channels
	{37, 3, 3},		// Channel Switch Announcement
	{38, 3, 255},	// Measurement Request
	{39, 3, 255},	// Measurement Report
	{40, 6, 6},		// Quiet
	{41, 8, 253},	// IBSS DFS
	{42, 1, 1},		// ERP
	{43, 4, 4},		// TS Delay
	{44, 1, 1},		// TCLAS Processing
	{45, 26, 26},	// HT Capabilities
	{46, 1, 1},		// QoS Capability
	{48, 34, 254},	// RSN
	{50, 1, 255},	// Extended Supported Rates
	{51, 1, 255},	// AP Channel Report
	{52, 13, 255},	// Neighbor Report
	{53, 1, 1},		// RCPI
	{54, 3, 3},		// Mobility Domain
	{55, 82, 255},	// Fast BSS Transition
	{56, 5, 5},		// Timeout Interval
	{57, 4, 4},		// RIC Data
	{58, 20, 20},	// DSE Registered Location
	{59, 2, 253},	// Supported Operating Classes
	{60, 4, 4},		// Extended Channel Switch Anouncement
	{61, 22, 22},	// HT Operation
	{62, 1, 1},		// Secondary Channel Offset
	{63, 1, 1},		// BSS Average Access Delay
	{64, 1, 1},		// Antenna
	{65, 1, 1},		// RSNI
	{66, 1, 255},	// Measurement Pilot Transmission
	{67, 2, 26},	// BSS Available Admission Capacity
	{68, 4, 4},		// BSS AC Access Delay
	{69, 1, 16},	// Time Advertisement
	{70, 5, 5},		// RM Enabled Capabilities
	{71, 1, 255},	// Multipe BSSID
	{72, 1, 1},		// 20/40 BSS Coexistence
	{73, 1, 255},	// 20/40 BSS Intolerant Channel Report
	{74, 14, 14},	// Overlapping BSS Scan Parameters
	{75, 1, 255},	// RIC Descriptor
	{76, 16, 16},	// Management MIC
	{78, 3, 255},	// Event Request
	{79, 3, 255},	// Event Report
	{80, 4, 255},	// Diagnostic Request
	{81, 3, 255},	// Diagnostic Report
	{82, 0, 255},	// Location Parameters
	{83, 2, 2},		// Nontransmitted BSSID Capability
	{84, 0, 255},	// SSID List
	{85, 1, 3},		// Multiple BSSID-Index
	{86, 1, 255},	// FMS Descriptor
	{87, 1, 255},	// FMS Request
	{88, 16, 255},	// FMS Response
	{89, 1, 3},		// QoS Traffic Capability
	{90, 3, 3},		// BSS Max Idle Period
	{91, 4, 255},	// TFS Request
	{92, 4, 254},	// TFS Response
	{93, 4, 4},		// WNM-Sleep Mode
	{94, 1, 1},		// TIM Broadcast Request
	{95, 1, 10},	// TIM Broadcast Response
	{96, 21, 21},	// Collocated Interference
	{97, 1, 255},	// Channel Usage
	{98, 1, 255},	// Time Zone
	{99, 1, 255},	// DMS Request
	{100, 1, 255},	// DMS Response
	{101, 18, 18},	// Link Identifier
	{102, 18, 18},	// Wakeup Schedule
	{104, 4, 4},	// Channel Switch Timing
	{105, 3, 3},	// PTI Control
	{106, 1, 1},	// TPU Buffer Status
	{107, 1, 9},	// Interworking
	{108, 0, 255},	// Advertisement Protocol
	{109, 1, 1},	// Expedited Bandwidth Request
	{110, 16, 58},	// QoS Map Set
	{111, 0, 255},	// Roaming Consortium
	{112, 8, 8},	// Emergency Alert Identitier
	{113, 7, 7},	// Mesh Configuration
	{114, 0, 32},	// Mesh ID
	{115, 1, 255},	// Mesh Link Metric Report
	{116, 14, 14},	// Congestion Notification
	{117, 3, 23},	// Mesh Peering Management
	{118, 6, 6},	// Mesh Channel Switch Parameters
	{119, 2, 2},	// Mesh Awake Window
	{120, 1, 253},	// Beacon Timing
	{121, 6, 6},	// MCCAOP Setup Request
	{122, 2, 7},	// MCCAOP Setup Reply
	{123, 2, 255},	// MCCAOP Advertisement
	{124, 1, 7},	// MCCAOP Teardown
	{125, 15, 15},	// GANN
	{126, 21, 21},	// RANN
	{127, 1, 6},	// Extended Capabilities
	{130, 37, 252}, // PREQ
	{131, 31, 37},	// PREP
	{132, 15, 249}, // PERR
	{137, 19, 255}, // PXU
	{138, 7, 7},	// PXUC
	{139, 84, 255}, // Authenticated Mesh Peering Exchange
	{140, 16, 16},	// MIC
	{141, 1, 255},	// Destination URI
	{142, 12, 255}, // U-APSD Coexistence
	{174, 6, 6},	// MCCAOP Advertisement Overview
	{221, 1, 254},	// Vendor Specific
	{-1, 0, 0}};

// 802.11ac
static int ie_ranges2016[260][3] = {
	{0, 0, 32},		// SSID
	{1, 1, 8},		// Supported Rates and BSS Membership Selectors
	{3, 1, 1},		// DSSS Parameter Set
	{4, 6, 6},		// CF Parameter Set
	{5, 4, 254},	// TIM
	{6, 2, 2},		// IBSS Parameter Set
	{7, 6, 254},	// Country
	{10, 0, 254},	// Request
	{11, 5, 5},		// BSS Load
	{12, 18, 18},	// EDCA Parameter Set
	{13, 55, 55},	// TSPEC
	{14, 0, 255},	// TCLAS
	{15, 14, 14},	// Schedule
	{16, 1, 253},	// Challenge text
	{32, 1, 1},		// Power Constraint
	{33, 2, 2},		// Power Capability
	{34, 0, 0},		// TPC Request
	{35, 2, 2},		// TPC Report
	{36, 2, 2},		// Supported Channels
	{37, 3, 3},		// Channel Switch Announcement
	{38, 3, 255},	// Measurement Request
	{39, 3, 255},	// Measurement Report
	{40, 6, 6},		// Quiet
	{41, 9, 253},	// IBSS DFS
	{42, 1, 1},		// ERP
	{43, 4, 4},		// TS Delay
	{44, 1, 1},		// TCLAS Processing
	{45, 26, 26},	// HT Capabilities
	{46, 1, 1},		// QoS Capability
	{48, 34, 254},	// RSN
	{50, 1, 255},	// Extended Supported Rates and BSS Membership Selectors
	{51, 1, 255},	// AP Channel Report
	{52, 13, 255},	// Neighbor Report
	{53, 1, 1},		// RCPI
	{54, 3, 3},		// Mobility Domain
	{55, 82, 255},	// Fast BSS Transition
	{56, 5, 5},		// Timeout Interval
	{57, 4, 4},		// RIC Data (RDE)
	{58, 20, 20},	// DSE Registered Location
	{59, 2, 253},	// Supported Operating Classes
	{60, 4, 4},		// Extended Channel Switch Announcement
	{61, 22, 22},	// HT Operation
	{62, 1, 1},		// Secondary Channel Offset
	{63, 1, 1},		// BSS Average Access Delay
	{64, 1, 1},		// Antenna
	{65, 1, 1},		// RSNI
	{66, 1, 255},	// Measurement Pilot Transmission
	{67, 2, 26},	// BSS Available Admission Capacity
	{68, 4, 4},		// BSS AC Access Delay
	{69, 1, 16},	// Time Advertisement
	{70, 5, 5},		// RM Enabled Capabilities
	{71, 1, 255},	// Multiple BSSID
	{72, 1, 1},		// 20/40 BSS Coexistence
	{73, 1, 255},	// 20/40 BSS Intolerant Channel Report
	{74, 14, 14},	// Overlapping BSS Scan Parameters
	{75, 1, 255},	// RIC Descriptor
	{76, 16, 16},	// Management MIC
	{78, 3, 255},	// Event Request
	{79, 3, 255},	// Event Report
	{80, 4, 255},	// Diagnostic Request
	{81, 3, 255},	// Diagnostic Report
	{82, 0, 255},	// Location Parameters
	{83, 2, 2},		// Nontransmitted BSSID Capability
	{84, 0, 255},	// SSID List
	{85, 1, 3},		// Multiple BSSID-Index
	{86, 1, 255},	// FMS Descriptor
	{87, 1, 255},	// FMS Request
	{88, 16, 255},	// FMS Response
	{89, 1, 3},		// QoS Traffic Capability
	{90, 3, 3},		// BSS Max Idle Period
	{91, 4, 255},	// TFS Request
	{92, 4, 254},	// TFS Response
	{93, 4, 4},		// WNM Sleep Mode
	{94, 1, 1},		// TIM Broadcast Request
	{95, 1, 10},	// TIM Broadcast Response
	{96, 21, 21},	// Collocated Interference Report
	{97, 1, 255},	// Channel Usage
	{98, 1, 255},	// Time Zone
	{99, 1, 255},	// DMS Request
	{100, 1, 255},	// DMS Response
	{101, 18, 18},	// Link Identifier
	{102, 18, 18},	// Wakeup Schedule
	{104, 4, 4},	// Channel Switch Timing
	{105, 3, 3},	// PTI Control
	{106, 3, 3},	// TPU Buffer Status
	{107, 3, 11},	// Interworking
	{108, 0, 255},	// Advertisement Protocol
	{109, 1, 1},	// Expedited Bandwidth Request
	{110, 16, 58},	// QoS Map
	{111, 0, 255},	// Roaming Consortium
	{112, 8, 8},	// Emergency Alert Identifier
	{113, 7, 7},	// Mesh Configuration
	{114, 0, 32},	// Mesh ID
	{115, 1, 255},	// Mesh Link Metric Report
	{116, 14, 14},	// Congestion Notification
	{117, 3, 23},	// Mesh Peering Management
	{118, 6, 6},	// Mesh Channel Switch Parameters
	{119, 2, 2},	// Mesh Awake Window
	{120, 1, 253},	// Beacon Timing
	{121, 6, 6},	// MCCAOP Setup Request
	{122, 2, 7},	// MCCAOP Setup Reply
	{123, 2, 255},	// MCCAOP Advertisement
	{124, 1, 7},	// MCCAOP Teardown
	{125, 15, 15},	// GANN
	{126, 21, 21},	// RANN
	{127, 1, 10},	// Extended Capabilities
	{130, 37, 252}, // PREQ
	{131, 31, 37},	// PREP
	{132, 15, 249}, // PERR
	{137, 30, 255}, // PXU
	{138, 7, 7},	// PXUC
	{139, 76, 255}, // Authenticated Mesh Peering Exchange
	{140, 16, 16},	// MIC
	{141, 1, 255},	// Destination URI
	{142, 12, 255}, // U-APSD Coexistence
	{143, 8, 8},	// DMG Wakeup Schedule
	{144, 15, 255}, // Extended Schedule
	{145, 2, 254},	// STA Availability
	{146, 15, 255}, // DMG TSPEC
	{147, 6, 6},	// Next DMG ATI
	{148, 22, 22},	// DMG Capabilities
	{151, 10, 10},	// DMG Operation
	{152, 7, 7},	// DMG BSS Parameter Change
	{153, 5, 5},	// DMG Beam Refinement
	{154, 0, 255},	// Channel Measurement Feedback
	{157, 2, 2},	// Awake Window
	{158, 22, 255}, // Multi-band
	{159, 1, 1},	// ADDBA Extension
	{160, 1, 255},	// Next PCP List
	{161, 13, 13},	// PCP Handover
	{162, 8, 8},	// DMG Link Margin
	{163, 4, 255},	// Switching Stream
	{164, 11, 11},	// Session Transition
	{165, 0, 255},	// Dynamic Tone Pairing Report
	{166, 2, 255},	// Cluster Report
	{167, 2, 2},	// Relay Capabilities
	{168, 8, 8},	// Relay Transfer Parameter Set
	{169, 1, 1},	// BeamLink Maintenance
	{170, 7, 255},	// Mutiple MAC Sublayers
	{171, 1, 255},	// U-PID
	{172, 5, 5},	// DMG Link Adaptation Acknowledgment
	{174, 6, 6},	// MCCAOP Advertisement Overview
	{175, 17, 17},	// Quiet Period Request
	{177, 10, 10},	// Quiet Period Response
	{181, 2, 255},	// QMF Policy
	{182, 11, 15},	// ECAPC Policy
	{183, 1, 1},	// Cluster Time Offset
	{184, 1, 1},	// Intra-Access Category Priority
	{185, 2, 255},	// SCS Descriptor
	{186, 21, 255}, // QLoad Report
	{187, 1, 1},	// HCCA TXOP Update Count
	{188, 1, 255},	// Higher Layer Stream ID
	{189, 6, 6},	// GCR Group Address
	{190, 3, 3},	// Antenna Sector ID Pattern
	{191, 12, 12},	// VHT Capabilities
	{192, 5, 5},	// VHT Operation
	{193, 6, 6},	// Extended BSS Load
	{194, 3, 3},	// Wide Bandwidth Channel Switch
	{195, 2, 5},	// Transmit Power Envelope
	{196, 0, 255},	// Channel Switch Wrapper
	{197, 2, 2},	// AID
	{198, 1, 7},	// Quiet Channel
	{199, 1, 1},	// Operating Mode Notification
	{200, 1, 33},	// UPSIM
	{201, 0, 255},	// Reduced Neighbor Report
	{202, 6, 6},	// TVHT Operation
	{204, 16, 16},	// Device Location
	{205, 1, 255},	// White Space Map
	{206, 9, 9},	// Fine Timing Measurement Parameters
	{221, 1, 254},	// Vendor Specific
	{255, 1, 254},	// FTM synchronization Information, Extended Request, Estimated Service Parameters, Future Channel Guidance
	{-1, 0, 0}};

// 802.11ax
static int ie_ranges2020[260][3] = {
	{0, 0, 32},		// SSID
	{1, 1, 8},		// Supported Rates and BSS Membership Selectors
	{3, 1, 1},		// DSSS Parameter Set
	{4, 6, 6},		// CF Parameter Set
	{5, 4, 254},	// TIM
	{6, 2, 2},		// IBSS Parameter Set
	{7, 6, 254},	// Country
	{10, 0, 254},	// Request
	{11, 5, 5},		// BSS Load
	{12, 18, 18},	// EDCA Parameter Set
	{13, 55, 55},	// TSPEC
	{14, 0, 255},	// TCLAS
	{15, 14, 14},	// Schedule
	{16, 1, 253},	// Challenge text
	{32, 1, 1},		// Power Constraint
	{33, 2, 2},		// Power Capability
	{34, 0, 0},		// TPC Request
	{35, 2, 2},		// TPC Report
	{36, 2, 2},		// Supported Channels
	{37, 3, 3},		// Channel Switch Announcement
	{38, 3, 255},	// Measurement Request
	{39, 3, 255},	// Measurement Report
	{40, 6, 6},		// Quiet
	{41, 9, 253},	// IBSS DFS
	{42, 1, 1},		// ERP
	{43, 4, 4},		// TS Delay
	{44, 1, 1},		// TCLAS Processing
	{45, 26, 26},	// HT Capabilities
	{46, 1, 1},		// QoS Capability
	{48, 34, 254},	// RSN
	{50, 1, 255},	// Extended Supported Rates and BSS Membership Selectors
	{51, 1, 255},	// AP Channel Report
	{52, 13, 255},	// Neighbor Report
	{53, 1, 1},		// RCPI
	{54, 3, 3},		// Mobility Domain
	{55, 82, 255},	// Fast BSS Transition
	{56, 5, 5},		// Timeout Interval
	{57, 4, 4},		// RIC Data (RDE)
	{58, 20, 20},	// DSE Registered Location
	{59, 2, 253},	// Supported Operating Classes
	{60, 4, 4},		// Extended Channel Switch Announcement
	{61, 22, 22},	// HT Operation
	{62, 1, 1},		// Secondary Channel Offset
	{63, 1, 1},		// BSS Average Access Delay
	{64, 1, 1},		// Antenna
	{65, 1, 1},		// RSNI
	{66, 1, 255},	// Measurement Pilot Transmission
	{67, 2, 26},	// BSS Available Admission Capacity
	{68, 4, 4},		// BSS AC Access Delay
	{69, 1, 16},	// Time Advertisement
	{70, 5, 5},		// RM Enabled Capabilities
	{71, 1, 255},	// Multiple BSSID
	{72, 1, 1},		// 20/40 BSS Coexistence
	{73, 1, 255},	// 20/40 BSS Intolerant Channel Report
	{74, 14, 14},	// Overlapping BSS Scan Parameters
	{75, 1, 255},	// RIC Descriptor
	{76, 16, 16},	// Management MIC
	{78, 3, 255},	// Event Request
	{79, 3, 255},	// Event Report
	{80, 4, 255},	// Diagnostic Request
	{81, 3, 255},	// Diagnostic Report
	{82, 0, 255},	// Location Parameters
	{83, 2, 2},		// Nontransmitted BSSID Capability
	{84, 0, 255},	// SSID List
	{85, 1, 3},		// Multiple BSSID-Index
	{86, 1, 255},	// FMS Descriptor
	{87, 1, 255},	// FMS Request
	{88, 16, 255},	// FMS Response
	{89, 1, 3},		// QoS Traffic Capability
	{90, 3, 3},		// BSS Max Idle Period
	{91, 4, 255},	// TFS Request
	{92, 4, 254},	// TFS Response
	{93, 4, 4},		// WNM Sleep Mode
	{94, 1, 1},		// TIM Broadcast Request21, 0, 255}, // Vendor Specific
	{95, 1, 10},	// TIM Broadcast Response
	{96, 21, 21},	// Collocated Interference Report
	{97, 1, 255},	// Channel Usage
	{98, 1, 255},	// Time Zone
	{99, 1, 255},	// DMS Request
	{100, 1, 255},	// DMS Response
	{101, 18, 18},	// Link Identifier
	{102, 18, 18},	// Wakeup Schedule
	{104, 4, 4},	// Channel Switch Timing
	{105, 3, 3},	// PTI Control
	{106, 3, 3},	// TPU Buffer Status
	{107, 3, 11},	// Interworking
	{108, 0, 255},	// Advertisement Protocol
	{109, 1, 1},	// Expedited Bandwidth Request
	{110, 16, 58},	// QoS Map
	{111, 0, 255},	// Roaming Consortium
	{112, 8, 8},	// Emergency Alert Identifier
	{113, 7, 7},	// Mesh Configuration
	{114, 0, 32},	// Mesh ID
	{115, 1, 255},	// Mesh Link Metric Report
	{116, 14, 14},	// Congestion Notification
	{117, 3, 23},	// Mesh Peering Management
	{118, 6, 6},	// Mesh Channel Switch Parameters
	{119, 2, 2},	// Mesh Awake Window
	{120, 1, 253},	// Beacon Timing
	{121, 6, 6},	// MCCAOP Setup Request
	{122, 2, 7},	// MCCAOP Setup Reply
	{123, 2, 255},	// MCCAOP Advertisement
	{124, 1, 7},	// MCCAOP Teardown
	{125, 15, 15},	// GANN
	{126, 21, 21},	// RANN
	{127, 1, 10},	// Extended Capabilities
	{130, 37, 252}, // PREQ
	{131, 31, 37},	// PREP
	{132, 15, 249}, // PERR
	{137, 30, 255}, // PXU
	{138, 7, 7},	// PXUC
	{139, 76, 255}, // Authenticated Mesh Peering Exchange
	{140, 16, 16},	// MIC
	{141, 1, 255},	// Destination URI
	{142, 12, 255}, // U-APSD Coexistence
	{143, 8, 8},	// DMG Wakeup Schedule
	{144, 15, 255}, // Extended Schedule
	{145, 2, 254},	// STA Availability
	{146, 15, 255}, // DMG TSPEC
	{147, 6, 6},	// Next DMG ATI
	{148, 22, 22},	// DMG Capabilities
	{151, 10, 10},	// DMG Operation
	{152, 7, 7},	// DMG BSS Parameter Change
	{153, 5, 5},	// DMG Beam Refinement
	{154, 0, 255},	// Channel Measurement Feedback
	{157, 2, 2},	// Awake Window
	{158, 22, 255}, // Multi-band
	{159, 1, 1},	// ADDBA Extension
	{160, 1, 255},	// Next PCP List
	{161, 13, 13},	// PCP Handover
	{162, 8, 8},	// DMG Link Margin
	{163, 4, 255},	// Switching Stream
	{164, 11, 11},	// Session Transition
	{165, 0, 255},	// Dynamic Tone Pairing Report
	{166, 2, 255},	// Cluster Report
	{167, 2, 2},	// Relay Capabilities
	{168, 8, 8},	// Relay Transfer Parameter Set
	{169, 1, 1},	// BeamLink Maintenance
	{170, 7, 255},	// Mutiple MAC Sublayers
	{171, 1, 255},	// U-PID
	{172, 5, 5},	// DMG Link Adaptation Acknowledgment
	{174, 6, 6},	// MCCAOP Advertisement Overview
	{175, 17, 17},	// Quiet Period Request
	{177, 10, 10},	// Quiet Period Response
	{181, 2, 255},	// QMF Policy
	{182, 11, 15},	// ECAPC Policy
	{183, 1, 1},	// Cluster Time Offset
	{184, 1, 1},	// Intra-Access Category Priority
	{185, 2, 255},	// SCS Descriptor
	{186, 21, 255}, // QLoad Report
	{187, 1, 1},	// HCCA TXOP Update Count
	{188, 1, 255},	// Higher Layer Stream ID
	{189, 6, 6},	// GCR Group Address
	{190, 3, 3},	// Antenna Sector ID Pattern
	{191, 12, 12},	// VHT Capabilities
	{192, 5, 5},	// VHT Operation
	{193, 6, 6},	// Extended BSS Load
	{194, 3, 3},	// Wide Bandwidth Channel Switch
	{195, 2, 5},	// Transmit Power Envelope
	{196, 0, 255},	// Channel Switch Wrapper
	{197, 2, 2},	// AID
	{198, 1, 7},	// Quiet Channel
	{199, 1, 1},	// Operating Mode Notification
	{200, 1, 33},	// UPSIM
	{201, 0, 255},	// Reduced Neighbor Report
	{202, 6, 6},	// TVHT Operation
	{204, 16, 16},	// Device Location
	{205, 1, 255},	// White Space Map
	{206, 9, 9},	// Fine Timing Measurement Parameters
	{207, 1, 1},	// S1G Open-Loop Link Margin Index
	{208, 3, 12},	// RPS
	{209, 4, 8},	// Page Slice
	{210, 1, 16},	// AID Request
	{211, 5, 5},	// AID Response
	{212, 3, 255},	// S1G Sector Operation
	{213, 8, 8},	// S1G Beacon Compatibility
	{214, 2, 2},	// Short Beacon Interval
	{215, 1, 1},	// Change Sequence
	{216, 7, 28},	// TWT
	{217, 15, 15},	// S1G Capabilities
	{220, 2, 4},	// Subchannel Selective Transmission
	{221, 1, 254},	// Vendor Specific
	{222, 2, 3},	// Authentication Control
	{223, 1, 1},	// TSF Timer Accuracy
	{224, 1, 7},	// S1G Relay
	{225, 7, 14},	// Reachable Address
	{226, 1, 9},	// S1G Relay Discovery
	{228, 8, 248},	// AID Announcement
	{229, 2, 7},	// PV1 Probe Response Option
	{230, 4, 4},	// EL Operation
	{231, 1, 254},	// Sectorized Group ID List
	{232, 6, 6},	// S1G Operation
	{233, 1, 18},	// Header Compression
	{234, 2, 2},	// SST Operation
	{235, 2, 2},	// MAD
	{236, 1, 2},	// S1G Relay Activation
	{237, 2, 254},	// CAG Number
	{239, 1, 1},	// AP-CSN
	{240, 2, 254},	// FILS Indication
	{241, 2, 4},	// DILS
	{242, 1, 254},	// Fragment
	{244, 1, 254},	// RSN Extension
	{255, 1, 254},	// Element ID Extension present
	{-1, 0, 0}};

// Element ID Extension ID
static int eie_ranges2020[260][3] = {
	// 0 Reserved
	{1, 1, 1},	   // Association Delay Info
	{2, 2, 2},	   // FILS Request Parameters
	{3, 1, 254},   // FILS Key Confirmation
	{4, 8, 8},	   // FILS Session
	{5, 12, 254},  // FILS HLP Container
	{6, 1, 21},	   // FILS IP Address Assignment
	{7, 8, 254},   // Key Delivery
	{8, 1, 254},   // FILS Wrapped Data
	{9, 4, 4},	   // FTM Synchronization Information
	{10, 1, 254},  // Extended Request
	{11, 3, 12},   // Estimated Service Parameters Inbound
	{12, 2, 254},  // FILS Public Key
	{13, 16, 16},  // FILS Nonce
	{14, 4, 254},  // Future Channel Guidance
	{15, 1, 254},  // Service Hint
	{16, 6, 254},  // Service Hash
	{17, 12, 12},  // CDMG Capabilities
	{18, 20, 20},  // Dynamic Bandwidth Control
	{19, 19, 254}, // CDMG Extended Schedule
	{20, 5, 254},  // SSW Report
	{21, 11, 11},  // Cluster Probe
	{22, 13, 22},  // Extended Cluster Report
	{23, 11, 11},  // Cluster Switch Announcement
	{24, 2, 2},	   // Enhanced Beam Tracking
	{25, 11, 254}, // SPSH Report
	{26, 2, 2},	   // Clustering Interference Assessment
	{27, 21, 21},  // CMMG Capabilities
	{28, 3, 3},	   // CMMG Operation
	{29, 2, 2},	   // CMMG Operating Mode Notification
	{30, 8, 8},	   // CMMG Link Margin
	{31, 5, 5},	   // CMMG Link Adaptation
	// 32 Reserved
	{33, 1, 254}, // Password identifier
	{34, 3, 3},	  // GLK-GCR Parameter
	// 35-39 Reserved
	{40, 1, 254}, // GAS Extension
	// 41-43 Reserved
	{44, 1, 254}, // Vendor Specific Request Element
	// 45-51 Reserved
	{52, 3, 3}, // Max Channel Switch Time
	{53, 1, 5}, // Estimated Service Parameters Outbound
	{54, 3, 6}, // Operating Channel Information
	// 55 Reserved
	{56, 1, 254}, // Non-Inheritance
	// 57-87 Reserved
	{88, 7, 254}, // MSCS Descriptor element
	{89, 1, 254}, // TCLAS Mask
	{90, 4, 4},	  // Supplemental Class 2 Capabilities
	{91, 8, 8},	  // OCT Source
	{92, 1, 254}, // Rejected Groups
	{93, 1, 254}, // Anti-Clogging Token Container
	// 94-255 Reserved
	{-1, 0, 0}};

typedef struct _default_ie
{
	uint8_t len;
	char *ie;
} default_ie;

static default_ie default_ie_data[256] = {
	/* 0 ssid */ {12, "\x00\x0A\x77\x66\x5F\x74\x65\x73\x74\x69\x6E\x67"},
	/* 1 */ {10, "\x01\x08\x82\x84\x8b\x96\x12\x24\x48\x6c"},
	/* 2 */ {0, ""},
	/* 3 */ {3, "\x03\x01\x0b"}, // 11
	/* 4 */ {0, ""},
	/* 5 */ {6, "\x05\x04\x00\x01\x00\x18"},
	/* 6 */ {0, ""},
	/* 7 */ {0, ""},
	/* 8 */ {0, ""},
	/* 9 */ {0, ""},
	/* 10 */ {0, ""},
	/* 11 */ {7, "\x0b\x05\x04\x00\x33\x12\x7a"},
	/* 12 */ {0, ""},
	/* 13 */ {0, ""},
	/* 14 */ {0, ""},
	/* 15 */ {0, ""},
	/* 16 */ {128, "\xcc\x66\x33\x99\xcb\xd0\x42\xeb\x5c\x1e\xf1\x8a\xae\x73\x67\xc5\xd7\x46\xc8\xbe\xfa\xeb\xa4\x23\xe6\xc9\x4a\x57\x42\x16\xb6\xb0\x78\xc2\xeb\x52\x4b\x58\x3b\x20\x04\xda\x2c\x9f\x06\x35\xa9\xb2\x90\x7a\xea\x56\xb0\x80\xfd\x10\x86\xcc\x9a\xd6\xb6\xb7\xb9\xc8\xba\x16\xa7\x3d\xe8\x45\xd0\x83\xe3\x1e\x0a\x56\x4e\x77\xbe\x0b\xd0\xbf\x03\xe1\xf3\x9e\x0f\x7d\x11\x74\xa7\x3d\xe8\x41\x0f\xc3\xf3\x9c\x19\xc9\xb4\xa2\xef\x7a\xd6\x4f\x7f\x01\x0b\x5d\x77\x21\x0e\x8d\x90\x7f\x05\x2f\x7c\xe2\x13\x9c\xe7\x39\xcb\xd1\xb8\xc1"},
	/* 17 */ {0, ""},
	/* 18 */ {0, ""},
	/* 19 */ {0, ""},
	/* 20 */ {0, ""},
	/* 21 */ {0, ""},
	/* 22 */ {0, ""},
	/* 23 */ {0, ""},
	/* 24 */ {0, ""},
	/* 25 */ {0, ""},
	/* 26 */ {0, ""},
	/* 27 */ {0, ""},
	/* 28 */ {0, ""},
	/* 29 */ {0, ""},
	/* 30 */ {0, ""},
	/* 31 */ {0, ""},
	/* 32 */ {6, "\x32\x04\x30\x48\x60\x6c"},
	/* 33 */ {0, ""},
	/* 34 */ {0, ""},
	/* 35 */ {0, ""},
	/* 36 */ {0, ""},
	/* 37 */ {0, ""},
	/* 38 */ {0, ""},
	/* 39 */ {0, ""},
	/* 40 */ {0, ""},
	/* 41 */ {0, ""},
	/* 42 */ {3, "\x2a\x01\x00"},
	/* 43 */ {0, ""},
	/* 44 */ {0, ""},
	/* 45 */ {28, "\x2d\x1a\xef\x09\x17\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"},
	/* 46 */ {0, ""},
	/* 47 */ {0, ""},
	/* 48 */ {22, "\x30\x14\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x02\x00\x00"},
	/* 49 */ {0, ""},
	/* 50 */ {6, "\x32\x04\x0c\x18\x30\x60"},
	/* 51 */ {0, ""},
	/* 52 */ {0, ""},
	/* 53 */ {0, ""},
	/* 54 */ {0, ""},
	/* 55 */ {0, ""},
	/* 56 */ {0, ""},
	/* 57 */ {0, ""},
	/* 58 */ {0, ""},
	/* 59 */ {0, ""},
	/* 60 */ {0, ""},
	/* 61 */ {24, "\x3d\x16\x30\x07\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"},
	/* 62 */ {0, ""},
	/* 63 */ {0, ""},
	/* 64 */ {0, ""},
	/* 65 */ {0, ""},
	/* 66 */ {0, ""},
	/* 67 */ {0, ""},
	/* 68 */ {0, ""},
	/* 69 */ {0, ""},
	/* 70 */ {0, ""},
	/* 71 */ {0, ""},
	/* 72 */ {0, ""},
	/* 73 */ {0, ""},
	/* 74 */ {0, ""},
	/* 75 */ {0, ""},
	/* 76 */ {0, ""},
	/* 77 */ {0, ""},
	/* 78 */ {0, ""},
	/* 79 */ {0, ""},
	/* 80 */ {0, ""},
	/* 81 */ {0, ""},
	/* 82 */ {0, ""},
	/* 83 */ {0, ""},
	/* 84 */ {0, ""},
	/* 85 */ {0, ""},
	/* 86 */ {0, ""},
	/* 87 */ {0, ""},
	/* 88 */ {0, ""},
	/* 89 */ {0, ""},
	/* 90 */ {0, ""},
	/* 91 */ {0, ""},
	/* 92 */ {0, ""},
	/* 93 */ {0, ""},
	/* 94 */ {0, ""},
	/* 95 */ {0, ""},
	/* 96 */ {0, ""},
	/* 97 */ {0, ""},
	/* 98 */ {0, ""},
	/* 99 */ {0, ""},
	/* 100 */ {0, ""},
	/* 101 */ {0, ""},
	/* 102 */ {0, ""},
	/* 103 */ {0, ""},
	/* 104 */ {0, ""},
	/* 105 */ {0, ""},
	/* 106 */ {0, ""},
	/* 107 */ {0, ""},
	/* 108 */ {0, ""},
	/* 109 */ {0, ""},
	/* 110 */ {0, ""},
	/* 111 */ {0, ""},
	/* 112 */ {0, ""},
	/* 113 */ {0, ""},
	/* 114 */ {0, ""},
	/* 115 */ {0, ""},
	/* 116 */ {0, ""},
	/* 117 */ {0, ""},
	/* 118 */ {0, ""},
	/* 119 */ {0, ""},
	/* 120 */ {0, ""},
	/* 121 */ {0, ""},
	/* 122 */ {0, ""},
	/* 123 */ {0, ""},
	/* 124 */ {0, ""},
	/* 125 */ {0, ""},
	/* 126 */ {0, ""},
	/* 127 */ {10, "\x7f\x08\x04\x00\x00\x00\x00\x00\x00\x40"},
	/* 128 */ {0, ""},
	/* 129 */ {0, ""},
	/* 130 */ {0, ""},
	/* 131 */ {0, ""},
	/* 132 */ {0, ""},
	/* 133 */ {0, ""},
	/* 134 */ {0, ""},
	/* 135 */ {0, ""},
	/* 136 */ {0, ""},
	/* 137 */ {0, ""},
	/* 138 */ {0, ""},
	/* 139 */ {0, ""},
	/* 140 */ {0, ""},
	/* 141 */ {0, ""},
	/* 142 */ {0, ""},
	/* 143 */ {0, ""},
	/* 144 */ {0, ""},
	/* 145 */ {0, ""},
	/* 146 */ {0, ""},
	/* 147 */ {0, ""},
	/* 148 */ {0, ""},
	/* 149 */ {0, ""},
	/* 150 */ {0, ""},
	/* 151 */ {0, ""},
	/* 152 */ {0, ""},
	/* 153 */ {0, ""},
	/* 154 */ {0, ""},
	/* 155 */ {0, ""},
	/* 156 */ {0, ""},
	/* 157 */ {0, ""},
	/* 158 */ {0, ""},
	/* 159 */ {0, ""},
	/* 160 */ {0, ""},
	/* 161 */ {0, ""},
	/* 162 */ {0, ""},
	/* 163 */ {0, ""},
	/* 164 */ {0, ""},
	/* 165 */ {0, ""},
	/* 166 */ {0, ""},
	/* 167 */ {0, ""},
	/* 168 */ {0, ""},
	/* 169 */ {0, ""},
	/* 170 */ {0, ""},
	/* 171 */ {0, ""},
	/* 172 */ {0, ""},
	/* 173 */ {0, ""},
	/* 174 */ {0, ""},
	/* 175 */ {0, ""},
	/* 176 */ {0, ""},
	/* 177 */ {0, ""},
	/* 178 */ {0, ""},
	/* 179 */ {0, ""},
	/* 180 */ {0, ""},
	/* 181 */ {0, ""},
	/* 182 */ {0, ""},
	/* 183 */ {0, ""},
	/* 184 */ {0, ""},
	/* 185 */ {0, ""},
	/* 186 */ {0, ""},
	/* 187 */ {0, ""},
	/* 188 */ {0, ""},
	/* 189 */ {0, ""},
	/* 190 */ {0, ""},
	/* 191 */ {0, ""},
	/* 192 */ {0, ""},
	/* 193 */ {0, ""},
	/* 194 */ {0, ""},
	/* 195 */ {0, ""},
	/* 196 */ {0, ""},
	/* 197 */ {0, ""},
	/* 198 */ {0, ""},
	/* 199 */ {0, ""},
	/* 200 */ {0, ""},
	/* 201 */ {0, ""},
	/* 202 */ {0, ""},
	/* 203 */ {0, ""},
	/* 204 */ {0, ""},
	/* 205 */ {0, ""},
	/* 206 */ {0, ""},
	/* 207 */ {0, ""},
	/* 208 */ {0, ""},
	/* 209 */ {0, ""},
	/* 210 */ {0, ""},
	/* 211 */ {0, ""},
	/* 212 */ {0, ""},
	/* 213 */ {0, ""},
	/* 214 */ {0, ""},
	/* 215 */ {0, ""},
	/* 216 */ {0, ""},
	/* 217 */ {0, ""},
	/* 218 */ {0, ""},
	/* 219 */ {0, ""},
	/* 220 */ {0, ""},
	/* 221 */ {9, "\xdd\x07\x00\x0c\x43\x03\x00\x00\x00"},
	/* 222 */ {0, ""},
	/* 223 */ {0, ""},
	/* 224 */ {0, ""},
	/* 225 */ {0, ""},
	/* 226 */ {0, ""},
	/* 227 */ {0, ""},
	/* 228 */ {0, ""},
	/* 229 */ {0, ""},
	/* 230 */ {0, ""},
	/* 231 */ {0, ""},
	/* 232 */ {0, ""},
	/* 233 */ {0, ""},
	/* 234 */ {0, ""},
	/* 235 */ {0, ""},
	/* 236 */ {0, ""},
	/* 237 */ {0, ""},
	/* 238 */ {0, ""},
	/* 239 */ {0, ""},
	/* 240 */ {0, ""},
	/* 241 */ {0, ""},
	/* 242 */ {0, ""},
	/* 243 */ {0, ""},
	/* 244 */ {0, ""},
	/* 245 */ {0, ""},
	/* 246 */ {0, ""},
	/* 247 */ {0, ""},
	/* 248 */ {0, ""},
	/* 249 */ {0, ""},
	/* 250 */ {0, ""},
	/* 251 */ {0, ""},
	/* 252 */ {0, ""},
	/* 253 */ {0, ""},
	/* 254 */ {0, ""},
	/* 255 */ {0, ""}

};

volatile IEEE_80211_VERSION g_current_version = IEEE_80211_UNKNOWN;

int add_attribute_tlv_fuzzing_data(struct packet *pkt, struct vendor_specific_ie *vsi, uint8_t id)
{
	struct attribute_tlv atlv = {0};
	FUZZING_VALUE_TYPE value_type;
	int rlen = 0;

	atlv.type = id;
	if (0 == fuzzing_opt.seed)
		srandom(time(NULL) + pkt->len);

	atlv.length = random() % 255;

	if (0 == fuzzing_opt.seed)
		srandom(time(NULL) + atlv.length);

	value_type = random() % (FUZZING_VALUE_END - 1) + 1;
	rlen = atlv.length; // random() % 256;

	generate_random_data(atlv.value, rlen, value_type);

	memcpy(pkt->data + pkt->len, &atlv, 3);
	memcpy(pkt->data + pkt->len + 3, atlv.value, rlen);
	if (vsi)
		vsi->length += (rlen + 3);
	pkt->len += (rlen + 3);

	return (rlen + 3);
}

int add_data_element_tlv_fuzzing_data(struct packet *pkt, struct vendor_specific_ie *vsi, uint16_t id)
{
	struct data_element_tlv detlv = {0};
	FUZZING_VALUE_TYPE value_type;
	int rlen = 0;

	detlv.type = id;
	if (0 == fuzzing_opt.seed)
		srandom(time(NULL) + pkt->len);

	detlv.length = random() % 255;

	if (0 == fuzzing_opt.seed)
		srandom(time(NULL) + detlv.length);

	value_type = random() % (FUZZING_VALUE_END - 1) + 1;
	rlen = detlv.length; // random() % 256;
	generate_random_data(detlv.value, rlen, value_type);

	memcpy(pkt->data + pkt->len, &detlv, 4);
	memcpy(pkt->data + pkt->len + 4, &detlv, rlen);
	if (vsi)
		vsi->length += (rlen + 4);
	pkt->len += (rlen + 4);

	return (rlen + 4);
}

void add_ie_data(struct packet *pkt, uint8_t id, FUZZING_TYPE fuzzing_type, uint8_t *specific_data, int specific_data_len)
{
	struct ie_data iedata = {0};

	if (0 == fuzzing_opt.seed)
		srandom(time(NULL) + pkt->len);

	iedata = get_ie_data_by_fuzzing_type(IEEE_80211_2020, id, fuzzing_type, random() % (FUZZING_VALUE_END - 1) + 1, specific_data, specific_data_len);
	memcpy(pkt->data + pkt->len, iedata.data, iedata.length);
	pkt->len += iedata.length;
}

void add_default_ie_data(struct packet *pkt, uint8_t id)
{
	if (!pkt)
		return;

	memcpy(pkt->data + pkt->len, default_ie_data[id].ie, default_ie_data[id].len);
	pkt->len += default_ie_data[id].len;
}

struct ie_data get_ie_data_by_fuzzing_type(IEEE_80211_VERSION ieee80211_version, uint8_t id, FUZZING_TYPE fuzzing_type, FUZZING_VALUE_TYPE value_type, uint8_t *specific_data, int specific_data_len)
{
	struct ie_data ie_d = {0};
	struct ie_common_data ie_cd = {0};
	uint8_t max_len, min_len;
	static int swch = 1;
	int rlen = 0;

	ie_cd.id = id;
	if (ieee80211_version == IEEE_80211_1999)
	{
		min_len = ie_ranges1999[id][1];
		max_len = ie_ranges1999[id][2];
	}
	else if (ieee80211_version == IEEE_80211_2007)
	{
		min_len = ie_ranges2007[id][1];
		max_len = ie_ranges2007[id][2];
	}
	else if (ieee80211_version == IEEE_80211_2012)
	{
		min_len = ie_ranges2012[id][1];
		max_len = ie_ranges2012[id][2];
	}
	else if (ieee80211_version == IEEE_80211_2016)
	{
		min_len = ie_ranges2016[id][1];
		max_len = ie_ranges2016[id][2];
	}
	else if (ieee80211_version == IEEE_80211_2020)
	{
		min_len = ie_ranges2020[id][1];
		max_len = ie_ranges2020[id][2];
	}
	else
	{
		min_len = ie_ranges2020[id][1];
		max_len = ie_ranges2020[id][2];
	}

	switch (fuzzing_type)
	{
	case NOT_PRESENT:
		break;
	case REPEATED:
		if (0 == fuzzing_opt.seed)
			srandom(time(NULL) + swch);

		ie_cd.length = min_len + (random() % (max_len - min_len + 1));
		break;
	case ALL_BITS_ZERO:
		ie_cd.length = 0x00;
		break;
	case MIN_SUB_1:
		if (min_len > 0)
			ie_cd.length = min_len - 1;
		else
			ie_cd.length = min_len;
		break;
	case MIN:
		ie_cd.length = min_len;
		break;
	case MIN_ADD_1:
		ie_cd.length = min_len + 1;
		break;
	case RANDOM_VALUE:
		if (0 == fuzzing_opt.seed)
			srandom(time(NULL) + swch);

		ie_cd.length = min_len + (random() % (max_len - min_len + 1));
		break;
	case SPECIFIC_VALUE:
		ie_cd.length = specific_data_len;
		break;
	case MAX_SUB_1:
		if (max_len > 0)
			ie_cd.length = max_len - 1;
		else
			ie_cd.length = max_len;
		break;
	case MAX:
		ie_cd.length = max_len;
		break;
	case MAX_ADD_1:
		if (max_len < 255)
			ie_cd.length = max_len + 1;
		else
			ie_cd.length = max_len;
		break;
	case ALL_BITS_ONE:
		ie_cd.length = 0xFF;
		break;
	default:
		break;
	}

	swch++;
	if (swch >= 5)
		swch = 1;

	if (fuzzing_type != SPECIFIC_VALUE)
	{
		if (fuzzing_type != RANDOM_VALUE)
		{
			if (0 == fuzzing_opt.seed)
				srandom(time(NULL));

			rlen = random() % 256;
			generate_random_data(ie_cd.data, rlen, value_type);
		}
		else
			generate_random_data(ie_cd.data, ie_cd.length, value_type);
	}

	if (fuzzing_type == REPEATED)
	{
		ie_d.length = (2 + ie_cd.length) * 2;
		memcpy(ie_d.data, &ie_cd.id, 1);
		memcpy(ie_d.data + 1, &ie_cd.length, 1);
		memcpy(ie_d.data + 2, ie_cd.data, ie_cd.length);

		memcpy(ie_d.data + 2 + ie_d.length, &ie_cd.id, 1);
		memcpy(ie_d.data + 2 + ie_d.length + 1, &ie_cd.length, 1);
		memcpy(ie_d.data + 2 + ie_d.length + 2, ie_cd.data, ie_cd.length);
	}
	else
	{
		if (fuzzing_type == RANDOM_VALUE)
		{
			ie_d.length = 2 + rlen;
			memcpy(ie_d.data, &ie_cd.id, 1);
			memcpy(ie_d.data + 1, &ie_cd.length, 1);
			memcpy(ie_d.data + 2, ie_cd.data, rlen);
		}
		else
		{
			ie_d.length = 2 + ie_cd.length;
			memcpy(ie_d.data, &ie_cd.id, 1);
			memcpy(ie_d.data + 1, &ie_cd.length, 1);
			if (fuzzing_type == SPECIFIC_VALUE)
			{
				memcpy(ie_d.data + 2, specific_data, ie_cd.length);
			}
			else
			{
				memcpy(ie_d.data + 2, ie_cd.data, ie_cd.length);
			}
		}
	}

	// dumphex(ie_cd.data, ie_cd.length);
	fuzz_logger_log(FUZZ_LOG_DEBUG, "get_ie_data_by_fuzzing_type -> id: %d, iedata.length = %d, fuzzing_type: %d, fuzzing_value_type: %d", id, ie_d.length, fuzzing_type, value_type);

	return ie_d;
}

struct ie_data get_ie_ex_data_by_fuzzing_type(IEEE_80211_VERSION ieee80211_version,
											  uint8_t id,
											  uint8_t ex_id,
											  FUZZING_TYPE fuzzing_type,
											  FUZZING_VALUE_TYPE value_type,
											  uint8_t *specific_data,
											  int specific_data_len)
{
	struct ie_data ie_d = {0};
	struct ie_common_data ie_cd = {0};
	uint8_t max_len, min_len;
	static int swch = 1;
	int rlen = 0;

	ie_cd.id = id;
	if (id != 255)
	{
		if (ieee80211_version == IEEE_80211_1999)
		{
			min_len = ie_ranges1999[id][1];
			max_len = ie_ranges1999[id][2];
		}
		else if (ieee80211_version == IEEE_80211_2007)
		{
			min_len = ie_ranges2007[id][1];
			max_len = ie_ranges2007[id][2];
		}
		else if (ieee80211_version == IEEE_80211_2012)
		{
			min_len = ie_ranges2012[id][1];
			max_len = ie_ranges2012[id][2];
		}
		else if (ieee80211_version == IEEE_80211_2016)
		{
			min_len = ie_ranges2016[id][1];
			max_len = ie_ranges2016[id][2];
		}
		else if (ieee80211_version == IEEE_80211_2020)
		{
			min_len = ie_ranges2020[id][1];
			max_len = ie_ranges2020[id][2];
		}
		else
		{
			min_len = ie_ranges2020[id][1];
			max_len = ie_ranges2020[id][2];
		}
	}
	else
	{
		min_len = eie_ranges2020[id][1];
		max_len = eie_ranges2020[id][2];
	}

	switch (fuzzing_type)
	{
	case NOT_PRESENT:
		break;
	case REPEATED:
		if (0 == fuzzing_opt.seed)
			srandom(time(NULL) + swch);

		ie_cd.length = min_len + (random() % (max_len - min_len + 1));
		break;
	case ALL_BITS_ZERO:
		ie_cd.length = 0x00;
		break;
	case MIN_SUB_1:
		if (min_len > 0)
			ie_cd.length = min_len - 1;
		else
			ie_cd.length = min_len;
		break;
	case MIN:
		ie_cd.length = min_len;
		break;
	case MIN_ADD_1:
		ie_cd.length = min_len + 1;
		break;
	case RANDOM_VALUE:
		if (0 == fuzzing_opt.seed)
			srandom(time(NULL) + swch);

		ie_cd.length = min_len + (random() % (max_len - min_len + 1));
		break;
	case SPECIFIC_VALUE:
		ie_cd.length = specific_data_len;
		break;
	case MAX_SUB_1:
		if (max_len > 0)
			ie_cd.length = max_len - 1;
		else
			ie_cd.length = max_len;
		break;
	case MAX:
		ie_cd.length = max_len;
		break;
	case MAX_ADD_1:
		if (max_len < 255)
			ie_cd.length = max_len + 1;
		else
			ie_cd.length = max_len;
		break;
	case ALL_BITS_ONE:
		ie_cd.length = 0xFF;
		break;
	default:
		break;
	}

	swch++;
	if (swch >= 5)
		swch = 1;

	if (fuzzing_type != SPECIFIC_VALUE)
	{
		if (fuzzing_type != RANDOM_VALUE)
		{
			if (0 == fuzzing_opt.seed)
				srandom(time(NULL));

			rlen = random() % 256;
			generate_random_data(ie_cd.data, rlen, value_type);
		}
		else
			generate_random_data(ie_cd.data, ie_cd.length, value_type);
	}

	if (fuzzing_type == REPEATED)
	{
		if (id != 255)
		{
			ie_d.length = (2 + ie_cd.length) * 2;
			memcpy(ie_d.data, &ie_cd.id, 1);
			memcpy(ie_d.data + 1, &ie_cd.length, 1);
			memcpy(ie_d.data + 2, ie_cd.data, ie_cd.length);

			memcpy(ie_d.data + 2 + ie_d.length, &ie_cd.id, 1);
			memcpy(ie_d.data + 2 + ie_d.length + 1, &ie_cd.length, 1);
			memcpy(ie_d.data + 2 + ie_d.length + 2, ie_cd.data, ie_cd.length);
		}
		else
		{
			ie_d.length = (3 + ie_cd.length) * 2;
			memcpy(ie_d.data, &ie_cd.id, 1);
			memcpy(ie_d.data + 1, &ie_cd.length, 1);
			memcpy(ie_d.data + 2, &ex_id, 1);
			memcpy(ie_d.data + 3, ie_cd.data, ie_cd.length);

			memcpy(ie_d.data + 3 + ie_d.length, &ie_cd.id, 1);
			memcpy(ie_d.data + 3 + ie_d.length + 1, &ie_cd.length, 1);
			memcpy(ie_d.data + 3 + ie_d.length + 2, &ex_id, 1);
			memcpy(ie_d.data + 3 + ie_d.length + 3, ie_cd.data, ie_cd.length);
		}
	}
	else
	{
		if (fuzzing_type == RANDOM_VALUE)
		{
			if (id != 255)
			{
				ie_d.length = 2 + rlen;
				memcpy(ie_d.data, &ie_cd.id, 1);
				memcpy(ie_d.data + 1, &ie_cd.length, 1);
				memcpy(ie_d.data + 2, ie_cd.data, rlen);
			}
			else
			{
				ie_d.length = 3 + rlen;
				memcpy(ie_d.data, &ie_cd.id, 1);
				memcpy(ie_d.data + 1, &ie_cd.length, 1);
				memcpy(ie_d.data + 2, &ex_id, 1);
				memcpy(ie_d.data + 3, ie_cd.data, rlen);
			}
		}
		else
		{
			if (id != 255)
			{
				ie_d.length = 2 + ie_cd.length;
				memcpy(ie_d.data, &ie_cd.id, 1);
				memcpy(ie_d.data + 1, &ie_cd.length, 1);
				if (fuzzing_type == SPECIFIC_VALUE)
				{
					memcpy(ie_d.data + 2, specific_data, ie_cd.length);
				}
				else
				{
					memcpy(ie_d.data + 2, ie_cd.data, ie_cd.length);
				}
			}
			else
			{
				ie_d.length = 3 + ie_cd.length;
				memcpy(ie_d.data, &ie_cd.id, 1);
				memcpy(ie_d.data + 1, &ie_cd.length, 1);
				memcpy(ie_d.data + 2, &ex_id, 1);
				if (fuzzing_type == SPECIFIC_VALUE)
				{
					memcpy(ie_d.data + 3, specific_data, ie_cd.length);
				}
				else
				{
					memcpy(ie_d.data + 3, ie_cd.data, ie_cd.length);
				}
			}
		}
	}

	// dumphex(ie_cd.data, ie_cd.length);
	fuzz_logger_log(FUZZ_LOG_DEBUG, "get_ie_data_by_fuzzing_type -> id: %d, iedata.length = %d, fuzzing_type: %d, fuzzing_value_type: %d", id, ie_d.length, fuzzing_type, value_type);

	return ie_d;
}

void create_frame_fuzzing_ie(struct packet *pkt,
							 char *frame_name,
							 uint8_t frame_ies[],
							 int *ieee_ver,
							 int *ieee_id,
							 uint8_t frame_ies_ext[],
							 int *ies_ext_id,
							 FUZZING_TYPE *fuzzing_step,
							 FUZZING_VALUE_TYPE *fuzzing_value_step)
{
	struct ie_data iedata = {0};

	if (frame_ies[0] == 0xff)
	{
		return;
	}

	if (*ieee_ver == 1)
	{
		*ieee_ver = 0;
		*ieee_id = 0;
		*ies_ext_id = 0;

		*fuzzing_step = NOT_PRESENT;
		*fuzzing_value_step = VALUE_ALL_BITS_ZERO;
	}

	if (frame_ies && ieee_id && 0 == get_ie_status(frame_ies[*ieee_id], 0)) // disable
	{
		*ieee_id += 1;
		*fuzzing_step = NOT_PRESENT;
		return;
	}
	else
	{
		if (frame_ies_ext && ies_ext_id && 0 == get_ie_status(frame_ies_ext[*ies_ext_id], 0))
		{
			*ies_ext_id += 1;
			*fuzzing_step = NOT_PRESENT;
			return;
		}
	}

	if (*ieee_ver == 0 && frame_ies[0] != 0xff)
	{
		if (frame_ies[*ieee_id] == 255)
		{
			if (frame_ies_ext && frame_ies_ext[0] != 0xff)
			{
				fuzz_logger_log(FUZZ_LOG_DEBUG, "%s testing(ieee80211) ==> ie extension(%d-%d) step: %d-%d", frame_name, frame_ies[*ieee_id], frame_ies_ext[*ies_ext_id], *fuzzing_step, *fuzzing_value_step);
				fuzzing_opt.current_ie = frame_ies[*ieee_id];
				fuzzing_opt.current_ie_ext = frame_ies_ext[*ies_ext_id];
				fuzzing_opt.fuzzing_step = *fuzzing_step;
				fuzzing_opt.fuzzing_value_step = *fuzzing_value_step;

				iedata = get_ie_ex_data_by_fuzzing_type(IEEE_80211_2020, frame_ies[*ieee_id], frame_ies_ext[*ies_ext_id], *fuzzing_step, *fuzzing_value_step, NULL, 0);
				memcpy(pkt->data + pkt->len, iedata.data, iedata.length);
				pkt->len += iedata.length;
			}
		}
		else
		{
			fuzz_logger_log(FUZZ_LOG_DEBUG, "%s testing(ieee80211) ==> ie(%d) step: %d-%d", frame_name, frame_ies[*ieee_id], *fuzzing_step, *fuzzing_value_step);
			fuzzing_opt.current_ie = frame_ies[*ieee_id];
			fuzzing_opt.current_ie_ext = 0;
			fuzzing_opt.fuzzing_step = *fuzzing_step;
			fuzzing_opt.fuzzing_value_step = *fuzzing_value_step;

			iedata = get_ie_data_by_fuzzing_type(IEEE_80211_2020, frame_ies[*ieee_id], *fuzzing_step, *fuzzing_value_step, NULL, 0);
			memcpy(pkt->data + pkt->len, iedata.data, iedata.length);
			pkt->len += iedata.length;
		}

		if (*fuzzing_value_step + 1 == FUZZING_VALUE_END)
		{
			*fuzzing_value_step = VALUE_ALL_BITS_ZERO;

			if (*fuzzing_step + 1 == FUZZING_END)
			{
				*fuzzing_step = NOT_PRESENT;

				if (frame_ies_ext[*ies_ext_id + 1] != 0)
				{
					*ies_ext_id += 1;
				}
				else
				{
					*ieee_id += 1;
					*ies_ext_id = 0;
				}
			}
			else
			{
				*fuzzing_step += 1;
			}

			if (frame_ies[*ieee_id] == 0 && *ieee_id != 0) // array end
			{
				*ieee_ver = 1;
			}
		}
		else
		{
			*fuzzing_value_step += 1;
		}
	}
}

void create_frame_ies(struct packet *pkt,
					  char *frame_name,
					  uint8_t frame_ie_ieee1999[],
					  uint8_t frame_ie_ieee2007[],
					  uint8_t frame_ie_ieee2012[],
					  uint8_t frame_ie_ieee2016[],
					  int *ieee1999,
					  int *ieee1999_id,
					  int *ieee2007,
					  int *ieee2007_id,
					  int *ieee2012,
					  int *ieee2012_id,
					  int *ieee2016,
					  int *ieee2016_id,
					  FUZZING_TYPE *fuzzing_step,
					  FUZZING_VALUE_TYPE *fuzzing_value_step)
{
	struct ie_data iedata = {0};

	if (frame_ie_ieee1999[0] == 0xff)
	{
		*ieee1999 = 1;
	}
	if (frame_ie_ieee2007[0] == 0xff)
	{
		*ieee2007 = 1;
	}
	if (frame_ie_ieee2012[0] == 0xff)
	{
		*ieee2012 = 1;
	}
	if (frame_ie_ieee2016[0] == 0xff)
	{
		*ieee2016 = 1;
	}

	if (*ieee1999 == 1 && *ieee2007 == 1 && *ieee2012 == 1 && *ieee2016 == 1)
	{
		*ieee1999 = 0;
		*ieee1999_id = 0;

		*ieee2007 = 0;
		*ieee2007_id = 0;

		*ieee2012 = 0;
		*ieee2012_id = 0;

		*ieee2016 = 0;
		*ieee2016_id = 0;

		*fuzzing_step = NOT_PRESENT;
		*fuzzing_value_step = VALUE_ALL_BITS_ZERO;
	}

	if (*ieee1999 == 0 && frame_ie_ieee1999[0] != 0xff)
	{
		fuzz_logger_log(FUZZ_LOG_DEBUG, "%s testing(ieee80211-) ==> ie(%d) step: %d-%d", frame_name, frame_ie_ieee1999[*ieee1999_id], *fuzzing_step, *fuzzing_value_step);

		iedata = get_ie_data_by_fuzzing_type(IEEE_80211_1999, frame_ie_ieee1999[*ieee1999_id], *fuzzing_step, *fuzzing_value_step, NULL, 0);
		memcpy(pkt->data + pkt->len, iedata.data, iedata.length);
		pkt->len += iedata.length;

		if (*fuzzing_value_step + 1 == FUZZING_VALUE_END)
		{
			*fuzzing_value_step = VALUE_ALL_BITS_ZERO;

			if (*fuzzing_step + 1 == FUZZING_END)
			{
				*ieee1999_id += 1;
				*fuzzing_step = NOT_PRESENT;
			}
			else
			{
				*fuzzing_step += 1;
			}

			if (frame_ie_ieee1999[*ieee1999_id] == 0 && *ieee1999_id != 0) // array end
			{
				*ieee1999 = 1;
			}
		}
		else
		{
			*fuzzing_value_step += 1;
		}
	}
	else if (*ieee2007 == 0 && frame_ie_ieee2007[0] != 0xff)
	{
		fuzz_logger_log(FUZZ_LOG_DEBUG, "%s testing(ieee80211-) ==> ie(%d) step: %d-%d", frame_name, frame_ie_ieee2007[*ieee2007_id], *fuzzing_step, *fuzzing_value_step);

		iedata = get_ie_data_by_fuzzing_type(IEEE_80211_2007, frame_ie_ieee2007[*ieee2007_id], *fuzzing_step, *fuzzing_value_step, NULL, 0);
		memcpy(pkt->data + pkt->len, iedata.data, iedata.length);
		pkt->len += iedata.length;

		if (*fuzzing_value_step + 1 == FUZZING_VALUE_END)
		{
			*fuzzing_value_step = VALUE_ALL_BITS_ZERO;

			if (*fuzzing_step + 1 == FUZZING_END)
			{
				*ieee2007_id += 1;
				*fuzzing_step = NOT_PRESENT;
			}
			else
			{
				*fuzzing_step += 1;
			}

			if (frame_ie_ieee2007[*ieee2007_id] == 0 && *ieee2007_id != 0) // array end
			{
				*ieee2007 = 1;
			}
		}
		else
		{
			*fuzzing_value_step += 1;
		}
	}
	else if (*ieee2012 == 0 && frame_ie_ieee2012[0] != 0xff)
	{
		fuzz_logger_log(FUZZ_LOG_DEBUG, "%s testing(ieee80211-) ==> ie(%d) step: %d-%d", frame_name, frame_ie_ieee2012[*ieee2012_id], *fuzzing_step, *fuzzing_value_step);

		iedata = get_ie_data_by_fuzzing_type(IEEE_80211_2012, frame_ie_ieee2012[*ieee2012_id], *fuzzing_step, *fuzzing_value_step, NULL, 0);
		memcpy(pkt->data + pkt->len, iedata.data, iedata.length);
		pkt->len += iedata.length;

		if (*fuzzing_value_step + 1 == FUZZING_VALUE_END)
		{
			*fuzzing_value_step = VALUE_ALL_BITS_ZERO;

			if (*fuzzing_step + 1 == FUZZING_END)
			{
				*ieee2012_id += 1;
				*fuzzing_step = NOT_PRESENT;
			}
			else
			{
				*fuzzing_step += 1;
			}

			if (frame_ie_ieee2012[*ieee2012_id] == 0 && *ieee2012_id != 0) // array end
			{
				*ieee2012 = 1;
			}
		}
		else
		{
			*fuzzing_value_step += 1;
		}
	}
	else if (*ieee2016 == 0 && frame_ie_ieee2016[0] != 0xff)
	{
		fuzz_logger_log(FUZZ_LOG_DEBUG, "%s testing(ieee80211-) ==> ie(%d) step: %d-%d", frame_name, frame_ie_ieee2016[*ieee2016_id], *fuzzing_step, *fuzzing_value_step);

		iedata = get_ie_data_by_fuzzing_type(IEEE_80211_2016, frame_ie_ieee2016[*ieee2016_id], *fuzzing_step, *fuzzing_value_step, NULL, 0);
		memcpy(pkt->data + pkt->len, iedata.data, iedata.length);
		pkt->len += iedata.length;

		if (*fuzzing_value_step + 1 == FUZZING_VALUE_END)
		{
			*fuzzing_value_step = VALUE_ALL_BITS_ZERO;

			if (*fuzzing_step + 1 == FUZZING_END)
			{
				*ieee2016_id += 1;
				*fuzzing_step = NOT_PRESENT;
			}
			else
			{
				*fuzzing_step += 1;
			}

			if (frame_ie_ieee2016[*ieee2016_id] == 0 && *ieee2016_id != 0) // array end
			{
				*ieee2016 = 1;
			}
		}
		else
		{
			*fuzzing_value_step += 1;
		}
	}
}

void create_radom_ie(struct packet *pkt,
					 IEEE_80211_VERSION ieee80211_version,
					 int ieee_ie_id)
{
	struct ie_data iedata = {0};
	int fuzzing_step = 0;
	int fuzzing_value_step = 0;

	if (0 == fuzzing_opt.seed)
		srandom(time(NULL));

	fuzzing_step = random() % (FUZZING_END - 1) + 1;

	if (0 == fuzzing_opt.seed)
		srandom(time(NULL) + ieee_ie_id);

	fuzzing_value_step = random() % (FUZZING_VALUE_END - 1) + 1;

	iedata = get_ie_data_by_fuzzing_type(ieee80211_version, ieee_ie_id, fuzzing_step, fuzzing_value_step, NULL, 0);
	memcpy(pkt->data + pkt->len, iedata.data, iedata.length);
	pkt->len += iedata.length;
}

void create_frame_fuzzing_ies(struct packet *pkt,
							  char *frame_name,
							  uint8_t frame_ie_ieee1999[],
							  uint8_t frame_ie_ieee2007[],
							  uint8_t frame_ie_ieee2012[],
							  uint8_t frame_ie_ieee2016[],
							  int *ieee1999,
							  int *ieee1999_id,
							  int *ieee2007,
							  int *ieee2007_id,
							  int *ieee2012,
							  int *ieee2012_id,
							  int *ieee2016,
							  int *ieee2016_id,
							  FUZZING_TYPE *fuzzing_step,
							  FUZZING_VALUE_TYPE *fuzzing_value_step)
{
	int ie_array_size;
	int ie_cnt = 0;
	int i;
	int max_ies = 5;

	create_frame_ies(pkt,
					 frame_name,
					 frame_ie_ieee1999,
					 frame_ie_ieee2007,
					 frame_ie_ieee2012,
					 frame_ie_ieee2016,
					 ieee1999,
					 ieee1999_id,
					 ieee2007,
					 ieee2007_id,
					 ieee2012,
					 ieee2012_id,
					 ieee2016,
					 ieee2016_id,
					 fuzzing_step,
					 fuzzing_value_step);

	return;

	if (*ieee1999 == 0 && frame_ie_ieee1999[0] != 0xff)
	{
		ie_array_size = sizeof(frame_ie_ieee1999) / sizeof(frame_ie_ieee1999[0]);
		ie_cnt = 1;
		for (i = 1; i < ie_array_size; i++)
		{
			if (frame_ie_ieee1999[i] == 0)
				break;

			ie_cnt++;
		}

		for (i = 0; i < max_ies; i++)
		{
			if (0 == fuzzing_opt.seed)
				srandom(time(NULL) + i);

			create_radom_ie(pkt, IEEE_80211_1999, frame_ie_ieee1999[random() % ie_cnt]);
		}
	}
	else if (*ieee2007 == 0 && frame_ie_ieee2007[0] != 0xff)
	{
		ie_array_size = sizeof(frame_ie_ieee2007) / sizeof(frame_ie_ieee2007[0]);
		ie_cnt = 1;
		for (i = 1; i < ie_array_size; i++)
		{
			if (frame_ie_ieee2007[i] == 0)
				break;

			ie_cnt++;
		}

		for (i = 0; i < max_ies; i++)
		{
			if (0 == fuzzing_opt.seed)
				srandom(time(NULL) + i);

			create_radom_ie(pkt, IEEE_80211_2007, frame_ie_ieee2007[random() % ie_cnt]);
		}
	}
	else if (*ieee2012 == 0 && frame_ie_ieee2012[0] != 0xff)
	{
		ie_array_size = sizeof(frame_ie_ieee2012) / sizeof(frame_ie_ieee2012[0]);
		ie_cnt = 1;
		for (i = 1; i < ie_array_size; i++)
		{
			if (frame_ie_ieee2012[i] == 0)
				break;

			ie_cnt++;
		}

		for (i = 0; i < max_ies; i++)
		{
			if (0 == fuzzing_opt.seed)
				srandom(time(NULL) + i);

			create_radom_ie(pkt, IEEE_80211_2012, frame_ie_ieee2012[random() % ie_cnt]);
		}
	}
	else if (*ieee2016 == 0 && frame_ie_ieee2016[0] != 0xff)
	{
		ie_array_size = sizeof(frame_ie_ieee2016) / sizeof(frame_ie_ieee2016[0]);
		ie_cnt = 1;
		for (i = 1; i < ie_array_size; i++)
		{
			if (frame_ie_ieee2016[i] == 0)
				break;

			ie_cnt++;
		}

		for (i = 0; i < max_ies; i++)
		{
			if (0 == fuzzing_opt.seed)
				srandom(time(NULL) + i);

			create_radom_ie(pkt, IEEE_80211_2016, frame_ie_ieee2016[random() % ie_cnt]);
		}
	}
}

uint8_t get_ie_status(uint8_t ie_type, uint8_t is_ext)
{
	int i = 0;

	if (is_ext == 0)
	{
		for (i = 0; i < 255; i++)
		{
			if (fuzzing_opt.ies_status[i].type == ie_type)
				return fuzzing_opt.ies_status[i].enabled;
		}
	}
	else
	{
		for (i = 0; i < 255; i++)
		{
			if (fuzzing_opt.ext_ies_status[i].type == ie_type)
				return fuzzing_opt.ext_ies_status[i].enabled;
		}
	}

	return 0;
}

void init_ie_creator()
{
	/*ies_creator[0].id = 0;
	ies_creator[0].pf_ie_creator = ie_0_creator;

	ies_creator[1].id = 1;
	ies_creator[1].pf_ie_creator = ie_1_creator;

	ies_creator[2].id = 2;
	ies_creator[2].pf_ie_creator = ie_2_creator;

	ies_creator[3].id = 3;
	ies_creator[3].pf_ie_creator = ie_3_creator;

	ies_creator[4].id = 4;
	ies_creator[4].pf_ie_creator = ie_4_creator;

	ies_creator[5].id = 5;
	ies_creator[5].pf_ie_creator = ie_5_creator;

	ies_creator[6].id = 6;
	ies_creator[6].pf_ie_creator = ie_6_creator;

	ies_creator[7].id = 7;
	ies_creator[7].pf_ie_creator = ie_7_creator;

	ies_creator[8].id = 8;
	ies_creator[8].pf_ie_creator = ie_8_creator;

	ies_creator[9].id = 9;
	ies_creator[9].pf_ie_creator = ie_9_creator;

	ies_creator[10].id = 10;
	ies_creator[10].pf_ie_creator = ie_10_creator;

	ies_creator[11].id = 11;
	ies_creator[11].pf_ie_creator = ie_11_creator;

	ies_creator[12].id = 12;
	ies_creator[12].pf_ie_creator = ie_12_creator;

	ies_creator[13].id = 13;
	ies_creator[13].pf_ie_creator = ie_13_creator;

	ies_creator[14].id = 14;
	ies_creator[14].pf_ie_creator = ie_14_creator;

	ies_creator[15].id = 15;
	ies_creator[15].pf_ie_creator = ie_15_creator;

	ies_creator[16].id = 16;
	ies_creator[16].pf_ie_creator = ie_16_creator;

	ies_creator[17].id = 17;
	ies_creator[17].pf_ie_creator = ie_17_creator;

	ies_creator[18].id = 18;
	ies_creator[18].pf_ie_creator = ie_18_creator;

	ies_creator[19].id = 19;
	ies_creator[19].pf_ie_creator = ie_19_creator;

	ies_creator[20].id = 20;
	ies_creator[20].pf_ie_creator = ie_20_creator;

	ies_creator[21].id = 21;
	ies_creator[21].pf_ie_creator = ie_21_creator;

	ies_creator[22].id = 22;
	ies_creator[22].pf_ie_creator = ie_22_creator;

	ies_creator[23].id = 23;
	ies_creator[23].pf_ie_creator = ie_23_creator;

	ies_creator[24].id = 24;
	ies_creator[24].pf_ie_creator = ie_24_creator;

	ies_creator[25].id = 25;
	ies_creator[25].pf_ie_creator = ie_25_creator;

	ies_creator[26].id = 26;
	ies_creator[26].pf_ie_creator = ie_26_creator;

	ies_creator[27].id = 27;
	ies_creator[27].pf_ie_creator = ie_27_creator;

	ies_creator[28].id = 28;
	ies_creator[28].pf_ie_creator = ie_28_creator;

	ies_creator[29].id = 29;
	ies_creator[29].pf_ie_creator = ie_29_creator;

	ies_creator[30].id = 30;
	ies_creator[30].pf_ie_creator = ie_30_creator;

	ies_creator[31].id = 31;
	ies_creator[31].pf_ie_creator = ie_31_creator;

	ies_creator[32].id = 32;
	ies_creator[32].pf_ie_creator = ie_32_creator;

	ies_creator[33].id = 33;
	ies_creator[33].pf_ie_creator = ie_33_creator;

	ies_creator[34].id = 34;
	ies_creator[34].pf_ie_creator = ie_34_creator;

	ies_creator[35].id = 35;
	ies_creator[35].pf_ie_creator = ie_35_creator;

	ies_creator[36].id = 36;
	ies_creator[36].pf_ie_creator = ie_36_creator;

	ies_creator[37].id = 37;
	ies_creator[37].pf_ie_creator = ie_37_creator;

	ies_creator[38].id = 38;
	ies_creator[38].pf_ie_creator = ie_38_creator;

	ies_creator[39].id = 39;
	ies_creator[39].pf_ie_creator = ie_39_creator;

	ies_creator[40].id = 40;
	ies_creator[40].pf_ie_creator = ie_40_creator;

	ies_creator[41].id = 41;
	ies_creator[41].pf_ie_creator = ie_41_creator;

	ies_creator[42].id = 42;
	ies_creator[42].pf_ie_creator = ie_42_creator;

	ies_creator[43].id = 43;
	ies_creator[43].pf_ie_creator = ie_43_creator;

	ies_creator[44].id = 44;
	ies_creator[44].pf_ie_creator = ie_44_creator;

	ies_creator[45].id = 45;
	ies_creator[45].pf_ie_creator = ie_45_creator;

	ies_creator[46].id = 46;
	ies_creator[46].pf_ie_creator = ie_46_creator;

	ies_creator[47].id = 47;
	ies_creator[47].pf_ie_creator = ie_47_creator;

	ies_creator[48].id = 48;
	ies_creator[48].pf_ie_creator = ie_48_creator;

	ies_creator[49].id = 49;
	ies_creator[49].pf_ie_creator = ie_49_creator;

	ies_creator[50].id = 50;
	ies_creator[50].pf_ie_creator = ie_50_creator;

	ies_creator[51].id = 51;
	ies_creator[51].pf_ie_creator = ie_51_creator;

	ies_creator[52].id = 52;
	ies_creator[52].pf_ie_creator = ie_52_creator;

	ies_creator[53].id = 53;
	ies_creator[53].pf_ie_creator = ie_53_creator;

	ies_creator[54].id = 54;
	ies_creator[54].pf_ie_creator = ie_54_creator;

	ies_creator[55].id = 55;
	ies_creator[55].pf_ie_creator = ie_55_creator;

	ies_creator[56].id = 56;
	ies_creator[56].pf_ie_creator = ie_56_creator;

	ies_creator[57].id = 57;
	ies_creator[57].pf_ie_creator = ie_57_creator;

	ies_creator[58].id = 58;
	ies_creator[58].pf_ie_creator = ie_58_creator;

	ies_creator[59].id = 59;
	ies_creator[59].pf_ie_creator = ie_59_creator;

	ies_creator[60].id = 60;
	ies_creator[60].pf_ie_creator = ie_60_creator;

	ies_creator[61].id = 61;
	ies_creator[61].pf_ie_creator = ie_61_creator;

	ies_creator[62].id = 62;
	ies_creator[62].pf_ie_creator = ie_62_creator;

	ies_creator[63].id = 63;
	ies_creator[63].pf_ie_creator = ie_63_creator;

	ies_creator[64].id = 64;
	ies_creator[64].pf_ie_creator = ie_64_creator;

	ies_creator[65].id = 65;
	ies_creator[65].pf_ie_creator = ie_65_creator;

	ies_creator[66].id = 66;
	ies_creator[66].pf_ie_creator = ie_66_creator;

	ies_creator[67].id = 67;
	ies_creator[67].pf_ie_creator = ie_67_creator;

	ies_creator[68].id = 68;
	ies_creator[68].pf_ie_creator = ie_68_creator;

	ies_creator[69].id = 69;
	ies_creator[69].pf_ie_creator = ie_69_creator;

	ies_creator[70].id = 70;
	ies_creator[70].pf_ie_creator = ie_70_creator;

	ies_creator[71].id = 71;
	ies_creator[71].pf_ie_creator = ie_71_creator;

	ies_creator[72].id = 72;
	ies_creator[72].pf_ie_creator = ie_72_creator;

	ies_creator[73].id = 73;
	ies_creator[73].pf_ie_creator = ie_73_creator;

	ies_creator[74].id = 74;
	ies_creator[74].pf_ie_creator = ie_74_creator;

	ies_creator[75].id = 75;
	ies_creator[75].pf_ie_creator = ie_75_creator;

	ies_creator[76].id = 76;
	ies_creator[76].pf_ie_creator = ie_76_creator;

	ies_creator[77].id = 77;
	ies_creator[77].pf_ie_creator = ie_77_creator;

	ies_creator[78].id = 78;
	ies_creator[78].pf_ie_creator = ie_78_creator;

	ies_creator[79].id = 79;
	ies_creator[79].pf_ie_creator = ie_79_creator;

	ies_creator[80].id = 80;
	ies_creator[80].pf_ie_creator = ie_80_creator;

	ies_creator[81].id = 81;
	ies_creator[81].pf_ie_creator = ie_81_creator;

	ies_creator[82].id = 82;
	ies_creator[82].pf_ie_creator = ie_82_creator;

	ies_creator[83].id = 83;
	ies_creator[83].pf_ie_creator = ie_83_creator;

	ies_creator[84].id = 84;
	ies_creator[84].pf_ie_creator = ie_84_creator;

	ies_creator[85].id = 85;
	ies_creator[85].pf_ie_creator = ie_85_creator;

	ies_creator[86].id = 86;
	ies_creator[86].pf_ie_creator = ie_86_creator;

	ies_creator[87].id = 87;
	ies_creator[87].pf_ie_creator = ie_87_creator;

	ies_creator[88].id = 88;
	ies_creator[88].pf_ie_creator = ie_88_creator;

	ies_creator[89].id = 89;
	ies_creator[89].pf_ie_creator = ie_89_creator;

	ies_creator[90].id = 90;
	ies_creator[90].pf_ie_creator = ie_90_creator;

	ies_creator[91].id = 91;
	ies_creator[91].pf_ie_creator = ie_91_creator;

	ies_creator[92].id = 92;
	ies_creator[92].pf_ie_creator = ie_92_creator;

	ies_creator[93].id = 93;
	ies_creator[93].pf_ie_creator = ie_93_creator;

	ies_creator[94].id = 94;
	ies_creator[94].pf_ie_creator = ie_94_creator;

	ies_creator[95].id = 95;
	ies_creator[95].pf_ie_creator = ie_95_creator;

	ies_creator[96].id = 96;
	ies_creator[96].pf_ie_creator = ie_96_creator;

	ies_creator[97].id = 97;
	ies_creator[97].pf_ie_creator = ie_97_creator;

	ies_creator[98].id = 98;
	ies_creator[98].pf_ie_creator = ie_98_creator;

	ies_creator[99].id = 99;
	ies_creator[99].pf_ie_creator = ie_99_creator;

	ies_creator[100].id = 100;
	ies_creator[100].pf_ie_creator = ie_100_creator;

	ies_creator[101].id = 101;
	ies_creator[101].pf_ie_creator = ie_101_creator;

	ies_creator[102].id = 102;
	ies_creator[102].pf_ie_creator = ie_102_creator;

	ies_creator[103].id = 103;
	ies_creator[103].pf_ie_creator = ie_103_creator;

	ies_creator[104].id = 104;
	ies_creator[104].pf_ie_creator = ie_104_creator;

	ies_creator[105].id = 105;
	ies_creator[105].pf_ie_creator = ie_105_creator;

	ies_creator[106].id = 106;
	ies_creator[106].pf_ie_creator = ie_106_creator;

	ies_creator[107].id = 107;
	ies_creator[107].pf_ie_creator = ie_107_creator;

	ies_creator[108].id = 108;
	ies_creator[108].pf_ie_creator = ie_108_creator;

	ies_creator[109].id = 109;
	ies_creator[109].pf_ie_creator = ie_109_creator;

	ies_creator[110].id = 110;
	ies_creator[110].pf_ie_creator = ie_110_creator;

	ies_creator[111].id = 111;
	ies_creator[111].pf_ie_creator = ie_111_creator;

	ies_creator[112].id = 112;
	ies_creator[112].pf_ie_creator = ie_112_creator;

	ies_creator[113].id = 113;
	ies_creator[113].pf_ie_creator = ie_113_creator;

	ies_creator[114].id = 114;
	ies_creator[114].pf_ie_creator = ie_114_creator;

	ies_creator[115].id = 115;
	ies_creator[115].pf_ie_creator = ie_115_creator;

	ies_creator[116].id = 116;
	ies_creator[116].pf_ie_creator = ie_116_creator;

	ies_creator[117].id = 117;
	ies_creator[117].pf_ie_creator = ie_117_creator;

	ies_creator[118].id = 118;
	ies_creator[118].pf_ie_creator = ie_118_creator;

	ies_creator[119].id = 119;
	ies_creator[119].pf_ie_creator = ie_119_creator;

	ies_creator[120].id = 120;
	ies_creator[120].pf_ie_creator = ie_120_creator;

	ies_creator[121].id = 121;
	ies_creator[121].pf_ie_creator = ie_121_creator;

	ies_creator[122].id = 122;
	ies_creator[122].pf_ie_creator = ie_122_creator;

	ies_creator[123].id = 123;
	ies_creator[123].pf_ie_creator = ie_123_creator;

	ies_creator[124].id = 124;
	ies_creator[124].pf_ie_creator = ie_124_creator;

	ies_creator[125].id = 125;
	ies_creator[125].pf_ie_creator = ie_125_creator;

	ies_creator[126].id = 126;
	ies_creator[126].pf_ie_creator = ie_126_creator;

	ies_creator[127].id = 127;
	ies_creator[127].pf_ie_creator = ie_127_creator;

	ies_creator[128].id = 128;
	ies_creator[128].pf_ie_creator = ie_128_creator;

	ies_creator[129].id = 129;
	ies_creator[129].pf_ie_creator = ie_129_creator;

	ies_creator[130].id = 130;
	ies_creator[130].pf_ie_creator = ie_130_creator;

	ies_creator[131].id = 131;
	ies_creator[131].pf_ie_creator = ie_131_creator;

	ies_creator[132].id = 132;
	ies_creator[132].pf_ie_creator = ie_132_creator;

	ies_creator[133].id = 133;
	ies_creator[133].pf_ie_creator = ie_133_creator;

	ies_creator[134].id = 134;
	ies_creator[134].pf_ie_creator = ie_134_creator;

	ies_creator[135].id = 135;
	ies_creator[135].pf_ie_creator = ie_135_creator;

	ies_creator[136].id = 136;
	ies_creator[136].pf_ie_creator = ie_136_creator;

	ies_creator[137].id = 137;
	ies_creator[137].pf_ie_creator = ie_137_creator;

	ies_creator[138].id = 138;
	ies_creator[138].pf_ie_creator = ie_138_creator;

	ies_creator[139].id = 139;
	ies_creator[139].pf_ie_creator = ie_139_creator;

	ies_creator[140].id = 140;
	ies_creator[140].pf_ie_creator = ie_140_creator;

	ies_creator[141].id = 141;
	ies_creator[141].pf_ie_creator = ie_141_creator;

	ies_creator[142].id = 142;
	ies_creator[142].pf_ie_creator = ie_142_creator;

	ies_creator[143].id = 143;
	ies_creator[143].pf_ie_creator = ie_143_creator;

	ies_creator[144].id = 144;
	ies_creator[144].pf_ie_creator = ie_144_creator;

	ies_creator[145].id = 145;
	ies_creator[145].pf_ie_creator = ie_145_creator;

	ies_creator[146].id = 146;
	ies_creator[146].pf_ie_creator = ie_146_creator;

	ies_creator[147].id = 147;
	ies_creator[147].pf_ie_creator = ie_147_creator;

	ies_creator[148].id = 148;
	ies_creator[148].pf_ie_creator = ie_148_creator;

	ies_creator[149].id = 149;
	ies_creator[149].pf_ie_creator = ie_149_creator;

	ies_creator[150].id = 150;
	ies_creator[150].pf_ie_creator = ie_150_creator;

	ies_creator[151].id = 151;
	ies_creator[151].pf_ie_creator = ie_151_creator;

	ies_creator[152].id = 152;
	ies_creator[152].pf_ie_creator = ie_152_creator;

	ies_creator[153].id = 153;
	ies_creator[153].pf_ie_creator = ie_153_creator;

	ies_creator[154].id = 154;
	ies_creator[154].pf_ie_creator = ie_154_creator;

	ies_creator[155].id = 155;
	ies_creator[155].pf_ie_creator = ie_155_creator;

	ies_creator[156].id = 156;
	ies_creator[156].pf_ie_creator = ie_156_creator;

	ies_creator[157].id = 157;
	ies_creator[157].pf_ie_creator = ie_157_creator;

	ies_creator[158].id = 158;
	ies_creator[158].pf_ie_creator = ie_158_creator;

	ies_creator[159].id = 159;
	ies_creator[159].pf_ie_creator = ie_159_creator;

	ies_creator[160].id = 160;
	ies_creator[160].pf_ie_creator = ie_160_creator;

	ies_creator[161].id = 161;
	ies_creator[161].pf_ie_creator = ie_161_creator;

	ies_creator[162].id = 162;
	ies_creator[162].pf_ie_creator = ie_162_creator;

	ies_creator[163].id = 163;
	ies_creator[163].pf_ie_creator = ie_163_creator;

	ies_creator[164].id = 164;
	ies_creator[164].pf_ie_creator = ie_164_creator;

	ies_creator[165].id = 165;
	ies_creator[165].pf_ie_creator = ie_165_creator;

	ies_creator[166].id = 166;
	ies_creator[166].pf_ie_creator = ie_166_creator;

	ies_creator[167].id = 167;
	ies_creator[167].pf_ie_creator = ie_167_creator;

	ies_creator[168].id = 168;
	ies_creator[168].pf_ie_creator = ie_168_creator;

	ies_creator[169].id = 169;
	ies_creator[169].pf_ie_creator = ie_169_creator;

	ies_creator[170].id = 170;
	ies_creator[170].pf_ie_creator = ie_170_creator;

	ies_creator[171].id = 171;
	ies_creator[171].pf_ie_creator = ie_171_creator;

	ies_creator[172].id = 172;
	ies_creator[172].pf_ie_creator = ie_172_creator;

	ies_creator[173].id = 173;
	ies_creator[173].pf_ie_creator = ie_173_creator;

	ies_creator[174].id = 174;
	ies_creator[174].pf_ie_creator = ie_174_creator;

	ies_creator[175].id = 175;
	ies_creator[175].pf_ie_creator = ie_175_creator;

	ies_creator[176].id = 176;
	ies_creator[176].pf_ie_creator = ie_176_creator;

	ies_creator[177].id = 177;
	ies_creator[177].pf_ie_creator = ie_177_creator;

	ies_creator[178].id = 178;
	ies_creator[178].pf_ie_creator = ie_178_creator;

	ies_creator[179].id = 179;
	ies_creator[179].pf_ie_creator = ie_179_creator;

	ies_creator[180].id = 180;
	ies_creator[180].pf_ie_creator = ie_180_creator;

	ies_creator[181].id = 181;
	ies_creator[181].pf_ie_creator = ie_181_creator;

	ies_creator[182].id = 182;
	ies_creator[182].pf_ie_creator = ie_182_creator;

	ies_creator[183].id = 183;
	ies_creator[183].pf_ie_creator = ie_183_creator;

	ies_creator[184].id = 184;
	ies_creator[184].pf_ie_creator = ie_184_creator;

	ies_creator[185].id = 185;
	ies_creator[185].pf_ie_creator = ie_185_creator;

	ies_creator[186].id = 186;
	ies_creator[186].pf_ie_creator = ie_186_creator;

	ies_creator[187].id = 187;
	ies_creator[187].pf_ie_creator = ie_187_creator;

	ies_creator[188].id = 188;
	ies_creator[188].pf_ie_creator = ie_188_creator;

	ies_creator[189].id = 189;
	ies_creator[189].pf_ie_creator = ie_189_creator;

	ies_creator[190].id = 190;
	ies_creator[190].pf_ie_creator = ie_190_creator;

	ies_creator[191].id = 191;
	ies_creator[191].pf_ie_creator = ie_191_creator;

	ies_creator[192].id = 192;
	ies_creator[192].pf_ie_creator = ie_192_creator;

	ies_creator[193].id = 193;
	ies_creator[193].pf_ie_creator = ie_193_creator;

	ies_creator[194].id = 194;
	ies_creator[194].pf_ie_creator = ie_194_creator;

	ies_creator[195].id = 195;
	ies_creator[195].pf_ie_creator = ie_195_creator;

	ies_creator[196].id = 196;
	ies_creator[196].pf_ie_creator = ie_196_creator;

	ies_creator[197].id = 197;
	ies_creator[197].pf_ie_creator = ie_197_creator;

	ies_creator[198].id = 198;
	ies_creator[198].pf_ie_creator = ie_198_creator;

	ies_creator[199].id = 199;
	ies_creator[199].pf_ie_creator = ie_199_creator;

	ies_creator[200].id = 200;
	ies_creator[200].pf_ie_creator = ie_200_creator;

	ies_creator[201].id = 201;
	ies_creator[201].pf_ie_creator = ie_201_creator;

	ies_creator[202].id = 202;
	ies_creator[202].pf_ie_creator = ie_202_creator;

	ies_creator[203].id = 203;
	ies_creator[203].pf_ie_creator = ie_203_creator;

	ies_creator[204].id = 204;
	ies_creator[204].pf_ie_creator = ie_204_creator;

	ies_creator[205].id = 205;
	ies_creator[205].pf_ie_creator = ie_205_creator;

	ies_creator[206].id = 206;
	ies_creator[206].pf_ie_creator = ie_206_creator;

	ies_creator[207].id = 207;
	ies_creator[207].pf_ie_creator = ie_207_creator;

	ies_creator[208].id = 208;
	ies_creator[208].pf_ie_creator = ie_208_creator;

	ies_creator[209].id = 209;
	ies_creator[209].pf_ie_creator = ie_209_creator;

	ies_creator[210].id = 210;
	ies_creator[210].pf_ie_creator = ie_210_creator;

	ies_creator[211].id = 211;
	ies_creator[211].pf_ie_creator = ie_211_creator;

	ies_creator[212].id = 212;
	ies_creator[212].pf_ie_creator = ie_212_creator;

	ies_creator[213].id = 213;
	ies_creator[213].pf_ie_creator = ie_213_creator;

	ies_creator[214].id = 214;
	ies_creator[214].pf_ie_creator = ie_214_creator;

	ies_creator[215].id = 215;
	ies_creator[215].pf_ie_creator = ie_215_creator;

	ies_creator[216].id = 216;
	ies_creator[216].pf_ie_creator = ie_216_creator;

	ies_creator[217].id = 217;
	ies_creator[217].pf_ie_creator = ie_217_creator;

	ies_creator[218].id = 218;
	ies_creator[218].pf_ie_creator = ie_218_creator;

	ies_creator[219].id = 219;
	ies_creator[219].pf_ie_creator = ie_219_creator;

	ies_creator[220].id = 220;
	ies_creator[220].pf_ie_creator = ie_220_creator;

	ies_creator[221].id = 221;
	ies_creator[221].pf_ie_creator = ie_221_creator;

	ies_creator[222].id = 222;
	ies_creator[222].pf_ie_creator = ie_222_creator;

	ies_creator[223].id = 223;
	ies_creator[223].pf_ie_creator = ie_223_creator;

	ies_creator[224].id = 224;
	ies_creator[224].pf_ie_creator = ie_224_creator;

	ies_creator[225].id = 225;
	ies_creator[225].pf_ie_creator = ie_225_creator;

	ies_creator[226].id = 226;
	ies_creator[226].pf_ie_creator = ie_226_creator;

	ies_creator[227].id = 227;
	ies_creator[227].pf_ie_creator = ie_227_creator;

	ies_creator[228].id = 228;
	ies_creator[228].pf_ie_creator = ie_228_creator;

	ies_creator[229].id = 229;
	ies_creator[229].pf_ie_creator = ie_229_creator;

	ies_creator[230].id = 230;
	ies_creator[230].pf_ie_creator = ie_230_creator;

	ies_creator[231].id = 231;
	ies_creator[231].pf_ie_creator = ie_231_creator;

	ies_creator[232].id = 232;
	ies_creator[232].pf_ie_creator = ie_232_creator;

	ies_creator[233].id = 233;
	ies_creator[233].pf_ie_creator = ie_233_creator;

	ies_creator[234].id = 234;
	ies_creator[234].pf_ie_creator = ie_234_creator;

	ies_creator[235].id = 235;
	ies_creator[235].pf_ie_creator = ie_235_creator;

	ies_creator[236].id = 236;
	ies_creator[236].pf_ie_creator = ie_236_creator;

	ies_creator[237].id = 237;
	ies_creator[237].pf_ie_creator = ie_237_creator;

	ies_creator[238].id = 238;
	ies_creator[238].pf_ie_creator = ie_238_creator;

	ies_creator[239].id = 239;
	ies_creator[239].pf_ie_creator = ie_239_creator;

	ies_creator[240].id = 240;
	ies_creator[240].pf_ie_creator = ie_240_creator;

	ies_creator[241].id = 241;
	ies_creator[241].pf_ie_creator = ie_241_creator;

	ies_creator[242].id = 242;
	ies_creator[242].pf_ie_creator = ie_242_creator;

	ies_creator[243].id = 243;
	ies_creator[243].pf_ie_creator = ie_243_creator;

	ies_creator[244].id = 244;
	ies_creator[244].pf_ie_creator = ie_244_creator;

	ies_creator[245].id = 245;
	ies_creator[245].pf_ie_creator = ie_245_creator;

	ies_creator[246].id = 246;
	ies_creator[246].pf_ie_creator = ie_246_creator;

	ies_creator[247].id = 247;
	ies_creator[247].pf_ie_creator = ie_247_creator;

	ies_creator[248].id = 248;
	ies_creator[248].pf_ie_creator = ie_248_creator;

	ies_creator[249].id = 249;
	ies_creator[249].pf_ie_creator = ie_249_creator;

	ies_creator[250].id = 250;
	ies_creator[250].pf_ie_creator = ie_250_creator;

	ies_creator[251].id = 251;
	ies_creator[251].pf_ie_creator = ie_251_creator;

	ies_creator[252].id = 252;
	ies_creator[252].pf_ie_creator = ie_252_creator;

	ies_creator[253].id = 253;
	ies_creator[253].pf_ie_creator = ie_253_creator;

	ies_creator[254].id = 254;
	ies_creator[254].pf_ie_creator = ie_254_creator;

	ies_creator[255].id = 255;
	ies_creator[255].pf_ie_creator = ie_255_creator;*/
}
