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

#include "association_request.h"
#include "ies_creator.h"

extern fuzzing_option fuzzing_opt;

uint8_t association_request_ie_ieee1999[10] = {0, 1, 0};
uint8_t association_request_ie_ieee2007[30] = {0, 1, 50, 33, 36, 48, 46, 221, 0};
uint8_t association_request_ie_ieee2012[80] = {0, 1, 50, 33, 36, 48, 46, 70, 54, 59, 45, 72, 127, 89, 94, 107, 221, 0};
uint8_t association_request_ie_ieee2016[100] = {0, 1, 50, 33, 36, 48, 46, 70, 54, 59, 45, 72, 127, 89, 94, 107, 158, 148, 170, 191, 199, 221, 0};
uint8_t association_request_ie_ieee2020[100] = {0, 1, 50, 33, 36, 48, 46, 70, 54, 59, 45, 72, 127, 89, 94, 107, 158, 148, 170, 191, 199,
                                                255,
                                                255,
                                                255,
                                                255,
                                                255,
                                                216,
                                                210,
                                                217,
                                                230,
                                                224,
                                                90,
                                                233,
                                                235,
                                                225,
                                                236,
                                                255,
                                                255,
                                                255,
                                                55,
                                                244,
                                                255,
                                                255,
                                                221,
                                                0};

static int ie_extension_id = 0;
static uint8_t ie_extension[50] = {
    IE_EXT_4_FILS_SESSION,
    IE_EXT_12_FILS_PUBLIC_KEY,
    IE_EXT_3_FILS_KEY_CONFIRMATION,
    IE_EXT_5_FILS_HLP_CONTAINER,
    IE_EXT_6_FILS_IP_ADDRESS_ASSIGNMENT,
    IE_EXT_17_CDMG_CAPABILITIES,
    IE_EXT_27_CMMG_CAPABILITIES,
    IE_EXT_34_GLK_GCR_PARAMETER_SET,
    IE_EXT_90_SUPPLEMENTAL_CLASS_2_CAPABILITIES,
    IE_EXT_88_MSCS_DESCRIPTOR,
    0};

static FUZZING_VALUE_TYPE fuzzing_value_step = VALUE_ALL_BITS_ZERO;
static FUZZING_TYPE fuzzing_step = NOT_PRESENT;

static int ieee2020 = 0;
static int ieee2020_id = 0;

void save_association_request_state()
{
}

void load_association_request_state()
{
}

struct packet create_association_request(struct ether_addr bssid, struct ether_addr smac, struct ether_addr dmac, char adhoc, struct packet *recv_pkt)
{
  struct packet pkt = {0};
  uint16_t *capabilities;
  uint16_t *interval;
  uint8_t *ie_data;
  uint8_t ie_len;
  uint8_t ie_id;
  int i, j;

  create_ieee_hdr(&pkt, IEEE80211_TYPE_ASSOCREQ, 'a', 0x013A, dmac, smac, bssid, SE_NULLMAC, 0);

  capabilities = (uint16_t *)(pkt.data + pkt.len);
  interval = (uint16_t *)(pkt.data + pkt.len + 2);

  *capabilities = 0xFFF0;
  *capabilities |= 0x0002;
  *capabilities |= 0x0010;

  *interval = htole16(0x64);

  pkt.len += 4;

  for (i = 0; i < fuzzing_opt.cur_sfs_cnt; i++)
  {
    if (fuzzing_opt.sfs[i].frame_type == IEEE80211_TYPE_ASSOCREQ && fuzzing_opt.sfs[i].bset == 1)
    {
      for (j = 0; j < fuzzing_opt.sfs[i].ie_cnt; j++)
      {
        add_ie_data(&pkt, fuzzing_opt.sfs[i].sies[j].id, SPECIFIC_VALUE, fuzzing_opt.sfs[i].sies[j].value, fuzzing_opt.sfs[i].sies[j].len);
      }
      break;
    }
  }

  if (fuzzing_opt.sfs[i].frame_type != IEEE80211_TYPE_ASSOCREQ)
  {
    add_ie_data(&pkt, 0, SPECIFIC_VALUE, (uint8_t *)fuzzing_opt.target_ssid, strlen(fuzzing_opt.target_ssid));
    // add_default_ie_data(&pkt, 1);

    if (fuzzing_opt.channel <= 14)
    {
      ie_data = (uint8_t *)IE_1_SUPPORTTED_RATES_B;
      ie_id = ie_data[0];
      ie_len = ie_data[1];
      add_ie_data(&pkt, ie_id, SPECIFIC_VALUE, ie_data + 2, ie_len);

      add_default_ie_data(&pkt, 45);
    }
    else
    {
      ie_data = (uint8_t *)IE_1_SUPPORTTED_RATES_N_AC;
      ie_id = ie_data[0];
      ie_len = ie_data[1];
      add_ie_data(&pkt, ie_id, SPECIFIC_VALUE, ie_data + 2, ie_len);

      add_default_ie_data(&pkt, 45);
      ie_data = (uint8_t *)malloc(strlen(IE_61_HT_INFORMATION));
      if (ie_data)
      {
        memcpy(ie_data, IE_61_HT_INFORMATION, strlen(IE_61_HT_INFORMATION));
        ie_data[2] = fuzzing_opt.channel;
        ie_id = ie_data[0];
        ie_len = ie_data[1];
        add_ie_data(&pkt, ie_id, SPECIFIC_VALUE, ie_data + 2, ie_len);
        free(ie_data);
      }
    }

    add_default_ie_data(&pkt, 50);

    if (fuzzing_opt.auth_type == WPA3)
    {
      add_default_ie_data(&pkt, 32);
      ie_data = (uint8_t *)IE_48_RSN_WPA3_AES_ASSOCREQ;
      ie_id = ie_data[0];
      ie_len = ie_data[1];
      add_ie_data(&pkt, ie_id, SPECIFIC_VALUE, ie_data + 2, ie_len);
      add_default_ie_data(&pkt, 127);
    }
    else if (fuzzing_opt.auth_type == WPA2_PSK_TKIP_AES || fuzzing_opt.auth_type == WPA2_PSK_AES || fuzzing_opt.auth_type == WPA2_PSK_TKIP ||
             fuzzing_opt.auth_type == WPA_PSK_TKIP_AES || fuzzing_opt.auth_type == WPA_PSK_AES || fuzzing_opt.auth_type == WPA_PSK_TKIP)
    {
      add_default_ie_data(&pkt, 32);
    }
    else if (fuzzing_opt.auth_type == SHARE_WEP)
    {
    }
    else if (fuzzing_opt.auth_type == OPEN_WEP || fuzzing_opt.auth_type == OPEN_NONE)
    {
    }
  }

  create_frame_fuzzing_ie(&pkt, "Association Request", association_request_ie_ieee2020, &ieee2020, &ieee2020_id, ie_extension, &ie_extension_id, &fuzzing_step, &fuzzing_value_step);

  /*create_frame_fuzzing_ies(&pkt, "Association Request",
      association_request_ie_ieee1999,
      association_request_ie_ieee2007,
      association_request_ie_ieee2012,
      association_request_ie_ieee2016,
      &ieee1999,
      &ieee1999_id,
      &ieee2007,
      &ieee2007_id,
      &ieee2012,
      &ieee2012_id,
      &ieee2016,
      &ieee2016_id,
      &fuzzing_step,
      &fuzzing_value_step);*/

  return pkt;
}
