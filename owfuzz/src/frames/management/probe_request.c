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

#include <assert.h>
#include <stdio.h>
#include "probe_request.h"
#include "ies_creator.h"

extern fuzzing_option fuzzing_opt;

uint8_t probe_request_ie_ieee1999[10] = {0, 1, 0};
uint8_t probe_request_ie_ieee2007[30] = {0, 1, 10, 50, 221, 0};
uint8_t probe_request_ie_ieee2012[80] = {0, 1, 50, 3, 59, 45, 72, 127, 84, 97, 107, 114, 221, 0};
uint8_t probe_request_ie_ieee2016[100] = {0, 1, 10, 50, 3, 59, 45, 72, 127, 84, 97, 107, 114, 158, 148, 170, 191, 255, 255, 221, 0};
uint8_t probe_request_ie_ieee2020[100] = {0, 1, 10, 50, 3, 59, 45, 72, 127, 84, 97, 107, 114, 158, 148, 170, 191,
                                          255,
                                          255,
                                          255,
                                          239,
                                          215,
                                          226,
                                          229,
                                          217,
                                          230,
                                          235,
                                          255,
                                          255,
                                          255,
                                          255,
                                          255,
                                          255,
                                          221,
                                          0};

static int ie_extension_id = 0;
static uint8_t ie_extension[50] = {
    IE_EXT_11_ESTIMATED_SERVICE_PARAMETERS_INBOUND,
    IE_EXT_10_EXTENDED_REQUEST,
    IE_EXT_2_FILS_REQUEST_PARAMETERS,
    IE_EXT_44_VENDOR_SPECIFIC_REQUEST,
    IE_EXT_17_CDMG_CAPABILITIES,
    IE_EXT_21_CLUSTER_PROBE,
    IE_EXT_27_CMMG_CAPABILITIES,
    IE_EXT_53_ESTIMATED_SERVICE_PARAMETERS_OUTBOUND,
    IE_EXT_90_SUPPLEMENTAL_CLASS_2_CAPABILITIES,
    0};

static FUZZING_VALUE_TYPE fuzzing_value_step = VALUE_ALL_BITS_ZERO;
static FUZZING_TYPE fuzzing_step = NOT_PRESENT;

static int ieee2020 = 0;
static int ieee2020_id = 0;

void save_probe_request_state()
{
}

void load_probe_request_state()
{
}

struct packet create_probe_request(struct ether_addr bssid, struct ether_addr smac, struct ether_addr dmac, char adhoc, struct packet *recv_pkt)
{
  struct packet probe = {0};
  uint8_t *ie_data;
  uint8_t ie_len;
  uint8_t ie_id;
  int i, j;

  create_ieee_hdr(&probe, IEEE80211_TYPE_PROBEREQ, 'a', 0, dmac, smac, bssid, SE_NULLMAC, 0);

  for (i = 0; i < fuzzing_opt.cur_sfs_cnt; i++)
  {
    if (fuzzing_opt.sfs[i].frame_type == IEEE80211_TYPE_PROBEREQ && fuzzing_opt.sfs[i].bset == 1)
    {
      for (j = 0; j < fuzzing_opt.sfs[i].ie_cnt; j++)
      {
        add_ie_data(&probe, fuzzing_opt.sfs[i].sies[j].id, SPECIFIC_VALUE, fuzzing_opt.sfs[i].sies[j].value, fuzzing_opt.sfs[i].sies[j].len);
      }
      break;
    }
  }

  if (fuzzing_opt.sfs[i].frame_type != IEEE80211_TYPE_PROBEREQ)
  {
    add_ie_data(&probe, 0, SPECIFIC_VALUE, (uint8_t *)fuzzing_opt.target_ssid, strlen(fuzzing_opt.target_ssid));
    if (fuzzing_opt.channel <= 14)
    {
      ie_data = (uint8_t *)IE_1_SUPPORTTED_RATES_B;
      ie_id = ie_data[0];
      ie_len = ie_data[1];
      add_ie_data(&probe, ie_id, SPECIFIC_VALUE, ie_data + 2, ie_len);

      add_default_ie_data(&probe, 45);
    }
    else
    {
      ie_data = (uint8_t *)IE_1_SUPPORTTED_RATES_N_AC;
      ie_id = ie_data[0];
      ie_len = ie_data[1];
      add_ie_data(&probe, ie_id, SPECIFIC_VALUE, ie_data + 2, ie_len);

      add_default_ie_data(&probe, 45);
      ie_data = (uint8_t *)malloc(strlen(IE_61_HT_INFORMATION));
      if (ie_data)
      {
        memcpy(ie_data, IE_61_HT_INFORMATION, strlen(IE_61_HT_INFORMATION));
        ie_data[2] = fuzzing_opt.channel;
        ie_id = ie_data[0];
        ie_len = ie_data[1];
        add_ie_data(&probe, ie_id, SPECIFIC_VALUE, ie_data + 2, ie_len);
        free(ie_data);
      }
    }

    add_default_ie_data(&probe, 50);
  }

  create_frame_fuzzing_ie(&probe, "Probe Request", probe_request_ie_ieee2020, &ieee2020, &ieee2020_id, ie_extension, &ie_extension_id, &fuzzing_step, &fuzzing_value_step);

  /*create_frame_fuzzing_ies(&probe, "Probe Request",
      probe_request_ie_ieee1999,
      probe_request_ie_ieee2007,
      probe_request_ie_ieee2012,
      probe_request_ie_ieee2016,
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

  return probe;
}

void create_probe_request_fuzzing_ies(struct packet *pkt)
{
  create_frame_fuzzing_ie(pkt, "Probe Request", probe_request_ie_ieee2020, &ieee2020, &ieee2020_id, ie_extension, &ie_extension_id, &fuzzing_step, &fuzzing_value_step);
}