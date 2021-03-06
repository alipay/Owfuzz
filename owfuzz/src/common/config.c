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
#include "config.h"
#include "log.h"

FILE * owfuzz_config_open(char* cfg_file)
{
    char owfuzz_cfg_path[256]={0};
    FILE *fp1 = NULL;
    char *ptr;

    if(readlink("/proc/self/exe", owfuzz_cfg_path,sizeof(owfuzz_cfg_path)) > 0)
    {
        ptr = strrchr(owfuzz_cfg_path, '/');
        if(ptr){
            ptr[1] = '\0';
            strcat(owfuzz_cfg_path, "owfuzz.cfg");

            if(cfg_file == NULL){
            fp1  = fopen(owfuzz_cfg_path, "r");
            }else{
                fp1 = fopen(cfg_file, "r");
            } 
        }
    }

    fuzz_logger_log(FUZZ_LOG_DEBUG, "owfuzz.cfg: %s\n", owfuzz_cfg_path);

    return fp1;
}


int owfuzz_config_get_sta_frames(uint8_t *owfuzz_frames, uint32_t *frame_cnt)
{
    FILE *fp1;
    unsigned char buf[256];
    unsigned char frame_name[64];
    int rc = 0,onoff;
    int frm_idx = 0;

    fp1 = owfuzz_config_open(NULL);
    if(fp1 != NULL)
    {
        while (!feof(fp1))
        {
            memset(buf, 0, sizeof(buf));
            if(fgets(buf, sizeof(buf), fp1))
            {
                if(buf[0] == '#' || buf[0] == '\r' || buf[0] == '\n')
                    continue;

                if(buf[0]=='['){
                    if(strstr(buf, "[sta-frames]") && (rc == 0)){
                        rc = 1;
                        continue;
                    }
                    else{
                        if(rc == 1)
                        {
                            rc = 0;
                            break;
                        }
                        else continue;

                    }
                   
                }

                if(rc)
                {
                    onoff = 0;
                    memset(frame_name, 0, sizeof(frame_name));
                    sscanf(buf, "%[^=]=%d", frame_name, &onoff);
                    if(onoff == 1)
                    {
                        // management
                        if(strstr(frame_name, "association_request"))
                        {
                            owfuzz_frames[frm_idx++] = IEEE80211_TYPE_ASSOCREQ;
                        }else if(strstr(frame_name, "association_response"))
                        {
                            owfuzz_frames[frm_idx++] = IEEE80211_TYPE_ASSOCRES;
                        }
                        else if(strstr(frame_name, "reassociation_request"))
                        {
                            owfuzz_frames[frm_idx++] = IEEE80211_TYPE_REASSOCREQ;
                        }
                        else if(strstr(frame_name, "reassociation_response"))
                        {
                            owfuzz_frames[frm_idx++] = IEEE80211_TYPE_REASSOCRES;
                        }
                        else if(strstr(frame_name, "probe_request"))
                        {
                            owfuzz_frames[frm_idx++] = IEEE80211_TYPE_PROBEREQ;
                        }
                        else if(strstr(frame_name, "probe_response"))
                        {
                            owfuzz_frames[frm_idx++] = IEEE80211_TYPE_PROBERES;
                        }
                        else if(strstr(frame_name, "timing_advertisement"))
                        {
                            owfuzz_frames[frm_idx++] = IEEE80211_TYPE_TIMADVERT;
                        }
                        else if(strstr(frame_name, "reserved_000111"))
                        {
                            owfuzz_frames[frm_idx++] = IEEE80211_TYPE_000111;
                        }
                        else if(strstr(frame_name, "beacon"))
                        {
                            owfuzz_frames[frm_idx++] = IEEE80211_TYPE_BEACON;
                        }
                        else if(strstr(frame_name, "atim"))
                        {
                            owfuzz_frames[frm_idx++] = IEEE80211_TYPE_ATIM;
                        }
                        else if(strstr(frame_name, "disassociation"))
                        {
                            owfuzz_frames[frm_idx++] = IEEE80211_TYPE_DISASSOC;
                        }
                        else if(strstr(frame_name, "authentication"))
                        {
                            owfuzz_frames[frm_idx++] = IEEE80211_TYPE_AUTH;
                        }
                        else if(strstr(frame_name, "deauthentication"))
                        {
                            owfuzz_frames[frm_idx++] = IEEE80211_TYPE_DEAUTH;
                        }
                        else if(strstr(frame_name, "action"))
                        {
                            owfuzz_frames[frm_idx++] = IEEE80211_TYPE_ACTION;
                        }
                        else if(strstr(frame_name, "action_no_ack"))
                        {
                            owfuzz_frames[frm_idx++] = IEEE80211_TYPE_ACTIONNOACK;
                        }
                        else if(strstr(frame_name, "reserved_001111"))
                        {
                            owfuzz_frames[frm_idx++] = IEEE80211_TYPE_001111;
                        }// data
                        else if(strstr(frame_name, "data"))
                        {
                            owfuzz_frames[frm_idx++] = IEEE80211_TYPE_DATA;
                        }
                        else if(strstr(frame_name, "data_cf_ack"))
                        {
                            owfuzz_frames[frm_idx++] = IEEE80211_TYPE_DATACFACK;
                        }
                        else if(strstr(frame_name, "data_cf_poll"))
                        {
                            owfuzz_frames[frm_idx++] = IEEE80211_TYPE_DATACFPOLL;
                        }
                        else if(strstr(frame_name, "data_cf_ack_cf_poll"))
                        {
                            owfuzz_frames[frm_idx++] = IEEE80211_TYPE_DATACFACKPOLL;
                        }
                        else if(strstr(frame_name, "null"))
                        {
                            owfuzz_frames[frm_idx++] = IEEE80211_TYPE_NULL;
                        }
                        else if(strstr(frame_name, "cf_ack"))
                        {
                            owfuzz_frames[frm_idx++] = IEEE80211_TYPE_CFACK;
                        }
                        else if(strstr(frame_name, "cf_poll"))
                        {
                            owfuzz_frames[frm_idx++] = IEEE80211_TYPE_CFPOLL;
                        }
                        else if(strstr(frame_name, "cf_ack_cf_poll"))
                        {
                            owfuzz_frames[frm_idx++] = IEEE80211_TYPE_CFACKPOLL;
                        }
                        else if(strstr(frame_name, "qos_data"))
                        {
                            owfuzz_frames[frm_idx++] = IEEE80211_TYPE_QOSDATA;
                        }
                        else if(strstr(frame_name, "qos_data_cf_ack"))
                        {
                            owfuzz_frames[frm_idx++] = IEEE80211_TYPE_QOSDATACFACK;
                        }
                        else if(strstr(frame_name, "qos_data_cf_poll"))
                        {
                            owfuzz_frames[frm_idx++] = IEEE80211_TYPE_QOSDATACFPOLL;
                        }
                        else if(strstr(frame_name, "qos_data_cf_ack_cf_poll"))
                        {
                            owfuzz_frames[frm_idx++] = IEEE80211_TYPE_QOSDATACFACKPOLL;
                        }
                        else if(strstr(frame_name, "qos_null"))
                        {
                            owfuzz_frames[frm_idx++] = IEEE80211_TYPE_QOSNULL;
                        }
                        else if(strstr(frame_name, "qos_cf_ack"))
                        {
                            owfuzz_frames[frm_idx++] = IEEE80211_TYPE_QOSCFACK;
                        }
                        else if(strstr(frame_name, "qos_cf_poll"))
                        {
                            owfuzz_frames[frm_idx++] = IEEE80211_TYPE_QOSCFPOLL;
                        }
                        else if(strstr(frame_name, "qos_cf_ack_cf_poll"))
                        {
                            owfuzz_frames[frm_idx++] = IEEE80211_TYPE_QOSCFACKPOLL;
                        }// control
                        else if(strstr(frame_name, "reserved_010000"))
                        {
                            owfuzz_frames[frm_idx++] = IEEE80211_TYPE_010000;
                        }
                        else if(strstr(frame_name, "reserved_010001"))
                        {
                            owfuzz_frames[frm_idx++] = IEEE80211_TYPE_010001;
                        }
                        else if(strstr(frame_name, "reserved_010010"))
                        {
                            owfuzz_frames[frm_idx++] = IEEE80211_TYPE_010010;
                        }
                        else if(strstr(frame_name, "reserved_010011"))
                        {
                            owfuzz_frames[frm_idx++] = IEEE80211_TYPE_010011;
                        }
                        else if(strstr(frame_name, "beamforming_report_poll"))
                        {
                            owfuzz_frames[frm_idx++] = IEEE80211_TYPE_BEAMFORMING;
                        }
                        else if(strstr(frame_name, "vht_ndp_announcement"))
                        {
                            owfuzz_frames[frm_idx++] = IEEE80211_TYPE_VHT;
                        }
                        else if(strstr(frame_name, "control_frame_extension"))
                        {
                            owfuzz_frames[frm_idx++] = IEEE80211_TYPE_CTRLFRMEXT;
                        }
                        else if(strstr(frame_name, "control_wrapper"))
                        {
                            owfuzz_frames[frm_idx++] = IEEE80211_TYPE_CTRLWRAP;
                        }
                        else if(strstr(frame_name, "block_ack_request"))
                        {
                            owfuzz_frames[frm_idx++] = IEEE80211_TYPE_BLOCKACKREQ;
                        }
                        else if(strstr(frame_name, "block_ack"))
                        {
                            owfuzz_frames[frm_idx++] = IEEE80211_TYPE_BLOCKACK;
                        }
                        else if(strstr(frame_name, "ps_poll"))
                        {
                            owfuzz_frames[frm_idx++] = IEEE80211_TYPE_PSPOLL;
                        }
                        else if(strstr(frame_name, "rts"))
                        {
                            owfuzz_frames[frm_idx++] = IEEE80211_TYPE_RTS;
                        }
                        else if(strstr(frame_name, "cts"))
                        {
                            owfuzz_frames[frm_idx++] = IEEE80211_TYPE_CTS;
                        }
                        else if(strstr(frame_name, "ack"))
                        {
                            owfuzz_frames[frm_idx++] = IEEE80211_TYPE_ACK;
                        }
                        else if(strstr(frame_name, "cf_end"))
                        {
                            owfuzz_frames[frm_idx++] = IEEE80211_TYPE_CFEND;
                        }
                        else if(strstr(frame_name, "cf_end_cf_ack"))
                        {
                            owfuzz_frames[frm_idx++] = IEEE80211_TYPE_CFENDACK;
                        }
                    }
                }


            }
        }
        *frame_cnt = frm_idx;
    }
    else{
        fuzz_logger_log(FUZZ_LOG_ERR, "Open owfuzz.cfg failed.");
        return -1;
    }

    fclose(fp1);
    return 0;
}

int owfuzz_config_get_ap_frames(uint8_t *owfuzz_frames, uint32_t *frame_cnt)
{
    FILE *fp1;
    unsigned char buf[256];
    unsigned char frame_name[64];
    int rc = 0,onoff;
    int frm_idx = 0;

    fp1 = owfuzz_config_open(NULL);
    if(fp1 != NULL)
    {
        while (!feof(fp1))
        {
            memset(buf, 0, sizeof(buf));
            if(fgets(buf, sizeof(buf), fp1))
            {
                if(buf[0] == '#' || buf[0] == '\r' || buf[0] == '\n')
                    continue;

                if(buf[0]=='['){
                    if(strstr(buf, "[ap-frames]") && (rc == 0)){
                        rc = 1;
                        continue;
                    }
                    else{
                        if(rc == 1)
                        {
                            rc = 0;
                            break;
                        }
                        else continue;
                    }
                }

                if(rc)
                {
                    onoff = 0;
                    sscanf(buf, "%[^=]=%d", frame_name, &onoff);
                    if(onoff == 1)
                    {
                        // management
                        if(strstr(frame_name, "association_request"))
                        {
                            owfuzz_frames[frm_idx++] = IEEE80211_TYPE_ASSOCREQ;
                        }else if(strstr(frame_name, "association_response"))
                        {
                            owfuzz_frames[frm_idx++] = IEEE80211_TYPE_ASSOCRES;
                        }
                        else if(strstr(frame_name, "reassociation_request"))
                        {
                            owfuzz_frames[frm_idx++] = IEEE80211_TYPE_REASSOCREQ;
                        }
                        else if(strstr(frame_name, "reassociation_response"))
                        {
                            owfuzz_frames[frm_idx++] = IEEE80211_TYPE_REASSOCRES;
                        }
                        else if(strstr(frame_name, "probe_request"))
                        {
                            owfuzz_frames[frm_idx++] = IEEE80211_TYPE_PROBEREQ;
                        }
                        else if(strstr(frame_name, "probe_response"))
                        {
                            owfuzz_frames[frm_idx++] = IEEE80211_TYPE_PROBERES;
                        }
                        else if(strstr(frame_name, "timing_advertisement"))
                        {
                            owfuzz_frames[frm_idx++] = IEEE80211_TYPE_TIMADVERT;
                        }
                        else if(strstr(frame_name, "reserved_000111"))
                        {
                            owfuzz_frames[frm_idx++] = IEEE80211_TYPE_000111;
                        }
                        else if(strstr(frame_name, "beacon"))
                        {
                            owfuzz_frames[frm_idx++] = IEEE80211_TYPE_BEACON;
                        }
                        else if(strstr(frame_name, "atim"))
                        {
                            owfuzz_frames[frm_idx++] = IEEE80211_TYPE_ATIM;
                        }
                        else if(strstr(frame_name, "disassociation"))
                        {
                            owfuzz_frames[frm_idx++] = IEEE80211_TYPE_DISASSOC;
                        }
                        else if(strstr(frame_name, "authentication"))
                        {
                            owfuzz_frames[frm_idx++] = IEEE80211_TYPE_AUTH;
                        }
                        else if(strstr(frame_name, "deauthentication"))
                        {
                            owfuzz_frames[frm_idx++] = IEEE80211_TYPE_DEAUTH;
                        }
                        else if(strstr(frame_name, "action"))
                        {
                            owfuzz_frames[frm_idx++] = IEEE80211_TYPE_ACTION;
                        }
                        else if(strstr(frame_name, "action_no_ack"))
                        {
                            owfuzz_frames[frm_idx++] = IEEE80211_TYPE_ACTIONNOACK;
                        }
                        else if(strstr(frame_name, "reserved_001111"))
                        {
                            owfuzz_frames[frm_idx++] = IEEE80211_TYPE_001111;
                        }// data
                        else if(strstr(frame_name, "data"))
                        {
                            owfuzz_frames[frm_idx++] = IEEE80211_TYPE_DATA;
                        }
                        else if(strstr(frame_name, "data_cf_ack"))
                        {
                            owfuzz_frames[frm_idx++] = IEEE80211_TYPE_DATACFACK;
                        }
                        else if(strstr(frame_name, "data_cf_poll"))
                        {
                            owfuzz_frames[frm_idx++] = IEEE80211_TYPE_DATACFPOLL;
                        }
                        else if(strstr(frame_name, "data_cf_ack_cf_poll"))
                        {
                            owfuzz_frames[frm_idx++] = IEEE80211_TYPE_DATACFACKPOLL;
                        }
                        else if(strstr(frame_name, "null"))
                        {
                            owfuzz_frames[frm_idx++] = IEEE80211_TYPE_NULL;
                        }
                        else if(strstr(frame_name, "cf_ack"))
                        {
                            owfuzz_frames[frm_idx++] = IEEE80211_TYPE_CFACK;
                        }
                        else if(strstr(frame_name, "cf_poll"))
                        {
                            owfuzz_frames[frm_idx++] = IEEE80211_TYPE_CFPOLL;
                        }
                        else if(strstr(frame_name, "cf_ack_cf_poll"))
                        {
                            owfuzz_frames[frm_idx++] = IEEE80211_TYPE_CFACKPOLL;
                        }
                        else if(strstr(frame_name, "qos_data"))
                        {
                            owfuzz_frames[frm_idx++] = IEEE80211_TYPE_QOSDATA;
                        }
                        else if(strstr(frame_name, "qos_data_cf_ack"))
                        {
                            owfuzz_frames[frm_idx++] = IEEE80211_TYPE_QOSDATACFACK;
                        }
                        else if(strstr(frame_name, "qos_data_cf_poll"))
                        {
                            owfuzz_frames[frm_idx++] = IEEE80211_TYPE_QOSDATACFPOLL;
                        }
                        else if(strstr(frame_name, "qos_data_cf_ack_cf_poll"))
                        {
                            owfuzz_frames[frm_idx++] = IEEE80211_TYPE_QOSDATACFACKPOLL;
                        }
                        else if(strstr(frame_name, "qos_null"))
                        {
                            owfuzz_frames[frm_idx++] = IEEE80211_TYPE_QOSNULL;
                        }
                        else if(strstr(frame_name, "qos_cf_ack"))
                        {
                            owfuzz_frames[frm_idx++] = IEEE80211_TYPE_QOSCFACK;
                        }
                        else if(strstr(frame_name, "qos_cf_poll"))
                        {
                            owfuzz_frames[frm_idx++] = IEEE80211_TYPE_QOSCFPOLL;
                        }
                        else if(strstr(frame_name, "qos_cf_ack_cf_poll"))
                        {
                            owfuzz_frames[frm_idx++] = IEEE80211_TYPE_QOSCFACKPOLL;
                        }// control
                        else if(strstr(frame_name, "reserved_010000"))
                        {
                            owfuzz_frames[frm_idx++] = IEEE80211_TYPE_010000;
                        }
                        else if(strstr(frame_name, "reserved_010001"))
                        {
                            owfuzz_frames[frm_idx++] = IEEE80211_TYPE_010001;
                        }
                        else if(strstr(frame_name, "reserved_010010"))
                        {
                            owfuzz_frames[frm_idx++] = IEEE80211_TYPE_010010;
                        }
                        else if(strstr(frame_name, "reserved_010011"))
                        {
                            owfuzz_frames[frm_idx++] = IEEE80211_TYPE_010011;
                        }
                        else if(strstr(frame_name, "beamforming_report_poll"))
                        {
                            owfuzz_frames[frm_idx++] = IEEE80211_TYPE_BEAMFORMING;
                        }
                        else if(strstr(frame_name, "vht_ndp_announcement"))
                        {
                            owfuzz_frames[frm_idx++] = IEEE80211_TYPE_VHT;
                        }
                        else if(strstr(frame_name, "control_frame_extension"))
                        {
                            owfuzz_frames[frm_idx++] = IEEE80211_TYPE_CTRLFRMEXT;
                        }
                        else if(strstr(frame_name, "control_wrapper"))
                        {
                            owfuzz_frames[frm_idx++] = IEEE80211_TYPE_CTRLWRAP;
                        }
                        else if(strstr(frame_name, "block_ack_request"))
                        {
                            owfuzz_frames[frm_idx++] = IEEE80211_TYPE_BLOCKACKREQ;
                        }
                        else if(strstr(frame_name, "block_ack"))
                        {
                            owfuzz_frames[frm_idx++] = IEEE80211_TYPE_BLOCKACK;
                        }
                        else if(strstr(frame_name, "ps_poll"))
                        {
                            owfuzz_frames[frm_idx++] = IEEE80211_TYPE_PSPOLL;
                        }
                        else if(strstr(frame_name, "rts"))
                        {
                            owfuzz_frames[frm_idx++] = IEEE80211_TYPE_RTS;
                        }
                        else if(strstr(frame_name, "cts"))
                        {
                            owfuzz_frames[frm_idx++] = IEEE80211_TYPE_CTS;
                        }
                        else if(strstr(frame_name, "ack"))
                        {
                            owfuzz_frames[frm_idx++] = IEEE80211_TYPE_ACK;
                        }
                        else if(strstr(frame_name, "cf_end"))
                        {
                            owfuzz_frames[frm_idx++] = IEEE80211_TYPE_CFEND;
                        }
                        else if(strstr(frame_name, "cf_end_cf_ack"))
                        {
                            owfuzz_frames[frm_idx++] = IEEE80211_TYPE_CFENDACK;
                        }
                    }
                }


            }
        }
        *frame_cnt = frm_idx;
    }
    else{
        fuzz_logger_log(FUZZ_LOG_ERR, "Open owfuzz.cfg failed.");
        return -1;
    }

    fclose(fp1);
    return 0;    
}

int owfuzz_config_get_interfaces(fuzzing_option *fo)
{
    FILE *fp1;
    unsigned char buf[256];
    int rc = 0;
    int cnt = 0;

    fp1 = owfuzz_config_open(NULL);
    if(fp1 != NULL)
    {
        while (!feof(fp1))
        {
            memset(buf, 0, sizeof(buf));
            if(fgets(buf, sizeof(buf), fp1))
            {
                if(buf[0] == '#' || buf[0] == '\r' || buf[0] == '\n')
                    continue;

                if(buf[0]=='['){
                    if(strstr(buf, "[interfaces]") && (rc == 0)){
                        rc = 1;
                        continue;
                    }
                    else{
                        if(rc == 1)
                        {
                            rc = 0;
                            break;
                        }
                        else continue;
                    }
                }

                if(rc)
                {
                    memset(fo->ois[cnt].osdep_iface_out, 0, sizeof(fo->ois[cnt].osdep_iface_out));
                    sscanf(buf, "%[^=]=%d", fo->ois[cnt].osdep_iface_out, &fo->ois[cnt].channel);
                    if(cnt == 0)
                        fo->channel = fo->ois[cnt].channel;
                    cnt++;
                }
            }
        }

        fo->ois_cnt = cnt;
    }
    else{
        fuzz_logger_log(FUZZ_LOG_ERR, "Open owfuzz.cfg failed.");
        return -1;
    }

    fclose(fp1);
    return 0;
}

int owfuzz_config_get_channels(fuzzing_option *fo)
{
    FILE *fp1;
    unsigned char buf[256];
    char iface[64] = {0};
    int rc = 0;
    int cnt = 0;

    fp1 = owfuzz_config_open(NULL);
    if(fp1 != NULL)
    {
        while (!feof(fp1))
        {
            memset(buf, 0, sizeof(buf));
            if(fgets(buf, sizeof(buf), fp1))
            {
                if(buf[0] == '#' || buf[0] == '\r' || buf[0] == '\n')
                    continue;

                if(buf[0]=='['){
                    if(strstr(buf, "[interfaces]") && (rc == 0)){
                        rc = 1;
                        continue;
                    }
                    else{
                        if(rc == 1)
                        {
                            rc = 0;
                            break;
                        }
                        else continue;
                    }
                }

                if(rc)
                {
                    memset(iface, 0, sizeof(iface));
                    sscanf(buf, "%[^=]=%d", iface, &fo->ois[cnt].channel);
                    fuzz_logger_log(FUZZ_LOG_DEBUG,"interface: %s, channel: %d\n", iface, fo->ois[cnt].channel);
                    cnt++;
                }
            }
        }

        fo->ois_cnt = cnt;
    }
    else{
        fuzz_logger_log(FUZZ_LOG_ERR, "Open owfuzz.cfg failed.");
        return -1;
    }

    fclose(fp1);
    return 0;    
}

int owfuzz_config_get_macs(fuzzing_option *fo)
{
    FILE *fp1;
    unsigned char buf[512];
    char option_name[256];
    char option_value[256];
    int rc = 0;

    fp1 = owfuzz_config_open(NULL);
    if(fp1 != NULL)
    {
        while (!feof(fp1))
        {
            memset(buf, 0, sizeof(buf));
            if(fgets(buf, sizeof(buf), fp1))
            {
                if(buf[0] == '#' || buf[0] == '\r' || buf[0] == '\n')
                    continue;

                if(buf[0]=='['){
                    if(strstr(buf, "[fuzzing_option]") && (rc == 0)){
                        rc = 1;
                        continue;
                    }
                    else{
                        if(rc == 1)
                        {
                            rc = 0;
                            break;
                        }
                        else continue;
                    }
                }

                if(rc)
                {
                    memset(option_name, 0, sizeof(option_name));
                    memset(option_value, 0, sizeof(option_value));

                    sscanf(buf, "%[^=]=%s", option_name, option_value);

                    fuzz_logger_log(FUZZ_LOG_DEBUG, "option_name: %s, option_value: %s", option_name, option_value);

                    if(!strcmp(option_name, "target_mac")){
                        fo->target_addr = parse_mac(option_value);
                    }
                    else if(!strcmp(option_name, "bssid")){
                        fo->bssid = parse_mac(option_value);
                    }
                    else if(!strcmp(option_name, "source_mac")){
                        fo->source_addr = parse_mac(option_value);
                    }
                }
            }
        }
    }
    else{
        fuzz_logger_log(FUZZ_LOG_ERR, "Open owfuzz.cfg failed.");
        return -1;
    }

    fclose(fp1);
    return 0;       
}

int owfuzz_config_get_fuzzing_option(fuzzing_option *fo)
{
    FILE *fp1;
    unsigned char buf[512];
    char option_name[256];
    char option_value[256];
    int rc = 0;

    fp1 = owfuzz_config_open(NULL);
    if(fp1 != NULL)
    {
        while (!feof(fp1))
        {
            memset(buf, 0, sizeof(buf));
            if(fgets(buf, sizeof(buf), fp1))
            {
                if(buf[0] == '#' || buf[0] == '\r' || buf[0] == '\n')
                    continue;

                if(buf[0]=='['){
                    if(strstr(buf, "[fuzzing_option]") && (rc == 0)){
                        rc = 1;
                        continue;
                    }
                    else{
                        if(rc == 1)
                        {
                            rc = 0;
                            break;
                        }
                        else continue;
                    }
                }

                if(rc)
                {
                    memset(option_name, 0, sizeof(option_name));
                    memset(option_value, 0, sizeof(option_value));

                    sscanf(buf, "%[^=]=%s", option_name, option_value);

                    fuzz_logger_log(FUZZ_LOG_DEBUG, "option_name: %s, option_value: %s", option_name, option_value);

                    if(!strcmp(option_name, "fuzz_mode")){
                        strncpy(fo->mode, option_value, sizeof(fo->mode));
                        if(strcmp(fo->mode, STA_MODE) == 0)
                        {
                            fo->fuzz_work_mode = FUZZ_WORK_MODE_STA;
                        }
                        else if(strcmp(fo->mode, AP_MODE) == 0)
                        {
                            fo->fuzz_work_mode = FUZZ_WORK_MODE_AP;
                        }
                        else if(strcmp(fo->mode, MITM_MODE) == 0)
                        {
                            fo->fuzz_work_mode = FUZZ_WORK_MODE_MITM;
                        }
                    }
                    else if(!strcmp(option_name, "target_mac")){
                        strncpy(fo->sztarget_addr, option_value, sizeof(fo->sztarget_addr)-1);
                        fo->target_addr = parse_mac(option_value);
                    }
                    else if(!strcmp(option_name, "bssid")){
                        strncpy(fo->szbssid, option_value, sizeof(fo->szbssid)-1);
                        fo->bssid = parse_mac(option_value);
                    }
                    else if(!strcmp(option_name, "source_mac")){
                        strncpy(fo->szsource_addr, option_value, sizeof(fo->szsource_addr)-1);
                        fo->source_addr = parse_mac(option_value);
                    }
                    else if(!strcmp(option_name, "target_ip")){
                        if(strlen(option_value))
                        {
                            strncpy(fo->target_ip, option_value, sizeof(fo->target_ip)-1);
                            if(inet_addr(fo->target_ip) == INADDR_NONE)
                            {
                                fuzz_logger_log(FUZZ_LOG_ERR, "Target's IP is error: %s", fo->target_ip);
                                fclose(fp1);
                                return -1;
                            }
                        }

                    }
                    else if(!strcmp(option_name, "ssid")){
                        if(strlen(option_value)>32)
                        {
                            fuzz_logger_log(FUZZ_LOG_ERR, "ERROR: AP's SSID is too long, limit 32 bytes.");
                            fclose(fp1);
                            return -1;
                        }

                        if(strlen(option_value) != 0)
                            strncpy(fo->target_ssid, option_value, sizeof(fo->target_ssid)-1);
                    }
                    else if(!strcmp(option_name, "auth_type")){

                        if(strcmp(option_value, "OPEN_NONE") == 0){
                            fo->auth_type = OPEN_NONE;
                        }else if(strcmp(option_value, "OPEN_WEP") == 0){
                            fo->auth_type = OPEN_WEP;
                        }else if(strcmp(option_value, "SHARE_WEP") == 0){
                            fo->auth_type = SHARE_WEP;
                        }else if(strcmp(option_value, "WPA_PSK_TKIP") == 0){
                            fo->auth_type = WPA_PSK_TKIP;
                        }else if(strcmp(option_value, "WPA_PSK_AES") == 0){
                            fo->auth_type = WPA_PSK_AES;
                        }else if(strcmp(option_value, "WPA_PSK_TKIP_AES") == 0){
                            fo->auth_type = WPA_PSK_TKIP_AES;
                        }else if(strcmp(option_value, "WPA2_PSK_TKIP") == 0){
                            fo->auth_type = WPA2_PSK_TKIP;
                        }else if(strcmp(option_value, "WPA2_PSK_AES") == 0){
                            fo->auth_type = WPA2_PSK_AES;
                        }else if(strcmp(option_value, "WPA2_PSK_TKIP_AES") == 0){
                            fo->auth_type = WPA2_PSK_TKIP_AES;
                        }else if(strcmp(option_value, "EAP_8021X") == 0){
                            fo->auth_type = EAP_8021X;
                        }else if(strcmp(option_value, "WPA3") == 0){
                            fo->auth_type = WPA3;
                        }else{
                            fuzz_logger_log(FUZZ_LOG_ERR, "Fuzzing target's auth type is wrong.");
                            fo->auth_type = WPA2_PSK_TKIP_AES;
                        }
                    }
                    else if(!strcmp(option_name, "test_type")){
                        fo->test_type = atoi(option_value);
                    }
                    else if(!strcmp(option_name, "log_level")){
                        fo->log_level = atoi(option_value);
                    }
                    else if(!strcmp(option_name, "log_file")){
                        strncpy(fo->log_file, option_value, sizeof(fo->log_file)-1);
                    }
                }
            }
        }
    }
    else{
        fuzz_logger_log(FUZZ_LOG_ERR, "Open owfuzz.cfg failed.");
        return -1;
    }

    fclose(fp1);
    return 0;    
}

int owfuzz_add_virtual_interface(char *iface, char *vif, char *type)
{
    char exec_cmd[256] = {0};

    sprintf(exec_cmd, "sudo iw %s interface add %s type %s", iface, vif, type);
    fuzz_logger_log(FUZZ_LOG_INFO, exec_cmd);

    return system(exec_cmd);
}

int owfuzz_del_virtual_interface(char *vif)
{
    char exec_cmd[256] = {0};

    sprintf(exec_cmd, "sudo iw dev %s del", vif);
    fuzz_logger_log(FUZZ_LOG_INFO, exec_cmd);

    return system(exec_cmd);
}

int owfuzz_change_interface_mac(char *iface, char *mac)
{
    char exec_cmd[256] = {0};

    sprintf(exec_cmd, "sudo macchanger -m %s %s", mac, iface);
    fuzz_logger_log(FUZZ_LOG_INFO, exec_cmd);

    return system(exec_cmd);
}