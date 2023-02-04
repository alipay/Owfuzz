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

#ifndef _CONFIG_H
#define _CONFIG_H

#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <pthread.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/time.h>

#include "../frames/frame.h"

FILE *owfuzz_config_open(char *cfg_file);
int owfuzz_config_get_sta_frames(char *cfg_file, uint8_t *owfuzz_frames, uint32_t *frame_cnt);
int owfuzz_config_get_ap_frames(char *cfg_file, uint8_t *owfuzz_frames, uint32_t *frame_cnt);
int owfuzz_config_get_interfaces(char *cfg_file, fuzzing_option *fo);
int owfuzz_config_get_fuzzing_option(char *cfg_file, fuzzing_option *fo);
int owfuzz_config_get_channels(char *cfg_file, fuzzing_option *fo);
int owfuzz_config_get_macs(char *cfg_file, fuzzing_option *fo);
int owfuzz_config_get_ies_status(char *cfg_file, fuzzing_option *fo);
int owfuzz_config_get_ext_ies_status(char *cfg_file, fuzzing_option *fo);

int owfuzz_add_virtual_interface(char *iface, char *vif, char *type);
int owfuzz_del_virtual_interface(char *vif);
int owfuzz_change_interface_mac(char *iface, char *mac);

#endif
