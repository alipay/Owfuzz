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
#include <stdint.h>
#ifndef FUZZ_CONTROL_H
#define FUZZ_CONTROL_H

int init(char *interface, int chan);
int reinit(char *interface, int chan);
int send_frame(struct packet *pkt);

int init_ex();
int oi_init(struct osdep_instance *oi);
struct packet read_packet_ex();
int send_packet_ex(struct packet *pkt);

int fuzzing(int argc, char *argv[]);
int load_payloads();
void save_exp_payload(struct packet *pkt);
void save_packet(struct packet *pkt);
void print_status(struct packet *pkt);
void sniff_ies(struct packet *pkt);
const char *return_frame_name(uint8_t type);

#endif
