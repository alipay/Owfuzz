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

#ifndef LOG_H
#define LOG_H

#define FUZZ_LOG_STDERR 0
#define FUZZ_LOG_EMERG 1
#define FUZZ_LOG_ALERT 2
#define FUZZ_LOG_CRIT 3
#define FUZZ_LOG_ERR 4
#define FUZZ_LOG_WARN 5
#define FUZZ_LOG_NOTICE 6
#define FUZZ_LOG_INFO 7
#define FUZZ_LOG_DEBUG 8

#define INVALID_FD -1

// #define DEBUG_LOG 1

#define true 1
#define false 0

#define MAX_PRINT_BUF_LEN 4096

void fuzz_logger_init(int log_level, char *file_log);
void fuzz_logger_log(int level, const char *fmt, ...);

#endif
