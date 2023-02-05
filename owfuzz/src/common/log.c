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

#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include "log.h"

static int default_level = FUZZ_LOG_INFO;
// static char *log_file = "fuzzer.log";
static int log_fd = INVALID_FD;
void fuzz_logger_init(int log_level, char *file_log)
{
	if (log_level != -1)
		default_level = log_level;

	if (NULL != file_log && strlen(file_log) > 0) {
		fuzz_logger_log(FUZZ_LOG_INFO, "Opening '%s' for logging.", file_log);
		log_fd = open(file_log, O_RDWR | O_CREAT | O_APPEND | O_SYNC, 0);
	}
	/*else
		log_fd = open(log_file, O_RDWR|O_CREAT|O_APPEND|O_SYNC, 0);	*/

	// log_fd = 2;
}

void fuzz_logger_log(int level, const char *fmt, ...)
{
	va_list args;
	char buf[MAX_PRINT_BUF_LEN + 2] = {0};
	if (level > default_level)
	{
		return;
	}

	va_start(args, fmt);
	int len = vsnprintf(buf, MAX_PRINT_BUF_LEN, fmt, args);

	if (len >= MAX_PRINT_BUF_LEN)
	{
		len = MAX_PRINT_BUF_LEN;
	}

	buf[len] = '\n';
	len += 1;
	buf[len] = 0;

	va_end(args);

	if (log_fd != INVALID_FD)
	{
		write(log_fd, buf, len);
		fsync(log_fd);
	}
	else
	{
		printf("%s", buf);
	}
}

void fuzz_logger_cleanup(void)
{
	if (log_fd != INVALID_FD)
	{
		close(log_fd);
	}
}
