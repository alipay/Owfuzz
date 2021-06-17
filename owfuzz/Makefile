# owfuzz
# Copyright (C) 2020 Hongjian Cao <haimohk@gmail.com> 

TOP_PATH = $(shell pwd)

CXX		= g++
CC		= gcc
LD 		= g++
CCLD	= gcc


LDFLAGS		+= 
CFLAGS		+= -Wall -I/usr/include/pcap -I/usr/include/libnl3 -I$(TOP_PATH)/../include -I$(TOP_PATH)/linux_wifi/control -I$(TOP_PATH)/linux_wifi/trans -L$(TOP_PATH)/linux_wifi/control -L$(TOP_PATH)/linux_wifi/trans -I$(TOP_PATH)/src/hostapd_lib -I$(TOP_PATH)/src/hostapd_lib/utils
CXXFLAGS	+= -Wall
CPPFLAGS	+= 

LIBS		+= -lcap -lncurses -ldw -lz -lpcre -lsqlite3
KSLIBS		+= -pthread -lpthread

PTHREADLIBS = -lpthread
NETLINKLIBS = -lnl-genl-3 -lnl-3
KISMETWIFI	= -lctrlwifi
OSDEPWIFI	= -losdep
LIBMLIB = -lm -lpcap

export TOP_PATH CXX CC LD CCLD LDFLAGS CFLAGS CXXFLAGS CPPFLAGS LIBS KSLIBS PTHREADLIBS NETLINKLIBS KISMETWIFI OSDEPWIFI LIBMLIB

SUBDIRS = linux_wifi src

all: subdir

subdir:
	@for dir in $(SUBDIRS); \
		do $(MAKE) -C $$dir || exit 1; \
	done \



.PHONY : clean
clean:
	@for dir in $(SUBDIRS); do $(MAKE) -C $$dir clean || exit 1; \
	done \

	rm -f *.o *.so *.a *~

