RELATIVE_PATH = ../../

NETLINKLIBS = -lnl-genl-3 -lnl-3

test_wi_write: test_wi_write.c
	gcc test_wi_write.c \
		-I$(RELATIVE_PATH)linux_wifi/trans/ \
		$(RELATIVE_PATH)linux_wifi/trans/osdep/osdep.o \
		$(RELATIVE_PATH)linux_wifi/trans/osdep/network.o \
		$(RELATIVE_PATH)linux_wifi/control/wifi_ht_channels.o \
		$(RELATIVE_PATH)linux_wifi/control/capture_linux_wifi/linux_netlink_control.o \
		$(RELATIVE_PATH)linux_wifi/trans/osdep/common.o \
		$(RELATIVE_PATH)linux_wifi/trans/osdep/radiotap/radiotap.o \
		$(RELATIVE_PATH)linux_wifi/trans/osdep/linux.o \
		$(RELATIVE_PATH)linux_wifi/trans/osdep/file.o \
		-o test_wi_write \
		-lm \
		$(NETLINKLIBS)

all: test_wi_write
