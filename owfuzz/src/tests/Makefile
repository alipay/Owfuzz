RELATIVE_PATH = ../../

NETLINKLIBS = -lnl-genl-3 -lnl-3

OBJS = test_wi_read test_wi_write test_wi_threads

all: $(OBJS)

test_wi_read: test_wi_read.c
	gcc -g test_wi_read.c \
		-I/usr/include/unicode/ \
		-I$(RELATIVE_PATH)linux_wifi/trans/ \
		$(RELATIVE_PATH)linux_wifi/trans/osdep/osdep.o \
		$(RELATIVE_PATH)linux_wifi/trans/osdep/network.o \
		$(RELATIVE_PATH)linux_wifi/control/wifi_ht_channels.o \
		$(RELATIVE_PATH)linux_wifi/control/capture_linux_wifi/linux_netlink_control.o \
		$(RELATIVE_PATH)linux_wifi/trans/osdep/common.o \
		$(RELATIVE_PATH)linux_wifi/trans/osdep/radiotap/radiotap.o \
		$(RELATIVE_PATH)linux_wifi/trans/osdep/linux.o \
		$(RELATIVE_PATH)linux_wifi/trans/osdep/file.o \
		-o test_wi_read \
		-lm \
		$(NETLINKLIBS)

test_wi_write: test_wi_write.c
	gcc -g test_wi_write.c \
		-I/usr/include/unicode/ \
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

test_wi_threads: test_wi_threads.c
	gcc -g test_wi_threads.c \
		-I/usr/include/unicode/ \
		-I$(RELATIVE_PATH)linux_wifi/trans/ \
		$(RELATIVE_PATH)linux_wifi/trans/osdep/osdep.o \
		$(RELATIVE_PATH)linux_wifi/trans/osdep/network.o \
		$(RELATIVE_PATH)linux_wifi/control/wifi_ht_channels.o \
		$(RELATIVE_PATH)linux_wifi/control/capture_linux_wifi/linux_netlink_control.o \
		$(RELATIVE_PATH)linux_wifi/trans/osdep/common.o \
		$(RELATIVE_PATH)linux_wifi/trans/osdep/radiotap/radiotap.o \
		$(RELATIVE_PATH)linux_wifi/trans/osdep/linux.o \
		$(RELATIVE_PATH)linux_wifi/trans/osdep/file.o \
		-o test_wi_threads \
		-lm \
		$(NETLINKLIBS)

clean:
	rm $(OBJS)
