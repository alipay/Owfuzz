include Makefile.inc

SUBDIRS = capture_linux_wifi


CTRL_LINUX_WIFI_OBJS = ./kismet_wifi_control.o ./interface_control.o ./wifi_ht_channels.o ./capture_linux_wifi/linux_wireless_rfkill.o ./capture_linux_wifi/linux_wireless_control.o ./capture_linux_wifi/linux_netlink_control.o


LIB = libctrlwifi.a 


all: $(LIB) 

$(LIB) : $(CTRL_LINUX_WIFI_OBJS)
	$(AR) crvs $(LIB) $(CTRL_LINUX_WIFI_OBJS)


install:

clean:
	@for dir in $(SUBDIRS); \
		do $(MAKE) -C $$dir clean || exit 1; \
	done \

	@-rm -f $(LIB)
	@-rm -f *.o *.so *.a *~
