# owfuzz
#
# Copyright (C) 2020 E7mer <haimohk@gmail.com>
#

export TOP_PATH CXX CC LD CCLD LDFLAGS CFLAGS CXXFLAGS CPPFLAGS LIBS KSLIBS PTHREADLIBS NETLINKLIBS KISMETWIFI OSDEPWIFI LIBMLIB

CFLAGS+= -g

SUBDIRS = frames common procedures

FRAMEOBJ = 	./common/queue.o ./common/config.o ./common/pcap_log.o ./common/log.o \
			./common/mac_addr.o ./frames/frame.o ./frames/80211_packet_common.o \
			./frames/management/beacon.o ./frames/management/ies_creator.o \
			./frames/management/probe_response.o ./frames/management/association_response.o ./frames/management/reassociation_response.o \
			./frames/management/timing_advertisement.o ./frames/management/authentication.o ./frames/management/action.o ./frames/management/deauthentication.o \
			./frames/management/disassociation.o ./frames/management/action_no_ack.o ./frames/management/association_request.o \
			./frames/management/reassociation_request.o \
			./frames/management/probe_request.o ./frames/management/atim.o \
			./frames/control/acknowledgement.o ./frames/control/beamforming_report_poll.o ./frames/control/block_ack_request.o ./frames/control/block_ack.o \
			./frames/control/cf_end_cf_ack.o ./frames/control/cf_end.o ./frames/control/control_frame_extension.o \
			./frames/control/control_wrapper.o ./frames/control/cts.o ./frames/control/ps_poll.o ./frames/control/rts.o \
			./frames/control/vht_ndp_announcement.o \
			./frames/data/qos_data.o ./frames/data/data.o ./frames/data/d_cf_ack_poll.o ./frames/data/d_cf_ack.o ./frames/data/d_cf_poll.o \
			./frames/data/data_cf_ack_poll.o \
			./frames/data/data_cf_ack.o ./frames/data/data_cf_poll.o ./frames/data/data_null.o ./frames/data/qos_cf_ack_poll.o ./frames/data/qos_cf_poll.o \
			./frames/data/qos_cf_ack.o \
			./frames/data/qos_data_cf_ack_poll.o ./frames/data/qos_data_cf_ack.o ./frames/data/qos_data_cf_poll.o ./frames/data/qos_null.o \
			./procedures/direct/direct.o ./procedures/awdl/awdl.o ./procedures/awdl/awdl_frame.o ./procedures/awdl/wire.o ./procedures/mesh/mesh.o \


OBJS = owfuzz.o fuzz_control.o hashtable.o

all: subdir owfuzz

subdir:
	@for dir in $(SUBDIRS); \
		do $(MAKE) -C $$dir || exit 1; \
	done \

owfuzz: $(OBJS) $(FRAMEOBJ)
	$(CC) $(OBJS) $(FRAMEOBJ) $(CFLAGS) -o $(@) $(KISMETWIFI) $(OSDEPWIFI) $(LIBMLIB) $(PTHREADLIBS) $(NETLINKLIBS)

rmsym:
	strip -g owfuzz
	strip -s owfuzz
	strip --remove-section=.symtab owfuzz
	#strip --remove-section=.dynsym owfuzz


.PHONY : clean
clean:
	@for dir in $(SUBDIRS); do $(MAKE) -C $$dir clean || exit 1; \
	done \

	rm -f *.o *.so *.a *~ owfuzz
