
SUBDIRS = control trans

all:
	@for dir in $(SUBDIRS); \
		do $(MAKE) -C $$dir || exit 1; \
	done \



test_main:


clean:
	@for dir in $(SUBDIRS); \
		do $(MAKE) -C $$dir clean || exit 1; \
	done \

	rm -f *.o *.so *.a *~


