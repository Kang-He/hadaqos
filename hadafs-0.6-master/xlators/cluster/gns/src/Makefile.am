
xlator_LTLIBRARIES = gns.la
xlatordir = $(libdir)/hadafs/$(PACKAGE_VERSION)/xlator/cluster

gns_la_LDFLAGS = -module -avoidversion

gns_la_SOURCES = gns.c
gns_la_LIBADD = $(top_builddir)/libhadafs/src/libhadafs.la

noinst_HEADERS = gns.h

AM_CFLAGS = -fPIC -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE -Wall -D$(HF_HOST_OS) \
	-I$(top_srcdir)/libhadafs/src -shared -nostartfiles $(HF_CFLAGS)

CLEANFILES = 

