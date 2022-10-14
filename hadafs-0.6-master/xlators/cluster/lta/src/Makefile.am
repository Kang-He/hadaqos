
xlator_LTLIBRARIES = lta.la
xlatordir = $(libdir)/hadafs/$(PACKAGE_VERSION)/xlator/cluster

lta_la_LDFLAGS = -module -avoidversion

lta_la_SOURCES = lta.c lta-metaup.c
lta_la_LIBADD = $(top_builddir)/libhadafs/src/libhadafs.la

noinst_HEADERS = lta.h

AM_CFLAGS = -fPIC -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE -Wall -D$(HF_HOST_OS) \
	-I$(top_srcdir)/libhadafs/src -shared -nostartfiles $(HF_CFLAGS)

CLEANFILES = 

