
xlator_LTLIBRARIES = gvolume.la
xlatordir = $(libdir)/hadafs/$(PACKAGE_VERSION)/xlator/cluster

gvolume_la_LDFLAGS = -module -avoidversion

gvolume_la_SOURCES = gvolume.c
gvolume_la_LIBADD = $(top_builddir)/libhadafs/src/libhadafs.la

noinst_HEADERS = gvolume.h

AM_CFLAGS = -fPIC -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE -Wall -D$(HF_HOST_OS) \
	-I$(top_srcdir)/libhadafs/src -shared -nostartfiles $(HF_CFLAGS)

CLEANFILES = 

