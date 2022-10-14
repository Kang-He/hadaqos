
xlator_LTLIBRARIES = lvolume.la
xlatordir = $(libdir)/hadafs/$(PACKAGE_VERSION)/xlator/cluster

lvolume_la_LDFLAGS = -module -avoidversion

lvolume_la_SOURCES = lvolume.c
lvolume_la_LIBADD = $(top_builddir)/libhadafs/src/libhadafs.la

noinst_HEADERS = lvolume.h

AM_CFLAGS = -fPIC -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE -Wall -D$(HF_HOST_OS) \
	-I$(top_srcdir)/libhadafs/src -shared -nostartfiles $(HF_CFLAGS)

CLEANFILES = 

