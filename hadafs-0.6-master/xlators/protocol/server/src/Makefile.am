xlator_LTLIBRARIES = server.la
xlatordir = $(libdir)/hadafs/$(PACKAGE_VERSION)/xlator/protocol

server_la_LDFLAGS = -module -avoidversion

server_la_SOURCES = server-protocol.c server-helpers.c
server_la_LIBADD = $(top_builddir)/libhadafs/src/libhadafs.la

noinst_HEADERS = server-protocol.h server-helpers.h

AM_CFLAGS = -fPIC -O3 -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE -Wall -D$(HF_HOST_OS) \
	-I$(top_srcdir)/libhadafs/src -shared -nostartfiles -L/usr/lib/\
	-DDATADIR=\"$(localstatedir)\" -DCONFDIR=\"$(sysconfdir)/hadafs\"  \
	$(HF_CFLAGS)

CLEANFILES = 

