noinst_HEADERS = socket.h name.h

transport_LTLIBRARIES = socket.la
transportdir = $(libdir)/hadafs/$(PACKAGE_VERSION)/transport

socket_la_LDFLAGS = -module -avoidversion

socket_la_SOURCES = socket.c name.c
socket_la_LIBADD = $(top_builddir)/libhadafs/src/libhadafs.la 

AM_CFLAGS = -fPIC -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE -Wall -D$(HF_HOST_OS)\
	-I$(top_srcdir)/libhadafs/src -shared -nostartfiles $(HF_CFLAGS)

CLEANFILES = *~
