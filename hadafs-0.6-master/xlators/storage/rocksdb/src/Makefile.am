
xlator_LTLIBRARIES = rocksdb.la
xlatordir = $(libdir)/hadafs/$(PACKAGE_VERSION)/xlator/storage

rocksdb_la_LDFLAGS = -module -avoidversion

rocksdb_la_SOURCES = rocksdb.c  name-server.c
rocksdb_la_LIBADD = $(top_builddir)/libhadafs/src/libhadafs.la 

noinst_HEADERS = rocksdb.h

AM_CFLAGS = -fPIC -fno-strict-aliasing -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE -D$(HF_HOST_OS) -Wall \
	-I$(top_srcdir)/libhadafs/src -shared -nostartfiles -I. -lstdc++ -lbz2 -llz4 -lz -lzstd \
	-I/usr/local/include/rocksdb -L/usr/local/lib -lrocksdb \
	$(HF_CFLAGS)

CLEANFILES = 

