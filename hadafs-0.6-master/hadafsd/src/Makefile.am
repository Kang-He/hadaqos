sbin_PROGRAMS = hadafsd

hadafsd_SOURCES = hadafsd.c fetch-spec.c genvol.c
hadafsd_LDADD = $(top_builddir)/libhadafs/src/libhadafs.la $(HF_LDADD)
hadafsd_LDFLAGS = $(HF_LDFLAGS) $(HF_HADAFS_LDFLAGS)
noinst_HEADERS = hadafsd.h

AM_CFLAGS = -fPIC -Wall -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE -D$(HF_HOST_OS)\
	-I$(top_srcdir)/libhadafs/src -DDATADIR=\"$(localstatedir)\" \
	-DCONFDIR=\"$(sysconfdir)/hadafs\" $(HF_HADAFS_CFLAGS)

CLEANFILES = 

$(top_builddir)/libhadafs/src/libhadafs.la:
	$(MAKE) -C $(top_builddir)/libhadafs/src/ all

uninstall-local:
	rm -f $(DESTDIR)$(sbindir)/hadafs

install-data-local:
	$(INSTALL) -d -m 755 $(DESTDIR)$(localstatedir)/run
	$(INSTALL) -d -m 755 $(DESTDIR)$(localstatedir)/log/hadafs
	rm -f $(DESTDIR)$(sbindir)/hadafs
	ln -s hadafsd $(DESTDIR)$(sbindir)/hadafs
