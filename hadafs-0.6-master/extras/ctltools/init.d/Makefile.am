
EXTRA_DIST = hadafsd-Debian hadafsd-Redhat hadafsd-SuSE hadafs-server.plist

CLEANFILES = 

initdir = @initdir@

$(HF_DISTRIBUTION): 
	$(mkdir_p) $(DESTDIR)$(initdir)	
	$(INSTALL_PROGRAM) hadafsd-$(HF_DISTRIBUTION) $(DESTDIR)$(initdir)/hadafsd

install-exec-local: $(HF_DISTRIBUTION)

install-data-local: 
if HF_DARWIN_HOST_OS
	cp hadafs-server.plist /Library/LaunchDaemons/com.hada.hadafs.plist 
endif
