## Process this file with automake to produce Makefile.in.

SUBDIRS = common lib zebra ospfd vtysh

EXTRA_DIST =					\
	aclocal.m4				\
	vtysh/Makefile.in vtysh/Makefile.am	\
	config.h userconfig.h++

SERVICES: Makefile
	grep VTY_PORT `find ./ -name "*.h"` `find ./ -name "*.hh"` `find ./ -name "*.c"` `find ./ -name "*.cxx"` | grep define | sed -e 's,^.*\define *,,' > SERVICES || { \
		rm -f SERVICES ; \
		exit 1 ; \
	}

all-local: SERVICES

DISTCLEANFILES = SERVICES

ACLOCAL_AMFLAGS = -I m4

BUILT_SOURCES = $(top_srcdir)/.version
$(top_srcdir)/.version:
	echo $(VERSION) > $@-t && mv $@-t $@

dist-hook:
	echo $(VERSION) > $(distdir)/.tarball-version
