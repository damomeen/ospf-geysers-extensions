## Process this file with automake to produce Makefile.in.

AM_CPPFLAGS = -I.. -I$(top_srcdir) -I$(top_srcdir)/lib -I$(top_srcdir)/common @SNMP_INCLUDES@

DEFS = @DEFS@ $(LOCAL_OPTS) -DSYSCONFDIR=\"$(sysconfdir)/\"
INSTALL_SDATA=@INSTALL@ -m 600

lib_LTLIBRARIES    = libospf.la
libospf_la_LDFLAGS = -version 0:0:0

bin_PROGRAMS = gmpls-ospf

if CORBA
noinst_LIBRARIES = libcorba.a
libcorba_a_CFLAGS  =				\
	$(OMNIORB_CFLAGS)			\
	$(GMPLS_IDL_CFLAGS)

libcorba_a_CXXFLAGS  =				\
	$(OMNIORB_CFLAGS)			\
	$(GMPLS_IDL_CFLAGS)

libcorba_a_SOURCES = \
	ospf_corba.cxx				\
    ospf_corba_utils.cxx
endif

libospf_la_SOURCES = \
	ospf_abr.c ospf_api.c ospf_apiserver.c ospf_asbr.c \
	ospf_ase.c ospf_dump.c ospf_flood.c ospf_ia.c ospf_interface.c \
	ospf_ism.c ospf_lsa.c ospf_lsdb.c ospf_neighbor.c ospf_network.c ospf_nsm.c \
	ospf_opaque.c ospf_packet.c ospf_route.c ospf_routemap.c ospf_snmp.c ospf_spf.c \
	ospf_te.c ospf_vty.c ospf_zebra.c ospf_scngw.c ospfd.c

ospfdheaderdir = $(pkgincludedir)/ospfd

noinst_HEADERS =				\
	ospf_abr.h				\
	ospf_api.h				\
	ospf_apiserver.h			\
	ospf_asbr.h				\
	ospf_ase.h				\
	ospf_corba.h				\
	ospf_corba_utils.h			\
	ospf_dump.h				\
	ospf_flood.h				\
	ospf_ia.h				\
	ospf_interface.h			\
	ospf_ism.h				\
	ospf_lsa.h				\
	ospf_lsdb.h				\
	ospf_neighbor.h				\
	ospf_network.h				\
	ospf_nsm.h				\
	ospf_opaque.h				\
	ospf_packet.h				\
	ospf_route.h				\
	ospf_snmp.h				\
	ospf_spf.h				\
	ospf_te.h				\
	ospf_vty.h				\
	ospf_zebra.h				\
	ospf_scngw.h				\
	ospfd.h

gmpls_ospf_SOURCES = ospf_main.c

gmpls_ospf_LDADD =

gmpls_ospf_LDADD +=				\
	libospf.la				\
	../lib/libzebra.la			\
	../common/libg2mpls.la			\
	$(G2MPLS_LIBS)				\
	@LIBCAP@

if CORBA
gmpls_ospf_LDADD +=				\
	libcorba.a				\
	$(GMPLS_IDL_LIBS)
endif

##EXTRA_DIST = XXX-MIB.txt XXX-TRAP-MIB.txt ChangeLog.opaque.txt

do_subst = sed					\
  -e 's,[@]LOGFILEDIR[@],${quagga_statedir},g'	\
  -e 's,[@]CONFDIR[@],${sysconfdir},g'

ospfd.conf.sample: Makefile $(srcdir)/ospfd.conf.sample.in
	( echo "Creating $@" && \
	  rm -f $@ $@.tmp && \
	  $(do_subst) < $(srcdir)/ospfd.conf.sample.in > $@.tmp && \
	  mv -f $@.tmp $@ ) || { \
		rm -f $@ $@.tmp ; \
		exit 1 ; \
	}
EXTRA_DIST = ospfd.conf.sample.in

examplesdir = $(exampledir)
dist_examples_DATA = ospfd.conf.sample

CLEANFILES = *.pid *.log ospfd.conf.sample *.vty
