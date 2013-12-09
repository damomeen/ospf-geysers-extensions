## Process this file with Automake to create Makefile.in

DEFS = @DEFS@ -DSYSCONFDIR=\"$(sysconfdir)/\"

LIBS = @LIBS@ @CURSES@ @LIBPAM@

bin_PROGRAMS = gmpls-vtysh

gmpls_vtysh_SOURCES  = vtysh_main.c vtysh.c vtysh_user.c vtysh_config.c
gmpls_vtysh_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/lib -I$(top_srcdir)/common
gmpls_vtysh_LDADD    = $(top_builddir)/lib/libzebra.la $(top_builddir)/common/libg2mpls.la $(G2MPLS_LIBS) @LIBCAP@ @LIBREADLINE@

nodist_gmpls_vtysh_SOURCES = vtysh_cmd.c
CLEANFILES = vtysh_cmd.c
noinst_HEADERS = vtysh.h vtysh_user.h

examplesdir = $(exampledir)
dist_examples_DATA = vtysh.conf.sample

EXTRA_DIST = extract.pl

vtysh_cmd_FILES =							\
		$(top_srcdir)/lib/vty.c					\
		$(top_srcdir)/ospfd/*.c

vtysh_cmd.c: $(vtysh_cmd_FILES)
	./$(EXTRA_DIST) $(vtysh_cmd_FILES) > vtysh_cmd.c

