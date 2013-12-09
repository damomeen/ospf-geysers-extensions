#
#  This file is part of phosphorus-g2mpls.
#
#  Copyright (C) 2006, 2007, 2008, 2009 Nextworks s.r.l.
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU Lesser General Public License as published by
#  the Free Software Foundation; either version 2.1 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU Lesser General Public License
#  along with this program; if not, write to the Free Software Foundation,
#  Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
#  Authors:
#
#  Giacomo Bernini       (Nextworks s.r.l.) <g.bernini_at_nextworks.it>
#  Gino Carrozzo         (Nextworks s.r.l.) <g.carrozzo_at_nextworks.it>
#  Nicola Ciulli         (Nextworks s.r.l.) <n.ciulli_at_nextworks.it>
#  Giodi Giorgi          (Nextworks s.r.l.) <g.giorgi_at_nextworks.it>
#  Francesco Salvestrini (Nextworks s.r.l.) <f.salvestrini_at_nextworks.it>
#

## Process this file with automake to produce Makefile.in.

#DEFS = -DSYSCONFDIR=\"$(sysconfdir)/\"

lib_LTLIBRARIES = libg2mpls.la

libg2mpls_la_CPPFLAGS =					\
	-I.. -I$(top_srcdir) -I$(top_srcdir)/idl

libg2mpls_la_CFLAGS =				\
	 $(GMPLS_IDL_CFLAGS)
libg2mpls_la_CXXFLAGS =				\
	 $(GMPLS_IDL_CFLAGS)

libg2mpls_la_SOURCES =				\
	g2mpls_addr.c				\
	g2mpls_utils.cxx			\
	g2mpls_corba_utils.cxx

pkginclude_HEADERS =				\
	g2mpls_addr.h				\
	g2mpls_types.h				\
	g2mpls_utils.h				\
	g2mpls_corba_utils.h
