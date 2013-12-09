/*
 *  This file is part of phosphorus-g2mpls.
 *
 *  Copyright (C) 2006, 2007, 2008, 2009 PSNC
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 *  Authors:
 *
 *  Giacomo Bernini (Nextworks s.r.l.)   <g.bernini_at_nextworks.it>
 */

#ifndef _ZEBRA_CORBA_H_
#define _ZEBRA_CORBA_H_

#include "prefix.h"
#include "zserv.h"

#ifdef __cplusplus
extern "C" {
#endif

int corba_server_setup(void);
int corba_node_server_setup(void);
int corba_tel_client_setup(void);
int corba_glob_client_setup(void);

int zebra_retrieve_telinks_from_lrm(struct zserv * client,
				    uint32_t       type);
int zebra_retrieve_rid_from_lrm(adj_type_t  type,
				uint32_t *  addr, uint32_t* powerConsumption);
#ifdef __cplusplus
}
#endif


#endif
