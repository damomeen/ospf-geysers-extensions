/*
 * This file is part of phosphorus-g2mpls.
 *
 * Copyright (C) 2006, 2007, 2008, 2009 Nextworks s.r.l.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301 USA.
 *
 * Authors:
 *
 * Giacomo Bernini       (Nextworks s.r.l.) <g.bernini_at_nextworks.it>
 * Gino Carrozzo         (Nextworks s.r.l.) <g.carrozzo_at_nextworks.it>
 * Nicola Ciulli         (Nextworks s.r.l.) <n.ciulli_at_nextworks.it>
 * Giodi Giorgi          (Nextworks s.r.l.) <g.giorgi_at_nextworks.it>
 * Francesco Salvestrini (Nextworks s.r.l.) <f.salvestrini_at_nextworks.it>
 */




#ifndef __G2MPLS_UTILS_H__
#define __G2MPLS_UTILS_H__

#ifdef __cplusplus

#include "g2mpls_types.h"

#include <iostream>
#include <fstream>
#include <stdlib.h>
#include <sstream>
#include <iomanip>

bool GridResSpecUpdate(grid_res_spec_t & dst, const grid_res_spec_t & src);
bool NetResSpecUpdate(net_res_spec_t & dst, const net_res_spec_t & src);
bool ResSpecUpdate(res_spec_t & dst, const res_spec_t & src);

#endif /* __cplusplus */

#endif /* __G2MPLS_UTILS_H__ */
