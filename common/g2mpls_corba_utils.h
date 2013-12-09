/*
 *  This file is part of phosphorus-g2mpls.
 *
 *  Copyright (C) 2006, 2007, 2008, 2009 Nextworks s.r.l.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as
 *  published by the Free Software Foundation; either version 2.1
 *  of the License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA 02110-1301 USA.
 *
 *  Authors:
 *
 *  Giacomo Bernini       (Nextworks s.r.l.) <g.bernini_at_nextworks.it>
 *  Gino Carrozzo         (Nextworks s.r.l.) <g.carrozzo_at_nextworks.it>
 *  Nicola Ciulli         (Nextworks s.r.l.) <n.ciulli_at_nextworks.it>
 *  Giodi Giorgi          (Nextworks s.r.l.) <g.giorgi_at_nextworks.it>
 *  Francesco Salvestrini (Nextworks s.r.l.) <f.salvestrini_at_nextworks.it>
 */


#include <config.h>

#include "g2mpls_addr.h"
#include "g2mpls_types.h"

#if HAVE_OMNIORB

#ifdef __cplusplus

#include "types.hh"
#include "gmpls.hh"

using namespace std;

#include <omniORB4/CORBA.h>

#include <iostream>
#include <fstream>
#include <stdlib.h>
#include <stdexcept>
#include <sstream>
#include <iomanip>

// nodeId
g2mpls_addr_t &
operator << (g2mpls_addr_t &                     dst,
	     const gmplsTypes::nodeId &         src);

gmplsTypes::nodeId &
operator << (gmplsTypes::nodeId &               dst,
	     const g2mpls_addr_t &               src);

std::string &
operator << (std::string &                       dst,
	     const gmplsTypes::nodeId &         src);


// linkId
g2mpls_addr_t &
operator << (g2mpls_addr_t &                     dst,
	     const gmplsTypes::linkId_var &     src);

gmplsTypes::linkId_var &
operator << (gmplsTypes::linkId_var &           dst,
	     const g2mpls_addr_t &               src);

std::string &
operator << (std::string &                       dst,
	     const gmplsTypes::linkId_var &     src);

bool
operator == (const g2mpls_addr_t &               dst,
	     const gmplsTypes::linkId_var &     src);

// labelId
label_id_t &
operator<< (label_id_t &                         dst,
	    const gmplsTypes::labelId_var &     src);

gmplsTypes::labelId_var &
operator<< (gmplsTypes::labelId_var &           dst,
	    const label_id_t &                   src);

std::string &
operator<< (std::string &                        dst,
	    const gmplsTypes::labelId_var &     src);

// xcDirection
xcdirection_t &
operator<< (xcdirection_t &                      dst,
	    const gmplsTypes::xcDirection &     src);

gmplsTypes::xcDirection &
operator<< (gmplsTypes::xcDirection &           dst,
	    const xcdirection_t &                src);

std::string &
operator << (std::string &                       dst,
	     const gmplsTypes::xcDirection &    src);

// tnrcResult
std::string &
operator << (std::string &                       dst,
	     const gmplsTypes::tnrcResult &     src);

// adjType
adj_type_t &
operator << (adj_type_t &                        dst,
	     const gmplsTypes::adjType &        src);

gmplsTypes::adjType &
operator << (gmplsTypes::adjType &              dst,
	     const adj_type_t &                  src);
bool
operator == (const adj_type_t &                  dst,
	     const gmplsTypes::adjType &        src);

std::string &
operator << (std::string &                       dst,
	     const gmplsTypes::adjType &        src);

// operState
opstate_t &
operator << (opstate_t &                         dst,
	     const gmplsTypes::operState &      src);

gmplsTypes::operState &
operator << (gmplsTypes::operState &            dst,
	     const opstate_t &                   src);

std::string &
operator << (std::string &                       dst,
	     const gmplsTypes::operState &      src);

// adminState
admstate_t &
operator << (admstate_t &                        dst,
	     const gmplsTypes::adminState &     src);

gmplsTypes::adminState &
operator << (gmplsTypes::adminState &           dst,
	     const admstate_t &                  src);

std::string &
operator << (std::string &                       dst,
	     const gmplsTypes::adminState &     src);

// switchingCap
sw_cap_t &
operator << (sw_cap_t &                          dst,
	     const gmplsTypes::switchingCap &   src);

gmplsTypes::switchingCap &
operator << (gmplsTypes::switchingCap &         dst,
	     const sw_cap_t  &                   src);

std::string &
operator << (std::string &                       dst,
	     const gmplsTypes::switchingCap &   src);

// encodingType
enc_type_t &
operator << (enc_type_t &                        dst,
	     const gmplsTypes::encodingType &   src);

gmplsTypes::encodingType &
operator << (gmplsTypes::encodingType &         dst,
	     const enc_type_t &                  src);

std::string &
operator << (std::string &                       dst,
	     const gmplsTypes::encodingType &   src);

// labelState
label_state_t &
operator << (label_state_t &                     dst,
	     const gmplsTypes::labelState &     src);

gmplsTypes::labelState &
operator << (gmplsTypes::labelState &           dst,
	     const label_state_t &               src);

std::string &
operator << (std::string &                       dst,
	     const gmplsTypes::labelState &     src);

// sourceId
g2mpls_addr_t &
operator<<(g2mpls_addr_t &                          dst,
	   const gmplsTypes::sourceId_var &        src);

gmplsTypes::sourceId_var &
operator<<(gmplsTypes::sourceId_var &              dst,
	   const g2mpls_addr_t &                    src);

std::string &
operator<<(std::string &                            dst,
	   const gmplsTypes::sourceId_var &        src);


// tnaId
g2mpls_addr_t &
operator<<(g2mpls_addr_t &                          dst,
	   const gmplsTypes::tnaId_var &           src);

gmplsTypes::tnaId_var &
operator<<(gmplsTypes::tnaId_var &                 dst,
	   const g2mpls_addr_t &                    src);

std::string &
operator<<(std::string &                            dst,
	   const gmplsTypes::tnaId_var &           src);

// labelId
label_id_t &
operator<<(label_id_t &                             dst,
	   const gmplsTypes::labelId_var &         src);

gmplsTypes::labelId_var &
operator<<(gmplsTypes::labelId_var &               dst,
	   const label_id_t &                       src);

std::string &
operator<<(std::string &                            dst,
	   const gmplsTypes::labelId_var &         src);

// callIdent
call_ident_t &
operator<<(call_ident_t &                           dst,
	   const gmplsTypes::callIdent_var &       src);

gmplsTypes::callIdent_var &
operator<<(gmplsTypes::callIdent_var &             dst,
	   const call_ident_t &                     src);

// tnResource
net_res_spec_t &
operator<<(net_res_spec_t &                         dst,
	   const gmplsTypes::tnResource_var &      src);

gmplsTypes::tnResource_var &
operator<<(gmplsTypes::tnResource_var &            dst,
	   const net_res_spec_t &                   src);

// tnaResource
net_res_spec_t &
operator<<(net_res_spec_t &                         dst,
	   const gmplsTypes::tnaResource_var &     src);

gmplsTypes::tnaResource_var &
operator<<(gmplsTypes::tnaResource_var &           dst,
	   const net_res_spec_t &                   src);

// callParams
call_info_t &
operator<<(call_info_t &                            dst,
	   const gmplsTypes::callParams_var &      src);

gmplsTypes::callParams_var &
operator<<(gmplsTypes::callParams_var &            dst,
	   const call_info_t &                      src);

// recoveryParams
recovery_info_t &
operator<<(recovery_info_t &                        dst,
	   const gmplsTypes::recoveryParams_var &  src);

gmplsTypes::recoveryParams_var &
operator<<(gmplsTypes::recoveryParams_var &        dst,
	   const recovery_info_t &                  src);

// lspIdent
lsp_ident_t &
operator<<(lsp_ident_t &                            dst,
	   const gmplsTypes::lspIdent_var &        src);

gmplsTypes::lspIdent_var &
operator<<(gmplsTypes::lspIdent_var &              dst,
	   const lsp_ident_t &                      src);

// lspParams
lsp_info_t &
operator<<(lsp_info_t &                             dst,
	   const gmplsTypes::lspParams_var &       src);

gmplsTypes::lspParams_var &
operator<<(gmplsTypes::lspParams_var &             dst,
	   const lsp_info_t &                       src);

// wdmLambdasBitmap
wdm_link_lambdas_bitmap_t &
operator<<(wdm_link_lambdas_bitmap_t &               dst,
	   const gmplsTypes::wdmLambdasBitmap_var & src);

gmplsTypes::wdmLambdasBitmap_var &
operator<<(gmplsTypes::wdmLambdasBitmap_var &      dst,
	   const wdm_link_lambdas_bitmap_t &        src);

// errorInfo
error_info_t &
operator<<(error_info_t &                           dst,
	   const gmplsTypes::errorInfo_var &       src);

gmplsTypes::errorInfo_var &
operator<<(gmplsTypes::errorInfo_var &             dst,
	   const error_info_t &                     src);


#endif // __cplusplus

#endif // HAVE_OMNIORB
