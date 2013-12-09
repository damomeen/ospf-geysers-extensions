//
//  This file is part of phosphorus-g2mpls.
//
//  Copyright (C) 2006, 2007, 2008, 2009 PSNC
//
//  This program is free software; you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation; either version 2 of the License, or
//  (at your option) any later version.
//
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//
//  You should have received a copy of the GNU General Public License along
//  with this program; if not, write to the Free Software Foundation, Inc.,
//  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
//  Authors:
//
//  Adam Kaliszan         (PSNC)             <kaliszan_at_man.poznan.pl>
//  Damian Parniewicz     (PSNC)             <damianp_at_man.poznan.pl>
//  Lukasz Lopatowski     (PSNC)             <llopat_at_man.poznan.pl>
//  Jakub Gutkowski       (PSNC)             <jgutkow_at_man.poznan.pl>
//

#if HAVE_OMNIORB

#include <zebra.h>
#include "log.h"

#include "g2mpls_addr.h"
#include "g2mpls_types.h"
#include "ospfd/ospf_corba.h"

#include "types.hh"


typedef enum {
  OCD_ACTION_SENT,
  OCD_ACTION_ABORTED
} ocd_action_t;

typedef enum {
  OCD_SERV_G2PCERA,
  OCD_SERV_GUNIGW
} ocd_server_t;

typedef enum {
  OCD_TYPE_TNA,
  OCD_TYPE_TELINK
} ocd_type_t;

void OSPF_CORBA_DEBUG(ocd_type_t type, ocd_action_t action, ocd_server_t server, string msgStr,
                      gmplsTypes::tnaIdent tnaIdent, gmplsTypes::teLinkIdent linkIdent);

gmplsTypes::nodeType                   nodeType_from_node_type_t               (node_type_t type);
gmplsTypes::linkMode                   linkMode_from_link_mode_t               (link_mode_t mode);

gmplsTypes::switchingCap               switching_cap_from_uchar                (uint8_t value);
uint8_t                                 switching_cap_from_enum                 (gmplsTypes::switchingCap swCap);
gmplsTypes::encodingType               encoding_type_from_uchar                (uint8_t value);
uint8_t                                 encoding_type_from_enum                 (gmplsTypes::encodingType encType);

gmplsTypes::srlgSeq                    diffSrlgs                               (gmplsTypes::srlgSeq srlgs1, gmplsTypes::srlgSeq srlgs2);
gmplsTypes::teLinkCalendarSeq          diffCalendars                           (gmplsTypes::teLinkCalendarSeq cal1, gmplsTypes::teLinkCalendarSeq cal2);
gmplsTypes::iscSeq                     diffIscs                                (gmplsTypes::iscSeq iscs1, gmplsTypes::iscSeq iscs2);

bool  isNodeInSeq                       (gmplsTypes::nodeIdent nodeIdent, gmplsTypes::nodeIdentSeq* nodeSeq);
bool  isTnaIdinSeq                      (gmplsTypes::tnaIdent tna, gmplsTypes::tnaIdentSeq* tnaSeq);
bool  isTELinkInSeq                     (gmplsTypes::teLinkIdent ident, gmplsTypes::teLinkIdentSeq* linkSeq);

bool  equalNetNodes                     (gmplsTypes::netNodeParams* nodeParams1, gmplsTypes::netNodeParams* nodeParams2);
bool  equalTeLinks                      (const gmplsTypes::teLinkIdent* linkParams1, gmplsTypes::teLinkIdent* linkParams2);
bool  equalComParams                    (gmplsTypes::teLinkComParams* comParam1, gmplsTypes::teLinkComParams* comParam2);
bool  equalTdmParams                    (gmplsTypes::teLinkTdmParams* tdmParam1, gmplsTypes::teLinkTdmParams* tdmParam2);
bool  equalLscG709Params                (gmplsTypes::teLinkLscG709Params* lscG709Params1, gmplsTypes::teLinkLscG709Params* lscG709Params2);
bool  equalLscWdmParams                 (gmplsTypes::teLinkLscWdmParams lscWdmParam1, gmplsTypes::teLinkLscWdmParams lscWdmParam2);
bool  equalLinkStates                   (gmplsTypes::statesBundle* states1, gmplsTypes::statesBundle* states2);
bool  equalTdmBw                        (gmplsTypes::freeCTPSeq freeCTP1, gmplsTypes::freeCTPSeq freeCTP2);
bool  equalLscG709Bw                    (gmplsTypes::freeCTPSeq freeODUk, gmplsTypes::freeCTPSeq freeOCh, gmplsTypes::freeCTPSeq serverFreeODUk, gmplsTypes::freeCTPSeq serverFreeOCh);
bool  equalLscWdmBw                     (gmplsTypes::teLinkWdmLambdasBitmap bitmap1, gmplsTypes::teLinkWdmLambdasBitmap bitmap2);

typedef enum {
  ISCS_GEN  ,
  ISCS_TDM  ,
  ISCS_PSC
} iscs_type_t;


#endif // HAVE_OMNIORB
