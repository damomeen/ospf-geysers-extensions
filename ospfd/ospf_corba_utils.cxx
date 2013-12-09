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

#include "g2mpls_corba_utils.h"
#include "ospfd/ospf_corba_utils.h"
#include "types.hh"


void OSPF_CORBA_DEBUG(ocd_type_t type, ocd_action_t action, ocd_server_t server, string msgStr,
                      gmplsTypes::tnaIdent tnaIdent, gmplsTypes::teLinkIdent linkIdent)
{
  string actionStr = "";
  switch (action)
  {
    case OCD_ACTION_SENT:    actionStr = "Sent";    break;
    case OCD_ACTION_ABORTED: actionStr = "Aborted sending"; break;
  }

  string serverStr = "";
  switch (server)
  {
    case OCD_SERV_G2PCERA: serverStr = "G2PCERA"; break;
    case OCD_SERV_GUNIGW:  serverStr = "GUNIGW";  break;
  }

  zlog_debug("[DBG] CORBA: %s %s message to %s", actionStr.c_str(), msgStr.c_str(), serverStr.c_str());

  gmplsTypes::tnaId_var tmpTna;
  gmplsTypes::TELinkId_var tmpLink;
  std::string tnaIdStr;
  std::string localIdStr;
  std::string remoteIdStr;
  std::string lclNodeIdStr;
  std::string rmtNodeIdStr;

  switch (type)
  {
    case OCD_TYPE_TNA:
      struct in_addr nodeId;
      nodeId.s_addr = htonl(tnaIdent.node);
      tmpTna = tnaIdent.tna;
      tnaIdStr << tmpTna;
      zlog_debug("[DBG]        Node id: %s, TNA id: %s", inet_ntoa(nodeId), tnaIdStr.c_str());
      break;

    case OCD_TYPE_TELINK:
      struct in_addr lclNodeId, rmtNodeId;
      lclNodeId.s_addr = htonl(linkIdent.localNodeId);
      rmtNodeId.s_addr = htonl(linkIdent.remoteNodeId);
      lclNodeIdStr = inet_ntoa(lclNodeId);
      rmtNodeIdStr = inet_ntoa(rmtNodeId);

      tmpLink = linkIdent.localId;
      localIdStr << tmpLink;
      tmpLink = linkIdent.remoteId;
      remoteIdStr << tmpLink;

      zlog_debug("[DBG]        Lcl node id: %s,  Rmt node id: %s", lclNodeIdStr.c_str(), rmtNodeIdStr.c_str());
      zlog_debug("[DBG]        Lcl id: %s,  Rmt id: %s", localIdStr.c_str(), remoteIdStr.c_str());
      break;
  }
  return;
}

gmplsTypes::nodeType
nodeType_from_node_type_t(node_type_t type)
{
  gmplsTypes::nodeType ntype;
  switch (type)
  {
    case NTYPE_UNKNOWN: ntype = gmplsTypes::NODETYPE_UNKNOWN; break;
    case NTYPE_NETWORK: ntype = gmplsTypes::NODETYPE_NETWORK; break;
  }
  return ntype;
}

gmplsTypes::linkMode
linkMode_from_link_mode_t(link_mode_t mode)
{
  gmplsTypes::linkMode lmode;
  switch (mode)
  {
    case LINKM_UNKNOWN:          lmode = gmplsTypes::LINKMODE_UNKNOWN;          break;
    case LINKM_P2P_UNNUMBERED:   lmode = gmplsTypes::LINKMODE_P2P_UNNUMBERED;   break;
    case LINKM_P2P_NUMBERED:     lmode = gmplsTypes::LINKMODE_P2P_NUMBERED;     break;
    case LINKM_MULTIACCESS:      lmode = gmplsTypes::LINKMODE_MULTIACCESS;      break;
    case LINKM_ENNI_INTERDOMAIN: lmode = gmplsTypes::LINKMODE_ENNI_INTERDOMAIN; break;
    case LINKM_ENNI_INTRADOMAIN: lmode = gmplsTypes::LINKMODE_ENNI_INTRADOMAIN; break;
  }
  return lmode;
}

gmplsTypes::switchingCap
switching_cap_from_uchar(uint8_t value)
{
  gmplsTypes::switchingCap cap;
  switch (value)
  {
    case 1:   cap = gmplsTypes::SWITCHINGCAP_PSC_1; break;
    case 2:   cap = gmplsTypes::SWITCHINGCAP_PSC_2; break;
    case 3:   cap = gmplsTypes::SWITCHINGCAP_PSC_3; break;
    case 4:   cap = gmplsTypes::SWITCHINGCAP_PSC_4; break;
    case 51:  cap = gmplsTypes::SWITCHINGCAP_L2SC;  break;
    case 100: cap = gmplsTypes::SWITCHINGCAP_TDM;   break;
    case 150: cap = gmplsTypes::SWITCHINGCAP_LSC;   break;
    case 200: cap = gmplsTypes::SWITCHINGCAP_FSC;   break;
  }
  return cap;
}

uint8_t
switching_cap_from_enum(gmplsTypes::switchingCap swCap)
{
  switch (swCap)
  {
    case gmplsTypes::SWITCHINGCAP_PSC_1: return 1;
    case gmplsTypes::SWITCHINGCAP_PSC_2: return 2;
    case gmplsTypes::SWITCHINGCAP_PSC_3: return 3;
    case gmplsTypes::SWITCHINGCAP_PSC_4: return 4;
    case gmplsTypes::SWITCHINGCAP_L2SC:  return 51;
    case gmplsTypes::SWITCHINGCAP_TDM:   return 100;
    case gmplsTypes::SWITCHINGCAP_LSC:   return 150;
    case gmplsTypes::SWITCHINGCAP_FSC:   return 200;
  }
  return 0;
}

gmplsTypes::encodingType
encoding_type_from_uchar(uint8_t value)
{
  gmplsTypes::encodingType type;
  switch (value)
  {
    case 1:  type = gmplsTypes::ENCODINGTYPE_PACKET;          break;
    case 2:  type = gmplsTypes::ENCODINGTYPE_ETHERNET;        break;
    case 3:  type = gmplsTypes::ENCODINGTYPE_ANSI_ETSI_PDH;   break;
    case 4:  type = gmplsTypes::ENCODINGTYPE_RESERVED_1;      break;
    case 5:  type = gmplsTypes::ENCODINGTYPE_SDH_SONET;       break;
    case 6:  type = gmplsTypes::ENCODINGTYPE_RESERVED_2;      break;
    case 7:  type = gmplsTypes::ENCODINGTYPE_DIGITAL_WRAPPER; break;
    case 8:  type = gmplsTypes::ENCODINGTYPE_LAMBDA;          break;
    case 9:  type = gmplsTypes::ENCODINGTYPE_FIBER;           break;
    case 10: type = gmplsTypes::ENCODINGTYPE_RESERVED_3;      break;
    case 11: type = gmplsTypes::ENCODINGTYPE_FIBERCHANNEL;    break;
    case 12: type = gmplsTypes::ENCODINGTYPE_G709_ODU;        break;
    case 13: type = gmplsTypes::ENCODINGTYPE_G709_OC;         break;
  }
  return type;
}

uint8_t
encoding_type_from_enum(gmplsTypes::encodingType encType)
{
  switch (encType)
  {
    case gmplsTypes::ENCODINGTYPE_PACKET:          return 1;
    case gmplsTypes::ENCODINGTYPE_ETHERNET:        return 2;
    case gmplsTypes::ENCODINGTYPE_ANSI_ETSI_PDH:   return 3;
    case gmplsTypes::ENCODINGTYPE_RESERVED_1:      return 4;
    case gmplsTypes::ENCODINGTYPE_SDH_SONET:       return 5;
    case gmplsTypes::ENCODINGTYPE_RESERVED_2:      return 6;
    case gmplsTypes::ENCODINGTYPE_DIGITAL_WRAPPER: return 7;
    case gmplsTypes::ENCODINGTYPE_LAMBDA:          return 8;
    case gmplsTypes::ENCODINGTYPE_FIBER:           return 9;
    case gmplsTypes::ENCODINGTYPE_RESERVED_3:     return 10;
    case gmplsTypes::ENCODINGTYPE_FIBERCHANNEL:   return 11;
    case gmplsTypes::ENCODINGTYPE_G709_ODU:       return 12;
    case gmplsTypes::ENCODINGTYPE_G709_OC:        return 13;
  }
  return 0;
}

bool isNodeInSeq(gmplsTypes::nodeIdent nodeIdent, gmplsTypes::nodeIdentSeq* nodeSeq)
{
  gmplsTypes::nodeIdent tmp;
  for (int i =0; i<nodeSeq->length(); i++) {
    tmp = (*nodeSeq)[i];
    if ((tmp.typee == nodeIdent.typee) && (tmp.id == nodeIdent.id))
      return true;
  }
  return false;
}

bool isTnaIdinSeq(gmplsTypes::tnaIdent tna, gmplsTypes::tnaIdentSeq* tnaSeq)
{
  gmplsTypes::tnaIdent tmp;

  g2mpls_addr_t addr1;
  g2mpls_addr_t addr2;

  gmplsTypes::tnaId_var tna1;
  gmplsTypes::tnaId_var tna2;
  tna1 = tna.tna;
  addr1 << tna1;

  for (int i =0; i<tnaSeq->length(); i++) {
    tmp = (*tnaSeq)[i];
    tna2 = tmp.tna;
    addr2 << tna2;
    if ((tmp.rc == tna.rc) && (tmp.node == tna.node) && addr_equal(addr1, addr2) && (tmp.prefix == tna.prefix))
      return true;
  }
  return false;
}

bool isTELinkInSeq(gmplsTypes::teLinkIdent ident, gmplsTypes::teLinkIdentSeq* linkSeq)
{
  gmplsTypes::teLinkIdent tmp;

  g2mpls_addr_t lclAddr1, rmtAddr1;
  g2mpls_addr_t lclAddr2, rmtAddr2;

  gmplsTypes::TELinkId_var lclTeLinkId1, rmtTeLinkId1; 
  gmplsTypes::TELinkId_var lclTeLinkId2, rmtTeLinkId2;

  lclTeLinkId1 = ident.localId;
  lclAddr1 << lclTeLinkId1;
  rmtTeLinkId1 = ident.remoteId;
  rmtAddr1 << rmtTeLinkId1;

  for (int i =0; i<linkSeq->length(); i++) {
    tmp = (*linkSeq)[i];
    lclTeLinkId2 = tmp.localId;
    lclAddr2 << lclTeLinkId2;
    rmtTeLinkId2 = tmp.remoteId;
    rmtAddr2 << rmtTeLinkId2;

    if ((tmp.localNodeId == ident.localNodeId) 
      && (tmp.remoteNodeId == ident.remoteNodeId)
      && addr_equal(lclAddr1, lclAddr2)
      && addr_equal(rmtAddr1, rmtAddr2)
      && (tmp.mode == ident.mode)
      && (tmp.localRcId == ident.localRcId)
      && (tmp.remoteRcId == ident.remoteRcId))
      return true;
  }
  return false;
}

bool equalTeLinks(const gmplsTypes::teLinkIdent* linkParams1, gmplsTypes::teLinkIdent* linkParams2)
{
  g2mpls_addr_t lclAddr1, rmtAddr1;
  g2mpls_addr_t lclAddr2, rmtAddr2;

  gmplsTypes::TELinkId_var lclTeLinkId1, rmtTeLinkId1; 
  gmplsTypes::TELinkId_var lclTeLinkId2, rmtTeLinkId2;

  lclTeLinkId1 = linkParams1->localId;
  lclAddr1 << lclTeLinkId1;
  rmtTeLinkId1 = linkParams1->remoteId;
  rmtAddr1 << rmtTeLinkId1;

  lclTeLinkId2 = linkParams2->localId;
  lclAddr2 << lclTeLinkId2;
  rmtTeLinkId2 = linkParams2->remoteId;
  rmtAddr2 << rmtTeLinkId2;

  if (linkParams1->localNodeId != linkParams2->localNodeId)
    return false;
  if (linkParams1->remoteNodeId != linkParams2->remoteNodeId)
    return false;
  if (!addr_equal(lclAddr1, lclAddr2))
    return false;
  if (!addr_equal(rmtAddr1, rmtAddr2))
    return false;
  if (linkParams1->mode != linkParams2->mode)
    return false;
  if (linkParams1->localRcId != linkParams2->localRcId)
    return false;
  if (linkParams1->remoteRcId != linkParams2->remoteRcId)
    return false;

  return true;
}

bool equalNetNodes(gmplsTypes::netNodeParams* nodeParams1, gmplsTypes::netNodeParams* nodeParams2)
{
  if (nodeParams1->isDomain != nodeParams2->isDomain)
    return false;
  if (nodeParams1->aState.opState != nodeParams2->aState.opState)
    return false;
  if (nodeParams1->aState.admState != nodeParams2->aState.admState)
    return false;
  if (nodeParams1->colors != nodeParams2->colors)
    return false;
  if (nodeParams1->areas.length() != nodeParams2->areas.length())
    return false;
  if (nodeParams1->powerConsumption != nodeParams2->powerConsumption)
    return false;
  for (int i =0; i<nodeParams1->areas.length(); i++) {
    if (nodeParams1->areas[i] != nodeParams2->areas[i])
      return false; 
  }
  return true;
}

bool equalComParams(gmplsTypes::teLinkComParams* comParam1, gmplsTypes::teLinkComParams* comParam2)
{
  if (comParam1->adminMetric != comParam2->adminMetric)
    return false;
  if (comParam1->teMetric != comParam2->teMetric)
    return false;
  if (comParam1->teColorMask != comParam2->teColorMask)
    return false;
  if (comParam1->teProtectionTypeMask != comParam2->teProtectionTypeMask)
    return false;
  if (comParam1->teMaxBw != comParam2->teMaxBw)
    return false;
  if (comParam1->teMaxResvBw != comParam2->teMaxResvBw)
    return false;
  if (comParam1->vlinkBwReplanning.length() != comParam2->vlinkBwReplanning.length())
    return false;
  if (comParam1->vlinkBwReplanning.length() > 0 && (comParam1->vlinkBwReplanning[0].maxBwUpgrade != comParam2->vlinkBwReplanning[0].maxBwUpgrade))
    return false;  
  if (comParam1->vlinkBwReplanning.length() > 0 && (comParam1->vlinkBwReplanning[0].maxBwDowngrade != comParam2->vlinkBwReplanning[0].maxBwDowngrade))
    return false;  
  return true;
}

bool equalTdmParams(gmplsTypes::teLinkTdmParams* tdmParam1, gmplsTypes::teLinkTdmParams* tdmParam2)
{
  if (tdmParam1->hoMuxCapMask != tdmParam2->hoMuxCapMask)
    return false;
  if (tdmParam1->loMuxCapMask != tdmParam2->loMuxCapMask)
    return false;
  if (tdmParam1->transparencyMask != tdmParam2->transparencyMask)
    return false;
  if (tdmParam1->blsrRingId != tdmParam2->blsrRingId)
    return false;

  return true;
}

bool equalLscG709Params(gmplsTypes::teLinkLscG709Params* lscG709Params1, gmplsTypes::teLinkLscG709Params* lscG709Params2)
{
  //TODO

  return false;
}

bool equalLscWdmParams(gmplsTypes::teLinkLscWdmParams lscWdmParam1, gmplsTypes::teLinkLscWdmParams lscWdmParam2)
{
  if (lscWdmParam1.dispersionPMD != lscWdmParam2.dispersionPMD)
    return false;
  if (lscWdmParam1.spanLength != lscWdmParam2.spanLength)
    return false;
  if (lscWdmParam1.amplifiers.length() != lscWdmParam2.amplifiers.length())
    return false;

  for (int i =0; i< lscWdmParam1.amplifiers.length(); i++) {
    if (lscWdmParam1.amplifiers[i].gain != lscWdmParam2.amplifiers[i].gain)
      return false; 
    if (lscWdmParam1.amplifiers[i].noiseFigure != lscWdmParam2.amplifiers[i].noiseFigure)
      return false;
  }
  return true;
}

bool equalLinkStates(gmplsTypes::statesBundle* states1, gmplsTypes::statesBundle* states2)
{
  if (states1->opState != states2->opState)
    return false;
  if (states1->admState != states2->admState)
    return false;

  return true;
}

bool equalTdmBw(gmplsTypes::freeCTPSeq freeCTP1, gmplsTypes::freeCTPSeq freeCTP2)
{
  if (freeCTP1.length() != freeCTP2.length())
    return false;

  for (int i =0; i< freeCTP1.length(); i++) {
    if (freeCTP1[i].sigType != freeCTP2[i].sigType)
      return false; 
    if (freeCTP1[i].ctps != freeCTP2[i].ctps)
      return false;
  }
  return true;
}

bool equalLscG709Bw(gmplsTypes::freeCTPSeq freeODUk1, gmplsTypes::freeCTPSeq freeOCh1,
                    gmplsTypes::freeCTPSeq freeODUk2, gmplsTypes::freeCTPSeq freeOCh2)
{
  if (freeODUk1.length() != freeODUk2.length())
    return false;
  if (freeOCh1.length() != freeOCh2.length())
    return false;

  for (int i =0; i< freeODUk1.length(); i++) {
    if (freeODUk1[i].sigType != freeODUk2[i].sigType)
      return false; 
    if (freeODUk1[i].ctps != freeODUk2[i].ctps)
      return false;
  }

  for (int i =0; i< freeOCh1.length(); i++) {
    if (freeOCh1[i].sigType != freeOCh2[i].sigType)
      return false; 
    if (freeOCh1[i].ctps != freeOCh2[i].ctps)
      return false;
  }
  return true;
}

bool equalLscWdmBw(gmplsTypes::teLinkWdmLambdasBitmap bitmap1, gmplsTypes::teLinkWdmLambdasBitmap bitmap2)
{
  if (bitmap1.baseLambda != bitmap2.baseLambda)
    return false;
  if (bitmap1.numLambdas != bitmap2.numLambdas)
    return false;
  if (bitmap1.bitmap.length() != bitmap2.bitmap.length())
    return false;

  for (int i=0; i< bitmap1.bitmap.length(); i++)
    if (bitmap1.bitmap[i] != bitmap2.bitmap[i])
      return false;

  return true;
}

gmplsTypes::srlgSeq diffSrlgs(gmplsTypes::srlgSeq srlgs1, gmplsTypes::srlgSeq srlgs2)
{
  gmplsTypes::srlgSeq_var seq;
  gmplsTypes::srlgSeq * tmp;
  bool *ind = new bool[srlgs1.length()];
  for (int m=0; m<srlgs1.length(); m++)
    ind[m] = false;

  int count = srlgs1.length();

  for (int i=0; i< srlgs1.length(); i++)
    for (int j=0; j< srlgs2.length(); j++)
  {
      if (srlgs1[i] == srlgs2[j])
      {
        count--;
        ind[i] = true;
      }
  }

  tmp = new gmplsTypes::srlgSeq(count);
  seq = tmp;
  seq->length(count);

  int index = 0;
  for (int m=0; m<srlgs1.length(); m++)
    if (ind[m] == false)
  {
    seq[index] = srlgs1[m];
    index++;
  }

  return seq;
}

gmplsTypes::teLinkCalendarSeq diffCalendars(gmplsTypes::teLinkCalendarSeq cal1, gmplsTypes::teLinkCalendarSeq cal2)
{
  gmplsTypes::teLinkCalendarSeq_var seq;
  gmplsTypes::teLinkCalendarSeq * tmp;
  bool *ind = new bool[cal1.length()];
  for (int m=0; m<cal1.length(); m++)
    ind[m] = false;

  int count = cal1.length();
  bool equal;

  for (int i=0; i< cal1.length(); i++)
    for (int j=0; j< cal2.length(); j++)
  {
    if (cal1[i].unixTime == cal2[j].unixTime)
    {
      equal = true;
      for (int k=0; k<8; k++)
        if (cal1[i].availBw[k] != cal2[j].availBw[k])
          equal = false;

      if (equal) {
        count--;
        ind[i] = true;
      }
    }
  }

  tmp = new gmplsTypes::teLinkCalendarSeq(count);
  seq = tmp;
  seq->length(count);

  int index = 0;
  for (int m=0; m<cal1.length(); m++)
    if (ind[m] == false)
  {
    seq[index] = cal1[m];
    index++;
  }

  return seq;
}

gmplsTypes::iscSeq diffIscs(gmplsTypes::iscSeq iscs1, gmplsTypes::iscSeq iscs2)
{
  gmplsTypes::isc_var isc1;
  gmplsTypes::isc_var isc2;
  gmplsTypes::iscParamsTdm_var tdm1;
  gmplsTypes::iscParamsTdm_var tdm2;
  gmplsTypes::iscParamsPsc_var psc1;
  gmplsTypes::iscParamsPsc_var psc2;
  gmplsTypes::iscParamsGen_var gen1;
  gmplsTypes::iscParamsGen_var gen2;

  gmplsTypes::iscSeq_var seq;
  gmplsTypes::iscSeq * tmp;
  bool *ind = new bool[iscs1.length()];
  for (int m=0; m<iscs1.length(); m++)
    ind[m] = false;

  int count = iscs1.length();

  bool equal;
  for (int i=0; i< iscs1.length(); i++)
    for (int j=0; j< iscs2.length(); j++)
  {
    isc1 = iscs1[i];
    isc2 = iscs2[j];

    if (isc1->_d() == isc2->_d())
    {
      switch (isc1->_d())
      {
        case gmplsTypes::SWITCHINGCAP_PSC_1:
        case gmplsTypes::SWITCHINGCAP_PSC_2:
        case gmplsTypes::SWITCHINGCAP_PSC_3:
        case gmplsTypes::SWITCHINGCAP_PSC_4:

          psc1 = isc1->psc();
          psc2 = isc2->psc();

          equal = true;

          if (psc1->swCap != psc2->swCap)
            equal = false;
          if (psc1->encType != psc2->encType)
            equal = false;
          if (psc1->minLSPbandwidth != psc2->minLSPbandwidth)
            equal = false;
          if (psc1->interfaceMTU != psc2->interfaceMTU)
            equal = false;

          for (int k=0; k<8; k++)
            if (psc1->maxLSPbandwidth[k] != psc2->maxLSPbandwidth[k])
              equal = false;

          if (equal) {
            count--;
            ind[i] = true;
          }

          break;

        case gmplsTypes::SWITCHINGCAP_TDM  :

          tdm1 = isc1->tdm();
          tdm2 = isc2->tdm();

          equal = true;

          if (tdm1->swCap != tdm2->swCap)
            equal = false;
          if (tdm1->encType != tdm2->encType)
            equal = false;
          if (tdm1->indication != tdm2->indication)
            equal = false;

          for (int k=0; k<8; k++)
            if (tdm1->maxLSPbandwidth[k] != tdm2->maxLSPbandwidth[k])
              equal = false;

          if (equal) {
            count--;
            ind[i] = true;
          }

          break;

        case gmplsTypes::SWITCHINGCAP_L2SC :
        case gmplsTypes::SWITCHINGCAP_LSC  :
        case gmplsTypes::SWITCHINGCAP_FSC  :

          gen1 = isc1->gen();
          gen2 = isc2->gen();

          equal = true;

          if (gen1->swCap != gen2->swCap)
            equal = false;
          if (gen1->encType != gen2->encType)
            equal = false;

          for (int k=0; k<8; k++)
            if (gen1->maxLSPbandwidth[k] != gen2->maxLSPbandwidth[k])
              equal = false;

          if (equal) {
            count--;
            ind[i] = true;
          }

          break;
        default :

          zlog_debug("[ERR] CORBA: method diffIscs (value out of range !!!)");
          break;
      }
    }
  }

  tmp = new gmplsTypes::iscSeq(count);
  seq = tmp;
  seq->length(count);

  int index = 0;
  for (int m=0; m<iscs1.length(); m++)
    if (ind[m] == false)
  {
    seq[index] = iscs1[m];
    index++;
  }

  return seq;
}
