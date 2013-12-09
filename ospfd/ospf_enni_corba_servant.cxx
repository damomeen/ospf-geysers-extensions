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

#include "zebra.h"
#include "log.h"
#include "linklist.h"
#include "prefix.h"
#include "memory.h"

#include <iostream>
#include <string>
#include <stdlib.h>

using namespace std;

#if HAVE_OMNIORB

#include "lib/corba.h"
#include "g2mpls_corba_utils.h"
#include "g2mpls_addr.h"
#include "g2mpls_types.h"

#include "ospfd/ospfd.h"

#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_te.h"
#include "ospfd/ospf_grid.h"
#include "ospfd/ospf_corba.h"
#include "ospfd/ospf_corba_utils.h"

#ifdef TOPOLOGY_ENNI_ON
#include "idl/g2mplsEnniTopology.hh"
#endif // TOPOLOGY_ENNI_ON

#ifdef TOPOLOGY_ENNI_ON
class g2mplsEnniTopology_i : public POA_g2mplsEnniTopology::Info,
                             public PortableServer::RefCountServantBase
{
  public:
    inline g2mplsEnniTopology_i()  {};
    virtual ~g2mplsEnniTopology_i() {};

    CORBA::Boolean
    nodeAdd(const g2mplsTypes::nodeIdent& id);

    CORBA::Boolean
    nodeDel(const g2mplsTypes::nodeIdent& id);

    g2mplsTypes::nodeIdentSeq* 
    nodeGetAll();

    CORBA::Boolean
    tnaIdAdd(const g2mplsTypes::tnaIdent& ident);

    CORBA::Boolean
    tnaIdDel(const g2mplsTypes::tnaIdent& ident);

    g2mplsTypes::tnaIdentSeq *
    tnaIdsGetAll();

    CORBA::Boolean
    linkAdd(const g2mplsTypes::teLinkIdent& ident);

    CORBA::Boolean
    linkDel(const g2mplsTypes::teLinkIdent& ident);

    g2mplsTypes::teLinkIdentSeq*
    teLinkGetAll();

    CORBA::Boolean
    teLinkUpdateCom(const g2mplsTypes::teLinkIdent& ident, const g2mplsTypes::teLinkComParams& info);

    CORBA::Boolean
    teLinkGetCom(const g2mplsTypes::teLinkIdent& ident, g2mplsTypes::teLinkComParams& info);

    CORBA::Boolean
    teLinkUpdateTdm(const g2mplsTypes::teLinkIdent& ident, const g2mplsTypes::teLinkTdmParams& info);

    CORBA::Boolean
    teLinkGetTdm(const g2mplsTypes::teLinkIdent& ident, g2mplsTypes::teLinkTdmParams& info);

    CORBA::Boolean
    teLinkUpdateLscG709(const g2mplsTypes::teLinkIdent& ident, const g2mplsTypes::teLinkLscG709Params&  info);

    CORBA::Boolean
    teLinkGetLscG709(const g2mplsTypes::teLinkIdent& ident, g2mplsTypes::teLinkLscG709Params_out info);

    CORBA::Boolean
    teLinkUpdateLscWdm(const g2mplsTypes::teLinkIdent& ident, const g2mplsTypes::teLinkLscWdmParams&  info);

    CORBA::Boolean
    teLinkGetLscWdm(const g2mplsTypes::teLinkIdent& ident, g2mplsTypes::teLinkLscWdmParams_out info);

    CORBA::Boolean
    teLinkUpdateStates(const g2mplsTypes::teLinkIdent& ident, const g2mplsTypes::statesBundle& states);

    CORBA::Boolean
    teLinkGetStates(const g2mplsTypes::teLinkIdent& ident, g2mplsTypes::statesBundle& states);

    CORBA::Boolean
    teLinkUpdateGenBw(const g2mplsTypes::teLinkIdent& ident, const g2mplsTypes::availBwPerPrio bw);

    CORBA::Boolean
    teLinkGetGenBw(const g2mplsTypes::teLinkIdent& ident, g2mplsTypes::availBwPerPrio bw);

    CORBA::Boolean
    teLinkUpdateTdmBw(const g2mplsTypes::teLinkIdent& ident, const g2mplsTypes::freeCTPSeq& freeBw);

    CORBA::Boolean
    teLinkGetTdmBw(const g2mplsTypes::teLinkIdent& ident, g2mplsTypes::freeCTPSeq_out freeTS);

    CORBA::Boolean
    teLinkUpdateLscG709Bw(const g2mplsTypes::teLinkIdent& ident, const g2mplsTypes::freeCTPSeq& freeODUk, const g2mplsTypes::freeCTPSeq& freeOCh);

    CORBA::Boolean
    teLinkGetLscG709Bw(const g2mplsTypes::teLinkIdent& ident, g2mplsTypes::freeCTPSeq_out freeODUk, g2mplsTypes::freeCTPSeq_out freeOCh);

    CORBA::Boolean
    teLinkUpdateLscWdmBw(const g2mplsTypes::teLinkIdent& ident, const g2mplsTypes::wdmLambdasBitmap& bm);

    CORBA::Boolean
    teLinkGetLscWdmBw(const g2mplsTypes::teLinkIdent& ident, g2mplsTypes::wdmLambdasBitmap_out bm);

    CORBA::Boolean
    teLinkAppendSrlgs(const g2mplsTypes::teLinkIdent& ident, const g2mplsTypes::srlgSeq& srlgs);

    CORBA::Boolean
    teLinkRemoveSrlgs(const g2mplsTypes::teLinkIdent& ident, const g2mplsTypes::srlgSeq& srlgs);

    CORBA::Boolean
    teLinkGetSrlgs(const g2mplsTypes::teLinkIdent& ident, g2mplsTypes::srlgSeq_out srlgs);

    CORBA::Boolean
    teLinkAppendCalendar(const g2mplsTypes::teLinkIdent& ident, const g2mplsTypes::teLinkCalendarSeq& cal);

    CORBA::Boolean
    teLinkRemoveCalendar(const g2mplsTypes::teLinkIdent& ident, const g2mplsTypes::teLinkCalendarSeq& cal);

    CORBA::Boolean
    teLinkGetCalendar(const g2mplsTypes::teLinkIdent& ident, g2mplsTypes::teLinkCalendarSeq_out cal);

    CORBA::Boolean
    teLinkAppendIsc(const g2mplsTypes::teLinkIdent& ident, const g2mplsTypes::iscSeq& iscs);

    CORBA::Boolean
    teLinkRemoveIsc(const g2mplsTypes::teLinkIdent& ident, const g2mplsTypes::iscSeq& iscs);

    CORBA::Boolean
    teLinkGetIsc(const g2mplsTypes::teLinkIdent& ident, g2mplsTypes::iscSeq_out iscs);
};
#endif // TOPOLOGY_ENNI_ON

#endif // HAVE_OMNIORB

#ifdef HAVE_OMNIORB

#ifdef TOPOLOGY_ENNI_ON
CORBA::Boolean
g2mplsEnniTopology_i::nodeAdd(const g2mplsTypes::nodeIdent& id)
{
  if(IS_DEBUG_GRID_NODE(CORBA))
    zlog_debug("[DBG] CORBA: Received NODE_ADD message from ENNI CLIENT");

  STACK_LOCK();

  struct in_addr ra;
  ra.s_addr = htonl((uint32_t) id.id);

  struct raHarmony* rah;
  try {

    rah = add_hnode(ra, 0);

  } catch (...) {
    STACK_UNLOCK();
    zlog_warn("[WRN] CORBA: Exception InternalProblems (nodeAdd)");
    throw (g2mplsEnniTopology::InternalProblems("nodeAdd"));
  }

  if (!rah)
  {
    STACK_UNLOCK();
    throw (g2mplsEnniTopology::NodeAlreadyExists(id,"nodeAdd"));
  }

  struct ospf *ospf_enni;
  ospf_enni = get_hospf();

  void *data;
  struct zlistnode *node;
  struct ospf_area *area;
  for (ALL_LIST_ELEMENTS_RO(ospf_enni->areas, node, data))
  {
    area = (struct ospf_area *) data;

    if (rah->engaged == 0) {
      ospf_te_ra_harmony_lsa_schedule (REORIGINATE_PER_AREA, ospf_enni, area, rah);
      if(IS_DEBUG_GRID_NODE(CORBA_ALL))
        zlog_debug("[DBG] CORBA: ospf_te_ra_harmony_lsa_schedule (REORIGINATE_PER_AREA, ospf_enni, area, rah)");
    }
    else {
      ospf_te_ra_harmony_lsa_schedule (REFRESH_THIS_LSA, ospf_enni, area, rah);
      if(IS_DEBUG_GRID_NODE(CORBA_ALL))
        zlog_debug("[DBG] CORBA: ospf_te_ra_lsa_schedule (REFRESH_THIS_LSA, ospf_enni, area, rah)");
    }
  }

  STACK_UNLOCK();

  return true;
}

CORBA::Boolean
g2mplsEnniTopology_i::nodeDel(const g2mplsTypes::nodeIdent& id)
{
  if(IS_DEBUG_GRID_NODE(CORBA))
    zlog_debug("[DBG] CORBA: Received NODE_DEL message from ENNI CLIENT");

  STACK_LOCK();

  struct in_addr ra;
  ra.s_addr = htonl((uint32_t) id.id);

  struct raHarmony* rah;
  try {

    rah = lookup_hnode(ra, 0);

  } catch (...) {
    STACK_UNLOCK();
    zlog_warn("[WRN] CORBA: Exception InternalProblems (nodeDel)");
    throw (g2mplsEnniTopology::InternalProblems("nodeDel"));
  }

  if (!rah)
  {
    STACK_UNLOCK();
    zlog_warn("[WRN] CORBA: Exception CannotFetchNode (nodeDel)");
    throw (g2mplsEnniTopology::CannotFetchNode(id, "nodeDel"));
  }

  struct ospf *ospf_enni;
  ospf_enni = get_hospf();

  void *data;
  struct zlistnode *node;
  struct ospf_area *area;
  for (ALL_LIST_ELEMENTS_RO(ospf_enni->areas, node, data))
  {
    area = (struct ospf_area *) data;

    ospf_te_ra_harmony_lsa_schedule (FLUSH_THIS_LSA, ospf_enni, area, rah);
    if(IS_DEBUG_GRID_NODE(CORBA_ALL))
      zlog_debug("[DBG] CORBA: ospf_te_ra_lsa_schedule (FLUSH_THIS_LSA, ospf, area, rah)");
  }

  if (del_hnode(ra, 0) == -1) {
    STACK_UNLOCK();
    zlog_warn("[WRN] CORBA: Exception CannotFetchNode (nodeDel)");
    throw (g2mplsEnniTopology::CannotFetchNode(id, "nodeDel"));
  }

  STACK_UNLOCK();

  return true;
}

g2mplsTypes::nodeIdentSeq*
g2mplsEnniTopology_i::nodeGetAll()
{
  if(IS_DEBUG_GRID_NODE(CORBA_ALL))
    zlog_debug("[DBG] CORBA: Received NODE_GET_ALL message from ENNI CLIENT");

  STACK_LOCK();

  void *tmp;
  struct zlistnode *node;
  struct ospf_lsa *lsa;
  struct te_tlv_header *subtlv;

  struct zlist lsas;
  lsas = lookup_lsas_from_lsdb(TE_TLV_ROUTER_ADDR);

  uint16_t count = listcount(&lsas);

  g2mplsTypes::nodeIdentSeq_var seq;
  {
    g2mplsTypes::nodeIdentSeq * tmp;
    tmp = new g2mplsTypes::nodeIdentSeq(count);
    if (!tmp) {
      STACK_UNLOCK();
      throw (g2mplsEnniTopology::InternalProblems("method nodeGetAll (tmp == NULL)"));
    }
    seq = tmp;
  }
  seq->length(count);

  uint16_t i = 0;
  for (ALL_LIST_ELEMENTS_RO (&lsas, node, tmp))
  {
    lsa = (struct ospf_lsa *) tmp;
    g2mplsTypes::nodeIdent ident;
    if (subtlv = te_subtlv_lookup(lsa, TE_TLV_ROUTER_ADDR, TE_ROUTER_ADDR_SUBTLV_ROUTER_ADDR)) {
      ident.id = ntohl (*((uint32_t *) (++subtlv)));
      ident.type = g2mplsTypes::NODETYPE_NETWORK;
      seq[i] = ident;
      i++;
    }
  }

  STACK_UNLOCK();
  return seq._retn();
}

CORBA::Boolean
g2mplsEnniTopology_i::tnaIdAdd(const g2mplsTypes::tnaIdent& ident)
{
  if(IS_DEBUG_GRID_NODE(CORBA_ALL))
    zlog_debug("[DBG] CORBA: Received TNA_ID_ADD message from ENNI CLIENT");

  STACK_LOCK();

  struct te_link* lp;

  struct in_addr node_id;
  node_id.s_addr = htonl(ident.node);
  struct in_addr anc_rc_id;
  anc_rc_id.s_addr = htonl(ident.rc);

  struct tna_addr_value tna;
  tna_addr_type_t type;
  void * tna_addr;

  struct in_addr ad_ipv4;
  struct in6_addr ad_ipv6;
  uint8_t tmp_nsap[20];
  uint32_t ad_nsap[5];

  switch (ident.tna._d()){
    case g2mplsTypes::TNAIDTYPE_IPV4:
      ad_ipv4.s_addr = htonl(ident.tna.ipv4());
      set_oif_tna_addr_ipv4 (&tna, ident.prefix, &ad_ipv4);
      tna.tna_addr_ipv6.header.length = 0;
      tna.tna_addr_nsap.header.length = 0;
      type = TNA_IP4;
      tna_addr = (void *) &ad_ipv4;
      break;
    case g2mplsTypes::TNAIDTYPE_IPV6:
      for (int i = 0; i < 4; i++)
        ad_ipv6.s6_addr[i] = htonl(ident.tna.ipv6()[i]);
      set_oif_tna_addr_ipv6 (&tna, ident.prefix, &ad_ipv6);
      tna.tna_addr_ipv4.header.length = 0;
      tna.tna_addr_nsap.header.length = 0;
      type = TNA_IP6;
      tna_addr = (void *) &ad_ipv6;
      break;
    case g2mplsTypes::TNAIDTYPE_NSAP:
      for (int i = 0; i < 20; i++)
        tmp_nsap[i] = ident.tna.nsap()[i];
      for (int i = 0; i < 5; i++)
        ad_nsap[i] = * (uint32_t *) tmp_nsap[i*4];
      set_oif_tna_addr_nsap (&tna, ident.prefix, ad_nsap);
      tna.tna_addr_ipv4.header.length = 0;
      tna.tna_addr_ipv6.header.length = 0;
      type = TNA_NSAP;
      tna_addr = (void *) &ad_nsap;
      break;
  }

  lp = add_htna(node_id, tna);

  if (!lp) {
    STACK_UNLOCK();
    zlog_warn("[WRN] CORBA: Exception TnaAlreadyExists (tnaIdAdd)");
    throw g2mplsEnniTopology::TnaAlreadyExists(ident, "tnaIdAdd");
  }

  if (add_tna_addr (lp, type, node_id, anc_rc_id, ident.prefix, tna_addr) == -1) {
    STACK_UNLOCK();
    zlog_warn("[WRN] CORBA: Exception InternalProblems (tnaIdAdd)");
    throw g2mplsEnniTopology::InternalProblems("tnaIdAdd");
  }

  if(IS_DEBUG_GRID_NODE(CORBA_ALL))
    zlog_debug("[DBG] CORBA: Done TNA_ID_ADD");

  if (lp->area != NULL)
  {
    if (lp->flags & LPFLG_LSA_TNA_ENGAGED)
    {
      ospf_te_lsa_schedule (lp, REFRESH_THIS_LSA, TNA_ADDRESS);
      if(IS_DEBUG_GRID_NODE(CORBA_ALL))
        zlog_debug("[DBG] CORBA: ospf_te_lsa_schedule (lp, REFRESH_THIS_LSA, TNA_ADDRESS)");
    }
    else
    {
      ospf_te_lsa_schedule (lp, REORIGINATE_PER_AREA, TNA_ADDRESS);
      if(IS_DEBUG_GRID_NODE(CORBA_ALL))
        zlog_debug("[DBG] CORBA: ospf_te_lsa_schedule (lp, REORIGINATE_PER_AREA, TNA_ADDRESS)");
    }
  }

  STACK_UNLOCK();

  return true;
}

CORBA::Boolean
g2mplsEnniTopology_i::tnaIdDel(const g2mplsTypes::tnaIdent& ident)
{
  if(IS_DEBUG_GRID_NODE(CORBA_ALL))
    zlog_debug("[DBG] CORBA: Received TNA_ID_DEL message from ENNI CLIENT");

  STACK_LOCK();

  struct te_link* lp;

  struct in_addr node_id;
  node_id.s_addr = htonl(ident.node);

  struct tna_addr_value tna;
  tna_addr_type_t type;
  void * tna_addr;

  struct in_addr ad_ipv4;
  struct in6_addr ad_ipv6;
  uint8_t tmp_nsap[20];
  uint32_t ad_nsap[5];

  switch (ident.tna._d()){
    case g2mplsTypes::TNAIDTYPE_IPV4:
      ad_ipv4.s_addr = htonl(ident.tna.ipv4());
      set_oif_tna_addr_ipv4 (&tna, ident.prefix, &ad_ipv4);
      tna.tna_addr_ipv6.header.length = 0;
      tna.tna_addr_nsap.header.length = 0;
      type = TNA_IP4;
      tna_addr = (void *) &ad_ipv4;
      break;
    case g2mplsTypes::TNAIDTYPE_IPV6:
      for (int i = 0; i < 4; i++)
        ad_ipv6.s6_addr[i] = htonl(ident.tna.ipv6()[i]);
      set_oif_tna_addr_ipv6 (&tna, ident.prefix, &ad_ipv6);
      tna.tna_addr_ipv4.header.length = 0;
      tna.tna_addr_nsap.header.length = 0;
      type = TNA_IP6;
      tna_addr = (void *) &ad_ipv6;
      break;
    case g2mplsTypes::TNAIDTYPE_NSAP:
      for (int i = 0; i < 20; i++)
        tmp_nsap[i] = ident.tna.nsap()[i];
      for (int i = 0; i < 5; i++)
        ad_nsap[i] = * (uint32_t *) tmp_nsap[i*4];
      set_oif_tna_addr_nsap (&tna, ident.prefix, ad_nsap);
      tna.tna_addr_ipv4.header.length = 0;
      tna.tna_addr_ipv6.header.length = 0;
      type = TNA_NSAP;
      tna_addr = (void *) &ad_nsap;
      break;
  }

  lp = lookup_htna(node_id, tna);

  if (!lp) {
    STACK_UNLOCK();
    zlog_warn("[WRN] CORBA: Exception CannotFetchTna (tnaIdDel)");
    throw g2mplsEnniTopology::CannotFetchTna(ident, "tnaIdDel");
  }

  if (lp->area != NULL)
  {
    ospf_te_lsa_schedule (lp, FLUSH_THIS_LSA, TNA_ADDRESS);
    if(IS_DEBUG_GRID_NODE(CORBA_ALL))
      zlog_debug("[DBG] CORBA: ospf_te_lsa_schedule (lp, FLUSH_THIS_LSA, TNA_ADDRESS)");
  }

  if (del_htna(node_id, tna) == -1) {
    STACK_UNLOCK();
    zlog_warn("[WRN] CORBA: Exception CannotFetchTna (tnaIdDel)");
    throw g2mplsEnniTopology::CannotFetchTna(ident, "tnaIdDel");
  }

  STACK_UNLOCK();

  return true;
}

struct tna_value
{
  struct in_addr node;
  g2mpls_addr_t tna;
  uint8_t preflen;
};

g2mplsTypes::tnaIdentSeq *
g2mplsEnniTopology_i::tnaIdsGetAll()
{
  if(IS_DEBUG_GRID_NODE(CORBA_ALL))
    zlog_debug("[DBG] CORBA: Received TNA_IDS_GET_ALL message from ENNI CLIENT");

  STACK_LOCK();

  void *tmp;
  uint8_t *value;
  uint16_t len, sum, count;

  struct zlist tnaAddresses;
  memset (&tnaAddresses, 0, sizeof (struct zlist));

  struct tna_value *n_value;
  struct zlistnode *node;
  struct ospf_lsa *lsa;
  struct te_tlv_header *subtlv;
  struct in_addr tnaNode;

  struct zlist lsas;
  lsas = lookup_lsas_from_lsdb(TE_TLV_TNA_ADDR);

  for (ALL_LIST_ELEMENTS_RO (&lsas, node, tmp))
  {
    lsa = (struct ospf_lsa *) tmp;

    if (!(subtlv = te_subtlv_lookup(lsa, TE_TLV_TNA_ADDR, TE_TNA_ADDR_SUBTLV_NODE_ID)))
      continue;

    has_lsa_tlv_type(lsa, TE_TLV_TNA_ADDR, &len);

    sum = 0;
    while (sum < len)
    {
      switch(ntohs (subtlv->type))
      {
        case TE_TNA_ADDR_SUBTLV_NODE_ID:
          tnaNode = * (struct in_addr *) (subtlv + 1);
          subtlv += 2; sum += 8;
          break;
        case TE_TNA_ADDR_SUBTLV_TNA_ADDR_IPV4:
          n_value = (struct tna_value *) XMALLOC (0, sizeof(struct tna_value));
          n_value->node = tnaNode;
          n_value->preflen = (* (uint32_t *) (subtlv + 1)) & 0xff;
          n_value->tna.preflen = n_value->preflen;
          n_value->tna.type = IPv4;
          n_value->tna.value.ipv4 = * (struct in_addr *) (subtlv + 2);
          listnode_add(&tnaAddresses, n_value);
          subtlv += 3; sum += 12;
          break;
        case TE_TNA_ADDR_SUBTLV_TNA_ADDR_IPV6:
          n_value = (struct tna_value *) XMALLOC (0, sizeof(struct tna_value));
          n_value->node = tnaNode;
          n_value->preflen = (* (uint32_t *) (subtlv + 1)) & 0xff;
          n_value->tna.preflen = n_value->preflen;
          n_value->tna.type = IPv6;
          n_value->tna.value.ipv6 = * (struct in6_addr *) (subtlv + 2);
          listnode_add(&tnaAddresses, n_value);
          subtlv += 6; sum += 24;
          break;
        case TE_TNA_ADDR_SUBTLV_TNA_ADDR_NSAP:
          n_value = (struct tna_value *) XMALLOC (0, sizeof(struct tna_value));
          n_value->node = tnaNode;
          n_value->preflen = (* (uint32_t *) (subtlv + 1)) & 0xff;
          n_value->tna.preflen = n_value->preflen;
          n_value->tna.type = NSAP;
          value = (uint8_t *) (subtlv + 2);
          for (int i=0; i < 20; i++)
            n_value->tna.value.nsap.nsap_addr8[i] = *value++;
          listnode_add(&tnaAddresses, n_value);
          subtlv += 7; sum += 28;
          break;
        default:
          throw (g2mplsEnniTopology::InternalProblems("method tnaIdsGetAll (malformed TNA LSA)"));
          sum = len;
          break;
       }
    }
  }

  count = listcount(&tnaAddresses);
  g2mplsTypes::tnaIdentSeq_var seq;
  {
    g2mplsTypes::tnaIdentSeq * tmp;
    tmp = new g2mplsTypes::tnaIdentSeq(count);
    if (!tmp) {
      STACK_UNLOCK();
      throw (g2mplsEnniTopology::InternalProblems("method tnaIdsGetAll (tmp == NULL)"));
    }
    seq = tmp;
  }
  seq->length(count);

  uint16_t i = 0;
  struct tna_value *tna;
  for (ALL_LIST_ELEMENTS_RO (&tnaAddresses, node, tmp))
  {
    tna = (struct tna_value *) tmp;

    g2mplsTypes::tnaIdent ident;
    ident.rc = 0;  // TODO
    ident.node = ntohl(tna->node.s_addr);

    g2mplsTypes::tnaId_var tnaAddr;
    tnaAddr << tna->tna;
    ident.tna = tnaAddr;
    ident.prefix = tna->preflen;

    seq[i] = ident;
    i++;
  }

  STACK_UNLOCK();

  return seq._retn();
}

CORBA::Boolean
g2mplsEnniTopology_i::linkAdd(const g2mplsTypes::teLinkIdent& ident)
{
  if(IS_DEBUG_GRID_NODE(CORBA_ALL))
    zlog_debug("[DBG] CORBA: Received LINK_ADD message from ENNI CLIENT");

  STACK_LOCK();

  struct te_link* lp;

  struct in_addr node_id;
  node_id.s_addr = htonl(ident.localNodeId);

  lp = add_hlink(node_id, ident.localId.ipv4());

  if (!lp) {
    STACK_UNLOCK();
    zlog_warn("[WRN] CORBA: Exception LinkAlreadyExists (linkAdd)");
    throw g2mplsEnniTopology::LinkAlreadyExists(ident, "linkAdd");
  }

  try {

    // set link id
    lp->link_id.header.type   = htons (TE_LINK_SUBTLV_LINK_ID);
    lp->link_id.header.length = htons (4);
    lp->link_id.value.s_addr  = htonl (ident.remoteRcId);

    // set link type
    lp->link_type.header.type   = htons (TE_LINK_SUBTLV_LINK_TYPE);
    lp->link_type.header.length = htons (1);
    lp->link_type.link_type.value = LINK_TYPE_SUBTLV_VALUE_PTP;
    lp->is_set_linkparams_link_type = 1;

    set_link_lcl_rmt_ids (lp, ident.localId.ipv4(), ident.remoteId.ipv4());

    set_oif_lcl_node_id (lp, node_id);

    node_id.s_addr = htonl(ident.remoteNodeId);
    set_oif_rmt_node_id (lp, node_id);

    struct in_addr rc_id;
    rc_id.s_addr = htonl (ident.localRcId);
    set_oif_anc_rc_id (lp, rc_id);

  } catch (...) {
    STACK_UNLOCK();
    zlog_warn("[WRN] CORBA: Exception InternalProblems (linkAdd)");
    throw g2mplsEnniTopology::InternalProblems("linkAdd");
  }

  if(IS_DEBUG_GRID_NODE(CORBA_ALL))
    zlog_debug("[DBG] CORBA: Done LINK_ADD");

  if (lp->area != NULL)
  {
    if (lp->flags & LPFLG_LSA_LI_ENGAGED)
    {
      ospf_te_lsa_schedule (lp, REFRESH_THIS_LSA, LINK);
      if(IS_DEBUG_GRID_NODE(CORBA_ALL))
        zlog_debug("[DBG] CORBA: ospf_te_lsa_schedule (lp, REFRESH_THIS_LSA, LINK)");
    }
    else
    {
      ospf_te_lsa_schedule (lp, REORIGINATE_PER_AREA, LINK);
      if(IS_DEBUG_GRID_NODE(CORBA_ALL))
        zlog_debug("[DBG] CORBA: ospf_te_lsa_schedule (lp, REORIGINATE_PER_AREA, LINK)");
    }
  }

  STACK_UNLOCK();

  return true;
}

CORBA::Boolean
g2mplsEnniTopology_i::linkDel(const g2mplsTypes::teLinkIdent& ident)
{
  if(IS_DEBUG_GRID_NODE(CORBA_ALL))
    zlog_debug("[DBG] CORBA: Received LINK_DEL message from ENNI CLIENT");

  STACK_LOCK();

  struct te_link* lp;

  struct in_addr node_id;
  node_id.s_addr = htonl(ident.localNodeId);

  lp =  lookup_hlink(node_id, ident.localId.ipv4());

  if (!lp) {
    STACK_UNLOCK();
    zlog_warn("[WRN] CORBA: Exception CannotFetchLink (linkDel)");
    throw g2mplsEnniTopology::CannotFetchLink(ident, "linkDel");
  }

  if (lp->area != NULL)
  {
    ospf_te_lsa_schedule (lp, FLUSH_THIS_LSA, LINK);
    if(IS_DEBUG_GRID_NODE(CORBA_ALL))
      zlog_debug("[DBG] CORBA: ospf_te_lsa_schedule (lp, FLUSH_THIS_LSA, LINK)");
  }

  if (del_hlink(lp) == -1) {
    STACK_UNLOCK();
    zlog_warn("[WRN] CORBA: Exception CannotFetchLink (linkDel)");
    throw g2mplsEnniTopology::CannotFetchLink(ident, "linkDel");
  }

  STACK_UNLOCK();

  return true;
}

g2mplsTypes::teLinkIdent _linkIdent;

struct in_addr _localNodeId;     // local node id (interdomain telink)
struct in_addr _remoteNodeId;    // remote node id (interdomain telink)
uint32_t       _localId;         // local id (interdomain telink)
uint32_t       _remoteId;        // remote id (interdomain telink)
struct in_addr _ancestorRcId;    // local rc id (interdomain telink)
struct in_addr _linkId;          // remote rc id (interdomain telink) & remote node id (intradomain telink)
struct in_addr _advertisingRId;  // local node id (intradomain telink)
uint8_t        _ltype;           // converted to link mode (interdomain & intradomain telink)

void _init_link_tmp_values()
{
  _localNodeId.s_addr = 0;
  _remoteNodeId.s_addr = 0;
  _localId = 0;
  _remoteId = 0;
  _ancestorRcId.s_addr = 0;
  _linkId.s_addr = 0;
  _ltype = 0;
}

void _init_link_ident()
{
  _linkIdent.localNodeId = 0;
  _linkIdent.remoteNodeId = 0;

  g2mpls_addr_t addr;
  addr.type = IPv4;
  addr.value.ipv4.s_addr = 0;
  g2mplsTypes::TELinkId_var initId;
  initId << addr;

  _linkIdent.localId = initId;
  _linkIdent.remoteId = initId;

  _linkIdent.localRcId = 0;
  _linkIdent.remoteRcId = 0;
  _linkIdent.mode = g2mplsTypes::LINKMODE_UNKNOWN;
}

g2mplsTypes::linkMode _link_type_2_link_mode()
{
  g2mplsTypes::linkMode mode;
  switch (_ltype)
  {
    case LINK_TYPE_SUBTLV_VALUE_PTP:
      if ((_linkIdent.localRcId != 0) && (_linkIdent.localRcId == _linkIdent.remoteRcId))
        mode = g2mplsTypes::LINKMODE_ENNI_INTRADOMAIN;
      else
        mode = g2mplsTypes::LINKMODE_ENNI_INTERDOMAIN;
      break;
    case LINK_TYPE_SUBTLV_VALUE_MA:
      mode = g2mplsTypes::LINKMODE_MULTIACCESS;
      break;
    default:
      mode = g2mplsTypes::LINKMODE_UNKNOWN;
      break;
  }

  return mode;
}

void _set_link_ident(g2mplsTypes::teLinkIdent *ident)
{
  _init_link_ident();

  g2mplsTypes::linkId_var clinkId;
  g2mpls_addr_t addr;

  ident->localNodeId = ntohl(_localNodeId.s_addr);
  ident->remoteNodeId = ntohl(_remoteNodeId.s_addr);

  addr.type = IPv4;
  addr.value.ipv4.s_addr = htonl(_localId);
  clinkId << addr;

  ident->localId  = (g2mplsTypes::TELinkId) clinkId;

  addr.value.ipv4.s_addr = htonl(_remoteId);
  clinkId << addr;

  ident->remoteId = (g2mplsTypes::TELinkId) clinkId;

  ident->localRcId = ntohl(_ancestorRcId.s_addr);
  ident->remoteRcId = ntohl(_linkId.s_addr);

  ident->mode = _link_type_2_link_mode();

  return;
}

g2mplsTypes::teLinkIdent create_link_ident_from_lsa(struct ospf_lsa *lsa)
{
  struct te_tlv_header *subtlv;
  _init_link_tmp_values();

  if (subtlv = te_subtlv_lookup(lsa, TE_TLV_LINK, TE_LINK_SUBTLV_LINK_ID))
    _linkId = *((struct in_addr *) (++subtlv));
  if (subtlv = te_subtlv_lookup(lsa, TE_TLV_LINK, TE_LINK_SUBTLV_LCL_NODE_ID))
    _localNodeId = *((struct in_addr *) (++subtlv));
  if (subtlv = te_subtlv_lookup(lsa, TE_TLV_LINK, TE_LINK_SUBTLV_RMT_NODE_ID))
    _remoteNodeId = *((struct in_addr *) (++subtlv));
  if (subtlv = te_subtlv_lookup(lsa, TE_TLV_LINK, TE_LINK_SUBTLV_LINK_LCL_RMT_IDS)) {
    _localId = ntohl (*((uint32_t *) (++subtlv)));
    _remoteId = ntohl (*((uint32_t *) (++subtlv)));
  }
  if (subtlv = te_subtlv_lookup(lsa, TE_TLV_LINK, TE_LINK_SUBTLV_LINK_TYPE))
    _ltype = *((uint8_t *) (++subtlv));
  if (subtlv = te_subtlv_lookup(lsa, TE_TLV_LINK, TE_LINK_SUBTLV_ANC_RC_ID))
    _ancestorRcId = *((struct in_addr *) (++subtlv));

  g2mplsTypes::teLinkIdent ident;
  _set_link_ident(&ident);

  return ident;
}

g2mplsTypes::teLinkIdentSeq*
g2mplsEnniTopology_i::teLinkGetAll()
{
  if(IS_DEBUG_GRID_NODE(CORBA_ALL))
    zlog_debug("[DBG] CORBA: Received TELINK_GET_ALL message from ENNI CLIENT");

  STACK_LOCK();

  void *tmp;
  struct zlistnode *node;
  struct ospf_lsa *lsa;
  struct te_tlv_header *subtlv;

  struct zlist lsas;
  lsas = lookup_lsas_from_lsdb(TE_TLV_LINK);

  uint16_t count = listcount(&lsas);

  g2mplsTypes::teLinkIdentSeq_var seq;
  {
    g2mplsTypes::teLinkIdentSeq * tmp;
    tmp = new g2mplsTypes::teLinkIdentSeq(count);
    if (!tmp) {
      STACK_UNLOCK();
      throw (g2mplsEnniTopology::InternalProblems("method teLinkGetAll (tmp == NULL)"));
    }
    seq = tmp;
  }
  seq->length(count);

  uint16_t i = 0;
  for (ALL_LIST_ELEMENTS_RO (&lsas, node, tmp))
  {
    lsa = (struct ospf_lsa *) tmp;
    seq[i] = create_link_ident_from_lsa(lsa);
    i++;
  }

  STACK_UNLOCK();

  return seq._retn();
}

CORBA::Boolean
g2mplsEnniTopology_i::teLinkUpdateCom(const g2mplsTypes::teLinkIdent& ident, const g2mplsTypes::teLinkComParams& info)
{
  if(IS_DEBUG_GRID_NODE(CORBA_ALL))
    zlog_debug("[DBG] CORBA: Received TELINK_UPDATE_COM message from ENNI CLIENT");

  STACK_LOCK();

  struct te_link* lp;

  struct in_addr node_id;
  node_id.s_addr = htonl(ident.localNodeId);

  lp =  lookup_hlink(node_id, ident.localId.ipv4());

  if (!lp) {
    STACK_UNLOCK();
    zlog_warn("[WRN] CORBA: Exception CannotFetchLink (teLinkUpdateCom)");
    throw g2mplsEnniTopology::CannotFetchLink(ident, "teLinkUpdateCom");
  }

  try {

    set_linkparams_te_metric (lp, info.teMetric);

    float fval;
    fval = (float) info.teMaxBw;
    set_linkparams_max_bw (lp, &fval);

    fval = (float) info.teMaxResvBw;
    set_linkparams_max_rsv_bw (lp, &fval);

    set_linkparams_rsc_clsclr (lp, info.teColorMask);

    set_link_protect_type(lp, info.teProtectionTypeMask);

  } catch (...) {
    STACK_UNLOCK();
    zlog_warn("[WRN] CORBA: Exception InternalProblems (teLinkUpdateCom)");
    throw g2mplsEnniTopology::InternalProblems("teLinkUpdateCom");
  }

  if(IS_DEBUG_GRID_NODE(CORBA_ALL))
    zlog_debug("[DBG] CORBA: Done TELINK_UPDATE_COM");

  if (lp->area != NULL)
  {
    if (lp->flags & LPFLG_LSA_LI_ENGAGED)
    {
      ospf_te_lsa_schedule (lp, REFRESH_THIS_LSA, LINK);
      if(IS_DEBUG_GRID_NODE(CORBA_ALL))
        zlog_debug("[DBG] CORBA: ospf_te_lsa_schedule (lp, REFRESH_THIS_LSA, LINK)");
    }
    else
    {
      ospf_te_lsa_schedule (lp, REORIGINATE_PER_AREA, LINK);
      if(IS_DEBUG_GRID_NODE(CORBA_ALL))
        zlog_debug("[DBG] CORBA: ospf_te_lsa_schedule (lp, REORIGINATE_PER_AREA, LINK)");
    }
  }

  STACK_UNLOCK();

  return true;
}

void init_teLinkComParams(g2mplsTypes::teLinkComParams* info)
{
  info->adminMetric = 0;        // temporary value
  info->teMetric = 0;
  info->teMaxBw = 0;
  info->teMaxResvBw = 0;
  info->teColorMask = 0;
  info->teProtectionTypeMask = 0;
}

CORBA::Boolean
g2mplsEnniTopology_i::teLinkGetCom(const g2mplsTypes::teLinkIdent& ident, g2mplsTypes::teLinkComParams& info)
{
  if(IS_DEBUG_GRID_NODE(CORBA_ALL))
    zlog_debug("[DBG] CORBA: Received TELINK_GET_COM message from ENNI CLIENT");

  STACK_LOCK();

  init_teLinkComParams(&info);

  void *tmp;
  struct zlistnode *node;
  struct ospf_lsa *lsa;
  struct te_tlv_header *subtlv;

  struct zlist lsas;
  lsas = lookup_lsas_from_lsdb(TE_TLV_LINK);

  float fval;
  uint32_t lu1, lu2;
  g2mplsTypes::teLinkIdent tmpIdent;
  for (ALL_LIST_ELEMENTS_RO (&lsas, node, tmp))
  {
    lsa = (struct ospf_lsa *) tmp;
    tmpIdent = create_link_ident_from_lsa(lsa);
    if (equalTeLinks(&ident, &tmpIdent))
    {
      if (subtlv = te_subtlv_lookup(lsa, TE_TLV_LINK, TE_LINK_SUBTLV_TE_METRIC))
        info.teMetric = ntohl (*((uint32_t *) (++subtlv)));
      if (subtlv = te_subtlv_lookup(lsa, TE_TLV_LINK, TE_LINK_SUBTLV_MAX_BW)) {
        memcpy (&lu1, (float *) (++subtlv), 4);
        lu2 = ntohl (lu1);
        memcpy (&fval, &lu2, 4);
        info.teMaxBw = (int) fval;
      }
      if (subtlv = te_subtlv_lookup(lsa, TE_TLV_LINK, TE_LINK_SUBTLV_MAX_RSV_BW)) {
        memcpy (&lu1, (float *) (++subtlv), 4);
        lu2 = ntohl (lu1);
        memcpy (&fval, &lu2, 4);
        info.teMaxResvBw = (int) fval;
      }
      if (subtlv = te_subtlv_lookup(lsa, TE_TLV_LINK, TE_LINK_SUBTLV_RSC_CLSCLR))
        info.teColorMask = ntohl (*((uint32_t *) (++subtlv)));
      if (subtlv = te_subtlv_lookup(lsa, TE_TLV_LINK, TE_LINK_SUBTLV_LINK_PROTECT_TYPE))
        info.teProtectionTypeMask = *((uint8_t *) (++subtlv));

      STACK_UNLOCK();
      return true;
    }
  }

  STACK_UNLOCK();

  if(IS_DEBUG_GRID_NODE(CORBA_ALL))
    zlog_debug("[WRN] CORBA: TeLink not found in LSDB");

  throw (g2mplsEnniTopology::CannotFetchLink(ident, "method teLinkGetCom"));

  return false;
}

CORBA::Boolean
g2mplsEnniTopology_i::teLinkUpdateTdm(const g2mplsTypes::teLinkIdent& ident, const g2mplsTypes::teLinkTdmParams& info)
{
  if(IS_DEBUG_GRID_NODE(CORBA_ALL))
    zlog_debug("[DBG] CORBA: Received TELINK_UPDATE_TDM message from ENNI CLIENT");

  STACK_LOCK();

  struct te_link* lp;

  struct in_addr node_id;
  node_id.s_addr = htonl(ident.localNodeId);

  lp =  lookup_hlink(node_id, ident.localId.ipv4());

  if (!lp) {
    STACK_UNLOCK();
    zlog_warn("[WRN] CORBA: Exception CannotFetchLink (teLinkUpdateTdm)");
    throw g2mplsEnniTopology::CannotFetchLink(ident, "teLinkUpdateTdm");
  }

  throw (g2mplsEnniTopology::InternalProblems("method teLinkUpdateTdm (not implemented)"));

  STACK_UNLOCK();

  return true;
}

CORBA::Boolean
g2mplsEnniTopology_i::teLinkGetTdm(const g2mplsTypes::teLinkIdent& ident, g2mplsTypes::teLinkTdmParams& info)
{
  if(IS_DEBUG_GRID_NODE(CORBA_ALL))
    zlog_debug("[DBG] CORBA: Received TELINK_GET_TDM message from ENNI CLIENT");

  STACK_LOCK();

  void *tmp;
  struct zlistnode *node;
  struct ospf_lsa *lsa;
  struct te_tlv_header *subtlv;

  struct zlist lsas;
  lsas = lookup_lsas_from_lsdb(TE_TLV_LINK);

  g2mplsTypes::teLinkIdent tmpIdent;
  for (ALL_LIST_ELEMENTS_RO (&lsas, node, tmp))
  {
    lsa = (struct ospf_lsa *) tmp;
    tmpIdent = create_link_ident_from_lsa(lsa);
    if (equalTeLinks(&ident, &tmpIdent))
    {
      STACK_UNLOCK();
      throw (g2mplsEnniTopology::InternalProblems("method teLinkGetTdm (not implemented)"));

      return true;
    }
  }

  STACK_UNLOCK();

  if(IS_DEBUG_GRID_NODE(CORBA_ALL))
    zlog_debug("[WRN] CORBA: TeLink not found in LSDB");

  throw (g2mplsEnniTopology::CannotFetchLink(ident, "method teLinkGetTdm"));

  return false;
}

CORBA::Boolean
g2mplsEnniTopology_i::teLinkUpdateLscG709(const g2mplsTypes::teLinkIdent& ident, const g2mplsTypes::teLinkLscG709Params&  info)
{
  if(IS_DEBUG_GRID_NODE(CORBA_ALL))
    zlog_debug("[DBG] CORBA: Received TELINK_UPDATE_LscG709 message from ENNI CLIENT");

  STACK_LOCK();

  struct te_link* lp;

  struct in_addr node_id;
  node_id.s_addr = htonl(ident.localNodeId);

  lp =  lookup_hlink(node_id, ident.localId.ipv4());

  if (!lp) {
    STACK_UNLOCK();
    zlog_warn("[WRN] CORBA: Exception CannotFetchLink (teLinkUpdateLscG709)");
    throw g2mplsEnniTopology::CannotFetchLink(ident, "teLinkUpdateLscG709");
  }

  throw (g2mplsEnniTopology::InternalProblems("method teLinkUpdateLscG709 (not implemented)"));

  STACK_UNLOCK();

  return true;
}

CORBA::Boolean
g2mplsEnniTopology_i::teLinkGetLscG709(const g2mplsTypes::teLinkIdent& ident, g2mplsTypes::teLinkLscG709Params_out info)
{
  if(IS_DEBUG_GRID_NODE(CORBA_ALL))
    zlog_debug("[DBG] CORBA: Received TELINK_GET_LscG709 message from ENNI CLIENT");

  STACK_LOCK();

  void *tmp;
  struct zlistnode *node;
  struct ospf_lsa *lsa;
  struct te_tlv_header *subtlv;

  struct zlist lsas;
  lsas = lookup_lsas_from_lsdb(TE_TLV_LINK);

  g2mplsTypes::teLinkIdent tmpIdent;
  for (ALL_LIST_ELEMENTS_RO (&lsas, node, tmp))
  {
    lsa = (struct ospf_lsa *) tmp;
    tmpIdent = create_link_ident_from_lsa(lsa);
    if (equalTeLinks(&ident, &tmpIdent))
    {
      STACK_UNLOCK();
      throw (g2mplsEnniTopology::InternalProblems("method teLinkGetLscG709 (not implemented)"));

      return true;
    }
  }

  STACK_UNLOCK();

  if(IS_DEBUG_GRID_NODE(CORBA_ALL))
    zlog_debug("[WRN] CORBA: TeLink not found in LSDB");

  throw (g2mplsEnniTopology::CannotFetchLink(ident, "method teLinkGetLscG709"));

  return false;
}

CORBA::Boolean
g2mplsEnniTopology_i::teLinkUpdateLscWdm(const g2mplsTypes::teLinkIdent& ident, const g2mplsTypes::teLinkLscWdmParams&  info)
{
  if(IS_DEBUG_GRID_NODE(CORBA_ALL))
    zlog_debug("[DBG] CORBA: Received TELINK_UPDATE_LscWdm message from ENNI CLIENT");

  STACK_LOCK();

  struct te_link* lp;

  struct in_addr node_id;
  node_id.s_addr = htonl(ident.localNodeId);

  lp =  lookup_hlink(node_id, ident.localId.ipv4());

  if (!lp) {
    STACK_UNLOCK();
    zlog_warn("[WRN] CORBA: Exception CannotFetchLink (teLinkUpdateLscWdm)");
    throw g2mplsEnniTopology::CannotFetchLink(ident, "teLinkUpdateLscWdm");
  }

  try {

    float fval;
    fval = (float) info.dispersionPMD;
    set_all_opt_ext_d_pdm (lp, &fval);

    set_all_opt_ext_span_length (lp, info.spanLength);

    clear_all_opt_ext_amp_list (lp);

    for (int i = 0; i < info.amplifiers.length(); i++) {
      fval = (float) info.amplifiers[i].noiseFigure;
      add_all_opt_ext_amp_list (lp, info.amplifiers[i].gain, &fval);
    }

  } catch (...) {
    STACK_UNLOCK();
    zlog_warn("[WRN] CORBA: Exception InternalProblems (teLinkUpdateLscWdm)");
    throw g2mplsEnniTopology::InternalProblems("teLinkUpdateLscWdm");
  }

  if(IS_DEBUG_GRID_NODE(CORBA_ALL))
    zlog_debug("[DBG] CORBA: Done TELINK_UPDATE_LscWdm");

  if (lp->area != NULL)
  {
    if (lp->flags & LPFLG_LSA_LI_ENGAGED)
    {
      ospf_te_lsa_schedule (lp, REFRESH_THIS_LSA, LINK);
      if(IS_DEBUG_GRID_NODE(CORBA_ALL))
        zlog_debug("[DBG] CORBA: ospf_te_lsa_schedule (lp, REFRESH_THIS_LSA, LINK)");
    }
    else
    {
      ospf_te_lsa_schedule (lp, REORIGINATE_PER_AREA, LINK);
      if(IS_DEBUG_GRID_NODE(CORBA_ALL))
        zlog_debug("[DBG] CORBA: ospf_te_lsa_schedule (lp, REORIGINATE_PER_AREA, LINK)");
    }
  }

  STACK_UNLOCK();

  return true;
}

g2mplsTypes::teLinkLscWdmParams_var init_teLinkLscWdmParams()
{
  g2mplsTypes::teLinkLscWdmParams_var info;
  info = new g2mplsTypes::teLinkLscWdmParams;
  info->dispersionPMD = 0;
  info->spanLength = 0;

  g2mplsTypes::amplifiersSeq_var seq;
  g2mplsTypes::amplifiersSeq * tmp;
  tmp = new g2mplsTypes::amplifiersSeq(0);
  seq = tmp;
  seq->length(0);
  info->amplifiers = seq;
  return info;
}

CORBA::Boolean
g2mplsEnniTopology_i::teLinkGetLscWdm(const g2mplsTypes::teLinkIdent& ident, g2mplsTypes::teLinkLscWdmParams_out info)
{
  if(IS_DEBUG_GRID_NODE(CORBA_ALL))
    zlog_debug("[DBG] CORBA: Received TELINK_GET_LscWdm message from ENNI CLIENT");

  STACK_LOCK();

  g2mplsTypes::teLinkLscWdmParams_var info_var;
  info_var = init_teLinkLscWdmParams();

  void *tmp;
  struct zlistnode *node;
  struct ospf_lsa *lsa;
  struct te_tlv_header *subtlv;

  struct zlist lsas;
  lsas = lookup_lsas_from_lsdb(TE_TLV_LINK);

  float fval;
  uint16_t i, n;
  uint32_t lu1, lu2;
  struct amp_par *amp;
  struct te_tlv_header *tlvh;
  g2mplsTypes::teLinkIdent tmpIdent;
  for (ALL_LIST_ELEMENTS_RO (&lsas, node, tmp))
  {
    lsa = (struct ospf_lsa *) tmp;
    tmpIdent = create_link_ident_from_lsa(lsa);
    if (equalTeLinks(&ident, &tmpIdent))
    {
      if (subtlv = te_subtlv_lookup(lsa, TE_TLV_LINK, TE_LINK_SUBTLV_D_PDM)) {
        memcpy (&lu1, (float *) (++subtlv), 4);
        lu2 = ntohl (lu1);
        memcpy (&fval, &lu2, 4);
        info_var->dispersionPMD = (int) fval;
      }
      if (subtlv = te_subtlv_lookup(lsa, TE_TLV_LINK, TE_LINK_SUBTLV_SPAN_LENGTH))
        info_var->spanLength = ntohl (*((uint32_t *) (++subtlv)));
      if (subtlv = te_subtlv_lookup(lsa, TE_TLV_LINK, TE_LINK_SUBTLV_AMP_LIST))
      {
         tlvh = (struct te_tlv_header *) subtlv;
         n = (u_int16_t) (TLV_BODY_SIZE(tlvh) / 8);

         g2mplsTypes::amplifiersSeq_var seq;
         {
           g2mplsTypes::amplifiersSeq * tmp;
           tmp = new g2mplsTypes::amplifiersSeq(n);
           if (!tmp) {
             STACK_UNLOCK();
             throw (g2mplsEnniTopology::InternalProblems("method teLinkGetLscWdm (tmp == NULL)"));
           }
           seq = tmp;
         }
         seq->length(n);

         if (n > 0)
         {
           amp = (struct amp_par *)((struct te_tlv_header *) (tlvh+1));
           for (i=0; i<n; i++)
           {
             g2mplsTypes::teLinkWdmAmplifierEntry entry;
             memcpy (&lu1, (float *) (&amp->noise), 4);
             lu2 = ntohl (lu1);
             memcpy (&fval, &lu2, 4);;
             entry.noiseFigure = (int) fval;
             entry.gain = ntohl (amp->gain);

             seq[i] = entry;
             amp++;
           }
         }
         info_var->amplifiers = seq;
      }
      info = info_var._retn();

      STACK_UNLOCK();

      return true;
    }
  }
  info = info_var._retn();

  STACK_UNLOCK();

  if(IS_DEBUG_GRID_NODE(CORBA_ALL))
    zlog_debug("[WRN] CORBA: TeLink not found in LSDB");

  throw (g2mplsEnniTopology::CannotFetchLink(ident, "method teLinkGetLscWdm"));

  return false;
}

CORBA::Boolean
g2mplsEnniTopology_i::teLinkUpdateStates(const g2mplsTypes::teLinkIdent& ident, const g2mplsTypes::statesBundle& states)
{
  if(IS_DEBUG_GRID_NODE(CORBA_ALL))
    zlog_debug("[DBG] CORBA: Received TELINK_UPDATE_STATES message from ENNI CLIENT");

  STACK_LOCK();

  struct te_link* lp;

  struct in_addr node_id;
  node_id.s_addr = htonl(ident.localNodeId);

  lp =  lookup_hlink(node_id, ident.localId.ipv4());

  if (!lp) {
    STACK_UNLOCK();
    zlog_warn("[WRN] CORBA: Exception CannotFetchLink (teLinkUpdateStates)");
    throw g2mplsEnniTopology::CannotFetchLink(ident, "teLinkUpdateStates");
  }

  throw (g2mplsEnniTopology::InternalProblems("method teLinkUpdateStates (not implemented)"));

  STACK_UNLOCK();

  return true;
}

CORBA::Boolean
g2mplsEnniTopology_i::teLinkGetStates(const g2mplsTypes::teLinkIdent& ident, g2mplsTypes::statesBundle& states)
{
  STACK_LOCK();

  throw (g2mplsEnniTopology::InternalProblems("method teLinkGetStates (not implemented)"));

  STACK_UNLOCK();

  return true;
}

CORBA::Boolean
g2mplsEnniTopology_i::teLinkUpdateGenBw(const g2mplsTypes::teLinkIdent& ident, const g2mplsTypes::availBwPerPrio bw)
{
  if(IS_DEBUG_GRID_NODE(CORBA_ALL))
    zlog_debug("[DBG] CORBA: Received TELINK_UPDATE_GENBW message from ENNI CLIENT");

  STACK_LOCK();

  struct te_link* lp;

  struct in_addr node_id;
  node_id.s_addr = htonl(ident.localNodeId);

  lp =  lookup_hlink(node_id, ident.localId.ipv4());

  if (!lp) {
    STACK_UNLOCK();
    zlog_warn("[WRN] CORBA: Exception CannotFetchLink (teLinkUpdateGenBw)");
    throw g2mplsEnniTopology::CannotFetchLink(ident, "teLinkUpdateGenBw");
  }

  try {

    float fval;
    for (int i = 0; i < 8; i++) {
      fval = (float) bw[i];
      set_linkparams_unrsv_bw (lp, i, &fval);
    }

  } catch (...) {
    STACK_UNLOCK();
    zlog_warn("[WRN] CORBA: Exception InternalProblems (teLinkUpdateGenBw)");
    throw g2mplsEnniTopology::InternalProblems("teLinkUpdateGenBw");
  }

  if(IS_DEBUG_GRID_NODE(CORBA_ALL))
    zlog_debug("[DBG] CORBA: Done TELINK_UPDATE_GENBW");

  if (lp->area != NULL)
  {
    if (lp->flags & LPFLG_LSA_LI_ENGAGED)
    {
      ospf_te_lsa_schedule (lp, REFRESH_THIS_LSA, LINK);
      if(IS_DEBUG_GRID_NODE(CORBA_ALL))
        zlog_debug("[DBG] CORBA: ospf_te_lsa_schedule (lp, REFRESH_THIS_LSA, LINK)");
    }
    else
    {
      ospf_te_lsa_schedule (lp, REORIGINATE_PER_AREA, LINK);
      if(IS_DEBUG_GRID_NODE(CORBA_ALL))
        zlog_debug("[DBG] CORBA: ospf_te_lsa_schedule (lp, REORIGINATE_PER_AREA, LINK)");
    }
  }

  STACK_UNLOCK();

  return true;
}

CORBA::Boolean
g2mplsEnniTopology_i::teLinkGetGenBw(const g2mplsTypes::teLinkIdent& ident, g2mplsTypes::availBwPerPrio bw)
{
  if(IS_DEBUG_GRID_NODE(CORBA_ALL))
    zlog_debug("[DBG] CORBA: Received TELINK_GET_GENBW message from ENNI CLIENT");

  STACK_LOCK();


  void *tmp;
  struct zlistnode *node;
  struct ospf_lsa *lsa;
  struct te_tlv_header *subtlv;

  struct zlist lsas;
  lsas = lookup_lsas_from_lsdb(TE_TLV_LINK);

  float fval;
  uint32_t lu1, lu2;
  g2mplsTypes::teLinkIdent tmpIdent;
  for (ALL_LIST_ELEMENTS_RO (&lsas, node, tmp))
  {
    lsa = (struct ospf_lsa *) tmp;
    tmpIdent = create_link_ident_from_lsa(lsa);
    if (equalTeLinks(&ident, &tmpIdent))
    {
      if (subtlv = te_subtlv_lookup(lsa, TE_TLV_LINK, TE_LINK_SUBTLV_UNRSV_BW)) {
        for (int i=0; i< 8; i++)
        {
          memcpy (&lu1, (float *) (++subtlv), 4);
          lu2 = ntohl (lu1);
          memcpy (&fval, &lu2, 4);
          bw[i] = (int) fval;
        }
      }
      STACK_UNLOCK();

      return true;
    }
  }
  STACK_UNLOCK();

  if(IS_DEBUG_GRID_NODE(CORBA_ALL))
    zlog_debug("[WRN] CORBA: TeLink not found in LSDB");

  throw (g2mplsEnniTopology::CannotFetchLink(ident, "method teLinkGetGenBw"));

  return false;
}

CORBA::Boolean
g2mplsEnniTopology_i::teLinkUpdateTdmBw(const g2mplsTypes::teLinkIdent& ident, const g2mplsTypes::freeCTPSeq& freeBw)
{
  if(IS_DEBUG_GRID_NODE(CORBA_ALL))
    zlog_debug("[DBG] CORBA: Received TELINK_UPDATE_TDMBW message from ENNI CLIENT");

  STACK_LOCK();

  struct te_link* lp;

  struct in_addr node_id;
  node_id.s_addr = htonl(ident.localNodeId);

  lp =  lookup_hlink(node_id, ident.localId.ipv4());

  if (!lp) {
    STACK_UNLOCK();
    zlog_warn("[WRN] CORBA: Exception CannotFetchLink (teLinkUpdateTdmBw)");
    throw g2mplsEnniTopology::CannotFetchLink(ident, "teLinkUpdateTdmBw");
  }

  try {

    set_oif_ssdh_if_sw_cap_desc (lp);

    clear_oif_ssdh_if_sw_cap_desc_signal (lp);

    uint8_t utslots[3];
    for (int i = 0; i < freeBw.length(); i++) {

      utslots[0] =  freeBw[i].ctps & 0xff;
      utslots[1] = (freeBw[i].ctps >> 8 ) & 0xff;
      utslots[2] = (freeBw[i].ctps >> 16) & 0xff;

      add_oif_ssdh_if_sw_cap_desc_signal (lp, freeBw[i].sigType, utslots);
    }

  } catch (...) {
    STACK_UNLOCK();
    zlog_warn("[WRN] CORBA: Exception InternalProblems (teLinkUpdateTdmBw)");
    throw g2mplsEnniTopology::InternalProblems("teLinkUpdateTdmBw");
  }

  if(IS_DEBUG_GRID_NODE(CORBA_ALL))
    zlog_debug("[DBG] CORBA: Done TELINK_UPDATE_TDMBW");

  if (lp->area != NULL)
  {
    if (lp->flags & LPFLG_LSA_LI_ENGAGED)
    {
      ospf_te_lsa_schedule (lp, REFRESH_THIS_LSA, LINK);
      if(IS_DEBUG_GRID_NODE(CORBA_ALL))
        zlog_debug("[DBG] CORBA: ospf_te_lsa_schedule (lp, REFRESH_THIS_LSA, LINK)");
    }
    else
    {
      ospf_te_lsa_schedule (lp, REORIGINATE_PER_AREA, LINK);
      if(IS_DEBUG_GRID_NODE(CORBA_ALL))
        zlog_debug("[DBG] CORBA: ospf_te_lsa_schedule (lp, REORIGINATE_PER_AREA, LINK)");
    }
  }

  STACK_UNLOCK();

  return true;
}

g2mplsTypes::freeCTPSeq_var init_teLinkGetTdmBw()
{
  g2mplsTypes::freeCTPSeq_var seq;
  g2mplsTypes::freeCTPSeq * tmp;
  tmp = new g2mplsTypes::freeCTPSeq(0);
  seq = tmp;
  seq->length(0);
  return seq;
}

CORBA::Boolean
g2mplsEnniTopology_i::teLinkGetTdmBw(const g2mplsTypes::teLinkIdent& ident, g2mplsTypes::freeCTPSeq_out freeTS)
{
  if(IS_DEBUG_GRID_NODE(CORBA_ALL))
    zlog_debug("[DBG] CORBA: Received TELINK_GET_TDMBW message from ENNI CLIENT");

  STACK_LOCK();

  g2mplsTypes::freeCTPSeq_var freeTS_var;
  freeTS_var = init_teLinkGetTdmBw();

  void *tmp;
  struct zlistnode *node;
  struct ospf_lsa *lsa;
  struct te_tlv_header *subtlv;

  struct zlist lsas;
  lsas = lookup_lsas_from_lsdb(TE_TLV_LINK);

  float fval;
  uint16_t i,n;
  uint32_t value;
  g2mplsTypes::teLinkIdent tmpIdent;
  struct signal_unalloc_tslots *ts;
  struct te_tlv_header *tlvh;
  for (ALL_LIST_ELEMENTS_RO (&lsas, node, tmp))
  {
    lsa = (struct ospf_lsa *) tmp;
    tmpIdent = create_link_ident_from_lsa(lsa);
    if (equalTeLinks(&ident, &tmpIdent))
    {
      if (subtlv = te_subtlv_lookup(lsa, TE_TLV_LINK, TE_LINK_SUBTLV_SSDH_IF_SW_CAP_DESC)) {

        tlvh = (struct te_tlv_header *) subtlv;
        n = (u_int16_t) ((TLV_BODY_SIZE(tlvh) / 4) - 1) ;

        g2mplsTypes::freeCTPSeq * tmp;
        tmp = new g2mplsTypes::freeCTPSeq(n);
        if (!tmp) {
          STACK_UNLOCK();
          throw (g2mplsEnniTopology::InternalProblems("method teLinkGetTdmBw (tmp == NULL)"));
        }
        freeTS_var = tmp;
        freeTS_var->length(n);

        if (n > 0)
        {
          ts = (struct signal_unalloc_tslots *)((struct te_tlv_header *) (tlvh+2)); 

          for (i=0; i< n; i++)
          {
            g2mplsTypes::freeCTPEntry entry;
            entry.sigType = (uint8_t) ts->signal_type;
            value  = 0;
            value  = ts->unalloc_tslots[0]; value <<= 8; value &= 0xff00;
            value |= ts->unalloc_tslots[1]; value <<= 8; value &= 0xffff00;
            value |= ts->unalloc_tslots[2]; value &= 0xffffff;
            entry.ctps = value;
            freeTS_var[i] = entry;
            ts++;
          }
        }
      }
      freeTS = freeTS_var._retn();

      STACK_UNLOCK();

      return true;
    }
  }
  freeTS = freeTS_var._retn();

  STACK_UNLOCK();

  if(IS_DEBUG_GRID_NODE(CORBA_ALL))
    zlog_debug("[WRN] CORBA: TeLink not found in LSDB");

  throw (g2mplsEnniTopology::CannotFetchLink(ident, "method teLinkGetTdmBw"));

  return false;
}

CORBA::Boolean
g2mplsEnniTopology_i::teLinkUpdateLscG709Bw(const g2mplsTypes::teLinkIdent& ident, const g2mplsTypes::freeCTPSeq& freeODUk, const g2mplsTypes::freeCTPSeq& freeOCh)
{
  if(IS_DEBUG_GRID_NODE(CORBA_ALL))
    zlog_debug("[DBG] CORBA: Received TELINK_UPDATE_LscG709BW message from ENNI CLIENT");

  STACK_LOCK();

  struct te_link* lp;

  struct in_addr node_id;
  node_id.s_addr = htonl(ident.localNodeId);

  lp =  lookup_hlink(node_id, ident.localId.ipv4());

  if (!lp) {
    STACK_UNLOCK();
    zlog_warn("[WRN] CORBA: Exception CannotFetchLink (teLinkUpdateLscG709Bw)");
    throw g2mplsEnniTopology::CannotFetchLink(ident, "teLinkUpdateLscG709Bw");
  }

  throw (g2mplsEnniTopology::InternalProblems("method teLinkUpdateLscG709Bw (not implemented)"));

  STACK_UNLOCK();

  return true;
}

CORBA::Boolean
g2mplsEnniTopology_i::teLinkGetLscG709Bw(const g2mplsTypes::teLinkIdent& ident, g2mplsTypes::freeCTPSeq_out freeODUk, g2mplsTypes::freeCTPSeq_out freeOCh)
{
  STACK_LOCK();

  throw (g2mplsEnniTopology::InternalProblems("method teLinkGetLscG709Bw (not implemented)"));

  STACK_UNLOCK();

  return true;
}

CORBA::Boolean
g2mplsEnniTopology_i::teLinkUpdateLscWdmBw(const g2mplsTypes::teLinkIdent& ident, const g2mplsTypes::wdmLambdasBitmap& bm)
{
  if(IS_DEBUG_GRID_NODE(CORBA_ALL))
    zlog_debug("[DBG] CORBA: Received TELINK_UPDATE_LscWdmBW message from ENNI CLIENT");

  STACK_LOCK();

  struct te_link* lp;

  struct in_addr node_id;
  node_id.s_addr = htonl(ident.localNodeId);

  lp =  lookup_hlink(node_id, ident.localId.ipv4());

  if (!lp) {
    STACK_UNLOCK();
    zlog_warn("[WRN] CORBA: Exception CannotFetchLink (teLinkUpdateLscWdmBw)");
    throw g2mplsEnniTopology::CannotFetchLink(ident, "teLinkUpdateLscWdmBw");
  }

  try {

    set_all_opt_ext_av_wave_mask (lp, (uint16_t) bm.numLambdas, bm.baseLambda);

    clear_all_opt_ext_av_wave_mask (lp);

    uint8_t *value = new uint8_t[bm.bitmap.length()];
    for (int i = 0; i < bm.bitmap.length() ; i++)
      value[i] = bm.bitmap[i];

    uint32_t *val32;
    val32 = (uint32_t *) value;
    for (int j = 0; j < bm.bitmap.length() / 4; j++) {
      add_all_opt_ext_av_wave_mask_bitmap (lp, htonl(*val32));
      val32++;
    }

    uint8_t rest; uint32_t val;
    if (rest = bm.bitmap.length() % 4) {
      switch (rest) {
        case 1: val = htonl(*val32) & 0xff000000; break;
        case 2: val = htonl(*val32) & 0xffff0000; break;
        case 3: val = htonl(*val32) & 0xffffff00; break;
      }
      add_all_opt_ext_av_wave_mask_bitmap (lp, val);
    }

  } catch (...) {
    STACK_UNLOCK();
    zlog_warn("[WRN] CORBA: Exception InternalProblems (teLinkUpdateLscWdmBw)");
    throw g2mplsEnniTopology::InternalProblems("teLinkUpdateLscWdmBw");
  }

  if(IS_DEBUG_GRID_NODE(CORBA_ALL))
    zlog_debug("[DBG] CORBA: Done TELINK_UPDATE_LscWdmBW");

  if (lp->area != NULL)
  {
    if (lp->flags & LPFLG_LSA_LI_ENGAGED)
    {
      ospf_te_lsa_schedule (lp, REFRESH_THIS_LSA, LINK);
      if(IS_DEBUG_GRID_NODE(CORBA_ALL))
        zlog_debug("[DBG] CORBA: ospf_te_lsa_schedule (lp, REFRESH_THIS_LSA, LINK)");
    }
    else
    {
      ospf_te_lsa_schedule (lp, REORIGINATE_PER_AREA, LINK);
      if(IS_DEBUG_GRID_NODE(CORBA_ALL))
        zlog_debug("[DBG] CORBA: ospf_te_lsa_schedule (lp, REORIGINATE_PER_AREA, LINK)");
    }
  }

  STACK_UNLOCK();

  return true;
}

g2mplsTypes::wdmLambdasBitmap_var init_teLinkGetLscWdmBw()
{
  g2mplsTypes::wdmLambdasBitmap_var bm;
  bm = new g2mplsTypes::wdmLambdasBitmap;

  bm->baseLambda = 0;
  bm->numLambdas = 0;

  g2mplsTypes::bitmapSeq_var seq;
  g2mplsTypes::bitmapSeq * tmp;
  tmp = new g2mplsTypes::bitmapSeq(0);
  seq = tmp;
  seq->length(0);
  bm->bitmap = seq;

  return bm;
}

CORBA::Boolean
g2mplsEnniTopology_i::teLinkGetLscWdmBw(const g2mplsTypes::teLinkIdent& ident, g2mplsTypes::wdmLambdasBitmap_out bm)
{
  if(IS_DEBUG_GRID_NODE(CORBA_ALL))
    zlog_debug("[DBG] CORBA: Received TELINK_GET_LSCWDMBW message from ENNI CLIENT");

  STACK_LOCK();


  g2mplsTypes::wdmLambdasBitmap_var bm_var;
  bm_var = init_teLinkGetLscWdmBw();

  void *tmp;
  struct zlistnode *node;
  struct ospf_lsa *lsa;
  struct te_tlv_header *subtlv;

  struct zlist lsas;
  lsas = lookup_lsas_from_lsdb(TE_TLV_LINK);

  uint16_t n;
  uint32_t *value;
  uint32_t *bitmaps;
  g2mplsTypes::teLinkIdent tmpIdent;
  struct te_link_subtlv_av_wave_mask *top;
  wdm_link_lambdas_bitmap_t lamBitmap;
  struct te_tlv_header *tlvh;
  for (ALL_LIST_ELEMENTS_RO (&lsas, node, tmp))
  {
    lsa = (struct ospf_lsa *) tmp;
    tmpIdent = create_link_ident_from_lsa(lsa);
    if (equalTeLinks(&ident, &tmpIdent))
    {
      if (subtlv = te_subtlv_lookup(lsa, TE_TLV_LINK, TE_LINK_SUBTLV_AV_WAVE_MASK)) {

        tlvh = (struct te_tlv_header *) subtlv;
        n = (u_int16_t) ((TLV_BODY_SIZE(tlvh)-8)/4);

        top = (struct te_link_subtlv_av_wave_mask *) tlvh;

        lamBitmap.num_wavelengths = ntohs(top->num_wavelengths);
        lamBitmap.base_lambda_label = ntohl(top->label_set_desc);
        lamBitmap.bitmap_size = (lamBitmap.num_wavelengths/32) + 1;
        bitmaps = new uint32_t[lamBitmap.bitmap_size];

        value = (uint32_t *) &top->bitmap_list;
        for (uint16_t i=0; i < n; i++)
          bitmaps[i] = ntohl(*(value++));

        lamBitmap.bitmap_word = bitmaps;
        bm_var << lamBitmap;
      }
      bm = bm_var._retn();

      STACK_UNLOCK();

      return true;
    }
  }
  bm = bm_var._retn();

  STACK_UNLOCK();

  if(IS_DEBUG_GRID_NODE(CORBA_ALL))
    zlog_debug("[WRN] CORBA: TeLink not found in LSDB");

  throw (g2mplsEnniTopology::CannotFetchLink(ident, "method teLinkGetLscWdmBw"));

  return false;
}

CORBA::Boolean
g2mplsEnniTopology_i::teLinkAppendSrlgs(const g2mplsTypes::teLinkIdent& ident, const g2mplsTypes::srlgSeq& srlgs)
{
  if(IS_DEBUG_GRID_NODE(CORBA_ALL))
    zlog_debug("[DBG] CORBA: Received TELINK_APPEND_SRLGS message from ENNI CLIENT");

  STACK_LOCK();

  struct te_link* lp;

  struct in_addr node_id;
  node_id.s_addr = htonl(ident.localNodeId);

  lp =  lookup_hlink(node_id, ident.localId.ipv4());

  if (!lp) {
    STACK_UNLOCK();
    zlog_warn("[WRN] CORBA: Exception CannotFetchLink (teLinkAppendSrlgs)");
    throw g2mplsEnniTopology::CannotFetchLink(ident, "teLinkAppendSrlgs");
  }

  try {

    for (int i = 0; i < srlgs.length(); i++)
      add_shared_risk_link_grp(lp, srlgs[i]);

  } catch (...) {
    STACK_UNLOCK();
    zlog_warn("[WRN] CORBA: Exception InternalProblems (teLinkAppendSrlgs)");
    throw g2mplsEnniTopology::InternalProblems("teLinkAppendSrlgs");
  }

  if(IS_DEBUG_GRID_NODE(CORBA_ALL))
    zlog_debug("[DBG] CORBA: Done TELINK_APPEND_SRLGS");

  if (lp->area != NULL)
  {
    if (lp->flags & LPFLG_LSA_LI_ENGAGED)
    {
      ospf_te_lsa_schedule (lp, REFRESH_THIS_LSA, LINK);
      if(IS_DEBUG_GRID_NODE(CORBA_ALL))
        zlog_debug("[DBG] CORBA: ospf_te_lsa_schedule (lp, REFRESH_THIS_LSA, LINK)");
    }
    else
    {
      ospf_te_lsa_schedule (lp, REORIGINATE_PER_AREA, LINK);
      if(IS_DEBUG_GRID_NODE(CORBA_ALL))
        zlog_debug("[DBG] CORBA: ospf_te_lsa_schedule (lp, REORIGINATE_PER_AREA, LINK)");
    }
  }

  STACK_UNLOCK();

  return true;
}

CORBA::Boolean
g2mplsEnniTopology_i::teLinkRemoveSrlgs(const g2mplsTypes::teLinkIdent& ident, const g2mplsTypes::srlgSeq& srlgs)
{
  if(IS_DEBUG_GRID_NODE(CORBA_ALL))
    zlog_debug("[DBG] CORBA: Received TELINK_REMOVE_SRLGS message from ENNI CLIENT");

  STACK_LOCK();

  struct te_link* lp;

  struct in_addr node_id;
  node_id.s_addr = htonl(ident.localNodeId);

  lp =  lookup_hlink(node_id, ident.localId.ipv4());

  if (!lp) {
    STACK_UNLOCK();
    zlog_warn("[WRN] CORBA: Exception CannotFetchLink (teLinkRemoveSrlgs)");
    throw g2mplsEnniTopology::CannotFetchLink(ident, "teLinkRemoveSrlgs");
  }

  try {

    for (int i = 0; i < srlgs.length(); i++)
      del_shared_risk_link_grp(lp, srlgs[i]);

  } catch (...) {
    STACK_UNLOCK();
    zlog_warn("[WRN] CORBA: Exception InternalProblems (teLinkRemoveSrlgs)");
    throw g2mplsEnniTopology::InternalProblems("teLinkRemoveSrlgs");
  }

  if(IS_DEBUG_GRID_NODE(CORBA_ALL))
    zlog_debug("[DBG] CORBA: Done TELINK_REMOVE_SRLGS");

  if (lp->area != NULL)
  {
    if (lp->flags & LPFLG_LSA_LI_ENGAGED)
    {
      ospf_te_lsa_schedule (lp, REFRESH_THIS_LSA, LINK);
      if(IS_DEBUG_GRID_NODE(CORBA_ALL))
        zlog_debug("[DBG] CORBA: ospf_te_lsa_schedule (lp, REFRESH_THIS_LSA, LINK)");
    }
    else
    {
      ospf_te_lsa_schedule (lp, REORIGINATE_PER_AREA, LINK);
      if(IS_DEBUG_GRID_NODE(CORBA_ALL))
        zlog_debug("[DBG] CORBA: ospf_te_lsa_schedule (lp, REORIGINATE_PER_AREA, LINK)");
    }
  }

  STACK_UNLOCK();

  return true;
}

g2mplsTypes::srlgSeq_var init_teLinkGetSrlgs()
{
  g2mplsTypes::srlgSeq_var seq;
  g2mplsTypes::srlgSeq * tmp;
  tmp = new g2mplsTypes::srlgSeq(0);
  seq = tmp;
  seq->length(0);
  return seq;
}

CORBA::Boolean
g2mplsEnniTopology_i::teLinkGetSrlgs(const g2mplsTypes::teLinkIdent& ident, g2mplsTypes::srlgSeq_out srlgs)
{
  if(IS_DEBUG_GRID_NODE(CORBA_ALL))
    zlog_debug("[DBG] CORBA: Received TELINK_GET_SRLGS message from ENNI CLIENT");

  STACK_LOCK();

  g2mplsTypes::srlgSeq_var srlgs_var;
  srlgs_var = init_teLinkGetSrlgs();

  void *tmp;
  struct zlistnode *node;
  struct ospf_lsa *lsa;
  struct te_tlv_header *subtlv;

  struct zlist lsas;
  lsas = lookup_lsas_from_lsdb(TE_TLV_LINK);

  uint16_t i,n;
  uint32_t *value;
  g2mplsTypes::teLinkIdent tmpIdent;
  struct te_tlv_header *tlvh;
  for (ALL_LIST_ELEMENTS_RO (&lsas, node, tmp))
  {
    lsa = (struct ospf_lsa *) tmp;
    tmpIdent = create_link_ident_from_lsa(lsa);
    if (equalTeLinks(&ident, &tmpIdent))
    {
      if (subtlv = te_subtlv_lookup(lsa, TE_TLV_LINK, TE_LINK_SUBTLV_SHARED_RISK_LINK_GRP)) {

        tlvh = (struct te_tlv_header *) subtlv;
        n = (u_int16_t) (TLV_BODY_SIZE(tlvh) / 4);

        g2mplsTypes::srlgSeq * tmp;
        tmp = new g2mplsTypes::srlgSeq(n);
        if (!tmp) {
          STACK_UNLOCK();
          throw (g2mplsEnniTopology::InternalProblems("method teLinkGetSrlgs (tmp == NULL)"));
        }
        srlgs_var = tmp;
        srlgs_var->length(n);

        if (n > 0)
        {
          value = (uint32_t *)(tlvh+1);

          for (i=0; i< n; i++)
            srlgs_var[i] = ntohl(*(value++));
        }
      }
      srlgs = srlgs_var._retn();

      STACK_UNLOCK();

      return true;
    }
  }
  srlgs = srlgs_var._retn();

  STACK_UNLOCK();

  if(IS_DEBUG_GRID_NODE(CORBA_ALL))
    zlog_debug("[WRN] CORBA: TeLink not found in LSDB");

  throw (g2mplsEnniTopology::CannotFetchLink(ident, "method teLinkGetSrlgs"));

  return false;
}

CORBA::Boolean
g2mplsEnniTopology_i::teLinkAppendCalendar(const g2mplsTypes::teLinkIdent& ident, const g2mplsTypes::teLinkCalendarSeq& cal)
{
  if(IS_DEBUG_GRID_NODE(CORBA_ALL))
    zlog_debug("[DBG] CORBA: Received TELINK_APPEND_CALENDAR message from ENNI CLIENT");

  STACK_LOCK();

  struct te_link* lp;

  struct in_addr node_id;
  node_id.s_addr = htonl(ident.localNodeId);

  lp =  lookup_hlink(node_id, ident.localId.ipv4());

  if (!lp) {
    STACK_UNLOCK();
    zlog_warn("[WRN] CORBA: Exception CannotFetchLink (teLinkAppendCalendar)");
    throw g2mplsEnniTopology::CannotFetchLink(ident, "teLinkAppendCalendar");
  }

  try {

    uint8_t j;
    float band[8];
    for (int i = 0; i < cal.length(); i++)
    {
      for (j = 0; j < 8; j++)
        band[j] = (float) cal[i].availBw[j];

      add_all_opt_ext_te_link_calendar (lp, cal[i].unixTime, band);
    }

  } catch (...) {
    STACK_UNLOCK();
    zlog_warn("[WRN] CORBA: Exception InternalProblems (teLinkAppendCalendar)");
    throw g2mplsEnniTopology::InternalProblems("teLinkAppendCalendar");
  }

  if(IS_DEBUG_GRID_NODE(CORBA_ALL))
    zlog_debug("[DBG] CORBA: Done TELINK_APPEND_CALENDAR");

  if (lp->area != NULL)
  {
    if (lp->flags & LPFLG_LSA_LI_ENGAGED)
    {
      ospf_te_lsa_schedule (lp, REFRESH_THIS_LSA, LINK);
      if(IS_DEBUG_GRID_NODE(CORBA_ALL))
        zlog_debug("[DBG] CORBA: ospf_te_lsa_schedule (lp, REFRESH_THIS_LSA, LINK)");
    }
    else
    {
      ospf_te_lsa_schedule (lp, REORIGINATE_PER_AREA, LINK);
      if(IS_DEBUG_GRID_NODE(CORBA_ALL))
        zlog_debug("[DBG] CORBA: ospf_te_lsa_schedule (lp, REORIGINATE_PER_AREA, LINK)");
    }
  }

  STACK_UNLOCK();

  return true;
}

CORBA::Boolean
g2mplsEnniTopology_i::teLinkRemoveCalendar(const g2mplsTypes::teLinkIdent& ident, const g2mplsTypes::teLinkCalendarSeq& cal)
{
  if(IS_DEBUG_GRID_NODE(CORBA_ALL))
    zlog_debug("[DBG] CORBA: Received TELINK_REMOVE_CALENDAR message from ENNI CLIENT");

  STACK_LOCK();

  struct te_link* lp;

  struct in_addr node_id;
  node_id.s_addr = htonl(ident.localNodeId);

  lp =  lookup_hlink(node_id, ident.localId.ipv4());

  if (!lp) {
    STACK_UNLOCK();
    zlog_warn("[WRN] CORBA: Exception CannotFetchLink (teLinkRemoveCalendar)");
    throw g2mplsEnniTopology::CannotFetchLink(ident, "teLinkRemoveCalendar");
  }

  try {

    uint8_t j;
    float band[8];
    for (int i = 0; i < cal.length(); i++)
    {
      for (j = 0; j < 8; j++)
        band[j] = (float) cal[i].availBw[j];

      del_all_opt_ext_te_link_calendar (lp, cal[i].unixTime, band);
    }

  } catch (...) {
    STACK_UNLOCK();
    zlog_warn("[WRN] CORBA: Exception InternalProblems (teLinkRemoveCalendar)");
    throw g2mplsEnniTopology::InternalProblems("teLinkRemoveCalendar");
  }

  if(IS_DEBUG_GRID_NODE(CORBA_ALL))
    zlog_debug("[DBG] CORBA: Done TELINK_REMOVE_CALENDAR");

  if (lp->area != NULL)
  {
    if (lp->flags & LPFLG_LSA_LI_ENGAGED)
    {
      ospf_te_lsa_schedule (lp, REFRESH_THIS_LSA, LINK);
      if(IS_DEBUG_GRID_NODE(CORBA_ALL))
        zlog_debug("[DBG] CORBA: ospf_te_lsa_schedule (lp, REFRESH_THIS_LSA, LINK)");
    }
    else
    {
      ospf_te_lsa_schedule (lp, REORIGINATE_PER_AREA, LINK);
      if(IS_DEBUG_GRID_NODE(CORBA_ALL))
        zlog_debug("[DBG] CORBA: ospf_te_lsa_schedule (lp, REORIGINATE_PER_AREA, LINK)");
    }
  }

  STACK_UNLOCK();

  return true;
}

g2mplsTypes::teLinkCalendarSeq_var init_teLinkGetCalendar()
{
  g2mplsTypes::teLinkCalendarSeq_var seq;
  g2mplsTypes::teLinkCalendarSeq * tmp;
  tmp = new g2mplsTypes::teLinkCalendarSeq(0);
  seq = tmp;
  seq->length(0);
  return seq;
}

CORBA::Boolean
g2mplsEnniTopology_i::teLinkGetCalendar(const g2mplsTypes::teLinkIdent& ident, g2mplsTypes::teLinkCalendarSeq_out cal)
{
  if(IS_DEBUG_GRID_NODE(CORBA_ALL))
    zlog_debug("[DBG] CORBA: Received TELINK_GET_CALENDAR message from ENNI CLIENT");

  STACK_LOCK();

  g2mplsTypes::teLinkCalendarSeq_var cal_var;
  cal_var = init_teLinkGetCalendar();

  void *tmp;
  struct zlistnode *node;
  struct ospf_lsa *lsa;
  struct te_tlv_header *subtlv;

  struct zlist lsas;
  lsas = lookup_lsas_from_lsdb(TE_TLV_LINK);

  float fval;
  uint16_t i, j, n;
  uint32_t lu1, lu2;
  uint32_t *value;
  g2mplsTypes::teLinkIdent tmpIdent;
  struct te_tlv_header *tlvh;
  for (ALL_LIST_ELEMENTS_RO (&lsas, node, tmp))
  {
    lsa = (struct ospf_lsa *) tmp;
    tmpIdent = create_link_ident_from_lsa(lsa);
    if (equalTeLinks(&ident, &tmpIdent))
    {
      if (subtlv = te_subtlv_lookup(lsa, TE_TLV_LINK, TE_LINK_SUBTLV_TE_LINK_CALENDAR)) {

        tlvh = (struct te_tlv_header *) subtlv;
        n = (u_int16_t) (TLV_BODY_SIZE(tlvh) / 36);

        g2mplsTypes::teLinkCalendarSeq * tmp;
        tmp = new g2mplsTypes::teLinkCalendarSeq(n);
        if (!tmp) {
          STACK_UNLOCK();
          throw (g2mplsEnniTopology::InternalProblems("method teLinkGetCalendar (tmp == NULL)"));
        }
        cal_var = tmp;
        cal_var->length(n);

        if (n > 0)
        {
          value = (uint32_t *)(tlvh+1);

          for (i=0; i<n; i++) 
          {
            g2mplsTypes::linkCalendarEvent event;

            event.unixTime = ntohl(*(value++));

            for (j=0; j< 8; j++) 
            {
              memcpy (&lu1, (float *) (value++), 4);
              lu2 = ntohl (lu1);
              memcpy (&fval, &lu2, 4);
              event.availBw[j] = (int) fval;
            }

            cal_var[i] = event;
          }
        }
      }
      cal = cal_var._retn();

      STACK_UNLOCK();

      return true;
    }
  }
  cal = cal_var._retn();

  STACK_UNLOCK();

  if(IS_DEBUG_GRID_NODE(CORBA_ALL))
    zlog_debug("[WRN] CORBA: TeLink not found in LSDB");

  throw (g2mplsEnniTopology::CannotFetchLink(ident, "method teLinkGetCalendar"));

  return false;
}

CORBA::Boolean
g2mplsEnniTopology_i::teLinkAppendIsc(const g2mplsTypes::teLinkIdent& ident, const g2mplsTypes::iscSeq& iscs)
{
  if(IS_DEBUG_GRID_NODE(CORBA_ALL))
    zlog_debug("[DBG] CORBA: Received TELINK_APPEND_ISC message from ENNI CLIENT");

  STACK_LOCK();


  struct te_link* lp;

  struct in_addr node_id;
  node_id.s_addr = htonl(ident.localNodeId);

  lp =  lookup_hlink(node_id, ident.localId.ipv4());

  if (!lp) {
    STACK_UNLOCK();
    zlog_warn("[WRN] CORBA: Exception CannotFetchLink (teLinkAppendIsc)");
    throw g2mplsEnniTopology::CannotFetchLink(ident, "teLinkAppendIsc");
  }

  try {

    g2mplsTypes::isc_var isc;
    g2mplsTypes::iscParamsTdm_var tdm;
    g2mplsTypes::iscParamsPsc_var psc;
    g2mplsTypes::iscParamsGen_var gen;

    float fval;
    float maxLspBw[8];

    for (int i = 0; i < iscs.length(); i++)
    {
      isc = iscs[i];
      switch (isc->_d())
      {
        case g2mplsTypes::SWITCHINGCAP_PSC_1:
        case g2mplsTypes::SWITCHINGCAP_PSC_2:
        case g2mplsTypes::SWITCHINGCAP_PSC_3:
        case g2mplsTypes::SWITCHINGCAP_PSC_4:

          psc = isc->psc();

          delete_te_link_subtlv_if_sw_cap_desc (lp, switching_cap_from_enum(psc->swCap), encoding_type_from_enum(psc->encType));

          create_te_link_subtlv_if_sw_cap_desc (lp, switching_cap_from_enum(psc->swCap), encoding_type_from_enum(psc->encType));

          fval = psc->minLSPbandwidth;
          set_if_sw_cap_desc_psc (lp, switching_cap_from_enum(psc->swCap), encoding_type_from_enum(psc->encType),
                                   &fval, (uint16_t) psc->interfaceMTU);

          for (int k=0; k<8; k++)
            maxLspBw[k] = (float) psc->maxLSPbandwidth[k];

          set_if_sw_cap_max_bands (lp, switching_cap_from_enum(psc->swCap), encoding_type_from_enum(psc->encType), maxLspBw);

          break;

        case g2mplsTypes::SWITCHINGCAP_TDM  :

          tdm = isc->tdm();

          delete_te_link_subtlv_if_sw_cap_desc (lp, switching_cap_from_enum(tdm->swCap), encoding_type_from_enum(tdm->encType));

          create_te_link_subtlv_if_sw_cap_desc (lp, switching_cap_from_enum(tdm->swCap), encoding_type_from_enum(tdm->encType));

          fval = tdm->minLSPbandwidth;
          set_if_sw_cap_desc_tdm (lp, switching_cap_from_enum(tdm->swCap), encoding_type_from_enum(tdm->encType),
                                   &fval, tdm->indication);

          for (int k=0; k<8; k++)
            maxLspBw[k] = (float) tdm->maxLSPbandwidth[k];

          set_if_sw_cap_max_bands (lp, switching_cap_from_enum(tdm->swCap), encoding_type_from_enum(tdm->encType), maxLspBw);

          break;

        case g2mplsTypes::SWITCHINGCAP_L2SC :
        case g2mplsTypes::SWITCHINGCAP_LSC  :
        case g2mplsTypes::SWITCHINGCAP_FSC  :

          gen = isc->gen();

          delete_te_link_subtlv_if_sw_cap_desc (lp, switching_cap_from_enum(gen->swCap), encoding_type_from_enum(gen->encType));

          create_te_link_subtlv_if_sw_cap_desc (lp, switching_cap_from_enum(gen->swCap), encoding_type_from_enum(gen->encType));

          for (int k=0; k<8; k++)
            maxLspBw[k] = (float) gen->maxLSPbandwidth[k];

          set_if_sw_cap_max_bands (lp, switching_cap_from_enum(gen->swCap), encoding_type_from_enum(gen->encType), maxLspBw);

          break;
      }
    }

  } catch (...) {
    STACK_UNLOCK();
    zlog_warn("[WRN] CORBA: Exception InternalProblems (teLinkAppendIsc)");
    throw g2mplsEnniTopology::InternalProblems("teLinkAppendIsc");
  }

  if(IS_DEBUG_GRID_NODE(CORBA_ALL))
    zlog_debug("[DBG] CORBA: Done TELINK_APPEND_ISC");

  if (lp->area != NULL)
  {
    if (lp->flags & LPFLG_LSA_LI_ENGAGED)
    {
      ospf_te_lsa_schedule (lp, REFRESH_THIS_LSA, LINK);
      if(IS_DEBUG_GRID_NODE(CORBA_ALL))
        zlog_debug("[DBG] CORBA: ospf_te_lsa_schedule (lp, REFRESH_THIS_LSA, LINK)");
    }
    else
    {
      ospf_te_lsa_schedule (lp, REORIGINATE_PER_AREA, LINK);
      if(IS_DEBUG_GRID_NODE(CORBA_ALL))
        zlog_debug("[DBG] CORBA: ospf_te_lsa_schedule (lp, REORIGINATE_PER_AREA, LINK)");
    }
  }


  STACK_UNLOCK();

  return true;
}

CORBA::Boolean
g2mplsEnniTopology_i::teLinkRemoveIsc(const g2mplsTypes::teLinkIdent& ident, const g2mplsTypes::iscSeq& iscs)
{
  if(IS_DEBUG_GRID_NODE(CORBA_ALL))
    zlog_debug("[DBG] CORBA: Received TELINK_REMOVE_ISC message from ENNI CLIENT");

  STACK_LOCK();

  struct te_link* lp;

  struct in_addr node_id;
  node_id.s_addr = htonl(ident.localNodeId);

  lp =  lookup_hlink(node_id, ident.localId.ipv4());

  if (!lp) {
    STACK_UNLOCK();
    zlog_warn("[WRN] CORBA: Exception CannotFetchLink (teLinkRemoveIsc)");
    throw g2mplsEnniTopology::CannotFetchLink(ident, "teLinkRemoveIsc");
  }

  try {

    g2mplsTypes::isc_var isc;
    g2mplsTypes::iscParamsTdm_var tdm;
    g2mplsTypes::iscParamsPsc_var psc;
    g2mplsTypes::iscParamsGen_var gen;

    float maxLspBw[8];

    for (int i = 0; i < iscs.length(); i++)
    {
      isc = iscs[i];
      switch (isc->_d())
      {
        case g2mplsTypes::SWITCHINGCAP_PSC_1:
        case g2mplsTypes::SWITCHINGCAP_PSC_2:
        case g2mplsTypes::SWITCHINGCAP_PSC_3:
        case g2mplsTypes::SWITCHINGCAP_PSC_4:

          psc = isc->psc();

          delete_te_link_subtlv_if_sw_cap_desc (lp, switching_cap_from_enum(psc->swCap), encoding_type_from_enum(psc->encType));

          break;

        case g2mplsTypes::SWITCHINGCAP_TDM  :

          tdm = isc->tdm();

          delete_te_link_subtlv_if_sw_cap_desc (lp, switching_cap_from_enum(tdm->swCap), encoding_type_from_enum(tdm->encType));

          break;

        case g2mplsTypes::SWITCHINGCAP_L2SC :
        case g2mplsTypes::SWITCHINGCAP_LSC  :
        case g2mplsTypes::SWITCHINGCAP_FSC  :

          gen = isc->gen();

          delete_te_link_subtlv_if_sw_cap_desc (lp, switching_cap_from_enum(gen->swCap), encoding_type_from_enum(gen->encType));

          break;
      }
    }

  } catch (...) {
    STACK_UNLOCK();
    zlog_warn("[WRN] CORBA: Exception InternalProblems (teLinkRemoveIsc)");
    throw g2mplsEnniTopology::InternalProblems("teLinkRemoveIsc");
  }

  if(IS_DEBUG_GRID_NODE(CORBA_ALL))
    zlog_debug("[DBG] CORBA: Done TELINK_REMOVE_ISC");

  if (lp->area != NULL)
  {
    if (lp->flags & LPFLG_LSA_LI_ENGAGED)
    {
      ospf_te_lsa_schedule (lp, REFRESH_THIS_LSA, LINK);
      if(IS_DEBUG_GRID_NODE(CORBA_ALL))
        zlog_debug("[DBG] CORBA: ospf_te_lsa_schedule (lp, REFRESH_THIS_LSA, LINK)");
    }
    else
    {
      ospf_te_lsa_schedule (lp, REORIGINATE_PER_AREA, LINK);
      if(IS_DEBUG_GRID_NODE(CORBA_ALL))
        zlog_debug("[DBG] CORBA: ospf_te_lsa_schedule (lp, REORIGINATE_PER_AREA, LINK)");
    }
  }

  STACK_UNLOCK();

  return true;
}

g2mplsTypes::iscSeq_var init_teLinkGetIsc()
{
  g2mplsTypes::iscSeq_var seq;
  g2mplsTypes::iscSeq * tmp;
  tmp = new g2mplsTypes::iscSeq(0);
  seq = tmp;
  seq->length(0);
  return seq;
}

CORBA::Boolean
g2mplsEnniTopology_i::teLinkGetIsc(const g2mplsTypes::teLinkIdent& ident, g2mplsTypes::iscSeq_out iscs)
{
  if(IS_DEBUG_GRID_NODE(CORBA_ALL))
    zlog_debug("[DBG] CORBA: Received TELINK_GET_ISC message from ENNI CLIENT");

  STACK_LOCK();

  g2mplsTypes::iscSeq_var iscs_var;
  iscs_var = init_teLinkGetIsc();

  void *data;
  float temp;
  uint16_t len, sum, count;
  uint32_t lu1, lu2;

  struct zlist ifSwCaps;
  memset (&ifSwCaps, 0, sizeof (struct zlist));

  struct zlistnode *node;
  struct ospf_lsa *lsa;
  struct te_tlv_header *subtlv;
  te_link_if_sw_cap_t *value;

  struct zlist lsas;
  lsas = lookup_lsas_from_lsdb(TE_TLV_LINK);

  g2mplsTypes::teLinkIdent tmpIdent;
  struct te_link_subtlv_if_sw_cap_desc *top;
  for (ALL_LIST_ELEMENTS_RO (&lsas, node, data))
  {
    lsa = (struct ospf_lsa *) data;
    tmpIdent = create_link_ident_from_lsa(lsa);
    if (equalTeLinks(&ident, &tmpIdent))
    {

      has_lsa_tlv_type(lsa, TE_TLV_TNA_ADDR, &len);

      if (subtlv = te_subtlv_lookup(lsa, TE_TLV_LINK, TE_LINK_SUBTLV_IF_SW_CAP_DESC))
      {
        sum = 0;
        while((sum < len) && (ntohs(subtlv->type) == TE_LINK_SUBTLV_IF_SW_CAP_DESC))
        {
          top = (struct te_link_subtlv_if_sw_cap_desc *) subtlv;

          value = (te_link_if_sw_cap_t *) XMALLOC (0, sizeof(te_link_if_sw_cap_t));

          value->switching_cap = (uint8_t)top->switching_cap;
          value->encoding = (uint8_t)top->encoding;

          for(int i=0; i<8; i++){
            memcpy (&lu1, &top->maxLSPbw[i], 4);
            lu2 = ntohl (lu1);
            memcpy (&temp, &lu2, 4);
            value->maxLSPbw[i] = temp;
          }

          switch (top->switching_cap)
          {
            case CAPABILITY_PSC1:
            case CAPABILITY_PSC2:
            case CAPABILITY_PSC3:
            case CAPABILITY_PSC4:
              memcpy (&lu1, &top->swcap_specific_info.swcap_specific_psc.min_lsp_bw, 4);
              lu2 = ntohl (lu1);
              memcpy (&temp, &lu2, 4);
              value->min_lsp_bw = temp;
              value->mtu = (uint32_t)ntohs(top->swcap_specific_info.swcap_specific_psc.mtu);
              break;
            case CAPABILITY_TDM:
              memcpy (&lu1, &top->swcap_specific_info.swcap_specific_psc.min_lsp_bw, 4);
              lu2 = ntohl (lu1);
              memcpy (&temp, &lu2, 4);
              value->min_lsp_bw = temp;
              value->indication = (uint8_t)(top->swcap_specific_info.swcap_specific_tdm.indication);
              break;
            case CAPABILITY_L2SC:
            case CAPABILITY_LSC:
            case CAPABILITY_FSC:
              break;
          }
          listnode_add(&ifSwCaps, value);

          sum += TLV_SIZE(subtlv);
          subtlv += TLV_SIZE(subtlv) / 4;
        }

        count = listcount(&ifSwCaps);
        g2mplsTypes::iscSeq * tmp;
        tmp = new g2mplsTypes::iscSeq(count);
        if (!tmp) {
          STACK_UNLOCK();
          throw (g2mplsEnniTopology::InternalProblems("method teLinkGetIsc (tmp == NULL)"));
        }
        iscs_var = tmp;
        iscs_var->length(count);

        uint16_t z = 0;
        for (ALL_LIST_ELEMENTS_RO (&ifSwCaps, node, data)) {

          value = (te_link_if_sw_cap *) data;
          g2mplsTypes::isc isc;

          g2mplsTypes::iscParamsGen gen;
          g2mplsTypes::iscParamsTdm tdm;
          g2mplsTypes::iscParamsPsc psc;

          switch(value->switching_cap)
          {
            case CAPABILITY_PSC1:
            case CAPABILITY_PSC2:
            case CAPABILITY_PSC3:
            case CAPABILITY_PSC4:
            case CAPABILITY_L2SC:
              psc.swCap   = switching_cap_from_uchar(value->switching_cap);
              psc.encType = encoding_type_from_uchar(value->encoding);
              for(int i=0; i<LINK_MAX_PRIORITY; i++)
                psc.maxLSPbandwidth[i] = (int) value->maxLSPbw[i];
              psc.minLSPbandwidth = (int) value->min_lsp_bw;
              psc.interfaceMTU = value->mtu;
              isc.psc(psc);
              break;
            case CAPABILITY_TDM:
              tdm.swCap   = switching_cap_from_uchar(value->switching_cap);
              tdm.encType = encoding_type_from_uchar(value->encoding);
              for(int i=0; i<LINK_MAX_PRIORITY; i++)
                tdm.maxLSPbandwidth[i] = (int) value->maxLSPbw[i];
              tdm.minLSPbandwidth = (int) value->min_lsp_bw;
              tdm.indication = value->indication;
              isc.tdm(tdm);
              break;
            case CAPABILITY_LSC:
            case CAPABILITY_FSC:
              gen.swCap   = switching_cap_from_uchar(value->switching_cap);
              gen.encType = encoding_type_from_uchar(value->encoding);
              for(int i=0; i<LINK_MAX_PRIORITY; i++)
                gen.maxLSPbandwidth[i] = (int) value->maxLSPbw[i];
              isc.gen(gen);
              break;
            default:
              break;
           }

           iscs_var[z] = isc;
           z++;
        }
        iscs = iscs_var._retn();

        STACK_UNLOCK();

        return true;
      }
    }
  }
  iscs = iscs_var._retn();

  STACK_UNLOCK();

  if(IS_DEBUG_GRID_NODE(CORBA_ALL))
    zlog_debug("[WRN] CORBA: TeLink not found in LSDB");

  throw (g2mplsEnniTopology::CannotFetchLink(ident, "method teLinkGetIsc"));

  return false;
}

g2mplsEnniTopology_i* _servant = 0;
#endif // TOPOLOGY_ENNI_ON
#endif // HAVE_OMNIORB

extern "C" {

  int corba_enni_server_setup(void)
  {
#ifdef HAVE_OMNIORB
#ifdef TOPOLOGY_ENNI_ON
    if (IS_DEBUG_GRID_NODE(CORBA))
      zlog_debug("[DBG] CORBA: Setting up CORBA ENNI server side");

    try {
      _servant = new g2mplsEnniTopology_i();
      if (!_servant) {
        throw string("Cannot create servant");
      }

      PortableServer::POA_var poa;
      poa = corba_poa();
      if (CORBA::is_nil(poa)) {
        throw string("Cannot get POA");
      }

      PortableServer::ObjectId_var servant_id;
      servant_id = poa->activate_object(_servant);

      CORBA::Object_var obj;
      obj = _servant->_this();
      if (CORBA::is_nil(obj)) {
        throw string("Cannot get object");
      }

      CORBA::ORB_var orb;
      orb = corba_orb();
      if (CORBA::is_nil(orb)) {
        throw string("Cannot get ORB");
      }

      CORBA::String_var sior(orb->object_to_string(obj));
      if (IS_DEBUG_GRID_NODE(CORBA))
        zlog_debug("[DBG] CORBA: IOR = '%s'", (char*) sior);

      if (!corba_dump_ior(CORBA_SERVANT_G2TOPOLOGY_ENNI, string(sior))) {
        throw string("Cannot dump IOR");
      }

      _servant->_remove_ref();

      PortableServer::POAManager_var poa_manager;
      poa_manager = corba_poa_manager();
      if (CORBA::is_nil(poa_manager)) {
        throw string("Cannot get POA Manager");
      }

      poa_manager->activate();

    if (IS_DEBUG_GRID_NODE(CORBA))
      zlog_debug("[DBG] CORBA: CORBA server side is up");

    } catch (CORBA::SystemException & e) {
      zlog_debug("[ERR] CORBA: Caught CORBA::SystemException");
      return 0;
    } catch (CORBA::Exception & e) {
      zlog_debug("[ERR] CORBA: Caught CORBA::Exception");
      return 0;
    } catch (omniORB::fatalException & e) {
      zlog_debug("[ERR] CORBA: Caught omniORB::fatalException:");
      zlog_debug("[ERR]        file: %s", e.file());
      zlog_debug("[ERR]        line: %d", e.line());
      zlog_debug("[ERR]        mesg: %s", e.errmsg());
      return 0;
    } catch (string & e) {
      zlog_debug("[ERR] CORBA: Caught exception: %s", e.c_str());
      return 0;
    } catch (...) {
      zlog_debug("[ERR] CORBA: Caught unknown exception");
      return 0;
    }
#else
    return -1;
#endif // TOPOLOGY_ENNI_ON
#endif // HAVE_OMNIORB  
    return 1;
  }


  int corba_enni_server_shutdown(void)
  {
#ifdef HAVE_OMNIORB
#ifdef TOPOLOGY_ENNI_ON
    try {
      if (IS_DEBUG_GRID_NODE(CORBA))
        zlog_debug("[DBG] CORBA: Shutting down CORBA ENNI server side");

      if (!corba_remove_ior(CORBA_SERVANT_G2TOPOLOGY_ENNI)) {
        throw string("Cannot remove IOR");
      }
    } catch (...) {
      zlog_debug("[ERR] CORBA: Caught unknown exception");
      return 0;
    }

    return 1;
#else
    return -1;
#endif // TOPOLOGY_ENNI_ON
#endif // HAVE_OMNIORB
  }

} //extern "C"
