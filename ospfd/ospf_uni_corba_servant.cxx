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
#include "ospfd/ospf_corba.h"
#include "ospfd/ospf_te.h"
#include "ospfd/ospf_grid.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_corba_utils.h"
#ifdef TOPOLOGY_UNI_ON
#include "topology.hh"
#endif

//
// Topology servant implementation
//

#ifdef TOPOLOGY_UNI_ON
class TOPOLOGY_i : public POA_TOPOLOGY::Info,
		   public PortableServer::RefCountServantBase
{
  public:
    inline TOPOLOGY_i()  {};
    virtual ~TOPOLOGY_i() {};

    CORBA::Boolean
    nodeAdd(const g2mplsTypes::nodeIdent& id);

    CORBA::Boolean
    nodeDel(const g2mplsTypes::nodeIdent& id);

    g2mplsTypes::nodeIdentSeq* 
    nodeGetAll();

    CORBA::Boolean
    netNodeUpdate(g2mplsTypes::nodeId id, const g2mplsTypes::netNodeParams& info);

    CORBA::Boolean
    netNodeGet(g2mplsTypes::nodeId id, g2mplsTypes::netNodeParams_out info);

    CORBA::Boolean
    gridSiteUpdate(g2mplsTypes::nodeId id, const g2mplsTypes::gridSiteParams& info);

    CORBA::Boolean
    gridSiteGet(g2mplsTypes::nodeId id, g2mplsTypes::gridSiteParams_out info,
                g2mplsTypes::gridSubNodes_out snodes);

    CORBA::Boolean
    gridSubNodeDel(g2mplsTypes::nodeId siteId, const g2mplsTypes::gridSubNodeIdent& id);

    CORBA::Boolean
    gridServiceUpdate(g2mplsTypes::nodeId siteId, g2mplsTypes::gridSubNodeId id,
                const g2mplsTypes::gridServiceParams& info);

    CORBA::Boolean
    gridServiceGet(g2mplsTypes::nodeId siteId, g2mplsTypes::gridSubNodeId id,
                   g2mplsTypes::gridServiceParams& info);

    CORBA::Boolean
    gridCompElemUpdate(g2mplsTypes::nodeId siteId, g2mplsTypes::gridSubNodeId id,
                       const g2mplsTypes::gridCEParams& info);

    CORBA::Boolean
    gridCompElemGet(g2mplsTypes::nodeId siteId, g2mplsTypes::gridSubNodeId id,
                    g2mplsTypes::gridCEParams_out info);

    CORBA::Boolean
    gridSubClusterUpdate(g2mplsTypes::nodeId siteId, g2mplsTypes::gridSubNodeId id,
                         const g2mplsTypes::gridSubClusterParams& info);

    CORBA::Boolean
    gridSubClusterGet(g2mplsTypes::nodeId siteId, g2mplsTypes::gridSubNodeId id,
                      g2mplsTypes::gridSubClusterParams_out info);

    CORBA::Boolean
    gridStorageElemUpdate(g2mplsTypes::nodeId siteId, g2mplsTypes::gridSubNodeId id,
                          const g2mplsTypes::gridSEParams& info);

    CORBA::Boolean
    gridStorageElemGet(g2mplsTypes::nodeId siteId, g2mplsTypes::gridSubNodeId id,
                       g2mplsTypes::gridSEParams_out info);

    CORBA::Boolean
    tnaIdAdd(const g2mplsTypes::tnaIdent& ident);

    CORBA::Boolean
    tnaIdDel(const g2mplsTypes::tnaIdent& ident);

    g2mplsTypes::tnaIdentSeq *
    tnaIdsGetAllFromNode(const g2mplsTypes::nodeId node,
                         CORBA::Boolean isDomain);

    CORBA::Boolean
    linkAdd(const g2mplsTypes::teLinkIdent& ident);

    CORBA::Boolean
    linkDel(const g2mplsTypes::teLinkIdent& ident);

    g2mplsTypes::teLinkIdentSeq*
    teLinkGetAllFromNode(const g2mplsTypes::nodeIdent& ident);

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
    teLinkGetSrlgs(const g2mplsTypes::teLinkIdent& ident, g2mplsTypes::srlgSeq_out srlgs);

    CORBA::Boolean
    teLinkAppendCalendar(const g2mplsTypes::teLinkIdent& ident, const g2mplsTypes::teLinkCalendarSeq& cal);

    CORBA::Boolean
    teLinkGetCalendar(const g2mplsTypes::teLinkIdent& ident, g2mplsTypes::teLinkCalendarSeq_out cal);

    CORBA::Boolean
    teLinkAppendIsc(const g2mplsTypes::teLinkIdent& ident, const g2mplsTypes::iscSeq& iscs);

    CORBA::Boolean
    teLinkGetIsc(const g2mplsTypes::teLinkIdent& ident, g2mplsTypes::iscSeq_out iscs);
};

#endif // TOPOLOGY_UNI_ON
#endif // HAVE_OMNIORB

#ifdef HAVE_OMNIORB

#ifdef TOPOLOGY_UNI_ON
CORBA::Boolean
TOPOLOGY_i::nodeAdd(const g2mplsTypes::nodeIdent& id)
{
  if(IS_DEBUG_GRID_NODE(CORBA))
    zlog_debug("[DBG] CORBA: Received NODE_ADD message from GUNIGW");

  STACK_LOCK();

  struct grid_node      *gn;
  struct interface      *ifp;
  struct ospf_interface *oi;

  if ((ifp = uni_interface_lookup()) == NULL)
  {
    STACK_UNLOCK();
    zlog_warn ("[WRN] CORBA: There is no UNI interface, can't add grid node.");
    throw TOPOLOGY::InternalProblems("nodeAdd");
  }

  if ((oi = lookup_oi_by_ifp(ifp)) == NULL)
  {
    STACK_UNLOCK();
    zlog_warn ("[WRN] CORBA: Can't find ospf interface.");
    throw TOPOLOGY::InternalProblems("nodeAdd");
  }

  if ((gn = lookup_grid_node_by_site_id (id.id))!= NULL)
  {
    STACK_UNLOCK();
    zlog_warn("[WRN] CORBA: Exception NodeAlreadyExists (nodeAdd)");
    g2mplsTypes::nodeIdent_var tmp;
    tmp->id   = id.id;
    tmp->typee = g2mplsTypes::NODETYPE_GRID;
    throw TOPOLOGY::NodeAlreadyExists(tmp, "nodeAdd");
  }

  if ((gn = static_cast<struct grid_node*>(XMALLOC (MTYPE_OSPF_GRID_NODE, sizeof (struct grid_node)))) == NULL)
  {
    STACK_UNLOCK();
    zlog_warn("[WRN] CORBA: Exception InternalProblems: XMALLOC: %s", safe_strerror (errno));
    throw TOPOLOGY::InternalProblems("nodeAdd");
  }
  memset (gn, 0, sizeof (struct grid_node));

  gn->ifp = ifp;
  gn->area = oi->area;

  if (initialize_grid_node_params (gn) != 0)
  {
    STACK_UNLOCK();
    zlog_warn("[WRN] CORBA: Exception InternalProblems: initialize_grid_node_params failed");
    throw TOPOLOGY::InternalProblems("nodeAdd");
  }

  try {

    set_grid_tlv_GridSite_ID(gn->gn_site,(uint32_t) id.id);
    listnode_add (OspfGRID.iflist, gn);

  } catch (...) {
    STACK_UNLOCK();
    zlog_warn("[WRN] CORBA: Exception InternalProblems (nodeAdd)");
    throw TOPOLOGY::InternalProblems("nodeAdd");
  }

  if(IS_DEBUG_GRID_NODE(CORBA_ALL))
    zlog_debug("[DBG] CORBA: Done NODE_ADD");

  if (gn->area != NULL)
  {
    if (gn->gn_site->base.flags & GRIDFLG_GRID_LSA_ENGAGED)
    {
      ospf_grid_site_lsa_schedule (gn->gn_site, GRID_REFRESH_THIS_LSA);
      if(IS_DEBUG_GRID_NODE(CORBA_ALL))
        zlog_debug("[DBG] CORBA: ospf_grid_site_lsa_schedule (gn->gn_site, GRID_REFRESH_THIS_LSA)");
    }
    else
    {
      ospf_grid_site_lsa_schedule (gn->gn_site, GRID_REORIGINATE_PER_AREA);
      if(IS_DEBUG_GRID_NODE(CORBA_ALL))
        zlog_debug("[DBG] CORBA: ospf_grid_site_lsa_schedule (gn->gn_site, GRID_REORIGINATE_PER_AREA)");
    }
  }

  STACK_UNLOCK();

  return true;
}

CORBA::Boolean
TOPOLOGY_i::nodeDel(const g2mplsTypes::nodeIdent& id)
{
  if(IS_DEBUG_GRID_NODE(CORBA))
    zlog_debug("[DBG] CORBA: Received NODE_DEL message from GUNIGW");

  STACK_LOCK();

  struct grid_node *gn;

  gn = lookup_grid_node_by_site_id(id.id);
  if (gn == NULL)
  {
    STACK_UNLOCK();
    zlog_warn("[WRN] CORBA: Exception CannotFetchNode (nodeDel)");
    throw TOPOLOGY::CannotFetchNode(id,"nodeDel");
  }

  if (listcount(gn->list_of_grid_node_service) > 0)
  {
    STACK_UNLOCK();
    zlog_warn("[WRN] CORBA: Exception InternalProblems (nodeDel)");
    throw TOPOLOGY::InternalProblems("Cannot remove node (grid services list in not empty)");
  }

  if (listcount(gn->list_of_grid_node_computing) > 0)
  {
    STACK_UNLOCK();
    zlog_warn("[WRN] CORBA: Exception InternalProblems (nodeDel)");
    throw TOPOLOGY::InternalProblems("Cannot remove node (grid computing elements list in not empty)");
  }

  if (listcount(gn->list_of_grid_node_subcluster) > 0)
  {
    STACK_UNLOCK();
    zlog_warn("[WRN] CORBA: Exception InternalProblems (nodeDel)");
    throw TOPOLOGY::InternalProblems("Cannot remove node (grid subclusters list in not empty)");
  }

  if (listcount(gn->list_of_grid_node_storage) > 0)
  {
    STACK_UNLOCK();
    zlog_warn("[WRN] CORBA: Exception InternalProblems (nodeDel)");
    throw TOPOLOGY::InternalProblems("Cannot remove node (grid storage elements list in not empty)");
  }

  try {

    grid_node_delete_node(gn);

  } catch (...) {
    STACK_UNLOCK();
    zlog_warn("[WRN] CORBA: Exception InternalProblems (nodeDel)");
    throw TOPOLOGY::InternalProblems("nodeDel");
  }

  STACK_UNLOCK();

  return true;
}

g2mplsTypes::nodeIdentSeq*
TOPOLOGY_i::nodeGetAll()
{
  if(IS_DEBUG_GRID_NODE(CORBA_ALL))
    zlog_debug("[DBG] CORBA: Received NODE_GET_ALL message from GUNIGW");

  STACK_LOCK();
  // XXX add code here

  g2mplsTypes::nodeIdentSeq* result = new g2mplsTypes::nodeIdentSeq();

  STACK_UNLOCK();
  return result;
}

CORBA::Boolean
TOPOLOGY_i::netNodeUpdate(g2mplsTypes::nodeId id,
			  const g2mplsTypes::netNodeParams& info)
{
  STACK_LOCK();

  throw TOPOLOGY::InvocationNotAllowed("netNodeUpdate");

  STACK_UNLOCK();

  return true;
}

CORBA::Boolean
TOPOLOGY_i::netNodeGet(g2mplsTypes::nodeId id,
		       g2mplsTypes::netNodeParams_out info)
{
  STACK_LOCK();

  throw TOPOLOGY::InvocationNotAllowed("netNodeGet");

  STACK_UNLOCK();

  return true;
}

CORBA::Boolean
TOPOLOGY_i::gridSiteUpdate(g2mplsTypes::nodeId id,
			   const g2mplsTypes::gridSiteParams& info)
{
  if(IS_DEBUG_GRID_NODE(CORBA))
  {
    zlog_debug("[DBG] CORBA: Received GRID_SITE_UPDATE message from GUNIGW");
    zlog_debug("[DBG]        Site id: %u", (uint32_t) id);
  }

  STACK_LOCK();

  struct grid_node *gn = lookup_grid_node_by_site_id(id);
  if (gn == NULL)
  {
    STACK_UNLOCK();
    zlog_warn("[WRN] CORBA: Exception CannotFetchNode (gridSiteUpdate)");
    g2mplsTypes::nodeIdent_var tmp;
    tmp->id   = id;
    tmp->typee = g2mplsTypes::NODETYPE_GRID;
    throw TOPOLOGY::CannotFetchNode(tmp, "gridSiteUpdate");
  }

  try {

    set_grid_tlv_GridSite_Name(gn->gn_site, (char *) (CORBA::String_var) info.name);

    uint8_t latitude[5];
    latitude[0] = info.location.latitute & 0xff;
    latitude[1] = (info.location.latitute >> 8) & 0xff;
    latitude[2] = (info.location.latitute >> 16) & 0xff;
    latitude[3] = (info.location.latitute >> 24) & 0xff;
    latitude[4] = (info.location.latitute >> 32) & 0x3;
    latitude[4] |= ((info.location.latResolution & 0x3f) << 2);
    set_grid_tlv_GridSite_Latitude(gn->gn_site, latitude);

    uint8_t longitude[5];
    longitude[0] = info.location.longitude & 0xff;
    longitude[1] = (info.location.longitude >> 8) & 0xff;
    longitude[2] = (info.location.longitude >> 16) & 0xff;
    longitude[3] = (info.location.longitude >> 24) & 0xff;
    longitude[4] = (info.location.longitude >> 32) & 0x3;
    longitude[4] |= ((info.location.lonResolution & 0x3f) << 2);
    set_grid_tlv_GridSite_Longitude(gn->gn_site, longitude);

    struct in_addr PeId;
    PeId.s_addr = htonl(info.peRouterId);
    set_grid_tlv_GridSite_PE_Router_ID(gn->gn_site, PeId);

  } catch (...) {
    STACK_UNLOCK();
    zlog_warn("[WRN] CORBA: Exception InternalProblems (gridSiteUpdate)");
    throw TOPOLOGY::InternalProblems("gridSiteUpdate");
  }

  if(IS_DEBUG_GRID_NODE(CORBA_ALL))
    zlog_debug("[DBG] CORBA: Done GRID_SITE_UPDATE");

  if (gn->area != NULL)
  {
    if (gn->gn_site->base.flags & GRIDFLG_GRID_LSA_ENGAGED)
    {
      ospf_grid_site_lsa_schedule (gn->gn_site, GRID_REFRESH_THIS_LSA);
      if(IS_DEBUG_GRID_NODE(CORBA_ALL))
        zlog_debug("[DBG] CORBA: ospf_grid_site_lsa_schedule (gn->gn_site, GRID_REFRESH_THIS_LSA)");
    }
    else
    {
      ospf_grid_site_lsa_schedule (gn->gn_site, GRID_REORIGINATE_PER_AREA);
      if(IS_DEBUG_GRID_NODE(CORBA_ALL))
        zlog_debug("[DBG] CORBA: ospf_grid_site_lsa_schedule (gn->gn_site, GRID_REORIGINATE_PER_AREA)");
    }
  }

  STACK_UNLOCK();

  return true;
}

static bool
get_grid_site_info(struct grid_node_site *gn_site, g2mplsTypes::g2mplsTypes::gridSiteParams_out& info)
{
  int i = 0;
  struct grid_tlv_GridSite_Name *siteName = &gn_site->gridSite.name;
  if (ntohs(siteName->header.length) > 0)
  {
    char* name = new char[listcount(&siteName->name)];
    struct zlistnode * node; void *data;
    for (ALL_LIST_ELEMENTS_RO(&siteName->name, node, data)) {
      name[i] = *((char *) data);
      i++;
    }
    info->name = (const char *) name;
    delete name;
  }

  struct grid_tlv_GridSite_Latitude *latitude = &gn_site->gridSite.latitude;
  if (ntohs(latitude->header.length) > 0)
  {
    uint8_t res = latitude->latitude[0] >> 2;
    res &= 0x3f;
    info->location.latResolution = res;
    u_int64_t value = latitude->latitude[0]; value <<= 8; value &= 0xff00;
    value |= latitude->latitude[1]; value <<= 8; value &= 0xffff00;
    value |= latitude->latitude[2]; value <<= 8; value &= 0xffffff00;
    value |= latitude->latitude[3]; value <<= 8; value &= 0xffffff00;
    value |= latitude->latitude[4];
    u_int64_t temp = 0;
    temp = value & 0xffffffff;
    info->location.latitute = temp;
  }

  struct grid_tlv_GridSite_Longitude *longitude = &gn_site->gridSite.longitude;
  if (ntohs(longitude->header.length) > 0)
  {
    uint8_t res = longitude->longitude[0] >> 2;
    res &= 0x3f;
    info->location.lonResolution = res;
    u_int64_t value = longitude->longitude[0]; value <<= 8; value &= 0xff00;
    value |= longitude->longitude[1]; value <<= 8; value &= 0xffff00;
    value |= longitude->longitude[2]; value <<= 8; value &= 0xffffff00;
    value |= longitude->longitude[3]; value <<= 8; value &= 0xffffff00;
    value |= longitude->longitude[4];
    u_int64_t temp = 0;
    temp = value & 0xffffffff;

    info->location.longitude = temp;
  }

  struct grid_tlv_GridSite_PE_Router_ID *peRouter = &gn_site->gridSite.peRouter_id;
  if(ntohs(peRouter->header.length) > 0)
  {
    info->peRouterId = ntohl(peRouter->routerID.s_addr);
  }

  return true;
}

static bool
get_grid_subnodes_info(struct grid_node *gn, g2mplsTypes::gridSubNodes_out& snodes)
{
  struct zlistnode * node;
  void *data;

  g2mplsTypes::gridSubNodeIdentSeq * tmp;
  g2mplsTypes::gridSubNodeIdentSeq_var seqService;
  {
    tmp = new g2mplsTypes::gridSubNodeIdentSeq(listcount(gn->list_of_grid_node_service));
    if (!tmp) {
      zlog_debug("[ERR] CORBA: get_grid_subnodes_info: tmp == NULL");
    }
    seqService = tmp;
  }
  seqService->length(listcount(gn->list_of_grid_node_service));

  g2mplsTypes::gridSubNodeIdentSeq_var seqCompElem;
  {
    tmp = new g2mplsTypes::gridSubNodeIdentSeq(listcount(gn->list_of_grid_node_computing));
    if (!tmp) {
      zlog_debug("[ERR] CORBA: get_grid_subnodes_info: tmp == NULL");
    }
    seqCompElem = tmp;
  }
  seqCompElem->length(listcount(gn->list_of_grid_node_computing));

  g2mplsTypes::gridSubNodeIdentSeq_var seqSubCluster;
  {
    tmp = new g2mplsTypes::gridSubNodeIdentSeq(listcount(gn->list_of_grid_node_subcluster));
    if (!tmp) {
      zlog_debug("[ERR] CORBA: get_grid_subnodes_info: tmp == NULL");
    }
    seqSubCluster = tmp;
  }
  seqSubCluster->length(listcount(gn->list_of_grid_node_subcluster));

  g2mplsTypes::gridSubNodeIdentSeq_var seqStorage;
  {
    tmp = new g2mplsTypes::gridSubNodeIdentSeq(listcount(gn->list_of_grid_node_storage));
    if (!tmp) {
      zlog_debug("[ERR] CORBA: get_grid_subnodes_info: tmp == NULL");
    }
    seqStorage = tmp;
  }
  seqStorage->length(listcount(gn->list_of_grid_node_storage));

  int i = 0;
  struct grid_node_service *gn_service;
  for (ALL_LIST_ELEMENTS_RO(gn->list_of_grid_node_service, node, data)) {
    gn_service = (struct grid_node_service *) data;
    assert(gn_service != 0);
    g2mplsTypes::gridSubNodeIdent subnodeService;
    subnodeService.id = ntohl(gn_service->gridService.id.id);
    subnodeService.typee = g2mplsTypes::GRIDSUBNODETYPE_SERVICE;
    seqService[i] = subnodeService;
    i++;
  }

  i = 0;
  struct grid_node_computing *gn_computing;
  for (ALL_LIST_ELEMENTS_RO(gn->list_of_grid_node_computing, node, data)) {
    gn_computing = (struct grid_node_computing *) data;
    assert(gn_computing != 0);
    g2mplsTypes::gridSubNodeIdent subnodeCompElem;
    subnodeCompElem.id = ntohl(gn_computing->gridCompElement.id.id);
    subnodeCompElem.typee = g2mplsTypes::GRIDSUBNODETYPE_COMPUTINGELEMENT;
    seqCompElem[i] = subnodeCompElem;
    i++;
  }

  i = 0;
  struct grid_node_subcluster *gn_subcluster;
  for (ALL_LIST_ELEMENTS_RO(gn->list_of_grid_node_subcluster, node, data)) {
    gn_subcluster = (struct grid_node_subcluster *) data;
    assert(gn_subcluster != 0);
    g2mplsTypes::gridSubNodeIdent subnodeSubCluster;
    subnodeSubCluster.id = ntohl(gn_subcluster->gridSubcluster.id.id);
    subnodeSubCluster.typee = g2mplsTypes::GRIDSUBNODETYPE_SUBCLUSTER;
    seqSubCluster[i] = subnodeSubCluster;
    i++;
  }

  i = 0;
  struct grid_node_storage *gn_storage;
  for (ALL_LIST_ELEMENTS_RO(gn->list_of_grid_node_storage, node, data)) {
    gn_storage = (struct grid_node_storage *) data;
    assert(gn_storage != 0);
    g2mplsTypes::gridSubNodeIdent subnodeStorage;
    subnodeStorage.id = ntohl(gn_storage->gridStorage.id.id);
    subnodeStorage.typee = g2mplsTypes::GRIDSUBNODETYPE_STORAGEELEMENT;
    seqStorage[i] = subnodeStorage;
    i++;
  }

  snodes->services = seqService;
  snodes->compElems = seqCompElem;
  snodes->subClusters = seqSubCluster;
  snodes->storageElems = seqStorage;
}

CORBA::Boolean
TOPOLOGY_i::gridSiteGet(g2mplsTypes::nodeId id,
			g2mplsTypes::gridSiteParams_out info,
			g2mplsTypes::gridSubNodes_out snodes)
{
  if(IS_DEBUG_GRID_NODE(CORBA_ALL))
    zlog_debug("[DBG] CORBA: Received GRID_SITE_GET message from GUNIGW");

  STACK_LOCK();

  struct grid_node *gn;
  struct grid_node_site* gn_site;

  if ((gn = lookup_grid_node_by_site_id(id)) == NULL)
  {
    STACK_UNLOCK();
    zlog_warn("[WRN] CORBA: Exception CannotFetchNode (gridSiteGet)");
    g2mplsTypes::nodeIdent_var tmp;
    tmp->id   = id;
    tmp->typee = g2mplsTypes::NODETYPE_GRID;
    throw TOPOLOGY::CannotFetchNode(tmp, "gridSiteGet");
  }

  gn_site = gn->gn_site;

  try {

    info = new g2mplsTypes::gridSiteParams();
    snodes = new g2mplsTypes::gridSubNodes();

    get_grid_site_info(gn_site, info);
    get_grid_subnodes_info(gn, snodes);

  } catch (...) {
    STACK_UNLOCK();
    zlog_warn("[WRN] CORBA: Exception InternalProblems (gridSiteGet)");
    throw TOPOLOGY::InternalProblems("gridSiteGet");
  }

  if(IS_DEBUG_GRID_NODE(CORBA_ALL))
    zlog_debug("[DBG] CORBA: Done GRID_SITE_GET");

  STACK_UNLOCK();

  return true;
}

CORBA::Boolean
TOPOLOGY_i::gridSubNodeDel(g2mplsTypes::nodeId siteId,
			   const g2mplsTypes::gridSubNodeIdent& id)
{
  if(IS_DEBUG_GRID_NODE(CORBA))
  {
    zlog_debug("[DBG] CORBA: Received GRID_SUB_NODE_DEL message from GUNIGW");
    const char* str;
    switch (id.typee)
    {
      case g2mplsTypes::GRIDSUBNODETYPE_UNKNOWN:          str = "UNKNOWN"; break;
      case g2mplsTypes::GRIDSUBNODETYPE_SERVICE:          str = "SERVICE"; break;
      case g2mplsTypes::GRIDSUBNODETYPE_COMPUTINGELEMENT: str = "COMPUTING_ELEMENT"; break;
      case g2mplsTypes::GRIDSUBNODETYPE_SUBCLUSTER:       str = "SUBCLUSTER"; break;
      case g2mplsTypes::GRIDSUBNODETYPE_STORAGEELEMENT:   str = "STORAGE_ELEMENT"; break;
    }
    zlog_debug("[DBG]        Site id: %u, SubNode type: %s, SubNode id: %u",
	       (uint32_t) siteId, str, (uint32_t) id.id);
  }

  STACK_LOCK();

  struct grid_node *gn = lookup_grid_node_by_site_id(siteId);
  if (gn == NULL)
  {
    STACK_UNLOCK();
    zlog_warn("[WRN] CORBA: Exception CannotFetchNode (gridSubNodeDel)");
    g2mplsTypes::nodeIdent_var tmp;
    tmp->id   = siteId;
    tmp->typee = g2mplsTypes::NODETYPE_GRID;
    throw (TOPOLOGY::CannotFetchNode(tmp, "gridSubNodeDel"));
  }

  struct grid_node_service*     gn_service;
  struct grid_node_computing*   gn_computing;
  struct grid_node_subcluster*  gn_subcluster;
  struct grid_node_storage*     gn_storage;

  switch (id.typee)
  {
    case g2mplsTypes::GRIDSUBNODETYPE_SERVICE:
      gn_service = lookup_grid_node_service_by_grid_node_and_sub_id(gn, id.id);
      if (gn_service == NULL)
      {
        STACK_UNLOCK();
        zlog_warn("[WRN] CORBA: Exception CannotFetchSubNode (gridSubNodeDel)");
        g2mplsTypes::nodeIdent_var tmp;
        tmp->id   = siteId;
        tmp->typee = g2mplsTypes::NODETYPE_GRID;
        throw (TOPOLOGY::CannotFetchSubNode(tmp, id, "gridSubNodeDel"));
      }
      else
      {
        try {
          delete_grid_node_service(gn, gn_service);
        } catch (...) {
          STACK_UNLOCK();
          zlog_warn("[WRN] CORBA: Exception InternalProblems (gridSubNodeDel)");
          throw TOPOLOGY::InternalProblems("gridSubNodeDel");
        }
      }
      break;
    case g2mplsTypes::GRIDSUBNODETYPE_COMPUTINGELEMENT:
      gn_computing = lookup_grid_node_computing_by_grid_node_and_sub_id(gn, id.id);
      if (gn_computing == NULL)
      {
        STACK_UNLOCK();
        zlog_warn("[WRN] CORBA: Exception CannotFetchSubNode (gridSubNodeDel)");
        g2mplsTypes::nodeIdent_var tmp;
        tmp->id   = siteId;
        tmp->typee = g2mplsTypes::NODETYPE_GRID;
        throw (TOPOLOGY::CannotFetchSubNode(tmp, id, "gridSubNodeDel"));
      }
      else
      {
        try {
          delete_grid_node_computing(gn, gn_computing);
        } catch (...) {
          STACK_UNLOCK();
          zlog_warn("[WRN] CORBA: Exception InternalProblems (gridSubNodeDel)");
          throw TOPOLOGY::InternalProblems("gridSubNodeDel");
        }
      }
      break;

    case g2mplsTypes::GRIDSUBNODETYPE_SUBCLUSTER:
      gn_subcluster = lookup_grid_node_subcluster_by_grid_node_and_sub_id (gn, id.id);
      if (gn_subcluster == NULL)
      {
        STACK_UNLOCK();
        zlog_warn("[WRN] CORBA: Exception CannotFetchSubNode (gridSubNodeDel)");
        g2mplsTypes::nodeIdent_var tmp;
        tmp->id   = siteId;
        tmp->typee = g2mplsTypes::NODETYPE_GRID;
        throw (TOPOLOGY::CannotFetchSubNode(tmp, id, "gridSubNodeDel"));
      }
      else
      {
        try {
          delete_grid_node_subcluster(gn, gn_subcluster);
        } catch (...) {
          STACK_UNLOCK();
          zlog_warn("[WRN] CORBA: Exception InternalProblems (gridSubNodeDel)");
          throw TOPOLOGY::InternalProblems("gridSubNodeDel");
        }
      }
      break;

    case g2mplsTypes::GRIDSUBNODETYPE_STORAGEELEMENT:
      gn_storage = lookup_grid_node_storage_by_grid_node_and_sub_id (gn, id.id);
      if (gn_storage == NULL)
      {
        STACK_UNLOCK();
        zlog_warn("[WRN] CORBA: Exception CannotFetchSubNode (gridSubNodeDel)");
        g2mplsTypes::nodeIdent_var tmp;
        tmp->id   = siteId;
        tmp->typee = g2mplsTypes::NODETYPE_GRID;
        throw (TOPOLOGY::CannotFetchSubNode(tmp, id, "gridSubNodeDel"));
      }
      else
      {
        try {
          delete_grid_node_storage(gn, gn_storage);
        } catch (...) {
          STACK_UNLOCK();
          zlog_warn("[WRN] CORBA: Exception InternalProblems (gridSubNodeDel)");
          throw TOPOLOGY::InternalProblems("gridSubNodeDel");
        }
      }
      break;

    default:
      STACK_UNLOCK();
      throw (TOPOLOGY::CannotFetchSubNode());
      break;
  }

  if(IS_DEBUG_GRID_NODE(CORBA_ALL))
    zlog_debug("[DBG] CORBA: Done GRID_SUB_NODE_DEL");

  STACK_UNLOCK();

  return true;
}

CORBA::Boolean
TOPOLOGY_i::gridServiceUpdate(g2mplsTypes::nodeId siteId,
			      g2mplsTypes::gridSubNodeId id,
			      const g2mplsTypes::gridServiceParams& info)
{
  STACK_LOCK();

  if(IS_DEBUG_GRID_NODE(CORBA))
  {
    zlog_debug("[DBG] CORBA: Received GRID_SERVICE_UPDATE message from GUNIGW");
    zlog_debug("[DBG]        Site id: %u, SubNode: %u",
	       (uint32_t) siteId, (uint32_t) id);
  }

  struct grid_node *gn = lookup_grid_node_by_site_id(siteId);
  if (gn == NULL)
  {
    STACK_UNLOCK();
    zlog_warn("[WRN] CORBA: Exception CannotFetchNode (gridServiceUpdate)");
    g2mplsTypes::nodeIdent_var tmp;
    tmp->id   = siteId;
    tmp->typee = g2mplsTypes::NODETYPE_GRID;
    throw (TOPOLOGY::CannotFetchNode(tmp, "gridServiceUpdate"));
  }

  struct grid_node_service *gn_service;
  try {

    gn_service = lookup_grid_node_service_by_grid_node_and_sub_id(gn, id);
    if (gn_service == NULL)
    {
      gn_service = create_new_grid_node_service(gn, id);
      listnode_add(gn->list_of_grid_node_service, gn_service);
    }

    set_grid_tlv_GridService_ParentSite_ID (gn_service, (uint32_t) siteId);

    uint16_t version = 0;
    version = (info.data.mjrRev << 12) & 0xf000;
    version |= (info.data.mnrRev << 6) & 0x0fc0;
    version |= info.data.bldFix;
    set_grid_tlv_GridService_ServiceInfo   (gn_service, (uint16_t) info.data.typee, version);

    set_grid_tlv_GridService_Status        (gn_service, (uint8_t) info.state);

    g2mplsTypes::gridHostId_var endP;
    endP = info.endPointAddr;
    g2mpls_addr_t addrEndP;
    addrEndP << endP;

    switch(addrEndP.type)
    {
      case IPv4:
        set_grid_tlv_GridService_AddressLength (gn_service, (uint8_t) 32);
        set_grid_tlv_GridService_IPv4Endpoint  (gn_service, addrEndP.value.ipv4);
        break;
      case IPv6:
        set_grid_tlv_GridService_AddressLength (gn_service, (uint8_t) 128);
        set_grid_tlv_GridService_IPv6Endpoint  (gn_service, addrEndP.value.ipv6);
        break;
      case NSAP: 
        set_grid_tlv_GridService_AddressLength (gn_service, (uint8_t) 160);
        uint32_t nsapEndp[5];
        uint32_t *value = (uint32_t *)addrEndP.value.nsap.nsap_addr8; 
        for (int i = 0;i < 5;i++)
        {
          nsapEndp[i] = *value++;
        }
        set_grid_tlv_GridService_NsapEndpoint  (gn_service, nsapEndp);
        break;
    }

  } catch (...) {
    STACK_UNLOCK();
    zlog_warn("[WRN] CORBA: Exception InternalProblems (gridServiceUpdate)");
    throw TOPOLOGY::InternalProblems("gridServiceUpdate");
  }

  if(IS_DEBUG_GRID_NODE(CORBA_ALL))
    zlog_debug("[DBG] CORBA: Done GRID_SERVICE_UPDATE");

  if (gn->area != NULL)
  {
    if (gn_service->base.flags & GRIDFLG_GRID_LSA_ENGAGED)
    {
      ospf_grid_service_lsa_schedule (gn_service, GRID_REFRESH_THIS_LSA);
      if (IS_DEBUG_GRID_NODE(CORBA_ALL))
        zlog_debug("[DBG] CORBA: ospf_grid_service_lsa_schedule (gn_service, GRID_REFRESH_THIS_LSA)");
    }
    else
    {
      ospf_grid_service_lsa_schedule (gn_service, GRID_REORIGINATE_PER_AREA);
      if (IS_DEBUG_GRID_NODE(CORBA_ALL))
        zlog_debug("[DBG] CORBA: ospf_grid_service_lsa_schedule (gn_service, GRID_REORIGINATE_PER_AREA)");
    }
  }

  STACK_UNLOCK();

  return true;
}

static bool
get_grid_service_info(struct grid_node_service *gn_service, g2mplsTypes::gridServiceParams& info)
{
  // GRID_TLV_GRIDSERVICE_SERVICEINFO   3
  if (ntohs(gn_service->gridService.serviceInfo.header.length) > 0)
  {
    info.data.typee = (g2mplsTypes::gridServiceType) ntohs(gn_service->gridService.serviceInfo.type);

    info.data.mjrRev = (ntohs(gn_service->gridService.serviceInfo.version) >> 12) & 0x000F;
    info.data.mnrRev = (ntohs(gn_service->gridService.serviceInfo.version) >> 6) & 0x003F;
    info.data.bldFix = ntohs(gn_service->gridService.serviceInfo.version) & 0x003F;
  }

  // GRID_TLV_GRIDSERVICE_STATUS        4
  if (ntohs(gn_service->gridService.status.header.length > 0))
    info.state = (g2mplsTypes::gridServiceState) gn_service->gridService.status.status;  //8 bit no ntohost conversion

  // GRID_TLV_GRIDSERVICE_ADDRESSLENGTH 5
  if (ntohs(gn_service->gridService.addressLength.header.length) > 0)
  {
    g2mpls_addr_t addr;
    g2mplsTypes::gridHostId_var host;
    uint32_t value[5];
    uint i,j;
    uint8_t *part;

    switch (gn_service->gridService.addressLength.addressLength)
    {
      case 32:    // GRID_TLV_GRIDSERVICE_IPV4ENDPOINT  6
        addr.type = IPv4;
        addr.value.ipv4 = gn_service->gridService.ipv4Endpoint.ipv4Endp;
        host << addr;
        info.endPointAddr = host;
        break;

      case 128:   // GRID_TLV_GRIDSERVICE_IPV6ENDPOINT  7
        addr.type = IPv6;
        addr.value.ipv6 = gn_service->gridService.ipv6Endpoint.ipv6Endp;
        host << addr;
        info.endPointAddr = host;
        break;

      case 160:   // GRID_TLV_GRIDSERVICE_NSAPENDPOINT  8
        addr.type = NSAP;
        for(j = 0; j < 5; j++)
          value[j] = ntohl(gn_service->gridService.nsapEndpoint.nsapEndp[4-j]);
        part = (uint8_t *) value;
        for (i = 0; i < 20; i++)
          addr.value.nsap.nsap_addr8[i] = *part++;
        host << addr;
        info.endPointAddr = host;
        break;

      default:
        break;
    }
  }
  return true;
}

CORBA::Boolean
TOPOLOGY_i::gridServiceGet(g2mplsTypes::nodeId siteId,
			   g2mplsTypes::gridSubNodeId id,
			   g2mplsTypes::gridServiceParams& info)
{
  STACK_LOCK();

  if(IS_DEBUG_GRID_NODE(CORBA_ALL))
    zlog_debug("[DBG] CORBA: Received GRID_SERVICE_GET message from GUNIGW");

  struct grid_node *gn;
  struct grid_node_service* gn_service;

  if ((gn = lookup_grid_node_by_site_id(siteId)) == NULL)
  {
    STACK_UNLOCK();
    zlog_warn("[WRN] CORBA: Exception CannotFetchNode (gridServiceGet)");
    g2mplsTypes::nodeIdent_var tmp;
    tmp->id   = siteId;
    tmp->typee = g2mplsTypes::NODETYPE_GRID;
    throw (TOPOLOGY::CannotFetchNode(tmp, "gridServiceGet"));
  }

  if ((gn_service = lookup_grid_node_service_by_grid_node_and_sub_id(gn, id)) == NULL)
  {
    STACK_UNLOCK();
    zlog_warn("[WRN] CORBA: Exception CannotFetchSubNode (gridServiceGet)");
    g2mplsTypes::nodeIdent_var n;
    n->id   = siteId;
    n->typee = g2mplsTypes::NODETYPE_GRID;
    g2mplsTypes::gridSubNodeIdent_var sn;
    sn->id = id;
    sn->typee = g2mplsTypes::GRIDSUBNODETYPE_SERVICE;
    throw (TOPOLOGY::CannotFetchSubNode(n, sn, "gridServiceGet"));
  }

  try {

    get_grid_service_info(gn_service, info);

  } catch (...) {
    STACK_UNLOCK();
    zlog_warn("[WRN] CORBA: Exception InternalProblems (gridServiceGet)");
    throw TOPOLOGY::InternalProblems("gridServiceGet");
  }

  if(IS_DEBUG_GRID_NODE(CORBA_ALL))
    zlog_debug("[DBG] CORBA: Done GRID_SERVICE_GET");

  STACK_UNLOCK();

  return true;
}

CORBA::Boolean
TOPOLOGY_i::gridCompElemUpdate(g2mplsTypes::nodeId siteId,
			       g2mplsTypes::gridSubNodeId id,
			       const g2mplsTypes::gridCEParams& info)
{
  STACK_LOCK();

  if(IS_DEBUG_GRID_NODE(CORBA))
  {
    zlog_debug("[DBG] CORBA: Received GRID_COMP_ELEM_UPDATE message from GUNIGW");
    zlog_debug("[DBG]        Site id: %u, SubNode: %u",
	       (uint32_t) siteId, (uint32_t) id);
  }

  struct grid_node *gn = lookup_grid_node_by_site_id(siteId);
  if (gn == NULL)
  {
    STACK_UNLOCK();
    zlog_warn("[WRN] CORBA: Exception CannotFetchNode (gridCompElemUpdate)");
    g2mplsTypes::nodeIdent_var tmp;
    tmp->id   = siteId;
    tmp->typee = g2mplsTypes::NODETYPE_GRID;
    throw (TOPOLOGY::CannotFetchNode(tmp, "gridCompElemUpdate"));
  }

  struct grid_node_computing *gn_computing;
  try {

    gn_computing = lookup_grid_node_computing_by_grid_node_and_sub_id(gn, id);
    if (gn_computing == NULL)
    {
      gn_computing = create_new_grid_node_computing(gn, id);
      set_grid_tlv_GridComputingElement_CeCalendar    (gn_computing, CLEAR, NULL);
      listnode_add(gn->list_of_grid_node_computing, gn_computing);
    }

    set_grid_tlv_GridComputingElement_ParentSiteID (gn_computing, (uint32_t) siteId);

    uint16_t version = 0;
    version = (info.lrmsInfo.mjrRev << 12) & 0xf000;
    version |= (info.lrmsInfo.mnrRev << 6) & 0xffc0;
    version |= info.lrmsInfo.bldFix;
    set_grid_tlv_GridComputingElement_LrmsInfo (gn_computing, info.lrmsInfo.typee, version);

    g2mplsTypes::gridHostId_var hostAddr;
    hostAddr = info.hostAddr;
    g2mpls_addr_t HostNameAddr;
    HostNameAddr << hostAddr;

    switch(HostNameAddr.type)
    {
      case IPv4:
        set_grid_tlv_GridComputingElement_AddressLength (gn_computing, 32);
        set_grid_tlv_GridComputingElement_IPv4HostName (gn_computing, HostNameAddr.value.ipv4);
        break;
      case IPv6:
        set_grid_tlv_GridComputingElement_AddressLength (gn_computing, 128);
        set_grid_tlv_GridComputingElement_IPv6HostName  (gn_computing, HostNameAddr.value.ipv6);
        break;
      case NSAP:
        set_grid_tlv_GridComputingElement_AddressLength (gn_computing, 160);
        uint32_t nsapHostN[5];
        uint32_t *value = (uint32_t *)HostNameAddr.value.nsap.nsap_addr8;
        for (int i = 0;i < 5;i++)
        {
          nsapHostN[i] = *value++;
        }
        set_grid_tlv_GridComputingElement_NsapHostName  (gn_computing, nsapHostN);
        break;
    }

    set_grid_tlv_GridComputingElement_GatekeeperPort(gn_computing, (uint32_t) info.gatekeeperPort);

    set_grid_tlv_GridComputingElement_JobManager    (gn_computing, (char *) (CORBA::String_var) info.jobManager);

    set_grid_tlv_GridComputingElement_DataDir       (gn_computing, (char *) (CORBA::String_var) info.dataDir);

    set_grid_tlv_GridComputingElement_DefaultStorageElement (gn_computing, (uint32_t) info.defaultStorageElemId);

    set_grid_tlv_GridComputingElement_JobsStates    (gn_computing, (uint16_t) info.jobsState.freeJobSlots, (uint8_t) info.jobsState.state);

    set_grid_tlv_GridComputingElement_JobsStats     (gn_computing, (uint32_t) info.jobsStats.runningJobs, (uint32_t) info.jobsStats.waitingJobs, (uint32_t) info.jobsStats.totalJobs);

    set_grid_tlv_GridComputingElement_JobsTimePerformances (gn_computing, (uint32_t) info.jobsTimePerf.estimatedResponseTime, (uint32_t)  info.jobsTimePerf.worstResponseTime);

    set_grid_tlv_GridComputingElement_JobsTimePolicy(gn_computing, (uint32_t) info.jobsTimePolicy.maxWallclockTime, (uint32_t) info.jobsTimePolicy.maxObtainableWallclockTime, (uint32_t) info.jobsTimePolicy.maxCpuTime, (uint32_t) info.jobsTimePolicy.maxObtainableCpuTime);

    uint8_t value = (uint8_t) info.jobsLoadPolicy.priority;
    value <<=1;
    value |= info.jobsLoadPolicy.preemptionFlag;
    set_grid_tlv_GridComputingElement_JobsLoadPolicy(gn_computing, (uint32_t) info.jobsLoadPolicy.maxTotalJobs, (uint32_t) info.jobsLoadPolicy.maxRunningJobs, (uint32_t) info.jobsLoadPolicy.maxWaitingJobs, (uint16_t) info.jobsLoadPolicy.assignedJobSlots, (uint16_t) info.jobsLoadPolicy.maxSlotsPerJob, value);

    set_grid_tlv_GridComputingElement_CeCalendar(gn_computing, CLEAR, NULL);
    struct ce_calendar *ce_cal;
    for (int j =0; j<info.freeJobSlotsCalendar.length(); j++) {
      ce_cal = (ce_calendar *) XMALLOC (0, sizeof(struct ce_calendar));
      ce_cal->time = htonl((uint32_t) info.freeJobSlotsCalendar[j].unixTime);
      ce_cal->freeJobSlots = htons((uint16_t) info.freeJobSlotsCalendar[j].JobSlots);
      set_grid_tlv_GridComputingElement_CeCalendar  (gn_computing, ADD, (void *) ce_cal);
    }

    set_grid_tlv_GridComputingElement_Name (gn_computing, (char *) (CORBA::String_var) info.name);

  } catch (...) {
    STACK_UNLOCK();
    zlog_warn("[WRN] CORBA: Exception InternalProblems (gridCompElemUpdate)");
    throw TOPOLOGY::InternalProblems("gridCompElemUpdate");
  }

  if(IS_DEBUG_GRID_NODE(CORBA_ALL))
    zlog_debug("[DBG] CORBA: Done GRID_COMP_ELEM_UPDATE");

  if (gn->area != NULL)
  {
    if (gn_computing->base.flags & GRIDFLG_GRID_LSA_ENGAGED)
    {
      ospf_grid_computing_lsa_schedule (gn_computing, GRID_REFRESH_THIS_LSA);
      if (IS_DEBUG_GRID_NODE(CORBA_ALL))
        zlog_debug("[DBG] CORBA: ospf_grid_computing_lsa_schedule (gn_computing, GRID_REFRESH_THIS_LSA)");
    }
    else
    {
      ospf_grid_computing_lsa_schedule (gn_computing, GRID_REORIGINATE_PER_AREA);
      if (IS_DEBUG_GRID_NODE(CORBA_ALL))
        zlog_debug("[DBG] CORBA: ospf_grid_computing_lsa_schedule (gn_computing, GRID_REORIGINATE_PER_AREA)");
    }
  }

  STACK_UNLOCK();

  return true;
}

static bool
get_grid_computing_info(struct grid_node_computing *gn_computing, g2mplsTypes::g2mplsTypes::gridCEParams_out& info)
{
  // GRID_TLV_GRIDCOMPUTINGELEMENT_LRMSINFO 3
  struct grid_tlv_GridComputingElement_LrmsInfo *lrmsInfo = &gn_computing->gridCompElement.lrmsInfo;  
  if (ntohs(lrmsInfo->header.length) > 0)
  {
    /** LRMS Type */
    info->lrmsInfo.typee  = (g2mplsTypes::gridLrmsType) ntohs(lrmsInfo->lrmsType);

    /** LRMS Version */
    uint16_t lrmsVersion = ntohs(lrmsInfo->lrmsVersion);
    info->lrmsInfo.mjrRev = (lrmsVersion >> 12) & 0x000f;
    info->lrmsInfo.mnrRev = (lrmsVersion >> 6) & 0x03f;
    info->lrmsInfo.bldFix = lrmsVersion & 0x03f;
  }

  // GRID_TLV_GRIDCOMPUTINGELEMENT_ADDRESSLENGTH 4
  struct grid_tlv_GridComputingElement_AddressLength *addressLength = &gn_computing->gridCompElement.addressLength;

  if (ntohs(addressLength->header.length) > 0)
  {
    /** Host name of the machine running this service */
    struct grid_tlv_GridComputingElement_IPv4HostName *ipv4HostName;
    struct grid_tlv_GridComputingElement_IPv6HostName *ipv6HostName;
    struct grid_tlv_GridComputingElement_NsapHostName *nsapHostName;

    g2mpls_addr_t hostAddr;
    g2mplsTypes::gridHostId_var temp_hostAddr;
    uint32_t value[5];
    uint i,j;
    uint8_t *part;

    switch (addressLength->addrLength)
    {
      case 32:  // GRID_TLV_GRIDCOMPUTINGELEMENT_IPV4HOSTNAME 5
        ipv4HostName = &gn_computing->gridCompElement.ipv4HostName;
        hostAddr.type = IPv4;
        hostAddr.value.ipv4 = ipv4HostName->ipv4HostNam;
        temp_hostAddr << hostAddr;
        info->hostAddr = temp_hostAddr; 
        break;
      case 128: // GRID_TLV_GRIDCOMPUTINGELEMENT_IPV6HOSTNAME 6
        ipv6HostName = &gn_computing->gridCompElement.ipv6HostName;
        hostAddr.type = IPv6;
        hostAddr.value.ipv6 = ipv6HostName->ipv6HostNam;
        temp_hostAddr << hostAddr;
        info->hostAddr = temp_hostAddr; 
        break;
      case 160: // GRID_TLV_GRIDCOMPUTINGELEMENT_NSAPHOSTNAME 7
        nsapHostName = &gn_computing->gridCompElement.nsapHostName;
        hostAddr.type = NSAP;
        for(j = 0; j < 5; j++)
          value[j] = ntohl(nsapHostName->nsapHostNam[4-j]);
        part = (uint8_t *) value;
        for (i = 0; i < 20; i++)
          hostAddr.value.nsap.nsap_addr8[i] = *part++;
        temp_hostAddr << hostAddr;
        info->hostAddr = temp_hostAddr;
        break;
      default:
        break;
    }
  }

  // GRID_TLV_GRIDCOMPUTINGELEMENT_GATEKEEPERPORT 8
  struct grid_tlv_GridComputingElement_GatekeeperPort *gatekeeperPort = &gn_computing->gridCompElement.gatekeeperPort;
  if (ntohs(gatekeeperPort->header.length) > 0)
  {
    info->gatekeeperPort = ntohl(gatekeeperPort->gateKPort);
  }

  // GRID_TLV_GRIDCOMPUTINGELEMENT_JOBMANAGER 9
  int i = 0; 
  struct grid_tlv_GridComputingElement_JobManager *jobManager = &gn_computing->gridCompElement.jobManager;
  if (ntohs(jobManager->header.length) > 0)
  {
    char* jobM = new char[listcount(&jobManager->jobManag)];
    struct zlistnode * node; void *data;
    for (ALL_LIST_ELEMENTS_RO(&jobManager->jobManag, node, data)) {
      jobM[i] = *((char *) data);
      i++;
    }
    info->jobManager = (const char *) jobM;
    delete jobM;
  }

  // GRID_TLV_GRIDCOMPUTINGELEMENT_DATADIR 10
  i = 0;
  struct grid_tlv_GridComputingElement_DataDir *dataDir = &gn_computing->gridCompElement.dataDir;
  if (ntohs(dataDir->header.length) > 0)
  {
    char* datD = new char[listcount(&dataDir->dataDirStr)];
    struct zlistnode * node; void *data;
    for (ALL_LIST_ELEMENTS_RO(&dataDir->dataDirStr, node, data)) {
      datD[i] = *((char *) data);
      i++;
    }
    info->dataDir = (const char *) datD;
    delete datD;
  }

  // GRID_TLV_GRIDCOMPUTINGELEMENT_DEFAULTSTORAGEELEMENT 11
  struct grid_tlv_GridComputingElement_DefaultStorageElement *defaultSe = &gn_computing->gridCompElement.defaultSe;
  if (ntohs(defaultSe->header.length) > 0)
  {
    info->defaultStorageElemId = ntohl(defaultSe->defaultSelement);
  }

  // GRID_TLV_GRIDCOMPUTINGELEMENT_JOBSSTATES 12
  struct grid_tlv_GridComputingElement_JobsStates *jobsStates = &gn_computing->gridCompElement.jobsStates;
  if (ntohs(jobsStates->header.length) > 0)
  {
    info->jobsState.freeJobSlots = ntohs(jobsStates->freeJobSlots);
    info->jobsState.state = (g2mplsTypes::gridCeSeState) jobsStates->status;
  }

  // GRID_TLV_GRIDCOMPUTINGELEMENT_JOBSSTATS 13
  struct grid_tlv_GridComputingElement_JobsStats *jobsStats = &gn_computing->gridCompElement.jobsStats;
  if (ntohs(jobsStats->header.length) > 0)
  {
    info->jobsStats.runningJobs = ntohl(jobsStats->runningJobs);
    info->jobsStats.waitingJobs = ntohl(jobsStats->waitingJobs);
    info->jobsStats.totalJobs = ntohl(jobsStats->totalJobs);
  }

  // GRID_TLV_GRIDCOMPUTINGELEMENT_JOBSTIMEPERFORMANCES 14
  struct grid_tlv_GridComputingElement_JobsTimePerformances *jobsTimePerformances = &gn_computing->gridCompElement.jobsTimePerformances;
  if (ntohs(jobsStats->header.length) > 0)
  {
    info->jobsTimePerf.estimatedResponseTime = ntohl(jobsTimePerformances->estRespTime);
    info->jobsTimePerf.worstResponseTime = ntohl(jobsTimePerformances->worstRespTime);
  }

  // GRID_TLV_GRIDCOMPUTINGELEMENT_JOBSTIMEPOLICY 15
  struct grid_tlv_GridComputingElement_JobsTimePolicy *jobsTimePolicy = &gn_computing->gridCompElement.jobsTimePolicy;
  if (ntohs(jobsTimePolicy->header.length) > 0)
  {
    info->jobsTimePolicy.maxWallclockTime           = ntohl(jobsTimePolicy->maxWcTime);
    info->jobsTimePolicy.maxObtainableWallclockTime = ntohl(jobsTimePolicy->maxObtWcTime);
    info->jobsTimePolicy.maxCpuTime                 = ntohl(jobsTimePolicy->maxCpuTime);
    info->jobsTimePolicy.maxObtainableCpuTime       = ntohl(jobsTimePolicy->maxObtCpuTime);
  }

  // GRID_TLV_GRIDCOMPUTINGELEMENT_JOBSLOADPOLICY 16
  struct grid_tlv_GridComputingElement_JobsLoadPolicy *jobsLoadPolicy = &gn_computing->gridCompElement.jobsLoadPolicy;
  if (ntohs(jobsLoadPolicy->header.length) > 0)
  {
    info->jobsLoadPolicy.priority         = (jobsLoadPolicy->priorityPreemptionFlag >> 1);
    info->jobsLoadPolicy.preemptionFlag   = (bool)(jobsLoadPolicy->priorityPreemptionFlag & 0x01);
    info->jobsLoadPolicy.maxTotalJobs     = ntohl(jobsLoadPolicy->maxTotalJobs);
    info->jobsLoadPolicy.maxRunningJobs   = ntohl(jobsLoadPolicy->maxRunJobs);
    info->jobsLoadPolicy.maxWaitingJobs   = ntohl(jobsLoadPolicy->maxWaitJobs);

    info->jobsLoadPolicy.assignedJobSlots = ntohs(jobsLoadPolicy->assignJobSlots);
    info->jobsLoadPolicy.maxSlotsPerJob  = ntohs(jobsLoadPolicy->maxSlotsPerJob);
  }

  // GRID_TLV_GRIDCOMPUTINGELEMENT_CECALENDAR 17
  struct grid_tlv_GridComputingElement_CeCalendar *ceCalendar = &gn_computing->gridCompElement.ceCalendar;
  if (ntohs(ceCalendar->header.length) > 0)
  {
    struct zlistnode * node;
    void *data;
    struct ce_calendar * elem;
    g2mplsTypes::JobSlotsCalendarSeq_var seq;
    {
      g2mplsTypes::JobSlotsCalendarSeq * tmp;
      tmp = new g2mplsTypes::JobSlotsCalendarSeq(listcount(&gn_computing->gridCompElement.ceCalendar.ceCalend));
      if (!tmp) {
        zlog_debug("[ERR] CORBA: update_grid_GridCompElem_CeCalendar: tmp == NULL");
      }
      seq = tmp;
    }
    seq->length(listcount(&gn_computing->gridCompElement.ceCalendar.ceCalend));

    int i = 0;
    for (ALL_LIST_ELEMENTS_RO(&gn_computing->gridCompElement.ceCalendar.ceCalend, node, data)) {
      elem = (struct ce_calendar *) data;
      assert(elem != 0);
      g2mplsTypes::JobSlotsCalendarEvent event;

      event.unixTime = ntohl(elem->time);
      event.JobSlots = ntohs(elem->freeJobSlots);
      seq[i] = event;
      i++;
    }
    info->freeJobSlotsCalendar = seq;
  }

  // GRID_TLV_GRIDCOMPUTINGELEMENT_NAME 18
  i = 0;
  struct grid_tlv_GridComputingElement_Name *name = &gn_computing->gridCompElement.name;
  if (ntohs(name->header.length) > 0)
  {
    char* nam = new char[listcount(&name->name)];
    struct zlistnode * node; void *data;
    for (ALL_LIST_ELEMENTS_RO(&name->name, node, data)) {
      nam[i] = *((char *) data);
      i++;
    }
    info->name = (const char *) nam;
    delete nam;
  }

  return true;
}

CORBA::Boolean
TOPOLOGY_i::gridCompElemGet(g2mplsTypes::nodeId siteId,
			    g2mplsTypes::gridSubNodeId id,
			    g2mplsTypes::gridCEParams_out info)
{
  STACK_LOCK();

  if(IS_DEBUG_GRID_NODE(CORBA_ALL))
    zlog_debug("[DBG] CORBA: Received GRID_COMP_ELEM_GET message from GUNIGW");

  struct grid_node *gn;
  struct grid_node_computing* gn_computing;

  if ((gn = lookup_grid_node_by_site_id(siteId)) == NULL)
  {
    STACK_UNLOCK();
    zlog_warn("[WRN] CORBA: Exception CannotFetchNode (gridCompElemGet)");
    g2mplsTypes::nodeIdent_var tmp;
    tmp->id   = siteId;
    tmp->typee = g2mplsTypes::NODETYPE_GRID;
    throw (TOPOLOGY::CannotFetchNode(tmp, "gridCompElemGet"));
  }

  if ((gn_computing = lookup_grid_node_computing_by_grid_node_and_sub_id(gn, id)) == NULL)
  {
    STACK_UNLOCK();
    zlog_warn("[WRN] CORBA: Exception CannotFetchSubNode (gridCompElemGet)");
    g2mplsTypes::nodeIdent_var n;
    n->id   = siteId;
    n->typee = g2mplsTypes::NODETYPE_GRID;
    g2mplsTypes::gridSubNodeIdent_var sn;
    sn->id = id;
    sn->typee = g2mplsTypes::GRIDSUBNODETYPE_SERVICE;
    throw (TOPOLOGY::CannotFetchSubNode(n, sn, "gridCompElemGet"));
  }

  try {

    info = new g2mplsTypes::gridCEParams();
    get_grid_computing_info(gn_computing, info);

  } catch (...) {
    STACK_UNLOCK();
    zlog_warn("[WRN] CORBA: Exception InternalProblems (gridCompElemGet)");
    throw TOPOLOGY::InternalProblems("gridCompElemGet");
  }

  STACK_UNLOCK();

  if(IS_DEBUG_GRID_NODE(CORBA_ALL))
    zlog_debug("[DBG] CORBA: Done GRID_COMP_ELEM_GET");

  return true;
}

void
CORBA_String_var_to_EnvSet (  struct grid_tlv_GridSubCluster_SoftwarePackage *sp, const char* envset)
{
  char *n_value;
  while (*(envset) != '\0')
  {
    n_value = (char *) XMALLOC (MTYPE_OSPF_STR_CHAR, sizeof(char));
    *(n_value) = *(envset++);
    listnode_add (&sp->environmentSetup, n_value);
  }
  return;
}

CORBA::Boolean
TOPOLOGY_i::gridSubClusterUpdate(g2mplsTypes::nodeId siteId,
				 g2mplsTypes::gridSubNodeId id,
				 const g2mplsTypes::gridSubClusterParams& info)
{
  STACK_LOCK();

  if(IS_DEBUG_GRID_NODE(CORBA))
  {
    zlog_debug("[DBG] CORBA: Received GRID_SUBCLUSTER_UPDATE message from GUNIGW");
    zlog_debug("[DBG]        Site id: %u, SubNode: %u",
	       (uint32_t) siteId, (uint32_t) id);
  }

  struct grid_node *gn = lookup_grid_node_by_site_id(siteId);
  if (gn == NULL)
  {
    STACK_UNLOCK();
    zlog_warn("[WRN] CORBA: Exception CannotFetchNode (gridSubClusterUpdate)");
    g2mplsTypes::nodeIdent_var tmp;
    tmp->id   = siteId;
    tmp->typee = g2mplsTypes::NODETYPE_GRID;
    throw (TOPOLOGY::CannotFetchNode(tmp, "gridSubClusterUpdate"));
  }

  struct grid_node_subcluster *gn_subcluster;
  try {

    gn_subcluster = lookup_grid_node_subcluster_by_grid_node_and_sub_id(gn, id);
    if (gn_subcluster == NULL)
    {
      gn_subcluster = create_new_grid_node_subcluster(gn, id);
      set_grid_tlv_GridSubCluster_SubClusterCalendar (gn_subcluster, CLEAR, NULL);
      listnode_add(gn->list_of_grid_node_subcluster, gn_subcluster);
    }

    set_grid_tlv_GridSubCluster_ParentSiteID (gn_subcluster, (uint32_t) siteId);

    set_grid_tlv_GridSubCluster_CpuInfo (gn_subcluster, (uint32_t) info.cpu.cpuCounts.physical, (uint32_t) info.cpu.cpuCounts.logical, (uint8_t) info.cpu.cpuArch);

    uint16_t version = 0;
    version = (info.os.mjrRev << 12) & 0xf000;
    version |= (info.os.mnrRev << 6) & 0x0fc0;
    version |= (info.os.bldFix & 0x3f);
    set_grid_tlv_GridSubCluster_OsInfo (gn_subcluster, (uint16_t) info.os.typee, version);

    set_grid_tlv_GridSubCluster_MemoryInfo (gn_subcluster, (uint32_t) info.memory.ramSize, (uint32_t) info.memory.virtualMemorySize);

    struct grid_tlv_GridSubCluster_SoftwarePackage *sp;
    version = 0;

    set_grid_tlv_GridSubCluster_SoftwarePackage(gn_subcluster, CLEAR , NULL);
    for (int i =0; i<info.softwarePackages.length(); i++) {
      sp = (grid_tlv_GridSubCluster_SoftwarePackage *) XMALLOC(MTYPE_OSPF_GRID_SUBCLUSTER_SOFT_PACKAGE, sizeof(struct  grid_tlv_GridSubCluster_SoftwarePackage));

      sp->softType = htons (info.softwarePackages[i].software.typee);

      version = 0;
      version = (info.softwarePackages[i].software.mjrRev << 12) & 0xf000;
      version |= (info.softwarePackages[i].software.mnrRev << 6) & 0x0fc0;
      version |= (info.softwarePackages[i].software.bldFix & 0x3f);
      sp->softVersion = htons (version);

      memset(&sp->environmentSetup, 0, sizeof (struct zlist));
      CORBA_String_var_to_EnvSet(sp, (char *) (CORBA::String_var) info.softwarePackages[i].softwareEnvironmentSetup);

      sp->header.type = htons(GRID_TLV_GRIDSUBCLUSTER_SOFTWAREPACKAGE);
      sp->header.length = htons(GRID_TLV_GRIDSUBCLUSTER_SOFTWAREPACKAGE_CONST_DATA_LENGTH + sp->environmentSetup.count);
      set_grid_tlv_GridSubCluster_SoftwarePackage (gn_subcluster, ADD, (void *) sp);
    }

    set_grid_tlv_GridSubCluster_SubClusterCalendar(gn_subcluster, CLEAR, NULL);
    struct sc_calendar *sc_cal;
    for (int i =0; i<info.subClusterCalendar.length(); i++) {
      sc_cal = (sc_calendar *) XMALLOC (0, sizeof(struct sc_calendar));
      sc_cal->time = htonl((uint32_t) info.subClusterCalendar[i].unixTime);
      sc_cal->physical_cpus = htons((uint16_t) info.subClusterCalendar[i].cpuCount.physical);
      sc_cal->logical_cpus = htons((uint16_t) info.subClusterCalendar[i].cpuCount.logical);
      set_grid_tlv_GridSubCluster_SubClusterCalendar (gn_subcluster, ADD, (void *) sc_cal);
    }

    set_grid_tlv_GridSubCluster_Name (gn_subcluster, (char *) (CORBA::String_var) info.name);

  } catch (...) {
    STACK_UNLOCK();
    zlog_warn("[WRN] CORBA: Exception InternalProblems (gridSubClusterUpdate)");
    throw TOPOLOGY::InternalProblems("gridSubClusterUpdate");
  }

  if(IS_DEBUG_GRID_NODE(CORBA_ALL))
    zlog_debug("[DBG] CORBA: Done GRID_SUBCLUSTER_UPDATE");


  if (gn->area != NULL)
  {
    if (gn_subcluster->base.flags & GRIDFLG_GRID_LSA_ENGAGED)
    {
      ospf_grid_subcluster_lsa_schedule (gn_subcluster, GRID_REFRESH_THIS_LSA);
      if (IS_DEBUG_GRID_NODE(CORBA_ALL))
        zlog_debug("[DBG] CORBA: ospf_grid_subcluster_lsa_schedule (gn_subcluster, GRID_REFRESH_THIS_LSA)");
    }
    else
    {
      ospf_grid_subcluster_lsa_schedule (gn_subcluster, GRID_REORIGINATE_PER_AREA);
      if (IS_DEBUG_GRID_NODE(CORBA_ALL))
        zlog_debug("[DBG] CORBA: ospf_grid_subcluster_lsa_schedule (gn_subcluster, GRID_REORIGINATE_PER_AREA)");
    }
  }

  STACK_UNLOCK();

  return true;
}

static bool
get_grid_subcluster_info(struct grid_tlv_GridSubCluster *gn_subcluster, g2mplsTypes::gridSubClusterParams_out info)
{
  // GRID_TLV_GRIDSUBCLUSTER_CPUINFO 3
  struct grid_tlv_GridSubCluster_CpuInfo *cpuInfo = &gn_subcluster->cpuInfo;
  if (ntohs(cpuInfo->header.length) > 0)
  {
    info->cpu.cpuCounts.physical = ntohl(cpuInfo->physicalCpus);
    info->cpu.cpuCounts.logical  = ntohl(cpuInfo->logicalCpus);
    info->cpu.cpuArch            = (g2mplsTypes::gridCpuArch) cpuInfo->cpuArch;
  }

  // GRID_TLV_GRIDSUBCLUSTER_OSINFO 4
  struct grid_tlv_GridSubCluster_OsInfo *osInfo = &gn_subcluster->osInfo;
  if (ntohs(osInfo->header.length) > 0)
  {
    info->os.mjrRev = ((ntohs(osInfo->osVersion) >> 12) & 0x0f);
    info->os.mnrRev = ((ntohs(osInfo->osVersion) >> 6) & 0x3f);
    info->os.bldFix = (ntohs(osInfo->osVersion) & 0x3f);
    info->os.typee  = (g2mplsTypes::gridOsType)(ntohs(osInfo->osType));
  }

  // GRID_TLV_GRIDSUBCLUSTER_MEMORYINFO 5
  struct grid_tlv_GridSubCluster_MemoryInfo *memoryInfo = &gn_subcluster->memoryInfo;
  if (ntohs(memoryInfo->header.length) > 0)
  {
    info->memory.ramSize           = ntohl(memoryInfo->ramSize);
    info->memory.virtualMemorySize = ntohl(memoryInfo->virtualMemorySize);
  }

  // GRID_TLV_GRIDSUBCLUSTER_SOFTWAREPACKAGE 6
  struct zlist *softwarePackage = &gn_subcluster->softwarePackage;
  int i = 0; int j = 0;
  if (softwarePackage->count > 0)
  {
    grid_tlv_GridSubCluster_SoftwarePackage *soft;
    void *data, *data2; struct zlistnode *node, *node2;
    char* envSet;
    g2mplsTypes::softwarePackageSeq_var seq;
    {
      g2mplsTypes::softwarePackageSeq * tmp;

     tmp = new g2mplsTypes::softwarePackageSeq(listcount(softwarePackage));
     if (!tmp) {
       zlog_debug("[ERR] CORBA: get_grid_subcluster_info: tmp == NULL");
     }
     seq = tmp;
    }
    seq->length(listcount(softwarePackage));

    i = 0;
    for (ALL_LIST_ELEMENTS_RO(softwarePackage, node, data)) {
      soft = (struct grid_tlv_GridSubCluster_SoftwarePackage *) data;
      assert(soft != 0);

      g2mplsTypes::gridSoftwarePackage softPack;

      softPack.software.typee  = (g2mplsTypes::gridApplicationType) ntohs (soft->softType);
      softPack.software.mjrRev = ((ntohs(soft->softVersion) >> 12) & 0x0f);
      softPack.software.mnrRev = ((ntohs(soft->softVersion) >> 6) & 0x3f);
      softPack.software.bldFix = (ntohs(soft->softVersion) & 0x3f);

      envSet = new char[listcount(&soft->environmentSetup)];
       j = 0;
       for (ALL_LIST_ELEMENTS_RO(&soft->environmentSetup, node2, data2)) {
         envSet[j] = *((char *) data2);
         j++;
       }
      softPack.softwareEnvironmentSetup = (const char *) envSet;
      delete envSet;

      seq[i] = softPack;
      i++;
    }

    info->softwarePackages = seq;
  }

  // GRID_TLV_GRIDSUBCLUSTER_SUBCLUSTERCALENDAR 7
  struct grid_tlv_GridSubCluster_SubClusterCalendar *subclusterCalendar = &gn_subcluster->subclusterCalendar;
  if (ntohs(subclusterCalendar->header.length) > 0)
  {
    struct zlistnode * node;
    void *data;
    struct sc_calendar * elem;
    int i;

    g2mplsTypes::subClusterCalendarSeq_var seq;
    {
      g2mplsTypes::subClusterCalendarSeq * tmp;

      tmp = new g2mplsTypes::subClusterCalendarSeq(listcount(&subclusterCalendar->subcluster_calendar));
      if (!tmp) {
        zlog_debug("[ERR] CORBA: get_grid_subcluster_info: tmp == NULL");
      }
      seq = tmp;
    }
    seq->length(listcount(&subclusterCalendar->subcluster_calendar));

    i = 0;
    for (ALL_LIST_ELEMENTS_RO(&subclusterCalendar->subcluster_calendar, node, data)) {
      elem = (struct sc_calendar *) data;
      assert(elem != 0);

      g2mplsTypes::subClusterCalendarEvent event;

      event.unixTime = ntohl (elem->time);
      event.cpuCount.physical = ntohs (elem->physical_cpus);
      event.cpuCount.logical = ntohs (elem->logical_cpus);
      seq[i] = event;
      i++;
    }
    info->subClusterCalendar = seq;
  }

  // GRID_TLV_GRIDSUBCLUSTER_NAME 8
  i = 0;
  struct grid_tlv_GridSubCluster_Name *name = &gn_subcluster->name;
  if (ntohs(name->header.length) > 0)
  {
    char* nam = new char[listcount(&name->name)];
    struct zlistnode * node; void *data;
    for (ALL_LIST_ELEMENTS_RO(&name->name, node, data)) {
      nam[i] = *((char *) data);
      i++;
    }
    info->name = (const char *) nam;
    delete nam;
  }

  return true;
}

CORBA::Boolean
TOPOLOGY_i::gridSubClusterGet(g2mplsTypes::nodeId siteId,
			      g2mplsTypes::gridSubNodeId id,
			      g2mplsTypes::gridSubClusterParams_out info)
{
  if(IS_DEBUG_GRID_NODE(CORBA_ALL))
    zlog_debug("[DBG] CORBA: Received GRID_SUBCLUSTER_GET message from GUNIGW");

  STACK_LOCK();
  struct grid_node *gn;
  struct grid_node_subcluster* gn_subcluster;

  if ((gn = lookup_grid_node_by_site_id(siteId)) == NULL)
  {
    STACK_UNLOCK();
    zlog_warn("[WRN] CORBA: Exception CannotFetchNode (gridSubClusterGet)");
    g2mplsTypes::nodeIdent_var tmp;
    tmp->id   = siteId;
    tmp->typee = g2mplsTypes::NODETYPE_GRID;
    throw (TOPOLOGY::CannotFetchNode(tmp, "gridSubClusterGet"));
  }

  if ((gn_subcluster = lookup_grid_node_subcluster_by_grid_node_and_sub_id(gn, id)) == NULL)
  {
    STACK_UNLOCK();
    zlog_warn("[WRN] CORBA: Exception CannotFetchSubNode (gridSubClusterGet)");
    g2mplsTypes::nodeIdent_var n;
    n->id   = siteId;
    n->typee = g2mplsTypes::NODETYPE_GRID;
    g2mplsTypes::gridSubNodeIdent_var sn;
    sn->id = id;
    sn->typee = g2mplsTypes::GRIDSUBNODETYPE_SERVICE;
    throw (TOPOLOGY::CannotFetchSubNode(n, sn, "gridSubClusterGet"));
  }

  try {

    info = new g2mplsTypes::gridSubClusterParams();
    get_grid_subcluster_info(&gn_subcluster->gridSubcluster, info);

  } catch (...) {
    STACK_UNLOCK();
    zlog_warn("[WRN] CORBA: Exception InternalProblems (gridSubClusterGet)");
    throw TOPOLOGY::InternalProblems("gridSubClusterGet");
  }

  if(IS_DEBUG_GRID_NODE(CORBA_ALL))
    zlog_debug("[DBG] CORBA: Done GRID_SUBCLUSTER_GET");

  STACK_UNLOCK();
  return true;
}

void
CORBA_String_var_to_Name (struct grid_tlv_GridStorage_StorageArea* sa, const char* name)
{
  char *n_value;
  int n = 0;
  while (*(name) != '\0')
  {
    n_value = (char *) XMALLOC (MTYPE_OSPF_STR_CHAR, sizeof(char));
    *(n_value) = *(name++);
    listnode_add (&sa->name, n_value);
    n++;
  }
  do
  {
    n_value = (char *) XMALLOC (MTYPE_OSPF_STR_CHAR, sizeof(char));
    *(n_value) = '\0';
    listnode_add (&sa->name, n_value);
    n++;
  }
  while (n % 4 != 0);
  return;
}

void
CORBA_String_var_to_Path (struct grid_tlv_GridStorage_StorageArea* sa, const char* path)
{
  char *n_value;
  int n = 0;
  while (*(path) != '\0')
  {
    n_value = (char *) XMALLOC (MTYPE_OSPF_STR_CHAR, sizeof(char));
    *(n_value) = *(path++);
    listnode_add (&sa->path, n_value);
    n++;
  }
  do
  {
    n_value = (char *) XMALLOC (MTYPE_OSPF_STR_CHAR, sizeof(char));
    *(n_value) = '\0';
    listnode_add (&sa->path, n_value);
    n++;
  }
  while (n % 4 != 0);
  return;
}

CORBA::Boolean
TOPOLOGY_i::gridStorageElemUpdate(g2mplsTypes::nodeId siteId,
				  g2mplsTypes::gridSubNodeId id,
				  const g2mplsTypes::gridSEParams& info)
{
  STACK_LOCK();

  if(IS_DEBUG_GRID_NODE(CORBA))
  {
    zlog_debug("[DBG] CORBA: Received GRID_STORAGE_ELEM_UPDATE message from GUNIGW");
    zlog_debug("[DBG]        Site id: %u, SubNode: %u",
	       (uint32_t) siteId, (uint32_t) id);
  }

  struct grid_node *gn = lookup_grid_node_by_site_id(siteId);
  if (gn == NULL)
  {
    STACK_UNLOCK();
    zlog_warn("[WRN] CORBA: Exception CannotFetchNode (gridStorageElemUpdate)");
    g2mplsTypes::nodeIdent_var tmp;
    tmp->id   = siteId;
    tmp->typee = g2mplsTypes::NODETYPE_GRID;
    throw (TOPOLOGY::CannotFetchNode(tmp, "gridStorageElemUpdate"));
  }

  struct grid_node_storage *gn_storage;
  try {

    gn_storage = lookup_grid_node_storage_by_grid_node_and_sub_id(gn, id);
    if (gn_storage == NULL)
    {
      gn_storage = create_new_grid_node_storage(gn, id);
      listnode_add(gn->list_of_grid_node_storage, gn_storage);
    }

    set_grid_tlv_GridStorage_ParentSiteID (gn_storage, (uint32_t) siteId);

    uint32_t storInfo = 0;
    storInfo = (uint32_t) (info.storageInfo.arch << 28) & 0xf0000000;
    storInfo |= (uint32_t) (info.storageInfo.state << 24) & 0xf000000;
    storInfo |= (uint32_t) (info.storageInfo.accessProtocolsMask << 12) & 0xfff000;
    storInfo |= (uint32_t) info.storageInfo.controlProtocolsMask & 0xfff;
    set_grid_tlv_GridStorage_StorageInfo  (gn_storage, storInfo);

    set_grid_tlv_GridStorage_OnlineSize   (gn_storage, (uint32_t) info.onlineSize.total, (uint32_t) info.onlineSize.used);

    set_grid_tlv_GridStorage_NearlineSize (gn_storage, (uint32_t) info.nearlineSize.total, (uint32_t) info.nearlineSize.used);

    struct grid_tlv_GridStorage_StorageArea *sa;
    char *n_value; char *name; char *path;
    int n = 0; uint8_t value;

    set_grid_tlv_GridStorage (gn_storage, CLEAR, NULL);
    for (int j =0; j<info.storageAreas.length(); j++) {
      sa = (grid_tlv_GridStorage_StorageArea *) XMALLOC(0, sizeof(struct grid_tlv_GridStorage_StorageArea));
      memset (&sa->name, 0, sizeof (struct zlist));
      memset (&sa->path, 0, sizeof (struct zlist));

      CORBA_String_var_to_Name(sa, (char *) (CORBA::String_var) info.storageAreas[j].storageAreaName);
      CORBA_String_var_to_Path(sa, (char *) (CORBA::String_var) info.storageAreas[j].storageAreaPath);

      sa->totalOnlineSize = htonl(info.storageAreas[j].storageAreaInfo.totalOnlineSize);
      sa->freeOnlineSize = htonl(info.storageAreas[j].storageAreaInfo.freeOnlineSize);
      sa->resTotalOnlineSize = htonl(info.storageAreas[j].storageAreaInfo.reservedTotalOnlineSize);
      sa->totalNearlineSize = htonl(info.storageAreas[j].storageAreaInfo.totalNearlineSize);
      sa->freeNearlineSize = htonl(info.storageAreas[j].storageAreaInfo.freeNearlineSize);
      sa->resNearlineSize = htonl(info.storageAreas[j].storageAreaInfo.reservedNearlineSize);

      value = ((uint8_t) info.storageAreas[j].storageAreaInfo.retentionPolicy << 4);
      value |= (uint8_t) info.storageAreas[j].storageAreaInfo.accessLatency;
      sa->retPolAccLat = value;
      sa->expirationMode = (uint8_t) info.storageAreas[j].storageAreaInfo.expirationMode << 4;

      sa->header.type = htons(GRID_TLV_GRIDSTORAGE_STORAGEAREA);
      sa->header.length = htons(GRID_TLV_GRIDSTORAGE_STORAGEAREA_CONST_DATA_LENGTH + sa->name.count + sa->path.count);

      set_grid_tlv_GridStorage (gn_storage, ADD, (void *) sa);
    }

    set_grid_tlv_GridStorage_SeCalendar(gn_storage, CLEAR, NULL);
    struct se_calendar *se_cal;
    for (int i =0; i<info.seCalendar.length(); i++) {
      se_cal = (se_calendar *) XMALLOC (0, sizeof(struct se_calendar));
      se_cal->time = htonl((uint32_t) info.seCalendar[i].unixTime);
      se_cal->freeOnlineSize = htonl((uint32_t) info.seCalendar[i].storageCount.freeOnlineSize);
      se_cal->freeNearlineSize = htonl((uint32_t) info.seCalendar[i].storageCount.logicalCpus);
      set_grid_tlv_GridStorage_SeCalendar (gn_storage, ADD, (void *) se_cal);
    }

    set_grid_tlv_GridStorage_Name (gn_storage, (char *) (CORBA::String_var) info.name);

  } catch (...) {
    STACK_UNLOCK();
    zlog_warn("[WRN] CORBA: Exception InternalProblems (gridStorageElemUpdate)");
    throw TOPOLOGY::InternalProblems("gridStorageElemUpdate");
  }

  if(IS_DEBUG_GRID_NODE(CORBA_ALL))
    zlog_debug("[DBG] CORBA: Done GRID_STORAGE_ELEM_UPDATE");

  if (gn->area != NULL)
  {
    if (gn_storage->base.flags & GRIDFLG_GRID_LSA_ENGAGED)
    {
      ospf_grid_storage_lsa_schedule (gn_storage, GRID_REFRESH_THIS_LSA);
      if(IS_DEBUG_GRID_NODE(CORBA_ALL))
        zlog_debug("[DBG] CORBA: ospf_grid_storage_lsa_schedule (gn_storage, GRID_REFRESH_THIS_LSA)");
    }
    else
    {
      ospf_grid_storage_lsa_schedule (gn_storage, GRID_REORIGINATE_PER_AREA);
      if(IS_DEBUG_GRID_NODE(CORBA_ALL))
        zlog_debug("[DBG] CORBA: ospf_grid_storage_lsa_schedule (gn_storage, GRID_REORIGINATE_PER_AREA)");
    }
  }
  STACK_UNLOCK();

  return true;
}

static bool
get_grid_storage_info(struct grid_node_storage *gn_storage, g2mplsTypes::gridSEParams_out info)
{
  // GRID_TLV_GRIDSTORAGE_STORAGEINFO 3
  struct grid_tlv_GridStorage_StorageInfo *storageInfo = &gn_storage->gridStorage.storageInfo;
  if (ntohs(storageInfo->header.length) > 0)
  {
    info->storageInfo.arch  = (g2mplsTypes::gridStorageArch) ((ntohl(storageInfo->storInfo) >> 28) & 0x0f);
    info->storageInfo.state = (g2mplsTypes::gridCeSeState)((ntohl(storageInfo->storInfo) >> 24) & 0x0f);
    info->storageInfo.accessProtocolsMask  = ((ntohl(storageInfo->storInfo) >> 12) & 0x3f);
    info->storageInfo.controlProtocolsMask = (ntohl(storageInfo->storInfo) & 0x3f);
  }

  // GRID_TLV_GRIDSTORAGE_ONLINESIZE 4
  struct grid_tlv_GridStorage_OnlineSize *onlineSize = &gn_storage->gridStorage.onlineSize;
  if (ntohs(onlineSize->header.length) > 0)
  {
    info->onlineSize.total = ntohl(onlineSize->totalSize);
    info->onlineSize.used  = ntohl(onlineSize->usedSize);
  }

  // GRID_TLV_GRIDSTORAGE_NEARLINESIZE 5
  struct grid_tlv_GridStorage_NearlineSize *nearlineSize = &gn_storage->gridStorage.nearlineSize;
  if (ntohs(nearlineSize->header.length) > 0)
  {
    info->nearlineSize.total = ntohl(nearlineSize->totalSize);
    info->nearlineSize.used  = ntohl(nearlineSize->usedSize);
  }

  // GRID_TLV_GRIDSTORAGE_STORAGEAREA 6
  struct zlist *storageArea = &gn_storage->gridStorage.storageArea;
  int i = 0; int j = 0;
  if (storageArea->count > 0)
  {
    grid_tlv_GridStorage_StorageArea* area;
    void *data, *data2; struct zlistnode *node, *node2;
    char* str;
    g2mplsTypes::StorageAreaSeq_var seq;
    {
      g2mplsTypes::StorageAreaSeq * tmp;

      tmp = new g2mplsTypes::StorageAreaSeq(listcount(storageArea));
      if (!tmp) {
        zlog_debug("[ERR] CORBA: get_grid_storage_info: tmp == NULL");
      }
      seq = tmp;
    }
    seq->length(listcount(storageArea));

    i = 0;
    for (ALL_LIST_ELEMENTS_RO(storageArea, node, data)) {
      area = (struct grid_tlv_GridStorage_StorageArea *) data;
      assert(area != 0);

      g2mplsTypes::gridStorageArea storArea;

      storArea.storageAreaInfo.totalOnlineSize = ntohl(area->totalOnlineSize);
      storArea.storageAreaInfo.freeOnlineSize = ntohl(area->freeOnlineSize);
      storArea.storageAreaInfo.reservedTotalOnlineSize = ntohl(area->resTotalOnlineSize);
      storArea.storageAreaInfo.totalNearlineSize = ntohl(area->totalNearlineSize);
      storArea.storageAreaInfo.freeNearlineSize = ntohl(area->freeNearlineSize);
      storArea.storageAreaInfo.reservedNearlineSize = ntohl(area->resNearlineSize);
      storArea.storageAreaInfo.retentionPolicy = (g2mplsTypes::gridStorageRetentionPolicy) ((area->retPolAccLat >> 4) & 0xf);
      storArea.storageAreaInfo.accessLatency = (g2mplsTypes::gridStorageAccessLatency) (area->retPolAccLat & 0xf);
      storArea.storageAreaInfo.expirationMode = (g2mplsTypes::gridStorageExpirationMode) ((area->expirationMode >> 4) & 0xf);

      str = new char[listcount(&area->name)];
      j = 0;
      for (ALL_LIST_ELEMENTS_RO(&area->name, node2, data2)) {
        str[j] = *((char *) data2);
        j++;
      }
      storArea.storageAreaName = (const char *) str;
      delete str;

      str = new char[listcount(&area->path)];
      j = 0;
      for (ALL_LIST_ELEMENTS_RO(&area->path, node2, data2)) {
        str[j] = *((char *) data2);
        j++;
      }
      storArea.storageAreaPath = (const char *) str;
      delete str;

      seq[i] = storArea;
      i++;
    }
    info->storageAreas = seq;
  }

  // GRID_TLV_GRIDSTORAGE_SECALENDAR 7
  struct grid_tlv_GridStorage_SeCalendar *seCalendar = &gn_storage->gridStorage.seCalendar;
  if (ntohs(seCalendar->header.length) > 0)
  {
    struct zlistnode * node;
    void *data;
    struct se_calendar * elem;
    int i;
    g2mplsTypes::seCalendarSeq_var seq;
    {
      g2mplsTypes::seCalendarSeq * tmp;

      tmp = new g2mplsTypes::seCalendarSeq(listcount(&seCalendar->seCalendar));
      seq = tmp;
    }
    seq->length(listcount(&seCalendar->seCalendar));
    i = 0;
    for (ALL_LIST_ELEMENTS_RO(&seCalendar->seCalendar, node, data)) 
    {
      elem = (struct se_calendar *) data;
      assert(elem != 0);

      g2mplsTypes::seCalendarEvent eventCal;

      eventCal.unixTime = ntohl(elem->time);
      eventCal.storageCount.freeOnlineSize = ntohl(elem->freeOnlineSize);
      eventCal.storageCount.logicalCpus = ntohl(elem->freeNearlineSize);        //wrong field name ??
      seq[i] = eventCal;

      i++;
    }
    info->seCalendar = seq;
  }

  // GRID_TLV_GRIDSTORAGE_NAME 8
  i = 0;
  struct grid_tlv_GridStorage_Name *name = &gn_storage->gridStorage.name;
  if (ntohs(name->header.length) > 0)
  {
    char* nam = new char[listcount(&name->name)];
    struct zlistnode * node; void *data;
    for (ALL_LIST_ELEMENTS_RO(&name->name, node, data)) {
      nam[i] = *((char *) data);
      i++;
    }
    info->name = (const char *) nam;
    delete nam;
  }

  return true;
}

CORBA::Boolean
TOPOLOGY_i::gridStorageElemGet(g2mplsTypes::nodeId siteId,
			       g2mplsTypes::gridSubNodeId id,
			       g2mplsTypes::gridSEParams_out info)
{
  STACK_LOCK();

  if(IS_DEBUG_GRID_NODE(CORBA_ALL))
    zlog_debug("[DBG] CORBA: Received GRID_STORAGE_ELEM_GET message from GUNIGW");

  struct grid_node *gn;
  struct grid_node_storage* gn_storage;

  if ((gn = lookup_grid_node_by_site_id(siteId)) == NULL)
  {
    STACK_UNLOCK();
    zlog_warn("[WRN] CORBA: Exception CannotFetchNode (gridStorageElemGet)");
    g2mplsTypes::nodeIdent_var tmp;
    tmp->id   = siteId;
    tmp->typee = g2mplsTypes::NODETYPE_GRID;
    throw (TOPOLOGY::CannotFetchNode(tmp, "gridStorageElemGet"));
  }

  if ((gn_storage = lookup_grid_node_storage_by_grid_node_and_sub_id(gn, id)) == NULL)
  {
    STACK_UNLOCK();
    zlog_warn("[WRN] CORBA: Exception CannotFetchSubNode (gridStorageElemGet)");
    g2mplsTypes::nodeIdent_var n;
    n->id   = siteId;
    n->typee = g2mplsTypes::NODETYPE_GRID;
    g2mplsTypes::gridSubNodeIdent_var sn;
    sn->id = id;
    sn->typee = g2mplsTypes::GRIDSUBNODETYPE_SERVICE;
    throw (TOPOLOGY::CannotFetchSubNode(n, sn, "gridStorageElemGet"));
  }

  try {

    info = new g2mplsTypes::gridSEParams();
    get_grid_storage_info(gn_storage, info);

  } catch (...) {
    STACK_UNLOCK();
    zlog_warn("[WRN] CORBA: Exception InternalProblems (gridStorageElemGet)");
    throw TOPOLOGY::InternalProblems("gridStorageElemGet");
  }

  if(IS_DEBUG_GRID_NODE(CORBA_ALL))
    zlog_debug("[DBG] CORBA: Done GRID_STORAGE_ELEM_GET");

  STACK_UNLOCK();

  return true;
}

CORBA::Boolean
TOPOLOGY_i::tnaIdAdd(const g2mplsTypes::tnaIdent& ident)
{
  STACK_LOCK();

  throw TOPOLOGY::InvocationNotAllowed("tnaIdAdd");

  STACK_UNLOCK();

  return true;
}

CORBA::Boolean
TOPOLOGY_i::tnaIdDel(const g2mplsTypes::tnaIdent& ident)
{
  STACK_LOCK();

  throw TOPOLOGY::InvocationNotAllowed("tnaIdDel");

  STACK_UNLOCK();

  return true;
}

g2mplsTypes::tnaIdentSeq *
TOPOLOGY_i::tnaIdsGetAllFromNode(const g2mplsTypes::nodeId node,
				 CORBA::Boolean isDomain)
{
  STACK_LOCK();
  g2mplsTypes::tnaIdentSeq* result = new g2mplsTypes::tnaIdentSeq();

  throw TOPOLOGY::InvocationNotAllowed("tnaIdsGetAllFromNode");

  STACK_UNLOCK();

  return result;
}

CORBA::Boolean
TOPOLOGY_i::linkAdd(const g2mplsTypes::teLinkIdent& ident)
{
  STACK_LOCK();

  throw TOPOLOGY::InvocationNotAllowed("linkAdd");

  STACK_UNLOCK();

  return true;
}

CORBA::Boolean
TOPOLOGY_i::linkDel(const g2mplsTypes::teLinkIdent& ident)
{
  STACK_LOCK();

  throw TOPOLOGY::InvocationNotAllowed("linkDel");

  STACK_UNLOCK();

  return true;
}

g2mplsTypes::teLinkIdentSeq*
TOPOLOGY_i::teLinkGetAllFromNode(const g2mplsTypes::nodeIdent& ident)
{
  STACK_LOCK();
  g2mplsTypes::teLinkIdentSeq* result = new g2mplsTypes::teLinkIdentSeq();

  throw TOPOLOGY::InvocationNotAllowed("teLinkGetAllFromNode");

  STACK_UNLOCK();

  return result;
}

CORBA::Boolean
TOPOLOGY_i::teLinkUpdateCom(const g2mplsTypes::teLinkIdent& ident,
			    const g2mplsTypes::teLinkComParams& info)
{
  STACK_LOCK();

  throw TOPOLOGY::InvocationNotAllowed("teLinkUpdateCom");

  STACK_UNLOCK();

  return true;
}

CORBA::Boolean
TOPOLOGY_i::teLinkGetCom(const g2mplsTypes::teLinkIdent& ident,
			 g2mplsTypes::teLinkComParams& info)
{
  STACK_LOCK();

  throw TOPOLOGY::InvocationNotAllowed("teLinkGetCom");

  STACK_UNLOCK();

  return true;
}

CORBA::Boolean
TOPOLOGY_i::teLinkUpdateTdm(const g2mplsTypes::teLinkIdent& ident,
			    const g2mplsTypes::teLinkTdmParams& info)
{
  STACK_LOCK();

  throw TOPOLOGY::InvocationNotAllowed("teLinkUpdateTdm");

  STACK_UNLOCK();

  return true;
}

CORBA::Boolean
TOPOLOGY_i::teLinkGetTdm(const g2mplsTypes::teLinkIdent& ident,
			 g2mplsTypes::teLinkTdmParams& info)
{
  STACK_LOCK();

  throw TOPOLOGY::InvocationNotAllowed("teLinkGetTdm");

  STACK_UNLOCK();

  return true;
}

CORBA::Boolean
TOPOLOGY_i::teLinkUpdateLscG709(const g2mplsTypes::teLinkIdent& ident,
				const g2mplsTypes::teLinkLscG709Params&  info)
{
  STACK_LOCK();

  throw TOPOLOGY::InvocationNotAllowed("teLinkUpdateLscG709");

  STACK_UNLOCK();

  return true;
}

CORBA::Boolean
TOPOLOGY_i::teLinkGetLscG709(const g2mplsTypes::teLinkIdent& ident,
			     g2mplsTypes::teLinkLscG709Params_out info)
{
  STACK_LOCK();

  throw TOPOLOGY::InvocationNotAllowed("teLinkGetLscG709");

  STACK_UNLOCK();

  return true;
}

CORBA::Boolean
TOPOLOGY_i::teLinkUpdateLscWdm(const g2mplsTypes::teLinkIdent& ident,
			       const g2mplsTypes::teLinkLscWdmParams&  info)
{
  STACK_LOCK();

  throw TOPOLOGY::InvocationNotAllowed("teLinkUpdateLscWdm");

  STACK_UNLOCK();

  return true;
}

CORBA::Boolean
TOPOLOGY_i::teLinkGetLscWdm(const g2mplsTypes::teLinkIdent& ident,
			    g2mplsTypes::teLinkLscWdmParams_out info)
{
  STACK_LOCK();
  throw TOPOLOGY::InvocationNotAllowed("teLinkGetLscWdm");

  STACK_UNLOCK();

  return true;
}

CORBA::Boolean
TOPOLOGY_i::teLinkUpdateStates(const g2mplsTypes::teLinkIdent& ident,
			       const g2mplsTypes::statesBundle& states)
{
  STACK_LOCK();

  throw TOPOLOGY::InvocationNotAllowed("teLinkUpdateStates");

  STACK_UNLOCK();

  return true;
}

CORBA::Boolean
TOPOLOGY_i::teLinkGetStates(const g2mplsTypes::teLinkIdent& ident,
			    g2mplsTypes::statesBundle& states)
{
  STACK_LOCK();

  throw TOPOLOGY::InvocationNotAllowed("teLinkGetStates");

  STACK_UNLOCK();

  return true;
}

CORBA::Boolean
TOPOLOGY_i::teLinkUpdateGenBw(const g2mplsTypes::teLinkIdent& ident,
			      const g2mplsTypes::availBwPerPrio bw)
{
  STACK_LOCK();

  throw TOPOLOGY::InvocationNotAllowed("teLinkUpdateGenBw");

  STACK_UNLOCK();

  return true;
}

CORBA::Boolean
TOPOLOGY_i::teLinkGetGenBw(const g2mplsTypes::teLinkIdent& ident,
			   g2mplsTypes::availBwPerPrio bw)
{
  STACK_LOCK();

  throw TOPOLOGY::InvocationNotAllowed("teLinkGetGenBw");

  STACK_UNLOCK();

  return true;
}

CORBA::Boolean
TOPOLOGY_i::teLinkUpdateTdmBw(const g2mplsTypes::teLinkIdent& ident,
			      const g2mplsTypes::freeCTPSeq& freeBw)
{
  STACK_LOCK();

  throw TOPOLOGY::InvocationNotAllowed("teLinkUpdateTdmBw");

  STACK_UNLOCK();

  return true;
}

CORBA::Boolean
TOPOLOGY_i::teLinkGetTdmBw(const g2mplsTypes::teLinkIdent& ident,
			   g2mplsTypes::freeCTPSeq_out freeTS)
{
  STACK_LOCK();

  throw TOPOLOGY::InvocationNotAllowed("teLinkGetTdmBw");

  STACK_UNLOCK();

  return true;
}

CORBA::Boolean
TOPOLOGY_i::teLinkUpdateLscG709Bw(const g2mplsTypes::teLinkIdent& ident,
				  const g2mplsTypes::freeCTPSeq& freeODUk,
				  const g2mplsTypes::freeCTPSeq& freeOCh)
{
  STACK_LOCK();

  throw TOPOLOGY::InvocationNotAllowed("teLinkUpdateLscG709Bw");

  STACK_UNLOCK();

  return true;
}

CORBA::Boolean
TOPOLOGY_i::teLinkGetLscG709Bw(const g2mplsTypes::teLinkIdent& ident,
			       g2mplsTypes::freeCTPSeq_out freeODUk,
			       g2mplsTypes::freeCTPSeq_out freeOCh)
{
  STACK_LOCK();

  throw TOPOLOGY::InvocationNotAllowed("teLinkGetLscG709Bw");

  STACK_UNLOCK();

  return true;
}

CORBA::Boolean
TOPOLOGY_i::teLinkUpdateLscWdmBw(const g2mplsTypes::teLinkIdent& ident,
				 const g2mplsTypes::wdmLambdasBitmap& bm)
{
  STACK_LOCK();

  throw TOPOLOGY::InvocationNotAllowed("teLinkUpdateLscWdmBw");

  STACK_UNLOCK();

  return true;
}

CORBA::Boolean
TOPOLOGY_i::teLinkGetLscWdmBw(const g2mplsTypes::teLinkIdent& ident,
			      g2mplsTypes::wdmLambdasBitmap_out bm)
{
  STACK_LOCK();

  throw TOPOLOGY::InvocationNotAllowed("teLinkGetLscWdmBw");

  STACK_UNLOCK();

  return true;
}

CORBA::Boolean
TOPOLOGY_i::teLinkAppendSrlgs(const g2mplsTypes::teLinkIdent& ident,
			      const g2mplsTypes::srlgSeq& srlgs)
{
  STACK_LOCK();

  throw TOPOLOGY::InvocationNotAllowed("teLinkAppendSrlgs");

  STACK_UNLOCK();

  return true;
}

CORBA::Boolean
TOPOLOGY_i::teLinkGetSrlgs(const g2mplsTypes::teLinkIdent& ident,
			   g2mplsTypes::srlgSeq_out srlgs)
{
  STACK_LOCK();

  throw TOPOLOGY::InvocationNotAllowed("teLinkGetSrlgs");

  STACK_UNLOCK();

  return true;
}

CORBA::Boolean
TOPOLOGY_i::teLinkAppendCalendar(const g2mplsTypes::teLinkIdent& ident,
				 const g2mplsTypes::teLinkCalendarSeq& cal)
{
  STACK_LOCK();

  throw TOPOLOGY::InvocationNotAllowed("teLinkAppendCalendar");

  STACK_UNLOCK();

  return true;
}

CORBA::Boolean
TOPOLOGY_i::teLinkGetCalendar(const g2mplsTypes::teLinkIdent& ident,
			      g2mplsTypes::teLinkCalendarSeq_out cal)
{
  STACK_LOCK();

  throw TOPOLOGY::InvocationNotAllowed("teLinkGetCalendar");

  STACK_UNLOCK();

  return true;
}

CORBA::Boolean
TOPOLOGY_i::teLinkAppendIsc(const g2mplsTypes::teLinkIdent& ident,
			    const g2mplsTypes::iscSeq& iscs)
{
  STACK_LOCK();

  throw TOPOLOGY::InvocationNotAllowed("teLinkAppendIsc");

  STACK_UNLOCK();

  return true;
}

CORBA::Boolean
TOPOLOGY_i::teLinkGetIsc(const g2mplsTypes::teLinkIdent& ident,
			 g2mplsTypes::iscSeq_out iscs)
{
 STACK_LOCK();

  throw TOPOLOGY::InvocationNotAllowed("teLinkGetIsc");

  STACK_UNLOCK();

  return true;
}

TOPOLOGY_i*     servant      = 0;
#endif // TOPOLOGY_UNI_ON
#endif // HAVE_OMNIORB

extern "C" {

  int corba_uni_server_setup(void)
  {
#ifdef HAVE_OMNIORB
#ifdef TOPOLOGY_UNI_ON
    if (IS_DEBUG_GRID_NODE(CORBA))
      zlog_debug("[DBG] CORBA: Setting up CORBA UNI server side");

    try {
      servant = new TOPOLOGY_i();
      if (!servant) {
        throw string("Cannot create servant");
      }

      PortableServer::POA_var poa;
      poa = corba_poa();
      if (CORBA::is_nil(poa)) {
        throw string("Cannot get POA");
      }

      PortableServer::ObjectId_var servant_id;
      servant_id = poa->activate_object(servant);

      CORBA::Object_var obj;
      obj = servant->_this();
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

      if (!corba_dump_ior(CORBA_SERVANT_G2TOPOLOGY_UNI, string(sior))) {
        throw string("Cannot dump IOR");
      }

      servant->_remove_ref();

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
#endif // TOPOLOGY_UNI_ON
#endif // HAVE_OMNIORB  
    return 1;
  }

  int corba_uni_server_shutdown(void)
  {
#ifdef HAVE_OMNIORB
#ifdef TOPOLOGY_UNI_ON
    try {
      if (IS_DEBUG_GRID_NODE(CORBA))
        zlog_debug("[DBG] CORBA: Shutting down CORBA UNI server side");

      if (!corba_remove_ior(CORBA_SERVANT_G2TOPOLOGY_UNI)) {
        throw string("Cannot remove IOR");
      }
    } catch (...) {
      zlog_debug("[DBG] CORBA: Caught unknown exception");
      return 0;
    }

    return 1;
#else
    return -1;
#endif // TOPOLOGY_UNI_ON
#endif // HAVE_OMNIORB
  }

} //extern "C"
