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

#include "lib/corba.h"
#include "g2mpls_corba_utils.h"

#ifdef TOPOLOGY_CLIENTS_ON
#include "topology.hh"
#endif // PCERA_ON

#ifdef GMPLS_NXW
#include "scngw.hh"
#endif // GMPLS_NXW

#include "ospfd/ospf_corba.h"
#include "ospfd/ospf_corba_utils.h"
#include "ospfd/ospf_te.h"
#ifdef GMPLS_NXW
#include "ospfd/ospf_scngw.h"
#endif // GMPLS_NXW

#include <iostream>
#include <string>
#include <stdlib.h>

using namespace std;

#if HAVE_OMNIORB

#ifdef TOPOLOGY_CLIENTS_ON
TOPOLOGY::Info_var  g2pcera_proxy;
TOPOLOGY::Info_var  gunigw_proxy;
#endif // TOPOLOGY_CLIENTS_ON
#ifdef GMPLS_NXW
SCNGW::NetServices_var    scngw_proxy;
#endif // GMPLS_NXW

#define UPDATE_G2PCERA      1
#define UPDATE_GUNIGW       2

#define REMOVE_TNA_ADDRESS  0
#define ADD_TNA_ADDRESS     1

#define REMOVE_TE_LINK      0
#define ADD_TE_LINK         1

extern "C" {

int corba_g2pcera_client_setup()
{
#ifdef TOPOLOGY_CLIENTS_ON
  if (1)
    zlog_debug("[DBG] CORBA: Setting up G2PCERA client side");
  try {
    CORBA::ORB_var orb;
    orb = corba_orb();
    if (CORBA::is_nil(orb)) {
      zlog_err("[ERR] CORBA: Cannot get ORB");
      return 0;
    }

    string ior;
    if (!corba_fetch_ior(CORBA_SERVANT_G2MPLS_TOPOLOGY, ior)) {
      zlog_err("[ERR] CORBA: Cannot fetch IOR");
      return 0;
    }

    CORBA::Object_var obj;
    obj = orb->string_to_object(ior.c_str());
    if (CORBA::is_nil(obj)) {
      zlog_err("[ERR] CORBA: Cannot get object");
      return 0;
    }

    g2pcera_proxy = TOPOLOGY::Info::_narrow(obj);
    if (CORBA::is_nil(g2pcera_proxy)) {
      zlog_err("[ERR] CORBA: Cannot invoke on a nil object reference");
      return 0;
    }
  }
  catch (...) {
    zlog_err("[ERR] CORBA unknown exception");
    return 0;
  }
  if (1)
    zlog_debug("[DBG] CORBA: G2PCERA client side is up");
  return 1;
#else
  return -1;
#endif // TOPOLOGY_CLIENTS_ON
}

}

extern "C" {

int corba_gunigw_client_setup()
{
#ifdef TOPOLOGY_CLIENTS_ON
  if (1)
    zlog_debug("[DBG] CORBA: Setting up GUNIGW client side");
  CORBA::ORB_var orb;
  orb = corba_orb();
  if (CORBA::is_nil(orb)) {
      zlog_err("[ERR] CORBA: Cannot get ORB");
    return 0;
  }

  string ior;
  if (!corba_fetch_ior(CORBA_SERVANT_G2TOPOLOGY_UNI, ior)) {
      zlog_err("[ERR] CORBA: Cannot fetch IOR");
    return 0;
  }

  CORBA::Object_var obj;
  obj = orb->string_to_object(ior.c_str());
  if (CORBA::is_nil(obj)) {
      zlog_err("[ERR] CORBA: Cannot get object");
    return 0;
  }

  gunigw_proxy = TOPOLOGY::Info::_narrow(obj);
  if (CORBA::is_nil(gunigw_proxy)) {
      zlog_err("[ERR] CORBA: Cannot invoke on a nil object reference");
    return 0;
  }
  if (1)
    zlog_debug("[DBG] CORBA: GUNIGW client side is up");
  return 1;
#else
  return -1;
#endif // TOPOLOGY_CLIENTS_ON
}

}

#ifdef GMPLS_NXW
extern "C" {

int corba_scngw_client_setup()
{
  zlog_debug("[DBG] CORBA: Setting up SCNGW client side");

  CORBA::ORB_var orb;
  orb = corba_orb();
  if (CORBA::is_nil(orb)) {
    zlog_err("[ERR] CORBA: Cannot get ORB");
    return 0;
  }

  string ior;
  if (!corba_fetch_ior(CORBA_SERVANT_SCNGW_NETSERVICES, ior)) {
    zlog_err("[ERR] CORBA: Cannot fetch IOR");
    return 0;
  }

  CORBA::Object_var obj;
  obj = orb->string_to_object(ior.c_str());
  if (CORBA::is_nil(obj)) {
    zlog_err("[ERR] CORBA: Cannot get object");
    return 0;
  }

  scngw_proxy = SCNGW::NetServices::_narrow(obj);
  if (CORBA::is_nil(scngw_proxy)) {
    zlog_err("[ERR] CORBA: Cannot invoke on a nil object reference");
    return 0;
  }

  zlog_debug("[DBG] CORBA: SCNGW client side is up");
  return 1;

}

}
#endif

gmplsTypes::nodeIdent nodeIdent;
gmplsTypes::nodeId nodeId;
uint32_t energyConsumption;

gmplsTypes::tnaIdent emptyTnaIdent;
gmplsTypes::teLinkIdent emptyLinkIdent;

extern "C" {

#ifdef GMPLS_NXW
int scngw_registration(client_type_t cl_type)
{
	try {
		zlog_debug("Going to send registration request to SCNGW");

		bool                             res = false;
		SCNGW::NetServices::sockOptMask  inOptMask;
		SCNGW::NetServices::sockOptMask  outOptMask;
		SCNGW::NetServices::clientInfo   ospfteInfo;
		Types::uint32                    sPort;
		SCNGW::NetServices_var           scngwProxy;

		ospfteInfo.typee = (( cl_type == OSPF_INNI) ?
				   SCNGW::NetServices::OSPF_INNI :
				   ((cl_type == OSPF_UNI ) ?
				    SCNGW::NetServices::OSPF_UNI  :
				    SCNGW::NetServices::OSPF_ENNI));

		ospfteInfo.encapPackets = (PACKETS_ENCAPSULATED(cl_type) ? true : false);
		ospfteInfo.flags        = 0;

		// TO CHECK
		// fill socket option mask
		// inOptMask << reqSockOpts;
		inOptMask.SCNGW::NetServices::sockOptMask::SCNGW_SO_LINGER    = false;
		inOptMask.SCNGW::NetServices::sockOptMask::SCNGW_SO_REUSEADDR = false;
		inOptMask.SCNGW::NetServices::sockOptMask::SCNGW_SO_SNDTIMEO  = false;
		inOptMask.SCNGW::NetServices::sockOptMask::SCNGW_SO_RCVTIMEO  = false;
		inOptMask.SCNGW::NetServices::sockOptMask::SCNGW_SO_SNDBUF    = false;
		inOptMask.SCNGW::NetServices::sockOptMask::SCNGW_SO_RCVBUF    = false;
		inOptMask.SCNGW::NetServices::sockOptMask::SCNGW_IP_HDRINCL   = false;
		//
		outOptMask.SCNGW::NetServices::sockOptMask::SCNGW_SO_LINGER    = false;
		outOptMask.SCNGW::NetServices::sockOptMask::SCNGW_SO_REUSEADDR = false;
		outOptMask.SCNGW::NetServices::sockOptMask::SCNGW_SO_SNDTIMEO  = false;
		outOptMask.SCNGW::NetServices::sockOptMask::SCNGW_SO_RCVTIMEO  = false;
		outOptMask.SCNGW::NetServices::sockOptMask::SCNGW_SO_SNDBUF    = false;
		outOptMask.SCNGW::NetServices::sockOptMask::SCNGW_SO_RCVBUF    = false;
		outOptMask.SCNGW::NetServices::sockOptMask::SCNGW_IP_HDRINCL   = false;
		//
		ospfteInfo.reqSockOpts = inOptMask;

		scngw_proxy->setupClientConnection(ospfteInfo,
							               sPort,
							               outOptMask);
		// TO CHECK
		// fill out socket options mask
		// repSockOpts << outOptMask;

		zlog_debug("Registration performed successfully");

		return sPort;

	} catch (CORBA::SystemException & e) {
#if MINOR_DEFINED_AS_A_MACRO
		zlog_err("Request setupClientConnection to SCNGW failed: "
			   "CORBA::SystemException");
#else
		zlog_err("Request setupClientConnection to SCNGW failed: "
			 "CORBA::SystemException (0x%x)", (uint32_t) e.minor());
#endif
		return -1;
	} catch (omniORB::fatalException & e) {
		zlog_err("Requesting setupClientConnection to SCNGW failed: "
			 "omniORB::fatalException:");
		zlog_err("  file: %s\n", e.file());
		zlog_err("  line: %d\n", e.line());
		zlog_err("  mesg: %s\n", e.errmsg());
		return -1;
	} catch (SCNGW::NetServices::optionError & e) {
		zlog_err("Request setupClientConnection to SCNGW failed: "
			 "option error");
		return -1;
	} catch (SCNGW::NetServices::cantCreateSock & e) {
		zlog_err("Requesting setupClientConnection to SCNGW failed: "
			 "SCNGW server cannot create socket");
		return -1;
	} catch (std::out_of_range & e) {
		zlog_err("Requesting setupClientConnection to SCNGW failed: %s",
			 e.what());
		return -1;
	} catch (...) {
		zlog_err("Requesting setupClientConnection to SCNGW failed: "
			 "UNKNOWN REASON");
		return -1;
	}

	// never reached
	return -1;
}
#endif

void node_add(uint8_t server, int id, node_type_t type)
{
#ifdef TOPOLOGY_CLIENTS_ON
  try {
    if (id == 0) return;

    if (id != -1) nodeIdent.id = id;
    else nodeIdent.id = nodeId;
    nodeIdent.typee = nodeType_from_node_type_t(type);

    struct in_addr nId;
    nId.s_addr = htonl(nodeIdent.id);

    if (!isNodeInSeq(nodeIdent, g2pcera_proxy->nodeGetAll()))
    {
      g2pcera_proxy->nodeAdd(nodeIdent);
    }
  } catch (TOPOLOGY::NodeAlreadyExists) {

    zlog_debug("[ERR] CORBA: Exception NodeAlreadyExists (method nodeAdd)");
    return;
  } catch (TOPOLOGY::InvocationNotAllowed) {

    zlog_debug("[ERR] CORBA: Exception InvocationNotAllowed (method nodeAdd)");
    return;
  } catch (TOPOLOGY::InternalProblems & e) {

    zlog_debug("[ERR] CORBA: Exception InternalProblems (method nodeAdd): %s", (char *) e.what);
  } catch (...) {

    zlog_debug("[ERR] CORBA: Exception Unknown (method nodeAdd)");
    return;
  }
#endif // TOPOLOGY_CLIENTS_ON
  return;
}

void node_del(uint8_t server, uint32_t id, node_type_t type)
{
#ifdef TOPOLOGY_CLIENTS_ON
  try {
    if (id == 0) return;

    if (id != -1) nodeIdent.id = id;
    else nodeIdent.id = nodeId;
    nodeIdent.typee = nodeType_from_node_type_t(type);

    struct in_addr nId;
    nId.s_addr = htonl(nodeIdent.id);

    int length = 0;
    gmplsTypes::teLinkIdentSeq* linkSeq;

    if (isNodeInSeq(nodeIdent, g2pcera_proxy->nodeGetAll()))
    {

      linkSeq = g2pcera_proxy->teLinkGetAllFromNode(nodeIdent);
      length = linkSeq->length();

      if (length == 0)
      {
        g2pcera_proxy->nodeDel(nodeIdent);
      }
    }
    return;
  } catch (TOPOLOGY::CannotFetchNode) {

    zlog_debug("[ERR] CORBA: Exception CannotFetchNode (method nodeDel)");
    return;
  } catch (TOPOLOGY::InvocationNotAllowed) {

    zlog_debug("[ERR] CORBA: Exception InvocationNotAllowed (method nodeDel)");
    return;
  } catch (TOPOLOGY::InternalProblems & e) {

    zlog_debug("[ERR] CORBA: Exception InternalProblems (method nodeDel): %s", (char *) e.what);
  } catch (...) {

    zlog_debug("[ERR] CORBA: Exception Unknown (method nodeDel)");
    return;
  }
#endif // TOPOLOGY_CLIENTS_ON
  return;
}

void update_net_node(int id, uint8_t isDomain)
{
#ifdef TOPOLOGY_CLIENTS_ON
  struct zlistnode * node; void *data;
  struct in_addr * addr;

  try {
    gmplsTypes::netNodeParams nodeParams;
    gmplsTypes::netNodeParams* serverNetNodeParams;
    nodeParams.isDomain = isDomain;
    nodeParams.aState.opState = gmplsTypes::OPERSTATE_UP;             // TODO Lukasz
    nodeParams.aState.admState = gmplsTypes::ADMINSTATE_ENABLED;      // TODO Lukasz
    nodeParams.colors = 0;                                            // TODO Lukasz

    gmplsTypes::areaSeq_var seq;
    {
      gmplsTypes::areaSeq * tmp;
      tmp = new gmplsTypes::areaSeq(1);
      if (!tmp) {
        zlog_debug("[ERR] CORBA: update_net_node: tmp == NULL");
        return;
      }
      seq = tmp;
    }
    seq->length(1);

    seq[0] = 0;                // TODO Lukasz: one area (0.0.0.0) in this moment
    nodeParams.areas = seq;

    if (id != -1) g2pcera_proxy->netNodeGet(id, serverNetNodeParams);  
    else          g2pcera_proxy->netNodeGet(nodeId, serverNetNodeParams);
    if (!equalNetNodes(&nodeParams, serverNetNodeParams))
    {
      if (id != -1) {
        g2pcera_proxy->netNodeUpdate(id, nodeParams);
        g2pcera_proxy->netNodeUpdatePower(id, energyConsumption);  // Damian: check if energy update is doubled at PCE
      }
      else {
        g2pcera_proxy->netNodeUpdate(nodeId, nodeParams);
        g2pcera_proxy->netNodeUpdatePower(nodeId, energyConsumption); // Damian: check if energy update is doubled at PCE
      }
    }
  } catch (TOPOLOGY::CannotFetchNode) {

    zlog_debug("[ERR] CORBA: Exception CannotFetchNode (method netNodeUpdate)");
    return;
  } catch (TOPOLOGY::NodeParamsMismatch) {

    zlog_debug("[ERR] CORBA: Exception NodeParamsMismatch (method netNodeUpdate)");
    return;
  } catch (TOPOLOGY::InvocationNotAllowed) {

    zlog_debug("[ERR] CORBA: Exception InvocationNotAllowed (method netNodeUpdate)");
    return;
  } catch (TOPOLOGY::InternalProblems & e) {

    zlog_debug("[ERR] CORBA: Exception InternalProblems (method netNodeUpdate): %s", (char *) e.what);
    return;
  } catch (...) {

    zlog_debug("[ERR] CORBA: Exception Unknown (method netNodeUpdate)");
    return;
  }
#endif // TOPOLOGY_CLIENTS_ON
  return;
}

} //extern "C"

extern "C" {

void corba_update_te_ra_router_addr(struct in_addr id)
{
  nodeId = ntohl(id.s_addr);
  return;
}

void corba_update_te_ra_router_energy_consumption(float energyConsum)
{
  uint32_t tmp = 0;
  memcpy(&tmp, &energyConsum, 4);
  energyConsumption = tmp;
  return;
}

// CORBA Update TE TNA related

struct in_addr  rc;       // Routing Controller ID used in tna_id_update
struct in_addr  node;     // Node Id used in tna_id_update

typedef struct tna_entry
{
  struct in_addr  node;     // Node Id used in tna_id_update
  g2mpls_addr_t   tna_addr; // TNA address used in tna_id_update
} tna_entry;

struct zlist tnaIds;

void init_tna_ident()
{
  rc.s_addr = 0;
  node.s_addr = 0;
  memset (&tnaIds, 0, sizeof (struct zlist));
  return;
}

// from TNA Address IPv4 | TNA Address IPv6 | TNA Address NSAP TNA Address Sub-TLV
void corba_update_te_tna_addr(g2mpls_addr_t tna)
{
  tna_entry* entry = (tna_entry *) XMALLOC(0, sizeof(tna_entry));
  entry->node = node;
  entry->tna_addr = tna;

  listnode_add(&tnaIds, entry);
  return;
}

// from Node ID TNA Address Sub-TLV
void corba_update_te_tna_node(struct in_addr node_id)
{
  node = node_id;
  return;
}

// from Ancestor RC Id TNA Address Sub-TLV
void corba_update_te_tna_anc_rc_id(struct in_addr value)
{
  rc = value;
  return;
}

void tna_ids_update(uint8_t option)
{
#ifdef TOPOLOGY_CLIENTS_ON
  gmplsTypes::tnaIdent ident;

  bool isDomain = false;
  void *data; 
  struct zlistnode *node, *nnode;

  tna_entry * item;
  for (ALL_LIST_ELEMENTS (&tnaIds, node, nnode, data)) {

    item = (tna_entry *) data;

    ident.rc = ntohl(rc.s_addr);
    ident.node = ntohl(item->node.s_addr);

    gmplsTypes::tnaId_var tnaAddr;
    tnaAddr << item->tna_addr;
    ident.tna = tnaAddr;
    ident.prefix = item->tna_addr.preflen;

    switch(option)
    {
      case ADD_TNA_ADDRESS:
        try {

          nodeIdent.typee = gmplsTypes::NODETYPE_NETWORK;

          if (!ident.rc) {
            isDomain = false;
            nodeIdent.id = ident.node;
          }
          else {
            isDomain = true;
            nodeIdent.id = ident.rc;
          }

          if (!isNodeInSeq(nodeIdent, g2pcera_proxy->nodeGetAll()))
            node_add(UPDATE_G2PCERA, nodeIdent.id, NTYPE_NETWORK);
          update_net_node(nodeIdent.id, isDomain);

          if (!isTnaIdinSeq(ident, g2pcera_proxy->tnaIdsGetAllFromNode(nodeIdent.id, isDomain)))
          {
            g2pcera_proxy->tnaIdAdd(ident);
          }
        } catch (TOPOLOGY::CannotFetchNode & e) {

          zlog_debug("[ERR] CORBA: Exception CannotFetchNode (method tnaIdAdd)");
          zlog_debug("[ERR]        %s", (char *) e.what);
          return;
        } catch (TOPOLOGY::TnaAlreadyExists & e) {

          zlog_debug("[ERR] CORBA: Exception TnaAlreadyExists (method tnaIdAdd)");
          zlog_debug("[ERR]        %s", (char *) e.what);
          return;
        } catch (TOPOLOGY::InvocationNotAllowed & e) {

          zlog_debug("[ERR] CORBA: Exception InvocationNotAllowed (method tnaIdAdd)");
          return;
        } catch (TOPOLOGY::InternalProblems & e) {

          zlog_debug("[ERR] CORBA: Exception InternalProblems (method tnaIdAdd");
          zlog_debug("[ERR]        %s", (char *) e.what);
          return;
        } catch (...) {

          zlog_debug("[ERR] CORBA: Exception Unknown (method tnaIdAdd)");
          return;
        }
        break;
      case REMOVE_TNA_ADDRESS:
        try {

          nodeIdent.typee = gmplsTypes::NODETYPE_NETWORK;

          if (!ident.rc) {
            isDomain = false;
            nodeIdent.id = ident.node;
          }
          else {
            isDomain = true;
            nodeIdent.id = ident.rc;
          }

          if (isNodeInSeq(nodeIdent, g2pcera_proxy->nodeGetAll()))
            if (isTnaIdinSeq(ident, g2pcera_proxy->tnaIdsGetAllFromNode(nodeIdent.id, isDomain)))
          {
            g2pcera_proxy->tnaIdDel(ident);
            }
          break;
        } catch (TOPOLOGY::CannotFetchNode & e) {

          zlog_debug("[ERR] CORBA: Exception CannotFetchNode (method tnaIdDel)");
          zlog_debug("[ERR]        %s", (char *) e.what);
          return;
        } catch (TOPOLOGY::CannotFetchTna & e) {

          zlog_debug("[ERR] CORBA: Exception CannotFetchTna (method tnaIdDel)");
          zlog_debug("[ERR]        %s", (char *) e.what);
          return;
        } catch (TOPOLOGY::InvocationNotAllowed & e) {

          zlog_debug("[ERR] CORBA: Exception InvocationNotAllowed (method tnaIdDel)");
          return;
        } catch (TOPOLOGY::InternalProblems & e) {

          zlog_debug("[ERR] CORBA: Exception InternalProblems (method tnaIdDel)");
          zlog_debug("[ERR]        %s", (char *) e.what);
          return;
        } catch (...) {

          zlog_debug("[ERR] CORBA: Exception Unknown (method tnaIdDel)");
          return;
        }
        break;
    }
  }
#endif // TOPOLOGY_CLIENTS_ON
  return;
}

}

extern "C" {

gmplsTypes::teLinkIdent linkIdent;

struct in_addr localNodeId;     // local node id (interdomain telink)
struct in_addr remoteNodeId;    // remote node id (interdomain telink)
uint32_t       localId;         // local id (interdomain telink)
uint32_t       remoteId;        // remote id (interdomain telink)
struct in_addr ancestorRcId;    // local rc id (interdomain telink)
struct in_addr linkId;          // remote rc id (interdomain telink) & remote node id (intradomain telink)
struct in_addr lclIfAddr;       // local id (intradomain telink)
struct in_addr rmtIfAddr;       // remote id (intradomain telink)
struct in_addr advertisingRId;  // local node id (intradomain telink)
uint8_t        ltype;           // converted to link mode (interdomain & intradomain telink)

void init_link_tmp_values()
{
  localNodeId.s_addr = 0;
  remoteNodeId.s_addr = 0;
  localId = 0;
  remoteId = 0;
  ancestorRcId.s_addr = 0;
  linkId.s_addr = 0;
  lclIfAddr.s_addr = 0;
  rmtIfAddr.s_addr = 0;
  ltype = 0;
}

void init_link_ident()
{
  linkIdent.localNodeId = 0;
  linkIdent.remoteNodeId = 0;

  g2mpls_addr_t addr;
  addr.type = IPv4;
  addr.value.ipv4.s_addr = 0;
  gmplsTypes::TELinkId_var initId;
  initId << addr;

  linkIdent.localId = initId;
  linkIdent.remoteId = initId;
  linkIdent.localRcId = 0;
  linkIdent.remoteRcId = 0;
  linkIdent.mode = gmplsTypes::LINKMODE_UNKNOWN;
}

gmplsTypes::linkMode link_type_2_link_mode(telink_type_t teltype);

void set_link_ident(telink_type_t type)
{
  init_link_ident();

  gmplsTypes::linkId_var clinkId;
  g2mpls_addr_t addr;
  switch (type)
  {
    case INTERDOM_TEL:
      linkIdent.localNodeId = ntohl(localNodeId.s_addr);
      linkIdent.remoteNodeId = ntohl(remoteNodeId.s_addr);

      addr.type = IPv4;
      addr.value.ipv4.s_addr = localId;
      clinkId << addr;

      linkIdent.localId  = (gmplsTypes::TELinkId) clinkId;

      addr.value.ipv4.s_addr = remoteId;
      clinkId << addr;

      linkIdent.remoteId = (gmplsTypes::TELinkId) clinkId;

      linkIdent.localRcId = ntohl(ancestorRcId.s_addr);
      linkIdent.remoteRcId = ntohl(linkId.s_addr);

      linkIdent.mode = link_type_2_link_mode(INTERDOM_TEL);
      break;

    case INTRADOM_TEL:
      linkIdent.localNodeId = ntohl(advertisingRId.s_addr);
      linkIdent.remoteNodeId = ntohl(linkId.s_addr);

      addr.type = IPv4;
      addr.value.ipv4 = lclIfAddr;
      clinkId << addr;

      linkIdent.localId = (gmplsTypes::TELinkId) clinkId;

      addr.value.ipv4 = rmtIfAddr;
      clinkId << addr;

      linkIdent.remoteId = (gmplsTypes::TELinkId) clinkId;

      linkIdent.localRcId = 0;
      linkIdent.remoteRcId = 0;

      linkIdent.mode = link_type_2_link_mode(INTRADOM_TEL);
      break;
  }

  return;
}

// from Local Node ID Link Sub-TLVs
void corba_update_te_link_lcl_node_id(struct in_addr localNId)
{
  localNodeId = localNId;
  return;
}

// from Remote Node ID Link Sub-TLV
void corba_update_te_link_rmt_node_id(struct in_addr remoteNId)
{
  remoteNodeId = remoteNId;
  return;
}

// from Link Local/Remote Identifiers Link Sub-TLV
void corba_update_te_link_lcl_rmt_ids(uint32_t lclId, uint32_t rmtId)
{
  localId = lclId;
  remoteId = rmtId;
  return;
}

// from Link Id Link Sub-TLV
void corba_update_te_link_id(struct in_addr telinkId)
{
  linkId = telinkId;
  return;
}

// from Ancestor RC Id Link Sub-TLV
void corba_update_te_link_anc_rc_id(struct in_addr value)
{
  ancestorRcId = value;
  return;
}

// from Local Interface IP Address Link Sub-TLV
void corba_update_te_link_lclif_ipaddr(struct in_addr value)
{
  lclIfAddr = value;
  return;
}

// from Remote Interface IP Address Link Sub-TLV
void corba_update_te_link_rmtif_ipaddr(struct in_addr value)
{
  rmtIfAddr = value;
  return;
}

void corba_update_advertising_router(struct in_addr value)
{
  advertisingRId = value;
  return;
}

// from Link Type Link Sub-TLV
void corba_update_te_link_type(uint8_t type)
{
  ltype = type;
  return;
}

gmplsTypes::linkMode link_type_2_link_mode(telink_type_t teltype)
{
  gmplsTypes::linkMode mode;
  switch (ltype)
  {
    case LINK_TYPE_SUBTLV_VALUE_PTP:
      if (teltype == INTRADOM_TEL) 
        mode = gmplsTypes::LINKMODE_P2P_NUMBERED;
      else
      {
        if ((linkIdent.localRcId != 0) && (linkIdent.localRcId == linkIdent.remoteRcId))
          mode = gmplsTypes::LINKMODE_ENNI_INTRADOMAIN;
        else
          mode = gmplsTypes::LINKMODE_ENNI_INTERDOMAIN;
      }
      break;
    case LINK_TYPE_SUBTLV_VALUE_MA:
      mode = gmplsTypes::LINKMODE_MULTIACCESS;
      break;
    default:
      mode = gmplsTypes::LINKMODE_UNKNOWN;
      break;
  }

  return mode;
}

uint8_t link_update(uint8_t option, telink_type_t type)
{
#ifdef TOPOLOGY_CLIENTS_ON
  set_link_ident(type);

  gmplsTypes::nodeIdent ident;
  ident.typee = gmplsTypes::NODETYPE_NETWORK;

  switch(option)
  {
    case ADD_TE_LINK:
      try {

        if ((!linkIdent.localRcId && !linkIdent.remoteRcId)
          || (!linkIdent.localRcId && linkIdent.remoteRcId))
        {
          ident.id = linkIdent.localNodeId;
          if (!isNodeInSeq(ident, g2pcera_proxy->nodeGetAll()))
          {
            node_add(UPDATE_G2PCERA, ident.id, NTYPE_NETWORK);
            update_net_node(ident.id, false);
          }
        }

        if ((linkIdent.localRcId && linkIdent.remoteRcId)
          || (linkIdent.localRcId && !linkIdent.remoteRcId))
        {
          ident.id = linkIdent.localRcId;
          if (!isNodeInSeq(ident, g2pcera_proxy->nodeGetAll()))
          {
            node_add(UPDATE_G2PCERA, ident.id, NTYPE_NETWORK);
            update_net_node(ident.id, true);
          }
        }

        if (!isTELinkInSeq(linkIdent, g2pcera_proxy->teLinkGetAllFromNode(ident)))
        {
          g2pcera_proxy->linkAdd(linkIdent);
        }
      } catch (TOPOLOGY::CannotFetchNode & e) {

        zlog_debug("[ERR] CORBA: Exception CannotFetchNode (method linkAdd)");
        zlog_debug("[ERR]        %s", (char *) e.what);
        return 0;
      } catch (TOPOLOGY::LinkAlreadyExists & e) {

        zlog_debug("[ERR] CORBA: Exception LinkAlreadyExists (method linkAdd)");
        zlog_debug("[ERR]        %s", (char *) e.what);
        return 0;
      } catch (TOPOLOGY::InvocationNotAllowed) {

        zlog_debug("[ERR] CORBA: Exception InvocationNotAllowed (method linkAdd)");
        return 0;
      } catch (TOPOLOGY::InternalProblems & e) {

        zlog_debug("[ERR] CORBA: Exception InternalProblems (method linkAdd)");
        zlog_debug("[ERR]        %s", (char *) e.what);
        return 0;
      } catch (...) {

        zlog_debug("[ERR] CORBA: Exception Unknown (method linkAdd)");
        return 0;
      }
      break;
    case REMOVE_TE_LINK:
      try {

        if ((!linkIdent.localRcId && !linkIdent.remoteRcId)
          || (!linkIdent.localRcId && linkIdent.remoteRcId))
          ident.id = linkIdent.localNodeId;

        if ((linkIdent.localRcId && linkIdent.remoteRcId)
          || (linkIdent.localRcId && !linkIdent.remoteRcId))
          ident.id = linkIdent.localRcId;

        if (isNodeInSeq(ident, g2pcera_proxy->nodeGetAll()))
          if (isTELinkInSeq(linkIdent, g2pcera_proxy->teLinkGetAllFromNode(ident)))
          {
            g2pcera_proxy->linkDel(linkIdent);
          }
      } catch (TOPOLOGY::CannotFetchNode & e) {

        zlog_debug("[ERR] CORBA: Exception CannotFetchNode (method linkDel)");
        zlog_debug("[ERR]        %s", (char *) e.what);
        return 0;
      } catch (TOPOLOGY::LinkAlreadyExists & e) {

        zlog_debug("[ERR] CORBA: Exception LinkAlreadyExists (method linkDel)");
        zlog_debug("[ERR]        %s", (char *) e.what);
        return 0;
      } catch (TOPOLOGY::CannotFetchLink & e) {

        zlog_debug("[ERR] CORBA: Exception CannotFetchLink (method linkDel)");
        zlog_debug("[ERR]        %s", (char *) e.what);
        return 0;
      } catch (TOPOLOGY::InvocationNotAllowed) {

        zlog_debug("[ERR] CORBA: Exception InvocationNotAllowed (method linkDel)");
        return 0;
      } catch (TOPOLOGY::InternalProblems & e) {

        zlog_debug("[ERR] CORBA: Exception InternalProblems (method linkDel)");
        zlog_debug("[ERR]        %s", (char *) e.what);
        return 0;
      } catch (...) {

        zlog_debug("[ERR] CORBA: Exception Unknown (method linkDel)");
        return 0;
      }
      break;
  }
#else
  return -1;
#endif // TOPOLOGY_CLIENTS_ON
  return 1;
}

gmplsTypes::teLinkComParams linkComParams;

void corba_update_te_link_metric(uint32_t teMetric)
{
  linkComParams.teMetric = teMetric;
  return;
}

void corba_update_te_link_max_bw(float teMaxBw)
{
  uint32_t tmp = 0;
  memcpy(&tmp, &teMaxBw, 4);
  linkComParams.teMaxBw = tmp;
  return;
}

void corba_update_te_link_max_res_bw(float teMaxResvBw)
{
  uint32_t tmp = 0;
  memcpy(&tmp, &teMaxResvBw, 4);
  linkComParams.teMaxResvBw = tmp;
  return;
}

gmplsTypes::bwPerPrio availBw;

void corba_update_te_link_unrsv_bw(float avBand[])
{
  uint32_t tmp;
  for (int i=0; i< 8; i++)
  {
    memcpy(&tmp, &avBand[i], 4);
    availBw[i] = tmp;
  }
  return;
}

void corba_update_te_link_rsc_clsclr(uint32_t teColorMask)
{
  linkComParams.teColorMask = teColorMask;
  return;
}

void corba_update_te_link_protect_type(uint8_t teProtectionTypeMask)
{
  linkComParams.teProtectionTypeMask = teProtectionTypeMask;
  return;
}

void corba_update_te_link_energy_consumption(float energyCons)
{
  uint32_t tmp = 0;
  memcpy(&tmp, &energyCons, 4);
  linkComParams.powerConsumption = tmp;
  return;
}

void corba_update_te_link_bwReplanning(float maxBwUpgrade, float maxBwDowngrade)
{
  gmplsTypes::vlinkBwReplanInfoSeq_var seq = new gmplsTypes::vlinkBwReplanInfoSeq();
  seq->length(1);

  uint32_t tmp = 0;
  memcpy(&tmp, &maxBwUpgrade, 4);
  seq[0].maxBwUpgrade = tmp;
  memcpy(&tmp, &maxBwDowngrade, 4);
  seq[0].maxBwDowngrade = tmp;
  linkComParams.vlinkBwReplanning = seq;
  return;
}

void link_update_com()
{
#ifdef TOPOLOGY_CLIENTS_ON
  try {
    gmplsTypes::teLinkComParams* serverLinkComParams;

    linkComParams.adminMetric = 0;      //FIXME Lukasz: where is this information?

    g2pcera_proxy->teLinkGetCom(linkIdent, serverLinkComParams);
    if (!equalComParams(&linkComParams, serverLinkComParams))
    {
      g2pcera_proxy->teLinkUpdateCom(linkIdent, linkComParams);
    }

  } catch (TOPOLOGY::CannotFetchNode) {

    zlog_debug("[ERR] CORBA: Exception CannotFetchNode (method teLinkUpdateCom)");
    return;
  } catch (TOPOLOGY::CannotFetchLink) {

    zlog_debug("[ERR] CORBA: Exception CannotFetchLink (method teLinkUpdateCom)");
    return;
  } catch (TOPOLOGY::LinkParamsMismatch) {

    zlog_debug("[ERR] CORBA: Exception LinkParamsMismatch (method teLinkUpdateCom)");
    return;
  } catch (TOPOLOGY::InvocationNotAllowed) {

    zlog_debug("[ERR] CORBA: Exception InvocationNotAllowed (method teLinkUpdateCom)");
    return;
  } catch (TOPOLOGY::InternalProblems & e) {

    zlog_debug("[ERR] CORBA: Exception InternalProblems (method teLinkUpdateCom): %s", (char *) e.what);
  } catch (...) {

    zlog_debug("[ERR] CORBA: Exception Unknown (method teLinkUpdateCom)");
    return;
  }
#endif // TOPOLOGY_CLIENTS_ON
  return;
}

void link_update_tdm()
{
#ifdef TOPOLOGY_CLIENTS_ON
  try {
    gmplsTypes::teLinkTdmParams serverLinkTdmParams;

    gmplsTypes::teLinkTdmParams linkTdmParams;
    linkTdmParams.hoMuxCapMask     = 0;         //FIXME Lukasz: where is this information?
    linkTdmParams.loMuxCapMask     = 0;         //FIXME Lukasz: where is this information?
    linkTdmParams.transparencyMask = 0;         //FIXME Lukasz: where is this information?
    linkTdmParams.blsrRingId       = 0;         //FIXME Lukasz: where is this information?

    g2pcera_proxy->teLinkGetTdm(linkIdent, serverLinkTdmParams);
    if (!equalTdmParams(&linkTdmParams, &serverLinkTdmParams))
    {
      g2pcera_proxy->teLinkUpdateTdm(linkIdent, linkTdmParams);
    }
  } catch (TOPOLOGY::CannotFetchNode) {

    zlog_debug("[ERR] CORBA: Exception CannotFetchNode (method teLinkUpdateTdm)");
    return;
  } catch (TOPOLOGY::CannotFetchLink) {

    zlog_debug("[ERR] CORBA: Exception CannotFetchLink (method teLinkUpdateTdm)");
    return;
  } catch (TOPOLOGY::LinkParamsMismatch) {

    zlog_debug("[ERR] CORBA: Exception LinkParamsMismatch (method teLinkUpdateTdm)");
    return;
  } catch (TOPOLOGY::InvocationNotAllowed) {

    zlog_debug("[ERR] CORBA: Exception InvocationNotAllowed (method teLinkUpdateTdm)");
    return;
  } catch (TOPOLOGY::InternalProblems & e) {

    zlog_debug("[ERR] CORBA: Exception InternalProblems (method teLinkUpdateTdm): %s", (char *) e.what);
  } catch (...) {

    zlog_debug("[ERR] CORBA: Exception Unknown (method teLinkUpdateTdm)");
    return;
  }
#endif // TOPOLOGY_CLIENTS_ON
  return;
}

void link_update_lscG709()
{
#ifdef TOPOLOGY_CLIENTS_ON
  try {
    gmplsTypes::teLinkLscG709Params serverLinkLscG709Params;

    gmplsTypes::teLinkLscG709Params linkLscG709Params;
    linkLscG709Params.odukMuxCapMask = 0;      //FIXME Lukasz: where is this information?

    g2pcera_proxy->teLinkGetLscG709(linkIdent, serverLinkLscG709Params);
    if (!equalLscG709Params(&linkLscG709Params, &serverLinkLscG709Params))
    {
      g2pcera_proxy->teLinkUpdateLscG709(linkIdent, linkLscG709Params);
    }
  } catch (TOPOLOGY::CannotFetchNode) {

    zlog_debug("[ERR] CORBA: Exception CannotFetchNode (method teLinkUpdateLscG709)");
    return;
  } catch (TOPOLOGY::CannotFetchLink) {

    zlog_debug("[ERR] CORBA: Exception CannotFetchLink (method teLinkUpdateLscG709)");
    return;
  } catch (TOPOLOGY::LinkParamsMismatch) {

    zlog_debug("[ERR] CORBA: Exception LinkParamsMismatch (method teLinkUpdateLscG709)");
    return;
  } catch (TOPOLOGY::InvocationNotAllowed) {

    zlog_debug("[ERR] CORBA: Exception InvocationNotAllowed (method teLinkUpdateLscG709)");
    return;
  } catch (TOPOLOGY::InternalProblems & e) {

    zlog_debug("[ERR] CORBA: Exception InternalProblems (method teLinkUpdateLscG709): %s", (char *) e.what);
  } catch (...) {

    zlog_debug("[ERR] CORBA: Exception Unknown (method teLinkUpdateLscG709)");
    return;
  }
#endif // TOPOLOGY_CLIENTS_ON
  return;
}

gmplsTypes::teLinkLscWdmParams linkLscWdmParams;

// from Dpdm Link Sub-TLV
void corba_update_te_link_d_pdm(uint32_t dispersionPMD)
{
  linkLscWdmParams.dispersionPMD = dispersionPMD;
  return;
}

// from Span Length Link Sub-TLV
void corba_update_te_link_span_length(uint32_t spanLength)
{
  linkLscWdmParams.spanLength = spanLength;
  return;
}

// from Amplifiers List Link Sub-TLV
void corba_update_te_link_amp_list(struct amp_par *amplist, uint16_t len)
{
  struct amp_par * elem;
  gmplsTypes::amplifiersSeq_var seq;

  gmplsTypes::amplifiersSeq * tmp;
  tmp = new gmplsTypes::amplifiersSeq(len);
  if (!tmp) {
    zlog_debug("[ERR] CORBA: corba_update_te_link_amp_list: tmp == NULL");
    return;
  }
  seq = tmp;
  seq->length(len);

  float tmpNoise;
  u_int32_t lu1, lu2;
  for (uint16_t i = 0; i< len; i++)
  {
    gmplsTypes::teLinkWdmAmplifierEntry entry;
    entry.gain = ntohl(amplist[i].gain);
    memcpy (&lu1, &amplist[i].noise, 4);
    lu2 = ntohl (lu1);
    memcpy (&tmpNoise, &lu2, 4);
    entry.noiseFigure = (int)tmpNoise;

    seq[i] = entry;
  }
  linkLscWdmParams.amplifiers = seq;
  return;
}

void link_update_lscwdm()
{
#ifdef TOPOLOGY_CLIENTS_ON
  try {
    gmplsTypes::teLinkLscWdmParams_var serverLinkLscWdmParams;

    g2pcera_proxy->teLinkGetLscWdm(linkIdent, serverLinkLscWdmParams);
    if (!equalLscWdmParams(linkLscWdmParams, serverLinkLscWdmParams))
    {
      g2pcera_proxy->teLinkUpdateLscWdm(linkIdent, linkLscWdmParams);
    }
  } catch (TOPOLOGY::CannotFetchNode) {

    zlog_debug("[ERR] CORBA: Exception CannotFetchNode (method teLinkUpdateLscWdm)");
    return;
  } catch (TOPOLOGY::CannotFetchLink) {

    zlog_debug("[ERR] CORBA: Exception CannotFetchLink (method teLinkUpdateLscWdm)");
    return;
  } catch (TOPOLOGY::LinkParamsMismatch) {

    zlog_debug("[ERR] CORBA: Exception LinkParamsMismatch (method teLinkUpdateLscWdm)");
    return;
  } catch (TOPOLOGY::InvocationNotAllowed) {

    zlog_debug("[ERR] CORBA: Exception InvocationNotAllowed (method teLinkUpdateLscWdm)");
    return;
  } catch (TOPOLOGY::InternalProblems & e) {

    zlog_debug("[ERR] CORBA: Exception InternalProblems (method teLinkUpdateLscWdm): %s", (char *) e.what);
  } catch (...) {

    zlog_debug("[ERR] CORBA: Exception Unknown (method teLinkUpdateLscWdm)");
    return;
  }
#endif // TOPOLOGY_CLIENTS_ON
  return;
}

void link_update_states()
{
#ifdef TOPOLOGY_CLIENTS_ON
  try {
    gmplsTypes::statesBundle serverStates;

    gmplsTypes::statesBundle states;
    states.opState = gmplsTypes::OPERSTATE_UP;
    states.admState = gmplsTypes::ADMINSTATE_ENABLED;

    g2pcera_proxy->teLinkGetStates(linkIdent, serverStates);
    if (!equalLinkStates(&states, &serverStates))
    {
      g2pcera_proxy->teLinkUpdateStates(linkIdent, states);
    }
  } catch (TOPOLOGY::CannotFetchNode) {

    zlog_debug("[ERR] CORBA: Exception CannotFetchNode (method teLinkUpdateStates)");
    return;
  } catch (TOPOLOGY::CannotFetchLink) {

    zlog_debug("[ERR] CORBA: Exception CannotFetchLink (method teLinkUpdateStates)");
    return;
  } catch (TOPOLOGY::LinkParamsMismatch) {

    zlog_debug("[ERR] CORBA: Exception LinkParamsMismatch (method teLinkUpdateStates)");
    return;
  } catch (TOPOLOGY::InvocationNotAllowed) {

    zlog_debug("[ERR] CORBA: Exception InvocationNotAllowed (method teLinkUpdateStates)");
    return;
  } catch (TOPOLOGY::InternalProblems & e) {

    zlog_debug("[ERR] CORBA: Exception InternalProblems (method teLinkUpdateStates): %s", (char *) e.what);
  } catch (...) {

    zlog_debug("[ERR] CORBA: Exception Unknown (method teLinkUpdateStates)");
    return;
  }
#endif // TOPOLOGY_CLIENTS_ON
  return;
}

void link_update_genbw()
{
#ifdef TOPOLOGY_CLIENTS_ON
  try {
    gmplsTypes::bwPerPrio serverAvailBw;

    g2pcera_proxy->teLinkGetGenBw(linkIdent, serverAvailBw);
    g2pcera_proxy->teLinkUpdateGenBw(linkIdent, availBw);
  } catch (TOPOLOGY::CannotFetchNode) {

    zlog_debug("[ERR] CORBA: Exception CannotFetchNode (method teLinkUpdateGenBw)");
    return;
  } catch (TOPOLOGY::CannotFetchLink) {

    zlog_debug("[ERR] CORBA: Exception CannotFetchLink (method teLinkUpdateGenBw)");
    return;
  } catch (TOPOLOGY::LinkParamsMismatch) {

    zlog_debug("[ERR] CORBA: Exception LinkParamsMismatch (method teLinkUpdateGenBw)");
    return;
  } catch (TOPOLOGY::InvocationNotAllowed) {

    zlog_debug("[ERR] CORBA: Exception InvocationNotAllowed (method teLinkUpdateGenBw)");
    return;
  } catch (TOPOLOGY::InternalProblems & e) {

    zlog_debug("[ERR] CORBA: Exception InternalProblems (method teLinkUpdateGenBw): %s", (char *) e.what);
  } catch (...) {

    zlog_debug("[ERR] CORBA: Exception Unknown (method teLinkUpdateGenBw)");
    return;
  }
#endif // TOPOLOGY_CLIENTS_ON
  return;
}

void link_update_power_consumption()
{
#ifdef TOPOLOGY_CLIENTS_ON
  try {
    g2pcera_proxy->teLinkUpdatePower(linkIdent, linkComParams.powerConsumption);
  } catch (TOPOLOGY::CannotFetchNode) {

    zlog_debug("[ERR] CORBA: Exception CannotFetchNode (method teLinkUpdatePower)");
    return;
  } catch (TOPOLOGY::CannotFetchLink) {

    zlog_debug("[ERR] CORBA: Exception CannotFetchLink (method teLinkUpdatePower)");
    return;
  } catch (TOPOLOGY::LinkParamsMismatch) {

    zlog_debug("[ERR] CORBA: Exception LinkParamsMismatch (method teLinkUpdatePower)");
    return;
  } catch (TOPOLOGY::InvocationNotAllowed) {

    zlog_debug("[ERR] CORBA: Exception InvocationNotAllowed (method teLinkUpdatePower)");
    return;
  } catch (TOPOLOGY::InternalProblems & e) {

    zlog_debug("[ERR] CORBA: Exception InternalProblems (method teLinkUpdatePower): %s", (char *) e.what);
  } catch (...) {

    zlog_debug("[ERR] CORBA: Exception Unknown (method teLinkUpdatePower)");
    return;
  }
#endif // TOPOLOGY_CLIENTS_ON
  return;
}

void link_update_dynamic_replanning()
{
  link_update_com(); // Damian: there is no replanning specific updated in topology.idl, update all link information
  return;
}


gmplsTypes::freeCTPSeq freeCTP;

void corba_update_te_link_ssdh_if_sw_cap_desc(struct zlist* freeTS)
{
  struct zlistnode *node;
  void *data;
  struct signal_unalloc_tslots *elem;
  int i = 0;

  gmplsTypes::freeCTPSeq_var seq;
  gmplsTypes::freeCTPSeq * tmp;
  tmp = new gmplsTypes::freeCTPSeq(listcount(freeTS));
  if (!tmp) {
    zlog_debug("[ERR] CORBA: corba_update_te_link_ssdh_if_sw_cap_desc: tmp == NULL");
    return;
  }
  seq = tmp;
  seq->length(listcount(freeTS));

  uint32_t value = 0;
  for (ALL_LIST_ELEMENTS_RO(freeTS, node, data))
  {
    elem = (struct signal_unalloc_tslots *) data;
    assert(elem != 0);

    gmplsTypes::freeCTPEntry entry;
    entry.sigType = (uint8_t) elem->signal_type;
    value  = 0;
    value  = elem->unalloc_tslots[0]; value <<= 8; value &= 0xff00;
    value |= elem->unalloc_tslots[1]; value <<= 8; value &= 0xffff00;
    value |= elem->unalloc_tslots[2]; value &= 0xffffff;
    entry.ctps = value;
    seq[i] = entry;

    i++;
  }
  freeCTP = seq;

  return;
}

void link_update_tdmbw()
{
#ifdef TOPOLOGY_CLIENTS_ON
  try {
    gmplsTypes::freeCTPSeq_var serverFreeCTP;

    g2pcera_proxy->teLinkGetTdmBw(linkIdent, serverFreeCTP);
    if (!equalTdmBw(freeCTP, serverFreeCTP))
    {
      g2pcera_proxy->teLinkUpdateTdmBw(linkIdent, freeCTP);
    }
  } catch (TOPOLOGY::CannotFetchNode) {

    zlog_debug("[ERR] CORBA: Exception CannotFetchNode (method teLinkUpdateTdmBw)");
    return;
  } catch (TOPOLOGY::CannotFetchLink) {

    zlog_debug("[ERR] CORBA: Exception CannotFetchLink (method teLinkUpdateTdmBw)");
    return;
  } catch (TOPOLOGY::LinkParamsMismatch) {

    zlog_debug("[ERR] CORBA: Exception LinkParamsMismatch (method teLinkUpdateTdmBw)");
    return;
  } catch (TOPOLOGY::InvocationNotAllowed) {

    zlog_debug("[ERR] CORBA: Exception InvocationNotAllowed (method teLinkUpdateTdmBw)");
    return;
  } catch (TOPOLOGY::InternalProblems & e) {

    zlog_debug("[ERR] CORBA: Exception InternalProblems (method teLinkUpdateTdmBw): %s", (char *) e.what);
  } catch (...) {

    zlog_debug("[ERR] CORBA: Exception Unknown (method teLinkUpdateTdmBw)");
    return;
  }
#endif // TOPOLOGY_CLIENTS_ON
  return;
}

void corba_update_te_link_band_account(uint32_t *band_account, uint32_t list_len)
{
  //TODO finish it
  return;
}

void link_update_lscG709bw(struct zlist *fODUk, struct zlist *fOCh)
{
#ifdef TOPOLOGY_CLIENTS_ON
  //TODO finish it
  try {
    gmplsTypes::freeCTPSeq* serverFreeODUk;
    gmplsTypes::freeCTPSeq* serverFreeOCh;

    gmplsTypes::freeCTPSeq_var seq;
    gmplsTypes::freeCTPSeq * tmp;
    tmp = new gmplsTypes::freeCTPSeq(0);
    if (!tmp) {
      zlog_debug("[ERR] CORBA: link_update_lscG709bw: tmp == NULL");
      return;
    }
    seq = tmp;
    seq->length(0);

    gmplsTypes::freeCTPSeq freeODUk = seq;      //FIXME Lukasz: where is this information?
    gmplsTypes::freeCTPSeq freeOCh = seq;       //FIXME Lukasz: where is this information?

    g2pcera_proxy->teLinkGetLscG709Bw(linkIdent, serverFreeODUk, serverFreeOCh);
    if (!equalLscG709Bw(freeODUk, freeOCh, *serverFreeODUk, *serverFreeOCh))
    {
      g2pcera_proxy->teLinkUpdateLscG709Bw(linkIdent, freeODUk, freeOCh);
    }
  } catch (TOPOLOGY::CannotFetchNode) {

    zlog_debug("[ERR] CORBA: Exception CannotFetchNode (method teLinkUpdateLscG709Bw)");
    return;
  } catch (TOPOLOGY::CannotFetchLink) {

    zlog_debug("[ERR] CORBA: Exception CannotFetchLink (method teLinkUpdateLscG709Bw)");
    return;
  } catch (TOPOLOGY::LinkParamsMismatch) {

    zlog_debug("[ERR] CORBA: Exception LinkParamsMismatch (method teLinkUpdateLscG709Bw)");
    return;
  } catch (TOPOLOGY::InvocationNotAllowed) {

    zlog_debug("[ERR] CORBA: Exception InvocationNotAllowed (method teLinkUpdateLscG709Bw)");
    return;
  } catch (TOPOLOGY::InternalProblems & e) {

    zlog_debug("[ERR] CORBA: Exception InternalProblems (method teLinkUpdateLscG709Bw): %s", (char *) e.what);
  } catch (...) {

    zlog_debug("[ERR] CORBA: Exception Unknown (method teLinkUpdateLscG709Bw)");
    return;
  }
#endif // TOPOLOGY_CLIENTS_ON
  return;
}

gmplsTypes::teLinkWdmLambdasBitmap_var lambdasBitmap;

void corba_update_te_link_av_wave_mask(u_int16_t num_wavelengths, u_int32_t label_set_desc, uint32_t *bitmap, uint16_t bitmap_len)
{
  wdm_link_lambdas_bitmap_t lamBitmap;

  lamBitmap.base_lambda_label = label_set_desc;
  lamBitmap.num_wavelengths = num_wavelengths;
  lamBitmap.bitmap_size = (num_wavelengths/32) + 1;
  uint32_t *bitmaps = new uint32_t[lamBitmap.bitmap_size];

  for (uint16_t i = 0; i<bitmap_len; i++)
    bitmaps[i] = bitmap[i];

  lamBitmap.bitmap_word = bitmaps;
  lambdasBitmap << lamBitmap;

  return;
}

void link_update_lscwdm_bw()
{
#ifdef TOPOLOGY_CLIENTS_ON
  gmplsTypes::teLinkWdmLambdasBitmap_var serverLambdasBitmap;

  bool isnew = false;
  try {

    g2pcera_proxy->teLinkGetLscWdmBw(linkIdent, serverLambdasBitmap);

  } catch (TOPOLOGY::InvocationNotAllowed) {
    isnew = true;
  } catch (...) {
    zlog_debug("[ERR] CORBA: Exception Generic (method teLinkGetLscWdmBw)");
    return;
  }

  try {
    if (isnew) {
      g2pcera_proxy->teLinkUpdateLscWdmBw(linkIdent, lambdasBitmap);
    } else {
      if (!equalLscWdmBw(lambdasBitmap, serverLambdasBitmap)) {
        g2pcera_proxy->teLinkUpdateLscWdmBw(linkIdent, lambdasBitmap);
      }
    }
  } catch (TOPOLOGY::CannotFetchNode) {

    zlog_debug("[ERR] CORBA: Exception CannotFetchNode (method teLinkUpdateLscWdmBw)");
    return;
  } catch (TOPOLOGY::CannotFetchLink) {

    zlog_debug("[ERR] CORBA: Exception CannotFetchLink (method teLinkUpdateLscWdmBw)");
    return;
  } catch (TOPOLOGY::LinkParamsMismatch) {

    zlog_debug("[ERR] CORBA: Exception LinkParamsMismatch (method teLinkUpdateLscWdmBw)");
    return;
  } catch (TOPOLOGY::InvocationNotAllowed) {

    zlog_debug("[ERR] CORBA: Exception InvocationNotAllowed (method teLinkUpdateLscWdmBw)");
    return;
  } catch (TOPOLOGY::InternalProblems & e) {

    zlog_debug("[ERR] CORBA: Exception InternalProblems (method teLinkUpdateLscWdmBw): %s", (char *) e.what);
  } catch (...) {

    zlog_debug("[ERR] CORBA: Exception Unknown (method teLinkUpdateLscWdmBw)");
    return;
  }
#endif // TOPOLOGY_CLIENTS_ON
  return;
}

gmplsTypes::srlgSeq srlgs;

void corba_update_te_link_shared_risk_link_grp(uint32_t *srlg, uint16_t len)
{
  gmplsTypes::srlgSeq_var seq;
  gmplsTypes::srlgSeq * tmp;

  tmp = new gmplsTypes::srlgSeq(len);
  if (!tmp) {
    zlog_debug("[ERR] CORBA: corba_update_te_link_shared_risk_link_grp: tmp == NULL");
    return;
  }
  seq = tmp;
  seq->length(len);

  for (uint16_t i = 0; i < len; i++)
    seq[i] = srlg[i];

  srlgs = seq;

  return;
}

void corba_update_te_link_srlg()
{
#ifdef TOPOLOGY_CLIENTS_ON
  try {
    gmplsTypes::srlgSeq uniqueSrlgs;
    gmplsTypes::srlgSeq * serverSrlgs;

    g2pcera_proxy->teLinkGetSrlgs(linkIdent, serverSrlgs);
    uniqueSrlgs = diffSrlgs(srlgs, *serverSrlgs);
    if (uniqueSrlgs.length() > 0)
    {
      g2pcera_proxy->teLinkAppendSrlgs(linkIdent, uniqueSrlgs);
    }
  } catch (TOPOLOGY::CannotFetchNode) {

    zlog_debug("[ERR] CORBA: Exception CannotFetchNode (method teLinkAppendSrlgs)");
    return;
  } catch (TOPOLOGY::CannotFetchLink) {

    zlog_debug("[ERR] CORBA: Exception CannotFetchLink (method teLinkAppendSrlgs)");
    return;
  } catch (TOPOLOGY::LinkParamsMismatch) {

    zlog_debug("[ERR] CORBA: Exception LinkParamsMismatch (method teLinkAppendSrlgs)");
    return;
  } catch (TOPOLOGY::InvocationNotAllowed) {

    zlog_debug("[ERR] CORBA: Exception InvocationNotAllowed (method teLinkAppendSrlgs)");
    return;
  } catch (TOPOLOGY::InternalProblems & e) {

    zlog_debug("[ERR] CORBA: Exception InternalProblems (method teLinkAppendSrlgs): %s", (char *) e.what);
  } catch (...) {

    zlog_debug("[ERR] CORBA: Exception Unknown (method teLinkAppendSrlgs)");
    return;
  }
#endif // TOPOLOGY_CLIENTS_ON
  return;
}

gmplsTypes::teLinkCalendarSeq cal;

void corba_update_te_link_callendar(struct te_link_calendar *te_calendar, uint16_t te_calendar_len)
{
  void *data;
  struct te_link_calendar *elem;
  gmplsTypes::teLinkCalendarSeq_var seq;

  gmplsTypes::teLinkCalendarSeq * tmp = new gmplsTypes::teLinkCalendarSeq(te_calendar_len);
  if (!tmp) {
    zlog_debug("[ERR] CORBA: corba_update_te_link_callendar: tmp == NULL");
    return;
  }
  seq = tmp;
  seq->length(te_calendar_len);

  uint32_t tmp32 = 0;
  int i = 0;
  for (uint16_t i=0; i<te_calendar_len; i++)
  {
    gmplsTypes::linkCalendarEvent entry;
    entry.unixTime = te_calendar[i].time;
    for(int j=0; j<8; j++)
    {
      memcpy(&tmp32, &te_calendar[i].value[j], 4);
      entry.availBw[j] = tmp32;
    }
    seq[i] = entry;
  }
  cal = seq;

  return;
}

void corba_update_te_link_tecal()
{
#ifdef TOPOLOGY_CLIENTS_ON
  try {
    gmplsTypes::teLinkCalendarSeq uniqueCal;
    gmplsTypes::teLinkCalendarSeq_var serverCal;

    g2pcera_proxy->teLinkGetCalendar(linkIdent, serverCal);
    uniqueCal = diffCalendars(cal, serverCal);
    if (uniqueCal.length() > 0)
    {
      g2pcera_proxy->teLinkAppendCalendar(linkIdent, uniqueCal);
    }
  } catch (TOPOLOGY::CannotFetchNode) {

    zlog_debug("[ERR] CORBA: Exception CannotFetchNode (method teLinkAppendCalendar)");
    return;
  } catch (TOPOLOGY::CannotFetchLink) {

    zlog_debug("[ERR] CORBA: Exception CannotFetchLink (method teLinkAppendCalendar)");
    return;
  } catch (TOPOLOGY::LinkParamsMismatch) {

    zlog_debug("[ERR] CORBA: Exception LinkParamsMismatch (method teLinkAppendCalendar)");
    return;
  } catch (TOPOLOGY::InvocationNotAllowed) {

    zlog_debug("[ERR] CORBA: Exception InvocationNotAllowed (method teLinkAppendCalendar)");
    return;
  } catch (TOPOLOGY::InternalProblems & e) {

    zlog_debug("[ERR] CORBA: Exception InternalProblems (method teLinkAppendCalendar): %s", (char *) e.what);
  } catch (...) {

    zlog_debug("[ERR] CORBA: Exception Unknown (method teLinkAppendCalendar)");
    return;
  }
#endif // TOPOLOGY_CLIENTS_ON
  return;
}

struct zlist teLinkIscs;

void init_grid_TELink_Iscs()
{
  memset (&teLinkIscs, 0, sizeof (struct zlist));
}

void corba_update_te_link_if_sw_cap_desc_genisc(uint8_t switching_cap, uint8_t encoding, float maxLSPbw[])
{
  te_link_if_sw_cap_t* isc = (te_link_if_sw_cap *) XMALLOC(0, sizeof(te_link_if_sw_cap));

  isc->switching_cap = switching_cap;
  isc->encoding = encoding;
  for(int i=0; i<LINK_MAX_PRIORITY; i++)
    isc->maxLSPbw[i] = maxLSPbw[i];

  listnode_add(&teLinkIscs, isc);
  return;
}

void corba_update_te_link_if_sw_cap_desc_tdmisc(uint8_t switching_cap, uint8_t encoding, float maxLSPbw[], float minLSPbw, uint8_t indication)
{
  te_link_if_sw_cap_t* isc = (te_link_if_sw_cap *) XMALLOC(0, sizeof(te_link_if_sw_cap));

  isc->switching_cap = switching_cap;
  isc->encoding = encoding;
  for(int i=0; i<LINK_MAX_PRIORITY; i++)
    isc->maxLSPbw[i] = maxLSPbw[i];
  isc->min_lsp_bw = minLSPbw;
  isc->indication = indication;

  listnode_add(&teLinkIscs, isc);
  return;
}

void corba_update_te_link_if_sw_cap_desc_pscisc(uint8_t switching_cap, uint8_t encoding, float maxLSPbw[], float minLSPbw, uint16_t interfaceMTU)
{
  te_link_if_sw_cap_t* isc = (te_link_if_sw_cap *) XMALLOC(0, sizeof(te_link_if_sw_cap));

  isc->switching_cap = switching_cap;
  isc->encoding = encoding;
  for(int i=0; i<LINK_MAX_PRIORITY; i++)
    isc->maxLSPbw[i] = maxLSPbw[i];
  isc->min_lsp_bw = minLSPbw;
  isc->mtu = interfaceMTU;

  listnode_add(&teLinkIscs, isc);
  return;
}

void corba_update_te_link_if_sw_cap_desc()
{
#ifdef TOPOLOGY_CLIENTS_ON
  void *data; 
  struct zlistnode *node, *nnode;

  gmplsTypes::iscSeq_var seq;
  {
    gmplsTypes::iscSeq * tmp;
    tmp = new gmplsTypes::iscSeq(listcount(&teLinkIscs));
    if (!tmp) {
      zlog_debug("[ERR] CORBA: corba_update_te_link_if_sw_cap_desc: tmp == NULL");
    }
    seq = tmp;
  }
  seq->length(listcount(&teLinkIscs));

  te_link_if_sw_cap_t * elem;
  uint32_t value, temp, z;
  z = 0;
  for (ALL_LIST_ELEMENTS (&teLinkIscs, node, nnode, data)) {

    elem = (te_link_if_sw_cap *) data;
    gmplsTypes::isc isc;

    gmplsTypes::iscParamsGen gen;
    gmplsTypes::iscParamsTdm tdm;
    gmplsTypes::iscParamsPsc psc;

    uint32_t tmp = 0;
    switch(elem->switching_cap)
    {
      case CAPABILITY_PSC1:
      case CAPABILITY_PSC2:
      case CAPABILITY_PSC3:
      case CAPABILITY_PSC4:
      case CAPABILITY_L2SC:
        psc.swCap   = switching_cap_from_uchar(elem->switching_cap);
        psc.encType = encoding_type_from_uchar(elem->encoding);
        for(int i=0; i<LINK_MAX_PRIORITY; i++)
        {
          memcpy(&tmp, &elem->maxLSPbw[i], 4);
          psc.maxLSPbandwidth[i] = tmp;
        }
        memcpy(&tmp, &elem->min_lsp_bw, 4);
        psc.minLSPbandwidth = tmp;
        psc.interfaceMTU = elem->mtu;
        isc.psc(psc);
        break;
      case CAPABILITY_TDM:
        tdm.swCap   = switching_cap_from_uchar(elem->switching_cap);
        tdm.encType = encoding_type_from_uchar(elem->encoding);
        for(int i=0; i<LINK_MAX_PRIORITY; i++)
        {
          memcpy(&tmp, &elem->maxLSPbw[i], 4);
          tdm.maxLSPbandwidth[i] = tmp;
        }
        memcpy(&tmp, &elem->min_lsp_bw, 4);
        tdm.minLSPbandwidth = tmp;
        tdm.indication = elem->indication;
        isc.tdm(tdm);
        break;
      case CAPABILITY_LSC:
      case CAPABILITY_FSC:
        gen.swCap   = switching_cap_from_uchar(elem->switching_cap);
        gen.encType = encoding_type_from_uchar(elem->encoding);
        for(int i=0; i<LINK_MAX_PRIORITY; i++)
        {
          memcpy(&tmp, &elem->maxLSPbw[i], 4);
          gen.maxLSPbandwidth[i] = tmp;
        }
        isc.gen(gen);
        break;
      default:
        break;
    }

    seq[z] = isc;
    z++;
  }

  gmplsTypes::iscSeq iscs;
  iscs = seq;

  try {
    gmplsTypes::iscSeq uniqueIscs;
    gmplsTypes::iscSeq_var serverIscs;

    g2pcera_proxy->teLinkGetIsc(linkIdent, serverIscs);
    uniqueIscs = diffIscs(iscs, serverIscs);
    if (uniqueIscs.length() > 0)
    {
      g2pcera_proxy->teLinkAppendIsc(linkIdent, uniqueIscs);
    }
  } catch (TOPOLOGY::CannotFetchNode) {

    zlog_debug("[ERR] CORBA: Exception CannotFetchNode (method teLinkAppendIsc)");
    return;
  } catch (TOPOLOGY::CannotFetchLink) {

    zlog_debug("[ERR] CORBA: Exception CannotFetchLink (method teLinkAppendIsc)");
    return;
  } catch (TOPOLOGY::LinkParamsMismatch) {

    zlog_debug("[ERR] CORBA: Exception LinkParamsMismatch (method teLinkAppendIsc)");
    return;
  } catch (TOPOLOGY::InvocationNotAllowed) {

    zlog_debug("[ERR] CORBA: Exception InvocationNotAllowed (method teLinkAppendIsc)");
    return;
  } catch (TOPOLOGY::InternalProblems & e) {

    zlog_debug("[ERR] CORBA: Exception InternalProblems (method teLinkAppendIsc): %s", (char *) e.what);
    return;
  } catch (...) {

    zlog_debug("[ERR] CORBA: Exception Unknown (method teLinkAppendIsc)");
    return;
  }
#endif // TOPOLOGY_CLIENTS_ON
  return;
}

} //extern "C"

#endif // HAVE_OMNIORB
