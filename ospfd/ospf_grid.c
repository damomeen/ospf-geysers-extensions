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
 *  Adam Kaliszan         (PSNC)             <kaliszan_at_man.poznan.pl>
 *  Damian Parniewicz     (PSNC)             <damianp_at_man.poznan.pl>
 *  Lukasz Lopatowski     (PSNC)             <llopat_at_man.poznan.pl>
 *  Jakub Gutkowski       (PSNC)             <jgutkow_at_man.poznan.pl>
 */

#include <zebra.h>

#ifndef HAVE_OPAQUE_LSA
#error "Wrong configure option"
#endif /* HAVE_OPAQUE_LSA */

#include "linklist.h"

#include "prefix.h"
#include "if.h"
#include "table.h"
#include "memory.h"
#include "command.h"
#include "vty.h"
#include "stream.h"
#include "log.h"

#include "thread.h"
#include "hash.h"
#include "sockunion.h"        /* for inet_aton() */

#include "ospfd/ospfd.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_grid.h"
#include "ospfd/ospf_ism.h"
#include "ospfd/ospf_asbr.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_lsdb.h"
#include "ospfd/ospf_neighbor.h"
#include "ospfd/ospf_nsm.h"
#include "ospfd/ospf_flood.h"
#include "ospfd/ospf_packet.h"
#include "ospfd/ospf_spf.h"
#include "ospfd/ospf_dump.h"
#include "ospfd/ospf_route.h"

#include "ospfd/ospf_ase.h"
#include "ospfd/ospf_zebra.h"
#include "ospfd/ospf_grid.h"
#include "ospfd/ospf_corba.h"
#include "ospfd/ospf_opaque.h"

struct ospf_grid OspfGRID;

/**
 * ospf interface state 
 */
enum oifstate {
    OI_ANY, OI_DOWN, OI_UP
};

enum type_of_lsa_grid_info {
  GRIDSITE = GRID_TLV_GRIDSITE,                         /** Grid Side Property TLV */
  GRIDSERVICE = GRID_TLV_GRIDSERVICE,                   /** Grid Service Property TLV */
  GRIDCOMPUTINGELEMENT = GRID_TLV_GRIDCOMPUTINGELEMENT, /** Grid Computing Element Property TLV */
  GRIDSUBCLUSTER = GRID_TLV_GRIDSUBCLUSTER,             /** Grid SubCluster Property TLV */
  GRIDSTORAGE = GRID_TLV_GRIDSTORAGE                    /** Grid Storage Element Property TLV */
};

static u_int32_t get_grid_instance_value   (void);

#if USE_UNTESTED_OSPF_GRID_CORBA_UPDATE
static void      update_grid_inf_from_lsdb (int server);
#endif /* #if USE_UNTESTED_OSPF_GRID_CORBA_UPDATE */

static int  ospf_grid_new_if               (struct interface *ifp);
static int  ospf_grid_del_if               (struct interface *ifp);
static void ospf_grid_ism_change           (struct ospf_interface *oi, int old_status);
static void ospf_grid_nsm_change           (struct ospf_neighbor *nbr, int old_status);
static void ospf_grid_config_write_if      (struct vty *vty, struct interface *ifp);
static int  ospf_grid_lsa_originate        (void *arg);
static void ospf_grid_lsa_refresh          (struct ospf_lsa *lsa);
static void ospf_grid_show_info            (struct vty *vtrmy, struct ospf_lsa *lsa);
static void ospf_grid_register_vty         (void);

static void uni_to_inni                    (struct ospf_lsa *lsa, int flush);
static void inni_to_uni                    (struct ospf_lsa *lsa, int flush);
static void inni_to_enni                   (struct ospf_lsa *lsa, int flush);
static void enni_to_inni                   (struct ospf_lsa *lsa, int flush);

static int  ospf_grid_new_lsa              (struct ospf_lsa *lsa);
static int  ospf_grid_del_lsa              (struct ospf_lsa *lsa);

void   ospf_grid_site_lsa_schedule         (struct grid_node_site       *gn_site,       enum grid_sched_opcode opcode);
void   ospf_grid_storage_lsa_schedule      (struct grid_node_storage    *gn_storage,    enum grid_sched_opcode opcode);
void   ospf_grid_computing_lsa_schedule    (struct grid_node_computing  *gn_computing,  enum grid_sched_opcode opcode);
void   ospf_grid_subcluster_lsa_schedule   (struct grid_node_subcluster *gn_subcluster, enum grid_sched_opcode opcode);
void   ospf_grid_service_lsa_schedule      (struct grid_node_service    *gn_service,    enum grid_sched_opcode opcode);

static struct ospf_lsa*             ospf_grid_site_lsa_new       (struct ospf_area *area, struct grid_node_site       *gn_site);
static struct ospf_lsa*             ospf_grid_service_lsa_new    (struct ospf_area *area, struct grid_node_service    *gn_service);
static struct ospf_lsa*             ospf_grid_storage_lsa_new    (struct ospf_area *area, struct grid_node_storage    *gn_storage);
static struct ospf_lsa*             ospf_grid_subcluster_lsa_new (struct ospf_area *area, struct grid_node_subcluster *gn_subcluster);
static struct ospf_lsa*             ospf_grid_computing_lsa_new  (struct ospf_area *area, struct grid_node_computing  *gn_computing);

static struct grid_node*            lookup_grid_node_by_ifp                     (struct interface *ifp);
static struct grid_node_site*       lookup_grid_node_site_by_lsa_instance       (struct ospf_lsa *lsa);
static struct grid_node_service*    lookup_grid_node_service_by_lsa_instance    (struct ospf_lsa *lsa);
static struct grid_node_computing*  lookup_grid_node_computing_by_lsa_instance  (struct ospf_lsa *lsa);
static struct grid_node_subcluster* lookup_grid_node_subcluster_by_lsa_instance (struct ospf_lsa *lsa);
static struct grid_node_storage*    lookup_grid_node_storage_by_lsa_instance    (struct ospf_lsa *lsa);

static void                         log_summary_grid_lsa                        (char *buf, struct ospf_lsa *lsa);

static void
del_mytype_grid_node_service (void *val)
{
  /* there is no list inside the struct grid_tlv_GridService*/ 
  ospf_grid_service_lsa_schedule((struct grid_node_service *)(val), GRID_FLUSH_THIS_LSA);
  XFREE (MTYPE_OSPF_GRID_SERVICE, val);   //TODO it may crash quagga
  return;
}

static void
del_mytype_grid_node_storage (void *val)
{
#ifdef USE_UNTESTED_OSPF_GRID
  struct grid_node_storage *gn_storage = (struct grid_node_storage *) val;
  ospf_grid_storage_lsa_schedule(gn_storage, GRID_FLUSH_THIS_LSA);
//TODO it may crash quagga
  list_delete_all_node(&gn_storage->gridStorage.seCalendar.seCalendar);
  list_delete_all_node(&gn_storage->gridStorage.name.name);
#endif /* USE_UNTESTED_OSPF_GRID */
  XFREE (MTYPE_OSPF_GRID_STORAGE, val);
  return;
}

static void
del_mytype_grid_node_computing (void *val)
{
#ifdef USE_UNTESTED_OSPF_GRID
  struct grid_node_computing *gn_computing = (struct grid_node_computing *) val;
  ospf_grid_computing_lsa_schedule(gn_computing, GRID_FLUSH_THIS_LSA);
//TODO it may crash quagga
  list_delete_all_node(&gn_computing->gridCompElement.ceCalendar.ceCalend);
  list_delete_all_node(&gn_computing->gridCompElement.dataDir.dataDirStr);
  list_delete_all_node(&gn_computing->gridCompElement.jobManager.jobManag);
  list_delete_all_node(&gn_computing->gridCompElement.name.name);
#endif /* USE_UNTESTED_OSPF_GRID */
  XFREE (MTYPE_OSPF_GRID_COMPUTING, val);
  return;
}

static void
del_mytype_grid_node_subcluster (void *val)
{
#ifdef USE_UNTESTED_OSPF_GRID
  struct grid_node_subcluster *gn_subcluster = (struct grid_node_subcluster *) val;
  ospf_grid_subcluster_lsa_schedule(gn_subcluster, GRID_FLUSH_THIS_LSA);
//TODO it may crash quagga
  list_delete_all_node(&gn_subcluster->gridSubcluster.subclusterCalendar.subcluster_calendar);
  list_delete_all_node(&gn_subcluster->gridSubcluster.softwarePackage);
  list_delete_all_node(&gn_subcluster->gridSubcluster.name.name);
#endif /* USE_UNTESTED_OSPF_GRID */
  XFREE (MTYPE_OSPF_GRID_SUBCLUSTER, val);
  return;
}

static void
del_mytype_grid_node(void *val)
{
  struct grid_node *gn = (struct grid_node*)(val);
  ospf_grid_site_lsa_schedule(gn->gn_site, GRID_FLUSH_THIS_LSA);
  list_delete_all_node(gn->list_of_grid_node_service);
  list_free(gn->list_of_grid_node_service);
  list_delete_all_node(gn->list_of_grid_node_storage);
  list_free(gn->list_of_grid_node_storage);
  list_delete_all_node(gn->list_of_grid_node_computing);
  list_free(gn->list_of_grid_node_computing);
  list_delete_all_node(gn->list_of_grid_node_subcluster);
  list_free(gn->list_of_grid_node_subcluster);
#ifdef USE_UNTESTED_OSPF_GRID          /* deleting struct grid_tlv_GridSite gn_site */
  list_delete_all_node(&gn->gn_site->gridSite.name.name);
  XFREE(MTYPE_OSPF_GRID_SITE, gn->gn_site);
#endif /* USE_UNTESTED_OSPF_GRID */
  XFREE(MTYPE_OSPF_GRID_NODE, val);
}

static void
del_mytype_se_calendar (void *val)
{
  XFREE (MTYPE_OSPF_GRID_SERVICE_CALENDAR, val);
  return;
}
static void
del_mytype_subcluster_calendar (void *val)
{
  XFREE (MTYPE_OSPF_GRID_SUBCLUSTER_CALENDAR, val);
  return;
}
static void
del_mytype_ce_calendar (void *val)
{
  XFREE (MTYPE_OSPF_GRID_COMPUTING_CALENDAR, val);
  return;
}

static void
del_mytype_str_char (void *val)
{
  XFREE (MTYPE_OSPF_STR_CHAR, val);
  return;
}

static void
del_mytype_storage_area (void *val)
{
  struct grid_tlv_GridStorage_StorageArea *StArea = (struct grid_tlv_GridStorage_StorageArea*) val;

  list_delete_all_node(&StArea->name);
  list_delete_all_node(&StArea->path);
  XFREE(MTYPE_OSPF_GRID_STRAGE_AREA, val);
  return;
}

static void
del_mytype_SoftwarePackage(void *val)
{
  struct grid_tlv_GridSubCluster_SoftwarePackage* softwarePackage = (struct grid_tlv_GridSubCluster_SoftwarePackage*) val;
  list_delete_all_node(&softwarePackage->environmentSetup);
  XFREE(MTYPE_OSPF_GRID_SUBCLUSTER_SOFT_PACKAGE, val);
  return;
}

void 
delete_grid_node_service (struct grid_node *gn, struct grid_node_service *gn_service)
{
  listnode_delete_with_data(gn->list_of_grid_node_service, gn_service);
  return;
}

void
delete_grid_node_storage (struct grid_node *gn, struct grid_node_storage *gn_storage)
{
  listnode_delete_with_data(gn->list_of_grid_node_storage, gn_storage);
  return;
}

void
delete_grid_node_computing (struct grid_node *gn, struct grid_node_computing *gn_computing)
{
  listnode_delete_with_data(gn->list_of_grid_node_computing, gn_computing);
  return;
}

void 
delete_grid_node_subcluster (struct grid_node *gn, struct grid_node_subcluster *gn_subcluster)
{
  listnode_delete_with_data(gn->list_of_grid_node_subcluster, gn_subcluster);
  return;
}

static void
set_grid_tlv_GridSite (struct grid_node_site *gn_site)
{
  gn_site->gridSite.header.type = htons(GRID_TLV_GRIDSITE);
  int len = 0;
  if (gn_site->gridSite.id.header.length > 0) len += ROUNDUP(ntohs(gn_site->gridSite.id.header.length)+4, 4);
  if (gn_site->gridSite.name.header.length > 0) len += ROUNDUP(ntohs(gn_site->gridSite.name.header.length)+4, 4);
  if (gn_site->gridSite.latitude.header.length > 0) len += ROUNDUP(ntohs(gn_site->gridSite.latitude.header.length)+4, 4);
  if (gn_site->gridSite.longitude.header.length > 0) len += ROUNDUP(ntohs(gn_site->gridSite.longitude.header.length)+4, 4);
  if (gn_site->gridSite.peRouter_id.header.length > 0) len += ROUNDUP(ntohs(gn_site->gridSite.peRouter_id.header.length)+4, 4);
  gn_site->gridSite.header.length = htons(len);
  return;
}

void
set_grid_tlv_GridSite_ID (struct grid_node_site *gn_site, uint32_t id)
{
  gn_site->gridSite.id.header.type = htons(GRID_TLV_GRIDSITE_ID);
  gn_site->gridSite.id.header.length = htons(GRID_TLV_GRIDSITE_ID_CONST_DATA_LENGTH);
  gn_site->gridSite.id.id = htonl(id);
  set_grid_tlv_GridSite(gn_site);
  return;
}

void
set_grid_tlv_GridSite_Name (struct grid_node_site *gn_site, const char* name)
{
  char *n_value;
  gn_site->gridSite.name.name.del = del_mytype_str_char;
  list_delete_all_node(&gn_site->gridSite.name.name);

  while (*(name) != '\0')
  {
    n_value = XMALLOC (MTYPE_OSPF_STR_CHAR, sizeof(char));
    *(n_value) = *(name++);
    listnode_add (&gn_site->gridSite.name.name, n_value);
  }

  gn_site->gridSite.name.header.type = htons(GRID_TLV_GRIDSITE_NAME);
  gn_site->gridSite.name.header.length = htons(gn_site->gridSite.name.name.count);
  set_grid_tlv_GridSite(gn_site);
  return;
}

void
set_grid_tlv_GridSite_Latitude (struct grid_node_site *gn_site, uint8_t *latitude)
{
  int i;
  gn_site->gridSite.latitude.header.type = htons(GRID_TLV_GRIDSITE_LATITUDE);
  gn_site->gridSite.latitude.header.length = htons(GRID_TLV_GRIDSITE_LATITUDE_CONST_DATA_LENGTH);
  for (i = 0;i < 5;i++)
    gn_site->gridSite.latitude.latitude[i] = latitude[4-i];
  set_grid_tlv_GridSite(gn_site);
  return;
}

void
set_grid_tlv_GridSite_Longitude (struct grid_node_site *gn_site, uint8_t *longitude)
{
  int i;
  gn_site->gridSite.longitude.header.type = htons(GRID_TLV_GRIDSITE_LONGITUDE);
  gn_site->gridSite.longitude.header.length = htons(GRID_TLV_GRIDSITE_LONGITUDE_CONST_DATA_LENGTH);
  for (i = 0;i < 5;i++) gn_site->gridSite.longitude.longitude[i] = longitude[4-i];
    set_grid_tlv_GridSite(gn_site);
  return;
}

void
set_grid_tlv_GridSite_PE_Router_ID (struct grid_node_site *gn_site, struct in_addr id)
{
  gn_site->gridSite.peRouter_id.header.type = htons(GRID_TLV_GRIDSITE_PEROUTERID);
  gn_site->gridSite.peRouter_id.header.length = htons(GRID_TLV_GRIDSITE_PEROUTERID_CONST_DATA_LENGTH);
  gn_site->gridSite.peRouter_id.routerID = id;
  set_grid_tlv_GridSite(gn_site);
  return;
}

static void
set_grid_tlv_GridService (struct grid_node_service *gn_service)
{
  gn_service->gridService.header.type = htons(GRID_TLV_GRIDSERVICE);
  gn_service->gridService.header.length = htons(GRID_TLV_GRIDSERVICE_CONST_DATA_LENGTH);
  return;
}

void
set_grid_tlv_GridService_ID (struct grid_node_service *gn_service, uint32_t id)
{
  gn_service->gridService.id.header.type = htons(GRID_TLV_GRIDSERVICE_ID);
  gn_service->gridService.id.header.length = htons(GRID_TLV_GRIDSERVICE_ID_CONST_DATA_LENGTH);
  gn_service->gridService.id.id = htonl(id);
  set_grid_tlv_GridService(gn_service);
  return;
}

void
set_grid_tlv_GridService_ParentSite_ID (struct grid_node_service *gn_service, uint32_t parent_site_id)
{
  gn_service->gridService.parentSite_id.header.type = htons(GRID_TLV_GRIDSERVICE_PARENTSITE_ID);
  gn_service->gridService.parentSite_id.header.length = htons(GRID_TLV_GRIDSERVICE_PARENTSITE_ID_CONST_DATA_LENGTH);
  gn_service->gridService.parentSite_id.parent_site_id = htonl(parent_site_id);
  set_grid_tlv_GridService(gn_service);
  return;
}

void
set_grid_tlv_GridService_ServiceInfo (struct grid_node_service *gn_service, uint16_t type, uint16_t version)
{
  gn_service->gridService.serviceInfo.header.type = htons(GRID_TLV_GRIDSERVICE_SERVICEINFO);
  gn_service->gridService.serviceInfo.header.length = htons(GRID_TLV_GRIDSERVICE_SERVICEINFO_CONST_DATA_LENGTH);
  gn_service->gridService.serviceInfo.type = htons(type);
  gn_service->gridService.serviceInfo.version = htons(version);
  set_grid_tlv_GridService(gn_service);
  return;
}

void
set_grid_tlv_GridService_Status (struct grid_node_service *gn_service, char status)
{
  gn_service->gridService.status.header.type = htons(GRID_TLV_GRIDSERVICE_STATUS);
  gn_service->gridService.status.header.length = htons(GRID_TLV_GRIDSERVICE_STATUS_CONST_DATA_LENGTH);
  gn_service->gridService.status.status = (status);
  set_grid_tlv_GridService(gn_service);
  return;
}

void
set_grid_tlv_GridService_AddressLength (struct grid_node_service *gn_service, char addressLength)
{
  gn_service->gridService.addressLength.header.type = htons(GRID_TLV_GRIDSERVICE_ADDRESSLENGTH);
  gn_service->gridService.addressLength.header.length = htons(GRID_TLV_GRIDSERVICE_ADDRESSLENGTH_CONST_DATA_LENGTH);
  gn_service->gridService.addressLength.addressLength = addressLength;
  set_grid_tlv_GridService(gn_service);
  return;
}

void
set_grid_tlv_GridService_IPv4Endpoint (struct grid_node_service *gn_service, struct in_addr ipv4Endp)
{
  gn_service->gridService.ipv4Endpoint.header.type = htons(GRID_TLV_GRIDSERVICE_IPV4ENDPOINT);
  gn_service->gridService.ipv4Endpoint.header.length = htons(GRID_TLV_GRIDSERVICE_IPV4ENDPOINT_CONST_DATA_LENGTH);
  gn_service->gridService.ipv4Endpoint.ipv4Endp = ipv4Endp;
  set_grid_tlv_GridService(gn_service);
  return;
}

void
set_grid_tlv_GridService_IPv6Endpoint (struct grid_node_service *gn_service, struct in6_addr ipv6Endp)
{
  gn_service->gridService.ipv6Endpoint.header.type = htons(GRID_TLV_GRIDSERVICE_IPV6ENDPOINT);
  gn_service->gridService.ipv6Endpoint.header.length = htons(GRID_TLV_GRIDSERVICE_IPV6ENDPOINT_CONST_DATA_LENGTH);
  gn_service->gridService.ipv6Endpoint.ipv6Endp = ipv6Endp;
  set_grid_tlv_GridService(gn_service);
  return;
}


void
set_grid_tlv_GridService_NsapEndpoint (struct grid_node_service *gn_service, uint32_t nsapEndp[])
{
  int i;
  gn_service->gridService.nsapEndpoint.header.type = htons(GRID_TLV_GRIDSERVICE_NSAPENDPOINT);
  gn_service->gridService.nsapEndpoint.header.length = htons(GRID_TLV_GRIDSERVICE_NSAPENDPOINT_CONST_DATA_LENGTH);
  for (i = 0;i < 5;i++) gn_service->gridService.nsapEndpoint.nsapEndp[i] = htonl (nsapEndp[4-i]);
  set_grid_tlv_GridService(gn_service);
  return;
}


static void
set_grid_tlv_GridComputingElement (struct grid_node_computing *gn_computing)
{
  gn_computing->gridCompElement.header.type = htons(GRID_TLV_GRIDCOMPUTINGELEMENT);
  int len = 0;
  len += ROUNDUP(ntohs(gn_computing->gridCompElement.id.header.length)+4, 4);
  len += ROUNDUP(ntohs(gn_computing->gridCompElement.parentSiteId.header.length)+4, 4);
  len += ROUNDUP(ntohs(gn_computing->gridCompElement.lrmsInfo.header.length)+4, 4);
  len += ROUNDUP(ntohs(gn_computing->gridCompElement.addressLength.header.length)+4, 4);
  len += ROUNDUP(ntohs(gn_computing->gridCompElement.ipv4HostName.header.length)+4, 4);
  len += ROUNDUP(ntohs(gn_computing->gridCompElement.ipv6HostName.header.length)+4, 4);
  len += ROUNDUP(ntohs(gn_computing->gridCompElement.nsapHostName.header.length)+4, 4);
  len += ROUNDUP(ntohs(gn_computing->gridCompElement.gatekeeperPort.header.length)+4, 4);
  len += ROUNDUP(ntohs(gn_computing->gridCompElement.jobManager.header.length)+4, 4);
  len += ROUNDUP(ntohs(gn_computing->gridCompElement.dataDir.header.length)+4, 4);
  len += ROUNDUP(ntohs(gn_computing->gridCompElement.defaultSe.header.length)+4, 4);
  len += ROUNDUP(ntohs(gn_computing->gridCompElement.jobsStates.header.length)+4, 4);
  len += ROUNDUP(ntohs(gn_computing->gridCompElement.jobsStats.header.length)+4, 4);
  len += ROUNDUP(ntohs(gn_computing->gridCompElement.jobsTimePerformances.header.length)+4, 4);
  len += ROUNDUP(ntohs(gn_computing->gridCompElement.jobsTimePolicy.header.length)+4, 4);
  len += ROUNDUP(ntohs(gn_computing->gridCompElement.jobsLoadPolicy.header.length)+4, 4);
  len += ROUNDUP(ntohs(gn_computing->gridCompElement.ceCalendar.header.length)+4, 4);
  len += ROUNDUP(ntohs(gn_computing->gridCompElement.name.header.length)+4, 4);
  gn_computing->gridCompElement.header.length = htons(len);
  return;
}

void
set_grid_tlv_GridComputingElement_ID (struct grid_node_computing *gn_computing, uint32_t id)
{
  gn_computing->gridCompElement.id.header.type = htons(GRID_TLV_GRIDCOMPUTINGELEMENT_ID);
  gn_computing->gridCompElement.id.header.length = htons(GRID_TLV_GRIDCOMPUTINGELEMENT_ID_CONST_DATA_LENGTH);
  gn_computing->gridCompElement.id.id = htonl(id);
  set_grid_tlv_GridComputingElement(gn_computing);
  return;
}

void
set_grid_tlv_GridComputingElement_ParentSiteID (struct grid_node_computing *gn_computing, uint32_t parSiteId)
{
  gn_computing->gridCompElement.parentSiteId.header.type = htons(GRID_TLV_GRIDCOMPUTINGELEMENT_PARENTSITEID);
  gn_computing->gridCompElement.parentSiteId.header.length = htons(GRID_TLV_GRIDCOMPUTINGELEMENT_PARENTSITEID_CONST_DATA_LENGTH);
  gn_computing->gridCompElement.parentSiteId.parSiteId = htonl(parSiteId);
  set_grid_tlv_GridComputingElement(gn_computing);
  return;
}

void
set_grid_tlv_GridComputingElement_LrmsInfo (struct grid_node_computing *gn_computing, uint16_t lrmsType, uint16_t lrmsVersion)
{
  gn_computing->gridCompElement.lrmsInfo.header.type = htons(GRID_TLV_GRIDCOMPUTINGELEMENT_LRMSINFO);
  gn_computing->gridCompElement.lrmsInfo.header.length = htons(GRID_TLV_GRIDCOMPUTINGELEMENT_LRMSINFO_CONST_DATA_LENGTH);
  gn_computing->gridCompElement.lrmsInfo.lrmsType = htons(lrmsType);
  gn_computing->gridCompElement.lrmsInfo.lrmsVersion = htons(lrmsVersion);
  set_grid_tlv_GridComputingElement(gn_computing);
  return;
}

void
set_grid_tlv_GridComputingElement_AddressLength (struct grid_node_computing *gn_computing, char addrLength)
{
  gn_computing->gridCompElement.addressLength.header.type = htons(GRID_TLV_GRIDCOMPUTINGELEMENT_ADDRESSLENGTH);
  gn_computing->gridCompElement.addressLength.header.length = htons(GRID_TLV_GRIDCOMPUTINGELEMENT_ADDRESSLENGTH_CONST_DATA_LENGTH);
  gn_computing->gridCompElement.addressLength.addrLength = addrLength;
  set_grid_tlv_GridComputingElement(gn_computing);
  return;
}

void
set_grid_tlv_GridComputingElement_IPv4HostName (struct grid_node_computing *gn_computing, struct in_addr ipv4HostNam)
{
  gn_computing->gridCompElement.ipv4HostName.header.type = htons(GRID_TLV_GRIDCOMPUTINGELEMENT_IPV4HOSTNAME);
  gn_computing->gridCompElement.ipv4HostName.header.length = htons(GRID_TLV_GRIDCOMPUTINGELEMENT_IPV4HOSTNAME_CONST_DATA_LENGTH);
  gn_computing->gridCompElement.ipv4HostName.ipv4HostNam = ipv4HostNam;
  set_grid_tlv_GridComputingElement(gn_computing);
  return;
}


void
set_grid_tlv_GridComputingElement_IPv6HostName (struct grid_node_computing *gn_computing, struct in6_addr ipv6HostNam)
{
  gn_computing->gridCompElement.ipv6HostName.header.type = htons(GRID_TLV_GRIDCOMPUTINGELEMENT_IPV6HOSTNAME);
  gn_computing->gridCompElement.ipv6HostName.header.length = htons(GRID_TLV_GRIDCOMPUTINGELEMENT_IPV6HOSTNAME_CONST_DATA_LENGTH);
  gn_computing->gridCompElement.ipv6HostName.ipv6HostNam = ipv6HostNam;
  set_grid_tlv_GridComputingElement(gn_computing);
  return;
}


void
set_grid_tlv_GridComputingElement_NsapHostName (struct grid_node_computing *gn_computing, uint32_t nsapHostNam[])
{
  int i;
  gn_computing->gridCompElement.nsapHostName.header.type = htons(GRID_TLV_GRIDCOMPUTINGELEMENT_NSAPHOSTNAME);
  gn_computing->gridCompElement.nsapHostName.header.length = htons(GRID_TLV_GRIDCOMPUTINGELEMENT_NSAPHOSTNAME_CONST_DATA_LENGTH);
  for (i = 0;i < 5;i++) gn_computing->gridCompElement.nsapHostName.nsapHostNam[i] = htonl (nsapHostNam[4-i]);
  set_grid_tlv_GridComputingElement(gn_computing);
  return;
}


void
set_grid_tlv_GridComputingElement_GatekeeperPort (struct grid_node_computing *gn_computing, uint32_t gateKPort)
{
  gn_computing->gridCompElement.gatekeeperPort.header.type = htons(GRID_TLV_GRIDCOMPUTINGELEMENT_GATEKEEPERPORT);
  gn_computing->gridCompElement.gatekeeperPort.header.length = htons(GRID_TLV_GRIDCOMPUTINGELEMENT_GATEKEEPERPORT_CONST_DATA_LENGTH);
  gn_computing->gridCompElement.gatekeeperPort.gateKPort = htonl(gateKPort);
  set_grid_tlv_GridComputingElement(gn_computing);
  return;
}

void
set_grid_tlv_GridComputingElement_JobManager (struct grid_node_computing *gn_computing, const char* jobManag)
{
  char *n_value;
  list_delete_all_node(&gn_computing->gridCompElement.jobManager.jobManag);

  while (*(jobManag) != '\0')
  {
    n_value = XMALLOC (MTYPE_OSPF_STR_CHAR, sizeof(char));
    *(n_value) = *(jobManag++);
    listnode_add (&gn_computing->gridCompElement.jobManager.jobManag, n_value);
  }

  gn_computing->gridCompElement.jobManager.header.type = htons(GRID_TLV_GRIDCOMPUTINGELEMENT_JOBMANAGER);
  gn_computing->gridCompElement.jobManager.header.length = htons(gn_computing->gridCompElement.jobManager.jobManag.count);
  set_grid_tlv_GridComputingElement(gn_computing);
  return;
}

void
set_grid_tlv_GridComputingElement_DataDir (struct grid_node_computing *gn_computing, const char* dataDirStr)
{
  char *n_value;
  list_delete_all_node(&gn_computing->gridCompElement.dataDir.dataDirStr);

  while (*(dataDirStr) != '\0')
  {
    n_value = XMALLOC (MTYPE_OSPF_STR_CHAR, sizeof(char));
    *(n_value) = *(dataDirStr++);
    listnode_add (&gn_computing->gridCompElement.dataDir.dataDirStr, n_value);
  }

  gn_computing->gridCompElement.dataDir.header.type = htons(GRID_TLV_GRIDCOMPUTINGELEMENT_DATADIR);
  gn_computing->gridCompElement.dataDir.header.length = htons(gn_computing->gridCompElement.dataDir.dataDirStr.count);
  set_grid_tlv_GridComputingElement(gn_computing);
  return;
}


void
set_grid_tlv_GridComputingElement_DefaultStorageElement (struct grid_node_computing *gn_computing, uint32_t defaultSelement)
{
  gn_computing->gridCompElement.defaultSe.header.type = htons(GRID_TLV_GRIDCOMPUTINGELEMENT_DEFAULTSTORAGEELEMENT);
  gn_computing->gridCompElement.defaultSe.header.length = htons(GRID_TLV_GRIDCOMPUTINGELEMENT_DEFAULTSTORAGEELEMENT_CONST_DATA_LENGTH);
  gn_computing->gridCompElement.defaultSe.defaultSelement = htonl(defaultSelement);
  set_grid_tlv_GridComputingElement(gn_computing);
  return;
}


void
set_grid_tlv_GridComputingElement_JobsStates (struct grid_node_computing *gn_computing, uint16_t freeJobSlots, char status)
{
  gn_computing->gridCompElement.jobsStates.header.type = htons(GRID_TLV_GRIDCOMPUTINGELEMENT_JOBSSTATES);
  gn_computing->gridCompElement.jobsStates.header.length = htons(GRID_TLV_GRIDCOMPUTINGELEMENT_JOBSSTATES_CONST_DATA_LENGTH);
  gn_computing->gridCompElement.jobsStates.freeJobSlots = htons(freeJobSlots);
  gn_computing->gridCompElement.jobsStates.status = (status);
  set_grid_tlv_GridComputingElement(gn_computing);
  return;
}


void
set_grid_tlv_GridComputingElement_JobsStats (struct grid_node_computing *gn_computing, uint32_t runningJobs, uint32_t waitingJobs, uint32_t totalJobs)
{
  gn_computing->gridCompElement.jobsStats.header.type = htons(GRID_TLV_GRIDCOMPUTINGELEMENT_JOBSSTATS);
  gn_computing->gridCompElement.jobsStats.header.length = htons(GRID_TLV_GRIDCOMPUTINGELEMENT_JOBSSTATS_CONST_DATA_LENGTH);
  gn_computing->gridCompElement.jobsStats.runningJobs = htonl(runningJobs);
  gn_computing->gridCompElement.jobsStats.waitingJobs = htonl(waitingJobs);
  gn_computing->gridCompElement.jobsStats.totalJobs = htonl(totalJobs);
  set_grid_tlv_GridComputingElement(gn_computing);
  return;
}

void
set_grid_tlv_GridComputingElement_JobsTimePerformances (struct grid_node_computing *gn_computing, uint32_t estRespTime, uint32_t worstRespTime)
{
  gn_computing->gridCompElement.jobsTimePerformances.header.type = htons(GRID_TLV_GRIDCOMPUTINGELEMENT_JOBSTIMEPERFORMANCES);
  gn_computing->gridCompElement.jobsTimePerformances.header.length = htons(GRID_TLV_GRIDCOMPUTINGELEMENT_JOBSTIMEPERFORMANCES_CONST_DATA_LENGTH);
  gn_computing->gridCompElement.jobsTimePerformances.estRespTime = htonl(estRespTime);
  gn_computing->gridCompElement.jobsTimePerformances.worstRespTime = htonl(worstRespTime);
  set_grid_tlv_GridComputingElement(gn_computing);
  return;
}

void
set_grid_tlv_GridComputingElement_JobsTimePolicy (struct grid_node_computing *gn_computing, uint32_t maxWcTime, uint32_t maxObtWcTime, uint32_t maxCpuTime, uint32_t maxObtCpuTime)
{
  gn_computing->gridCompElement.jobsTimePolicy.header.type = htons(GRID_TLV_GRIDCOMPUTINGELEMENT_JOBSTIMEPOLICY);
  gn_computing->gridCompElement.jobsTimePolicy.header.length = htons(GRID_TLV_GRIDCOMPUTINGELEMENT_JOBSTIMEPOLICY_CONST_DATA_LENGTH);
  gn_computing->gridCompElement.jobsTimePolicy.maxWcTime = htonl(maxWcTime);
  gn_computing->gridCompElement.jobsTimePolicy.maxObtWcTime = htonl(maxObtWcTime);
  gn_computing->gridCompElement.jobsTimePolicy.maxCpuTime = htonl(maxCpuTime);
  gn_computing->gridCompElement.jobsTimePolicy.maxObtCpuTime = htonl(maxObtCpuTime);
  set_grid_tlv_GridComputingElement(gn_computing);
  return;
}


void
set_grid_tlv_GridComputingElement_JobsLoadPolicy (struct grid_node_computing *gn_computing, uint32_t maxTotalJobs, uint32_t maxRunJobs, uint32_t maxWaitJobs, uint16_t assignJobSlots, uint16_t maxSlotsPerJob, char priorityPreemptionFlag)
{
  gn_computing->gridCompElement.jobsLoadPolicy.header.type = htons(GRID_TLV_GRIDCOMPUTINGELEMENT_JOBSLOADPOLICY);
  gn_computing->gridCompElement.jobsLoadPolicy.header.length = htons(GRID_TLV_GRIDCOMPUTINGELEMENT_JOBSLOADPOLICY_CONST_DATA_LENGTH);
  gn_computing->gridCompElement.jobsLoadPolicy.maxTotalJobs = htonl(maxTotalJobs);
  gn_computing->gridCompElement.jobsLoadPolicy.maxRunJobs = htonl(maxRunJobs);
  gn_computing->gridCompElement.jobsLoadPolicy.maxWaitJobs = htonl(maxWaitJobs);
  gn_computing->gridCompElement.jobsLoadPolicy.assignJobSlots = htons(assignJobSlots);
  gn_computing->gridCompElement.jobsLoadPolicy.maxSlotsPerJob = htons(maxSlotsPerJob);
  gn_computing->gridCompElement.jobsLoadPolicy.priorityPreemptionFlag = (priorityPreemptionFlag);
  set_grid_tlv_GridComputingElement(gn_computing);
  return;
}


void
set_grid_tlv_GridComputingElement_CeCalendar (struct grid_node_computing *gn_computing, enum list_opcode l_opcode, void *list_arg)
{
  gn_computing->gridCompElement.ceCalendar.header.type = htons(GRID_TLV_GRIDCOMPUTINGELEMENT_CECALENDAR);

  switch(l_opcode)
  {
    case CREATE:
      memset (&gn_computing->gridCompElement.ceCalendar.ceCalend, 0, sizeof (struct zlist));
      gn_computing->gridCompElement.ceCalendar.ceCalend.del = list_arg;        /* setting pointer to the function that deletes nede contents */
      break;

    case CLEAR:
      list_delete_all_node (&gn_computing->gridCompElement.ceCalendar.ceCalend);
      break;

    case ADD:
      listnode_add(&gn_computing->gridCompElement.ceCalendar.ceCalend, list_arg);
      break;

    case LEAVE:        /* Do nothing */
      break;
  }
  int len = GRID_TLV_GRIDCOMPUTINGELEMENT_CECALENDAR_CONST_DATA_LENGTH;
  len += gn_computing->gridCompElement.ceCalendar.ceCalend.count * 6; /*sizeof(struct ce_calendar)*/
  gn_computing->gridCompElement.ceCalendar.header.length = htons(len);
  set_grid_tlv_GridComputingElement(gn_computing);
  return;
}

void
set_grid_tlv_GridComputingElement_Name (struct grid_node_computing *gn_computing, const char* name)
{
  char *n_value;
  gn_computing->gridCompElement.name.name.del = del_mytype_str_char;
  list_delete_all_node(&gn_computing->gridCompElement.name.name);

  while (*(name) != '\0')
  {
    n_value = XMALLOC (MTYPE_OSPF_STR_CHAR, sizeof(char));
    *(n_value) = *(name++);
    listnode_add (&gn_computing->gridCompElement.name.name, n_value);
  }

  gn_computing->gridCompElement.name.header.type = htons(GRID_TLV_GRIDCOMPUTINGELEMENT_NAME);
  gn_computing->gridCompElement.name.header.length = htons(gn_computing->gridCompElement.name.name.count);
  set_grid_tlv_GridComputingElement(gn_computing);
  return;
}

static void
set_grid_tlv_GridSubCluster (struct grid_node_subcluster *gn_subcluster)
{
  gn_subcluster->gridSubcluster.header.type = htons(GRID_TLV_GRIDSUBCLUSTER);
  int len = 0;
  len += ROUNDUP(ntohs(gn_subcluster->gridSubcluster.id.header.length)+4, 4);
  len += ROUNDUP(ntohs(gn_subcluster->gridSubcluster.parentSiteId.header.length)+4, 4);
  len += ROUNDUP(ntohs(gn_subcluster->gridSubcluster.cpuInfo.header.length)+4, 4);
  len += ROUNDUP(ntohs(gn_subcluster->gridSubcluster.osInfo.header.length)+4, 4);
  len += ROUNDUP(ntohs(gn_subcluster->gridSubcluster.memoryInfo.header.length)+4, 4);

  struct zlistnode *node, *nnode;
  struct grid_tlv_GridSubCluster_SoftwarePackage* softwarePackage;
  for (ALL_LIST_ELEMENTS(&gn_subcluster->gridSubcluster.softwarePackage, node, nnode, softwarePackage))
    len += ROUNDUP(ntohs(softwarePackage->header.length) + 4, 4);

  len += ROUNDUP(ntohs(gn_subcluster->gridSubcluster.subclusterCalendar.header.length)+4, 4);
  len += ROUNDUP(ntohs(gn_subcluster->gridSubcluster.name.header.length)+4, 4);
  gn_subcluster->gridSubcluster.header.length = htons(len);
  return;
}

void
set_grid_tlv_GridSubCluster_ID (struct grid_node_subcluster *gn_subcluster, uint32_t id)
{
  gn_subcluster->gridSubcluster.id.header.type = htons(GRID_TLV_GRIDSUBCLUSTER_ID);
  gn_subcluster->gridSubcluster.id.header.length = htons(GRID_TLV_GRIDSUBCLUSTER_ID_CONST_DATA_LENGTH);
  gn_subcluster->gridSubcluster.id.id = htonl(id);
  set_grid_tlv_GridSubCluster(gn_subcluster);
  return;
}


void
set_grid_tlv_GridSubCluster_ParentSiteID (struct grid_node_subcluster *gn_subcluster, uint32_t parSiteId)
{
  gn_subcluster->gridSubcluster.parentSiteId.header.type = htons(GRID_TLV_GRIDSUBCLUSTER_PARENTSITEID);
  gn_subcluster->gridSubcluster.parentSiteId.header.length = htons(GRID_TLV_GRIDSUBCLUSTER_PARENTSITEID_CONST_DATA_LENGTH);
  gn_subcluster->gridSubcluster.parentSiteId.parSiteId = htonl(parSiteId);
  set_grid_tlv_GridSubCluster(gn_subcluster);
  return;
}


void
set_grid_tlv_GridSubCluster_CpuInfo (struct grid_node_subcluster *gn_subcluster, uint32_t physicalCpus, uint32_t logicalCpus, char cpuArch)
{
  gn_subcluster->gridSubcluster.cpuInfo.header.type = htons(GRID_TLV_GRIDSUBCLUSTER_CPUINFO);
  gn_subcluster->gridSubcluster.cpuInfo.header.length = htons(GRID_TLV_GRIDSUBCLUSTER_CPUINFO_CONST_DATA_LENGTH);
  gn_subcluster->gridSubcluster.cpuInfo.physicalCpus = htonl(physicalCpus);
  gn_subcluster->gridSubcluster.cpuInfo.logicalCpus = htonl(logicalCpus);
  gn_subcluster->gridSubcluster.cpuInfo.cpuArch = (cpuArch);
  set_grid_tlv_GridSubCluster(gn_subcluster);
  return;
}


void
set_grid_tlv_GridSubCluster_OsInfo (struct grid_node_subcluster *gn_subcluster, uint16_t osType, uint16_t osVersion)
{
  gn_subcluster->gridSubcluster.osInfo.header.type = htons(GRID_TLV_GRIDSUBCLUSTER_OSINFO);
  gn_subcluster->gridSubcluster.osInfo.header.length = htons(GRID_TLV_GRIDSUBCLUSTER_OSINFO_CONST_DATA_LENGTH);
  gn_subcluster->gridSubcluster.osInfo.osType = htons(osType);
  gn_subcluster->gridSubcluster.osInfo.osVersion = htons(osVersion);
  set_grid_tlv_GridSubCluster(gn_subcluster);
  return;
}


void
set_grid_tlv_GridSubCluster_MemoryInfo (struct grid_node_subcluster *gn_subcluster, uint32_t ramSize, uint32_t virtualMemorySize)
{
  gn_subcluster->gridSubcluster.memoryInfo.header.type = htons(GRID_TLV_GRIDSUBCLUSTER_MEMORYINFO);
  gn_subcluster->gridSubcluster.memoryInfo.header.length = htons(GRID_TLV_GRIDSUBCLUSTER_MEMORYINFO_CONST_DATA_LENGTH);
  gn_subcluster->gridSubcluster.memoryInfo.ramSize = htonl(ramSize);
  gn_subcluster->gridSubcluster.memoryInfo.virtualMemorySize = htonl(virtualMemorySize);
  set_grid_tlv_GridSubCluster(gn_subcluster);
  return;
}


static struct grid_tlv_GridSubCluster_SoftwarePackage*
create_grid_tlv_GridSubCluster_SoftwarePackage (uint16_t softType, uint16_t softVersion, const char *environmentSetup)
{
  struct grid_tlv_GridSubCluster_SoftwarePackage *sp = XMALLOC(MTYPE_OSPF_GRID_SUBCLUSTER_SOFT_PACKAGE, sizeof(struct  grid_tlv_GridSubCluster_SoftwarePackage));
  memset(sp, 0, sizeof(struct  grid_tlv_GridSubCluster_SoftwarePackage));

  sp->header.type = htons(GRID_TLV_GRIDSUBCLUSTER_SOFTWAREPACKAGE);
  sp->softType    = htons(softType);
  sp->softVersion = htons(softVersion);

  sp->environmentSetup.del = del_mytype_str_char;
  char *n_value;
  while (*(environmentSetup) != '\0')
  {
    n_value = XMALLOC (MTYPE_OSPF_STR_CHAR, sizeof(char));
    *(n_value) = *(environmentSetup++);
    listnode_add (&sp->environmentSetup, n_value);
  }

  sp->header.length = htons(GRID_TLV_GRIDSUBCLUSTER_SOFTWAREPACKAGE_CONST_DATA_LENGTH + sp->environmentSetup.count);
  return sp;
}

void
set_grid_tlv_GridSubCluster_SoftwarePackage (struct grid_node_subcluster *gn_subcluster, enum list_opcode l_opcode, void* list_arg)
{
  switch(l_opcode)
  {
    case CREATE:
      memset (&gn_subcluster->gridSubcluster.softwarePackage, 0, sizeof (struct zlist));
      gn_subcluster->gridSubcluster.softwarePackage.del = list_arg;
      break;

    case CLEAR:
      list_delete_all_node (&gn_subcluster->gridSubcluster.softwarePackage);
      break;

    case ADD:
      listnode_add(&gn_subcluster->gridSubcluster.softwarePackage, list_arg);
      break;

    case LEAVE:
      break;
  }
  set_grid_tlv_GridSubCluster(gn_subcluster);
  return;
}

void
set_grid_tlv_GridSubCluster_SubClusterCalendar (struct grid_node_subcluster *gn_subcluster, enum list_opcode l_opcode, void *list_arg)
{
  gn_subcluster->gridSubcluster.subclusterCalendar.header.type = htons(GRID_TLV_GRIDSUBCLUSTER_SUBCLUSTERCALENDAR);

  switch(l_opcode)
  {
    case CREATE:
      memset (&gn_subcluster->gridSubcluster.subclusterCalendar.subcluster_calendar, 0, sizeof (struct zlist));
      gn_subcluster->gridSubcluster.subclusterCalendar.subcluster_calendar.del = list_arg;        /* setting pointer to the function that deletes nede contents */
      break;

    case CLEAR:
      list_delete_all_node (&gn_subcluster->gridSubcluster.subclusterCalendar.subcluster_calendar);
      break;

    case ADD:
      listnode_add(&gn_subcluster->gridSubcluster.subclusterCalendar.subcluster_calendar, list_arg);
      break;

    case LEAVE:        /* Do nothing */
      break;
  }
  int len = GRID_TLV_GRIDSUBCLUSTER_SUBCLUSTERCALENDAR_CONST_DATA_LENGTH;
  len += 8 * gn_subcluster->gridSubcluster.subclusterCalendar.subcluster_calendar.count;
  gn_subcluster->gridSubcluster.subclusterCalendar.header.length = htons(len);
  set_grid_tlv_GridSubCluster(gn_subcluster);
  return;
}

void
set_grid_tlv_GridSubCluster_Name (struct grid_node_subcluster *gn_subcluster, const char* name)
{
  char *n_value;
  gn_subcluster->gridSubcluster.name.name.del = del_mytype_str_char;
  list_delete_all_node(&gn_subcluster->gridSubcluster.name.name);

  while (*(name) != '\0')
  {
    n_value = XMALLOC (MTYPE_OSPF_STR_CHAR, sizeof(char));
    *(n_value) = *(name++);
    listnode_add (&gn_subcluster->gridSubcluster.name.name, n_value);
  }

  gn_subcluster->gridSubcluster.name.header.type = htons(GRID_TLV_GRIDSUBCLUSTER_NAME);
  gn_subcluster->gridSubcluster.name.header.length = htons(gn_subcluster->gridSubcluster.name.name.count);
  set_grid_tlv_GridSubCluster(gn_subcluster);
  return;
}

void
set_grid_tlv_GridStorage (struct grid_node_storage *gn_storage, enum list_opcode l_opcode, void *list_arg)
{
  switch(l_opcode)
  {
    case CREATE:
      memset (&gn_storage->gridStorage.storageArea, 0, sizeof (struct zlist));
      gn_storage->gridStorage.storageArea.del = list_arg;        /* setting pointer to the function that deletes nede contents */
      break;

    case CLEAR:
      list_delete_all_node (&gn_storage->gridStorage.storageArea);
      break;

    case ADD:
      listnode_add(&gn_storage->gridStorage.storageArea, list_arg);
      break;

    case LEAVE:        /* Do nothing */
      break;
  }

  gn_storage->gridStorage.header.type = htons(GRID_TLV_GRIDSTORAGE);
  int len = 0;
  len += ROUNDUP(ntohs(gn_storage->gridStorage.id.header.length)+4,4);
  len += ROUNDUP(ntohs(gn_storage->gridStorage.parentSiteId.header.length)+4,4);
  len += ROUNDUP(ntohs(gn_storage->gridStorage.storageInfo.header.length)+4,4);
  len += ROUNDUP(ntohs(gn_storage->gridStorage.onlineSize.header.length)+4,4);
  len += ROUNDUP(ntohs(gn_storage->gridStorage.nearlineSize.header.length)+4,4);

  struct zlistnode *node, *nnode;
  struct grid_tlv_GridStorage_StorageArea *StArea;

  for (ALL_LIST_ELEMENTS (&gn_storage->gridStorage.storageArea, node, nnode, StArea))
    len += ROUNDUP(ntohs(StArea->header.length)+4,4);

  len += ROUNDUP(ntohs(gn_storage->gridStorage.seCalendar.header.length)+4,4);
  len += ROUNDUP(ntohs(gn_storage->gridStorage.name.header.length)+4,4);
  gn_storage->gridStorage.header.length = htons(len);
  return;
}

void
set_grid_tlv_GridStorage_ID (struct grid_node_storage *gn_storage, uint32_t id)
{
  gn_storage->gridStorage.id.header.type = htons(GRID_TLV_GRIDSTORAGE_ID);
  gn_storage->gridStorage.id.header.length = htons(GRID_TLV_GRIDSTORAGE_ID_CONST_DATA_LENGTH);
  gn_storage->gridStorage.id.id = htonl(id);
  set_grid_tlv_GridStorage(gn_storage, LEAVE, NULL);
  return;
}


void
set_grid_tlv_GridStorage_ParentSiteID (struct grid_node_storage *gn_storage, uint32_t parSiteId)
{
  gn_storage->gridStorage.parentSiteId.header.type = htons(GRID_TLV_GRIDSTORAGE_PARENTSITEID);
  gn_storage->gridStorage.parentSiteId.header.length = htons(GRID_TLV_GRIDSTORAGE_PARENTSITEID_CONST_DATA_LENGTH);
  gn_storage->gridStorage.parentSiteId.parSiteId = htonl(parSiteId);
  set_grid_tlv_GridStorage(gn_storage, LEAVE, NULL);
  return;
}


void
set_grid_tlv_GridStorage_StorageInfo (struct grid_node_storage *gn_storage, uint32_t storInfo)
{
  gn_storage->gridStorage.storageInfo.header.type = htons(GRID_TLV_GRIDSTORAGE_STORAGEINFO);
  gn_storage->gridStorage.storageInfo.header.length = htons(GRID_TLV_GRIDSTORAGE_STORAGEINFO_CONST_DATA_LENGTH);
  gn_storage->gridStorage.storageInfo.storInfo = htonl(storInfo);
  set_grid_tlv_GridStorage(gn_storage, LEAVE, NULL);
  return;
}


void
set_grid_tlv_GridStorage_OnlineSize (struct grid_node_storage *gn_storage, uint32_t totalSize, uint32_t usedSize)
{
  gn_storage->gridStorage.onlineSize.header.type = htons(GRID_TLV_GRIDSTORAGE_ONLINESIZE);
  gn_storage->gridStorage.onlineSize.header.length = htons(GRID_TLV_GRIDSTORAGE_ONLINESIZE_CONST_DATA_LENGTH);
  gn_storage->gridStorage.onlineSize.totalSize = htonl(totalSize);
  gn_storage->gridStorage.onlineSize.usedSize = htonl(usedSize);
  set_grid_tlv_GridStorage(gn_storage, LEAVE, NULL);
  return;
}


void
set_grid_tlv_GridStorage_NearlineSize (struct grid_node_storage *gn_storage, uint32_t totalSize, uint32_t usedSize)
{
  gn_storage->gridStorage.nearlineSize.header.type = htons(GRID_TLV_GRIDSTORAGE_NEARLINESIZE);
  gn_storage->gridStorage.nearlineSize.header.length = htons(GRID_TLV_GRIDSTORAGE_NEARLINESIZE_CONST_DATA_LENGTH);
  gn_storage->gridStorage.nearlineSize.totalSize = htonl(totalSize);
  gn_storage->gridStorage.nearlineSize.usedSize = htonl(usedSize);
  set_grid_tlv_GridStorage(gn_storage, LEAVE, NULL);
  return;
}

static struct grid_tlv_GridStorage_StorageArea*
create_grid_tlv_GridStorage_StorageArea (const char * name, const char * path, uint32_t totalOnlineSize, uint32_t freeOnlineSize, uint32_t resTotalOnlineSize, uint32_t totalNearlineSize, uint32_t freeNearlineSize, uint32_t resNearlineSize, char retPolAccLat, char expirationMode)
{
  struct grid_tlv_GridStorage_StorageArea *result = XMALLOC(MTYPE_OSPF_GRID_STRAGE_AREA, sizeof(struct grid_tlv_GridStorage_StorageArea));
  memset(result, 0, sizeof (struct grid_tlv_GridStorage_StorageArea));
  result->name.del = del_mytype_str_char;
  result->path.del = del_mytype_str_char;

  char *n_value;
  int i = 0;

  while (*(name) != '\0')
  {
    n_value = XMALLOC (MTYPE_OSPF_STR_CHAR, sizeof(char));
    *(n_value) = *(name++);
    listnode_add (&result->name, n_value);
    i++;
  }
  do
  {
    n_value = XMALLOC (MTYPE_OSPF_STR_CHAR, sizeof(char));
    *(n_value) = '\0';
    listnode_add (&result->name, n_value);
    i++;
  }
  while (i % 4 != 0);

  while (*(path) != '\0')
  {
    n_value = XMALLOC (MTYPE_OSPF_STR_CHAR, sizeof(char));
    *(n_value) = *(path++);
    listnode_add (&result->path, n_value);
    i++;
  }
  do
  {
    n_value = XMALLOC (MTYPE_OSPF_STR_CHAR, sizeof(char));
    *(n_value) = '\0';
    listnode_add (&result->path, n_value);
    i++;
  }
  while (i % 4 != 0);

  result->totalOnlineSize = htonl(totalOnlineSize);
  result->freeOnlineSize = htonl(freeOnlineSize);
  result->resTotalOnlineSize = htonl(resTotalOnlineSize);
  result->totalNearlineSize = htonl(totalNearlineSize);
  result->freeNearlineSize = htonl(freeNearlineSize);
  result->resNearlineSize = htonl(resNearlineSize);
  result->retPolAccLat = (retPolAccLat);
  result->expirationMode = (expirationMode);

  result->header.type = htons(GRID_TLV_GRIDSTORAGE_STORAGEAREA);
  result->header.length = htons(GRID_TLV_GRIDSTORAGE_STORAGEAREA_CONST_DATA_LENGTH + result->name.count + result->path.count);

  return result;
}


void
set_grid_tlv_GridStorage_SeCalendar (struct grid_node_storage *gn_storage, enum list_opcode l_opcode, void *list_arg)
{
  gn_storage->gridStorage.seCalendar.header.type = htons(GRID_TLV_GRIDSTORAGE_SECALENDAR);

  switch(l_opcode)
  {
    case CREATE:
      memset (&gn_storage->gridStorage.seCalendar.seCalendar, 0, sizeof (struct zlist));
      gn_storage->gridStorage.seCalendar.seCalendar.del = list_arg;        /* setting pointer to the function that deletes nede contents */
      break;

    case CLEAR:
      list_delete_all_node (&gn_storage->gridStorage.seCalendar.seCalendar);
      break;


    case ADD:
      listnode_add(&gn_storage->gridStorage.seCalendar.seCalendar, list_arg);
      break;

    case LEAVE:        /* Do nothing */
      break;
  }
  int len = GRID_TLV_GRIDSTORAGE_SECALENDAR_CONST_DATA_LENGTH;
  len += 12 * gn_storage->gridStorage.seCalendar.seCalendar.count;
  gn_storage->gridStorage.seCalendar.header.length = htons(len);
  set_grid_tlv_GridStorage(gn_storage, LEAVE, NULL);
  return;
}

void
set_grid_tlv_GridStorage_Name (struct grid_node_storage *gn_storage, const char* name)
{
  char *n_value;
  gn_storage->gridStorage.name.name.del = del_mytype_str_char;
  list_delete_all_node(&gn_storage->gridStorage.name.name);

  while (*(name) != '\0')
  {
    n_value = XMALLOC (MTYPE_OSPF_STR_CHAR, sizeof(char));
    *(n_value) = *(name++);
    listnode_add (&gn_storage->gridStorage.name.name, n_value);
  }

  gn_storage->gridStorage.name.header.type = htons(GRID_TLV_GRIDSTORAGE_NAME);
  gn_storage->gridStorage.name.header.length = htons(gn_storage->gridStorage.name.name.count);
  set_grid_tlv_GridStorage(gn_storage, LEAVE, NULL);
  return;
}

int 
initialize_grid_node_params (struct grid_node *gn)
{
  struct interface *ifp = gn->ifp;
  if (ifp == NULL)
  {
    zlog_warn("[WRN] INITIALIZE_GRID_NODE_PARAMS: ifp == NULL");
    return -1;
  }

/*struct ospf_interface *oi;
  float fval;
  int i;grid-node service ID

  if ((oi = lookup_oi_by_ifp (ifp, NULL, OI_ANY)) == NULL)
    return; */

  /** Try to set initial values those can be derived from ??? no specyfication */
  gn->gn_site = XMALLOC(MTYPE_OSPF_GRID_SITE, sizeof(struct grid_node_site));
  memset (gn->gn_site, 0, sizeof (struct grid_node_site));

  gn->gn_site->base.gn=gn;
  gn->gn_site->base.instance_no = get_grid_instance_value ();

  /** setting default parameters for Unique Identifier of the Site */
  /* set_grid_tlv_GridSite_ID(gn->gn_site, 0); */

  /** setting default parameters for Human-readable name */
  /* char nam[] = "";
  set_grid_tlv_GridSite_Name(gn->gn_site, nam); */

  /** setting default parameters for Degree the position of a place north or south of the equator */
  /* uint8_t lat[5];
  lat[0] = 0; lat[1] = 0; lat[2] = 0; lat[3] = 0; lat[4] = 0;
  set_grid_tlv_GridSite_Latitude(gn->gn_site, lat); */

  /** setting default parameters for Degree the position of a place east or west of Greenwich */
  /* uint8_t lon[5];
  lon[0] = 0; lon[1] = 0; lon[2] = 0; lon[3] = 0; lon[4] = 0;
  set_grid_tlv_GridSite_Longitude(gn->gn_site, lon); */

  /** setting default parameters for PE router id */
  struct in_addr address_ip4;
  inet_aton ("0.0.0.0", &address_ip4);
  set_grid_tlv_GridSite_PE_Router_ID(gn->gn_site, address_ip4);

  gn->list_of_grid_node_service = list_new ();
  gn->list_of_grid_node_service->del = del_mytype_grid_node_service;

  gn->list_of_grid_node_computing = list_new ();
  gn->list_of_grid_node_computing->del = del_mytype_grid_node_computing;

  gn->list_of_grid_node_subcluster = list_new ();
  gn->list_of_grid_node_subcluster->del = del_mytype_grid_node_subcluster;

  gn->list_of_grid_node_storage = list_new ();
  gn->list_of_grid_node_storage->del = del_mytype_grid_node_storage;

  return 0;
}

struct grid_node_service*
create_new_grid_node_service(struct grid_node *gn, uint32_t id)
{
  struct grid_node_service* gn_service;

  gn_service = XMALLOC(MTYPE_OSPF_GRID_SERVICE, sizeof(struct grid_node_service));
  memset(gn_service, 0, sizeof(struct grid_node_service));

  gn_service->base.gn = gn;
  gn_service->base.instance_no = get_grid_instance_value();

  /** setting default parameters for Unique Identifier of the Service */
  set_grid_tlv_GridService_ID(gn_service, id);

  /** setting default parameters for Identifier of the Grid Site that is exporting this service */
  set_grid_tlv_GridService_ParentSite_ID(gn_service, 0);

  /** setting default parameters for The service info including service type and version */
  set_grid_tlv_GridService_ServiceInfo(gn_service, 0, 0);

  /** setting default parameters for Status of the service */
  set_grid_tlv_GridService_Status(gn_service, 0);

  /** setting default parameters for Length of the endpoint address */
  set_grid_tlv_GridService_AddressLength(gn_service, 0);

  /** setting default parameters for Network endpoint for this service */
  struct in_addr address_ip4;
  inet_aton ("0.0.0.0", &address_ip4);
  set_grid_tlv_GridService_IPv4Endpoint(gn_service, address_ip4);

  /** setting default parameters for Network endpoint for this service */
  struct in6_addr address_ip6;
  str2in6_addr ("00000000000000000000000000000000", &address_ip6);
  set_grid_tlv_GridService_IPv6Endpoint(gn_service, address_ip6);

  /** setting default parameters for Network endpoint for this service */
  uint32_t init[5];
  init[0] = 0; init[1] = 0; init[2] = 0; init[3] = 0; init[4] = 0;
  set_grid_tlv_GridService_NsapEndpoint(gn_service, init);

  return gn_service;
}

struct grid_node_computing*  create_new_grid_node_computing(struct grid_node *gn, uint32_t id)
{
  struct grid_node_computing *gn_computing;

  gn_computing = XMALLOC(MTYPE_TMP, sizeof(struct grid_node_computing));
  memset(gn_computing, 0, sizeof(struct grid_node_computing));

  gn_computing->base.gn = gn;
  gn_computing->base.instance_no = get_grid_instance_value();

  /** setting default parameters for Unique Identifier of the Computing Element */
  set_grid_tlv_GridComputingElement_ID(gn_computing, id);

  /** setting default parameters for Identifier of the Grid Site that is exporting this computing element */
  set_grid_tlv_GridComputingElement_ParentSiteID(gn_computing, 0);

  /** setting default parameters for Type and version of the underlying LRMS */
  set_grid_tlv_GridComputingElement_LrmsInfo(gn_computing, 0, 0);

  /** setting default parameters for Length of the host name address */
  set_grid_tlv_GridComputingElement_AddressLength(gn_computing, 0);

  /** setting default parameters for Host name of the machine running this service */
  struct in_addr address_ip4_hn;
  inet_aton ("0.0.0.0", &address_ip4_hn);
  set_grid_tlv_GridComputingElement_IPv4HostName(gn_computing, address_ip4_hn);

  /** setting default parameters for Host name of the machine running this service */
  struct in6_addr address_ip6_hn;
  str2in6_addr ("00000000000000000000000000000000", &address_ip6_hn);
  set_grid_tlv_GridComputingElement_IPv6HostName(gn_computing, address_ip6_hn);

  /** setting default parameters for Host name of the machine running this service */
  uint32_t init1[5];
  init1[0] = 0; init1[1] = 0; init1[2] = 0; init1[3] = 0; init1[4] = 0;
  set_grid_tlv_GridComputingElement_NsapHostName(gn_computing, init1);

  /** setting default parameters for Gatekeeper port */
  set_grid_tlv_GridComputingElement_GatekeeperPort(gn_computing, 0);

  /** setting default parameters for The job manager used by the gatekeeper */
  memset (&gn_computing->gridCompElement.jobManager.jobManag, 0, sizeof (struct zlist));
  gn_computing->gridCompElement.jobManager.jobManag.del = del_mytype_str_char;       /* setting pointer to the function that deletes nede contents */
  char empty_str[] = "";
  set_grid_tlv_GridComputingElement_JobManager(gn_computing, empty_str);

  /** setting default parameters for String representing the path of a run directory */
  memset (&gn_computing->gridCompElement.dataDir.dataDirStr, 0, sizeof (struct zlist));
  gn_computing->gridCompElement.dataDir.dataDirStr.del = del_mytype_str_char;       /* setting pointer to the function that deletes nede contents */
  set_grid_tlv_GridComputingElement_DataDir(gn_computing, empty_str);

  /** setting default parameters for The unique identifier of the default Storage Element */
  set_grid_tlv_GridComputingElement_DefaultStorageElement(gn_computing, 0);

  /** setting default parameters for It contains the number of free job slots, and the queue status */
  set_grid_tlv_GridComputingElement_JobsStates(gn_computing, 0, 0);

  /** setting default parameters for It contains the number of jobs in running, waiting, any state */
  set_grid_tlv_GridComputingElement_JobsStats(gn_computing, 0, 0, 0);

  /** setting default parameters for The estimated time and the worst time to last for a new job from the acceptance to the start of its execution */
  set_grid_tlv_GridComputingElement_JobsTimePerformances(gn_computing, 0, 0);

  /** setting default parameters for The maximum wall clock time, the maximum obtainable wall clock time, the default maximum CPU time allowed to each job by the batch system and finally the maximum obtainable CPU time that can be granted to the job upon user request */
  set_grid_tlv_GridComputingElement_JobsTimePolicy(gn_computing, 0, 0, 0, 0);

  /** setting default parameters for Jobs Load Policy */
  set_grid_tlv_GridComputingElement_JobsLoadPolicy(gn_computing, 0, 0, 0, 0, 0, 0);

  /** setting default parameters for The jobs scheduling calendar reporting the available FreeJobsSlots for each timestamp */
  set_grid_tlv_GridComputingElement_CeCalendar(gn_computing, CREATE, del_mytype_ce_calendar);

  /** setting computing element name */
  memset (&gn_computing->gridCompElement.name.name, 0, sizeof (struct zlist));
  gn_computing->gridCompElement.name.name.del = del_mytype_str_char;
  set_grid_tlv_GridComputingElement_Name(gn_computing, empty_str);

  return gn_computing;
}

struct grid_node_subcluster* create_new_grid_node_subcluster(struct grid_node *gn, uint32_t id)
{
  struct grid_node_subcluster *gn_subcluster;

  gn_subcluster = XMALLOC(MTYPE_TMP, sizeof(struct grid_node_subcluster));
  memset(gn_subcluster, 0, sizeof(struct grid_node_subcluster));

  gn_subcluster->base.gn = gn;
  gn_subcluster->base.instance_no = get_grid_instance_value();

  /** setting default parameters for Unique Identifier of the Sub-Cluster */
  set_grid_tlv_GridSubCluster_ID(gn_subcluster, id);

  /** setting default parameters for Identifier of the Grid Site that is exporting this sub-cluster */
  set_grid_tlv_GridSubCluster_ParentSiteID(gn_subcluster, 0);

  /** setting default parameters for The CPU architecture, the total and the effective number of CPUs */
  set_grid_tlv_GridSubCluster_CpuInfo(gn_subcluster, 0, 0, 0);

  /** setting default parameters for Information about the type of the OS and its version */
  set_grid_tlv_GridSubCluster_OsInfo(gn_subcluster, 0, 0);

  /** setting default parameters for The amount of RAM and Virtual Memory (in MB) */
  set_grid_tlv_GridSubCluster_MemoryInfo(gn_subcluster, 0, 0);

  /** setting default parameters for StoragePackage list */
  set_grid_tlv_GridSubCluster_SoftwarePackage(gn_subcluster, CREATE, del_mytype_SoftwarePackage);

  /** setting default parameters for The PhysicalCPUs and LogicalCPUs scheduling calendar for each timestamp */
  set_grid_tlv_GridSubCluster_SubClusterCalendar(gn_subcluster, CREATE, del_mytype_subcluster_calendar);

  /** setting subcluster name */
  memset (&gn_subcluster->gridSubcluster.name.name, 0, sizeof (struct zlist));
  gn_subcluster->gridSubcluster.name.name.del = del_mytype_str_char;
  char empty_str[] = "";
  set_grid_tlv_GridSubCluster_Name(gn_subcluster, empty_str);

  return gn_subcluster;
}

struct grid_node_storage*    create_new_grid_node_storage(struct grid_node *gn, uint32_t id)
{
  struct grid_node_storage *gn_storage;
  gn_storage = XMALLOC(MTYPE_TMP, sizeof(struct grid_node_storage));
  memset(gn_storage, 0, sizeof(struct grid_node_storage));

  gn_storage->base.gn = gn;
  gn_storage->base.instance_no = get_grid_instance_value();

  /** setting default parameters for Unique Identifier of the Storage Element */
  set_grid_tlv_GridStorage_ID(gn_storage, id);

  /** setting default parameters for TLV gridStorage*/
  memset (&gn_storage->gridStorage.storageArea, 0, sizeof (struct zlist));
  gn_storage->gridStorage.storageArea.del = del_mytype_storage_area;              /* setting pointer to the function that deletes nede contents */

  /** setting default parameters for Identifier of the Grid Site that is exporting this storage */
  set_grid_tlv_GridStorage_ParentSiteID(gn_storage, 0);

  /** setting default parameters for Information about the storage architecture the status of the SE the access and control protocols */
  set_grid_tlv_GridStorage_StorageInfo(gn_storage, 0);

  /** setting default parameters for The online storage sizes (total + used) in GB */
  set_grid_tlv_GridStorage_OnlineSize(gn_storage, 0, 0);

  /** setting default parameters for The nearline storage sizes (total + used) in GB */
  set_grid_tlv_GridStorage_NearlineSize(gn_storage, 0, 0);

  /** setting default parameters for The FreeOnlineSize and FreeNearlineSize scheduling calendar for each timestamp */
  set_grid_tlv_GridStorage_SeCalendar(gn_storage, CREATE, del_mytype_se_calendar);

  /** setting storage name */
  memset (&gn_storage->gridStorage.name.name, 0, sizeof (struct zlist));
  gn_storage->gridStorage.name.name.del = del_mytype_str_char;
  char empty_str[] = "";
  set_grid_tlv_GridStorage_Name(gn_storage, empty_str);

  return gn_storage;
}


/**
 * Used when ospf-grid is enabled. Function register new function table concerned with ospf-grid, and sets main grid object OspfGRID.
 * @return init result
 */
int ospf_grid_init (void)
{
  int rc;
  rc = ospf_register_opaque_functab (
    OSPF_OPAQUE_AREA_LSA,
    OPAQUE_TYPE_GRID_LSA,
    ospf_grid_new_if,
    ospf_grid_del_if,
    ospf_grid_ism_change,
    ospf_grid_nsm_change,
    NULL,                            /* ospf_grid_config_write_router */
    ospf_grid_config_write_if,
    NULL,                            /* ospf_grid_config_write_debug */
    ospf_grid_show_info,
    ospf_grid_lsa_originate,
    ospf_grid_lsa_refresh,
    ospf_grid_new_lsa,               /* ospf_grid_new_lsa_hook */
    ospf_grid_del_lsa);              /* ospf_grid_del_lsa_hook */
  if (rc != 0)
  {
    zlog_warn ("[WRN] ospf_grid_init: Failed to register functions");
    goto out;
  }
  memset (&OspfGRID, 0, sizeof (struct ospf_grid));
  OspfGRID.status = enabled;        /* GRID enabled */
  OspfGRID.iflist = list_new ();
  OspfGRID.iflist->del = del_mytype_grid_node;
  OspfGRID.grid_ifp = NULL;

#ifdef USE_UNTESTED_OSPF_GRID
  OspfGRID.map_inni      = list_new ();
  OspfGRID.map_inni->del = del_mytype_instance_map_element;

  OspfGRID.map_enni      = list_new ();
  OspfGRID.map_enni->del = del_mytype_instance_map_element;

  OspfGRID.map_uni       = list_new ();
  OspfGRID.map_uni->del  = del_mytype_instance_map_element;
#endif /* USE_UNTESTED_OSPF_GRID */

  OspfGRID.debug = 0;
  ospf_grid_register_vty ();

out:
  return rc;
}

void  ospf_grid_term (void)
{
  list_delete (OspfGRID.iflist);
  OspfGRID.iflist = NULL;

#ifdef USE_UNTESTED_OSPF_GRID
  list_delete (OspfGRID.map_inni);
  OspfGRID.map_inni = NULL;
  list_delete (OspfGRID.map_enni);
  OspfGRID.map_enni = NULL;
  list_delete (OspfGRID.map_uni);
  OspfGRID.map_uni  = NULL;
#endif /* USE_UNTESTED_OSPF_GRID */

  OspfGRID.status = disabled;
  ospf_delete_opaque_functab (OSPF_OPAQUE_AREA_LSA, OPAQUE_TYPE_GRID_LSA);
  return;
}

/**
 * Function returns 16 bit unique value.
 */
static u_int32_t  get_grid_instance_value (void)
{
  static u_int32_t seqno = 0;

  if (LEGAL_GRID_INSTANCE_RANGE (seqno + 1))
    seqno += 1;
  else
    seqno  = 1; /* Avoid zero. */

  return seqno;
}

struct interface*
uni_interface_lookup()
{
  struct interface* ifp = NULL;
  struct zlistnode *node;
  for (ALL_LIST_ELEMENTS_RO (iflist, node, ifp))
  {
    if (ifp->ospf_instance == UNI)
    {
      break;
    }
  }
  return ifp;
}

/**
 * Search a first ospf interface related to Zebra interface in particular state and area
 * @param ifp - pointer to Zebra interface
 * @param area - area filter for ospf interfaces belongs to
 * @param oifstate - state filter for ospf interfaces
 * @return  ospf interface or null 
 */
struct ospf_interface *
lookup_oi_by_ifp (struct interface *ifp)
{
  struct ospf_interface *oi = NULL;
  struct route_node *rn;

  for (rn = route_top (IF_OIFS (ifp)); rn; rn = route_next (rn))
  {
    if ((oi = rn->info) == NULL)
      continue;
    else
      break;
  }
  return oi;
}

/** Search GRID_NODES adherent to Zebra interface  */
static struct grid_node *
lookup_grid_node_by_ifp (struct interface *ifp)
{
  struct zlistnode *node, *nnode;
  struct grid_node *gn;

  for (ALL_LIST_ELEMENTS (OspfGRID.iflist, node, nnode, gn))
    if (gn->ifp == ifp)
      return gn;

  return NULL;
}

struct grid_node*
lookup_grid_node_by_site_id(uint32_t id)
{
  struct zlistnode *node;
  struct grid_node *gn;

  for (ALL_LIST_ELEMENTS_RO (OspfGRID.iflist, node, gn))
  {
    if (ntohl(gn->gn_site->gridSite.id.id) == id)
      return gn;
  }
  return NULL;
}

struct grid_node_service*
lookup_grid_node_service_by_grid_node_and_sub_id(struct grid_node *gn, uint32_t id)
{
  if (gn == NULL)
    return NULL;
  struct zlistnode *node, *nnode;
  struct grid_node_service *gn_service;

  for (ALL_LIST_ELEMENTS (gn->list_of_grid_node_service, node, nnode, gn_service))
  {
    if (ntohl(gn_service->gridService.id.id) == id)
      return gn_service;
  }
  return NULL;
}

struct grid_node_computing*
lookup_grid_node_computing_by_grid_node_and_sub_id(struct grid_node *gn, uint32_t id)
{
  if (gn == NULL)
    return NULL;
  struct zlistnode *node, *nnode;
  struct grid_node_computing *gn_computing;

  for (ALL_LIST_ELEMENTS (gn->list_of_grid_node_computing, node, nnode, gn_computing))
  {
    if (ntohl(gn_computing->gridCompElement.id.id) == id)
      return gn_computing;
  }
  return NULL;
}

struct grid_node_subcluster*
lookup_grid_node_subcluster_by_grid_node_and_sub_id(struct grid_node *gn, uint32_t id)
{
  if (gn == NULL)
    return NULL;
  struct zlistnode *node, *nnode;
  struct grid_node_subcluster *gn_subcluster;

  for (ALL_LIST_ELEMENTS (gn->list_of_grid_node_subcluster, node, nnode, gn_subcluster))
  {
    if (ntohl(gn_subcluster->gridSubcluster.id.id) == id)
      return gn_subcluster;
  }
  return NULL;
}

struct grid_node_storage*
lookup_grid_node_storage_by_grid_node_and_sub_id(struct grid_node *gn, uint32_t id)
{
  if (gn == NULL)
    return NULL;
  struct zlistnode *node, *nnode;
  struct grid_node_storage *gn_storage;

  for (ALL_LIST_ELEMENTS (gn->list_of_grid_node_storage, node, nnode, gn_storage))
  {
    if (ntohl(gn_storage->gridStorage.id.id) == id)
      return gn_storage;
  }
  return NULL;
}

/** Search GRID_NODES with particular instance */
static struct grid_node_site *
lookup_grid_node_site_by_lsa_instance (struct ospf_lsa *lsa)
{
  if (lsa->area->ospf->router_id.s_addr != lsa->data->adv_router.s_addr)
  {
    zlog_warn("[WRN] lookup_grid_node_site_by_lsa_instance: LSA comes from different router");
    return NULL;
  }

  struct zlistnode          *node;
  struct grid_node          *gn;

  unsigned int key = GET_OPAQUE_ID (ntohl (lsa->data->id.s_addr));

  for (ALL_LIST_ELEMENTS_RO (OspfGRID.iflist, node, gn))
  {
      if (gn->gn_site->base.instance_no == key)
        return gn->gn_site;
  }
  return NULL;
}

static struct grid_node_service *
lookup_grid_node_service_by_lsa_instance (struct ospf_lsa *lsa)
{
  if (lsa->area->ospf->router_id.s_addr != lsa->data->adv_router.s_addr)
  {
    zlog_warn("[WRN] lookup_grid_node_service_by_lsa_instance: LSA comes from different router");
    return NULL;
  }

  struct zlistnode          *node, *gn_node;
  struct grid_node          *gn;
  struct grid_node_service  *gn_service;

  unsigned int key = GET_OPAQUE_ID (ntohl (lsa->data->id.s_addr));

  for (ALL_LIST_ELEMENTS_RO (OspfGRID.iflist, node, gn))
  {
    for (ALL_LIST_ELEMENTS_RO(gn->list_of_grid_node_service, gn_node, gn_service))
    {
      if (gn_service->base.instance_no == key)
        return gn_service;
    }
  }
  return NULL;
}

static struct grid_node_computing *
lookup_grid_node_computing_by_lsa_instance (struct ospf_lsa *lsa)
{
  if (lsa->area->ospf->router_id.s_addr != lsa->data->adv_router.s_addr)
  {
    zlog_warn("[WRN] lookup_grid_node_computing_by_lsa_instance: LSA comes from different router");
    return NULL;
  }

  struct zlistnode            *node, *gn_node;
  struct grid_node            *gn;
  struct grid_node_computing  *gn_computing;

  unsigned int key = GET_OPAQUE_ID (ntohl (lsa->data->id.s_addr));

  for (ALL_LIST_ELEMENTS_RO (OspfGRID.iflist, node, gn))
  {
    for (ALL_LIST_ELEMENTS_RO(gn->list_of_grid_node_computing, gn_node, gn_computing))
    {
      if (gn_computing->base.instance_no == key)
        return gn_computing;
    }
  }
  return NULL;
}

static struct grid_node_subcluster *
lookup_grid_node_subcluster_by_lsa_instance (struct ospf_lsa *lsa)
{
  if (lsa->area->ospf->router_id.s_addr != lsa->data->adv_router.s_addr)
  {
    zlog_warn("[WRN] lookup_grid_node_subcluster_by_lsa_instance: LSA comes from different router");
    return NULL;
  }

  struct zlistnode            *node, *gn_node;
  struct grid_node            *gn;
  struct grid_node_subcluster *gn_subcluster;

  unsigned int key = GET_OPAQUE_ID (ntohl (lsa->data->id.s_addr));

  for (ALL_LIST_ELEMENTS_RO (OspfGRID.iflist, node, gn))
  {
    for (ALL_LIST_ELEMENTS_RO(gn->list_of_grid_node_subcluster, gn_node, gn_subcluster))
    {
      if (gn_subcluster->base.instance_no == key)
        return gn_subcluster;
    }
  }
  return NULL;
}

static struct grid_node_storage *
lookup_grid_node_storage_by_lsa_instance (struct ospf_lsa *lsa)
{
  if (lsa->area->ospf->router_id.s_addr != lsa->data->adv_router.s_addr)
  {
    zlog_warn("[WRN] lookup_grid_node_storage_by_lsa_instance: LSA comes from different router");
    return NULL;
  }

  struct zlistnode          *node, *gn_node;
  struct grid_node          *gn;
  struct grid_node_storage  *gn_storage;

  unsigned int key = GET_OPAQUE_ID (ntohl (lsa->data->id.s_addr));

  for (ALL_LIST_ELEMENTS_RO (OspfGRID.iflist, node, gn))
  {
    for (ALL_LIST_ELEMENTS_RO(gn->list_of_grid_node_storage, gn_node, gn_storage))
    {
      if (gn_storage->base.instance_no == key)
        return gn_storage;
    }
  }
  return NULL;
}

#if 0
/**
 * Execute specyfic function on all areas
 * @param (*func) (struct grid_node *gn, enum grid_sched_opcode) - pointer to the function
 * @param grid_sched_opcode - GRID_REORIGINATE_PER_AREA, GRID_REFRESH_THIS_LSA, GRID_FLUSH_THIS_LSA
 * @enum type_of_lsa_grid_info TLV
*/
static void
ospf_grid_node_foreach_area (
  void (*func)(struct grid_node *gn, enum grid_sched_opcode, enum type_of_lsa_grid_info),
  enum grid_sched_opcode sched_opcode, enum type_of_lsa_grid_info lsa_type)
{
  struct zlistnode *node, *nnode; 
  struct zlistnode *node2;
  struct grid_node *gn, *gn2;
  struct ospf_area *area;

  for (ALL_LIST_ELEMENTS (OspfGRID.iflist, node, nnode, gn))
  {
    if ((area = gn->area) == NULL)
      continue;
    if ((lsa_type == GRIDSITE) && (gn->flags & GRIDFLG_GRIDSITE_LSA_LOOKUP_DONE))
     continue;
    if ((lsa_type == GRIDSERVICE) && (gn->flags & GRIDFLG_GRIDSERVICE_LSA_LOOKUP_DONE))
     continue;
    if ((lsa_type == GRIDCOMPUTINGELEMENT) && (gn->flags & GRIDFLG_GRIDCOMPUTINGELEMENT_LSA_LOOKUP_DONE))
     continue;
    if ((lsa_type == GRIDSUBCLUSTER) && (gn->flags & GRIDFLG_GRIDSUBCLUSTER_LSA_LOOKUP_DONE))
     continue;
    if ((lsa_type == GRIDSTORAGE) && (gn->flags & GRIDFLG_GRIDSTORAGE_LSA_LOOKUP_DONE))
     continue;
    if (func != NULL)
      (* func)(gn, sched_opcode, lsa_type);

    for (node2 = listnextnode (node); node2; node2 = listnextnode (node2))
      if ((gn2 = listgetdata (node2)) != NULL)
        if (gn2->area != NULL)
          if (IPV4_ADDR_SAME (&gn2->area->area_id, &area->area_id))
            switch (lsa_type)
            {
              case GRIDSITE:
                gn2->flags |= GRIDFLG_GRIDSITE_LSA_LOOKUP_DONE;
                break;
              case GRIDSERVICE:
                gn2->flags |= GRIDFLG_GRIDSERVICE_LSA_LOOKUP_DONE;
                break;
              case GRIDCOMPUTINGELEMENT:
                gn2->flags |= GRIDFLG_GRIDCOMPUTINGELEMENT_LSA_LOOKUP_DONE;
                break;
              case GRIDSUBCLUSTER:
                gn2->flags |= GRIDFLG_GRIDSUBCLUSTER_LSA_LOOKUP_DONE;
                break;
              case GRIDSTORAGE:
                gn2->flags |= GRIDFLG_GRIDSTORAGE_LSA_LOOKUP_DONE;
                break;
            }
  }
  switch (lsa_type)
  {
    case GRIDSITE:
      for (ALL_LIST_ELEMENTS_RO (OspfGRID.iflist, node, gn))
        if (gn->area != NULL)
          gn->flags &= ~GRIDFLG_GRIDSITE_LSA_LOOKUP_DONE;
      break;
    case GRIDSERVICE:
      for (ALL_LIST_ELEMENTS_RO (OspfGRID.iflist, node, gn))
        if (gn->area != NULL)
          gn->flags &= ~GRIDFLG_GRIDSERVICE_LSA_LOOKUP_DONE;
      break;
    case GRIDCOMPUTINGELEMENT:
      for (ALL_LIST_ELEMENTS_RO (OspfGRID.iflist, node, gn))
        if (gn->area != NULL)
          gn->flags &= ~GRIDFLG_GRIDCOMPUTINGELEMENT_LSA_LOOKUP_DONE;
      break;
    case GRIDSUBCLUSTER:
      for (ALL_LIST_ELEMENTS_RO (OspfGRID.iflist, node, gn))
        if (gn->area != NULL)
          gn->flags &= ~GRIDFLG_GRIDSUBCLUSTER_LSA_LOOKUP_DONE;
      break;
    case GRIDSTORAGE:
      for (ALL_LIST_ELEMENTS_RO (OspfGRID.iflist, node, gn))
        if (gn->area != NULL)
          gn->flags &= ~GRIDFLG_GRIDSTORAGE_LSA_LOOKUP_DONE;
      break;
  }
  return;
}
#endif

#ifdef USE_UNTESTED_OSPF_GRID
static uint32_t map_inni(struct in_addr adv_router, uint32_t old_instance_no)
{
/*  zlog_debug("ospf_grid.c map_inni"); */
  uint32_t instance_no = get_from_map(OspfGRID.map_inni, adv_router, old_instance_no, get_grid_instance_value);
  uint32_t id = SET_OPAQUE_LSID (OPAQUE_TYPE_GRID_LSA, instance_no);
/*  zlog_debug("ospf_grid.c map_inni: id = %d", id); */
  return id;
}

static uint32_t map_enni(struct in_addr adv_router, uint32_t old_instance_no)
{
/*  zlog_debug("ospf_grid.c map_enni"); */
  uint32_t instance_no = get_from_map(OspfGRID.map_enni, adv_router, old_instance_no, get_grid_instance_value);
  uint32_t id = SET_OPAQUE_LSID (OPAQUE_TYPE_GRID_LSA, instance_no);
/*  zlog_debug("ospf_grid.c map_enni: id = %d", id);*/
  return id;
}

static uint32_t map_uni(struct in_addr adv_router, uint32_t old_instance_no)
{
/*  zlog_debug("ospf_grid.c map_uni");*/
  uint32_t instance_no = get_from_map(OspfGRID.map_uni, adv_router, old_instance_no, get_grid_instance_value);
  uint32_t id = SET_OPAQUE_LSID (OPAQUE_TYPE_GRID_LSA, instance_no);
/*  zlog_debug("ospf_grid.c map_uni: id = %d", id);*/
  return id;
}
#endif /* USE_UNTESTED_OSPF_GRID */

static void uni_to_inni(struct ospf_lsa *lsa, int flush)
{
  struct ospf *ospf_inni, *ospf_uni;
  if ((ospf_inni = ospf_inni_lookup()) == NULL)
  {
    if (IS_DEBUG_GRID_NODE(UNI_TO_INNI))
      zlog_debug("[DBG] uni_to_inni%s LSA type GRID: OSPF INNI not found", (flush==1)? " flush" : "");
    goto out;
  }
  if ((ospf_uni = ospf_uni_lookup()) == NULL)
  {
    if (IS_DEBUG_GRID_NODE(UNI_TO_INNI))
      zlog_debug("[DBG] uni_to_inni%s LSA type GRID: OSPF UNI not found", (flush==1)? " flush" : "");
    goto out;
  }
  if (&ospf_inni->lsdb == NULL)
  {
    zlog_warn("[WRN] uni_to_inni%s LSA type GRID: LSDB not found", (flush==1)? " flush" : "");
    goto out;
  }

  u_int16_t length = ntohs(lsa->data->length);

  struct ospf_lsa  *lsa_new = NULL;
  struct ospf_area *area    = NULL;
  struct ospf_area *tmp_area;

  struct zlistnode *node, *nnode;
  for(ALL_LIST_ELEMENTS(ospf_inni->areas, node, nnode, tmp_area))
    if (tmp_area->area_id.s_addr == lsa->area->area_id.s_addr)
      area = tmp_area;

  if (area == NULL)
  {
    if (IS_DEBUG_GRID_NODE(UNI_TO_INNI))
      zlog_debug("[DBG] uni_to_inni%s LSA type GRID: Can't find appropriate area in OSPF INNI", (flush==1)? " flush" : "");
    goto out;
  }

  if ((lsa_new = ospf_lsa_new ()) == NULL)
  {
    if (IS_DEBUG_GRID_NODE(UNI_TO_INNI))
      zlog_warn ("[WRN] uni_to_inni%s LSA type GRID: ospf_lsa_new() failed", (flush==1)? " flush" : "");
    goto out;
  }

  if ((lsa_new->data = ospf_lsa_data_new (length)) == NULL)
  {
    zlog_warn ("[WRN] uni_to_inni%s LSA type GRID: ospf_lsa_data_new() failed", (flush==1)? " flush" : "");
    ospf_lsa_unlock (&lsa_new);
    goto out;
  }

  memcpy (lsa_new->data, lsa->data, length);

  lsa_new->area = area;
  SET_FLAG (lsa_new->flags, OSPF_LSA_SELF);
  SET_FLAG (lsa_new->instance_copy, OSPF_LSA_FROM_UNI_COPY);

  u_char options, lsa_type;

  options  = LSA_OPTIONS_GET (area);
  options |= LSA_OPTIONS_NSSA_GET (area);
  options |= OSPF_OPTION_O; /* Don't forget this :-) */

  lsa_type = OSPF_OPAQUE_AREA_LSA;

  /* Set opaque-LSA header fields. */
  lsa_new->data->ls_age     = htons (0);
  lsa_new->data->options    = options;
  lsa_new->data->type       = lsa_type;
#ifdef USE_UNTESTED_OSPF_GRID
  lsa_new->data->id.s_addr  = htonl(map_inni(lsa->data->adv_router, lsa->data->id.s_addr));
  lsa_new->data->adv_router = ospf_inni->router_id;
#endif /* USE_UNTESTED_OSPF_GRID */

  if (IS_DEBUG_GRID_NODE(UNI_TO_INNI))
  {
    char buf[50];
    log_summary_grid_lsa(buf, lsa);
    zlog_debug("[DBG] uni_to_inni%s LSA type GRID: lsa %s", (flush==1)? " flush" : "", buf);
  }
  if (flush == 0)
  {
    ospf_lsa_checksum (lsa_new->data);
    ospf_lsa_install(ospf_inni, NULL, lsa_new);
    ospf_flood_through_area (area, NULL/*nbr*/, lsa_new);
  }
  else
  {
    lsa_new->data->ls_age = htons(OSPF_LSA_MAXAGE);
    ospf_lsa_checksum (lsa_new->data);
    ospf_opaque_lsa_flush_schedule(lsa_new);
  }
  out:
  /*zlog_debug("[DBG] uni_to_inni%s LSA type GRID: OK", (flush==1)? " flush" : ""); */
  return;
}

static void inni_to_uni(struct ospf_lsa *lsa, int flush)
{
  struct ospf *ospf_inni, *ospf_uni;
  if ((ospf_inni = ospf_inni_lookup()) == NULL)
  {
    if (IS_DEBUG_GRID_NODE(INNI_TO_UNI))
      zlog_debug("[DBG] inni_to_uni%s LSA type GRID: OSPF INNI not found", (flush==1)? " flush" : "");
    goto out;
  }
  if ((ospf_uni = ospf_uni_lookup()) == NULL)
  {
    if (IS_DEBUG_GRID_NODE(INNI_TO_UNI))
      zlog_debug("[DBG] inni_to_uni%s LSA type GRID: OSPF UNI not found", (flush==1)? " flush" : "");
    goto out;
  }
  if (&ospf_uni->lsdb == NULL)
  {
    zlog_warn("[WRN] inni_to_uni%s LSA type GRID: LSDB not found", (flush==1)? " flush" : "");
    goto out;
  }

  u_int16_t length = ntohs(lsa->data->length);

  struct ospf_lsa  *lsa_new = NULL;
  struct ospf_area *area    = NULL;
  struct ospf_area *tmp_area;

  struct zlistnode *node, *nnode;
  for(ALL_LIST_ELEMENTS(ospf_uni->areas, node, nnode, tmp_area))
    if (tmp_area->area_id.s_addr == lsa->area->area_id.s_addr)
      area = tmp_area;

  if (area == NULL)
  {
    if (IS_DEBUG_GRID_NODE(INNI_TO_UNI))
      zlog_debug("[DBG] inni_to_uni%s LSA type GRID: Can't find appropriate area in OSPF UNI", (flush==1)? " flush" : "");
    goto out;
  }

  if ((lsa_new = ospf_lsa_new ()) == NULL)
  {
    zlog_warn ("[WRN] inni_to_uni%s LSA type GRID: ospf_lsa_new() failed", (flush==1)? " flush" : "");
    goto out;
  }

  if ((lsa_new->data = ospf_lsa_data_new (length)) == NULL)
  {
    zlog_warn ("[WRN] inni_to_uni%s LSA type GRID: ospf_lsa_data_new() failed", (flush==1)? " flush" : "");
    ospf_lsa_unlock (&lsa_new);
    goto out;
  }

  memcpy (lsa_new->data, lsa->data, length);

  lsa_new->area = area;
  SET_FLAG (lsa_new->flags, OSPF_LSA_SELF);
  SET_FLAG (lsa_new->instance_copy, OSPF_LSA_FROM_INNI_COPY);

  u_char options, lsa_type;

  options  = LSA_OPTIONS_GET (area);
  options |= LSA_OPTIONS_NSSA_GET (area);
  options |= OSPF_OPTION_O; /* Don't forget this :-) */

  lsa_type = OSPF_OPAQUE_AREA_LSA;

  /* Set opaque-LSA header fields. */
  lsa_new->data->ls_age     = htons (0);
  lsa_new->data->options    = options;
  lsa_new->data->type       = lsa_type;

#ifdef USE_UNTESTED_OSPF_GRID
  lsa_new->data->id.s_addr  = htonl(map_uni(lsa->data->adv_router, lsa->data->id.s_addr));
  lsa_new->data->adv_router = ospf_uni->router_id;
#endif /* USE_UNTESTED_OSPF_GRID */

  if (IS_DEBUG_GRID_NODE(INNI_TO_UNI))
  {
    char buf[50];
    log_summary_grid_lsa(buf, lsa);
    zlog_debug("[DBG] inni_to_uni%s LSA type GRID: lsa %s", (flush==1)? " flush" : "", buf);
  }

  if (flush == 0)
  {
    ospf_lsa_checksum (lsa_new->data);
    ospf_lsa_install(ospf_uni, NULL, lsa_new);
//  register_opaque_lsa(lsa_new);
    ospf_flood_through_area (area, NULL/*nbr*/, lsa_new);
  }
  else
  {
    lsa_new->data->ls_age = htons(OSPF_LSA_MAXAGE);
    ospf_lsa_checksum (lsa_new->data);
    ospf_opaque_lsa_flush_schedule(lsa_new);
  }
  out:
  /*zlog_debug("[DBG] inni_to_uni%s LSA type GRID: OK", (flush==1)? " flush" : "");*/
  return;
}

static void inni_to_enni(struct ospf_lsa *lsa, int flush)
{
  struct ospf *ospf_inni, *ospf_enni;
  if ((ospf_inni = ospf_inni_lookup()) == NULL)
  {
    if (IS_DEBUG_GRID_NODE(FEED_UP))
      zlog_debug("[DBG] inni_to_enni%s: LSA type GRID: OSPF INNI not found", (flush==1)? " flush" : "");
    goto out;
  }
  if ((ospf_enni = ospf_enni_lookup()) == NULL)
  {
    if (IS_DEBUG_GRID_NODE(FEED_UP))
      zlog_debug("[DBG] inni_to_enni%s: LSA type GRID: OSPF ENNI not found", (flush==1)? " flush" : "");
    goto out;
  }
  if (&ospf_enni->lsdb == NULL)
  {
    zlog_warn("[WRN] inni_to_enni%s: LSA type GRID: LSDB not found", (flush==1)? " flush" : "");
    goto out;
  }

  u_int16_t length = ntohs(lsa->data->length);

  struct ospf_lsa  *lsa_new = NULL;
  struct ospf_area *area    = NULL;
  struct ospf_area *tmp_area;

  struct zlistnode *node, *nnode;
  for(ALL_LIST_ELEMENTS(ospf_enni->areas, node, nnode, tmp_area))
    if (tmp_area->area_id.s_addr == lsa->area->area_id.s_addr)
      area = tmp_area;

  if (area == NULL)
  {
    if (IS_DEBUG_GRID_NODE(FEED_UP))
      zlog_debug("[DBG] inni_to_enni%s LSA type GRID: Can't find appropriate area in OSPF ENNI", (flush==1)? " flush" : "");
    goto out;
  }

  if ((lsa_new = ospf_lsa_new ()) == NULL)
  {
    zlog_warn ("[WRN] inni_to_enni%s LSA type GRID: ospf_lsa_new() failed", (flush==1)? " flush" : "");
    goto out;
  }

  if ((lsa_new->data = ospf_lsa_data_new (length)) == NULL)
  {
    zlog_warn ("[WRN] inni_to_enni%s LSA type GRID: ospf_lsa_data_new() failed", (flush==1)? " flush" : "");
    ospf_lsa_unlock (&lsa_new);
    goto out;
  }

  memcpy (lsa_new->data, lsa->data, length);

  lsa_new->area = area;
  SET_FLAG (lsa_new->flags, OSPF_LSA_SELF);
  SET_FLAG (lsa_new->instance_copy, OSPF_LSA_FROM_INNI_COPY);

  u_char options, lsa_type;

  options  = LSA_OPTIONS_GET (area);
  options |= LSA_OPTIONS_NSSA_GET (area);
  options |= OSPF_OPTION_O; /* Don't forget this :-) */

  lsa_type = OSPF_OPAQUE_AREA_LSA;

  /* Set opaque-LSA header fields. */
  lsa_new->data->ls_age     = htons (0);
  lsa_new->data->options    = options;
  lsa_new->data->type       = lsa_type;

#ifdef USE_UNTESTED_OSPF_GRID
  lsa_new->data->id.s_addr  = htonl(map_enni(lsa->data->adv_router, lsa->data->id.s_addr));
  lsa_new->data->adv_router = ospf_enni->router_id;
#endif /* USE_UNTESTED_OSPF_GRID */

  if (IS_DEBUG_GRID_NODE(FEED_UP))
  {
    char buf[50];
    log_summary_grid_lsa(buf, lsa);
    zlog_debug("[WRN] inni_to_enni %s LSA type GRID: lsa %s", (flush == 1) ? " flush" : "", buf);
  }
  if (flush == 0)
  {
    ospf_lsa_checksum (lsa_new->data);
    ospf_lsa_install(ospf_enni, NULL, lsa_new);
//  register_opaque_lsa(lsa_new);
    ospf_flood_through_area (area, NULL/*nbr*/, lsa_new);
  }
  else
  {
    lsa_new->data->ls_age = htons(OSPF_LSA_MAXAGE);
    ospf_lsa_checksum (lsa_new->data);
    ospf_opaque_lsa_flush_schedule(lsa_new);
  }
  out:
  /*zlog_debug("[DBG] inni_to_enni %s LSA type GRID: OK", (flush == 0) ? "Installing new LSA" : "Flushing LSA"); */
  return;
}

static void enni_to_inni(struct ospf_lsa *lsa, int flush)
{
  struct ospf *ospf_inni, *ospf_enni;
  if ((ospf_inni = ospf_inni_lookup()) == NULL)
  {
    if (IS_DEBUG_GRID_NODE(FEED_DOWN))
      zlog_debug("[DBG] enni_to_inni%s LSA type GRID: OSPF INNI not found, exiting", (flush==1)? " flush" : "");
    goto out;
  }
  if ((ospf_enni = ospf_enni_lookup()) == NULL)
  {
    if (IS_DEBUG_GRID_NODE(FEED_DOWN))
      zlog_debug("[DBG] enni_to_inni%s LSA type GRID: OSPF ENNI not found, exiting", (flush==1)? " flush" : "");
    goto out;
  }
  if (&ospf_inni->lsdb == NULL)
  {
    zlog_warn("[WRN] enni_to_inni%s LSA type GRID: LSDB not found, exiting", (flush==1)? " flush" : "");
    goto out;
  }

  u_int16_t length = ntohs(lsa->data->length);

  struct ospf_lsa  *lsa_new = NULL;
  struct ospf_area *area    = NULL;
  struct ospf_area *tmp_area;

  struct zlistnode *node, *nnode;
  for(ALL_LIST_ELEMENTS(ospf_inni->areas, node, nnode, tmp_area))
    if (tmp_area->area_id.s_addr == lsa->area->area_id.s_addr)
      area = tmp_area;

  if (area == NULL)
  {
    zlog_warn ("[WRN] enni_to_inni%s: LSA type GRID: Can't find appropriate area in OSPF INNI, exiting", (flush==1)? " flush" : "");
    goto out;
  }

  if ((lsa_new = ospf_lsa_new ()) == NULL)
  {
    zlog_warn ("[WRN] enni_to_inni%s: LSA type GRID: ospf_lsa_new() failed", (flush==1)? " flush" : "");
    goto out;
  }

  if ((lsa_new->data = ospf_lsa_data_new (length)) == NULL)
  {
    zlog_warn ("[WRN] enni_to_inni%s LSA type GRID: ospf_lsa_data_new() failed", (flush==1)? " flush" : "");
    ospf_lsa_unlock (&lsa_new);
    goto out;
  }

  memcpy (lsa_new->data, lsa->data, length);

  lsa_new->area = area;
  SET_FLAG (lsa_new->flags, OSPF_LSA_SELF);
  SET_FLAG (lsa_new->instance_copy, OSPF_LSA_FROM_ENNI_COPY);

  u_char options, lsa_type;

  options  = LSA_OPTIONS_GET (area);
  options |= LSA_OPTIONS_NSSA_GET (area);
  options |= OSPF_OPTION_O; /* Don't forget this :-) */

  lsa_type = OSPF_OPAQUE_AREA_LSA;

  /* Set opaque-LSA header fields. */
  lsa_new->data->ls_age     = htons (0);
  lsa_new->data->options    = options;
  lsa_new->data->type       = lsa_type;
#if USE_UNTESTED_OSPF_GRID
  lsa_new->data->id.s_addr  = htonl(map_inni(lsa_new->data->adv_router, lsa_new->data->id.s_addr));
  lsa_new->data->adv_router = area->ospf->router_id;
#endif /* USE_UNTESTED_OSPF_GRID */

  if (IS_DEBUG_GRID_NODE(FEED_DOWN))
  {
    char buf[50];
    log_summary_grid_lsa(buf, lsa);
    zlog_debug("[DBG] enni_to_inni %s LSA type GRID: lsa %s", (flush==1) ? " flush" : "", buf);
  }
  if (flush == 0)
  {
    ospf_lsa_checksum (lsa_new->data);
    ospf_lsa_install(ospf_inni, NULL, lsa_new);
//  register_opaque_lsa(lsa_new);
    ospf_flood_through_area (area, NULL/*nbr*/, lsa_new);
  }
  else
  {
    lsa_new->data->ls_age = htons(OSPF_LSA_MAXAGE);
    ospf_lsa_checksum (lsa_new->data);
    ospf_opaque_lsa_flush_schedule(lsa_new);
  }
  out:
  /* zlog_debug("[DBG] enni_to_inni%s LSA type GRID: OK", (flush==1)? " flush" : ""); */
  return;
}

/** *** Update PCE & UNIGW Grid information *** */

#define UPDATE_G2PCERA    1
#define UPDATE_GUNIGW     2

#define REMOVE_TNA_ADDRESS  0
#define ADD_TNA_ADDRESS     1

static u_int16_t 
update_corba_info_unknown_tlv (struct grid_tlv_header *tlvh)
{
  return GRID_TLV_SIZE (tlvh);
}

static u_int16_t
update_corba_info_GridSite_ID(struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridSite_ID *top;
  top = (struct grid_tlv_GridSite_ID *) tlvh;
  corba_update_gn_GridSite_ID((uint32_t) top->id);
  return GRID_TLV_SIZE (tlvh);
}

static u_int16_t
update_corba_info_GridSite_Name(struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridSite_Name *top;
  top = (struct grid_tlv_GridSite_Name *) tlvh;

  int len = ntohs(top->header.length);
  char *name = XMALLOC(MTYPE_OSPF_STR_CHAR, len+1);
  char* ptr = (char*) &top->name;
  for (int i=0; i< len; i++) name[i] = *(ptr++);
    name[len] = '\0';
  corba_update_gn_GridSite_Name(name);
  XFREE(MTYPE_OSPF_STR_CHAR, name);
  return GRID_TLV_SIZE (tlvh);
}
static u_int16_t
update_corba_info_GridSite_Latitude(struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridSite_Latitude *top;
  top = (struct grid_tlv_GridSite_Latitude *) tlvh;
  u_int8_t lat[5];
  for (int i=0; i<5; i++) lat[i] = (u_int8_t)top->latitude[4-i];
  corba_update_gn_GridSite_Latitude(lat);
  return GRID_TLV_SIZE (tlvh);
}
static u_int16_t
update_corba_info_GridSite_Longitude(struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridSite_Longitude *top;
  top = (struct grid_tlv_GridSite_Longitude *) tlvh;
  u_int8_t lon[5];
  for (int i=0; i<5; i++) lon[i] = (uint8_t)top->longitude[4-i];
  corba_update_gn_GridSite_Longitude(lon);
  return GRID_TLV_SIZE (tlvh);
}
static u_int16_t
update_corba_info_GridSite_PE_Router_ID(struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridSite_PE_Router_ID *top;
  top = (struct grid_tlv_GridSite_PE_Router_ID *) tlvh;
  corba_update_gn_GridSite_PERouter_ID((struct in_addr) top->routerID);
  return GRID_TLV_SIZE (tlvh);
}

static u_int16_t
update_corba_info_GridSite (int server, struct grid_tlv_header *tlvh0, u_int16_t subtotal, u_int16_t total)
{
  struct grid_tlv_header *tlvh;
  u_int16_t sum = subtotal;
  init_grid_GridSite();
  for (tlvh = tlvh0; sum < total; tlvh = GRID_TLV_HDR_NEXT (tlvh))
  {
    switch (ntohs (tlvh->type))
    {
      case GRID_TLV_GRIDSITE_ID:
        sum += update_corba_info_GridSite_ID(tlvh);
        break;
      case GRID_TLV_GRIDSITE_NAME:
        sum += update_corba_info_GridSite_Name(tlvh);
        break;
      case GRID_TLV_GRIDSITE_LATITUDE:
        sum += update_corba_info_GridSite_Latitude(tlvh);
        break;
      case GRID_TLV_GRIDSITE_LONGITUDE:
        sum += update_corba_info_GridSite_Longitude(tlvh);
        break;
      case GRID_TLV_GRIDSITE_PEROUTERID:
        sum += update_corba_info_GridSite_PE_Router_ID(tlvh);
        break;
      default:
        sum += update_corba_info_unknown_tlv (tlvh);
    }
  }
  switch(server)
  {
    case UPDATE_G2PCERA: 
      node_add(UPDATE_G2PCERA, -1, NTYPE_GRID);
      corba_update_gn_GridSite(UPDATE_G2PCERA);
      break;
    case UPDATE_GUNIGW:  corba_update_gn_GridSite(UPDATE_GUNIGW); break;
  }
  return sum - subtotal;
}

static u_int16_t
update_corba_info_GridService_ID(struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridService_ID *top;
  top = (struct grid_tlv_GridService_ID *) tlvh;
  corba_update_gn_GridService_ID(top->id);
  return GRID_TLV_SIZE (tlvh);
}
static u_int16_t
update_corba_info_GridService_ParentSite_ID(struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridService_ParentSite_ID *top;
  top = (struct grid_tlv_GridService_ParentSite_ID *) tlvh;
  corba_update_gn_GridService_ParentSite_ID(top->parent_site_id);
  return GRID_TLV_SIZE (tlvh);
}
static u_int16_t
update_corba_info_GridService_ServiceInfo(struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridService_ServiceInfo *top;
  top = (struct grid_tlv_GridService_ServiceInfo *) tlvh;
  corba_update_gn_GridService_ServiceInfo(top->type, top->version);
  return GRID_TLV_SIZE (tlvh);
}
static u_int16_t
update_corba_info_GridService_Status(struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridService_Status *top;
  top = (struct grid_tlv_GridService_Status *) tlvh;
  corba_update_gn_GridService_Status(top->status);
  return GRID_TLV_SIZE (tlvh);
}
static u_int16_t
update_corba_info_GridService_AddressLength(struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridService_AddressLength *top;
  top = (struct grid_tlv_GridService_AddressLength *) tlvh;
  corba_update_gn_GridService_AddressLength(top->addressLength);
  return GRID_TLV_SIZE (tlvh);
}
static u_int16_t
update_corba_info_GridService_IPv4Endpoint(struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridService_IPv4Endpoint *top;
  top = (struct grid_tlv_GridService_IPv4Endpoint *) tlvh;
  corba_update_gn_GridService_IPv4Endpoint((struct in_addr)top->ipv4Endp);
  return GRID_TLV_SIZE (tlvh);
}
static u_int16_t
update_corba_info_GridService_IPv6Endpoint(struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridService_IPv6Endpoint *top;
  top = (struct grid_tlv_GridService_IPv6Endpoint *) tlvh;
  corba_update_gn_GridService_IPv6Endpoint(top->ipv6Endp);
  return GRID_TLV_SIZE (tlvh);
}
static u_int16_t
update_corba_info_GridService_NsapEndpoint(struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridService_NsapEndpoint *top;
  top = (struct grid_tlv_GridService_NsapEndpoint *) tlvh;
  u_int32_t adr[5];
  for (int i=0; i<5; i++) adr[i] = (u_int32_t) ntohl (top->nsapEndp[4-i]);
  corba_update_gn_GridService_NsapEndpoint(adr);
  return GRID_TLV_SIZE (tlvh);
}
static u_int16_t
update_corba_info_GridService (int server, struct grid_tlv_header *tlvh0, u_int16_t subtotal, u_int16_t total)
{
  struct grid_tlv_header *tlvh;
  u_int16_t sum = subtotal;
  init_grid_GridService();
  for (tlvh = tlvh0; sum < total; tlvh = GRID_TLV_HDR_NEXT (tlvh))
  {
    switch (ntohs (tlvh->type))
    {
      case GRID_TLV_GRIDSERVICE_ID:
        sum += update_corba_info_GridService_ID(tlvh);
        break;
      case GRID_TLV_GRIDSERVICE_PARENTSITE_ID:
        sum += update_corba_info_GridService_ParentSite_ID(tlvh);
        break;
      case GRID_TLV_GRIDSERVICE_SERVICEINFO:
        sum += update_corba_info_GridService_ServiceInfo(tlvh);
        break;
      case GRID_TLV_GRIDSERVICE_STATUS:
        sum += update_corba_info_GridService_Status(tlvh);
        break;
      case GRID_TLV_GRIDSERVICE_ADDRESSLENGTH:
        sum += update_corba_info_GridService_AddressLength(tlvh);
        break;
      case GRID_TLV_GRIDSERVICE_IPV4ENDPOINT:
        sum += update_corba_info_GridService_IPv4Endpoint(tlvh);
        break;
      case GRID_TLV_GRIDSERVICE_IPV6ENDPOINT:
        sum += update_corba_info_GridService_IPv6Endpoint(tlvh);
        break;
      case GRID_TLV_GRIDSERVICE_NSAPENDPOINT:
        sum += update_corba_info_GridService_NsapEndpoint(tlvh);
        break;
      default:
        sum += update_corba_info_unknown_tlv (tlvh);
    }
  }
  switch(server)
  {
    case UPDATE_G2PCERA: corba_update_gn_GridService(UPDATE_G2PCERA); break;
    case UPDATE_GUNIGW:  corba_update_gn_GridService(UPDATE_GUNIGW); break;
  }
  return sum - subtotal;
}

static u_int16_t
update_corba_info_GridComputingElement_ID(struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridComputingElement_ID *top;
  top = (struct grid_tlv_GridComputingElement_ID *) tlvh;
  corba_update_gn_GCE_ID(top->id);
  return GRID_TLV_SIZE (tlvh);
}
static u_int16_t
update_corba_info_GridComputingElement_ParentSiteID(struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridComputingElement_ParentSiteID *top;
  top = (struct grid_tlv_GridComputingElement_ParentSiteID *) tlvh;
  corba_update_gn_GCE_ParentSiteID(top->parSiteId);
  return GRID_TLV_SIZE (tlvh);
}
static u_int16_t
update_corba_info_GridComputingElement_LrmsInfo(struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridComputingElement_LrmsInfo *top;
  top = (struct grid_tlv_GridComputingElement_LrmsInfo *) tlvh;
  corba_update_gn_GCE_LrmsInfo(top->lrmsType, top->lrmsVersion);
  return GRID_TLV_SIZE (tlvh);
}
static u_int16_t
update_corba_info_GridComputingElement_AddressLength(struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridComputingElement_AddressLength *top;
  top = (struct grid_tlv_GridComputingElement_AddressLength *) tlvh;
  corba_update_gn_GCE_AddressLength(top->addrLength);
  return GRID_TLV_SIZE (tlvh);
}
static u_int16_t
update_corba_info_GridComputingElement_IPv4HostName(struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridComputingElement_IPv4HostName *top;
  top = (struct grid_tlv_GridComputingElement_IPv4HostName *) tlvh;
  corba_update_gn_GCE_IPv4HostName(top->ipv4HostNam);
  return GRID_TLV_SIZE (tlvh);
}
static u_int16_t
update_corba_info_GridComputingElement_IPv6HostName(struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridComputingElement_IPv6HostName *top;
  top = (struct grid_tlv_GridComputingElement_IPv6HostName *) tlvh;
  corba_update_gn_GCE_IPv6HostName(top->ipv6HostNam);
  return GRID_TLV_SIZE (tlvh);
}
static u_int16_t
update_corba_info_GridComputingElement_NsapHostName(struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridComputingElement_NsapHostName *top;
  top = (struct grid_tlv_GridComputingElement_NsapHostName *) tlvh;
  u_int32_t adr[5];
  for (int i=0; i<5; i++) adr[i] = (u_int32_t) ntohl (top->nsapHostNam[4-i]);
  corba_update_gn_GCE_NsapHostName(adr);
  return GRID_TLV_SIZE (tlvh);
}
static u_int16_t
update_corba_info_GridComputingElement_GatekeeperPort(struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridComputingElement_GatekeeperPort *top;
  top = (struct grid_tlv_GridComputingElement_GatekeeperPort *) tlvh;
  corba_update_gn_GCE_GatekeeperPort(top->gateKPort);
  return GRID_TLV_SIZE (tlvh);
}

static u_int16_t
update_corba_info_GridComputingElement_JobManager(struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridComputingElement_JobManager *top;
  top = (struct grid_tlv_GridComputingElement_JobManager *) tlvh;
  int len = ntohs(top->header.length);
  char* jman = XMALLOC(MTYPE_OSPF_STR_CHAR, len+1);
  char* ptr = (char*) &top->jobManag;
  for (int i=0; i< len; i++) jman[i] = *(ptr++);
  jman[len] = '\0';
  corba_update_gn_GCE_JobManager(jman);
  XFREE(MTYPE_OSPF_STR_CHAR, jman);
  return GRID_TLV_SIZE (tlvh);
}

static u_int16_t
update_corba_info_GridComputingElement_DataDir(struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridComputingElement_DataDir *top;
  top = (struct grid_tlv_GridComputingElement_DataDir *) tlvh;
  int len = ntohs(top->header.length);
  char* datd = XMALLOC(MTYPE_OSPF_STR_CHAR, len+1);
  char* ptr = (char*) &top->dataDirStr;
  for (int i=0; i< len; i++) datd[i] = *(ptr++);
  datd[len] = '\0';
  corba_update_gn_GCE_DataDir(datd);
  XFREE(MTYPE_OSPF_STR_CHAR, datd);
  return GRID_TLV_SIZE (tlvh);
}
static u_int16_t
update_corba_info_GridComputingElement_DefaultStorageElement(struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridComputingElement_DefaultStorageElement *top;
  top = (struct grid_tlv_GridComputingElement_DefaultStorageElement *) tlvh;
  corba_update_gn_GCE_DefaultStorageElement(top->defaultSelement);
  return GRID_TLV_SIZE (tlvh);
}
static u_int16_t
update_corba_info_GridComputingElement_JobsStates(struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridComputingElement_JobsStates *top;
  top = (struct grid_tlv_GridComputingElement_JobsStates *) tlvh;
  corba_update_gn_GCE_JobsStates(top->freeJobSlots, top->status);
  return GRID_TLV_SIZE (tlvh);
}
static u_int16_t
update_corba_info_GridComputingElement_JobsStats(struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridComputingElement_JobsStats *top;
  top = (struct grid_tlv_GridComputingElement_JobsStats *) tlvh;
  corba_update_gn_GCE_JobsStats(top->runningJobs, top->waitingJobs, top->totalJobs);
  return GRID_TLV_SIZE (tlvh);
}
static u_int16_t
update_corba_info_GridComputingElement_JobsTimePerformances(struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridComputingElement_JobsTimePerformances *top;
  top = (struct grid_tlv_GridComputingElement_JobsTimePerformances *) tlvh;
  corba_update_gn_GCE_JobsTimePerformances(top->estRespTime, top->worstRespTime);
  return GRID_TLV_SIZE (tlvh);
}
static u_int16_t
update_corba_info_GridComputingElement_JobsTimePolicy(struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridComputingElement_JobsTimePolicy *top;
  top = (struct grid_tlv_GridComputingElement_JobsTimePolicy *) tlvh;
  corba_update_gn_GCE_JobsTimePolicy(top->maxWcTime, top->maxObtWcTime, top->maxCpuTime, top->maxObtCpuTime);
  return GRID_TLV_SIZE (tlvh);
}
static u_int16_t
update_corba_info_GridComputingElement_JobsLoadPolicy(struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridComputingElement_JobsLoadPolicy *top;
  top = (struct grid_tlv_GridComputingElement_JobsLoadPolicy *) tlvh;
  corba_update_gn_GCE_JobsLoadPolicy(top->maxTotalJobs, top->maxRunJobs, top->maxWaitJobs, top->assignJobSlots, top->maxSlotsPerJob, top->priorityPreemptionFlag);
  return GRID_TLV_SIZE (tlvh);
}
static u_int16_t
update_corba_info_GridComputingElement_CeCalendar(struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridComputingElement_CeCalendar *top;
  struct zlist ceCalendarList;
  top = (struct grid_tlv_GridComputingElement_CeCalendar *) tlvh;
  memset (&ceCalendarList, 0, sizeof (struct zlist));
  struct ce_calendar* ce_cal = NULL;
  int len = ntohs(top->header.length) - GRID_TLV_GRIDCOMPUTINGELEMENT_CECALENDAR_CONST_DATA_LENGTH;
  struct ce_calendar* ptr = (struct ce_calendar*) (void *) &top->ceCalend;
  uint32_t *ptr32 = (uint32_t *) ptr;
  uint16_t *ptr16;
  for (int i=0; i< len-2; i=i+6)
  {
    ce_cal = XMALLOC (MTYPE_OSPF_GRID_COMPUTING_CALENDAR, sizeof(struct ce_calendar));
    ce_cal->time = (uint32_t) *ptr32++;
    ptr16 = (uint16_t *) ptr32;
    ce_cal->freeJobSlots = (uint16_t) *ptr16++;
    listnode_add(&ceCalendarList, ce_cal);
    ptr32 = (uint32_t *) ptr16;
  }
  corba_update_gn_GCE_CeCalendar(&ceCalendarList);
  return GRID_TLV_SIZE (tlvh);
}

static u_int16_t
update_corba_info_GridComputingElement_Name(struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridComputingElement_Name *top;
  top = (struct grid_tlv_GridComputingElement_Name *) tlvh;
  int len = ntohs(top->header.length);
  char* name = XMALLOC(MTYPE_OSPF_STR_CHAR, len+1);
  char* ptr = (char*) &top->name;
  for (int i=0; i< len; i++) name[i] = *(ptr++);
  name[len] = '\0';
  corba_update_gn_GCE_Name(name);
  XFREE(MTYPE_OSPF_STR_CHAR, name);
  return GRID_TLV_SIZE (tlvh);
}

static u_int16_t
update_corba_info_GridComputingElement (int server, struct grid_tlv_header *tlvh0, u_int16_t subtotal, u_int16_t total)
{
  struct grid_tlv_header *tlvh;
  u_int16_t sum = subtotal;
  init_grid_GridComputingElement();
  for (tlvh = tlvh0; sum < total; tlvh = GRID_TLV_HDR_NEXT (tlvh))
  {
    switch (ntohs (tlvh->type))
    {
      case GRID_TLV_GRIDCOMPUTINGELEMENT_ID:
        sum += update_corba_info_GridComputingElement_ID(tlvh);
        break;
      case GRID_TLV_GRIDCOMPUTINGELEMENT_PARENTSITEID:
        sum += update_corba_info_GridComputingElement_ParentSiteID(tlvh);
        break;
      case GRID_TLV_GRIDCOMPUTINGELEMENT_LRMSINFO:
        sum += update_corba_info_GridComputingElement_LrmsInfo(tlvh);
        break;
      case GRID_TLV_GRIDCOMPUTINGELEMENT_ADDRESSLENGTH:
        sum += update_corba_info_GridComputingElement_AddressLength(tlvh);
        break;
      case GRID_TLV_GRIDCOMPUTINGELEMENT_IPV4HOSTNAME:
        sum += update_corba_info_GridComputingElement_IPv4HostName(tlvh);
        break;
      case GRID_TLV_GRIDCOMPUTINGELEMENT_IPV6HOSTNAME:
        sum += update_corba_info_GridComputingElement_IPv6HostName(tlvh);
        break;
      case GRID_TLV_GRIDCOMPUTINGELEMENT_NSAPHOSTNAME:
        sum += update_corba_info_GridComputingElement_NsapHostName(tlvh);
        break;
      case GRID_TLV_GRIDCOMPUTINGELEMENT_GATEKEEPERPORT:
        sum += update_corba_info_GridComputingElement_GatekeeperPort(tlvh);
        break;
      case GRID_TLV_GRIDCOMPUTINGELEMENT_JOBMANAGER:
        sum += update_corba_info_GridComputingElement_JobManager(tlvh);
        break;
      case GRID_TLV_GRIDCOMPUTINGELEMENT_DATADIR:
        sum += update_corba_info_GridComputingElement_DataDir(tlvh);
        break;
      case GRID_TLV_GRIDCOMPUTINGELEMENT_DEFAULTSTORAGEELEMENT:
        sum += update_corba_info_GridComputingElement_DefaultStorageElement(tlvh);
        break;
      case GRID_TLV_GRIDCOMPUTINGELEMENT_JOBSSTATES:
        sum += update_corba_info_GridComputingElement_JobsStates(tlvh);
        break;
      case GRID_TLV_GRIDCOMPUTINGELEMENT_JOBSSTATS:
        sum += update_corba_info_GridComputingElement_JobsStats(tlvh);
        break;
      case GRID_TLV_GRIDCOMPUTINGELEMENT_JOBSTIMEPERFORMANCES:
        sum += update_corba_info_GridComputingElement_JobsTimePerformances(tlvh);
        break;
      case GRID_TLV_GRIDCOMPUTINGELEMENT_JOBSTIMEPOLICY:
        sum += update_corba_info_GridComputingElement_JobsTimePolicy(tlvh);
        break;
      case GRID_TLV_GRIDCOMPUTINGELEMENT_JOBSLOADPOLICY:
        sum += update_corba_info_GridComputingElement_JobsLoadPolicy(tlvh);
        break;
      case GRID_TLV_GRIDCOMPUTINGELEMENT_CECALENDAR:
        sum += update_corba_info_GridComputingElement_CeCalendar(tlvh);
        break;
      case GRID_TLV_GRIDCOMPUTINGELEMENT_NAME:
        sum += update_corba_info_GridComputingElement_Name(tlvh);
        break;
      default:
        sum += update_corba_info_unknown_tlv (tlvh);
    }
  }
  switch(server)
  {
    case UPDATE_G2PCERA: corba_update_gn_GCE(UPDATE_G2PCERA); break;
    case UPDATE_GUNIGW:  corba_update_gn_GCE(UPDATE_GUNIGW); break;
  }
  return sum - subtotal;
}

static u_int16_t
update_corba_info_GridSubCluster_ID(struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridSubCluster_ID *top;
  top = (struct grid_tlv_GridSubCluster_ID *) tlvh;
  corba_update_gn_GSCluster_ID(top->id);
  return GRID_TLV_SIZE (tlvh);
}
static u_int16_t
update_corba_info_GridSubCluster_ParentSiteID(struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridSubCluster_ParentSiteID *top;
  top = (struct grid_tlv_GridSubCluster_ParentSiteID *) tlvh;
  corba_update_gn_GSCluster_ParentSiteID(top->parSiteId);
  return GRID_TLV_SIZE (tlvh);
}
static u_int16_t
update_corba_info_GridSubCluster_CpuInfo(struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridSubCluster_CpuInfo *top;
  top = (struct grid_tlv_GridSubCluster_CpuInfo *) tlvh;
  corba_update_gn_GSCluster_CpuInfo(top->physicalCpus, top->logicalCpus, top->cpuArch);
  return GRID_TLV_SIZE (tlvh);
}
static u_int16_t
update_corba_info_GridSubCluster_OsInfo(struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridSubCluster_OsInfo *top;
  top = (struct grid_tlv_GridSubCluster_OsInfo *) tlvh;
  corba_update_gn_GSCluster_OsInfo(top->osType, top->osVersion);
  return GRID_TLV_SIZE (tlvh);
}
static u_int16_t
update_corba_info_GridSubCluster_MemoryInfo(struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridSubCluster_MemoryInfo *top;
  top = (struct grid_tlv_GridSubCluster_MemoryInfo *) tlvh;
  corba_update_gn_GSCluster_MemoryInfo(top->ramSize, top->virtualMemorySize);
  return GRID_TLV_SIZE (tlvh);
}

static u_int16_t
update_corba_info_GridSubCluster_SoftwarePackage(struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridSubCluster_SoftwarePackage *top;
  top = (struct grid_tlv_GridSubCluster_SoftwarePackage *) tlvh;
  int len = ntohs(top->header.length);
  char* env = XMALLOC(MTYPE_OSPF_STR_CHAR, len-3);
  char* ptr = (char*) &top->environmentSetup;
  for (int i=0; i< len-4; i++) env[i] = *(ptr++);
  env[len-4] = '\0';
  corba_update_gn_GSCluster_NewSoftwarePackage(top->softType, top->softVersion, env);
  return GRID_TLV_SIZE (tlvh);
}

static u_int16_t
update_corba_info_GridSubCluster_SubClusterCalendar(struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridSubCluster_SubClusterCalendar *top;
  struct zlist subclusterCalendarList;
  top = (struct grid_tlv_GridSubCluster_SubClusterCalendar *) tlvh;
  memset (&subclusterCalendarList, 0, sizeof (struct zlist));
  struct sc_calendar *sc_cal = NULL;
  int len = ntohs(top->header.length) - GRID_TLV_GRIDSUBCLUSTER_SUBCLUSTERCALENDAR_CONST_DATA_LENGTH;
  struct sc_calendar* ptr = (struct sc_calendar*) (void *) &top->subcluster_calendar;
  for (int i=0; i< len; i=i+8)
  {
    sc_cal = XMALLOC (MTYPE_OSPF_GRID_SUBCLUSTER_CALENDAR, sizeof(struct sc_calendar));
    sc_cal->time = ptr->time;
    sc_cal->physical_cpus = ptr->physical_cpus;
    sc_cal->logical_cpus = ptr->logical_cpus;
    listnode_add(&subclusterCalendarList, sc_cal);
    ptr++;
  }
  corba_update_gn_GSCluster_SubClusterCalendar(&subclusterCalendarList);
  return GRID_TLV_SIZE (tlvh);
}

static u_int16_t
update_corba_info_GridSubCluster_Name(struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridSubCluster_Name *top;
  top = (struct grid_tlv_GridSubCluster_Name *) tlvh;
  int len = ntohs(top->header.length);
  char* name = XMALLOC(MTYPE_OSPF_STR_CHAR, len+1);
  char* ptr = (char*) &top->name;
  for (int i=0; i< len; i++) name[i] = *(ptr++);
  name[len] = '\0';
  corba_update_gn_GSCluster_Name(name);
  XFREE(MTYPE_OSPF_STR_CHAR, name);
  return GRID_TLV_SIZE (tlvh);
}

static u_int16_t
update_corba_info_GridSubCluster (int server, struct grid_tlv_header *tlvh0, u_int16_t subtotal, u_int16_t total)
{
  struct grid_tlv_header *tlvh;
  u_int16_t sum = subtotal;
  init_grid_GridSubCluster();
  for (tlvh = tlvh0; sum < total; tlvh = GRID_TLV_HDR_NEXT (tlvh))
  {
    switch (ntohs (tlvh->type))
    {
      case GRID_TLV_GRIDSUBCLUSTER_ID:
        sum += update_corba_info_GridSubCluster_ID(tlvh);
        break;
      case GRID_TLV_GRIDSUBCLUSTER_PARENTSITEID:
        sum += update_corba_info_GridSubCluster_ParentSiteID(tlvh);
        break;
      case GRID_TLV_GRIDSUBCLUSTER_CPUINFO:
        sum += update_corba_info_GridSubCluster_CpuInfo(tlvh);
        break;
      case GRID_TLV_GRIDSUBCLUSTER_OSINFO:
        sum += update_corba_info_GridSubCluster_OsInfo(tlvh);
        break;
      case GRID_TLV_GRIDSUBCLUSTER_MEMORYINFO:
        sum += update_corba_info_GridSubCluster_MemoryInfo(tlvh);
        break;
      case GRID_TLV_GRIDSUBCLUSTER_SOFTWAREPACKAGE:
        sum += update_corba_info_GridSubCluster_SoftwarePackage(tlvh);
        break;
      case GRID_TLV_GRIDSUBCLUSTER_SUBCLUSTERCALENDAR:
        sum += update_corba_info_GridSubCluster_SubClusterCalendar(tlvh);
        break;
      case GRID_TLV_GRIDSUBCLUSTER_NAME:
        sum += update_corba_info_GridSubCluster_Name(tlvh);
        break;
      default:
        sum += update_corba_info_unknown_tlv (tlvh);
    }
  }
  corba_update_gn_GSCluster_SoftwarePackages();
  switch(server)
  {
    case UPDATE_G2PCERA: corba_update_gn_GSCluster(UPDATE_G2PCERA); break;
    case UPDATE_GUNIGW:  corba_update_gn_GSCluster(UPDATE_GUNIGW); break;
  }
  return sum - subtotal;
}

static u_int16_t
update_corba_info_GridStorage_ID(struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridStorage_ID *top;
  top = (struct grid_tlv_GridStorage_ID *) tlvh;
  corba_update_gn_GridStorage_ID((uint32_t)top->id);
  return GRID_TLV_SIZE (tlvh);
}
static u_int16_t
update_corba_info_GridStorage_ParentSiteID(struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridStorage_ParentSiteID *top;
  top = (struct grid_tlv_GridStorage_ParentSiteID *) tlvh;
  corba_update_gn_GridStorage_ParentSiteID((uint32_t)top->parSiteId);
  return GRID_TLV_SIZE (tlvh);
}
static u_int16_t
update_corba_info_GridStorage_StorageInfo(struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridStorage_StorageInfo *top;
  top = (struct grid_tlv_GridStorage_StorageInfo *) tlvh;
  corba_update_gn_GridStorage_StorageInfo(top->storInfo);
  return GRID_TLV_SIZE (tlvh);
}
static u_int16_t
update_corba_info_GridStorage_OnlineSize(struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridStorage_OnlineSize *top;
  top = (struct grid_tlv_GridStorage_OnlineSize *) tlvh;
  corba_update_gn_GridStorage_OnlineSize(top->totalSize, top->usedSize);
  return GRID_TLV_SIZE (tlvh);
}
static u_int16_t
update_corba_info_GridStorage_NearlineSize(struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridStorage_NearlineSize *top;
  top = (struct grid_tlv_GridStorage_NearlineSize *) tlvh;
  corba_update_gn_GridStorage_NearlineSize(top->totalSize, top->usedSize);
  return GRID_TLV_SIZE (tlvh);
}

static u_int16_t
update_corba_info_GridStorage_StorageArea(struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridStorage_StorageArea *top, *top_after_lists;
  top = (struct grid_tlv_GridStorage_StorageArea *) tlvh;

  int i = 0;
  int len = ntohs(top->header.length);
  char *nam = XMALLOC(MTYPE_OSPF_STR_CHAR, len);
  char *pat = XMALLOC(MTYPE_OSPF_STR_CHAR, len);

  char* ptr = (char*) &top->name;
  int write_list = 1;
  while ((write_list == 1) || (i%4 != 0))
  {
    if (*(ptr) == '\0') write_list = 0;
    else nam[i] = *(ptr);
    ptr++;
    i++;
  }
  nam[i-1] = '\0';

  int off = i;
  write_list = 1;
  while ((write_list == 1) || (i%4 != 0))
  {
    if (*(ptr) == '\0') write_list = 0;
    else pat[i-off] =  *(ptr);
    ptr++;
    i++;
  }
  pat[i-off-1] = '\0';

  char *offset = (char *)(top) + i - 2 * sizeof(struct zlist);
  top_after_lists = (struct grid_tlv_GridStorage_StorageArea *) offset;

  corba_update_gn_GridStorage_NewStorageArea(nam, pat, top_after_lists->totalOnlineSize, top_after_lists->freeOnlineSize, top_after_lists->resTotalOnlineSize, top_after_lists->totalNearlineSize, top_after_lists->freeNearlineSize, top_after_lists->resNearlineSize, top_after_lists->retPolAccLat, top_after_lists->expirationMode);
  return GRID_TLV_SIZE (tlvh);
}

static u_int16_t
update_corba_info_GridStorage_SeCalendar(struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridStorage_SeCalendar *top;
  struct zlist seCalendarList;
  top = (struct grid_tlv_GridStorage_SeCalendar *) tlvh;
  memset (&seCalendarList, 0, sizeof (struct zlist));
  struct se_calendar *se_cal = NULL;
  int len = ntohs(top->header.length) - GRID_TLV_GRIDSTORAGE_SECALENDAR_CONST_DATA_LENGTH;
  struct se_calendar* ptr = (struct se_calendar*) (void *) &top->seCalendar;
  for (int i=0; i< len; i=i+12)
  {
    se_cal = XMALLOC(MTYPE_OSPF_GRID_SERVICE_CALENDAR, sizeof(struct se_calendar));
    se_cal->time = ptr->time;
    se_cal->freeOnlineSize = ptr->freeOnlineSize;
    se_cal->freeNearlineSize = ptr->freeNearlineSize;
    listnode_add(&seCalendarList, se_cal);
    ptr++;
  }
  corba_update_gn_GridStorage_SeCalendar(&seCalendarList);
  return GRID_TLV_SIZE (tlvh);
}

static u_int16_t
update_corba_info_GridStorage_Name(struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridStorage_Name *top;
  top = (struct grid_tlv_GridStorage_Name *) tlvh;
  int len = ntohs(top->header.length);
  char* name = XMALLOC(MTYPE_OSPF_STR_CHAR, len+1);
  char* ptr = (char*) &top->name;
  for (int i=0; i< len; i++) name[i] = *(ptr++);
  name[len] = '\0';
  corba_update_gn_GridStorage_Name(name);
  XFREE(MTYPE_OSPF_STR_CHAR, name);
  return GRID_TLV_SIZE (tlvh);
}

static u_int16_t
update_corba_info_GridStorage (int server, struct grid_tlv_header *tlvh0, u_int16_t subtotal, u_int16_t total)
{
  struct grid_tlv_header *tlvh;
  u_int16_t sum = subtotal;
  init_grid_GridStorage();
  for (tlvh = tlvh0; sum < total; tlvh = GRID_TLV_HDR_NEXT (tlvh))
  {
    switch (ntohs (tlvh->type))
    {
      case GRID_TLV_GRIDSTORAGE_ID:
        sum += update_corba_info_GridStorage_ID(tlvh);
        break;
      case GRID_TLV_GRIDSTORAGE_PARENTSITEID:
        sum += update_corba_info_GridStorage_ParentSiteID(tlvh);
        break;
      case GRID_TLV_GRIDSTORAGE_STORAGEINFO:
        sum += update_corba_info_GridStorage_StorageInfo(tlvh);
        break;
      case GRID_TLV_GRIDSTORAGE_ONLINESIZE:
        sum += update_corba_info_GridStorage_OnlineSize(tlvh);
        break;
      case GRID_TLV_GRIDSTORAGE_NEARLINESIZE:
        sum += update_corba_info_GridStorage_NearlineSize(tlvh);
        break;
      case GRID_TLV_GRIDSTORAGE_STORAGEAREA:
        sum += update_corba_info_GridStorage_StorageArea(tlvh);
        break;
      case GRID_TLV_GRIDSTORAGE_SECALENDAR:
        sum += update_corba_info_GridStorage_SeCalendar(tlvh);
        break;
      case GRID_TLV_GRIDSTORAGE_NAME:
        sum += update_corba_info_GridStorage_Name(tlvh);
        break;
      default:
        sum += update_corba_info_unknown_tlv (tlvh);
    }
  }
  corba_update_gn_GridStorage_StorageAreas();
  switch(server)
  {
    case UPDATE_G2PCERA: corba_update_gn_GridStorage(UPDATE_G2PCERA); break;
    case UPDATE_GUNIGW:  corba_update_gn_GridStorage(UPDATE_GUNIGW); break;
  }
  return sum - subtotal;
}

#if USE_UNTESTED_OSPF_GRID_CORBA_UPDATE
static void update_corba_grid_info(int server, struct ospf_lsa *lsa)
{
  struct lsa_header *lsah = (struct lsa_header *) lsa->data;
  struct grid_tlv_header *tlvh;
  u_int16_t sum, total, l;
  total = ntohs (lsah->length) - OSPF_LSA_HEADER_SIZE;
  sum = 0;
  tlvh = GRID_TLV_HDR_TOP (lsah);

  if(IS_DEBUG_GRID_NODE(CORBA_ALL))
  {
    const char* str;
    switch (ntohs (tlvh->type))
    {
      case GRID_TLV_GRIDSITE:             str = "SITE";              break;
      case GRID_TLV_GRIDSERVICE:          str = "SERVICE";           break;
      case GRID_TLV_GRIDCOMPUTINGELEMENT: str = "COMPUTING ELEMENT"; break;
      case GRID_TLV_GRIDSUBCLUSTER:       str = "SUBCLUSTER";        break;
      case GRID_TLV_GRIDSTORAGE:          str = "STORAGE";           break;
      default:                            str = "";                  break;
    }
    zlog_debug("[DBG]       LSA type: %s", str);
    switch (server)
    {
      case UPDATE_G2PCERA: str = "G2PCERA"; break;
      case UPDATE_GUNIGW:  str = "GUNIGW"; break;
    }
    zlog_debug("[DBG] CORBA: Preparing update for %s", str);
  }

  while (sum < total)
  {
    switch (ntohs (tlvh->type))
    {
      case GRID_TLV_GRIDSITE:      /* Grid Side Property TLV */
        l = ntohs (tlvh->length);
        sum += TLV_HEADER_SIZE;
        sum += update_corba_info_GridSite (server, tlvh+1, sum, sum + l);
        sum += update_corba_info_unknown_tlv (tlvh);
        break;
      case GRID_TLV_GRIDSERVICE:      /* Grid Service Property TLV */
        l = ntohs (tlvh->length);
        sum += TLV_HEADER_SIZE;
        sum += update_corba_info_GridService (server, tlvh+1, sum, sum + l);
        sum += update_corba_info_unknown_tlv (tlvh);
        break;
      case GRID_TLV_GRIDCOMPUTINGELEMENT:      /* Grid Computing Element Property TLV */
        l = ntohs (tlvh->length);
        sum += TLV_HEADER_SIZE;
        sum += update_corba_info_GridComputingElement (server, tlvh+1, sum, sum + l);
        sum += update_corba_info_unknown_tlv (tlvh);
        break;
      case GRID_TLV_GRIDSUBCLUSTER:      /* Grid SubCluster Property TLV */
        l = ntohs (tlvh->length);
        sum += TLV_HEADER_SIZE;
        sum += update_corba_info_GridSubCluster (server, tlvh+1, sum, sum + l);
        sum += update_corba_info_unknown_tlv (tlvh);
        break;
      case GRID_TLV_GRIDSTORAGE:      /* Grid Storage Element Property TLV */
        l = ntohs (tlvh->length);
        sum += TLV_HEADER_SIZE;
        sum += update_corba_info_GridStorage (server, tlvh+1, sum, sum + l);
        sum += update_corba_info_unknown_tlv (tlvh);
        break;
      default:
        sum += update_corba_info_unknown_tlv (tlvh);
    }
    tlvh = (struct grid_tlv_header *)((char *)(GRID_TLV_HDR_TOP (lsah)) + sum);
  }
  return;
}
#endif /* USE_UNTESTED_OSPF_GRID_CORBA_UPDATE */

#if USE_UNTESTED_OSPF_GRID_CORBA_UPDATE
static void update_grid_inf_from_lsdb(int server)
{
#if HAVE_OMNIORB
  if(IS_DEBUG_GRID_NODE(CORBA_ALL))
    zlog_debug("[DBG] CORBA: BEGIN update_grid_inf_from_lsdb");

  struct prefix_ls lp;
  struct route_node *rn, *start;
  struct ospf_lsa *lsa;
  struct ospf *ospf;
  struct ospf_area *area;
  struct zlistnode *node;

  ospf = ospf_uni_lookup();

  memset (&lp, 0, sizeof (struct prefix_ls));
  lp.family = 0;
  lp.prefixlen = 0;

  for (ALL_LIST_ELEMENTS_RO (ospf->areas, node, area))
  {
    start = route_node_get ( AREA_LSDB (area, OSPF_OPAQUE_AREA_LSA), (struct prefix *) &lp);
    if (start)
    {
      route_lock_node (start);
      for (rn = start; rn; rn = route_next_until (rn, start))
        if ((lsa = rn->info))
        {
          update_corba_grid_info(server, lsa);
          route_unlock_node (start);
        }
    }
  }
  if(IS_DEBUG_GRID_NODE(CORBA_ALL))
    zlog_debug("[DBG] CORBA: FINISH update_grid_inf_from_lsdb");
#endif /* HAVE_OMNIORB */
  return;
}
#endif /* USE_UNTESTED_OSPF_GRID_CORBA_UPDATE */

/** ****** */

/**
 * Search in LSA if there is Te TLV with specyfied type
 * @param lsa ospf LSA
 * @param type type of searched in LSA Te TLV
 * @param length_ptr <OUT> length of searched TLV
 * @return tlv_positpon, 0 if speciffied TLV doesn't exists, -1 if LSA is malformed 
 */
static int has_lsa_tlv_type(struct ospf_lsa *lsa, uint16_t type, uint16_t *length)
{
  struct lsa_header       *lsah = (struct lsa_header *) lsa->data;
  struct grid_tlv_header  *tlvh = TLV_GRID_HDR_TOP (lsah);
  u_int16_t               sum   = 0;
  u_int16_t               total = ntohs (lsah->length) - OSPF_LSA_HEADER_SIZE;

  while (sum < total)
  {
    if (ntohs (tlvh->type) == type)
    {
      *length = GRID_TLV_BODY_SIZE(tlvh);
      return sum + OSPF_LSA_HEADER_SIZE;
    }

    u_int16_t len = GRID_TLV_BODY_SIZE(tlvh);
    len+=TLV_HEADER_SIZE;

    if (len > 0)
      sum += len;
    else
    {
      zlog_err("[ERR] has_lsa_tlv_type: Wrong TLV length. TLV corrupted");
      length = 0;
      return -1;
    }
    tlvh = (struct grid_tlv_header *)((char *) (GRID_TLV_HDR_TOP(lsah)) + sum);
  }
  if (sum > total)
  {
    zlog_err("[ERR] has_lsa_tlv_type: Return -1 LSA malformed");
    length = 0;
    return -1;
  }
  length = 0;
  return 0;
}

static struct grid_tlv_header* get_subtlv_from_lsa(struct ospf_lsa *lsa, uint16_t type, uint16_t subtype)
{
  struct lsa_header     *lsah  = (struct lsa_header *) lsa->data;

  struct grid_tlv_header  *tlvh  = TLV_GRID_HDR_TOP (lsah);
  struct grid_tlv_header  *subTlvh;
  u_int16_t             sum    = 0;
  u_int16_t             subSum = 0;
  u_int16_t             total  = ntohs (lsah->length) - OSPF_LSA_HEADER_SIZE;

  while (sum < total)
  {
    if (ntohs (tlvh->type) == type)
    {
      uint16_t length = htons(tlvh->length);
      subSum = 4;
      while (subSum <= length)
      {
        subTlvh = (struct grid_tlv_header *)((char *)(TLV_GRID_HDR_TOP (lsah)) + sum + subSum);
        if (ntohs (subTlvh->type) == subtype)
          return subTlvh;
        subSum += (ROUNDUP(htons(subTlvh->length),4)+4);
      }
    }
    sum += (ROUNDUP(htons(tlvh->length),4)+4);
    tlvh = (struct grid_tlv_header *)((char *)(TLV_GRID_HDR_TOP (lsah)) + sum);
  }
  if (sum > total)
  {
    zlog_err("[ERR] get_subtlv_from_lsa: LSA malformed");
    return NULL;
  }
  return NULL;
}

static int has_lsa_tlv_type_and_subtype(struct ospf_lsa *lsa, uint16_t type, uint16_t subtype)
{
  struct lsa_header     *lsah  = (struct lsa_header *) lsa->data;

  struct grid_tlv_header  *tlvh  = TLV_GRID_HDR_TOP (lsah);
  struct grid_tlv_header  *subTlvh;
  u_int16_t             sum    = 0;
  u_int16_t             subSum = 0;
  u_int16_t             total  = ntohs (lsah->length) - OSPF_LSA_HEADER_SIZE;

//  zlog_debug("has_lsa_tlv_type: total = %d", total);
  while (sum < total)
  {
//    zlog_debug("has_lsa_tlv_type: sum = %d", sum);
    if (ntohs (tlvh->type) == type)
    {
//      zlog_debug("has_lsa_tlv_type = %d", sum+OSPF_LSA_HEADER_SIZE);
      uint16_t length = htons(tlvh->length);
      subSum = 4;
      while (subSum <= length)
      {
        subTlvh = (struct grid_tlv_header *)((char *)(TLV_GRID_HDR_TOP (lsah)) + sum + subSum);
        if (ntohs (subTlvh->type) == subtype)
          return sum + subSum;
        subSum += (ROUNDUP(htons(subTlvh->length),4)+4);
      }
    }
    sum += (ROUNDUP(htons(tlvh->length),4)+4);
    tlvh = (struct grid_tlv_header *)((char *)(TLV_GRID_HDR_TOP (lsah)) + sum);
  }
  if (sum > total)
  {
    zlog_err("[ERR] has_lsa_tlv_type: Return -1 LSA malformed");
    return -1;
  }
//  zlog_debug("has_lsa_tlv_type = 0");
  return 0;
}

static int ospf_grid_del_lsa(struct ospf_lsa *lsa)
{
  if ((((ntohl(lsa->data->id.s_addr)) >> 24) & 0xFF) != OPAQUE_TYPE_GRID_LSA)
  {
    goto out;
  }

  if (ntohs(lsa->data->ls_age) != OSPF_LSA_MAXAGE)
    goto out;

  if (IS_DEBUG_GRID_NODE(LSA_DELETE))
    zlog_debug("[DBG] OSPF_GRID_DEL_LSA: OSPF instance: %s, lsa age: %d", SHOW_ADJTYPE(lsa->area->ospf->instance), ntohs(lsa->data->ls_age));
//  ospf_discard_from_db (lsa->area->ospf, lsa->area->lsdb, lsa);

  uint16_t sub_lsa_len;
  switch (lsa->area->ospf->instance)
  {
    case UNI:
      /*TODO modify function update_grid_node and uncomment the code
      if ((gn = lookup_grid_node_by_lsa(lsa)) != NULL)
        update_grid_node(gn, lsa); */
      if (CHECK_FLAG (lsa->instance_copy, OSPF_LSA_FROM_INNI_COPY) == 0)
      {
        /* PE address update. This addres had to be update before lsa moving to ospf INNI instance */
        if (lsa->area->ospf->interface_side == NETWORK)
        {
          if (IS_DEBUG_GRID_NODE(LSA_NEW))
            zlog_debug("[DBG] OSPF_GRID_DEL_LSA: Interface: UNI, side: NETWORK");
          uni_to_inni(lsa, 1);
        }
      }
      break;

    case INNI:
      if (CHECK_FLAG (lsa->instance_copy, OSPF_LSA_FROM_UNI_COPY) == 0)
        inni_to_uni(lsa, 1);
      if (CHECK_FLAG (lsa->instance_copy, OSPF_LSA_FROM_ENNI_COPY) == 0)
        inni_to_enni(lsa, 1);

     /** removing grid-node from PCE */
#if USE_UNTESTED_OSPF_GRID_CORBA_UPDATE
     if (has_lsa_tlv_type(lsa, GRID_TLV_GRIDSITE, &sub_lsa_len))
     {
       struct grid_tlv_GridSite_ID *subtlv = (struct grid_tlv_GridSite_ID*) (get_subtlv_from_lsa(lsa, GRID_TLV_GRIDSITE, GRID_TLV_GRIDSITE_ID));
       if (subtlv != NULL)
       {
         node_del(UPDATE_G2PCERA, ntohl(subtlv->id), NTYPE_GRID);
         if ((IS_DEBUG_GRID_NODE(USER)) || (IS_DEBUG_GRID_NODE(CORBA_ALL)))
           zlog_debug("[DBG] OSPF_GRID_DEL_LSA: Removing grid-node %d", ntohl(subtlv->id));
       }
     }

     /** removing grid subnode grid service from PCE */
     if (has_lsa_tlv_type(lsa, GRID_TLV_GRIDSERVICE, &sub_lsa_len))
     {
       struct grid_tlv_GridService_ID *subtlv_id = (struct grid_tlv_GridService_ID*) (get_subtlv_from_lsa(lsa, GRID_TLV_GRIDSERVICE, GRID_TLV_GRIDSERVICE_ID));
       struct grid_tlv_GridService_ParentSite_ID *subtlv_parId = (struct grid_tlv_GridService_ParentSite_ID*) (get_subtlv_from_lsa(lsa, GRID_TLV_GRIDSERVICE, GRID_TLV_GRIDSERVICE_PARENTSITE_ID));

       if ((subtlv_id != NULL) && (subtlv_parId))
       {
         grid_subnode_del(ntohl(subtlv_parId->parent_site_id), ntohl(subtlv_id->id), GRIDSUBNTYPE_SERVICE);
         if ((IS_DEBUG_GRID_NODE(USER)) || (IS_DEBUG_GRID_NODE(CORBA_ALL)))
           zlog_debug("[DBG] OSPF_GRID_DEL_LSA: Removing subnode grid service from PCE (%d, %d)", ntohl(subtlv_parId->parent_site_id), ntohl(subtlv_id->id));
       }
     }

     if (has_lsa_tlv_type(lsa, GRID_TLV_GRIDCOMPUTINGELEMENT, &sub_lsa_len))
     {
       struct grid_tlv_GridComputingElement_ID *subtlv_id = (struct grid_tlv_GridComputingElement_ID*) (get_subtlv_from_lsa(lsa, GRID_TLV_GRIDCOMPUTINGELEMENT, GRID_TLV_GRIDCOMPUTINGELEMENT_ID));
       struct grid_tlv_GridComputingElement_ParentSiteID *subtlv_parId = (struct grid_tlv_GridComputingElement_ParentSiteID*) (get_subtlv_from_lsa(lsa, GRID_TLV_GRIDCOMPUTINGELEMENT, GRID_TLV_GRIDCOMPUTINGELEMENT_PARENTSITEID));

       if ((subtlv_id != NULL) && (subtlv_parId))
       {
         grid_subnode_del(ntohl(subtlv_parId->parSiteId), ntohl(subtlv_id->id), GRIDSUBNTYPE_COMPUTINGELEMENT);
         if ((IS_DEBUG_GRID_NODE(USER)) || (IS_DEBUG_GRID_NODE(CORBA_ALL)))
           zlog_debug("[DBG] OSPF_GRID_DEL_LSA: Removing subnode grid computingelement from PCE (%d, %d)", ntohl(subtlv_parId->parSiteId), ntohl(subtlv_id->id));
       }
     }

     if (has_lsa_tlv_type(lsa, GRID_TLV_GRIDSUBCLUSTER, &sub_lsa_len))
     {
       struct grid_tlv_GridSubCluster_ID *subtlv_id = (struct grid_tlv_GridSubCluster_ID*) (get_subtlv_from_lsa(lsa, GRID_TLV_GRIDSUBCLUSTER, GRID_TLV_GRIDSUBCLUSTER_ID));
       struct grid_tlv_GridSubCluster_ParentSiteID *subtlv_parId = (struct grid_tlv_GridSubCluster_ParentSiteID*) (get_subtlv_from_lsa(lsa, GRID_TLV_GRIDSUBCLUSTER, GRID_TLV_GRIDSUBCLUSTER_PARENTSITEID));

       if ((subtlv_id != NULL) && (subtlv_parId))
       {
         grid_subnode_del(ntohl(subtlv_parId->parSiteId), ntohl(subtlv_id->id), GRIDSUBNTYPE_SUBCLUSTER);
         if ((IS_DEBUG_GRID_NODE(USER)) || (IS_DEBUG_GRID_NODE(CORBA_ALL)))
           zlog_debug("[DBG] OSPF_GRID_DEL_LSA: Removing subnode grid subcluster from PCE (%d, %d)", ntohl(subtlv_parId->parSiteId), ntohl(subtlv_id->id));
       }
     }

     if (has_lsa_tlv_type(lsa, GRID_TLV_GRIDSTORAGE, &sub_lsa_len))
     {
       struct grid_tlv_GridStorage_ID *subtlv_id = (struct grid_tlv_GridStorage_ID*) (get_subtlv_from_lsa(lsa, GRID_TLV_GRIDSTORAGE, GRID_TLV_GRIDSTORAGE_ID));
       struct grid_tlv_GridStorage_ParentSiteID *subtlv_parId = (struct grid_tlv_GridStorage_ParentSiteID*) (get_subtlv_from_lsa(lsa, GRID_TLV_GRIDSTORAGE, GRID_TLV_GRIDSTORAGE_PARENTSITEID));

       if ((subtlv_id != NULL) && (subtlv_parId))
       {
          grid_subnode_del(ntohl(subtlv_parId->parSiteId), ntohl(subtlv_id->id), GRIDSUBNTYPE_STORAGEELEMENT);
         if ((IS_DEBUG_GRID_NODE(USER)) || (IS_DEBUG_GRID_NODE(CORBA_ALL)))
           zlog_debug("[DBG] OSPF_GRID_DEL_LSA: Removing subnode grid storage from PCE (%d, %d)", ntohl(subtlv_parId->parSiteId), ntohl(subtlv_id->id));
       }
     }
#endif /*USE_UNTESTED_OSPF_GRID_CORBA_UPDATE*/
     //
     break;

    case ENNI:
      if (CHECK_FLAG (lsa->instance_copy, OSPF_LSA_FROM_INNI_COPY) == 0)
        enni_to_inni(lsa, 1);
      break;

    default:
      zlog_warn("[WRN] OSPF_GRID_DEL_LSA: Interface UNKNOWN");
      goto out;
  }
  UNSET_FLAG(lsa->instance_copy, OSPF_LSA_FROM_UNI_COPY);
  UNSET_FLAG(lsa->instance_copy, OSPF_LSA_FROM_INNI_COPY);
  UNSET_FLAG(lsa->instance_copy, OSPF_LSA_FROM_ENNI_COPY);
out:
  return 0;
}

static int ospf_grid_new_lsa(struct ospf_lsa *lsa)
{
  if ((((ntohl(lsa->data->id.s_addr)) >> 24) & 0xFF) != OPAQUE_TYPE_GRID_LSA)
  {
    goto out;
  }
#if USE_UNTESTED_OSPF_GRID
#else
  goto out;
#endif /* USE_UNTESTED_OSPF_GRID */

  register_opaque_lsa(lsa);

  switch (lsa->area->ospf->instance)
  {
    case UNI:
      /*TODO modify function update_grid_node and uncomment the code
      if ((gn = lookup_grid_node_by_lsa(lsa)) != NULL)
        update_grid_node(gn, lsa); */

      if (CHECK_FLAG (lsa->instance_copy, OSPF_LSA_FROM_INNI_COPY) == 0)
      {
        /* PE address update. This addres had to be update before lsa moving to ospf INNI instance */
        if (lsa->area->ospf->interface_side == NETWORK)
        {
          if (IS_DEBUG_GRID_NODE(LSA_NEW))
            zlog_debug("[DBG] OSPF_GRID_NEW_LSA: Interface: UNI, side: NETWORK");
          int PE_offset = has_lsa_tlv_type_and_subtype(lsa, GRID_TLV_GRIDSITE, GRID_TLV_GRIDSITE_PEROUTERID);
          if (PE_offset > 0)
          {
            struct lsa_header *lsah  = (struct lsa_header *) lsa->data;

            /* ADAM: Be carefull, wrong memory address may crash quagga */
            struct grid_tlv_GridSite_PE_Router_ID *tlvh = (struct grid_tlv_GridSite_PE_Router_ID *)((char *)(TLV_GRID_HDR_TOP (lsah)) + PE_offset);

            struct ospf *ospf_inni = ospf_inni_lookup();
            if (ospf_inni)
              tlvh->routerID = ospf_inni->router_id;

            /* don't forget about Re-calculating checksum. */
            ospf_lsa_checksum (lsah);
          }
          uni_to_inni(lsa, 0);
        }
      }
      break;

    case INNI:

      #if USE_UNTESTED_OSPF_GRID_CORBA_UPDATE
        if(IS_DEBUG_GRID_NODE(CORBA_ALL))
          zlog_debug("[DBG] CORBA: Received new GRID LSA");

        /* ****************************************** */

        update_corba_grid_info(UPDATE_G2PCERA, lsa);   // Update G2PCERA information
        //update_corba_grid_info(UPDATE_GUNIGW, lsa);  // Update GUNIGW information

       /* ******************************************* */ 

      #endif /* USE_UNTESTED_OSPF_GRID_CORBA_UPDATE */

      if (CHECK_FLAG (lsa->instance_copy, OSPF_LSA_FROM_UNI_COPY) == 0)
        inni_to_uni(lsa, 0);
      if (CHECK_FLAG (lsa->instance_copy, OSPF_LSA_FROM_ENNI_COPY) == 0)
        inni_to_enni(lsa, 0);
      break;

    case ENNI:
      if (CHECK_FLAG (lsa->instance_copy, OSPF_LSA_FROM_INNI_COPY) == 0)
        enni_to_inni(lsa, 0);
      break;

    default:
      zlog_warn("[WRN] OSPF_GRID_NEW_LSA: Interface UNKNOWN");
      goto out;
  }
  UNSET_FLAG(lsa->instance_copy, OSPF_LSA_FROM_UNI_COPY);
  UNSET_FLAG(lsa->instance_copy, OSPF_LSA_FROM_INNI_COPY);
  UNSET_FLAG(lsa->instance_copy, OSPF_LSA_FROM_ENNI_COPY);

out:
  return 0;
}

/**
 * Adding new structure grid_node to OspfGRID assosiated with new interface. 
 * If such structure exists, function do nothing.
 * Creating and setting new structure grid_node.
 * @param ifp - pointer to new interface that is being added to te system
 * @return 0 - succes, -1 memory allocation problem 
 */
static int ospf_grid_new_if (struct interface *ifp)
{
  if (ifp->adj_type == UNI)
  {
    OspfGRID.grid_ifp = ifp;
    if (IS_DEBUG_GRID_NODE(USER))
      zlog_debug("[DBG] OSPF_GRID_NEW_IF: Interface %s (ospf %s, adj_type %s) is used for sending grid-node opaques", ifp->name, SHOW_ADJTYPE(ifp->ospf_instance), SHOW_ADJTYPE(ifp->adj_type));
  }

  int rc = -1;
#if 0
  struct grid_node *new;

  if ((new = lookup_grid_node_by_ifp (ifp))!= NULL)
  {
    rc = 0; /* Do nothing here. */
    goto out;
  }

  if ((new = XMALLOC (MTYPE_OSPF_GRID_NODE, sizeof (struct grid_node))) == NULL)
  {
    zlog_warn ("[WRN] ospf_grid_new_if: XMALLOC: %s", safe_strerror (errno));
    goto out;
  }
  memset (new, 0, sizeof (struct grid_node));

  new->area = NULL;
  new->ifp = ifp;

  initialize_grid_node_params (new);
  listnode_add (OspfGRID.iflist, new);
#endif
/* Schedule Opaque-LSA refresh. *//* XXX */
  rc = 0;
//out:
  return rc;
}

int
grid_node_delete_node(struct grid_node *gn)
{
  listnode_delete_with_data (OspfGRID.iflist, gn);
  if (listcount (OspfGRID.iflist) == 0) OspfGRID.iflist->head = OspfGRID.iflist->tail = NULL;
  return 0;
}


static void
log_summary_grid_lsa(char *buf, struct ospf_lsa *lsa)
{
  struct lsa_header *lsah       = (struct lsa_header *) lsa->data;
  struct grid_tlv_header *tlvh  = (struct grid_tlv_header *)((char *)(lsah) + OSPF_LSA_HEADER_SIZE);
  uint32_t id                   = *((uint32_t *)(tlvh+2));
  uint32_t parent_id            = *((uint32_t *)(tlvh+4));

  struct in_addr ids, parent_ids;
  ids.s_addr = id;
  parent_ids.s_addr = parent_id;

  switch (ntohs (tlvh->type))
  {
    case GRID_TLV_GRIDSITE:
      sprintf(buf, " Grid Site: %s", inet_ntoa(ids));
      break;
    case GRID_TLV_GRIDSERVICE:
      sprintf(buf, " Grid Service: %s, %s", inet_ntoa(parent_ids), inet_ntoa(ids));
      break;
    case GRID_TLV_GRIDCOMPUTINGELEMENT:
      sprintf(buf, " Grid Computing Element: %s, %s", inet_ntoa(parent_ids), inet_ntoa(ids));
      break;
    case GRID_TLV_GRIDSUBCLUSTER:
      sprintf(buf, " Grid SubCluster: %s, %s", inet_ntoa(parent_ids), inet_ntoa(ids));
      break;
    case GRID_TLV_GRIDSTORAGE:
      sprintf(buf, " Grid Storage: %s, %s", inet_ntoa(parent_ids), inet_ntoa(ids));
      break;
    default:
      break;
  }
}

/**
 * Deleting structure grid_node associated with specyfied interface.
 * Remowing grid_node from list
 */
static int ospf_grid_del_if (struct interface *ifp)
{
  int rc = -1;

  rc = 0;
/*out:*/
  return rc;
}

/**
 * changing the state of the ospf interface (interface state mashine)
 * @param *oi pointer to the ospf interface
 * @param  old_state
 */
static void  ospf_grid_ism_change (struct ospf_interface *oi, int old_state)
{
  if (oi->area == NULL || oi->area->ospf == NULL)
  {
    zlog_warn ("[WRN] OSPF_GRID_ISM_CHANGE: Cannot refer to OSPF from OI(%s)?",
    IF_NAME (oi));
    goto out;
  }

  struct grid_node *gn;
  struct zlistnode *node, *nnode;
  for (ALL_LIST_ELEMENTS(OspfGRID.iflist, node, nnode, gn))
  {
    if (gn->ifp != oi->ifp)
      continue;
    zlog_debug("[DBG] OSPF_GRID_ISM_CHANGE: Found matching gn->ifp to oi->ifp");
#ifdef notyet
  struct zlistnode *node1, *nnode1;
    if ((gn->area != NULL &&  !IPV4_ADDR_SAME (&gn->area->area_id, &oi->area->area_id)) || (gn->area != NULL && oi->area == NULL))
    {
/* How should we consider this case? */
      zlog_warn ("[WRN] OSPF_GRID_ISM_CHANGE: Area for OI%s has changed to [%s], flush previous LSAs", IF_NAME (oi), oi->area ? inet_ntoa (oi->area->area_id) : "N/A");
      if (gn->gn_site->base.flags & GRIDFLG_GRID_LSA_ENGAGED)
      {
        ospf_grid_site_lsa_schedule (gn->gn_site, GRID_FLUSH_THIS_LSA);
        if (IS_DEBUG_GRID_NODE(ISM_CHANGE))
          zlog_debug("[DBG] OSPF_GRID_ISM_CHANGE: ospf_grid_site_lsa_schedule (gn->gn_site, GRID_FLUSH_THIS_LSA)");
      }

      for(ALL_LIST_ELEMENTS(gn->list_of_grid_node_service, node1, nnode1, gn_service))
      {
        if (gn_service->base.flags & GRIDFLG_GRID_LSA_ENGAGED)
        {
          ospf_grid_service_lsa_schedule (gn_service, GRID_FLUSH_THIS_LSA);
          if (IS_DEBUG_GRID_NODE(ISM_CHANGE))
            zlog_debug("[DBG] OSPF_GRID_ISM_CHANGE: ospf_grid_service_lsa_schedule (gn_service, GRID_FLUSH_THIS_LSA)");
        }
      }

      for(ALL_LIST_ELEMENTS(gn->list_of_grid_node_storage, node1, nnode1, gn_storage))
      {
        if (gn_storage->base.flags & GRIDFLG_GRID_LSA_ENGAGED)
        {
          ospf_grid_storage_lsa_schedule (gn_storage, GRID_FLUSH_THIS_LSA);
          if (IS_DEBUG_GRID_NODE(ISM_CHANGE))
            zlog_debug("[DBG] OSPF_GRID_ISM_CHANGE: ospf_grid_storage_lsa_schedule (gn_storage, GRID_FLUSH_THIS_LSA)");
        }
      }

      for(ALL_LIST_ELEMENTS(gn->list_of_grid_node_computing, node1, nnode1, gn_computing))
      {
        if (gn_computing->base.flags & GRIDFLG_GRID_LSA_ENGAGED)
        {
          ospf_grid_computing_lsa_schedule (gn_computing, GRID_FLUSH_THIS_LSA);
          if (IS_DEBUG_GRID_NODE(ISM_CHANGE))
            zlog_debug("[DBG] OSPF_GRID_ISM_CHANGE: ospf_grid_computing_lsa_schedule (gn_computing, GRID_FLUSH_THIS_LSA)");
        }
      }

      for(ALL_LIST_ELEMENTS(gn->list_of_grid_node_subcluster, node1, nnode1, gn_subcluster))
      {
        if (gn_subcluster->base.flags & GRIDFLG_GRID_LSA_ENGAGED)
        {
          ospf_grid_subcluster_lsa_schedule (gn_subcluster, GRID_FLUSH_THIS_LSA);
          if (IS_DEBUG_GRID_NODE(ISM_CHANGE))
            zlog_debug("[DBG] OSPF_GRID_ISM_CHANGE: ospf_grid_subcluster_lsa_schedule (gn_subcluster, GRID_FLUSH_THIS_LSA)");
        }
      }
    }
#endif
/* Keep Area information in conbination with linkparams. */
    gn->area = oi->area;
/* This functionality allows to flushing lsa if interface is down (ISM_Down)
   and originate lsa after interface state change into the state != ISM_Down */
#if ism_grid_force_refresh
    struct grid_node_service    *gn_service;
    struct grid_node_storage    *gn_storage;
    struct grid_node_subcluster *gn_subcluster;
    struct grid_node_computing  *gn_computing;
#endif /*ism_grid_force_refresh*/
    switch (oi->state)
    {
      case ISM_PointToPoint:
      case ISM_DROther:
      case ISM_Backup:
      case ISM_DR:
#if ism_grid_force_refresh
        if ((OspfGRID.status == enabled) && (gn->area != NULL))
        {
          if (gn->gn_site->base.flags & GRIDFLG_GRID_LSA_ENGAGED)
          {
            ospf_grid_site_lsa_schedule (gn->gn_site, GRID_REFRESH_THIS_LSA);
            if (IS_DEBUG_GRID_NODE(ISM_CHANGE))
              zlog_debug("[DBG] OSPF_GRID_ISM_CHANGE: ospf_grid_site_lsa_schedule (gn->gn_site, GRID_REFRESH_THIS_LSA)");
          }
          else
          {
            ospf_grid_site_lsa_schedule (gn->gn_site, GRID_REORIGINATE_PER_AREA);
            if (IS_DEBUG_GRID_NODE(ISM_CHANGE))
              zlog_debug("[DBG] OSPF_GRID_ISM_CHANGE: ospf_grid_site_lsa_schedule (gn->gn_site, GRID_REORIGINATE_PER_AREA)");
          }

          for(ALL_LIST_ELEMENTS(gn->list_of_grid_node_service, node1, nnode1, gn_service))
          {
            if (gn_service->base.flags & GRIDFLG_GRID_LSA_ENGAGED)
            {
              ospf_grid_service_lsa_schedule (gn_service, GRID_REFRESH_THIS_LSA);
              if (IS_DEBUG_GRID_NODE(ISM_CHANGE))
                zlog_debug("[DBG] OSPF_GRID_ISM_CHANGE: ospf_grid_service_lsa_schedule (gn_service, GRID_REFRESH_THIS_LSA)");
            }
            else
            {
              ospf_grid_service_lsa_schedule (gn_service, GRID_REORIGINATE_PER_AREA);
              if (IS_DEBUG_GRID_NODE(ISM_CHANGE))
                zlog_debug("[DBG] OSPF_GRID_ISM_CHANGE: ospf_grid_service_lsa_schedule (gn_service, GRID_REORIGINATE_PER_AREA)");
            }
          }

          for(ALL_LIST_ELEMENTS(gn->list_of_grid_node_storage, node1, nnode1, gn_storage))
          {
            if (gn_storage->base.flags & GRIDFLG_GRID_LSA_ENGAGED)
            {
              ospf_grid_storage_lsa_schedule (gn_storage, GRID_REFRESH_THIS_LSA);
              if (IS_DEBUG_GRID_NODE(ISM_CHANGE))
                zlog_debug("[DBG] OSPF_GRID_ISM_CHANGE: ospf_grid_storage_lsa_schedule (gn_storage, GRID_REFRESH_THIS_LSA)");
            }
            else
            {
              ospf_grid_storage_lsa_schedule (gn_storage, GRID_REORIGINATE_PER_AREA);
              if (IS_DEBUG_GRID_NODE(ISM_CHANGE))
                zlog_debug("[DBG] OSPF_GRID_ISM_CHANGE: ospf_grid_storage_lsa_schedule (gn_storage, GRID_REORIGINATE_PER_AREA)");
            }
          }

          for(ALL_LIST_ELEMENTS(gn->list_of_grid_node_computing, node1, nnode1, gn_computing))
          {
            if (gn_computing->base.flags & GRIDFLG_GRID_LSA_ENGAGED)
            {
              ospf_grid_computing_lsa_schedule (gn_computing, GRID_REFRESH_THIS_LSA);
              if (IS_DEBUG_GRID_NODE(ISM_CHANGE))
                zlog_debug("[DBG] OSPF_GRID_ISM_CHANGE: ospf_grid_computing_lsa_schedule (gn_computing, GRID_REFRESH_THIS_LSA)");
            }
            else
            {
              ospf_grid_computing_lsa_schedule (gn_computing, GRID_REORIGINATE_PER_AREA);
              if (IS_DEBUG_GRID_NODE(ISM_CHANGE))
                zlog_debug("[DBG] OSPF_GRID_ISM_CHANGE: ospf_grid_computing_lsa_schedule (gn_computing, GRID_REORIGINATE_PER_AREA)");
            }
          }

          for(ALL_LIST_ELEMENTS(gn->list_of_grid_node_subcluster, node1, nnode1, gn_subcluster))
          {
            if (gn_subcluster->base.flags & GRIDFLG_GRID_LSA_ENGAGED)
            {
              ospf_grid_subcluster_lsa_schedule (gn_subcluster, GRID_REFRESH_THIS_LSA);
              if (IS_DEBUG_GRID_NODE(ISM_CHANGE))
                zlog_debug("[DBG] OSPF_GRID_ISM_CHANGE: ospf_grid_subcluster_lsa_schedule (gn_subcluster, GRID_REFRESH_THIS_LSA)");
            }
            else
            {
              ospf_grid_subcluster_lsa_schedule (gn_subcluster, GRID_REORIGINATE_PER_AREA);
              if (IS_DEBUG_GRID_NODE(ISM_CHANGE))
                zlog_debug("[DBG] OSPF_GRID_ISM_CHANGE: ospf_grid_subcluster_lsa_schedule (gn_subcluster, GRID_REORIGINATE_PER_AREA)");
            }
          }
        }
#endif /*ism_grid_force_refresh*/
        break;
      case ISM_Down:
      default:
#if ism_grid_force_refresh
        if ((OspfGRID.status == enabled) && (gn->area != NULL))
        {
          if (gn->gn_site->base.flags & GRIDFLG_GRID_LSA_ENGAGED)
          {
            ospf_grid_site_lsa_schedule (gn->gn_site, GRID_FLUSH_THIS_LSA);
            if (IS_DEBUG_GRID_NODE(ISM_CHANGE))
              zlog_debug("[DBG] OSPF_GRID_ISM_CHANGE: ospf_grid_site_lsa_schedule (gn->gn_site, GRID_FLUSH_THIS_LSA)");
          }

          for(ALL_LIST_ELEMENTS(gn->list_of_grid_node_service, node1, nnode1, gn_service))
          {
            if (gn_service->base.flags & GRIDFLG_GRID_LSA_ENGAGED)
            {
              ospf_grid_service_lsa_schedule (gn_service, GRID_FLUSH_THIS_LSA);
              if (IS_DEBUG_GRID_NODE(ISM_CHANGE))
                zlog_debug("[DBG] OSPF_GRID_ISM_CHANGE: ospf_grid_service_lsa_schedule (gn_service, GRID_FLUSH_THIS_LSA)");
            }
          }

          for(ALL_LIST_ELEMENTS(gn->list_of_grid_node_storage, node1, nnode1, gn_storage))
          {
            if (gn_storage->base.flags & GRIDFLG_GRID_LSA_ENGAGED)
            {
              ospf_grid_storage_lsa_schedule (gn_storage, GRID_FLUSH_THIS_LSA);
              if (IS_DEBUG_GRID_NODE(ISM_CHANGE))
                zlog_debug("[DBG] OSPF_GRID_ISM_CHANGE: ospf_grid_storage_lsa_schedule (gn_storage, GRID_FLUSH_THIS_LSA)");
            }
          }

          for(ALL_LIST_ELEMENTS(gn->list_of_grid_node_computing, node1, nnode1, gn_computing))
          {
            if (gn_computing->base.flags & GRIDFLG_GRID_LSA_ENGAGED)
            {
              ospf_grid_computing_lsa_schedule (gn_computing, GRID_FLUSH_THIS_LSA);
              if (IS_DEBUG_GRID_NODE(ISM_CHANGE))
                zlog_debug("[DBG] OSPF_GRID_ISM_CHANGE: ospf_grid_computing_lsa_schedule (gn_computing, GRID_FLUSH_THIS_LSA)");
            }
          }

          for(ALL_LIST_ELEMENTS(gn->list_of_grid_node_subcluster, node1, nnode1, gn_subcluster))
          {
            if (gn_subcluster->base.flags & GRIDFLG_GRID_LSA_ENGAGED)
            {
              ospf_grid_subcluster_lsa_schedule (gn_subcluster, GRID_FLUSH_THIS_LSA);
              if (IS_DEBUG_GRID_NODE(ISM_CHANGE))
                zlog_debug("[DBG] OSPF_GRID_ISM_CHANGE: ospf_grid_subcluster_lsa_schedule (gn_subcluster, GRID_FLUSH_THIS_LSA)");
            }
          }
        }
#endif /*ism_grid_force_refresh*/
        break;
    }
  }
out:
  return;
}
/** OSPF Neighbor State Machine State */
static void  ospf_grid_nsm_change (struct ospf_neighbor *nbr, int old_state)
{
  struct ospf *top;

  struct zlistnode            *node, *nnode;
  struct zlistnode            *node1, *nnode1;
  struct grid_node_service    *gn_service;
  struct grid_node_storage    *gn_storage;
  struct grid_node_subcluster *gn_subcluster;
  struct grid_node_computing  *gn_computing;
  struct grid_node            *gn;

  if ((top = oi_to_top (nbr->oi)) != NULL)
  {
    if (CHECK_FLAG (top->opaque, OPAQUE_OPERATION_READY_BIT))
    {
      if (IS_DEBUG_GRID_NODE(NSM_CHANGE))
        zlog_debug("[DBG] NSM_STATE_CHANGE: %s->%s grid callback function.",
          LOOKUP (ospf_nsm_state_msg, old_state),
          LOOKUP (ospf_nsm_state_msg, nbr->state));

      if (IS_OPAQUE_LSA_ORIGINATION_BLOCKED (top->opaque))
      {
        if (IS_DEBUG_GRID_NODE(NSM_CHANGE))
          zlog_debug ("[DBG] NSM_STATE_CHANGE: NSM under blockade opaque reoriginate / refresh skipped. Force unblocking");
        //TODO Adam: it is very ugly solution. I don't know how to fix it on different way
        UNSET_FLAG (top->opaque, OPAQUE_BLOCK_TYPE_10_LSA_BIT);
      }
      if (nbr->state == NSM_Deleted)
      {
        struct route_node *rn;
        struct ospf_lsa   *lsa;
        struct ospf_area  *area;
        struct zlistnode  *node;

        for (ALL_LIST_ELEMENTS_RO (top->areas, node, area))
        {
          LSDB_LOOP (OPAQUE_AREA_LSDB (area), rn, lsa)
          {
            if ((lsa->data->adv_router.s_addr == nbr->router_id.s_addr) && (((((ntohl(lsa->data->id.s_addr)) >> 24) & 0xFF) == OPAQUE_TYPE_GRID_LSA)))
            {
              if ((IS_DEBUG_GRID_NODE(NSM_CHANGE))||(IS_DEBUG_GRID_NODE(USER)))
              {
                char buf[50];
                log_summary_grid_lsa(buf, lsa);
                struct in_addr temp;
                temp.s_addr = lsa->data->id.s_addr;
                zlog_debug("[DBG] ospf_grid_nsm_change: state -> %s flushing opaque (%s, id %s) generated by not existing neighbour",
                  LOOKUP (ospf_nsm_state_msg, nbr->state),
                  buf,
                  inet_ntoa(temp));
              }
              lsa->data->ls_age = htons (OSPF_LSA_MAXAGE);
              ospf_lsa_maxage (top, lsa);
            }
          }
        }
      }
      else
      {
        for(ALL_LIST_ELEMENTS(OspfGRID.iflist, node1, nnode1, gn))
        {
//        gn=lookup_grid_node_by_ifp(nbr->oi->ifp);
          if ((OspfGRID.status == enabled) && (gn->area != NULL) && (top->instance == UNI) && (top->interface_side == CLIENT))
          {
            if (IS_DEBUG_GRID_NODE(NSM_CHANGE))
              zlog_debug("[DBG] ospf_grid_nsm_change: NSM force opaque originating");
            if (gn->gn_site->base.flags & GRIDFLG_GRID_LSA_ENGAGED)
            {
              ospf_grid_site_lsa_schedule (gn->gn_site, GRID_REFRESH_THIS_LSA);
              if (IS_DEBUG_GRID_NODE(NSM_CHANGE))
                zlog_debug("[DBG] ospf_grid_nsm_change: ospf_grid_site_lsa_schedule (gn->gn_site, GRID_REFRESH_THIS_LSA)");
            }
            else
            {
              ospf_grid_site_lsa_schedule (gn->gn_site, GRID_REORIGINATE_PER_AREA);
              if (IS_DEBUG_GRID_NODE(NSM_CHANGE))
                zlog_debug("[DBG] ospf_grid_nsm_change: ospf_grid_site_lsa_schedule (gn->gn_site, GRID_REORIGINATE_PER_AREA)");
            }

            for(ALL_LIST_ELEMENTS(gn->list_of_grid_node_service, node, nnode, gn_service))
            {
              if (gn_service->base.flags & GRIDFLG_GRID_LSA_ENGAGED)
              {
                ospf_grid_service_lsa_schedule (gn_service, GRID_REFRESH_THIS_LSA);
                if (IS_DEBUG_GRID_NODE(NSM_CHANGE))
                  zlog_debug("[DBG] ospf_grid_nsm_change: ospf_grid_service_lsa_schedule (gn_service, GRID_REFRESH_THIS_LSA)");
              }
              else
              {
                ospf_grid_service_lsa_schedule (gn_service, GRID_REORIGINATE_PER_AREA);
                if (IS_DEBUG_GRID_NODE(NSM_CHANGE))
                  zlog_debug("[DBG] ospf_grid_nsm_change: ospf_grid_service_lsa_schedule (gn_service, GRID_REORIGINATE_PER_AREA)");
              }
            }
  
            for(ALL_LIST_ELEMENTS(gn->list_of_grid_node_storage, node, nnode, gn_storage))
            {
              if (gn_storage->base.flags & GRIDFLG_GRID_LSA_ENGAGED)
              {
                ospf_grid_storage_lsa_schedule (gn_storage, GRID_REFRESH_THIS_LSA);
                if (IS_DEBUG_GRID_NODE(NSM_CHANGE))
                  zlog_debug("[DBG] ospf_grid_nsm_change: ospf_grid_storage_lsa_schedule (gn_storage, GRID_REFRESH_THIS_LSA)");
              }
              else
              {
                ospf_grid_storage_lsa_schedule (gn_storage, GRID_REORIGINATE_PER_AREA);
                if (IS_DEBUG_GRID_NODE(NSM_CHANGE))
                  zlog_debug("[DBG] ospf_grid_nsm_change: ospf_grid_storage_lsa_schedule (gn_storage, GRID_REORIGINATE_PER_AREA)");
              }
            }
  
            for(ALL_LIST_ELEMENTS(gn->list_of_grid_node_computing, node, nnode, gn_computing))
            {
              if (gn_computing->base.flags & GRIDFLG_GRID_LSA_ENGAGED)
              {
                ospf_grid_computing_lsa_schedule (gn_computing, GRID_REFRESH_THIS_LSA);
                if (IS_DEBUG_GRID_NODE(NSM_CHANGE))
                  zlog_debug("[DBG] ospf_grid_nsm_change: ospf_grid_computing_lsa_schedule (gn_computing, GRID_REFRESH_THIS_LSA)");
              }
              else
              {
                ospf_grid_computing_lsa_schedule (gn_computing, GRID_REORIGINATE_PER_AREA);
                if (IS_DEBUG_GRID_NODE(NSM_CHANGE))
                  zlog_debug("[DBG] ospf_grid_nsm_change: ospf_grid_computing_lsa_schedule (gn_computing, GRID_REORIGINATE_PER_AREA)");
              }
            }
  
            for(ALL_LIST_ELEMENTS(gn->list_of_grid_node_subcluster, node, nnode, gn_subcluster))
            {
              if (gn_subcluster->base.flags & GRIDFLG_GRID_LSA_ENGAGED)
              {
                ospf_grid_subcluster_lsa_schedule (gn_subcluster, GRID_REFRESH_THIS_LSA);
                if (IS_DEBUG_GRID_NODE(NSM_CHANGE))
                  zlog_debug("[DBG] ospf_grid_nsm_change: ospf_grid_subcluster_lsa_schedule (gn_subcluster, GRID_REFRESH_THIS_LSA)");
              }
              else
              {
                ospf_grid_subcluster_lsa_schedule (gn_subcluster, GRID_REORIGINATE_PER_AREA);
                if (IS_DEBUG_GRID_NODE(NSM_CHANGE))
                  zlog_debug("[DBG] ospf_grid_nsm_change: ospf_grid_subcluster_lsa_schedule (gn_subcluster, GRID_REORIGINATE_PER_AREA)");
              }
            }
          }
          else
          {
            if (IS_DEBUG_GRID_NODE(NSM_CHANGE))
            {
              zlog_debug("[DBG] ospf_grid_nsm_change: NSM force opaque originating skipped. Reasons:");
              if (OspfGRID.status != enabled)
                zlog_debug("[DBG] ospf_grid_nsm_change: NSM OspfGris.status not enabled");
              if (gn->area == NULL)
                zlog_debug("[DBG] ospf_grid_nsm_change: NSM gn->area is NULL");
              if (top->instance != UNI)
                zlog_debug("[DBG] ospf_grid_nsm_change: NSM interface is not UNI");
              if (top->interface_side != CLIENT)
                zlog_debug("[DBG] ospf_grid_nsm_change: NSM client side is NETWORK");
            }
          }
        }
      }
    }
    else
    {
      if (IS_DEBUG_GRID_NODE(NSM_CHANGE))
        zlog_debug("[DBG] NSM_STATE_CHANGE: %s->%s grid callback function, but neighbour's ospf is still not operational",
          LOOKUP (ospf_nsm_state_msg, old_state),
          LOOKUP (ospf_nsm_state_msg, nbr->state));
    }
  }
  /* So far, nothing to do here. */
  return;
}
static u_int16_t
show_vty_grid_tlv_header (struct vty *vty, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_header *top = (struct grid_tlv_header *) tlvh;

  if (vty != NULL)
    vty_out (vty, "  Link: %u octets of data%s", ntohs (top->length), VTY_NEWLINE);
  else
    zlog_debug ("    Link: %u octets of data", ntohs (top->length));

  return GRID_TLV_HDR_SIZE;    /* Here is special, not "GRID_TLV_SIZE". */
}

static u_int16_t show_vty_unknown_tlv (struct vty *vty, struct grid_tlv_header *tlvh)
{
  if (vty != NULL)
    vty_out (vty, "  Unknown TLV: [type(0x%x), length(0x%x)]%s", ntohs(tlvh->type), ntohs (tlvh->length), VTY_NEWLINE);
  else
    zlog_debug ("    Unknown TLV: [type(0x%x), length(0x%x)]", ntohs(tlvh->type), ntohs (tlvh->length));

  return GRID_TLV_SIZE (tlvh);
}

static void
stream_padding_put(struct stream *s, uint8_t len)
{
  static uint8_t zeros[3]= {0,0,0};
  int rest = len %4;
  if (rest != 0)
    stream_put (s, zeros, 4-rest);
}


static void
build_grid_tlv_header (struct stream *s, struct grid_tlv_header *tlvh)
{
  stream_put (s, tlvh, sizeof (struct grid_tlv_header));
  return;
}

static void
build_grid_tlv_GridSite_ID(struct stream *s, struct grid_node_site *gn_site)
{
  struct grid_tlv_header *tlvh = &gn_site->gridSite.id.header;
  if (ntohs (tlvh->type) != 0)
  {
    build_grid_tlv_header (s, tlvh);
    stream_put(s, &gn_site->gridSite.id.id, 4);
    stream_padding_put(s, ntohs(tlvh->length));
  }
  return;
}
static void
build_grid_tlv_GridSite_Name(struct stream *s, struct grid_node_site *gn_site)
{
  struct grid_tlv_header *tlvh = &gn_site->gridSite.name.header;
  if (ntohs (tlvh->type) != 0)
  {
    build_grid_tlv_header (s, tlvh);
    struct zlistnode *node, *nnode;
    char *name;
    for (ALL_LIST_ELEMENTS (&gn_site->gridSite.name.name, node, nnode, name))
    {
      stream_put(s, name, 1);
    }
    stream_padding_put(s, ntohs(tlvh->length));
  }
  return;
}
static void
build_grid_tlv_GridSite_Latitude(struct stream *s, struct grid_node_site *gn_site)
{
  struct grid_tlv_header *tlvh = &gn_site->gridSite.latitude.header;
  if (ntohs (tlvh->type) != 0)
  {
    build_grid_tlv_header (s, tlvh);
    stream_put(s, &gn_site->gridSite.latitude.latitude, 5);
    stream_put(s, &gn_site->gridSite.latitude.reserved, 3);
  }
  return;
}
static void
build_grid_tlv_GridSite_Longitude(struct stream *s, struct grid_node_site *gn_site)
{
  struct grid_tlv_header *tlvh = &gn_site->gridSite.longitude.header;
  if (ntohs (tlvh->type) != 0)
  {
    build_grid_tlv_header (s, tlvh);
    stream_put(s, &gn_site->gridSite.longitude.longitude, 5);
    stream_put(s, &gn_site->gridSite.longitude.reserved, 3);
  }
  return;
}
static void
build_grid_tlv_GridSite_PE_Router_ID(struct stream *s, struct grid_node_site *gn_site)
{
  struct grid_tlv_header *tlvh = &gn_site->gridSite.peRouter_id.header;
  if (ntohs (tlvh->type) != 0)
  {
    build_grid_tlv_header (s, tlvh);
    stream_put(s, &gn_site->gridSite.peRouter_id.routerID, 4);
  }
  return;
}
static void
build_grid_tlv_GridSite(struct stream *s, struct grid_node_site *gn_site)
{
  struct grid_tlv_header *tlvh = &gn_site->gridSite.header;
  if ((ntohs (tlvh->type) != 0) && (ntohs (tlvh->length) != 0))
  {
    build_grid_tlv_header (s, tlvh);
    build_grid_tlv_GridSite_ID(s, gn_site);
    build_grid_tlv_GridSite_Name(s, gn_site);
    build_grid_tlv_GridSite_Latitude(s, gn_site);
    build_grid_tlv_GridSite_Longitude(s, gn_site);
    build_grid_tlv_GridSite_PE_Router_ID(s, gn_site);
  }
  return;
}
static void
build_grid_tlv_GridService_ID(struct stream *s, struct grid_node_service *gn_service)
{
  struct grid_tlv_header *tlvh = &gn_service->gridService.id.header;
  if (ntohs (tlvh->type) != 0)
  {
    build_grid_tlv_header (s, tlvh);
    stream_put(s, &gn_service->gridService.id.id, 4);
  }
  return;
}
static void
build_grid_tlv_GridService_ParentSite_ID(struct stream *s, struct grid_node_service *gn_service)
{
  struct grid_tlv_header *tlvh = &gn_service->gridService.parentSite_id.header;
  if (ntohs (tlvh->type) != 0)
  {
    build_grid_tlv_header (s, tlvh);
    stream_put(s, &gn_service->gridService.parentSite_id.parent_site_id, 4);
  }
  return;
}
static void
build_grid_tlv_GridService_ServiceInfo(struct stream *s, struct grid_node_service *gn_service)
{
  struct grid_tlv_header *tlvh = &gn_service->gridService.serviceInfo.header;
  if (ntohs (tlvh->type) != 0)
  {
    build_grid_tlv_header (s, tlvh);
    stream_put(s, &gn_service->gridService.serviceInfo.type, 2);
    stream_put(s, &gn_service->gridService.serviceInfo.version, 2);
  }
  return;
}
static void
build_grid_tlv_GridService_Status(struct stream *s, struct grid_node_service *gn_service)
{
  struct grid_tlv_header *tlvh = &gn_service->gridService.status.header;
  if (ntohs (tlvh->type) != 0)
  {
    build_grid_tlv_header (s, tlvh);
    stream_put(s, &gn_service->gridService.status.status, 1);
    stream_put(s, &gn_service->gridService.status.reserved, 3);
  }
  return;
}
static void
build_grid_tlv_GridService_AddressLength(struct stream *s, struct grid_node_service *gn_service)
{
  struct grid_tlv_header *tlvh = &gn_service->gridService.addressLength.header;
  if (ntohs (tlvh->type) != 0)
  {
    build_grid_tlv_header (s, tlvh);
    stream_put(s, &gn_service->gridService.addressLength.addressLength, 1);
    stream_put(s, &gn_service->gridService.addressLength.padding, 3);
  }
  return;
}
static void
build_grid_tlv_GridService_IPv4Endpoint(struct stream *s, struct grid_node_service *gn_service)
{
  struct grid_tlv_header *tlvh = &gn_service->gridService.ipv4Endpoint.header;
  if (ntohs (tlvh->type) != 0)
  {
    build_grid_tlv_header (s, tlvh);
    stream_put(s, &gn_service->gridService.ipv4Endpoint.ipv4Endp, 4);
  }
  return;
}
static void
build_grid_tlv_GridService_IPv6Endpoint(struct stream *s, struct grid_node_service *gn_service)
{
  struct grid_tlv_header *tlvh = &gn_service->gridService.ipv6Endpoint.header;
  if (ntohs (tlvh->type) != 0)
  {
    build_grid_tlv_header (s, tlvh);
    stream_put(s, &gn_service->gridService.ipv6Endpoint.ipv6Endp, 16);
  }
  return;
}
static void
build_grid_tlv_GridService_NsapEndpoint(struct stream *s, struct grid_node_service *gn_service)
{
  struct grid_tlv_header *tlvh = &gn_service->gridService.nsapEndpoint.header;
  if (ntohs (tlvh->type) != 0)
  {
    build_grid_tlv_header (s, tlvh);
    stream_put(s, &gn_service->gridService.nsapEndpoint.nsapEndp, 20);
  }
  return;
}
static void
build_grid_tlv_GridService(struct stream *s, struct grid_node_service *gn_service)
{
  struct grid_tlv_header *tlvh = &gn_service->gridService.header;
  if ((ntohs (tlvh->type) != 0) && (ntohs (tlvh->length) != 0))
  {
    build_grid_tlv_header (s, tlvh);
    build_grid_tlv_GridService_ID(s, gn_service);
    build_grid_tlv_GridService_ParentSite_ID(s, gn_service);
    build_grid_tlv_GridService_ServiceInfo(s, gn_service);
    build_grid_tlv_GridService_Status(s, gn_service);
    build_grid_tlv_GridService_AddressLength(s, gn_service);
    build_grid_tlv_GridService_IPv4Endpoint(s, gn_service);
    build_grid_tlv_GridService_IPv6Endpoint(s, gn_service);
    build_grid_tlv_GridService_NsapEndpoint(s, gn_service);
  }
  return;
}
static void
build_grid_tlv_GridComputingElement_ID(struct stream *s, struct grid_node_computing *gn_computing)
{
  struct grid_tlv_header *tlvh = &gn_computing->gridCompElement.id.header;
  if (ntohs (tlvh->type) != 0)
  {
    build_grid_tlv_header (s, tlvh);
    stream_put(s, &gn_computing->gridCompElement.id.id, 4);
  }
  return;
}
static void
build_grid_tlv_GridComputingElement_ParentSiteID(struct stream *s, struct grid_node_computing *gn_computing)
{
  struct grid_tlv_header *tlvh = &gn_computing->gridCompElement.parentSiteId.header;
  if (ntohs (tlvh->type) != 0)
  {
    build_grid_tlv_header (s, tlvh);
    stream_put(s, &gn_computing->gridCompElement.parentSiteId.parSiteId, 4);
  }
  return;
}
static void
build_grid_tlv_GridComputingElement_LrmsInfo(struct stream *s, struct grid_node_computing *gn_computing)
{
  struct grid_tlv_header *tlvh = &gn_computing->gridCompElement.lrmsInfo.header;
  if (ntohs (tlvh->type) != 0)
  {
    build_grid_tlv_header (s, tlvh);
    stream_put(s, &gn_computing->gridCompElement.lrmsInfo.lrmsType, 2);
    stream_put(s, &gn_computing->gridCompElement.lrmsInfo.lrmsVersion, 2);
  }
  return;
}
static void
build_grid_tlv_GridComputingElement_AddressLength(struct stream *s, struct grid_node_computing *gn_computing)
{
  struct grid_tlv_header *tlvh = &gn_computing->gridCompElement.addressLength.header;
  if (ntohs (tlvh->type) != 0)
  {
    build_grid_tlv_header (s, tlvh);
    stream_put(s, &gn_computing->gridCompElement.addressLength.addrLength, 1);
    stream_padding_put(s, ntohs(tlvh->length));
  }
  return;
}
static void
build_grid_tlv_GridComputingElement_IPv4HostName(struct stream *s, struct grid_node_computing *gn_computing)
{
  struct grid_tlv_header *tlvh = &gn_computing->gridCompElement.ipv4HostName.header;
  if (ntohs (tlvh->type) != 0)
  {
    build_grid_tlv_header (s, tlvh);
    stream_put(s, &gn_computing->gridCompElement.ipv4HostName.ipv4HostNam, 4);
  }
  return;
}
static void
build_grid_tlv_GridComputingElement_IPv6HostName(struct stream *s, struct grid_node_computing *gn_computing)
{
  struct grid_tlv_header *tlvh = &gn_computing->gridCompElement.ipv6HostName.header;
  if (ntohs (tlvh->type) != 0)
  {
    build_grid_tlv_header (s, tlvh);
    stream_put(s, &gn_computing->gridCompElement.ipv6HostName.ipv6HostNam, 16);
  }
  return;
}
static void
build_grid_tlv_GridComputingElement_NsapHostName(struct stream *s, struct grid_node_computing *gn_computing)
{
  struct grid_tlv_header *tlvh = &gn_computing->gridCompElement.nsapHostName.header;
  if (ntohs (tlvh->type) != 0)
  {
    build_grid_tlv_header (s, tlvh);
    stream_put(s, &gn_computing->gridCompElement.nsapHostName.nsapHostNam, 20);
  }
  return;
}
static void
build_grid_tlv_GridComputingElement_GatekeeperPort(struct stream *s, struct grid_node_computing *gn_computing)
{
  struct grid_tlv_header *tlvh = &gn_computing->gridCompElement.gatekeeperPort.header;
  if (ntohs (tlvh->type) != 0)
  {
    build_grid_tlv_header (s, tlvh);
    stream_put(s, &gn_computing->gridCompElement.gatekeeperPort.gateKPort, 4);
  }
  return;
}
static void
build_grid_tlv_GridComputingElement_JobManager(struct stream *s, struct grid_node_computing *gn_computing)
{
  struct grid_tlv_header *tlvh = &gn_computing->gridCompElement.jobManager.header;
  if (ntohs (tlvh->type) != 0)
  {
    build_grid_tlv_header (s, tlvh);
    struct zlistnode *node, *nnode;
    char *jman;
    for (ALL_LIST_ELEMENTS (&gn_computing->gridCompElement.jobManager.jobManag, node, nnode, jman))
    {
      stream_put(s, jman, 1);
    }
  stream_padding_put(s, ntohs(tlvh->length));
  }
  return;
}
static void
build_grid_tlv_GridComputingElement_DataDir(struct stream *s, struct grid_node_computing *gn_computing)
{
  struct grid_tlv_header *tlvh = &gn_computing->gridCompElement.dataDir.header;
  if (ntohs (tlvh->type) != 0)
  {
    build_grid_tlv_header (s, tlvh);
    struct zlistnode *node, *nnode;
    char *ddir;
    for (ALL_LIST_ELEMENTS (&gn_computing->gridCompElement.dataDir.dataDirStr, node, nnode, ddir))
    {
      stream_put(s, ddir, 1);
    }
  stream_padding_put(s, ntohs(tlvh->length));
  }
  return;
}
static void
build_grid_tlv_GridComputingElement_DefaultStorageElement(struct stream *s, struct grid_node_computing *gn_computing)
{
  struct grid_tlv_header *tlvh = &gn_computing->gridCompElement.defaultSe.header;
  if (ntohs (tlvh->type) != 0)
  {
    build_grid_tlv_header (s, tlvh);
    stream_put(s, &gn_computing->gridCompElement.defaultSe.defaultSelement, 4);
  }
  return;
}
static void
build_grid_tlv_GridComputingElement_JobsStates(struct stream *s, struct grid_node_computing *gn_computing)
{
  struct grid_tlv_header *tlvh = &gn_computing->gridCompElement.jobsStates.header;
  if (ntohs (tlvh->type) != 0)
  {
    build_grid_tlv_header (s, tlvh);
    stream_put(s, &gn_computing->gridCompElement.jobsStates.freeJobSlots, 2);
    stream_put(s, &gn_computing->gridCompElement.jobsStates.status, 1);
    stream_put(s, &gn_computing->gridCompElement.jobsStates.padding, 1);
  }
  return;
}
static void
build_grid_tlv_GridComputingElement_JobsStats(struct stream *s, struct grid_node_computing *gn_computing)
{
  struct grid_tlv_header *tlvh = &gn_computing->gridCompElement.jobsStats.header;
  if (ntohs (tlvh->type) != 0)
  {
    build_grid_tlv_header (s, tlvh);
    stream_put(s, &gn_computing->gridCompElement.jobsStats.runningJobs, 4);
    stream_put(s, &gn_computing->gridCompElement.jobsStats.waitingJobs, 4);
    stream_put(s, &gn_computing->gridCompElement.jobsStats.totalJobs, 4);
  }
  return;
}
static void
build_grid_tlv_GridComputingElement_JobsTimePerformances(struct stream *s, struct grid_node_computing *gn_computing)
{
  struct grid_tlv_header *tlvh = &gn_computing->gridCompElement.jobsTimePerformances.header;
  if (ntohs (tlvh->type) != 0)
  {
    build_grid_tlv_header (s, tlvh);
    stream_put(s, &gn_computing->gridCompElement.jobsTimePerformances.estRespTime, 4);
    stream_put(s, &gn_computing->gridCompElement.jobsTimePerformances.worstRespTime, 4);
  }
  return;
}
static void
build_grid_tlv_GridComputingElement_JobsTimePolicy(struct stream *s, struct grid_node_computing *gn_computing)
{
  struct grid_tlv_header *tlvh = &gn_computing->gridCompElement.jobsTimePolicy.header;
  if (ntohs (tlvh->type) != 0)
  {
    build_grid_tlv_header (s, tlvh);
    stream_put(s, &gn_computing->gridCompElement.jobsTimePolicy.maxWcTime, 4);
    stream_put(s, &gn_computing->gridCompElement.jobsTimePolicy.maxObtWcTime, 4);
    stream_put(s, &gn_computing->gridCompElement.jobsTimePolicy.maxCpuTime, 4);
    stream_put(s, &gn_computing->gridCompElement.jobsTimePolicy.maxObtCpuTime, 4);
  }
  return;
}
static void
build_grid_tlv_GridComputingElement_JobsLoadPolicy(struct stream *s, struct grid_node_computing *gn_computing)
{
  struct grid_tlv_header *tlvh = &gn_computing->gridCompElement.jobsLoadPolicy.header;
  if (ntohs (tlvh->type) != 0)
  {
    build_grid_tlv_header (s, tlvh);
    stream_put(s, &gn_computing->gridCompElement.jobsLoadPolicy.maxTotalJobs, 4);
    stream_put(s, &gn_computing->gridCompElement.jobsLoadPolicy.maxRunJobs, 4);
    stream_put(s, &gn_computing->gridCompElement.jobsLoadPolicy.maxWaitJobs, 4);
    stream_put(s, &gn_computing->gridCompElement.jobsLoadPolicy.assignJobSlots, 2);
    stream_put(s, &gn_computing->gridCompElement.jobsLoadPolicy.maxSlotsPerJob, 2);
    stream_put(s, &gn_computing->gridCompElement.jobsLoadPolicy.priorityPreemptionFlag, 1);
    stream_put(s, &gn_computing->gridCompElement.jobsLoadPolicy.reserved, 3);
  }
  return;
}
static void
build_grid_tlv_GridComputingElement_CeCalendar(struct stream *s, struct grid_node_computing *gn_computing)
{
  struct grid_tlv_header *tlvh = &gn_computing->gridCompElement.ceCalendar.header;
  if (ntohs (tlvh->type) != 0)
  {
    build_grid_tlv_header (s, tlvh);
    struct zlistnode *node, *nnode;
    struct ce_calendar *temp;
    for (ALL_LIST_ELEMENTS (&gn_computing->gridCompElement.ceCalendar.ceCalend, node, nnode, temp))
    {
      stream_put(s, temp, 6);
    }
    if (gn_computing->gridCompElement.ceCalendar.ceCalend.count % 2)
      stream_padding_put(s, 2);
  }
  return;
}
static void
build_grid_tlv_GridComputingElement_Name(struct stream *s, struct grid_node_computing *gn_computing)
{
  struct grid_tlv_header *tlvh = &gn_computing->gridCompElement.name.header;
  if (ntohs (tlvh->type) != 0)
  {
    build_grid_tlv_header (s, tlvh);
    struct zlistnode *node, *nnode;
    char *name;
    for (ALL_LIST_ELEMENTS (&gn_computing->gridCompElement.name.name, node, nnode, name))
    {
      stream_put(s, name, 1);
    }
    stream_padding_put(s, ntohs(tlvh->length));
  }
  return;
}
static void
build_grid_tlv_GridComputingElement(struct stream *s, struct grid_node_computing *gn_computing)
{
  struct grid_tlv_header *tlvh = &gn_computing->gridCompElement.header;
  if ((ntohs (tlvh->type) != 0) && (ntohs (tlvh->length) != 0))
  {
    build_grid_tlv_header (s, tlvh);
    build_grid_tlv_GridComputingElement_ID(s, gn_computing);
    build_grid_tlv_GridComputingElement_ParentSiteID(s, gn_computing);
    build_grid_tlv_GridComputingElement_LrmsInfo(s, gn_computing);
    build_grid_tlv_GridComputingElement_AddressLength(s, gn_computing);
    build_grid_tlv_GridComputingElement_IPv4HostName(s, gn_computing);
    build_grid_tlv_GridComputingElement_IPv6HostName(s, gn_computing);
    build_grid_tlv_GridComputingElement_NsapHostName(s, gn_computing);
    build_grid_tlv_GridComputingElement_GatekeeperPort(s, gn_computing);
    build_grid_tlv_GridComputingElement_JobManager(s, gn_computing);
    build_grid_tlv_GridComputingElement_DataDir(s, gn_computing);
    build_grid_tlv_GridComputingElement_DefaultStorageElement(s, gn_computing);
    build_grid_tlv_GridComputingElement_JobsStates(s, gn_computing);
    build_grid_tlv_GridComputingElement_JobsStats(s, gn_computing);
    build_grid_tlv_GridComputingElement_JobsTimePerformances(s, gn_computing);
    build_grid_tlv_GridComputingElement_JobsTimePolicy(s, gn_computing);
    build_grid_tlv_GridComputingElement_JobsLoadPolicy(s, gn_computing);
    build_grid_tlv_GridComputingElement_CeCalendar(s, gn_computing);
    build_grid_tlv_GridComputingElement_Name(s, gn_computing);
  }
  return;
}
static void
build_grid_tlv_GridSubCluster_ID(struct stream *s, struct grid_node_subcluster *gn_subcluster)
{
  struct grid_tlv_header *tlvh = &gn_subcluster->gridSubcluster.id.header;
  if (ntohs (tlvh->type) != 0)
  {
    build_grid_tlv_header (s, tlvh);
    stream_put(s, &gn_subcluster->gridSubcluster.id.id, 4);
  }
  return;
}
static void
build_grid_tlv_GridSubCluster_ParentSiteID(struct stream *s, struct grid_node_subcluster *gn_subcluster)
{
  struct grid_tlv_header *tlvh = &gn_subcluster->gridSubcluster.parentSiteId.header;
  if (ntohs (tlvh->type) != 0)
  {
    build_grid_tlv_header (s, tlvh);
    stream_put(s, &gn_subcluster->gridSubcluster.parentSiteId.parSiteId, 4);
  }
  return;
}
static void
build_grid_tlv_GridSubCluster_CpuInfo(struct stream *s, struct grid_node_subcluster *gn_subcluster)
{
  struct grid_tlv_header *tlvh = &gn_subcluster->gridSubcluster.cpuInfo.header;
  if (ntohs (tlvh->type) != 0)
  {
    build_grid_tlv_header (s, tlvh);
    stream_put(s, &gn_subcluster->gridSubcluster.cpuInfo.physicalCpus, 4);
    stream_put(s, &gn_subcluster->gridSubcluster.cpuInfo.logicalCpus, 4);
    stream_put(s, &gn_subcluster->gridSubcluster.cpuInfo.cpuArch, 1);
    stream_put(s, &gn_subcluster->gridSubcluster.cpuInfo.reserved, 3);
  }
  return;
}
static void
build_grid_tlv_GridSubCluster_OsInfo(struct stream *s, struct grid_node_subcluster *gn_subcluster)
{
  struct grid_tlv_header *tlvh = &gn_subcluster->gridSubcluster.osInfo.header;
  if (ntohs (tlvh->type) != 0)
  {
    build_grid_tlv_header (s, tlvh);
    stream_put(s, &gn_subcluster->gridSubcluster.osInfo.osType, 2);
    stream_put(s, &gn_subcluster->gridSubcluster.osInfo.osVersion, 2);
  }
  return;
}
static void
build_grid_tlv_GridSubCluster_MemoryInfo(struct stream *s, struct grid_node_subcluster *gn_subcluster)
{
  struct grid_tlv_header *tlvh = &gn_subcluster->gridSubcluster.memoryInfo.header;
  if (ntohs (tlvh->type) != 0)
  {
    build_grid_tlv_header (s, tlvh);
    stream_put(s, &gn_subcluster->gridSubcluster.memoryInfo.ramSize, 4);
    stream_put(s, &gn_subcluster->gridSubcluster.memoryInfo.virtualMemorySize, 4);
  }
  return;
}
static void
build_grid_tlv_GridSubCluster_SoftwarePackage(struct stream *s, struct grid_tlv_GridSubCluster_SoftwarePackage *sp)
{
  struct grid_tlv_header *tlvh = &sp->header;
  if (ntohs (tlvh->type) != 0)
  {
    build_grid_tlv_header (s, tlvh);
    stream_put(s, &sp->softType, 2);
    stream_put(s, &sp->softVersion, 2);

    struct zlistnode *node, *nnode;
    char *eset;
    for (ALL_LIST_ELEMENTS (&sp->environmentSetup, node, nnode, eset))
    {
      stream_put(s, eset, 1);
    }
    stream_padding_put(s, ntohs(tlvh->length));
  }
  return;
}
static void
build_grid_tlv_GridSubCluster_SubClusterCalendar(struct stream *s, struct grid_node_subcluster *gn_subcluster)
{
  struct grid_tlv_header *tlvh = &gn_subcluster->gridSubcluster.subclusterCalendar.header;
  if (ntohs (tlvh->type) != 0)
  {
    build_grid_tlv_header (s, tlvh);
    struct zlistnode *node, *nnode;
    struct sc_calendar *temp;
    for (ALL_LIST_ELEMENTS (&gn_subcluster->gridSubcluster.subclusterCalendar.subcluster_calendar, node, nnode, temp))
    {
      stream_put(s, temp, 8);
    }
    stream_padding_put(s, ntohs(tlvh->length));
  }
  return;
}
static void
build_grid_tlv_GridSubCluster_Name(struct stream *s, struct grid_node_subcluster *gn_subcluster)
{
  struct grid_tlv_header *tlvh = &gn_subcluster->gridSubcluster.name.header;
  if (ntohs (tlvh->type) != 0)
  {
    build_grid_tlv_header (s, tlvh);
    struct zlistnode *node, *nnode;
    char *name;
    for (ALL_LIST_ELEMENTS (&gn_subcluster->gridSubcluster.name.name, node, nnode, name))
    {
      stream_put(s, name, 1);
    }
    stream_padding_put(s, ntohs(tlvh->length));
  }
  return;
}
static void
build_grid_tlv_GridSubCluster(struct stream *s, struct grid_node_subcluster *gn_subcluster)
{
  struct grid_tlv_header *tlvh = &gn_subcluster->gridSubcluster.header;
  if ((ntohs (tlvh->type) != 0) && (ntohs (tlvh->length) != 0))
  {
    build_grid_tlv_header (s, tlvh);
    build_grid_tlv_GridSubCluster_ID(s, gn_subcluster);
    build_grid_tlv_GridSubCluster_ParentSiteID(s, gn_subcluster);
    build_grid_tlv_GridSubCluster_CpuInfo(s, gn_subcluster);
    build_grid_tlv_GridSubCluster_OsInfo(s, gn_subcluster);
    build_grid_tlv_GridSubCluster_MemoryInfo(s, gn_subcluster);

    struct zlistnode *node, *nnode;
    struct grid_tlv_GridSubCluster_SoftwarePackage *sp;
    for (ALL_LIST_ELEMENTS(&gn_subcluster->gridSubcluster.softwarePackage, node, nnode, sp))
      build_grid_tlv_GridSubCluster_SoftwarePackage(s, sp);

    build_grid_tlv_GridSubCluster_SubClusterCalendar(s, gn_subcluster);
    build_grid_tlv_GridSubCluster_Name(s, gn_subcluster);
  }
  return;
}
static void
build_grid_tlv_GridStorage_ID(struct stream *s, struct grid_node_storage *gn_storage)
{
  struct grid_tlv_header *tlvh = &gn_storage->gridStorage.id.header;
  if (ntohs (tlvh->type) != 0)
  {
    build_grid_tlv_header (s, tlvh);
    stream_put(s, &gn_storage->gridStorage.id.id, 4);
  }
  return;
}
static void
build_grid_tlv_GridStorage_ParentSiteID(struct stream *s, struct grid_node_storage *gn_storage)
{
  struct grid_tlv_header *tlvh = &gn_storage->gridStorage.parentSiteId.header;
  if (ntohs (tlvh->type) != 0)
  {
    build_grid_tlv_header (s, tlvh);
    stream_put(s, &gn_storage->gridStorage.parentSiteId.parSiteId, 4);
  }
  return;
}
static void
build_grid_tlv_GridStorage_StorageInfo(struct stream *s, struct grid_node_storage *gn_storage)
{
  struct grid_tlv_header *tlvh = &gn_storage->gridStorage.storageInfo.header;
  if (ntohs (tlvh->type) != 0)
  {
    build_grid_tlv_header (s, tlvh);
    stream_put(s, &gn_storage->gridStorage.storageInfo.storInfo, 4);
  }
  return;
}
static void
build_grid_tlv_GridStorage_OnlineSize(struct stream *s, struct grid_node_storage *gn_storage)
{
  struct grid_tlv_header *tlvh = &gn_storage->gridStorage.onlineSize.header;
  if (ntohs (tlvh->type) != 0)
  {
    build_grid_tlv_header (s, tlvh);
    stream_put(s, &gn_storage->gridStorage.onlineSize.totalSize, 4);
    stream_put(s, &gn_storage->gridStorage.onlineSize.usedSize, 4);
  }
  return;
}
static void
build_grid_tlv_GridStorage_NearlineSize(struct stream *s, struct grid_node_storage *gn_storage)
{
  struct grid_tlv_header *tlvh = &gn_storage->gridStorage.nearlineSize.header;
  if (ntohs (tlvh->type) != 0)
  {
    build_grid_tlv_header (s, tlvh);
    stream_put(s, &gn_storage->gridStorage.nearlineSize.totalSize, 4);
    stream_put(s, &gn_storage->gridStorage.nearlineSize.usedSize, 4);
  }
  return;
}
static void
build_grid_tlv_GridStorage_StorageArea(struct stream *s, struct grid_tlv_GridStorage_StorageArea *StArea)
{
  struct grid_tlv_header *tlvh = (struct grid_tlv_header*) StArea;
  if (ntohs (tlvh->type) != 0)
  {
    build_grid_tlv_header (s, tlvh);
    struct zlistnode *node, *nnode;

    char *name;
    for (ALL_LIST_ELEMENTS (&StArea->name, node, nnode, name))
    {
      stream_put(s, name, 1);
    }
    char *path;
    for (ALL_LIST_ELEMENTS (&StArea->path, node, nnode, path))
    {
      stream_put(s, path, 1);
    }

    stream_put(s, &StArea->totalOnlineSize, 4);
    stream_put(s, &StArea->freeOnlineSize, 4);
    stream_put(s, &StArea->resTotalOnlineSize, 4);
    stream_put(s, &StArea->totalNearlineSize, 4);
    stream_put(s, &StArea->freeNearlineSize, 4);
    stream_put(s, &StArea->resNearlineSize, 4);
    stream_put(s, &StArea->retPolAccLat, 1);
    stream_put(s, &StArea->expirationMode, 1);
    stream_put(s, &StArea->reserved, 2);
  }
  return;
}
static void
build_grid_tlv_GridStorage_SeCalendar(struct stream *s, struct grid_node_storage *gn_storage)
{
  struct grid_tlv_header *tlvh = &gn_storage->gridStorage.seCalendar.header;
  if (ntohs (tlvh->type) != 0)
  {
    build_grid_tlv_header (s, tlvh);
    struct zlistnode *node, *nnode;
    struct se_calendar *temp;
    for (ALL_LIST_ELEMENTS (&gn_storage->gridStorage.seCalendar.seCalendar, node, nnode, temp))
    {
      stream_put(s, temp, 12);
    }
    stream_padding_put(s, ntohs(tlvh->length));
  }
  return;
}
static void
build_grid_tlv_GridStorage_Name(struct stream *s, struct grid_node_storage *gn_storage)
{
  struct grid_tlv_header *tlvh = &gn_storage->gridStorage.name.header;
  if (ntohs (tlvh->type) != 0)
  {
    build_grid_tlv_header (s, tlvh);
    struct zlistnode *node, *nnode;
    char *name;
    for (ALL_LIST_ELEMENTS (&gn_storage->gridStorage.name.name, node, nnode, name))
    {
      stream_put(s, name, 1);
    }
    stream_padding_put(s, ntohs(tlvh->length));
  }
  return;
}
static void
build_grid_tlv_GridStorage(struct stream *s, struct grid_node_storage *gn_storage)
{
  struct grid_tlv_header *tlvh = &gn_storage->gridStorage.header;
  if ((ntohs (tlvh->type) != 0) && (ntohs (tlvh->length) != 0))
  {
    build_grid_tlv_header (s, tlvh);
    build_grid_tlv_GridStorage_ID(s, gn_storage);
    build_grid_tlv_GridStorage_ParentSiteID(s, gn_storage);
    build_grid_tlv_GridStorage_StorageInfo(s, gn_storage);
    build_grid_tlv_GridStorage_OnlineSize(s, gn_storage);
    build_grid_tlv_GridStorage_NearlineSize(s, gn_storage);

    struct zlistnode *node, *nnode;
    struct grid_tlv_GridStorage_StorageArea *StArea;
    for(ALL_LIST_ELEMENTS (&gn_storage->gridStorage.storageArea, node, nnode, StArea))
      build_grid_tlv_GridStorage_StorageArea(s, StArea);

    build_grid_tlv_GridStorage_SeCalendar(s, gn_storage);
    build_grid_tlv_GridStorage_Name(s, gn_storage);
  }
  return;
}
static u_int16_t
show_vty_grid_tlv_GridSite_ID(struct vty *vty, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridSite_ID *top;
  top = (struct grid_tlv_GridSite_ID *) tlvh;
  if (vty != NULL)
  {
    vty_out (vty, "  Identifier of the Site: %u%s", ntohl(top->id), VTY_NEWLINE);
  }
  else
  {
    zlog_debug ("  Identifier of the Site: %u", ntohl(top->id));
  }
  return GRID_TLV_SIZE (tlvh);
}
static u_int16_t
show_vty_grid_tlv_GridSite_Name_FromStruct(struct vty *vty, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridSite_Name *top;
  top = (struct grid_tlv_GridSite_Name *) tlvh;

  if (vty != NULL)
  {
    vty_out (vty, "  Name: ");
    char* name;
    struct zlistnode *node, *nnode;
    for (ALL_LIST_ELEMENTS (&top->name, node, nnode, name))
    {
      char temp = *name;
      vty_out(vty, "%c", temp);
    }
    vty_out(vty, "%s", VTY_NEWLINE);
  }
  else
  {
    zlog_debug ("  Name: ");
    char* name;
    struct zlistnode *node, *nnode;
    for (ALL_LIST_ELEMENTS (&top->name, node, nnode, name))
    {
      char temp = *name;
      zlog_debug("%c", temp);
    }
  }

  return GRID_TLV_SIZE (tlvh);
}
static u_int16_t
show_vty_grid_tlv_GridSite_Name_FromTlv(struct vty *vty, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridSite_Name *top;
  top = (struct grid_tlv_GridSite_Name *) tlvh;
  if (vty != NULL)
  {
    int len = ntohs(top->header.length);
    int i;
    vty_out (vty, "  GridSite Name: ");
    char* ptr = (char*) &top->name;
    for (i=0; i< len; i++)
    {
      vty_out (vty, "%c", *(ptr));
      ptr++;
    }
    vty_out (vty, "%s", VTY_NEWLINE);
  }
  else
  {
    int len = ntohs(top->header.length);
    int i;
    zlog_debug ("  GridSite: ");
    char* ptr = (char*) &top->name;
    for (i=0; i< len; i++)
    {
      zlog_debug ("%c", *(ptr));
      ptr++;
    }
  }
  return GRID_TLV_SIZE (tlvh);
}
static u_int16_t  
show_vty_grid_tlv_GridSite_Latitude(struct vty *vty, struct grid_tlv_header *tlvh)
{
  if (GRID_TLV_BODY_SIZE (tlvh) == 0)
    return GRID_TLV_SIZE (tlvh);
  struct grid_tlv_GridSite_Latitude *top;
  top = (struct grid_tlv_GridSite_Latitude *) tlvh;
  int i;
  u_int64_t val=0;
  u_int64_t temp;

  if (vty != NULL)
  {
    vty_out (vty, "  Latitude: %s",VTY_NEWLINE);
    for (i=0; i<5; i++)
    {
      val |= (uint8_t)top->latitude[i];
      if(i < 4)val <<= 8;
    }
    val <<= 24;
    temp = val & 0xfc00000000000000;
    temp >>= 58;
    vty_out (vty, "    Resolution: 0x%x%s", (uint32_t) temp, VTY_NEWLINE);
    temp = val & 0x03fe000000000000;
    temp >>= 49;
    vty_out (vty, "    Integer part: 0x%x%s", (uint32_t) temp, VTY_NEWLINE);
    temp = val & 0x0001ffffff000000;
    temp >>= 24;
    vty_out (vty, "    Fractional part: 0x%x%s", (uint32_t) temp, VTY_NEWLINE);
  }
  else
  {
    zlog_debug ("  Latitude: ");
    for (i=0; i<5; i++)
    {
      val |= (uint8_t)top->latitude[i];
      if(i < 4)val <<= 8;
    }
    val <<= 24;
    temp = val & 0xfc00000000000000;
    temp >>= 58;
    zlog_debug ("    Resolution: 0x%x", (uint32_t) temp);
    temp = val & 0x03fe000000000000;
    temp >>= 49;
    zlog_debug ("    Integer part: 0x%x", (uint32_t) temp);
    temp = val & 0x0001ffffff000000;
    temp >>= 24;
    zlog_debug ("    Fractional part: 0x%x", (uint32_t) temp);
  }
  return GRID_TLV_SIZE (tlvh);
}
static u_int16_t
show_vty_grid_tlv_GridSite_Longitude(struct vty *vty, struct grid_tlv_header *tlvh)
{
  if (GRID_TLV_BODY_SIZE (tlvh) == 0)
    return GRID_TLV_SIZE (tlvh);
  struct grid_tlv_GridSite_Longitude *top;
  top = (struct grid_tlv_GridSite_Longitude *) tlvh;
  int i;
  u_int64_t val=0;
  u_int64_t temp;

  if (vty != NULL)
  {
    vty_out (vty, "  Longitude: %s",VTY_NEWLINE);
    for (i=0; i<5; i++)
    {
      val |= (uint8_t)top->longitude[i];
      if(i < 4)val <<= 8;
    }
    val <<= 24;
    temp = val & 0xfc00000000000000;
    temp >>= 58;
    vty_out (vty, "    Resolution: 0x%x%s", (uint32_t) temp, VTY_NEWLINE);
    temp = val & 0x03fe000000000000;
    temp >>= 49;
    vty_out (vty, "    Integer part: 0x%x%s", (uint32_t) temp, VTY_NEWLINE);
    temp = val & 0x0001ffffff000000;
    temp >>= 24;
    vty_out (vty, "    Fractional part: 0x%x%s", (uint32_t) temp, VTY_NEWLINE);
  }
  else
  {
    zlog_debug ("  Longitude: ");
    for (i=0; i<5; i++)
    {
      val |= (uint8_t)top->longitude[i];
      if(i < 4)val <<= 8;
    }
    val <<= 24;
    temp = val & 0xfc00000000000000;
    temp >>= 58;
    zlog_debug ("    Resolution: 0x%x", (uint32_t) temp);
    temp = val & 0x03fe000000000000;
    temp >>= 49;
    zlog_debug ("    Integer part: 0x%x", (uint32_t) temp);
    temp = val & 0x0001ffffff000000;
    temp >>= 24;
    zlog_debug ("    Fractional part: 0x%x", (uint32_t) temp);
  }
  return GRID_TLV_SIZE (tlvh);
}
static u_int16_t
show_vty_grid_tlv_GridSite_PE_Router_ID(struct vty *vty, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridSite_PE_Router_ID *top;
  top = (struct grid_tlv_GridSite_PE_Router_ID *) tlvh;
  if (vty != NULL)
  {
    vty_out (vty, "  Provider Edge router ID: %s%s", inet_ntoa (top->routerID), VTY_NEWLINE);
  }
  else
  {
    zlog_debug ("  Provider Edge router ID: %s", inet_ntoa (top->routerID));
  }
  return GRID_TLV_SIZE (tlvh);
}
static u_int16_t
show_vty_grid_tlv_GridSite (struct vty *vty, struct grid_tlv_header *tlvh0, u_int16_t subtotal, u_int16_t total)
{
  struct grid_tlv_header *tlvh;
  u_int16_t sum = subtotal;
  for (tlvh = tlvh0; sum < total; tlvh = GRID_TLV_HDR_NEXT (tlvh))
  {
    switch (ntohs (tlvh->type))
    {
      case GRID_TLV_GRIDSITE_ID:      /* Unique Identifier of the Site */
        sum += show_vty_grid_tlv_GridSite_ID(vty, tlvh);
        break;
      case GRID_TLV_GRIDSITE_NAME:      /* Human-readable name */
        sum += show_vty_grid_tlv_GridSite_Name_FromTlv(vty, tlvh);
        break;
      case GRID_TLV_GRIDSITE_LATITUDE:      /* Degree the position of a place north or south of the equator */
        sum += show_vty_grid_tlv_GridSite_Latitude(vty, tlvh);
        break;
      case GRID_TLV_GRIDSITE_LONGITUDE:      /* Degree the position of a place east or west of Greenwich */
        sum += show_vty_grid_tlv_GridSite_Longitude(vty, tlvh);
        break;
      case GRID_TLV_GRIDSITE_PEROUTERID:     /* PE router ID */
        sum += show_vty_grid_tlv_GridSite_PE_Router_ID(vty, tlvh);
        break;
      default:
        sum += show_vty_unknown_tlv (vty, tlvh);
    }
  }
  return sum - subtotal;
}
static u_int16_t
show_vty_grid_tlv_GridService_ID(struct vty *vty, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridService_ID *top;
  top = (struct grid_tlv_GridService_ID *) tlvh;
  if (vty != NULL)
  {
    vty_out (vty, "  Identifier of the Service: %u%s", ntohl(top->id), VTY_NEWLINE);
  }
  else
  {
    zlog_debug ("  Identifier of the Service: %u", ntohl(top->id));
  }
  return GRID_TLV_SIZE (tlvh);
}
static u_int16_t
show_vty_grid_tlv_GridService_ParentSite_ID(struct vty *vty, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridService_ParentSite_ID *top;
  top = (struct grid_tlv_GridService_ParentSite_ID *) tlvh;
  if (vty != NULL)
  {
    vty_out (vty, "  Identifier of the Grid Site: %u%s", ntohl(top->parent_site_id), VTY_NEWLINE);
  }
  else
  {
    zlog_debug ("  Identifier of the Grid Site: %u", ntohl(top->parent_site_id));
  }
  return GRID_TLV_SIZE (tlvh);
}
static u_int16_t
show_vty_grid_tlv_GridService_ServiceInfo(struct vty *vty, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridService_ServiceInfo *top;
  top = (struct grid_tlv_GridService_ServiceInfo *) tlvh;
  if (vty != NULL)
  {
    vty_out (vty, "  The service type: %u%s", ntohs(top->type), VTY_NEWLINE);
    vty_out (vty, "  Version of the service: %u%s", ntohs(top->version), VTY_NEWLINE);
  }
  else
  {
    zlog_debug ("  The service type: %u", ntohs(top->type));
    zlog_debug ("  Version of the service: %u", ntohs(top->version));
  }
  return GRID_TLV_SIZE (tlvh);
}
static u_int16_t
show_vty_grid_tlv_GridService_Status(struct vty *vty, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridService_Status *top;
  top = (struct grid_tlv_GridService_Status *) tlvh;
  if (vty != NULL)
  {
    vty_out (vty, "  Status of the service: %d%s", (top->status), VTY_NEWLINE);
  }
  else
  {
    zlog_debug ("  Status of the service: %d", (top->status));
  }
  return GRID_TLV_SIZE (tlvh);
}
static u_int16_t
show_vty_grid_tlv_GridService_AddressLength(struct vty *vty, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridService_AddressLength *top;
  top = (struct grid_tlv_GridService_AddressLength *) tlvh;
  if (vty != NULL)
  {
    vty_out (vty, "  Length of the endpoint address: %d%s", (uint8_t) top->addressLength, VTY_NEWLINE);
  }
  else
  {
    zlog_debug ("  Length of the endpoint address: %d", (uint8_t) top->addressLength);
  }
  return GRID_TLV_SIZE (tlvh);
}
static u_int16_t
show_vty_grid_tlv_GridService_IPv4Endpoint(struct vty *vty, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridService_IPv4Endpoint *top;
  top = (struct grid_tlv_GridService_IPv4Endpoint *) tlvh;
  if (vty != NULL)
  {
    vty_out (vty, "  Network endpoint for this service (IPv4 address): %s%s", inet_ntoa (top->ipv4Endp), VTY_NEWLINE);
  }
  else
  {
    zlog_debug ("  Network endpoint for this service (IPv4 address): %s", inet_ntoa (top->ipv4Endp));
  }
  return GRID_TLV_SIZE (tlvh);
}
static u_int16_t
show_vty_grid_tlv_GridService_IPv6Endpoint(struct vty *vty, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridService_IPv6Endpoint *top;
  top = (struct grid_tlv_GridService_IPv6Endpoint *) tlvh;
  if (vty != NULL)
  {
    vty_out (vty, "  Network endpoint for this service (IPv6 address): %s%s", inet6_ntoa (top->ipv6Endp), VTY_NEWLINE);
  }
  else
  {
    zlog_debug ("  Network endpoint for this service (IPv6 address): %s", inet6_ntoa (top->ipv6Endp));
  }
  return GRID_TLV_SIZE (tlvh);
}
static u_int16_t
show_vty_grid_tlv_GridService_NsapEndpoint(struct vty *vty, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridService_NsapEndpoint *top;
  top = (struct grid_tlv_GridService_NsapEndpoint *) tlvh;
  int i;

  if (vty != NULL)
  {
    vty_out (vty, "  Network endpoint for this service (NSAP address): ");
    for (i=0; i<5; i++)
    {
      vty_out (vty, "%x ", (u_int32_t) ntohl (top->nsapEndp[i]));
    }
    vty_out (vty, "%s", VTY_NEWLINE);
  }
  else
  {
    zlog_debug ("  Network endpoint for this service (NSAP address): ");
    for (i=0; i<5; i++)
    {
      zlog_debug ("0x%x", (u_int32_t) ntohl (top->nsapEndp[i]));
    }
  }
  return GRID_TLV_SIZE (tlvh);
}
static u_int16_t
show_vty_grid_tlv_GridService (struct vty *vty, struct grid_tlv_header *tlvh0, u_int16_t subtotal, u_int16_t total)
{
  struct grid_tlv_header *tlvh;
  u_int16_t sum = subtotal;
  for (tlvh = tlvh0; sum < total; tlvh = GRID_TLV_HDR_NEXT (tlvh))
  {
    switch (ntohs (tlvh->type))
    {
      case GRID_TLV_GRIDSERVICE_ID:      /* Unique Identifier of the Service */
        sum += show_vty_grid_tlv_GridService_ID(vty, tlvh);
        break;
      case GRID_TLV_GRIDSERVICE_PARENTSITE_ID:      /* Identifier of the Grid Site that is exporting this service */
        sum += show_vty_grid_tlv_GridService_ParentSite_ID(vty, tlvh);
        break;
      case GRID_TLV_GRIDSERVICE_SERVICEINFO:      /* The service info including service type and version */
        sum += show_vty_grid_tlv_GridService_ServiceInfo(vty, tlvh);
        break;
      case GRID_TLV_GRIDSERVICE_STATUS:      /* Status of the service */
        sum += show_vty_grid_tlv_GridService_Status(vty, tlvh);
        break;
      case GRID_TLV_GRIDSERVICE_ADDRESSLENGTH:      /* Length of the endpoint address */
        sum += show_vty_grid_tlv_GridService_AddressLength(vty, tlvh);
        break;
      case GRID_TLV_GRIDSERVICE_IPV4ENDPOINT:      /* Network endpoint for this service */
        sum += show_vty_grid_tlv_GridService_IPv4Endpoint(vty, tlvh);
        break;
      case GRID_TLV_GRIDSERVICE_IPV6ENDPOINT:      /* Network endpoint for this service */
        sum += show_vty_grid_tlv_GridService_IPv6Endpoint(vty, tlvh);
        break;
      case GRID_TLV_GRIDSERVICE_NSAPENDPOINT:      /* Network endpoint for this service */
        sum += show_vty_grid_tlv_GridService_NsapEndpoint(vty, tlvh);
        break;
      default:
        sum += show_vty_unknown_tlv (vty, tlvh);
    }
  }
  return sum - subtotal;
}
static u_int16_t
show_vty_grid_tlv_GridComputingElement_ID(struct vty *vty, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridComputingElement_ID *top;
  top = (struct grid_tlv_GridComputingElement_ID *) tlvh;
  if (vty != NULL)
  {
    vty_out (vty, "  Identifier of the Computing Element: %u%s", ntohl(top->id), VTY_NEWLINE);
  }
  else
  {
    zlog_debug ("  Identifier of the Computing Element: %u", ntohl(top->id));
  }
  return GRID_TLV_SIZE (tlvh);
}
static u_int16_t
show_vty_grid_tlv_GridComputingElement_ParentSiteID(struct vty *vty, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridComputingElement_ParentSiteID *top;
  top = (struct grid_tlv_GridComputingElement_ParentSiteID *) tlvh;
  if (vty != NULL)
  {
    vty_out (vty, "  Identifier of the Grid Site: %u%s", ntohl(top->parSiteId), VTY_NEWLINE);
  }
  else
  {
    zlog_debug ("  Identifier of the Grid Site: %u", ntohl(top->parSiteId));
  }
  return GRID_TLV_SIZE (tlvh);
}
static u_int16_t
show_vty_grid_tlv_GridComputingElement_LrmsInfo(struct vty *vty, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridComputingElement_LrmsInfo *top;
  top = (struct grid_tlv_GridComputingElement_LrmsInfo *) tlvh;
  if (vty != NULL)
  {
    vty_out (vty, "  LRMS Type: %u%s", ntohs(top->lrmsType), VTY_NEWLINE);
    vty_out (vty, "  LRMS Version: %u%s", ntohs(top->lrmsVersion), VTY_NEWLINE);
  }
  else
  {
    zlog_debug ("  LRMS Type: %u", ntohs(top->lrmsType));
    zlog_debug ("  LRMS Version: %u", ntohs(top->lrmsVersion));
  }
  return GRID_TLV_SIZE (tlvh);
}
static u_int16_t
show_vty_grid_tlv_GridComputingElement_AddressLength(struct vty *vty, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridComputingElement_AddressLength *top;
  top = (struct grid_tlv_GridComputingElement_AddressLength *) tlvh;
  if (vty != NULL)
  {
    vty_out (vty, "  Length of the host name address: %d%s", (uint8_t) top->addrLength, VTY_NEWLINE);
  }
  else
  {
    zlog_debug ("  Length of the host name address: %d", (uint8_t) top->addrLength);
  }
  return GRID_TLV_SIZE (tlvh);
}
static u_int16_t
show_vty_grid_tlv_GridComputingElement_IPv4HostName(struct vty *vty, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridComputingElement_IPv4HostName *top;
  top = (struct grid_tlv_GridComputingElement_IPv4HostName *) tlvh;
  if (vty != NULL)
  {
    vty_out (vty, "  Host name of the machine (IPv4 address): %s%s", inet_ntoa(top->ipv4HostNam), VTY_NEWLINE);
  }
  else
  {
    zlog_debug ("  Host name of the machine (IPv4 address): %s", inet_ntoa(top->ipv4HostNam));
  }
  return GRID_TLV_SIZE (tlvh);
}
static u_int16_t
show_vty_grid_tlv_GridComputingElement_IPv6HostName(struct vty *vty, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridComputingElement_IPv6HostName *top;
  top = (struct grid_tlv_GridComputingElement_IPv6HostName *) tlvh;
  if (vty != NULL)
  {
    vty_out (vty, "  Host name of the machine (IPv6 address): %s%s", inet6_ntoa(top->ipv6HostNam), VTY_NEWLINE);
  }
  else
  {
    zlog_debug ("  Host name of the machine (IPv6 address): %s", inet6_ntoa(top->ipv6HostNam));
  }
  return GRID_TLV_SIZE (tlvh);
}
static u_int16_t
show_vty_grid_tlv_GridComputingElement_NsapHostName(struct vty *vty, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridComputingElement_NsapHostName *top;
  top = (struct grid_tlv_GridComputingElement_NsapHostName *) tlvh;
  int i;

  if (vty != NULL)
  {
    vty_out (vty, "  Host name of the machine (NSAP address): ");
    for (i=0; i<5; i++)
    {
      vty_out (vty, "%x ", (u_int32_t) ntohl (top->nsapHostNam[i]));
    }
    vty_out (vty, "%s", VTY_NEWLINE);
  }
  else
  {
    zlog_debug ("  Host name of the machine (NSAP address): ");
    for (i=0; i<5; i++)
    {
      zlog_debug ("0x%x", (u_int32_t) ntohl (top->nsapHostNam[i]));
    }
  }
  return GRID_TLV_SIZE (tlvh);
}
static u_int16_t
show_vty_grid_tlv_GridComputingElement_GatekeeperPort(struct vty *vty, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridComputingElement_GatekeeperPort *top;
  top = (struct grid_tlv_GridComputingElement_GatekeeperPort *) tlvh;
  if (vty != NULL)
  {
    vty_out (vty, "  Gatekeeper port: %u%s", ntohl(top->gateKPort), VTY_NEWLINE);
  }
  else
  {
    zlog_debug ("  Gatekeeper port: %u", ntohl(top->gateKPort));
  }
  return GRID_TLV_SIZE (tlvh);
}
static u_int16_t
show_vty_grid_tlv_GridComputingElement_JobManager_FromStruct(struct vty *vty, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridComputingElement_JobManager *top;
  top = (struct grid_tlv_GridComputingElement_JobManager *) tlvh;
  char* jman;
  char temp;
  if (vty != NULL)
  {
    vty_out (vty, "  Job Manager: ");

    struct zlistnode *node, *nnode;
    for (ALL_LIST_ELEMENTS (&top->jobManag, node, nnode, jman))
    {
      temp = *jman;
      vty_out(vty, "%c", temp);
    }
    vty_out(vty, "%s", VTY_NEWLINE);
  }
  else
  {
    zlog_debug ("  Job Manager: ");
    struct zlistnode *node, *nnode;
    for (ALL_LIST_ELEMENTS (&top->jobManag, node, nnode, jman))
    {
      temp = *jman;
      zlog_debug("%c", temp);
    }
  }

  return GRID_TLV_SIZE (tlvh);
}
static u_int16_t
show_vty_grid_tlv_GridComputingElement_JobManager_FromTlv(struct vty *vty, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridComputingElement_JobManager *top;
  top = (struct grid_tlv_GridComputingElement_JobManager *) tlvh;
  if (vty != NULL)
  {
    int len = ntohs(top->header.length);
    int i;
    vty_out (vty, "  Job Manager: ");
    char* ptr = (char*) &top->jobManag;
    for (i=0; i< len; i++)
    {
      vty_out (vty, "%c", *(ptr));
      ptr++;
    }
    vty_out (vty, "%s", VTY_NEWLINE);
  }
  else
  {
    int len = ntohs(top->header.length);
    int i;
    zlog_debug ("  Job Manager: ");
    char* ptr = (char*) &top->jobManag;
    for (i=0; i< len; i++)
    {
      zlog_debug ("%c", *(ptr));
      ptr++;
    }
  }
  return GRID_TLV_SIZE (tlvh);
}
static u_int16_t
show_vty_grid_tlv_GridComputingElement_DataDir_FromStruct(struct vty *vty, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridComputingElement_DataDir *top;
  top = (struct grid_tlv_GridComputingElement_DataDir *) tlvh;
  char *ddir;
  char temp;

  if (vty != NULL)
  {
    vty_out (vty, "  Data Dir: ");
    struct zlistnode *node, *nnode;
    for (ALL_LIST_ELEMENTS (&top->dataDirStr, node, nnode, ddir))
    {
      temp = *ddir;
      vty_out(vty, "%c", temp);
    }
    vty_out(vty, "%s", VTY_NEWLINE);
  }
  else
  {
    zlog_debug ("  Data Dir: ");
    struct zlistnode *node, *nnode;
    for (ALL_LIST_ELEMENTS (&top->dataDirStr, node, nnode, ddir))
    {
      temp = *ddir;
      zlog_debug("%c", temp);
    }
  }

  return GRID_TLV_SIZE (tlvh);
}
static u_int16_t
show_vty_grid_tlv_GridComputingElement_DataDir_FromTlv(struct vty *vty, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridComputingElement_DataDir *top;
  top = (struct grid_tlv_GridComputingElement_DataDir *) tlvh;
  if (vty != NULL)
  {
    int len = ntohs(top->header.length);
    int i;
    vty_out (vty, "  Data Dir: ");
    char* ptr = (char*) &top->dataDirStr;
    for (i=0; i< len; i++)
    {
      vty_out (vty, "%c", *(ptr));
      ptr++;
    }
    vty_out (vty, "%s", VTY_NEWLINE);
  }
  else
  {
    int len = ntohs(top->header.length);
    int i;
    zlog_debug ("  GridSite: ");
    char* ptr = (char*) &top->dataDirStr;
    for (i=0; i< len; i++)
    {
      zlog_debug ("%c", *(ptr));
      ptr++;
    }
  }
  return GRID_TLV_SIZE (tlvh);
}
static u_int16_t
show_vty_grid_tlv_GridComputingElement_DefaultStorageElement(struct vty *vty, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridComputingElement_DefaultStorageElement *top;
  top = (struct grid_tlv_GridComputingElement_DefaultStorageElement *) tlvh;
  if (vty != NULL)
  {
    vty_out (vty, "  The unique identifier of the default Storage Element: %u%s", ntohl(top->defaultSelement), VTY_NEWLINE);
  }
  else
  {
    zlog_debug ("  The unique identifier of the default Storage Element: %u", ntohl(top->defaultSelement));
  }
  return GRID_TLV_SIZE (tlvh);
}
static u_int16_t
show_vty_grid_tlv_GridComputingElement_JobsStates(struct vty *vty, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridComputingElement_JobsStates *top;
  top = (struct grid_tlv_GridComputingElement_JobsStates *) tlvh;
  if (vty != NULL)
  {
    vty_out (vty, "  The number of free job slots: %u%s", ntohs(top->freeJobSlots), VTY_NEWLINE);
    vty_out (vty, "  Status: %d%s", (top->status), VTY_NEWLINE);
  }
  else
  {
    zlog_debug ("  The number of free job slots: %u", ntohs(top->freeJobSlots));
    zlog_debug ("  Status: %d", (top->status));
  }
  return GRID_TLV_SIZE (tlvh);
}
static u_int16_t
show_vty_grid_tlv_GridComputingElement_JobsStats(struct vty *vty, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridComputingElement_JobsStats *top;
  top = (struct grid_tlv_GridComputingElement_JobsStats *) tlvh;
  if (vty != NULL)
  {
    vty_out (vty, "  Number of jobs in running state: %u%s", ntohl(top->runningJobs), VTY_NEWLINE);
    vty_out (vty, "  Number of jobs in waiting state: %u%s", ntohl(top->waitingJobs), VTY_NEWLINE);
    vty_out (vty, "  Number of jobs in any state: %u%s", ntohl(top->totalJobs), VTY_NEWLINE);
  }
  else
  {
    zlog_debug ("  Number of jobs in running state: %u", ntohl(top->runningJobs));
    zlog_debug ("  Number of jobs in waiting state: %u", ntohl(top->waitingJobs));
    zlog_debug ("  Number of jobs in any state: %u", ntohl(top->totalJobs));
  }
  return GRID_TLV_SIZE (tlvh);
}
static u_int16_t
show_vty_grid_tlv_GridComputingElement_JobsTimePerformances(struct vty *vty, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridComputingElement_JobsTimePerformances *top;
  top = (struct grid_tlv_GridComputingElement_JobsTimePerformances *) tlvh;
  if (vty != NULL)
  {
    vty_out (vty, "  Estimated response time: %u%s", ntohl(top->estRespTime), VTY_NEWLINE);
    vty_out (vty, "  Worst response time: %u%s", ntohl(top->worstRespTime), VTY_NEWLINE);
  }
  else
  {
    zlog_debug ("  Estimated response time: %u", ntohl(top->estRespTime));
    zlog_debug ("  Worst response time: %u", ntohl(top->worstRespTime));
  }
  return GRID_TLV_SIZE (tlvh);
}
static u_int16_t
show_vty_grid_tlv_GridComputingElement_JobsTimePolicy(struct vty *vty, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridComputingElement_JobsTimePolicy *top;
  top = (struct grid_tlv_GridComputingElement_JobsTimePolicy *) tlvh;
  if (vty != NULL)
  {
    vty_out (vty, "  The default maximum wall clock time: %u%s", ntohl(top->maxWcTime), VTY_NEWLINE);
    vty_out (vty, "  The maximum obtainable wall clock time: %u%s", ntohl(top->maxObtWcTime), VTY_NEWLINE);
    vty_out (vty, "  The default maximum CPU time: %u%s", ntohl(top->maxCpuTime), VTY_NEWLINE);
    vty_out (vty, "  The maximum obtainable CPU time: %u%s", ntohl(top->maxObtCpuTime), VTY_NEWLINE);
  }
  else
  {
    zlog_debug ("  The default maximum wall clock time: %u", ntohl(top->maxWcTime));
    zlog_debug ("  The maximum obtainable wall clock time: %u", ntohl(top->maxObtWcTime));
    zlog_debug ("  The default maximum CPU time: %u", ntohl(top->maxCpuTime));
    zlog_debug ("  The maximum obtainable CPU time: %u", ntohl(top->maxObtCpuTime));
  }
  return GRID_TLV_SIZE (tlvh);
}
static u_int16_t
show_vty_grid_tlv_GridComputingElement_JobsLoadPolicy(struct vty *vty, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridComputingElement_JobsLoadPolicy *top;
  top = (struct grid_tlv_GridComputingElement_JobsLoadPolicy *) tlvh;
  char val;
  if (vty != NULL)
  {
    vty_out (vty, "  The maximum allowed number of jobs in the CE: %u%s", ntohl(top->maxTotalJobs), VTY_NEWLINE);
    vty_out (vty, "  The maximum allowed number of jobs in running state in the CE: %u%s", ntohl(top->maxRunJobs), VTY_NEWLINE);
    vty_out (vty, "  The maximum allowed number of jobs in waiting state in the CE: %u%s", ntohl(top->maxWaitJobs), VTY_NEWLINE);
    vty_out (vty, "  Number of slots for jobs to be in running state: %u%s", ntohs(top->assignJobSlots), VTY_NEWLINE);
    vty_out (vty, "  The maximum number of slots per single job: %u%s", ntohs(top->maxSlotsPerJob), VTY_NEWLINE);
    val = top->priorityPreemptionFlag >> 1;
    vty_out (vty, "  Jobs priority: %d%s", val, VTY_NEWLINE);
    val = top->priorityPreemptionFlag & 0x1;
    if (val) vty_out (vty, "  Pre-emption flag: TRUE%s", VTY_NEWLINE);
    else vty_out (vty, "  Pre-emption flag: FALSE%s", VTY_NEWLINE);
  }
  else
  {
    zlog_debug ("  The maximum allowed number of jobs in the CE: %u", ntohl(top->maxTotalJobs));
    zlog_debug ("  The maximum allowed number of jobs in running state in the CE: %u", ntohl(top->maxRunJobs));
    zlog_debug ("  The maximum allowed number of jobs in waiting state in the CE: %u", ntohl(top->maxWaitJobs));
    zlog_debug ("  Number of slots for jobs to be in running state: %u", ntohs(top->assignJobSlots));
    zlog_debug ("  The maximum number of slots per single job: %u", ntohs(top->maxSlotsPerJob));
    val = top->priorityPreemptionFlag >> 1;
    zlog_debug ("  Jobs priority: %d", val);
    val = top->priorityPreemptionFlag & 0x1;
    if (val) zlog_debug ("  Pre-emption flag: TRUE");
    else zlog_debug ("  Pre-emption flag: FALSE");
  }
  return GRID_TLV_SIZE (tlvh);
}
static u_int16_t
show_vty_grid_tlv_GridComputingElement_CeCalendar_FromStruct(struct vty *vty, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridComputingElement_CeCalendar *top;
  top = (struct grid_tlv_GridComputingElement_CeCalendar *) tlvh;
  uint32_t temp_time;
  uint16_t temp_freeJS;
  if (vty != NULL)
  {
    vty_out (vty, "  Computing Element Calendar: %s", VTY_NEWLINE);
    struct ce_calendar* temp_ptr;
    struct zlistnode *node, *nnode;
    for (ALL_LIST_ELEMENTS (&top->ceCalend, node, nnode, temp_ptr))
    {
      temp_time = ntohl(temp_ptr->time);
      temp_freeJS = ntohs(temp_ptr->freeJobSlots);
      vty_out(vty, "    Timestamp: %u  FreeJobsSlots: %u%s", temp_time, temp_freeJS, VTY_NEWLINE);
    }
  }
  else
  {
    zlog_debug ("  Computing Element Calendar:");
    struct ce_calendar* temp_ptr;
    struct zlistnode *node, *nnode;
    for (ALL_LIST_ELEMENTS (&top->ceCalend, node, nnode, temp_ptr))
    {
      temp_time = ntohl(temp_ptr->time);
      temp_freeJS = ntohs(temp_ptr->freeJobSlots);
      zlog_debug("    Timestamp: %u  FreeJobsSlots: %u", temp_time, temp_freeJS);
    }
  }
  return GRID_TLV_SIZE (tlvh);
}
static u_int16_t
show_vty_grid_tlv_GridComputingElement_CeCalendar_FromTlv(struct vty *vty, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridComputingElement_CeCalendar *top;
  top = (struct grid_tlv_GridComputingElement_CeCalendar *) tlvh;
  if (vty != NULL)
  {
    int len = ntohs(top->header.length) - GRID_TLV_GRIDCOMPUTINGELEMENT_CECALENDAR_CONST_DATA_LENGTH;
    int i;
    vty_out (vty, "  Computing Element Calendar: %s", VTY_NEWLINE);

    struct ce_calendar* ptr = (struct ce_calendar*) (void *) &top->ceCalend;
    for (i=0; i< len-2; i=i+6)
    {
      vty_out (vty, "    Timestamp: %u  FreeJobsSlots: %u%s", ntohl(ptr->time), ntohs(ptr->freeJobSlots), VTY_NEWLINE);
      ptr++;
    }
  }
  else
  {
    int len = ntohs(top->header.length) - GRID_TLV_GRIDCOMPUTINGELEMENT_CECALENDAR_CONST_DATA_LENGTH;
    int i;
    zlog_debug ("  Computing Element Calendar:");

    struct ce_calendar* ptr = (struct ce_calendar*) (void *) &top->ceCalend;
    for (i=0; i< len; i=i+6)
    {
      zlog_debug ("    Timestamp: %u  FreeJobsSlots: %u", ntohl(ptr->time), ntohs(ptr->freeJobSlots));
      ptr++;
    }
  }
  return GRID_TLV_SIZE (tlvh);
}
static u_int16_t
show_vty_grid_tlv_GridComputingElement_Name_FromStruct(struct vty *vty, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridComputingElement_Name *top;
  top = (struct grid_tlv_GridComputingElement_Name *) tlvh;

  if (vty != NULL)
  {
    vty_out (vty, "  Name: ");
    char* name;
    struct zlistnode *node, *nnode;
    for (ALL_LIST_ELEMENTS (&top->name, node, nnode, name))
    {
      char temp = *name;
      vty_out(vty, "%c", temp);
    }
    vty_out(vty, "%s", VTY_NEWLINE);
  }
  else
  {
    zlog_debug ("  Name: ");
    char* name;
    struct zlistnode *node, *nnode;
    for (ALL_LIST_ELEMENTS (&top->name, node, nnode, name))
    {
      char temp = *name;
      zlog_debug("%c", temp);
    }
  }

  return GRID_TLV_SIZE (tlvh);
}
static u_int16_t
show_vty_grid_tlv_GridComputingElement_Name_FromTlv(struct vty *vty, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridComputingElement_Name *top;
  top = (struct grid_tlv_GridComputingElement_Name *) tlvh;
  if (vty != NULL)
  {
    int len = ntohs(top->header.length);
    int i;
    vty_out (vty, "  Name: ");
    char* ptr = (char*) &top->name;
    for (i=0; i< len; i++)
    {
      vty_out (vty, "%c", *(ptr));
      ptr++;
    }
    vty_out (vty, "%s", VTY_NEWLINE);
  }
  else
  {
    int len = ntohs(top->header.length);
    int i;
    zlog_debug ("  Name: ");
    char* ptr = (char*) &top->name;
    for (i=0; i< len; i++)
    {
      zlog_debug ("%c", *(ptr));
      ptr++;
    }
  }
  return GRID_TLV_SIZE (tlvh);
}
static u_int16_t
show_vty_grid_tlv_GridComputingElement_FromTlv (struct vty *vty, struct grid_tlv_header *tlvh0, u_int16_t subtotal, u_int16_t total)
{
  struct grid_tlv_header *tlvh;
  u_int16_t sum = subtotal;
  for (tlvh = tlvh0; sum < total; tlvh = GRID_TLV_HDR_NEXT (tlvh))
  {
    switch (ntohs (tlvh->type))
    {
      case GRID_TLV_GRIDCOMPUTINGELEMENT_ID:      /* Unique Identifier of the Computing Element */
        sum += show_vty_grid_tlv_GridComputingElement_ID(vty, tlvh);
        break;
      case GRID_TLV_GRIDCOMPUTINGELEMENT_PARENTSITEID:      /* Identifier of the Grid Site that is exporting this computing element */
        sum += show_vty_grid_tlv_GridComputingElement_ParentSiteID(vty, tlvh);
        break;
      case GRID_TLV_GRIDCOMPUTINGELEMENT_LRMSINFO:      /* Type and version of the underlying LRMS */
        sum += show_vty_grid_tlv_GridComputingElement_LrmsInfo(vty, tlvh);
        break;
      case GRID_TLV_GRIDCOMPUTINGELEMENT_ADDRESSLENGTH:      /* Length of the host name address */
        sum += show_vty_grid_tlv_GridComputingElement_AddressLength(vty, tlvh);
        break;
      case GRID_TLV_GRIDCOMPUTINGELEMENT_IPV4HOSTNAME:      /* Host name of the machine running this service */
        sum += show_vty_grid_tlv_GridComputingElement_IPv4HostName(vty, tlvh);
        break;
      case GRID_TLV_GRIDCOMPUTINGELEMENT_IPV6HOSTNAME:      /* Host name of the machine running this service */
        sum += show_vty_grid_tlv_GridComputingElement_IPv6HostName(vty, tlvh);
        break;
      case GRID_TLV_GRIDCOMPUTINGELEMENT_NSAPHOSTNAME:      /* Host name of the machine running this service */
        sum += show_vty_grid_tlv_GridComputingElement_NsapHostName(vty, tlvh);
        break;
      case GRID_TLV_GRIDCOMPUTINGELEMENT_GATEKEEPERPORT:      /* Gatekeeper port */
        sum += show_vty_grid_tlv_GridComputingElement_GatekeeperPort(vty, tlvh);
        break;
      case GRID_TLV_GRIDCOMPUTINGELEMENT_JOBMANAGER:      /* The job manager used by the gatekeeper */
        sum += show_vty_grid_tlv_GridComputingElement_JobManager_FromTlv(vty, tlvh);
        break;
      case GRID_TLV_GRIDCOMPUTINGELEMENT_DATADIR:      /* String representing the path of a run directory */
        sum += show_vty_grid_tlv_GridComputingElement_DataDir_FromTlv(vty, tlvh);
        break;
      case GRID_TLV_GRIDCOMPUTINGELEMENT_DEFAULTSTORAGEELEMENT:      /* The unique identifier of the default Storage Element */
        sum += show_vty_grid_tlv_GridComputingElement_DefaultStorageElement(vty, tlvh);
        break;
      case GRID_TLV_GRIDCOMPUTINGELEMENT_JOBSSTATES:      /* It contains the number of free job slots, and the queue status */
        sum += show_vty_grid_tlv_GridComputingElement_JobsStates(vty, tlvh);
        break;
      case GRID_TLV_GRIDCOMPUTINGELEMENT_JOBSSTATS:      /* It contains the number of jobs in running, waiting, any state */
        sum += show_vty_grid_tlv_GridComputingElement_JobsStats(vty, tlvh);
        break;
      case GRID_TLV_GRIDCOMPUTINGELEMENT_JOBSTIMEPERFORMANCES:      /* The estimated time and the worst time to last for a new job from the acceptance to the start of its execution */
        sum += show_vty_grid_tlv_GridComputingElement_JobsTimePerformances(vty, tlvh);
        break;
      case GRID_TLV_GRIDCOMPUTINGELEMENT_JOBSTIMEPOLICY:      /* The maximum wall clock time, the maximum obtainable wall clock time, the default maximum CPU time allowed to each job by the batch system and finally the maximum obtainable CPU time that can be granted to the job upon user request */
        sum += show_vty_grid_tlv_GridComputingElement_JobsTimePolicy(vty, tlvh);
        break;
      case GRID_TLV_GRIDCOMPUTINGELEMENT_JOBSLOADPOLICY:      /* Jobs Load Policy */
        sum += show_vty_grid_tlv_GridComputingElement_JobsLoadPolicy(vty, tlvh);
        break;
      case GRID_TLV_GRIDCOMPUTINGELEMENT_CECALENDAR:      /* The jobs scheduling calendar reporting the available FreeJobsSlots for each timestamp */
        sum += show_vty_grid_tlv_GridComputingElement_CeCalendar_FromTlv(vty, tlvh);
        break;
      case GRID_TLV_GRIDCOMPUTINGELEMENT_NAME:
        sum += show_vty_grid_tlv_GridComputingElement_Name_FromTlv(vty, tlvh);
        break;
      default:
        sum += show_vty_unknown_tlv (vty, tlvh);
    }
  }
  return sum - subtotal;
}
static u_int16_t
show_vty_grid_tlv_GridSubCluster_ID(struct vty *vty, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridSubCluster_ID *top;
  top = (struct grid_tlv_GridSubCluster_ID *) tlvh;
  if (vty != NULL)
  {
    vty_out (vty, "  Identifier of the Sub-Cluster: %u%s", ntohl(top->id), VTY_NEWLINE);
  }
  else
  {
    zlog_debug ("  Identifier of the Sub-Cluster: %u", ntohl(top->id));
  }
  return GRID_TLV_SIZE (tlvh);
}
static u_int16_t
show_vty_grid_tlv_GridSubCluster_ParentSiteID(struct vty *vty, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridSubCluster_ParentSiteID *top;
  top = (struct grid_tlv_GridSubCluster_ParentSiteID *) tlvh;
  if (vty != NULL)
  {
    vty_out (vty, "  Identifier of the Grid Site: %u%s", ntohl(top->parSiteId), VTY_NEWLINE);
  }
  else
  {
    zlog_debug ("  Identifier of the Grid Site: %u", ntohl(top->parSiteId));
  }
  return GRID_TLV_SIZE (tlvh);
}
static u_int16_t
show_vty_grid_tlv_GridSubCluster_CpuInfo(struct vty *vty, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridSubCluster_CpuInfo *top;
  top = (struct grid_tlv_GridSubCluster_CpuInfo *) tlvh;
  if (vty != NULL)
  {
    vty_out (vty, "  Total number of CPUs: %u%s", ntohl(top->physicalCpus), VTY_NEWLINE);
    vty_out (vty, "  Effective number of CPUs: %u%s", ntohl(top->logicalCpus), VTY_NEWLINE);
    vty_out (vty, "  The CPU architecture: %d%s", (top->cpuArch), VTY_NEWLINE);
  }
  else
  {
    zlog_debug ("  Total number of CPUs: %u", ntohl(top->physicalCpus));
    zlog_debug ("  Effective number of CPUs: %u", ntohl(top->logicalCpus));
    zlog_debug ("  The CPU architecture: %d", (top->cpuArch));
  }
  return GRID_TLV_SIZE (tlvh);
}
static u_int16_t
show_vty_grid_tlv_GridSubCluster_OsInfo(struct vty *vty, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridSubCluster_OsInfo *top;
  top = (struct grid_tlv_GridSubCluster_OsInfo *) tlvh;
  if (vty != NULL)
  {
    vty_out (vty, "  OS Type: %u%s", ntohs(top->osType), VTY_NEWLINE);
    vty_out (vty, "  OS Version: %u%s", ntohs(top->osVersion), VTY_NEWLINE);
  }
  else
  {
    zlog_debug ("  OS Type: %u", ntohs(top->osType));
    zlog_debug ("  OS Version: %u", ntohs(top->osVersion));
  }
  return GRID_TLV_SIZE (tlvh);
}
static u_int16_t
show_vty_grid_tlv_GridSubCluster_MemoryInfo(struct vty *vty, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridSubCluster_MemoryInfo *top;
  top = (struct grid_tlv_GridSubCluster_MemoryInfo *) tlvh;
  if (vty != NULL)
  {
    vty_out (vty, "  RAM Size in MB: %u%s", ntohl(top->ramSize), VTY_NEWLINE);
    vty_out (vty, "  Virtual Memory Size in MB: %u%s", ntohl(top->virtualMemorySize), VTY_NEWLINE);
  }
  else
  {
    zlog_debug ("  RAM Size in MB: %u", ntohl(top->ramSize));
    zlog_debug ("  Virtual Memory Size in MB: %u", ntohl(top->virtualMemorySize));
  }
  return GRID_TLV_SIZE (tlvh);
}
static u_int16_t
show_vty_grid_tlv_GridSubCluster_SoftwarePackage_FromStruct(struct vty *vty, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridSubCluster_SoftwarePackage *top;
  top = (struct grid_tlv_GridSubCluster_SoftwarePackage *) tlvh;
  if (vty != NULL)
  {
    vty_out (vty, "  Software Package: %s", VTY_NEWLINE);
    vty_out (vty, "    Software Type: %u%s", ntohs(top->softType), VTY_NEWLINE);
    vty_out (vty, "    Software Version: %u%s", ntohs(top->softVersion), VTY_NEWLINE);
    vty_out (vty, "    Environment Setup: ");
    struct zlistnode *node, *nnode;
    char *eset;
    for (ALL_LIST_ELEMENTS (&top->environmentSetup, node, nnode, eset))
      vty_out(vty, "%c", *eset);
    vty_out(vty, "%s", VTY_NEWLINE);
  }
  else
  {
    zlog_debug ("  Software Package");
    zlog_debug ("    Software Type: %u", ntohs(top->softType));
    zlog_debug ("    Software Version: %u", ntohs(top->softVersion));
    zlog_debug ("    Environment Setup: ");
    struct zlistnode *node, *nnode;
    char *eset;
    for (ALL_LIST_ELEMENTS (&top->environmentSetup, node, nnode, eset))
      zlog_debug("%c", *eset);
  }
  return GRID_TLV_SIZE (tlvh);
}

static u_int16_t
show_vty_grid_tlv_GridSubCluster_SoftwarePackage_FromTlv(struct vty *vty, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridSubCluster_SoftwarePackage *top;
  top = (struct grid_tlv_GridSubCluster_SoftwarePackage *) tlvh;
  if (vty != NULL)
  {
    vty_out (vty, "  Software Package: %s", VTY_NEWLINE);
    vty_out (vty, "    Software Type: %u%s", ntohs(top->softType), VTY_NEWLINE);
    vty_out (vty, "    Software Version: %u%s", ntohs(top->softVersion), VTY_NEWLINE);
  }
  else
  {
    zlog_debug ("  Software Type: %u", ntohs(top->softType));
    zlog_debug ("  Software Version: %u", ntohs(top->softVersion));
  }

  if (vty != NULL)
  {
    int len = ntohs(top->header.length);
    int i;
    vty_out (vty, "    Environment Setup: ");
    char* ptr = (char*) &top->environmentSetup;
    for (i=0; i< len; i++)
    {
      vty_out (vty, "%c", *(ptr));
      ptr++;
    }
    vty_out (vty, "%s", VTY_NEWLINE);
  }
  else
  {
    int len = ntohs(top->header.length);
    int i;
    zlog_debug ("  Environment Setup: ");
    char* ptr = (char*) &top->environmentSetup;
    for (i=0; i< len; i++)
    {
      zlog_debug ("%c", *(ptr));
      ptr++;
    }
  }
  return GRID_TLV_SIZE (tlvh);
}

static u_int16_t
show_vty_grid_tlv_GridSubCluster_SubClusterCalendar_FromStruct(struct vty *vty, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridSubCluster_SubClusterCalendar *top;
  top = (struct grid_tlv_GridSubCluster_SubClusterCalendar *) tlvh;
  uint32_t temp_time;
  uint16_t temp_pcpus;
  uint16_t temp_lcpus;
  if (vty != NULL)
  {
    vty_out (vty, "  SubCluster Calendar: %s",VTY_NEWLINE);
    struct sc_calendar* temp_ptr;
    struct zlistnode *node, *nnode;
    for (ALL_LIST_ELEMENTS (&top->subcluster_calendar, node, nnode, temp_ptr))
    {
      temp_time = ntohl(temp_ptr->time);
      temp_pcpus = ntohs(temp_ptr->physical_cpus);
      temp_lcpus = ntohs(temp_ptr->logical_cpus);
      vty_out(vty, "    Timestamp: %u  Physical CPUs: %u  Logical CPUs: %u%s", temp_time, temp_pcpus, temp_lcpus, VTY_NEWLINE);
    }
  }
  else
  {
    zlog_debug ("  SubCluster Calendar:");
    struct sc_calendar* temp_ptr;
    struct zlistnode *node, *nnode;
    for (ALL_LIST_ELEMENTS (&top->subcluster_calendar, node, nnode, temp_ptr))
    {
      uint32_t temp_time = ntohl(temp_ptr->time);
      uint16_t temp_pcpus = ntohs(temp_ptr->physical_cpus);
      uint16_t temp_lcpus = ntohs(temp_ptr->logical_cpus);
      zlog_debug("    Timestamp: %u  Physical CPUs: %u  Logical CPUs: %u", temp_time, temp_pcpus, temp_lcpus);
    }
  }
  return GRID_TLV_SIZE (tlvh);
}
static u_int16_t
show_vty_grid_tlv_GridSubCluster_SubClusterCalendar_FromTlv(struct vty *vty, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridSubCluster_SubClusterCalendar *top;
  top = (struct grid_tlv_GridSubCluster_SubClusterCalendar *) tlvh;
  if (vty != NULL)
  {
    int len = ntohs(top->header.length) - GRID_TLV_GRIDSUBCLUSTER_SUBCLUSTERCALENDAR_CONST_DATA_LENGTH;
    int i;
    vty_out (vty, "  SubCluster Calendar: %s", VTY_NEWLINE);
    struct sc_calendar* ptr = (struct sc_calendar*) (void *) &top->subcluster_calendar;
    for (i=0; i< len; i=i+8)
    {
      vty_out (vty, "    Timestamp: %u  Physical CPUs: %u  Logical CPUs: %u %s", ntohl(ptr->time), ntohs(ptr->physical_cpus), ntohs(ptr->logical_cpus), VTY_NEWLINE);
      ptr++;
    }
  }
  else
  {
    int len = ntohs(top->header.length) - GRID_TLV_GRIDSUBCLUSTER_SUBCLUSTERCALENDAR_CONST_DATA_LENGTH;
    int i;
    zlog_debug ("  SubCluster Calendar: ");
    struct sc_calendar* ptr = (struct sc_calendar*) (void *) &top->subcluster_calendar;
    for (i=0; i< len; i=i+8)
    {
      zlog_debug ("    Timestamp: %u  Physical CPUs: %u  Logical CPUs: %u", ntohl(ptr->time), ntohs(ptr->physical_cpus), ntohs(ptr->logical_cpus));
      ptr++;
    }
  }
  return GRID_TLV_SIZE (tlvh);
}
static u_int16_t
show_vty_grid_tlv_GridSubCluster_Name_FromStruct(struct vty *vty, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridSubCluster_Name *top;
  top = (struct grid_tlv_GridSubCluster_Name *) tlvh;

  if (vty != NULL)
  {
    vty_out (vty, "  Name: ");
    char* name;
    struct zlistnode *node, *nnode;
    for (ALL_LIST_ELEMENTS (&top->name, node, nnode, name))
    {
      char temp = *name;
      vty_out(vty, "%c", temp);
    }
    vty_out(vty, "%s", VTY_NEWLINE);
  }
  else
  {
    zlog_debug ("  Name: ");
    char* name;
    struct zlistnode *node, *nnode;
    for (ALL_LIST_ELEMENTS (&top->name, node, nnode, name))
    {
      char temp = *name;
      zlog_debug("%c", temp);
    }
  }

  return GRID_TLV_SIZE (tlvh);
}
static u_int16_t
show_vty_grid_tlv_GridSubCluster_Name_FromTlv(struct vty *vty, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridSubCluster_Name *top;
  top = (struct grid_tlv_GridSubCluster_Name *) tlvh;
  if (vty != NULL)
  {
    int len = ntohs(top->header.length);
    int i;
    vty_out (vty, "  Name: ");
    char* ptr = (char*) &top->name;
    for (i=0; i< len; i++)
    {
      vty_out (vty, "%c", *(ptr));
      ptr++;
    }
    vty_out (vty, "%s", VTY_NEWLINE);
  }
  else
  {
    int len = ntohs(top->header.length);
    int i;
    zlog_debug ("  Name: ");
    char* ptr = (char*) &top->name;
    for (i=0; i< len; i++)
    {
      zlog_debug ("%c", *(ptr));
      ptr++;
    }
  }
  return GRID_TLV_SIZE (tlvh);
}
static u_int16_t
show_vty_grid_tlv_GridSubCluster_FromTlv (struct vty *vty, struct grid_tlv_header *tlvh0, u_int16_t subtotal, u_int16_t total)
{
  struct grid_tlv_header *tlvh;
  u_int16_t sum = subtotal;
  for (tlvh = tlvh0; sum < total; tlvh = GRID_TLV_HDR_NEXT (tlvh))
  {
    switch (ntohs (tlvh->type))
    {
      case GRID_TLV_GRIDSUBCLUSTER_ID:      /* Unique Identifier of the Sub-Cluster */
        sum += show_vty_grid_tlv_GridSubCluster_ID(vty, tlvh);
        break;
      case GRID_TLV_GRIDSUBCLUSTER_PARENTSITEID:      /* Identifier of the Grid Site that is exporting this sub-cluster */
        sum += show_vty_grid_tlv_GridSubCluster_ParentSiteID(vty, tlvh);
        break;
      case GRID_TLV_GRIDSUBCLUSTER_CPUINFO:      /* The CPU architecture, the total and the effective number of CPUs */
        sum += show_vty_grid_tlv_GridSubCluster_CpuInfo(vty, tlvh);
        break;
      case GRID_TLV_GRIDSUBCLUSTER_OSINFO:      /* Information about the type of the OS and its version */
        sum += show_vty_grid_tlv_GridSubCluster_OsInfo(vty, tlvh);
        break;
      case GRID_TLV_GRIDSUBCLUSTER_MEMORYINFO:      /* The amount of RAM and Virtual Memory (in MB) */
        sum += show_vty_grid_tlv_GridSubCluster_MemoryInfo(vty, tlvh);
        break;
      case GRID_TLV_GRIDSUBCLUSTER_SOFTWAREPACKAGE:
        sum += show_vty_grid_tlv_GridSubCluster_SoftwarePackage_FromTlv(vty, tlvh);
        break;
      case GRID_TLV_GRIDSUBCLUSTER_SUBCLUSTERCALENDAR:      /* The PhysicalCPUs and LogicalCPUs scheduling calendar for each timestamp */
        sum += show_vty_grid_tlv_GridSubCluster_SubClusterCalendar_FromTlv(vty, tlvh);
        break;
      case GRID_TLV_GRIDSUBCLUSTER_NAME:
        sum += show_vty_grid_tlv_GridSubCluster_Name_FromTlv(vty, tlvh);
        break;
      default:
        sum += show_vty_unknown_tlv (vty, tlvh);
    }
  }
  return sum - subtotal;
}
static u_int16_t
show_vty_grid_tlv_GridStorage_ID(struct vty *vty, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridStorage_ID *top;
  top = (struct grid_tlv_GridStorage_ID *) tlvh;
  if (vty != NULL)
  {
    vty_out (vty, "  Identifier of the Storage Element: %u%s", ntohl(top->id), VTY_NEWLINE);
  }
  else
  {
    zlog_debug ("  Identifier of the Storage Element: %u", ntohl(top->id));
  }
  return GRID_TLV_SIZE (tlvh);
}
static u_int16_t
show_vty_grid_tlv_GridStorage_ParentSiteID(struct vty *vty, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridStorage_ParentSiteID *top;
  top = (struct grid_tlv_GridStorage_ParentSiteID *) tlvh;
  if (vty != NULL)
  {
    vty_out (vty, "  Identifier of the Grid Site: %u%s", ntohl(top->parSiteId), VTY_NEWLINE);
  }
  else
  {
    zlog_debug ("  Identifier of the Grid Site: %u", ntohl(top->parSiteId));
  }
  return GRID_TLV_SIZE(tlvh);
}
static u_int16_t
show_vty_grid_tlv_GridStorage_StorageInfo(struct vty *vty, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridStorage_StorageInfo *top;
  top = (struct grid_tlv_GridStorage_StorageInfo *) tlvh;
  u_int32_t temp;
  if (vty != NULL)
  {
    vty_out (vty, "  Storage Info:%s", VTY_NEWLINE);
    temp = ntohl(top->storInfo) & 0xf0000000;
    temp >>= 28;
    vty_out (vty, "    The storage architecture: 0x%x%s", temp, VTY_NEWLINE);
    temp = ntohl(top->storInfo) & 0x0f000000;
    temp >>= 24;
    vty_out (vty, "    Status: 0x%x%s", temp, VTY_NEWLINE);
    temp = ntohl(top->storInfo) & 0x00fff000;
    temp >>= 12;
    vty_out (vty, "    Access protocol: 0x%x%s", temp, VTY_NEWLINE);
    temp = ntohl(top->storInfo) & 0x00000fff; 
    vty_out (vty, "    Control protocol: 0x%x%s", temp, VTY_NEWLINE);
  }
  else
  {
    zlog_debug ("  Storage Info:");
    temp = ntohl(top->storInfo) & 0xf0000000;
    temp >>= 28;
    zlog_debug ("    The storage architecture: 0x%x", temp);
    temp = ntohl(top->storInfo) & 0x0f000000;
    temp >>= 24;
    zlog_debug ("    Status: 0x%x", temp);
    temp = ntohl(top->storInfo) & 0x00fff000;
    temp >>= 12;
    zlog_debug ("    Access protocol: 0x%x", temp);
    temp = ntohl(top->storInfo) & 0x00000fff; 
    zlog_debug ("    Control protocol: 0x%x", temp);
  }
  return GRID_TLV_SIZE (tlvh);
}
static u_int16_t
show_vty_grid_tlv_GridStorage_OnlineSize(struct vty *vty, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridStorage_OnlineSize *top;
  top = (struct grid_tlv_GridStorage_OnlineSize *) tlvh;
  if (vty != NULL)
  {
    vty_out (vty, "  Online total Size in GB: %u%s", ntohl(top->totalSize), VTY_NEWLINE);
    vty_out (vty, "  Online used Size in GB: %u%s", ntohl(top->usedSize), VTY_NEWLINE);
  }
  else
  {
    zlog_debug ("  Online total Size in GB: %u", ntohl(top->totalSize));
    zlog_debug ("  Unline used Size in GB: %u", ntohl(top->usedSize));
  }
  return GRID_TLV_SIZE (tlvh);
}
static u_int16_t
show_vty_grid_tlv_GridStorage_NearlineSize(struct vty *vty, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridStorage_NearlineSize *top;
  top = (struct grid_tlv_GridStorage_NearlineSize *) tlvh;
  if (vty != NULL)
  {
    vty_out (vty, "  Nearline total Size in GB: %u%s", ntohl(top->totalSize), VTY_NEWLINE);
    vty_out (vty, "  Nearline used Size in GB: %u%s", ntohl(top->usedSize), VTY_NEWLINE);
  }
  else
  {
    zlog_debug ("  Total Size in GB: %u", ntohl(top->totalSize));
    zlog_debug ("  Used Size in GB: %u", ntohl(top->usedSize));
  }
  return GRID_TLV_SIZE (tlvh);
}
static u_int16_t
show_vty_grid_tlv_GridStorage_StorageArea_FromStruct(struct vty *vty, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridStorage_StorageArea *top;
  top = (struct grid_tlv_GridStorage_StorageArea *) tlvh;
  char *name; char *path;
  char temp;
  if (vty != NULL)
  {
    vty_out (vty, "  Storage Area: %s",VTY_NEWLINE);
    vty_out (vty, "    Name: ");
    struct zlistnode *node, *nnode;
    for (ALL_LIST_ELEMENTS (&top->name, node, nnode, name))
    {
      temp = *name;
      if (temp != '\0')
        vty_out(vty, "%c", temp);
    }
    vty_out(vty, "%s    Path: ", VTY_NEWLINE);

    for (ALL_LIST_ELEMENTS (&top->path, node, nnode, path))
    {
      temp = *path;
      if (temp != '\0')
        vty_out(vty, "%c", temp);
    }
    vty_out(vty, "%s", VTY_NEWLINE);
  }
  else
  {
    zlog_debug ("  Storage Area: ");
    zlog_debug ("    Name: ");
    struct zlistnode *node, *nnode;
    for (ALL_LIST_ELEMENTS (&top->name, node, nnode, name))
    {
      temp = *name;
      zlog_debug ("%c", temp);
    }
    zlog_debug ("    Path: ");
    for (ALL_LIST_ELEMENTS (&top->path, node, nnode, path))
    {
      temp = *path;
      zlog_debug("%c", temp);
    }
  }
  
  if (vty != NULL)
  {
    vty_out (vty, "    Total online size: %u%s", ntohl(top->totalOnlineSize), VTY_NEWLINE);
    vty_out (vty, "    Free online size: %u%s", ntohl(top->freeOnlineSize), VTY_NEWLINE);
    vty_out (vty, "    Reserved total online size: %u%s", ntohl(top->resTotalOnlineSize), VTY_NEWLINE);
    vty_out (vty, "    Total nearline size: %u%s", ntohl(top->totalNearlineSize), VTY_NEWLINE);
    vty_out (vty, "    Free nearline size: %u%s", ntohl(top->freeNearlineSize), VTY_NEWLINE);
    vty_out (vty, "    Reserved nearline size: %u%s", ntohl(top->resNearlineSize), VTY_NEWLINE);
    temp = (uint8_t) top->retPolAccLat >> 4;
    vty_out (vty, "    Retention policy (4 bits): %u%s", temp, VTY_NEWLINE);
    temp = (uint8_t) top->retPolAccLat & 0xf;
    vty_out (vty, "    Access latency (4 bits): %u%s", temp, VTY_NEWLINE);
    temp = (uint8_t) top->expirationMode >> 4;
    vty_out (vty, "    Expiration mode (4 bits): %d%s", temp, VTY_NEWLINE);
  }
  else
  {
    zlog_debug ("  Total online size: %u", ntohl(top->totalOnlineSize));
    zlog_debug ("  Free online size: %u", ntohl(top->freeOnlineSize));
    zlog_debug ("  Reserved total online size: %u", ntohl(top->resTotalOnlineSize));
    zlog_debug ("  Total nearline size: %u", ntohl(top->totalNearlineSize));
    zlog_debug ("  Free nearline size: %u", ntohl(top->freeNearlineSize));
    zlog_debug ("  Reserved nearline size: %u", ntohl(top->resNearlineSize));
    temp = (uint8_t) top->retPolAccLat >> 4;
    zlog_debug ("    Retention policy (4 bits): %u", temp);
    temp = (uint8_t) top->retPolAccLat & 0xf;
    zlog_debug ("    Access latency (4 bits): %u", temp);
    temp = (uint8_t) top->expirationMode >> 4;
    zlog_debug ("    Expiration mode (4 bits): %d", temp);
  }
  return GRID_TLV_SIZE (tlvh);
}
static u_int16_t
show_vty_grid_tlv_GridStorage_StorageArea_FromTlv(struct vty *vty, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridStorage_StorageArea *top, *top_after_lists;
  top = (struct grid_tlv_GridStorage_StorageArea *) tlvh;
  char temp;

  int i;
  if (vty != NULL)
  {
    i = 0;
//    int len = ntohs(top->header.length);
    vty_out (vty, "  Storage Area: %s", VTY_NEWLINE);
    vty_out (vty, "    Name: ");
    char* ptr = (char*) &top->name;
    int write_list = 1;    
    while ((write_list == 1) || (i%4 != 0))
    {
      if (*(ptr) == '\0')
        write_list = 0;
      else
        vty_out (vty, "%c", *(ptr));
      ptr++;
      i++;
    }
   
    vty_out (vty, "%s", VTY_NEWLINE);
    vty_out (vty, "    Path: ");
    write_list = 1;
    while ((write_list == 1) || (i%4 != 0))
    {
      if (*(ptr) == '\0')
        write_list = 0;
      else
        vty_out (vty, "%c", *(ptr));
      ptr++;
      i++;
    }
    vty_out (vty, "%s", VTY_NEWLINE);
  }
  else
  {
//    int len = ntohs(top->header.length);
    i = 0;
    zlog_debug ("  Name: ");
    char* ptr = (char*) &top->name;
    int write_list = 1;    
    while ((write_list == 1) || (i%4 != 0))
    {
      if (*(ptr) == '\0')
        write_list = 0;
      else
        zlog_debug ("%c", *(ptr));
      ptr++;
      i++;
    }
    zlog_debug ("  Path: ");
    write_list = 1;    
    while ((write_list == 1) || (i%4 != 0))
    {
      if (*(ptr) == '\0')
        write_list = 0;
      else
        zlog_debug ("%c", *(ptr));
      ptr++;
      i++;
    }
  }

  char *offset = (char *)(top) + i - 2 * sizeof(struct zlist);
  top_after_lists = (struct grid_tlv_GridStorage_StorageArea *) offset;

  if (vty != NULL)
  {
    vty_out (vty, "    Total online size: %u%s", ntohl(top_after_lists->totalOnlineSize), VTY_NEWLINE);
    vty_out (vty, "    Free online size: %u%s", ntohl(top_after_lists->freeOnlineSize), VTY_NEWLINE);
    vty_out (vty, "    Reserved total online size: %u%s", ntohl(top_after_lists->resTotalOnlineSize), VTY_NEWLINE);
    vty_out (vty, "    Total nearline size: %u%s", ntohl(top_after_lists->totalNearlineSize), VTY_NEWLINE);
    vty_out (vty, "    Free nearline size: %u%s", ntohl(top_after_lists->freeNearlineSize), VTY_NEWLINE);
    vty_out (vty, "    Reserved nearline size: %u%s", ntohl(top_after_lists->resNearlineSize), VTY_NEWLINE);
    temp = (uint8_t) top_after_lists->retPolAccLat >> 4;
    vty_out (vty, "    Retention policy (4 bits): %u%s", temp, VTY_NEWLINE);
    temp = (uint8_t) top_after_lists->retPolAccLat & 0xf;
    vty_out (vty, "    Access latency (4 bits): %u%s", temp, VTY_NEWLINE);
    temp = (uint8_t) top_after_lists->expirationMode >> 4;
    vty_out (vty, "    Expiration mode (4 bits): %d%s", temp, VTY_NEWLINE);
  }
  else
  {
    zlog_debug ("  Total online size: %u", ntohl(top_after_lists->totalOnlineSize));
    zlog_debug ("  Free online size: %u", ntohl(top_after_lists->freeOnlineSize));
    zlog_debug ("  Reserved total online size: %u", ntohl(top_after_lists->resTotalOnlineSize));
    zlog_debug ("  Total nearline size: %u", ntohl(top_after_lists->totalNearlineSize));
    zlog_debug ("  Free nearline size: %u", ntohl(top_after_lists->freeNearlineSize));
    zlog_debug ("  Reserved nearline size: %u", ntohl(top_after_lists->resNearlineSize));
    temp = (uint8_t) top_after_lists->retPolAccLat >> 4;
    zlog_debug ("    Retention policy (4 bits): %u", temp);
    temp = (uint8_t) top_after_lists->retPolAccLat & 0xf;
    zlog_debug ("    Access latency (4 bits): %u", temp);
    temp = (uint8_t) top_after_lists->expirationMode >> 4;
    zlog_debug ("    Expiration mode (4 bits): %d", temp);
  }
  return GRID_TLV_SIZE (tlvh);
}
static u_int16_t
show_vty_grid_tlv_GridStorage_SeCalendar_FromStruct(struct vty *vty, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridStorage_SeCalendar *top;
  top = (struct grid_tlv_GridStorage_SeCalendar *) tlvh;
  uint32_t temp_time;
  uint32_t temp_freeOnlineSize;
  uint32_t temp_freeNearlineSize;
  if (vty != NULL)
  {
    vty_out (vty, "  Storage Element Calendar: %s", VTY_NEWLINE);
    struct se_calendar* temp_ptr;
    struct zlistnode *node, *nnode;
    for (ALL_LIST_ELEMENTS (&top->seCalendar, node, nnode, temp_ptr))
    {
      temp_time = ntohl(temp_ptr->time);
      temp_freeOnlineSize = ntohl(temp_ptr->freeOnlineSize);
      temp_freeNearlineSize = ntohl(temp_ptr->freeNearlineSize);
      vty_out(vty, "    Timestamp: %u  Free Online Size: %u  Free Nearline Size: %u %s", temp_time, temp_freeOnlineSize, temp_freeNearlineSize, VTY_NEWLINE);
    }
  }
  else
  {
    zlog_debug ("  Storage Element Calendar: ");
    struct se_calendar* temp_ptr;
    struct zlistnode *node, *nnode;
    for (ALL_LIST_ELEMENTS (&top->seCalendar, node, nnode, temp_ptr))
    {
      temp_time = ntohl(temp_ptr->time);
      temp_freeOnlineSize = ntohl(temp_ptr->freeOnlineSize);
      temp_freeNearlineSize = ntohl(temp_ptr->freeNearlineSize);
      zlog_debug("    Timestamp: %u  Free Online Size: %u  Free Nearline Size: %u", temp_time, temp_freeOnlineSize, temp_freeNearlineSize);
    }
  }
  return GRID_TLV_SIZE (tlvh);
}
static u_int16_t
show_vty_grid_tlv_GridStorage_SeCalendar_FromTlv(struct vty *vty, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridStorage_SeCalendar *top;
  top = (struct grid_tlv_GridStorage_SeCalendar *) tlvh;
  if (vty != NULL)
  {
    int len = ntohs(top->header.length) - GRID_TLV_GRIDSTORAGE_SECALENDAR_CONST_DATA_LENGTH;
    int i;
    vty_out (vty, "  Storage Element Calendar: %s", VTY_NEWLINE);
    struct se_calendar* ptr = (struct se_calendar*) (void *) &top->seCalendar;
    for (i=0; i< len; i=i+12)
    {
      vty_out (vty, "    Timestamp: %u  Free Jobs Slots: %u  Free Nearline Size: %u %s", ntohl(ptr->time), ntohl(ptr->freeOnlineSize), ntohl(ptr->freeNearlineSize), VTY_NEWLINE);
      ptr++;
    }
  }
  else
  {
    int len = ntohs(top->header.length) - GRID_TLV_GRIDSTORAGE_SECALENDAR_CONST_DATA_LENGTH;
    int i;
    zlog_debug ("  Storage Element Calendar: ");
    struct se_calendar* ptr = (struct se_calendar*) (void *) &top->seCalendar;
    for (i=0; i< len; i=i+12)
    {
      zlog_debug ("    Timestamp: %u  Free Jobs Slots: %u  Free Nearline Size: %u", ntohl(ptr->time), ntohl(ptr->freeOnlineSize), ntohl(ptr->freeNearlineSize));
      ptr++;
    }
  }
  return GRID_TLV_SIZE (tlvh);
}
static u_int16_t
show_vty_grid_tlv_GridStorage_Name_FromStruct(struct vty *vty, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridStorage_Name *top;
  top = (struct grid_tlv_GridStorage_Name *) tlvh;

  if (vty != NULL)
  {
    vty_out (vty, "  Name: ");
    char* name;
    struct zlistnode *node, *nnode;
    for (ALL_LIST_ELEMENTS (&top->name, node, nnode, name))
    {
      char temp = *name;
      vty_out(vty, "%c", temp);
    }
    vty_out(vty, "%s", VTY_NEWLINE);
  }
  else
  {
    zlog_debug ("  Name: ");
    char* name;
    struct zlistnode *node, *nnode;
    for (ALL_LIST_ELEMENTS (&top->name, node, nnode, name))
    {
      char temp = *name;
      zlog_debug("%c", temp);
    }
  }

  return GRID_TLV_SIZE (tlvh);
}
static u_int16_t
show_vty_grid_tlv_GridStorage_Name_FromTlv(struct vty *vty, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridStorage_Name *top;
  top = (struct grid_tlv_GridStorage_Name *) tlvh;
  if (vty != NULL)
  {
    int len = ntohs(top->header.length);
    int i;
    vty_out (vty, "  Name: ");
    char* ptr = (char*) &top->name;
    for (i=0; i< len; i++)
    {
      vty_out (vty, "%c", *(ptr));
      ptr++;
    }
    vty_out (vty, "%s", VTY_NEWLINE);
  }
  else
  {
    int len = ntohs(top->header.length);
    int i;
    zlog_debug ("  Name: ");
    char* ptr = (char*) &top->name;
    for (i=0; i< len; i++)
    {
      zlog_debug ("%c", *(ptr));
      ptr++;
    }
  }
  return GRID_TLV_SIZE (tlvh);
}
static u_int16_t
show_vty_grid_tlv_GridStorage_FromTlv (struct vty *vty, struct grid_tlv_header *tlvh0, u_int16_t subtotal, u_int16_t total)
{
  struct grid_tlv_header *tlvh;
  u_int16_t sum = subtotal;
  for (tlvh = tlvh0; sum < total; tlvh = GRID_TLV_HDR_NEXT (tlvh))
  {
    switch (ntohs (tlvh->type))
    {
      case GRID_TLV_GRIDSTORAGE_ID:      /* Unique Identifier of the Storage Element */
        sum += show_vty_grid_tlv_GridStorage_ID(vty, tlvh);
        break;
      case GRID_TLV_GRIDSTORAGE_PARENTSITEID:      /* Identifier of the Grid Site that is exporting this storage */
        sum += show_vty_grid_tlv_GridStorage_ParentSiteID(vty, tlvh);
        break;
      case GRID_TLV_GRIDSTORAGE_STORAGEINFO:      /* Information about the storage architecture the status of the SE the access and control protocols */
        sum += show_vty_grid_tlv_GridStorage_StorageInfo(vty, tlvh);
        break;
      case GRID_TLV_GRIDSTORAGE_ONLINESIZE:      /* The online storage sizes (total + used) in GB */
        sum += show_vty_grid_tlv_GridStorage_OnlineSize(vty, tlvh);
        break;
      case GRID_TLV_GRIDSTORAGE_NEARLINESIZE:      /* The nearline storage sizes (total + used) in GB */
        sum += show_vty_grid_tlv_GridStorage_NearlineSize(vty, tlvh);
        break;
      case GRID_TLV_GRIDSTORAGE_STORAGEAREA:
        sum += show_vty_grid_tlv_GridStorage_StorageArea_FromTlv(vty, tlvh);
        break;
      case GRID_TLV_GRIDSTORAGE_SECALENDAR:      /* The FreeOnlineSize and FreeNearlineSize scheduling calendar for each timestamp */
        sum += show_vty_grid_tlv_GridStorage_SeCalendar_FromTlv(vty, tlvh);
        break;
      case GRID_TLV_GRIDSTORAGE_NAME:
        sum += show_vty_grid_tlv_GridStorage_Name_FromTlv(vty, tlvh);
        break;
      default:
        sum += show_vty_unknown_tlv (vty, tlvh);
    }
  }
  return sum - subtotal;
}
static void
ospf_grid_show_info (struct vty *vty, struct ospf_lsa *lsa)
{
  struct lsa_header *lsah = (struct lsa_header *) lsa->data;
  struct grid_tlv_header *tlvh;
  u_int16_t sum, total, l;
  total = ntohs (lsah->length) - OSPF_LSA_HEADER_SIZE;
  sum = 0;
  tlvh = GRID_TLV_HDR_TOP (lsah);
  while (sum < total)
  {
    switch (ntohs (tlvh->type))
    {
      case GRID_TLV_GRIDSITE:      /* Grid Side Property TLV */
        l = ntohs (tlvh->length);
        sum += show_vty_grid_tlv_header (vty, tlvh);
        sum += show_vty_grid_tlv_GridSite (vty, tlvh+1, sum, sum + l);
        break;
      case GRID_TLV_GRIDSERVICE:      /* Grid Service Property TLV */
        l = ntohs (tlvh->length);
        sum += show_vty_grid_tlv_header (vty, tlvh);
        sum += show_vty_grid_tlv_GridService (vty, tlvh+1, sum, sum + l);
        break;
      case GRID_TLV_GRIDCOMPUTINGELEMENT:      /* Grid Computing Element Property TLV */
        l = ntohs (tlvh->length);
        sum += show_vty_grid_tlv_header (vty, tlvh);
        sum += show_vty_grid_tlv_GridComputingElement_FromTlv (vty, tlvh+1, sum, sum + l);
        break;
      case GRID_TLV_GRIDSUBCLUSTER:      /* Grid SubCluster Property TLV */
        l = ntohs (tlvh->length);
        sum += show_vty_grid_tlv_header (vty, tlvh);
        sum += show_vty_grid_tlv_GridSubCluster_FromTlv (vty, tlvh+1, sum, sum + l);
        break;
      case GRID_TLV_GRIDSTORAGE:      /* Grid Storage Element Property TLV */
        l = ntohs (tlvh->length);
        sum += show_vty_grid_tlv_header (vty, tlvh);
        sum += show_vty_grid_tlv_GridStorage_FromTlv (vty, tlvh+1, sum, sum + l);
        break;
      default:
        sum += show_vty_unknown_tlv (vty, tlvh);
    }
    tlvh = (struct grid_tlv_header *)((char *)(GRID_TLV_HDR_TOP (lsah)) + sum);
  }
  return;
}

static int
is_mandated_params_set (struct grid_node *gn)
{
  int rc = 0;

  if (gn->ifp->adj_type > 2)
  {
    zlog_warn("[WRN] is_mandated_params_set: grid_node: adj_type > 2");
    goto out;
  }
  rc = 1;
out:
  return rc;
}

static struct ospf_lsa *
ospf_grid_storage_lsa_new (struct ospf_area *area, struct grid_node_storage *gn_storage)
{
  struct stream *s;
  struct lsa_header *lsah;
  struct ospf_lsa *new = NULL;
  u_char options, lsa_type;
  struct in_addr lsa_id; 
  u_int32_t tmp;
  u_int16_t length;

  /* Create a stream for LSA. */
  if ((s = stream_new (OSPF_MAX_LSA_SIZE)) == NULL)
    {
      zlog_warn ("[WRN] ospf_grid_storage_lsa_new: stream_new() ?");
      goto out;
    }
  lsah = (struct lsa_header *) STREAM_DATA (s);

  options  = LSA_OPTIONS_GET (area);
  options |= LSA_OPTIONS_NSSA_GET (area);
  options |= OSPF_OPTION_O; /* Don't forget this :-) */

  lsa_type = OSPF_OPAQUE_AREA_LSA;
  tmp = SET_OPAQUE_LSID (OPAQUE_TYPE_GRID_LSA, gn_storage->base.instance_no);
  lsa_id.s_addr = htonl (tmp);

  if (IS_DEBUG_GRID_NODE (GENERATE))
    zlog_debug ("[DBG] ospf_grid_storage_lsa_new: LSA[Type%d:%s]: Create an Opaque-LSA/GRID instance", lsa_type, inet_ntoa (lsa_id)); 

  /* Set opaque-LSA header fields. */
  lsa_header_set (s, options, lsa_type, lsa_id, area->ospf->router_id);

  /* Set opaque-LSA body fields. */
  build_grid_tlv_GridStorage(s, gn_storage);

  /* Set length. */
  length = stream_get_endp (s);
  lsah->length = htons (length);

  /* Now, create an OSPF LSA instance. */
  if ((new = ospf_lsa_new ()) == NULL)
    {
      zlog_warn ("[WRN] ospf_grid_storage_lsa_new: ospf_lsa_new() ?");
      stream_free (s);
      goto out;
    }
  if ((new->data = ospf_lsa_data_new (length)) == NULL)
    {
      zlog_warn ("[WRN] ospf_grid_storage_lsa_new: ospf_lsa_data_new() ?");
      ospf_lsa_unlock (&new);
      new = NULL;
      stream_free (s);
      goto out;
    }

  new->area = area;
  SET_FLAG (new->flags, OSPF_LSA_SELF);
  memcpy (new->data, lsah, length);
  stream_free (s);

out:
  return new;
}

static struct ospf_lsa *
ospf_grid_subcluster_lsa_new (struct ospf_area *area, struct grid_node_subcluster *gn_subcluster)
{
  struct stream *s;
  struct lsa_header *lsah;
  struct ospf_lsa *new = NULL;
  u_char options, lsa_type;
  struct in_addr lsa_id; 
  u_int32_t tmp;
  u_int16_t length;

  /* Create a stream for LSA. */
  if ((s = stream_new (OSPF_MAX_LSA_SIZE)) == NULL)
    {
      zlog_warn ("[WRN] ospf_grid_subcluster_lsa_new: stream_new() ?");
      goto out;
    }
  lsah = (struct lsa_header *) STREAM_DATA (s);

  options  = LSA_OPTIONS_GET (area);
  options |= LSA_OPTIONS_NSSA_GET (area);
  options |= OSPF_OPTION_O; /* Don't forget this :-) */

  lsa_type = OSPF_OPAQUE_AREA_LSA;
  tmp = SET_OPAQUE_LSID (OPAQUE_TYPE_GRID_LSA, gn_subcluster->base.instance_no);
  lsa_id.s_addr = htonl (tmp);

  if (IS_DEBUG_GRID_NODE (GENERATE))
    zlog_debug ("[DBG] ospf_grid_subcluster_lsa_new: LSA[Type%d:%s]: Create an Opaque-LSA/GRID instance", lsa_type, inet_ntoa (lsa_id)); 

  /* Set opaque-LSA header fields. */
  lsa_header_set (s, options, lsa_type, lsa_id, area->ospf->router_id);

  /* Set opaque-LSA body fields. */
  build_grid_tlv_GridSubCluster(s, gn_subcluster);

  /* Set length. */
  length = stream_get_endp (s);
  lsah->length = htons (length);

  /* Now, create an OSPF LSA instance. */
  if ((new = ospf_lsa_new ()) == NULL)
    {
      zlog_warn ("[WRN] ospf_grid_subcluster_lsa_new: ospf_lsa_new() ?");
      stream_free (s);
      goto out;
    }
  if ((new->data = ospf_lsa_data_new (length)) == NULL)
    {
      zlog_warn ("[WRN] ospf_grid_subcluster_lsa_new: ospf_lsa_data_new() ?");
      ospf_lsa_unlock (&new);
      new = NULL;
      stream_free (s);
      goto out;
    }

  new->area = area;
  SET_FLAG (new->flags, OSPF_LSA_SELF);
  memcpy (new->data, lsah, length);
  stream_free (s);

out:
  return new;
}

static struct ospf_lsa *
ospf_grid_computing_lsa_new (struct ospf_area *area, struct grid_node_computing *gn_computing)
{
  struct stream *s;
  struct lsa_header *lsah;
  struct ospf_lsa *new = NULL;
  u_char options, lsa_type;
  struct in_addr lsa_id; 
  u_int32_t tmp;
  u_int16_t length;

  /* Create a stream for LSA. */
  if ((s = stream_new (OSPF_MAX_LSA_SIZE)) == NULL)
    {
      zlog_warn ("[WRN] ospf_grid_computing_lsa_new: stream_new() ?");
      goto out;
    }
  lsah = (struct lsa_header *) STREAM_DATA (s);

  options  = LSA_OPTIONS_GET (area);
  options |= LSA_OPTIONS_NSSA_GET (area);
  options |= OSPF_OPTION_O; /* Don't forget this :-) */

  lsa_type = OSPF_OPAQUE_AREA_LSA;
  tmp = SET_OPAQUE_LSID (OPAQUE_TYPE_GRID_LSA, gn_computing->base.instance_no);
  lsa_id.s_addr = htonl (tmp);

  if (IS_DEBUG_GRID_NODE (GENERATE))
    zlog_debug ("[DBG] ospf_grid_computing_lsa_new: LSA[Type%d:%s]: Create an Opaque-LSA/GRID instance", lsa_type, inet_ntoa (lsa_id)); 

  /* Set opaque-LSA header fields. */
  lsa_header_set (s, options, lsa_type, lsa_id, area->ospf->router_id);

  /* Set opaque-LSA body fields. */
  build_grid_tlv_GridComputingElement (s, gn_computing);

  /* Set length. */
  length = stream_get_endp (s);
  lsah->length = htons (length);

  /* Now, create an OSPF LSA instance. */
  if ((new = ospf_lsa_new ()) == NULL)
    {
      zlog_warn ("[WRN] ospf_grid_computing_lsa_new: ospf_lsa_new() ?");
      stream_free (s);
      goto out;
    }
  if ((new->data = ospf_lsa_data_new (length)) == NULL)
    {
      zlog_warn ("[WRN] ospf_grid_computing_lsa_new: ospf_lsa_data_new() ?");
      ospf_lsa_unlock (&new);
      new = NULL;
      stream_free (s);
      goto out;
    }

  new->area = area;
  SET_FLAG (new->flags, OSPF_LSA_SELF);
  memcpy (new->data, lsah, length);
  stream_free (s);

out:
  return new;
}

static struct ospf_lsa *
ospf_grid_site_lsa_new (struct ospf_area *area, struct grid_node_site *gn_site)
{
  struct stream *s;
  struct lsa_header *lsah;
  struct ospf_lsa *new = NULL;
  u_char options, lsa_type;
  struct in_addr lsa_id; 
  u_int32_t tmp;
  u_int16_t length;

  /* Create a stream for LSA. */
  if ((s = stream_new (OSPF_MAX_LSA_SIZE)) == NULL)
    {
      zlog_warn ("[WRN] ospf_grid_site_lsa_new: stream_new() ?");
      goto out;
    }
  lsah = (struct lsa_header *) STREAM_DATA (s);

  options  = LSA_OPTIONS_GET (area);
  options |= LSA_OPTIONS_NSSA_GET (area);
  options |= OSPF_OPTION_O; /* Don't forget this :-) */

  lsa_type = OSPF_OPAQUE_AREA_LSA;
  tmp = SET_OPAQUE_LSID (OPAQUE_TYPE_GRID_LSA, gn_site->base.instance_no);
  lsa_id.s_addr = htonl (tmp);

  if (IS_DEBUG_GRID_NODE (GENERATE))
    zlog_debug ("[DBG] ospf_grid_site_lsa_new: LSA[Type%d:%s]: Create an Opaque-LSA/GRID instance", lsa_type, inet_ntoa (lsa_id)); 

  /* Set opaque-LSA header fields. */
  lsa_header_set (s, options, lsa_type, lsa_id, area->ospf->router_id);

  /* Set opaque-LSA body fields. */
  build_grid_tlv_GridSite (s, gn_site);

  /* Set length. */
  length = stream_get_endp (s);
  lsah->length = htons (length);

  /* Now, create an OSPF LSA instance. */
  if ((new = ospf_lsa_new ()) == NULL)
    {
      zlog_warn ("[WRN] ospf_grid_site_lsa_new: ospf_lsa_new() ?");
      stream_free (s);
      goto out;
    }
  if ((new->data = ospf_lsa_data_new (length)) == NULL)
    {
      zlog_warn ("[WRN] ospf_grid_site_lsa_new: ospf_lsa_data_new() ?");
      ospf_lsa_unlock (&new);
      new = NULL;
      stream_free (s);
      goto out;
    }

  new->area = area;
  SET_FLAG (new->flags, OSPF_LSA_SELF);
  memcpy (new->data, lsah, length);
  stream_free (s);

out:
  return new;
}

static struct ospf_lsa *
ospf_grid_service_lsa_new (struct ospf_area *area, struct grid_node_service *gn_service)
{
  struct stream *s;
  struct lsa_header *lsah;
  struct ospf_lsa *new = NULL;
  u_char options, lsa_type;
  struct in_addr lsa_id; 
  u_int32_t tmp;
  u_int16_t length;

  /* Create a stream for LSA. */
  if ((s = stream_new (OSPF_MAX_LSA_SIZE)) == NULL)
    {
      zlog_warn ("[WRN] ospf_grid_service_lsa_new: stream_new() ?");
      goto out;
    }
  lsah = (struct lsa_header *) STREAM_DATA (s);

  options  = LSA_OPTIONS_GET (area);
  options |= LSA_OPTIONS_NSSA_GET (area);
  options |= OSPF_OPTION_O; /* Don't forget this :-) */

  lsa_type = OSPF_OPAQUE_AREA_LSA;
  tmp = SET_OPAQUE_LSID (OPAQUE_TYPE_GRID_LSA, gn_service->base.instance_no);
  lsa_id.s_addr = htonl (tmp);

  if (IS_DEBUG_GRID_NODE (GENERATE))
    zlog_debug ("[DBG] ospf_grid_service_lsa_new: LSA[Type%d:%s]: Create an Opaque-LSA/GRID instance", lsa_type, inet_ntoa (lsa_id)); 

  /* Set opaque-LSA header fields. */
  lsa_header_set (s, options, lsa_type, lsa_id, area->ospf->router_id);

  /* Set opaque-LSA body fields. */
  build_grid_tlv_GridService(s, gn_service);

  /* Set length. */
  length = stream_get_endp (s);
  lsah->length = htons (length);

  /* Now, create an OSPF LSA instance. */
  if ((new = ospf_lsa_new ()) == NULL)
    {
      zlog_warn ("[WRN] ospf_grid_service_lsa_new: ospf_lsa_new() ?");
      stream_free (s);
      goto out;
    }
  if ((new->data = ospf_lsa_data_new (length)) == NULL)
    {
      zlog_warn ("[WRN] ospf_grid_service_lsa_new: ospf_lsa_data_new() ?");
      ospf_lsa_unlock (&new);
      new = NULL;
      stream_free (s);
      goto out;
    }

  new->area = area;
  SET_FLAG (new->flags, OSPF_LSA_SELF);
  memcpy (new->data, lsah, length);
  stream_free (s);

out:
  return new;
}

static int
ospf_grid_site_lsa_originate (struct ospf_area *area, struct grid_node_site *gn_site)
{
  struct ospf_lsa *new;
  int rc = -1;

  if ((new = ospf_grid_site_lsa_new(area, gn_site)) == NULL)
  {
    zlog_warn ("[WRN] ospf_grid_site_lsa_originate: ospf_grid_site_lsa_new(area, gn_site) = NULL");
    goto out;
  }

  /* Install this LSA into LSDB. */
  if (ospf_lsa_install (area->ospf, NULL/*oi*/, new) == NULL)
    {
      zlog_warn ("[WRN] ospf_grid_site_lsa_originate: ospf_lsa_install() ?");
      ospf_lsa_unlock (&new);
      goto out;
    }

  gn_site->base.flags |= GRIDFLG_GRID_LSA_ENGAGED;

  /* Update new LSA origination count. */
  area->ospf->lsa_originate_count++;

  /* Flood new LSA through area. */
  ospf_flood_through_area (area, NULL/*nbr*/, new);

  if (IS_DEBUG_OSPF (lsa, LSA_GENERATE))
  {
    char area_id[INET_ADDRSTRLEN];
    strcpy (area_id, inet_ntoa (area->area_id));
//    zlog_debug ("LSA[Type%d:%s]: Originate Opaque-LSA/GRID: Area(%s), Link(%s)", new->data->type, inet_ntoa (new->data->id), area_id, gn->ifp->name);
    ospf_lsa_header_dump (new->data);
  }
  rc = 0;
out:
  return rc;
} 

static int
ospf_grid_computing_lsa_originate (struct ospf_area *area, struct grid_node_computing *gn_computing)
{
  struct ospf_lsa *new;
  int rc = -1;

  if ((new = ospf_grid_computing_lsa_new(area, gn_computing)) == NULL)
  {
    zlog_warn ("[WRN] ospf_grid_computing_lsa_originate: ospf_grid_xxx_lsa_new(, , build_grid_tlv_GridStorage, ) ?");
    goto out;
  }

  /* Install this LSA into LSDB. */
  if (ospf_lsa_install (area->ospf, NULL/*oi*/, new) == NULL)
    {
      zlog_warn ("[WRN] ospf_grid_computing_lsa_originate: ospf_lsa_install() ?");
      ospf_lsa_unlock (&new);
      goto out;
    }

  gn_computing->base.flags |= GRIDFLG_GRID_LSA_ENGAGED;

  /* Update new LSA origination count. */
  area->ospf->lsa_originate_count++;

  /* Flood new LSA through area. */
  ospf_flood_through_area (area, NULL/*nbr*/, new);

  if (IS_DEBUG_OSPF (lsa, LSA_GENERATE))
  {
    char area_id[INET_ADDRSTRLEN];
    strcpy (area_id, inet_ntoa (area->area_id));
//    zlog_debug ("LSA[Type%d:%s]: Originate Opaque-LSA/GRID: Area(%s), Link(%s)", new->data->type, inet_ntoa (new->data->id), area_id, gn->ifp->name);
    ospf_lsa_header_dump (new->data);
  }
  rc = 0;
out:
  return rc;
} 

static int
ospf_grid_storage_lsa_originate (struct ospf_area *area, struct grid_node_storage *gn_storage)
{
  struct ospf_lsa *new;
  int rc = -1;

  if ((new = ospf_grid_storage_lsa_new(area, gn_storage)) == NULL)
  {
    zlog_warn ("[WRN] ospf_grid_storage_lsa_originate: ospf_grid_xxx_lsa_new(, , build_grid_tlv_GridStorage, ) ?");
    goto out;
  }

  /* Install this LSA into LSDB. */
  if (ospf_lsa_install (area->ospf, NULL/*oi*/, new) == NULL)
    {
      zlog_warn ("[WRN] ospf_grid_storage_lsa_originate: ospf_lsa_install() ?");
      ospf_lsa_unlock (&new);
      goto out;
    }

  gn_storage->base.flags |= GRIDFLG_GRID_LSA_ENGAGED;

  /* Update new LSA origination count. */
  area->ospf->lsa_originate_count++;

  /* Flood new LSA through area. */
  ospf_flood_through_area (area, NULL/*nbr*/, new);

  if (IS_DEBUG_OSPF (lsa, LSA_GENERATE))
  {
    char area_id[INET_ADDRSTRLEN];
    strcpy (area_id, inet_ntoa (area->area_id));
//    zlog_debug ("LSA[Type%d:%s]: Originate Opaque-LSA/GRID: Area(%s), Link(%s)", new->data->type, inet_ntoa (new->data->id), area_id, gn->ifp->name);
    ospf_lsa_header_dump (new->data);
  }
  rc = 0;
out:
  return rc;
} 

static int
ospf_grid_subcluster_lsa_originate (struct ospf_area *area, struct grid_node_subcluster *gn_subcluster)
{
  struct ospf_lsa *new;
  int rc = -1;

  if ((new = ospf_grid_subcluster_lsa_new(area, gn_subcluster)) == NULL)
  {
    zlog_warn ("[WRN] ospf_grid_subcluster_lsa_originate: ospf_grid_xxx_lsa_new(, , build_grid_tlv_GridStorage, ) ?");
    goto out;
  }

  /* Install this LSA into LSDB. */
  if (ospf_lsa_install (area->ospf, NULL/*oi*/, new) == NULL)
    {
      zlog_warn ("[WRN] ospf_grid_subcluster_lsa_originate: ospf_lsa_install() ?");
      ospf_lsa_unlock (&new);
      goto out;
    }

  gn_subcluster->base.flags |= GRIDFLG_GRID_LSA_ENGAGED;

  /* Update new LSA origination count. */
  area->ospf->lsa_originate_count++;

  /* Flood new LSA through area. */
  ospf_flood_through_area (area, NULL/*nbr*/, new);

  if (IS_DEBUG_OSPF (lsa, LSA_GENERATE))
  {
    char area_id[INET_ADDRSTRLEN];
    strcpy (area_id, inet_ntoa (area->area_id));
//    zlog_debug ("LSA[Type%d:%s]: Originate Opaque-LSA/GRID: Area(%s), Link(%s)", new->data->type, inet_ntoa (new->data->id), area_id, gn->ifp->name);
    ospf_lsa_header_dump (new->data);
  }
  rc = 0;
out:
  return rc;
}

static int
ospf_grid_service_lsa_originate (struct ospf_area *area, struct grid_node_service *gn_service)
{
  struct ospf_lsa *new;
  int rc = -1;

  if ((new = ospf_grid_service_lsa_new(area, gn_service)) == NULL)
  {
    zlog_warn ("[WRN] ospf_grid_service_lsa_originate: ospf_grid_xxx_lsa_new(, , build_grid_tlv_GridStorage, ) ?");
    goto out;
  }

  /* Install this LSA into LSDB. */
  if (ospf_lsa_install (area->ospf, NULL/*oi*/, new) == NULL)
    {
      zlog_warn ("[WRN] ospf_grid_service_lsa_originate: ospf_lsa_install() ?");
      ospf_lsa_unlock (&new);
      goto out;
    }

  gn_service->base.flags |= GRIDFLG_GRID_LSA_ENGAGED;

  /* Update new LSA origination count. */
  area->ospf->lsa_originate_count++;

  /* Flood new LSA through area. */
  ospf_flood_through_area (area, NULL/*nbr*/, new);

  if (IS_DEBUG_OSPF (lsa, LSA_GENERATE))
  {
    char area_id[INET_ADDRSTRLEN];
    strcpy (area_id, inet_ntoa (area->area_id));
//    zlog_debug ("LSA[Type%d:%s]: Originate Opaque-LSA/GRID: Area(%s), Link(%s)", new->data->type, inet_ntoa (new->data->id), area_id, gn->ifp->name);
    ospf_lsa_header_dump (new->data);
  }
  rc = 0;
out:
  return rc;
} 

static int
ospf_grid_lsa_originate (void *arg)
{
  if (IS_DEBUG_GRID_NODE (ORIGINATE))
    zlog_debug("[DBG] OSPF_GRID_LSA_ORIGINATE");
  struct ospf_area *area = (struct ospf_area *) arg;

  struct zlistnode          *node, *nnode;
  struct grid_node          *gn;

  struct zlistnode          *gn_node, *gn_nnode;
  struct grid_node_storage    *gn_storage;
  struct grid_node_service    *gn_service;
  struct grid_node_computing  *gn_computing;
  struct grid_node_subcluster *gn_subcluster;

  int rc = -1;

  if (OspfGRID.status == disabled)
  {
    if (IS_DEBUG_GRID_NODE (ORIGINATE))
      zlog_debug ("[DBG] OSPF_GRID_LSA_ORIGINATE: GRID is disabled now.");
    rc = 0; /* This is not an error case. */
    goto out;
  }

  if ((area->ospf->instance != UNI) || (area->ospf->interface_side == NETWORK))
  {
    if (IS_DEBUG_GRID_NODE (ORIGINATE))
      zlog_debug ("[DBG] OSPF_GRID_LSA_ORIGINATE: GRID NODE is originated only to the ospf UNI instance, interface side CLIENT.");
    rc = 0; /* This is not an error case. */
    goto out;
  }

  for (ALL_LIST_ELEMENTS (OspfGRID.iflist, node, nnode, gn))
  {
    if (gn->area == NULL)
      continue;

    if (gn->ifp->ospf_instance  != area->ospf->instance)
    {
      continue;
    }

    if (! IPV4_ADDR_SAME (&gn->area->area_id, &area->area_id))
    {
      continue;
    }

    if ((ntohs(gn->gn_site->gridSite.id.header.type) == 0) && (ntohs(gn->gn_site->gridSite.id.header.length) == 0))
    {
      if (IS_DEBUG_GRID_NODE (ORIGINATE))
        zlog_debug ("[DBG] OSPF_GRID_LSA_ORIGINATE: GRID NODE is originated if the grid site is configured");
      continue;
    }

    if ((gn->gn_site->base.flags & GRIDFLG_GRID_LSA_FORCED_REFRESH && (gn->gn_site->base.flags & GRIDFLG_GRID_LSA_ENGAGED)))
    {
      gn->gn_site->base.flags &= ~GRIDFLG_GRID_LSA_FORCED_REFRESH;
      ospf_grid_site_lsa_schedule (gn->gn_site, GRID_REFRESH_THIS_LSA);
      continue;
    }

    for (ALL_LIST_ELEMENTS(gn->list_of_grid_node_service, gn_node, gn_nnode, gn_service))
    {
      if ((gn_service->base.flags & GRIDFLG_GRID_LSA_FORCED_REFRESH && (gn_service->base.flags & GRIDFLG_GRID_LSA_ENGAGED)))
      {
        gn_service->base.flags &= ~GRIDFLG_GRID_LSA_FORCED_REFRESH;
        ospf_grid_service_lsa_schedule(gn_service, GRID_REFRESH_THIS_LSA);
        continue;
      }
    }

    for (ALL_LIST_ELEMENTS(gn->list_of_grid_node_computing, gn_node, gn_nnode, gn_computing))
    {
      if ((gn_computing->base.flags & GRIDFLG_GRID_LSA_FORCED_REFRESH && (gn_computing->base.flags & GRIDFLG_GRID_LSA_ENGAGED)))
      {
        gn_computing->base.flags &= ~GRIDFLG_GRID_LSA_FORCED_REFRESH;
        ospf_grid_computing_lsa_schedule (gn_computing, GRID_REFRESH_THIS_LSA);
        continue;
      }
    }

    for (ALL_LIST_ELEMENTS(gn->list_of_grid_node_subcluster, gn_node, gn_nnode, gn_subcluster))
    {
      if ((gn_subcluster->base.flags & GRIDFLG_GRID_LSA_FORCED_REFRESH && (gn_subcluster->base.flags & GRIDFLG_GRID_LSA_ENGAGED)))
      {
        gn_subcluster->base.flags &= ~GRIDFLG_GRID_LSA_FORCED_REFRESH;
        ospf_grid_subcluster_lsa_schedule(gn_subcluster, GRID_REFRESH_THIS_LSA);
        continue;
      }
    }

    for (ALL_LIST_ELEMENTS(gn->list_of_grid_node_storage, gn_node, gn_nnode, gn_storage))
    {
      if ((gn_storage->base.flags & GRIDFLG_GRID_LSA_FORCED_REFRESH && (gn_storage->base.flags & GRIDFLG_GRID_LSA_ENGAGED)))
      {
        gn_storage->base.flags &= ~GRIDFLG_GRID_LSA_FORCED_REFRESH;
        ospf_grid_storage_lsa_schedule(gn_storage, GRID_REFRESH_THIS_LSA);
        continue;
      }
    }

    if (! is_mandated_params_set (gn))
    {
      zlog_warn("[WRN] OSPF_GRID_LSA_ORIGINATE: Link(%s) lacks some mandated GRID parameters.", gn->ifp ? gn->ifp->name : "?");
      continue;
    }
      /* Ok, let's try to originate an LSA for this area and Link. */
    if ((gn->gn_site->base.flags & GRIDFLG_GRID_LSA_ENGAGED)==0)
    {
      if (ospf_grid_site_lsa_originate (area, gn->gn_site) != 0)
      {
        zlog_warn("[WRN] OSPF_GRID_LSA_ORIGINATE: build_grid_tlv_GridSite in lsa originate FAILED");
        goto out;
      }
      else
        gn->gn_site->base.flags |= GRIDFLG_GRID_LSA_ENGAGED;
    }

    for (ALL_LIST_ELEMENTS(gn->list_of_grid_node_service, gn_node, gn_nnode, gn_service))
    {
      if ((gn_service->base.flags & GRIDFLG_GRID_LSA_ENGAGED)==0)
      {
        if (ospf_grid_service_lsa_originate (area, gn_service) != 0)
        {
          zlog_warn("[WRN] OSPF_GRID_LSA_ORIGINATE: build_grid_tlv_GridService in lsa originate FAILED");
          goto out;
        }
        else
          gn_service->base.flags |= GRIDFLG_GRID_LSA_ENGAGED;
      }
    }

    for (ALL_LIST_ELEMENTS(gn->list_of_grid_node_computing, gn_node, gn_nnode, gn_computing))
    {
      if ((gn_computing->base.flags & GRIDFLG_GRID_LSA_ENGAGED)==0)
      {
        if (ospf_grid_computing_lsa_originate (area, gn_computing) != 0)
        {
          zlog_warn("[WRN] OSPF_GRID_LSA_ORIGINATE: build_grid_tlv_GridComputing in lsa originate FAILED");
          goto out;
        }
        else
          gn_computing->base.flags |= GRIDFLG_GRID_LSA_ENGAGED;
      }
    }

    for (ALL_LIST_ELEMENTS(gn->list_of_grid_node_subcluster, gn_node, gn_nnode, gn_subcluster))
    {
      if ((gn_subcluster->base.flags & GRIDFLG_GRID_LSA_ENGAGED)==0)
      {
        if (ospf_grid_subcluster_lsa_originate (area, gn_subcluster) != 0)
        {
          zlog_warn("[WRN] OSPF_GRID_LSA_ORIGINATE: build_grid_tlv_GridSubCluster in lsa originate FAILED");
          goto out;
        }
        else
          gn_subcluster->base.flags |= GRIDFLG_GRID_LSA_ENGAGED;
      }
    }

    for (ALL_LIST_ELEMENTS(gn->list_of_grid_node_storage, gn_node, gn_nnode, gn_storage))
    {
      if ((gn_storage->base.flags & GRIDFLG_GRID_LSA_ENGAGED)==0)
      {
        if (ospf_grid_storage_lsa_originate (area, gn_storage) != 0)
        {
          zlog_warn("[WRN] OSPF_GRID_LSA_ORIGINATE: build_grid_tlv_GridStorage in lsa originate FAILED");
          goto out;
        }
        else
          gn_storage->base.flags |= GRIDFLG_GRID_LSA_ENGAGED;
      }
    }
  }
  rc = 0;
out:
  if (IS_DEBUG_GRID_NODE (ORIGINATE))
    zlog_debug("[DBG] OSPF_GRID_LSA_ORIGINATE: OK");
  return rc;
}

void
ospf_grid_service_lsa_schedule(struct grid_node_service *gn_service, enum grid_sched_opcode opcode)
{
  struct ospf_lsa lsa;
  struct lsa_header lsah;
  u_int32_t tmp;

  memset (&lsa, 0, sizeof (lsa));
  memset (&lsah, 0, sizeof (lsah));

  lsa.area = gn_service->base.gn->area;
  lsa.data = &lsah;
  lsah.type = OSPF_OPAQUE_AREA_LSA;

  tmp = SET_OPAQUE_LSID (OPAQUE_TYPE_GRID_LSA, gn_service->base.instance_no);

  lsah.id.s_addr = htonl (tmp);

  switch (opcode)
  {
    case GRID_REORIGINATE_PER_AREA:
      ospf_opaque_lsa_reoriginate_schedule ((void *) gn_service->base.gn->area, OSPF_OPAQUE_AREA_LSA, OPAQUE_TYPE_GRID_LSA);
      if (IS_DEBUG_GRID_NODE(ORIGINATE))
        zlog_debug("[DBG] ospf_grid_service_lsa_schedule: GRID_REORIGINATE_PER_AREA OK");
      break;
    case GRID_REFRESH_THIS_LSA:
      ospf_opaque_lsa_refresh_schedule (&lsa);
      if (IS_DEBUG_GRID_NODE(REFRESH))
        zlog_debug("[DBG] ospf_grid_service_lsa_schedule: GRID_REFRESH_THIS_LSA OK");
      break;
    case GRID_FLUSH_THIS_LSA:
      gn_service->base.flags &= ~GRIDFLG_GRID_LSA_ENGAGED;
      ospf_opaque_lsa_flush_schedule (&lsa);
      if (IS_DEBUG_GRID_NODE(FLUSH))
        zlog_debug("[DBG] ospf_grid_service_lsa_schedule: GRID_FLUSH_THIS_LSA OK");
      break;
    default:
      zlog_warn ("[WRN] ospf_grid_service_lsa_schedule: Unknown opcode (%u)", opcode);
      break;
  }
  return;
}

void
ospf_grid_site_lsa_schedule(struct grid_node_site *gn_site, enum grid_sched_opcode opcode)
{
  struct ospf_lsa lsa;
  struct lsa_header lsah;
  u_int32_t tmp;

  memset (&lsa, 0, sizeof (lsa));
  memset (&lsah, 0, sizeof (lsah));

  lsa.area = gn_site->base.gn->area;
  lsa.data = &lsah;
  lsah.type = OSPF_OPAQUE_AREA_LSA;

  tmp = SET_OPAQUE_LSID (OPAQUE_TYPE_GRID_LSA, gn_site->base.instance_no);

  lsah.id.s_addr = htonl (tmp);

  switch (opcode)
  {
    case GRID_REORIGINATE_PER_AREA:
      ospf_opaque_lsa_reoriginate_schedule ((void *) gn_site->base.gn->area, OSPF_OPAQUE_AREA_LSA, OPAQUE_TYPE_GRID_LSA);
      break;
    case GRID_REFRESH_THIS_LSA:
      ospf_opaque_lsa_refresh_schedule (&lsa);
      break;
    case GRID_FLUSH_THIS_LSA:
      gn_site->base.flags &= ~GRIDFLG_GRID_LSA_ENGAGED;
      ospf_opaque_lsa_flush_schedule (&lsa);
      break;
    default:
      zlog_warn ("[WRN] ospf_grid_site_lsa_schedule: Unknown opcode (%u)", opcode);
      break;
  }
  return;
}

void
ospf_grid_computing_lsa_schedule (struct grid_node_computing *gn_computing, enum grid_sched_opcode opcode)
{
  struct ospf_lsa lsa;
  struct lsa_header lsah;
  u_int32_t tmp;

  memset (&lsa, 0, sizeof (lsa));
  memset (&lsah, 0, sizeof (lsah));

  lsa.area = gn_computing->base.gn->area;
  lsa.data = &lsah;
  lsah.type = OSPF_OPAQUE_AREA_LSA;

  tmp = SET_OPAQUE_LSID (OPAQUE_TYPE_GRID_LSA, gn_computing->base.instance_no);

  lsah.id.s_addr = htonl (tmp);

  switch (opcode)
  {
    case GRID_REORIGINATE_PER_AREA:
      ospf_opaque_lsa_reoriginate_schedule ((void *) gn_computing->base.gn->area, OSPF_OPAQUE_AREA_LSA, OPAQUE_TYPE_GRID_LSA);
      break;
    case GRID_REFRESH_THIS_LSA:
      ospf_opaque_lsa_refresh_schedule (&lsa);
      break;
    case GRID_FLUSH_THIS_LSA:
      gn_computing->base.flags &= ~GRIDFLG_GRID_LSA_ENGAGED;
      ospf_opaque_lsa_flush_schedule (&lsa);
      break;
    default:
      zlog_warn ("[WRN] ospf_grid_computing_lsa_schedule: Unknown opcode (%u)", opcode);
      break;
  }
  return;
}

void
ospf_grid_storage_lsa_schedule(struct grid_node_storage *gn_storage, enum grid_sched_opcode opcode)
{
  struct ospf_lsa lsa;
  struct lsa_header lsah;
  u_int32_t tmp;

  memset (&lsa, 0, sizeof (lsa));
  memset (&lsah, 0, sizeof (lsah));

  lsa.area = gn_storage->base.gn->area;
  lsa.data = &lsah;
  lsah.type = OSPF_OPAQUE_AREA_LSA;

  tmp = SET_OPAQUE_LSID (OPAQUE_TYPE_GRID_LSA, gn_storage->base.instance_no);

  lsah.id.s_addr = htonl (tmp);

  switch (opcode)
  {
    case GRID_REORIGINATE_PER_AREA:
      ospf_opaque_lsa_reoriginate_schedule ((void *) gn_storage->base.gn->area, OSPF_OPAQUE_AREA_LSA, OPAQUE_TYPE_GRID_LSA);
      if (IS_DEBUG_GRID_NODE(ORIGINATE))
        zlog_debug ("[DBG] ospf_grid_storage_lsa_schedule: GRID_REORIGINATE_PER_AREA OK");
      break;
    case GRID_REFRESH_THIS_LSA:
      ospf_opaque_lsa_refresh_schedule (&lsa);
      if (IS_DEBUG_GRID_NODE(REFRESH))
        zlog_debug ("[DBG] ospf_grid_storage_lsa_schedule: GRID_REFRESH_THIS_LSA OK");
      break;
    case GRID_FLUSH_THIS_LSA:
      gn_storage->base.flags &= ~GRIDFLG_GRID_LSA_ENGAGED;
      ospf_opaque_lsa_flush_schedule (&lsa);
      if (IS_DEBUG_GRID_NODE(FLUSH))
        zlog_debug ("[DBG] ospf_grid_storage_lsa_schedule: GRID_FLUSH_THIS_LSA OK");
      break;
    default:
      zlog_warn ("[WRN] ospf_grid_storage_lsa_schedule: Unknown opcode (%u)", opcode);
      break;
  }
  return;
}

void
ospf_grid_subcluster_lsa_schedule(struct grid_node_subcluster *gn_subcluster, enum grid_sched_opcode opcode)
{
  struct ospf_lsa lsa;
  struct lsa_header lsah;
  u_int32_t tmp;

  memset (&lsa, 0, sizeof (lsa));
  memset (&lsah, 0, sizeof (lsah));

  lsa.area = gn_subcluster->base.gn->area;
  lsa.data = &lsah;
  lsah.type = OSPF_OPAQUE_AREA_LSA;

  tmp = SET_OPAQUE_LSID (OPAQUE_TYPE_GRID_LSA, gn_subcluster->base.instance_no);

  lsah.id.s_addr = htonl (tmp);

  switch (opcode)
  {
    case GRID_REORIGINATE_PER_AREA:
      ospf_opaque_lsa_reoriginate_schedule ((void *) gn_subcluster->base.gn->area, OSPF_OPAQUE_AREA_LSA, OPAQUE_TYPE_GRID_LSA);
      break;
    case GRID_REFRESH_THIS_LSA:
      ospf_opaque_lsa_refresh_schedule (&lsa);
      break;
    case GRID_FLUSH_THIS_LSA:
      gn_subcluster->base.flags &= ~GRIDFLG_GRID_LSA_ENGAGED;
      ospf_opaque_lsa_flush_schedule (&lsa);
      break;
    default:
      zlog_warn ("[WRN] ospf_grid_subcluster_lsa_schedule: Unknown opcode (%u)", opcode);
      break;
  }
  return;
}

static int
ospf_grid_storage_lsa_refresh (struct ospf_lsa *lsa, struct grid_node_storage *gn_storage)
{
  int result = -1;
  struct ospf_lsa *new = NULL;
  struct ospf_area *area = lsa->area;


  if ((new = ospf_grid_storage_lsa_new (area, gn_storage)) == NULL)
    {
      zlog_warn ("[WRN] ospf_grid_storage_lsa_refresh: ospf_storage_grid_lsa_new() ?");
      goto out;
    }
  new->data->ls_seqnum = lsa_seqnum_increment (lsa);

  /* Install this LSA into LSDB. */
  /* Given "lsa" will be freed in the next function. */
  if (ospf_lsa_install (area->ospf, NULL/*oi*/, new) == NULL)
    {
      zlog_warn ("[WRN] ospf_grid_storage_lsa_refresh: ospf_lsa_install() ?");
      ospf_lsa_unlock (&new);
      goto out;
    }

  /* Flood updated LSA through area. */
  ospf_flood_through_area (area, NULL/*nbr*/, new);

  /* Debug logging. */
  if (IS_DEBUG_GRID_NODE(REFRESH))
  {
    zlog_debug ("[DBG] ospf_grid_storage_lsa_refresh: LSA[Type%d:%s]: Refresh Opaque-LSA/TE", new->data->type, inet_ntoa (new->data->id));
    ospf_lsa_header_dump (new->data);
  }
  result=0;
out:
  return result;
}

static int
ospf_grid_service_lsa_refresh (struct ospf_lsa *lsa, struct grid_node_service *gn_service)
{
  int result = -1;
  struct ospf_lsa *new = NULL;
  struct ospf_area *area = lsa->area;


  if ((new = ospf_grid_service_lsa_new (area, gn_service)) == NULL)
    {
      zlog_warn ("[WRN] ospf_grid_service_lsa_refresh: ospf_grid_service_lsa_new() ?");
      goto out;
    }
  new->data->ls_seqnum = lsa_seqnum_increment (lsa);

  /* Install this LSA into LSDB. */
  /* Given "lsa" will be freed in the next function. */
  if (ospf_lsa_install (area->ospf, NULL/*oi*/, new) == NULL)
    {
      zlog_warn ("[WRN] ospf_grid_service_lsa_refresh: ospf_lsa_install() ?");
      ospf_lsa_unlock (&new);
      goto out;
    }

  /* Flood updated LSA through area. */
  ospf_flood_through_area (area, NULL/*nbr*/, new);

  /* Debug logging. */
  if (IS_DEBUG_GRID_NODE(REFRESH))
  {
    zlog_debug ("[DBG] ospf_grid_service_lsa_refresh: LSA[Type%d:%s]: Refresh Opaque-LSA/TE",
       new->data->type, inet_ntoa (new->data->id));
    ospf_lsa_header_dump (new->data);
  }
  result =0;
out:
  return result;
}

static int
ospf_grid_subcluster_lsa_refresh (struct ospf_lsa *lsa, struct grid_node_subcluster *gn_subcluster)
{
  int result = -1;
  struct ospf_lsa *new = NULL;
  struct ospf_area *area = lsa->area;


  if ((new = ospf_grid_subcluster_lsa_new (area, gn_subcluster)) == NULL)
    {
      zlog_warn ("[WRN] ospf_grid_subcluster_lsa_refresh: ospf_grid_subcluster_lsa_new() ?");
      goto out;
    }
  new->data->ls_seqnum = lsa_seqnum_increment (lsa);

  /* Install this LSA into LSDB. */
  /* Given "lsa" will be freed in the next function. */
  if (ospf_lsa_install (area->ospf, NULL/*oi*/, new) == NULL)
    {
      zlog_warn ("[WRN] ospf_grid_subcluster_lsa_refresh: ospf_lsa_install() ?");
      ospf_lsa_unlock (&new);
      goto out;
    }

  /* Flood updated LSA through area. */
  ospf_flood_through_area (area, NULL/*nbr*/, new);

  /* Debug logging. */
  if (IS_DEBUG_GRID_NODE(REFRESH))
  {
    zlog_debug ("[DBG] ospf_grid_subcluster_lsa_refresh: LSA[Type%d:%s]: Refresh Opaque-LSA/TE",
       new->data->type, inet_ntoa (new->data->id));
    ospf_lsa_header_dump (new->data);
  }
  result =0;
out:
  return result;
}

static int
ospf_grid_computing_lsa_refresh (struct ospf_lsa *lsa, struct grid_node_computing *gn_computing)
{
  int result = -1;
  struct ospf_lsa *new = NULL;
  struct ospf_area *area = lsa->area;


  if ((new = ospf_grid_computing_lsa_new (area, gn_computing)) == NULL)
    {
      zlog_warn ("[WRN] ospf_grid_computing_lsa_refresh: ospf_grid_computing_lsa_new() ?");
      goto out;
    }
  new->data->ls_seqnum = lsa_seqnum_increment (lsa);

  /* Install this LSA into LSDB. */
  /* Given "lsa" will be freed in the next function. */
  if (ospf_lsa_install (area->ospf, NULL/*oi*/, new) == NULL)
    {
      zlog_warn ("[WRN] ospf_grid_computing_lsa_refresh: ospf_lsa_install() ?");
      ospf_lsa_unlock (&new);
      goto out;
    }

  /* Flood updated LSA through area. */
  ospf_flood_through_area (area, NULL/*nbr*/, new);

  /* Debug logging. */
  if (IS_DEBUG_GRID_NODE(REFRESH))
  {
    zlog_debug ("[DBG] ospf_grid_computing_lsa_refresh: LSA[Type%d:%s]: Refresh Opaque-LSA/TE",
       new->data->type, inet_ntoa (new->data->id));
    ospf_lsa_header_dump (new->data);
  }
  result =0;
out:
  return result;
}

static int
ospf_grid_site_lsa_refresh (struct ospf_lsa *lsa, struct grid_node_site *gn_site)
{
  int result = -1;
  struct ospf_lsa *new = NULL;
  struct ospf_area *area = lsa->area;


  if ((new = ospf_grid_site_lsa_new (area, gn_site)) == NULL)
    {
      zlog_warn ("[WRN] ospf_grid_site_lsa_refresh: ospf_grid_site_lsa_new() ?");
      goto out;
    }
  new->data->ls_seqnum = lsa_seqnum_increment (lsa);

  /* Install this LSA into LSDB. */
  /* Given "lsa" will be freed in the next function. */
  if (ospf_lsa_install (area->ospf, NULL/*oi*/, new) == NULL)
    {
      zlog_warn ("[WRN] ospf_grid_site_lsa_refresh: ospf_lsa_install() ?");
      ospf_lsa_unlock (&new);
      goto out;
    }

  /* Flood updated LSA through area. */
  ospf_flood_through_area (area, NULL/*nbr*/, new);

  /* Debug logging. */
  if (IS_DEBUG_GRID_NODE(REFRESH))
  {
    zlog_debug ("[DBG] ospf_grid_site_lsa_refresh: SA[Type%d:%s]: Refresh Opaque-LSA/TE",
       new->data->type, inet_ntoa (new->data->id));
    ospf_lsa_header_dump (new->data);
  }
  result =0;
out:
  return result;
}

static void
ospf_grid_lsa_refresh (struct ospf_lsa *lsa)
{
  if (GET_OPAQUE_TYPE(ntohl(lsa->data->id.s_addr)) != OPAQUE_TYPE_GRID_LSA)
    return;

  if (IS_DEBUG_GRID_NODE(REFRESH))
    zlog_debug("[DBG] OSPF_GRID_LSA_REFRESH");
  if (OspfGRID.status == disabled)
  {
    /*
     * This LSA must have flushed before due to MPLS-GRID status change.
     * It seems a slip among routers in the routing domain.
     */
    zlog_info ("[INF] OSPF_GRID_LSA_REFRESH: GRID is disabled now.");
    lsa->data->ls_age = htons (OSPF_LSA_MAXAGE); /* Flush it anyway. */
  }

  unsigned int key = GET_OPAQUE_ID (ntohl (lsa->data->id.s_addr));

  if (lsa->area->ospf->router_id.s_addr == lsa->data->adv_router.s_addr)
  {
    if (IS_DEBUG_GRID_NODE(REFRESH))
      zlog_debug("[DBG] OSPF_GRID_LSA_REFRESH: Refresh LSA from own OSPF instance");

    /* At first, resolve lsa/lp relationship. */
    struct grid_node_storage    *gn_storage    = lookup_grid_node_storage_by_lsa_instance(lsa);
    struct grid_node_service    *gn_service    = lookup_grid_node_service_by_lsa_instance(lsa);
    struct grid_node_computing  *gn_computing  = lookup_grid_node_computing_by_lsa_instance(lsa);
    struct grid_node_subcluster *gn_subcluster = lookup_grid_node_subcluster_by_lsa_instance(lsa);
    struct grid_node_site       *gn_site       = lookup_grid_node_site_by_lsa_instance(lsa);

    if ((gn_storage == NULL) && (gn_service == NULL) && (gn_computing == NULL) && (gn_subcluster == NULL) && (gn_site == NULL))
    {
      zlog_warn ("[WRN] OSPF_GRID_LSA_REFRESH: Invalid parameter?");
      lsa->data->ls_age = htons (OSPF_LSA_MAXAGE);  /* Flush it anyway. */
      ospf_lsa_checksum (lsa->data);
      ospf_opaque_lsa_flush_schedule (lsa);         /* Adam trying to find problem with non flushed grid LSA */
      goto out;
    }

  #ifndef GMPLS
    if ((lsa->data->area->ospf->interface_type != UNI) || ((lsa->data->area->ospf->interface_side != NETWORK)))
    {
      goto out:
    }
  #endif

    /* If the lsa's age reached to MaxAge, start flushing procedure. */
    if (IS_LSA_MAXAGE (lsa))
    {
      if (gn_storage != NULL)
        gn_storage->base.flags &= ~GRIDFLG_GRID_LSA_ENGAGED;
      else if (gn_service != NULL)
        gn_service->base.flags &= ~GRIDFLG_GRID_LSA_ENGAGED;
      else if (gn_computing != NULL)
        gn_computing->base.flags &= ~GRIDFLG_GRID_LSA_ENGAGED;
      else if (gn_site->base.instance_no == key)
        gn_site->base.flags &= ~GRIDFLG_GRID_LSA_ENGAGED;
      else if (gn_subcluster->base.instance_no == key)
        gn_subcluster->base.flags &= ~GRIDFLG_GRID_LSA_ENGAGED;

      ospf_opaque_lsa_flush_schedule (lsa);
      goto out;
    }

    if (gn_storage != NULL)
    {
      if (ospf_grid_storage_lsa_refresh(lsa, gn_storage) == -1)
        goto out;
    }
    else if (gn_service != NULL)
    {
      if (ospf_grid_service_lsa_refresh(lsa, gn_service) == -1)
        goto out;
    }
    else if (gn_site != NULL)
    {
      if (ospf_grid_site_lsa_refresh(lsa, gn_site) == -1)
        goto out;
    }
    else if (gn_computing != NULL)
    {
      if (ospf_grid_computing_lsa_refresh(lsa, gn_computing) == -1)
        goto out;
    }
    else if (gn_subcluster != NULL)
    {
      if (ospf_grid_subcluster_lsa_refresh(lsa, gn_subcluster) == -1)
        goto out;
    }
  }
out:
  if (IS_DEBUG_GRID_NODE(REFRESH))
    zlog_debug("[DBG] OSPF_GRID_LSA_REFRESH: OK");
  return;
}

static void
ospf_grid_config_write_if (struct vty *vty, struct interface *ifp)
{
  return;
}

static void
show_grid_tlv_GridSite_sub (struct vty *vty, struct grid_node *gn)
{
  if (gn->ifp->adj_type != UNI)
    return;
  struct ospf *ospf = ospf_uni_lookup();
  if (ospf == NULL)
    return;

  struct grid_tlv_header *tlvh;

  if (OspfGRID.status == enabled)
  {
    vty_out (vty, "-- %s parameters for %s --%s", (gn->ifp->ospf_instance == INNI) ? "INNI": (gn->ifp->ospf_instance == ENNI) ? "ENNI": "UNI", gn->ifp->name, VTY_NEWLINE);
    tlvh = &gn->gn_site->gridSite.id.header;
    show_vty_grid_tlv_GridSite_ID(vty, tlvh);
    tlvh = &gn->gn_site->gridSite.name.header;
    show_vty_grid_tlv_GridSite_Name_FromStruct(vty, tlvh);
    tlvh = &gn->gn_site->gridSite.latitude.header;
    show_vty_grid_tlv_GridSite_Latitude(vty, tlvh);
    tlvh = &gn->gn_site->gridSite.longitude.header;
    show_vty_grid_tlv_GridSite_Longitude(vty, tlvh);
    tlvh = &gn->gn_site->gridSite.peRouter_id.header;
    show_vty_grid_tlv_GridSite_PE_Router_ID(vty, tlvh);
  }
  return;
}

DEFUN (debug_ospf_grid_node,
       debug_ospf_grid_node_cmd,
       "debug ospf grid-node (all|generate|originate|refresh|flush|feed-up|feed-down|uni-inni|inni-uni|delete|corba|corba-all|user)",
       DEBUG_STR
       OSPF_STR
       "Grid Node information\n"
       "all grid node events\n"
       "grid node generate events\n"
       "grid node originate events\n"
       "grid node opaque refresh events\n"
       "grid node opaque flush events\n"
       "grid node feed up\n"
       "grid node feed down\n"
       "grid node moving lsa from ospf uni to ospf inni instance\n"
       "grid node moving lsa from ospf inni to ospf uni instance\n"
       "grid node opaque delete\n"
       "grid node basic corba events\n"
       "grid node all corba events\n"
       "grid node debug for user purposes\n")
{
  if (strcmp (argv[0], "all") == 0)
    GRID_NODE_DEBUG_ON (ALL);
  else if (strcmp (argv[0], "generate") == 0)
    GRID_NODE_DEBUG_ON (GENERATE);
  else if (strcmp (argv[0], "originate") == 0)
    GRID_NODE_DEBUG_ON (ORIGINATE);
  else if (strcmp (argv[0], "flush") == 0)
    GRID_NODE_DEBUG_ON (FLUSH);
  else if (strcmp (argv[0], "refresh") == 0)
    GRID_NODE_DEBUG_ON (REFRESH);
  else if (strcmp (argv[0], "feed-up") == 0)
    GRID_NODE_DEBUG_ON (FEED_UP);
  else if (strcmp (argv[0], "feed-down") == 0)
    GRID_NODE_DEBUG_ON (FEED_DOWN);
  else if (strcmp (argv[0], "uni-inni") == 0)
    GRID_NODE_DEBUG_ON (UNI_TO_INNI);
  else if (strcmp (argv[0], "inni-uni") == 0)
    GRID_NODE_DEBUG_ON (INNI_TO_UNI);
  else if (strcmp (argv[0], "delete") == 0)
    GRID_NODE_DEBUG_ON (DELETE);
  else if (strcmp (argv[0], "corba") == 0)
    GRID_NODE_DEBUG_ON (CORBA);
  else if (strcmp (argv[0], "corba-all") == 0)
    GRID_NODE_DEBUG_ON (CORBA_ALL);
  else if (strcmp (argv[0], "user") == 0)
    GRID_NODE_DEBUG_ON (USER);
  return CMD_SUCCESS;
}

DEFUN (no_debug_ospf_grid_node,
       no_debug_ospf_grid_node_cmd,
       "no debug ospf grid-node (all|generate|originate|refresh|flush|feed-up|feed-down|uni-inni|inni-uni|corba|corba-all|delete|user)",
       NO_STR
       DEBUG_STR
       OSPF_STR
       "Grid Node information\n"
       "all grid node events\n"
       "grid node generate events\n"
       "grid node flooding events\n"
       "grid node opaque refresh events\n"
       "grid node opaque flush events\n"
       "grid node feed up\n"
       "grid node feed down\n"
       "grid node moving lsa from ospf uni to ospf inni instance\n"
       "grid node moving lsa from ospf inni to ospf uni instance\n"
       "grid node opaque delete\n"
       "grid node basic corba events\n"
       "grid node all corba events\n"
       "grid node debug for user purposes\n")
{
  if (strcmp (argv[0], "all") == 0)
    GRID_NODE_DEBUG_OFF (ALL);
  else if (strcmp (argv[0], "generate") == 0)
    GRID_NODE_DEBUG_OFF (GENERATE);
  else if (strcmp (argv[0], "originate") == 0)
    GRID_NODE_DEBUG_OFF (ORIGINATE);
  else if (strcmp (argv[0], "flush") == 0)
    GRID_NODE_DEBUG_OFF (FLUSH);
  else if (strcmp (argv[0], "refresh") == 0)
    GRID_NODE_DEBUG_OFF (REFRESH);
  else if (strcmp (argv[0], "feed-up") == 0)
    GRID_NODE_DEBUG_OFF (FEED_UP);
  else if (strcmp (argv[0], "feed-down") == 0)
    GRID_NODE_DEBUG_OFF (FEED_DOWN);
  else if (strcmp (argv[0], "uni-inni") == 0)
    GRID_NODE_DEBUG_OFF (UNI_TO_INNI);
  else if (strcmp (argv[0], "inni-uni") == 0)
    GRID_NODE_DEBUG_OFF (INNI_TO_UNI);
  else if (strcmp (argv[0], "delete") == 0)
    GRID_NODE_DEBUG_OFF (DELETE);
  else if (strcmp (argv[0], "corba") == 0)
    GRID_NODE_DEBUG_OFF (CORBA);
  else if (strcmp (argv[0], "corba-all") == 0)
    GRID_NODE_DEBUG_OFF (CORBA_ALL);
  else if (strcmp (argv[0], "user") == 0)
    GRID_NODE_DEBUG_OFF (USER);

  return CMD_SUCCESS;
}

DEFUN(show_cli_grid_tlv_GridSite,
      show_cli_grid_tlv_GridSite_cmd,
      "show grid-node site [ID]",
      SHOW_STR
      "Grid Node information\n"
      "Grid Side Property TLV\n"
      "Site ID\n")
{
  struct grid_node *gn;
  struct zlistnode *node, *nnode;

  /* Show All Interfaces. */
  if (argc == 0)
  {
    for (ALL_LIST_ELEMENTS (OspfGRID.iflist, node, nnode, gn))
      show_grid_tlv_GridSite_sub (vty, gn);
  }
  /* Interface name is specified. */
  else
  {
    uint32_t id = strtoul(argv[0], NULL, 10);
    if ((gn = lookup_grid_node_by_site_id(id)) == NULL)
    {
      if (vty)
        vty_out (vty, "No grid site ID: %d%s", id, VTY_NEWLINE);
      else
        zlog_debug("[DBG] show_cli_grid_tlv_GridSite: No grid site ID: %d", id);
    }
    else
      show_grid_tlv_GridSite_sub (vty, gn);
  }
  return CMD_SUCCESS;
}
static void
show_grid_tlv_GridService_sub (struct vty *vty, struct grid_node *gn)
{
  if (gn->ifp->adj_type != UNI)
    return;
  struct ospf *ospf = ospf_uni_lookup();
  if (ospf == NULL)
    return;

  struct grid_tlv_header    *tlvh;
  struct zlistnode          *snode, *snode2;
  struct grid_node_service  *gn_service;

  if (OspfGRID.status == enabled)
  {
    vty_out (vty, "-- %s parameters for %s --%s", (gn->ifp->ospf_instance == INNI) ? "INNI": (gn->ifp->ospf_instance == ENNI) ? "ENNI" : "UNI", gn->ifp->name, VTY_NEWLINE);
    for(ALL_LIST_ELEMENTS(gn->list_of_grid_node_service, snode, snode2, gn_service))
    {
      vty_out (vty, " -------------------------------%s", VTY_NEWLINE);
      tlvh = &gn_service->gridService.id.header;
      show_vty_grid_tlv_GridService_ID(vty, tlvh);
      tlvh = &gn_service->gridService.parentSite_id.header;
      show_vty_grid_tlv_GridService_ParentSite_ID(vty, tlvh);
      tlvh = &gn_service->gridService.serviceInfo.header;
      show_vty_grid_tlv_GridService_ServiceInfo(vty, tlvh);
      tlvh = &gn_service->gridService.status.header;
      show_vty_grid_tlv_GridService_Status(vty, tlvh);
      tlvh = &gn_service->gridService.addressLength.header;
      show_vty_grid_tlv_GridService_AddressLength(vty, tlvh);
      tlvh = &gn_service->gridService.ipv4Endpoint.header;
      show_vty_grid_tlv_GridService_IPv4Endpoint(vty, tlvh);
      tlvh = &gn_service->gridService.ipv6Endpoint.header;
      show_vty_grid_tlv_GridService_IPv6Endpoint(vty, tlvh);
      tlvh = &gn_service->gridService.nsapEndpoint.header;
      show_vty_grid_tlv_GridService_NsapEndpoint(vty, tlvh);
    }
  }
  return;
}
DEFUN(show_cli_grid_tlv_GridService,
      show_cli_grid_tlv_GridService_cmd,
      "show grid-node service [ID]",
      SHOW_STR
      "Grid Node information\n"
      "Grid Service Property TLV\n"
      "Site ID\n")
{
  struct grid_node *gn;
  struct zlistnode *node, *nnode;

  /* Show All Interfaces. */
  if (argc == 0)
  {
    for (ALL_LIST_ELEMENTS (OspfGRID.iflist, node, nnode, gn))
      show_grid_tlv_GridService_sub (vty, gn);
  }
  /* Interface name is specified. */
  else
  {
    int id = strtoul(argv[0], NULL, 10);
    if ((gn = lookup_grid_node_by_site_id(id)) == NULL)
    {
      if (vty)
        vty_out (vty, "No such site id: %d%s", id, VTY_NEWLINE);
      else
        zlog_debug("[DBG] show_cli_grid_tlv_GridService: No such site id: %d", id);
    }
    else
      show_grid_tlv_GridService_sub (vty, gn);
  }
  return CMD_SUCCESS;
}
static void
show_grid_tlv_GridComputingElement_sub (struct vty *vty, struct grid_node *gn)
{
  if (gn->ifp->adj_type != UNI)
    return;
  struct ospf *ospf = ospf_uni_lookup();
  if (ospf == NULL)
    return;

  struct grid_tlv_header     *tlvh;
  struct zlistnode           *node;
  struct grid_node_computing *gn_computing;

  if (OspfGRID.status == enabled)
  {
    vty_out (vty, "-- %s parameters for %s --%s", (gn->ifp->ospf_instance == INNI) ? "INNI": (gn->ifp->ospf_instance == ENNI) ? "ENNI" : "UNI", gn->ifp->name, VTY_NEWLINE);
    for(ALL_LIST_ELEMENTS_RO(gn->list_of_grid_node_computing, node, gn_computing))
    {
      vty_out (vty, " -------------------------------%s", VTY_NEWLINE);
      tlvh = &gn_computing->gridCompElement.id.header;
      show_vty_grid_tlv_GridComputingElement_ID(vty, tlvh);
      tlvh = &gn_computing->gridCompElement.parentSiteId.header;
      show_vty_grid_tlv_GridComputingElement_ParentSiteID(vty, tlvh);
      tlvh = &gn_computing->gridCompElement.lrmsInfo.header;
      show_vty_grid_tlv_GridComputingElement_LrmsInfo(vty, tlvh);
      tlvh = &gn_computing->gridCompElement.addressLength.header;
      show_vty_grid_tlv_GridComputingElement_AddressLength(vty, tlvh);
      tlvh = &gn_computing->gridCompElement.ipv4HostName.header;
      show_vty_grid_tlv_GridComputingElement_IPv4HostName(vty, tlvh);
      tlvh = &gn_computing->gridCompElement.ipv6HostName.header;
      show_vty_grid_tlv_GridComputingElement_IPv6HostName(vty, tlvh);
      tlvh = &gn_computing->gridCompElement.nsapHostName.header;
      show_vty_grid_tlv_GridComputingElement_NsapHostName(vty, tlvh);
      tlvh = &gn_computing->gridCompElement.gatekeeperPort.header;
      show_vty_grid_tlv_GridComputingElement_GatekeeperPort(vty, tlvh);
      tlvh = &gn_computing->gridCompElement.jobManager.header;
      show_vty_grid_tlv_GridComputingElement_JobManager_FromStruct(vty, tlvh);
      tlvh = &gn_computing->gridCompElement.dataDir.header;
      show_vty_grid_tlv_GridComputingElement_DataDir_FromStruct(vty, tlvh);
      tlvh = &gn_computing->gridCompElement.defaultSe.header;
      show_vty_grid_tlv_GridComputingElement_DefaultStorageElement(vty, tlvh);
      tlvh = &gn_computing->gridCompElement.jobsStates.header;
      show_vty_grid_tlv_GridComputingElement_JobsStates(vty, tlvh);
      tlvh = &gn_computing->gridCompElement.jobsStats.header;
      show_vty_grid_tlv_GridComputingElement_JobsStats(vty, tlvh);
      tlvh = &gn_computing->gridCompElement.jobsTimePerformances.header;
      show_vty_grid_tlv_GridComputingElement_JobsTimePerformances(vty, tlvh);
      tlvh = &gn_computing->gridCompElement.jobsTimePolicy.header;
      show_vty_grid_tlv_GridComputingElement_JobsTimePolicy(vty, tlvh);
      tlvh = &gn_computing->gridCompElement.jobsLoadPolicy.header;
      show_vty_grid_tlv_GridComputingElement_JobsLoadPolicy(vty, tlvh);
      tlvh = &gn_computing->gridCompElement.ceCalendar.header;
      show_vty_grid_tlv_GridComputingElement_CeCalendar_FromStruct(vty, tlvh);
      tlvh = &gn_computing->gridCompElement.name.header;
      show_vty_grid_tlv_GridComputingElement_Name_FromStruct(vty, tlvh);
    }
  }
  return;
}
DEFUN(show_cli_grid_tlv_GridComputingElement,
      show_cli_grid_tlv_GridComputingElement_cmd,
      "show grid-node computing [ID]",
      SHOW_STR
      "Grid Node information\n"
      "Grid Computing Element Property TLV\n"
      "Site ID\n")
{
  struct grid_node *gn;
  struct zlistnode *node, *nnode;

  /* Show All Interfaces. */
  if (argc == 0)
  {
    for (ALL_LIST_ELEMENTS (OspfGRID.iflist, node, nnode, gn))
      show_grid_tlv_GridComputingElement_sub (vty, gn);
  }
  /* Interface name is specified. */
  else
  {
    int id = strtoul(argv[0], NULL, 10);
    if ((gn = lookup_grid_node_by_site_id(id)) == NULL)
    {
      if (vty)
        vty_out (vty, "No such Site id: %d%s", id, VTY_NEWLINE);
      else
        zlog_debug ("[DBG] show_cli_grid_tlv_GridComputingElement: No such Site id: %d", id);
    }
    else
      show_grid_tlv_GridComputingElement_sub (vty, gn);
  }
  return CMD_SUCCESS;
}
static void
show_grid_tlv_GridSubCluster_sub (struct vty *vty, struct grid_node *gn)
{
  if (gn->ifp->adj_type != UNI)
    return;
  struct ospf *ospf = ospf_uni_lookup();
  if (ospf == NULL)
    return;

  struct grid_tlv_header                          *tlvh;
  struct zlistnode                                *node, *nnode;
  struct zlistnode                                *gn_node, *gn_nnode;
  struct grid_tlv_GridSubCluster_SoftwarePackage  *temp_ptr;
  struct grid_node_subcluster                     *gn_subcluster;

  if (OspfGRID.status == enabled)
  {
    vty_out (vty, "-- %s parameters for %s --%s", (gn->ifp->ospf_instance == INNI) ? "INNI": (gn->ifp->ospf_instance == ENNI) ? "ENNI" : "UNI", gn->ifp->name, VTY_NEWLINE);
    for (ALL_LIST_ELEMENTS(gn->list_of_grid_node_subcluster, gn_node, gn_nnode, gn_subcluster))
    {
      vty_out (vty, " -------------------------------%s", VTY_NEWLINE);
      tlvh = &gn_subcluster->gridSubcluster.id.header;
      show_vty_grid_tlv_GridSubCluster_ID(vty, tlvh);
      tlvh = &gn_subcluster->gridSubcluster.parentSiteId.header;
      show_vty_grid_tlv_GridSubCluster_ParentSiteID(vty, tlvh);
      tlvh = &gn_subcluster->gridSubcluster.cpuInfo.header;
      show_vty_grid_tlv_GridSubCluster_CpuInfo(vty, tlvh);
      tlvh = &gn_subcluster->gridSubcluster.osInfo.header;
      show_vty_grid_tlv_GridSubCluster_OsInfo(vty, tlvh);
      tlvh = &gn_subcluster->gridSubcluster.memoryInfo.header;
      show_vty_grid_tlv_GridSubCluster_MemoryInfo(vty, tlvh);
      for (ALL_LIST_ELEMENTS (&gn_subcluster->gridSubcluster.softwarePackage, node, nnode, temp_ptr))
      {
        tlvh = &temp_ptr->header;
        show_vty_grid_tlv_GridSubCluster_SoftwarePackage_FromStruct(vty, tlvh);
      }
      tlvh = &gn_subcluster->gridSubcluster.subclusterCalendar.header;
      show_vty_grid_tlv_GridSubCluster_SubClusterCalendar_FromStruct(vty, tlvh);
      tlvh = &gn_subcluster->gridSubcluster.name.header;
      show_vty_grid_tlv_GridSubCluster_Name_FromStruct(vty, tlvh);
    }
  }
  return;
}

DEFUN (reoriginate_grid,
       reoriginate_grid_cmd,
       "grid-node reoriginate",
       "Configure Grid Node parameters\n"
       "Reoriginate Grid Nodes\n")
{
  if (OspfGRID.status == disabled)
  {
    vty_out(vty, "Ospf Grid is disabled. Enable Ospf Grid first%s", VTY_NEWLINE);
    return CMD_WARNING;
  }

  struct zlistnode *node, *nnode;

  struct ospf *ospf = (struct ospf*) vty->index;
  struct ospf_area *area;

  for (ALL_LIST_ELEMENTS (ospf->areas, node, nnode, area))
    ospf_grid_lsa_originate(area);

  return CMD_SUCCESS;
}

DEFUN(show_cli_grid_tlv_GridSubCluster,
      show_cli_grid_tlv_GridSubCluster_cmd,
      "show grid-node subcluster [ID]",
      SHOW_STR
      "Grid Node information\n"
      "Grid SubCluster Property TLV\n"
      "Grid node SiteID\n")
{
  struct grid_node *gn;
  struct zlistnode *node, *nnode;

  /* Show All Interfaces. */
  if (argc == 0)
  {
    for (ALL_LIST_ELEMENTS (OspfGRID.iflist, node, nnode, gn))
      show_grid_tlv_GridSubCluster_sub (vty, gn);
  }
  /* Interface name is specified. */
  else
  {
    if ((gn = lookup_grid_node_by_site_id(strtoul(argv[0], NULL, 10))) == NULL)
      vty_out (vty, "No grid node with site id %s%s", argv[0], VTY_NEWLINE);
    else
      show_grid_tlv_GridSubCluster_sub (vty, gn);
  }
  return CMD_SUCCESS;
}

static void
show_grid_tlv_GridStorage_sub (struct vty *vty, struct grid_node *gn)
{
  struct ospf *ospf = ospf_uni_lookup();
  if (ospf == NULL)
    return;

  struct grid_tlv_header *tlvh;

//  struct zlistnode *node, *node2;
//  struct 

  if (OspfGRID.status == enabled)
  {
    vty_out (vty, "-- %s parameters for %s --%s", (gn->ifp->ospf_instance == INNI) ? "INNI": (gn->ifp->ospf_instance == ENNI) ? "ENNI" : "UNI", gn->ifp->name, VTY_NEWLINE);

    struct zlistnode *snode, *snode2;
    struct grid_node_storage *gn_storage;
    for(ALL_LIST_ELEMENTS(gn->list_of_grid_node_storage, snode, snode2, gn_storage))
    {
      vty_out (vty, " -------------------------------%s", VTY_NEWLINE);
      tlvh = &gn_storage->gridStorage.id.header;
      show_vty_grid_tlv_GridStorage_ID(vty, tlvh);
      tlvh = &gn_storage->gridStorage.parentSiteId.header;
      show_vty_grid_tlv_GridStorage_ParentSiteID(vty, tlvh);
      tlvh = &gn_storage->gridStorage.storageInfo.header;
      show_vty_grid_tlv_GridStorage_StorageInfo(vty, tlvh);
      tlvh = &gn_storage->gridStorage.onlineSize.header;
      show_vty_grid_tlv_GridStorage_OnlineSize(vty, tlvh);
      tlvh = &gn_storage->gridStorage.nearlineSize.header;
      show_vty_grid_tlv_GridStorage_NearlineSize(vty, tlvh);
      
      struct zlistnode *node, *nnode;
      struct grid_tlv_GridStorage_StorageArea *StArea;
      for (ALL_LIST_ELEMENTS (&gn_storage->gridStorage.storageArea, node, nnode, StArea))
      {
        show_vty_grid_tlv_GridStorage_StorageArea_FromStruct(vty, (struct grid_tlv_header*) (void *) StArea);
      }
      tlvh = &gn_storage->gridStorage.seCalendar.header;
      show_vty_grid_tlv_GridStorage_SeCalendar_FromStruct(vty, tlvh);
      tlvh = &gn_storage->gridStorage.name.header;
      show_vty_grid_tlv_GridStorage_Name_FromStruct(vty, tlvh);
    }
  }
  else
  {
    vty_out (vty, "  %s: Grid node options are disabled on this interface%s", gn->ifp->name, VTY_NEWLINE);
  }
  return;
}

DEFUN(show_cli_grid_tlv_GridStorage,
      show_cli_grid_tlv_GridStorage_cmd,
      "show grid-node storage [ID]",
      SHOW_STR
      "Grid Node information\n"
      "Grid Storage Element Property TLV\n"
      "Interface name\n")
{
  struct grid_node *gn;
  struct zlistnode *node, *nnode;

  /* Show All Interfaces. */
  if (argc == 0)
  {
    for (ALL_LIST_ELEMENTS (OspfGRID.iflist, node, nnode, gn))
      show_grid_tlv_GridStorage_sub (vty, gn);
  }
  /* Interface name is specified. */
  else
  {
    int id = strtoul(argv[0], NULL, 10);
    if ((gn = lookup_grid_node_by_site_id(id)) == NULL)
    {
      if (vty != NULL)
        vty_out (vty, "No grid-node with such id: %d%s", id, VTY_NEWLINE);
      else
        zlog_warn("[WRN] show_cli_grid_tlv_GridStorage: No grid-node with such id: %d", id);
    }
    else
      show_grid_tlv_GridStorage_sub (vty, gn);
  }
  return CMD_SUCCESS;
}

DEFUN(set_cli_grid_tlv_GridStorage_Name,
      set_cli_grid_tlv_GridStorage_Name_cmd,
      "storage ID name NAME",
      "Grid Storage Property TLV\n"
      "Grid Storage Element ID\n"
      "Human-readable name\n"
      "Name (string)\n")
{
  struct grid_node          *gn = (struct grid_node *) vty->index;
  struct grid_node_storage  *gn_storage;

  if ((gn_storage = lookup_grid_node_storage_by_grid_node_and_sub_id (gn, strtoul(argv[0], NULL, 0)))==NULL)
  {
    vty_out (vty, "no storage element with ID %d, add new storage element before%s", (uint32_t) strtoul(argv[0], NULL, 0), VTY_NEWLINE);
    return CMD_WARNING;
  }

  if (1)
  {
    set_grid_tlv_GridStorage_Name(gn_storage, argv[1]);
    if (OspfGRID.status == enabled)
      if (gn->area != NULL)
      {
        if (gn_storage->base.flags & GRIDFLG_GRID_LSA_ENGAGED)
        {
          ospf_grid_storage_lsa_schedule (gn_storage, GRID_REFRESH_THIS_LSA);
          zlog_debug("[DBG] ospf_grid_storage_lsa_schedule (gn_storage, GRID_REFRESH_THIS_LSA)");
        }
        else
        {
          ospf_grid_storage_lsa_schedule (gn_storage, GRID_REORIGINATE_PER_AREA);
          zlog_debug("[DBG] ospf_grid_storage_lsa_schedule (gn_storage, GRID_REORIGINATE_PER_AREA)");
        }
      }
  }
  return CMD_SUCCESS;
}

DEFUN(set_cli_grid_tlv_GridStorage_SeCalendar,
      set_cli_grid_tlv_GridStorage_SeCalendar_cmd,
      "storage ID se_calendar (add|clear|skip) [TIME] [FREE_ONLINE_SIZE] [FREE_NEARLINE_SIZE]",
      "Grid Storage Element Property TLV\n"
      "Grid Storage Element ID\n"
      "The FreeOnlineSize and FreeNearlineSize scheduling calendar for each timestamp\n"
      "Add new element to the list\n"
      "Clear the list\n"
      "Skip the list modiffication\n"
      "Timestamp\n"
      "Free Online Size\n"
      "Free Nearline Size\n")
{
  struct grid_node          *gn = (struct grid_node *) vty->index;
  struct grid_node_storage  *gn_storage;

  if ((gn_storage = lookup_grid_node_storage_by_grid_node_and_sub_id(gn, strtoul(argv[0], NULL, 0)))==NULL)
  {
    vty_out (vty, "no storage element with ID %d, add new storage before%s", (uint32_t) strtoul(argv[0], NULL, 0),  VTY_NEWLINE);
    return CMD_WARNING;
  }

  enum list_opcode value0;
  struct se_calendar* se_cal = NULL;
  if (strcmp(argv[1], "add") == 0)
  {
    value0 = ADD;
    se_cal = XMALLOC (MTYPE_OSPF_GRID_SERVICE_CALENDAR, sizeof(struct se_calendar));
    unsigned int time;
    unsigned int freeOnlineSize;
    unsigned int freeNearlineSize;
    if (argc <= 3)
    {
      vty_out (vty, "Please write value to add to the list%s", VTY_NEWLINE);
      return CMD_WARNING;   
    }
    if (sscanf (argv[2], "%u", &time) != 1)
    {
      vty_out (vty, "set_cli_grid_tlv_GridStorage_SeCalendar: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
      return CMD_WARNING;
    }
    se_cal->time = htonl((uint32_t)time);
    if (sscanf (argv[3], "%u", &freeOnlineSize) != 1)
    {
      vty_out (vty, "set_cli_grid_tlv_GridStorage_SeCalendar: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
      return CMD_WARNING;
    }
    se_cal->freeOnlineSize = htonl((uint32_t)freeOnlineSize);
    if (sscanf (argv[4], "%u", &freeNearlineSize) != 1)
    {
      vty_out (vty, "set_cli_grid_tlv_GridStorage_SeCalendar: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
      return CMD_WARNING;
    }
    se_cal->freeNearlineSize = htonl((uint32_t)freeNearlineSize);
  }
  else
  {
    if (strcmp(argv[1], "clear") == 0)
      value0 = CLEAR;
    else
      value0 = LEAVE;
  }

  if (1)
  {
    set_grid_tlv_GridStorage_SeCalendar(gn_storage, value0, (void *) se_cal);

    if (OspfGRID.status == enabled)
      if (gn->area != NULL)
      {
        if (gn_storage->base.flags & GRIDFLG_GRID_LSA_ENGAGED)
        {
          ospf_grid_storage_lsa_schedule (gn_storage, GRID_REFRESH_THIS_LSA);
          zlog_debug("[DBG] ospf_grid_storage_lsa_schedule (gn_storage, GRID_REFRESH_THIS_LSA)");
        }
        else
        {
          ospf_grid_storage_lsa_schedule (gn_storage, GRID_REORIGINATE_PER_AREA);
          zlog_debug("[DBG] ospf_grid_storage_lsa_schedule (gn_storage, GRID_REORIGINATE_PER_AREA)");
        }
      }
  }
  return CMD_SUCCESS;
}
DEFUN(set_cli_grid_tlv_GridStorage_StorageArea,
      set_cli_grid_tlv_GridStorage_StorageArea_cmd,
      "storage ID area (add|clear) [NAME] [PATH] [TOTAL_ONLINE_SIZE] [FREE_ONLINE_SIZE] [RES_TOTAL_ONLINE_SIZE] [TOTAL_NEARLINE_SIZE] [FREE_NEARLINE_SIZE] [RES_NEARLINE_SIZE] [RET_POLICY] [ACC_LATENCY] [EXPIRATION_MODE]",
      "Grid Storage Element Property TLV\n"
      "Grid Storage Element ID\n"
      "Storage Area\n"
      "add to Storage Area\n"
      "clear the Storage Area list\n"
      "Name\n"
      "Path\n"
      "Total online size\n"
      "Free online size\n"
      "Reserved total online size\n"
      "Total nearline size\n"
      "Free nearline size\n"
      "Reserved nearline size\n"
      "Retention policy (4 bits)\n"
      "Access latency (4 bits)\n"
      "Expiration mode (4 bits)\n")
{
  struct grid_node          *gn = (struct grid_node *) vty->index;
  struct grid_node_storage  *gn_storage;

  if ((gn_storage = lookup_grid_node_storage_by_grid_node_and_sub_id(gn, strtoul(argv[0], NULL, 0)))==NULL)
  {
    vty_out (vty, "no storage element with ID %d, add new storage before%s", (uint32_t) strtoul(argv[0], NULL, 0),  VTY_NEWLINE);
    return CMD_WARNING;
  }


  if (strcmp(argv[1], "add") == 0)
  {
    if (argc > 12)
    {
      long unsigned int value2;
      if (sscanf (argv[4], "%lu", &value2) != 1)
      {
        vty_out (vty, "set_cli_grid_tlv_GridStorage_StorageArea: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
        return CMD_WARNING;
      }
      long unsigned int value3;
      if (sscanf (argv[5], "%lu", &value3) != 1)
      {
        vty_out (vty, "set_cli_grid_tlv_GridStorage_StorageArea: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
        return CMD_WARNING;
      }
      long unsigned int value4;
      if (sscanf (argv[6], "%lu", &value4) != 1)
      {
        vty_out (vty, "set_cli_grid_tlv_GridStorage_StorageArea: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
        return CMD_WARNING;
      }
      long unsigned int value5;
      if (sscanf (argv[7], "%lu", &value5) != 1)
      {
        vty_out (vty, "set_cli_grid_tlv_GridStorage_StorageArea: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
        return CMD_WARNING;
      }
      long unsigned int value6;
      if (sscanf (argv[8], "%lu", &value6) != 1)
      {
        vty_out (vty, "set_cli_grid_tlv_GridStorage_StorageArea: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
        return CMD_WARNING;
      }
      long unsigned int value7;
      if (sscanf (argv[9], "%lu", &value7) != 1)
      {
        vty_out (vty, "set_cli_grid_tlv_GridStorage_StorageArea: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
        return CMD_WARNING;
      }
      unsigned int  value8;
      if (sscanf (argv[10], "%u", &value8) != 1)
      {
        vty_out (vty, "set_cli_grid_tlv_GridStorage_StorageArea: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
        return CMD_WARNING;
      }
      unsigned int temp = value8 << 4;
      if (sscanf (argv[11], "%u", &value8) != 1)
      {
        vty_out (vty, "set_cli_grid_tlv_GridStorage_StorageArea: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
        return CMD_WARNING;
      }
      value8 |= temp;
      unsigned int  value9;
      if (sscanf (argv[12], "%u", &value9) != 1)
      {
        vty_out (vty, "set_cli_grid_tlv_GridStorage_StorageArea: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
        return CMD_WARNING;
      }
      value9 <<= 4;

      struct grid_tlv_GridStorage_StorageArea *StArea = create_grid_tlv_GridStorage_StorageArea(argv[2],argv[3],(uint32_t) value2,(uint32_t) value3,(uint32_t) value4,(uint32_t) value5,(uint32_t) value6,(uint32_t) value7,(uint8_t) value8, (uint8_t) value9);

      set_grid_tlv_GridStorage(gn_storage, ADD, StArea);
    }
    else
    {
      vty_out(vty, "%% Command incomplete.%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  }
  else
    set_grid_tlv_GridStorage(gn_storage, CLEAR, NULL);

  if (1)
  {
    if (OspfGRID.status == enabled)
      if (gn->area != NULL)
      {
        if (gn_storage->base.flags & GRIDFLG_GRID_LSA_ENGAGED)
        {
          ospf_grid_storage_lsa_schedule (gn_storage, GRID_REFRESH_THIS_LSA);
          zlog_debug("[DBG] ospf_grid_storage_lsa_schedule (gn_storage, GRID_REFRESH_THIS_LSA)");
        }
        else
        {
          ospf_grid_storage_lsa_schedule (gn_storage, GRID_REORIGINATE_PER_AREA);
          zlog_debug("[DBG] ospf_grid_storage_lsa_schedule (gn_storage, GRID_REORIGINATE_PER_AREA)");
        }
      }
  }
  return CMD_SUCCESS;
}
DEFUN(set_cli_grid_tlv_GridStorage_NearlineSize,
      set_cli_grid_tlv_GridStorage_NearlineSize_cmd,
      "storage ID nearline_size TOTAL_SIZE USED_SIZE",
      "Grid Storage Element Property TLV\n"
      "Grid Storage Element ID\n"
      "The nearline storage sizes (total + used) in GB\n"
      "Total Size in GB\n"
      "Used Size in GB\n")
{
  struct grid_node          *gn = (struct grid_node *) vty->index;
  struct grid_node_storage  *gn_storage;

  if ((gn_storage = lookup_grid_node_storage_by_grid_node_and_sub_id(gn, strtoul(argv[0], NULL, 0)))==NULL)
  {
    vty_out (vty, "no storage element with ID %d, add new storage before%s", (uint32_t) strtoul(argv[0], NULL, 0), VTY_NEWLINE);
    return CMD_WARNING;
  }

  long unsigned int value0;
  if (sscanf (argv[1], "%lu", &value0) != 1)
  {
    vty_out (vty, "set_cli_grid_tlv_GridStorage_NearlineSize: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
    return CMD_WARNING;
  }
  long unsigned int value1;
  if (sscanf (argv[2], "%lu", &value1) != 1)
  {
    vty_out (vty, "set_cli_grid_tlv_GridStorage_NearlineSize: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
    return CMD_WARNING;
  }

  if ((ntohs(gn_storage->gridStorage.nearlineSize.header.type) == 0)
     ||(ntohl(gn_storage->gridStorage.nearlineSize.totalSize) != value0)
     ||(ntohl(gn_storage->gridStorage.nearlineSize.usedSize) != value1))
  {
    set_grid_tlv_GridStorage_NearlineSize(gn_storage,(uint32_t) value0,(uint32_t) value1);

    if (OspfGRID.status == enabled)
      if (gn->area != NULL)
      {
        if (gn_storage->base.flags & GRIDFLG_GRID_LSA_ENGAGED)
        {
          ospf_grid_storage_lsa_schedule (gn_storage, GRID_REFRESH_THIS_LSA);
          zlog_debug("[DBG] ospf_grid_storage_lsa_schedule (gn_storage, GRID_REFRESH_THIS_LSA)");
        }
        else
        {
          ospf_grid_storage_lsa_schedule (gn_storage, GRID_REORIGINATE_PER_AREA);
          zlog_debug("[DBG] ospf_grid_storage_lsa_schedule (gn_storage, GRID_REORIGINATE_PER_AREA)");
        }
      }
  }
  return CMD_SUCCESS;
}
DEFUN(set_cli_grid_tlv_GridStorage_OnlineSize,
      set_cli_grid_tlv_GridStorage_OnlineSize_cmd,
      "storage ID online_size TOTAL_SIZE USED_SIZE",
      "Grid Storage Element ID\n"
      "Grid Storage Element Property TLV\n"
      "The online storage sizes (total + used) in GB\n"
      "Total Size in GB\n"
      "Used Size in GB\n")
{
  struct grid_node          *gn = (struct grid_node *) vty->index;
  struct grid_node_storage  *gn_storage;

  if ((gn_storage = lookup_grid_node_storage_by_grid_node_and_sub_id(gn, strtoul(argv[0], NULL, 0)))==NULL)
  {
    vty_out (vty, "no storage element with ID %d, add new storage before%s", (uint32_t) strtoul(argv[0], NULL, 0), VTY_NEWLINE);
    return CMD_WARNING;
  }

  long unsigned int value0;
  if (sscanf (argv[1], "%lu", &value0) != 1)
  {
    vty_out (vty, "set_cli_grid_tlv_GridStorage_OnlineSize: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
    return CMD_WARNING;
  }
  long unsigned int value1;
  if (sscanf (argv[2], "%lu", &value1) != 1)
  {
    vty_out (vty, "set_cli_grid_tlv_GridStorage_OnlineSize: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
    return CMD_WARNING;
  }

  if ((ntohs(gn_storage->gridStorage.onlineSize.header.type) == 0)
     ||(ntohl(gn_storage->gridStorage.onlineSize.totalSize) != value0)
     ||(ntohl(gn_storage->gridStorage.onlineSize.usedSize) != value1))
  {
    set_grid_tlv_GridStorage_OnlineSize(gn_storage,(uint32_t) value0,(uint32_t) value1);

    if (OspfGRID.status == enabled)
      if (gn->area != NULL)
      {
        if (gn_storage->base.flags & GRIDFLG_GRID_LSA_ENGAGED)
        {
          ospf_grid_storage_lsa_schedule (gn_storage, GRID_REFRESH_THIS_LSA);
          zlog_debug("[DBG] ospf_grid_storage_lsa_schedule (gn_storage, GRID_REFRESH_THIS_LSA)");
        }
        else
        {
          ospf_grid_storage_lsa_schedule (gn_storage, GRID_REORIGINATE_PER_AREA);
          zlog_debug("[DBG] ospf_grid_storage_lsa_schedule (gn_storage, GRID_REORIGINATE_PER_AREA)");
        }
      }
  }
  return CMD_SUCCESS;
}
DEFUN(set_cli_grid_tlv_GridStorage_StorageInfo,
      set_cli_grid_tlv_GridStorage_StorageInfo_cmd,
      "storage ID storage_info ARCH STATUS ACC_PROT CON_PROT",
      "Grid Storage Element ID\n"
      "Grid Storage Element Property TLV\n"
      "Information about the storage architecture the status of the SE the access and control protocols\n"
      "Storage architecture (4 bits) ex. 0xa1\n" 
      "Status (4 bits) ex. 0xa1\n"
      "Access protocol (12 bits) ex. 0xa1\n"
      "Control protocol (12 bits) ex. 0x.a1\n")
{
  struct grid_node          *gn = (struct grid_node *) vty->index;
  struct grid_node_storage  *gn_storage;

  if ((gn_storage = lookup_grid_node_storage_by_grid_node_and_sub_id(gn, strtoul(argv[0], NULL, 0)))==NULL)
  {
    vty_out (vty, "no storage element with ID %d, add new storage before%s", (uint32_t) strtoul(argv[0], NULL, 0), VTY_NEWLINE);
    return CMD_WARNING;
  }

  u_int32_t temp;
  unsigned int value0;
  if (sscanf (argv[1], "0x%x", &value0) != 1)
  {
    vty_out (vty, "set_cli_grid_tlv_GridStorage_StorageInfo: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
    return CMD_WARNING;
  }
  value0 <<= 28;
  if (sscanf (argv[2], "0x%x", &temp) != 1)
  {
    vty_out (vty, "set_cli_grid_tlv_GridStorage_StorageInfo: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
    return CMD_WARNING;
  }
  temp <<= 24;
  value0 |= temp;
  if (sscanf (argv[3], "0x%x", &temp) != 1)
  {
    vty_out (vty, "set_cli_grid_tlv_GridStorage_StorageInfo: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
    return CMD_WARNING;
  }
  temp <<= 12;
  value0 |= temp;
  if (sscanf (argv[4], "0x%x", &temp) != 1)
  {
    vty_out (vty, "set_cli_grid_tlv_GridStorage_StorageInfo: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
    return CMD_WARNING;
  }
  value0 |= temp;

  if ((ntohs(gn_storage->gridStorage.storageInfo.header.type) == 0)
     ||(ntohl(gn_storage->gridStorage.storageInfo.storInfo) != value0))
  {
    set_grid_tlv_GridStorage_StorageInfo(gn_storage, (uint32_t) value0);

    if (OspfGRID.status == enabled)
      if (gn->area != NULL)
      {
        if (gn_storage->base.flags & GRIDFLG_GRID_LSA_ENGAGED)
        {
          ospf_grid_storage_lsa_schedule (gn_storage, GRID_REFRESH_THIS_LSA);
          zlog_debug("[DBG] ospf_grid_storage_lsa_schedule (gn_storage, GRID_REFRESH_THIS_LSA)");
        }
        else
        {
          ospf_grid_storage_lsa_schedule (gn_storage, GRID_REORIGINATE_PER_AREA);
          zlog_debug("[DBG] ospf_grid_storage_lsa_schedule (gn_storage, GRID_REORIGINATE_PER_AREA)");
        }
      }
  }
  return CMD_SUCCESS;
}
DEFUN(set_cli_grid_tlv_GridStorage_ParentSiteID,
      set_cli_grid_tlv_GridStorage_ParentSiteID_cmd,
      "storage ID parent_site_id PARENT_SITE_ID",
      "Grid Storage Element ID\n"
      "Grid Storage Element Property TLV\n"
      "Identifier of the Grid Site that is exporting this storage\n"
      "Identifier of the Grid Site\n")
{
  struct grid_node          *gn = (struct grid_node *) vty->index;
  struct grid_node_storage  *gn_storage;

  if ((gn_storage = lookup_grid_node_storage_by_grid_node_and_sub_id(gn, strtoul(argv[0], NULL, 0)))==NULL)
  {
    vty_out (vty, "no storage element with ID %d, add new storage before%s", (uint32_t) strtoul(argv[0], NULL, 0), VTY_NEWLINE);
    return CMD_WARNING;
  }

  long unsigned int value0;
  if (sscanf (argv[1], "%lu", &value0) != 1)
  {
    vty_out (vty, "set_cli_grid_tlv_GridStorage_ParentSiteID: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
    return CMD_WARNING;
  }

  if ((ntohs(gn_storage->gridStorage.parentSiteId.header.type) == 0)
     ||(ntohl(gn_storage->gridStorage.parentSiteId.parSiteId) != value0))
  {
    set_grid_tlv_GridStorage_ParentSiteID(gn_storage,(uint32_t) value0);

    if (OspfGRID.status == enabled)
      if (gn->area != NULL)
      {
        if (gn_storage->base.flags & GRIDFLG_GRID_LSA_ENGAGED)
        {
          ospf_grid_storage_lsa_schedule (gn_storage, GRID_REFRESH_THIS_LSA);
          zlog_debug("[DBG] ospf_grid_storage_lsa_schedule (gn_storage, GRID_REFRESH_THIS_LSA)");
        }
        else
        {
          ospf_grid_storage_lsa_schedule (gn_storage, GRID_REORIGINATE_PER_AREA);
          zlog_debug("[DBG] ospf_grid_storage_lsa_schedule (gn_storage, GRID_REORIGINATE_PER_AREA)");
        }
      }
  }
  return CMD_SUCCESS;
}
DEFUN(set_cli_grid_tlv_GridStorage_ID,
      set_cli_grid_tlv_GridStorage_ID_cmd,
      "storage add ID",
      "Grid Storage Element Property TLV\n"
      "Add new Storage Element\n"
      "Identifier of the new Storage Element\n")
{
  struct grid_node          *gn = (struct grid_node *) vty->index;
  struct grid_node_storage  *gn_storage;

  uint32_t value0 = strtoul(argv[0], NULL, 0);

  if ((gn_storage = lookup_grid_node_storage_by_grid_node_and_sub_id(gn, value0))==NULL)
  {
    gn_storage = create_new_grid_node_storage(gn, value0);
    listnode_add(gn->list_of_grid_node_storage, gn_storage);
  }
  else
  {
    vty_out (vty, "Alredy exists!%s", VTY_NEWLINE);
    return CMD_WARNING;
  }

  if (OspfGRID.status == enabled)
  {
    if (gn->area != NULL)
    {
      ospf_grid_storage_lsa_schedule(gn_storage, GRID_REORIGINATE_PER_AREA);
      zlog_debug("[DBG] ospf_grid_storage_lsa_schedule (gn_storage, GRID_REORIGINATE_PER_AREA)");
    }
  }
  return CMD_SUCCESS;
}

DEFUN(set_cli_grid_tlv_GridSubCluster_Name,
      set_cli_grid_tlv_GridSubCluster_Name_cmd,
      "subcluster ID name NAME",
      "Grid SubCluster Property TLV\n"
      "Grid SubCluster ID uint32_t\n"
      "Human-readable name\n"
      "Name (string)\n")
{
  struct grid_node             *gn = (struct grid_node *) vty->index;
  struct grid_node_subcluster  *gn_subcluster;

  if ((gn_subcluster = lookup_grid_node_subcluster_by_grid_node_and_sub_id (gn, strtoul(argv[0], NULL, 0)))==NULL)
  {
    vty_out (vty, "no subcluster with ID %d, add new subcluster before%s", (uint32_t) strtoul(argv[0], NULL, 0), VTY_NEWLINE);
    return CMD_WARNING;
  }

  if (1)
  {
    set_grid_tlv_GridSubCluster_Name(gn_subcluster, argv[1]);
    if (OspfGRID.status == enabled)
      if (gn->area != NULL)
      {
        if (gn_subcluster->base.flags & GRIDFLG_GRID_LSA_ENGAGED)
        {
          ospf_grid_subcluster_lsa_schedule (gn_subcluster, GRID_REFRESH_THIS_LSA);
          zlog_debug("[DBG] ospf_grid_subcluster_lsa_schedule (gn_subcluster, GRID_REFRESH_THIS_LSA)");
        }
        else
        {
          ospf_grid_subcluster_lsa_schedule (gn_subcluster, GRID_REORIGINATE_PER_AREA);
          zlog_debug("[DBG] ospf_grid_subcluster_lsa_schedule (gn_subcluster, GRID_REORIGINATE_PER_AREA)");
        }
      }
  }
  return CMD_SUCCESS;
}

DEFUN(set_cli_grid_tlv_GridSubCluster_SubClusterCalendar,
      set_cli_grid_tlv_GridSubCluster_SubClusterCalendar_cmd,
      "subcluster ID subcluster_calendar (add|clear|skip) [TIME] [PHY_CPUS] [LOG_CPUS] ",
      "Grid SubCluster Property TLV\n"
      "Grid SubCluster ID uint32_t\n"
      "The PhysicalCPUs and LogicalCPUs scheduling calendar for each timestamp\n"
      "Add new element to the list\n"
      "Clear the list\n"
      "Skip the list modiffication\n"
      "Timestamp\n"
      "Physical CPUs\n"
      "Logical CPUs\n")
{
  struct grid_node             *gn = (struct grid_node *) vty->index;
  struct grid_node_subcluster  *gn_subcluster;

  if ((gn_subcluster = lookup_grid_node_subcluster_by_grid_node_and_sub_id(gn, strtoul(argv[0], NULL, 0)))==NULL)
  {
    vty_out (vty, "no storage element with ID %d, add new storage before%s", (uint32_t) strtoul(argv[0], NULL, 0), VTY_NEWLINE);
    return CMD_WARNING;
  }

  enum list_opcode value0;
  struct sc_calendar *sc_cal = NULL;
  if (strcmp(argv[1], "add") == 0)
  {
    value0 = ADD;
    sc_cal = XMALLOC (MTYPE_OSPF_GRID_SUBCLUSTER_CALENDAR, sizeof(struct sc_calendar));
    unsigned int time;
    unsigned int pcpus;
    unsigned int lcpus;
    if (argc <= 2)
    {
      vty_out (vty, "Please write value to add to the list%s", VTY_NEWLINE);
      return CMD_WARNING;   
    }
    if (sscanf (argv[2], "%u", &time) != 1)
    {
      vty_out (vty, "set_cli_grid_tlv_GridSubCluster_SubClusterCalendar: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
      return CMD_WARNING;
    }
    sc_cal->time = htonl((uint32_t)time);
    if (sscanf (argv[3], "%u", &pcpus) != 1)
    {
      vty_out (vty, "set_cli_grid_tlv_GridSubCluster_SubClusterCalendar: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
      return CMD_WARNING;
    }
    sc_cal->physical_cpus = htons((uint16_t)pcpus);
    if (sscanf (argv[4], "%u", &lcpus) != 1)
    {
      vty_out (vty, "set_cli_grid_tlv_GridSubCluster_SubClusterCalendar: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
      return CMD_WARNING;
    }
    sc_cal->logical_cpus = htons((uint16_t)lcpus);
  }
  else
  {
    if (strcmp(argv[1], "clear") == 0)
      value0 = CLEAR;
    else
      value0 = LEAVE;
  }

  if (1)
  {
    set_grid_tlv_GridSubCluster_SubClusterCalendar(gn_subcluster, value0, (void *) sc_cal);

    if (OspfGRID.status == enabled)
      if (gn->area != NULL)
      {
        if (gn_subcluster->base.flags & GRIDFLG_GRID_LSA_ENGAGED)
        {
          ospf_grid_subcluster_lsa_schedule (gn_subcluster, GRID_REFRESH_THIS_LSA);
          zlog_debug("[DBG] ospf_grid_subcluster_lsa_schedule (gn_subcluster, GRID_REFRESH_THIS_LSA)");
        }
        else
        {
          ospf_grid_subcluster_lsa_schedule (gn_subcluster, GRID_REORIGINATE_PER_AREA);
          zlog_debug("[DBG] ospf_grid_subcluster_lsa_schedule (gn_subcluster, GRID_REORIGINATE_PER_AREA)");
        }
      }
  }
  return CMD_SUCCESS;
}
DEFUN(set_cli_grid_tlv_GridSubCluster_SoftwarePackage,
      set_cli_grid_tlv_GridSubCluster_SoftwarePackage_cmd,
      "subcluster ID software_package (add|clear|skip) [SOFT_TYPE] [SOFT_VERSION] [ENVIRONMENT_SETUP]",
      "Grid SubCluster Property TLV\n"
      "Grid SubCluster ID uint32_t\n"
      "Software Package\n"
      "Software Type\n"
      "Software Version\n"
      "Environment Setup\n")
{
  struct grid_node             *gn = (struct grid_node *) vty->index;
  struct grid_node_subcluster  *gn_subcluster;

  if ((gn_subcluster = lookup_grid_node_subcluster_by_grid_node_and_sub_id(gn, strtoul(argv[0], NULL, 0)))==NULL)
  {
    vty_out (vty, "no storage element with ID %d, add new storage before%s", (uint32_t) strtoul(argv[0], NULL, 0), VTY_NEWLINE);
    return CMD_WARNING;
  }

  if (strcmp(argv[1], "add") == 0)
  {
    unsigned int value0;
    if (sscanf (argv[2], "%u", &value0) != 1)
    {
      vty_out (vty, "set_cli_grid_tlv_GridSubCluster_SoftwarePackage: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
      return CMD_WARNING;
    }
    unsigned int value1;
    if (sscanf (argv[3], "%u", &value1) != 1)
    {
      vty_out (vty, "set_cli_grid_tlv_GridSubCluster_SoftwarePackage: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
      return CMD_WARNING;
    }
    struct grid_tlv_GridSubCluster_SoftwarePackage *sp= create_grid_tlv_GridSubCluster_SoftwarePackage((uint16_t) value0, (uint16_t) value1, argv[4]);
    set_grid_tlv_GridSubCluster_SoftwarePackage(gn_subcluster, ADD, sp);
  }
  else
  {
    if (strcmp(argv[1], "clear") == 0)
      set_grid_tlv_GridSubCluster_SoftwarePackage(gn_subcluster, CLEAR , NULL);
    else
      set_grid_tlv_GridSubCluster_SoftwarePackage(gn_subcluster, LEAVE , NULL);
  }

  if (OspfGRID.status == enabled)
  {
    if (gn->area != NULL)
    {
      if (gn_subcluster->base.flags & GRIDFLG_GRID_LSA_ENGAGED)
      {
        ospf_grid_subcluster_lsa_schedule (gn_subcluster, GRID_REFRESH_THIS_LSA);
        zlog_debug("[DBG] ospf_grid_subcluster_lsa_schedule (gn_subcluster, GRID_REFRESH_THIS_LSA)");
      }
      else
      {
        ospf_grid_subcluster_lsa_schedule (gn_subcluster, GRID_REORIGINATE_PER_AREA);
        zlog_debug("[DBG] ospf_grid_subcluster_lsa_schedule (gn_subcluster, GRID_REORIGINATE_PER_AREA)");
      }
    }
  }
  return CMD_SUCCESS;
}
DEFUN(set_cli_grid_tlv_GridSubCluster_MemoryInfo,
      set_cli_grid_tlv_GridSubCluster_MemoryInfo_cmd,
      "subcluster ID memory_info RAM_SIZE VIRTUAL_MEMORY_SIZE",
      "Grid SubCluster Property TLV\n"
      "Grid SubCluster ID uint32_t\n"
      "The amount of RAM and Virtual Memory (in MB)\n"
      "RAM Size in MB\n"
      "Virtual Memory Size in MB\n")
{
  struct grid_node             *gn = (struct grid_node *) vty->index;
  struct grid_node_subcluster  *gn_subcluster;

  if ((gn_subcluster = lookup_grid_node_subcluster_by_grid_node_and_sub_id(gn, strtoul(argv[0], NULL, 0)))==NULL)
  {
    vty_out (vty, "no storage element with ID %d, add new storage before%s", (uint32_t) strtoul(argv[0], NULL, 0), VTY_NEWLINE);
    return CMD_WARNING;
  }

  long unsigned int value0;
  if (sscanf (argv[1], "%lu", &value0) != 1)
  {
    vty_out (vty, "set_cli_grid_tlv_GridSubCluster_MemoryInfo: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
    return CMD_WARNING;
  }
  long unsigned int value1;
  if (sscanf (argv[2], "%lu", &value1) != 1)
  {
    vty_out (vty, "set_cli_grid_tlv_GridSubCluster_MemoryInfo: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
    return CMD_WARNING;
  }

  if ((ntohs(gn_subcluster->gridSubcluster.memoryInfo.header.type) == 0)
     ||(ntohl(gn_subcluster->gridSubcluster.memoryInfo.ramSize) != value0)
     ||(ntohl(gn_subcluster->gridSubcluster.memoryInfo.virtualMemorySize) != value1))
  {
    set_grid_tlv_GridSubCluster_MemoryInfo(gn_subcluster,(uint32_t) value0,(uint32_t) value1);

    if (OspfGRID.status == enabled)
    {
      if (gn->area != NULL)
      {
        if (gn_subcluster->base.flags & GRIDFLG_GRID_LSA_ENGAGED)
        {
          ospf_grid_subcluster_lsa_schedule (gn_subcluster, GRID_REFRESH_THIS_LSA);
          zlog_debug("[DBG] ospf_grid_subcluster_lsa_schedule (gn_subcluster, GRID_REFRESH_THIS_LSA)");
        }
        else
        {
          ospf_grid_subcluster_lsa_schedule (gn_subcluster, GRID_REORIGINATE_PER_AREA);
          zlog_debug("[DBG] ospf_grid_subcluster_lsa_schedule (gn_subcluster, GRID_REORIGINATE_PER_AREA)");
        }
      }
    }
  }
  return CMD_SUCCESS;
}
DEFUN(set_cli_grid_tlv_GridSubCluster_OsInfo,
      set_cli_grid_tlv_GridSubCluster_OsInfo_cmd,
      "subcluster ID os_info OS_TYPE OS_VERSION",
      "Grid SubCluster Property TLV\n"
      "Grid SubCluster ID uint32_t\n"
      "Information about the type of the OS and its version\n"
      "OS Type\n"
      "OS Version\n")
{
  struct grid_node             *gn = (struct grid_node *) vty->index;
  struct grid_node_subcluster  *gn_subcluster;

  if ((gn_subcluster = lookup_grid_node_subcluster_by_grid_node_and_sub_id(gn, strtoul(argv[0], NULL, 0)))==NULL)
  {
    vty_out (vty, "no storage element with ID %d, add new storage before%s", (uint32_t) strtoul(argv[0], NULL, 0), VTY_NEWLINE);
    return CMD_WARNING;
  }

  unsigned int value0;
  if (sscanf (argv[1], "%u", &value0) != 1)
  {
    vty_out (vty, "set_cli_grid_tlv_GridSubCluster_OsInfo: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
    return CMD_WARNING;
  }
  unsigned int value1;
  if (sscanf (argv[2], "%u", &value1) != 1)
  {
    vty_out (vty, "set_cli_grid_tlv_GridSubCluster_OsInfo: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
    return CMD_WARNING;
  }

  if ((ntohs(gn_subcluster->gridSubcluster.osInfo.header.type) == 0)
     ||(ntohs(gn_subcluster->gridSubcluster.osInfo.osType) != value0)
     ||(ntohs(gn_subcluster->gridSubcluster.osInfo.osVersion) != value1))
  {
    set_grid_tlv_GridSubCluster_OsInfo(gn_subcluster,(uint16_t) value0,(uint16_t) value1);

    if (OspfGRID.status == enabled)
      if (gn->area != NULL)
      {
        if (gn_subcluster->base.flags & GRIDFLG_GRID_LSA_ENGAGED)
        {
          ospf_grid_subcluster_lsa_schedule (gn_subcluster, GRID_REFRESH_THIS_LSA);
          zlog_debug("[DBG] ospf_grid_subcluster_lsa_schedule (gn_subcluster, GRID_REFRESH_THIS_LSA)");
        }
        else
        {
          ospf_grid_subcluster_lsa_schedule (gn_subcluster, GRID_REORIGINATE_PER_AREA);
          zlog_debug("[DBG] ospf_grid_subcluster_lsa_schedule (gn_subcluster, GRID_REORIGINATE_PER_AREA)");
        }
      }
  }
  return CMD_SUCCESS;
}
DEFUN(set_cli_grid_tlv_GridSubCluster_CpuInfo,
      set_cli_grid_tlv_GridSubCluster_CpuInfo_cmd,
      "subcluster ID cpu_info PHYSICAL_CPUS LOGICAL_CPUS CPU_ARCH",
      "Grid SubCluster Property TLV\n"
      "Grid SubCluster ID uint32_t\n"
      "The CPU architecture, the total and the effective number of CPUs\n"
      "Total number of CPUs\n"
      "Effective number of CPUs\n"
      "The CPU architecture\n")
{
  struct grid_node             *gn = (struct grid_node *) vty->index;
  struct grid_node_subcluster  *gn_subcluster;

  if ((gn_subcluster = lookup_grid_node_subcluster_by_grid_node_and_sub_id(gn, strtoul(argv[0], NULL, 0)))==NULL)
  {
    vty_out (vty, "no storage element with ID %d, add new storage before%s", (uint32_t) strtoul(argv[0], NULL, 0), VTY_NEWLINE);
    return CMD_WARNING;
  }

  long unsigned int value0;
  if (sscanf (argv[1], "%lu", &value0) != 1)
  {
    vty_out (vty, "set_cli_grid_tlv_GridSubCluster_CpuInfo: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
    return CMD_WARNING;
  }
  long unsigned int value1;
  if (sscanf (argv[2], "%lu", &value1) != 1)
  {
    vty_out (vty, "set_cli_grid_tlv_GridSubCluster_CpuInfo: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
    return CMD_WARNING;
  }
  unsigned int  value2;
  if (sscanf (argv[3], "%u", &value2) != 1)
  {
    vty_out (vty, "set_cli_grid_tlv_GridSubCluster_CpuInfo: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
    return CMD_WARNING;
  }

  if ((ntohs(gn_subcluster->gridSubcluster.cpuInfo.header.type) == 0)
     ||(ntohl(gn_subcluster->gridSubcluster.cpuInfo.physicalCpus) != value0)
     ||(ntohl(gn_subcluster->gridSubcluster.cpuInfo.logicalCpus) != value1)
     ||((gn_subcluster->gridSubcluster.cpuInfo.cpuArch) != (char) value2))
  {
    set_grid_tlv_GridSubCluster_CpuInfo(gn_subcluster,(uint32_t) value0,(uint32_t) value1,(uint8_t) value2);

    if (OspfGRID.status == enabled)
      if (gn->area != NULL)
      {
        if (gn_subcluster->base.flags & GRIDFLG_GRID_LSA_ENGAGED)
        {
          ospf_grid_subcluster_lsa_schedule (gn_subcluster, GRID_REFRESH_THIS_LSA);
          zlog_debug("[DBG] ospf_grid_subcluster_lsa_schedule (gn_subcluster, GRID_REFRESH_THIS_LSA)");
        }
        else
        {
          ospf_grid_subcluster_lsa_schedule (gn_subcluster, GRID_REORIGINATE_PER_AREA);
          zlog_debug("[DBG] ospf_grid_subcluster_lsa_schedule (gn_subcluster, GRID_REORIGINATE_PER_AREA)");
        }
      }
  }
  return CMD_SUCCESS;
}
DEFUN(set_cli_grid_tlv_GridSubCluster_ParentSiteID,
      set_cli_grid_tlv_GridSubCluster_ParentSiteID_cmd,
      "subcluster ID parent_site_id PARENT_SITE_ID",
      "Grid SubCluster Property TLV\n"
      "Grid SubCluster ID uint32_t\n"
      "Identifier of the Grid Site that is exporting this sub-cluster\n"
      "Identifier of the Grid Site\n")
{
  struct grid_node             *gn = (struct grid_node *) vty->index;
  struct grid_node_subcluster  *gn_subcluster;

  if ((gn_subcluster = lookup_grid_node_subcluster_by_grid_node_and_sub_id(gn, strtoul(argv[0], NULL, 0)))==NULL)
  {
    vty_out (vty, "no storage element with ID %d, add new storage before%s", (uint32_t) strtoul(argv[0], NULL, 0), VTY_NEWLINE);
    return CMD_WARNING;
  }

  long unsigned int value0;
  if (sscanf (argv[1], "%lu", &value0) != 1)
  {
    vty_out (vty, "set_cli_grid_tlv_GridSubCluster_ParentSiteID: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
    return CMD_WARNING;
  }

  if ((ntohs(gn_subcluster->gridSubcluster.parentSiteId.header.type) == 0)
     ||(ntohl(gn_subcluster->gridSubcluster.parentSiteId.parSiteId) != value0))
  {
    set_grid_tlv_GridSubCluster_ParentSiteID(gn_subcluster,(uint32_t) value0);

    if (OspfGRID.status == enabled)
      if (gn->area != NULL)
      {
        if (gn_subcluster->base.flags & GRIDFLG_GRID_LSA_ENGAGED)
        {
          ospf_grid_subcluster_lsa_schedule (gn_subcluster, GRID_REFRESH_THIS_LSA);
          zlog_debug("[DBG] ospf_grid_subcluster_lsa_schedule (gn_subcluster, GRID_REFRESH_THIS_LSA)");
        }
        else
        {
          ospf_grid_subcluster_lsa_schedule (gn_subcluster, GRID_REORIGINATE_PER_AREA);
          zlog_debug("[DBG] ospf_grid_subcluster_lsa_schedule (gn_subcluster, GRID_REORIGINATE_PER_AREA)");
        }
      }
  }
  return CMD_SUCCESS;
}
DEFUN(set_cli_grid_tlv_GridSubCluster_ID,
      set_cli_grid_tlv_GridSubCluster_ID_cmd,
      "subcluster add ID",
      "Grid SubCluster Property TLV\n"
      "Add new Sub-Cluster\n"
      "Identifier of the new Sub-Cluster\n")
{
  struct grid_node             *gn = (struct grid_node *) vty->index;
  struct grid_node_subcluster  *gn_subcluster;

  long unsigned int value0;
  if (sscanf (argv[0], "%lu", &value0) != 1)
  {
    vty_out (vty, "set_cli_grid_tlv_GridStorage_ID: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
    return CMD_WARNING;
  }

  if ((gn_subcluster = lookup_grid_node_subcluster_by_grid_node_and_sub_id(gn, value0))==NULL)
  {
    gn_subcluster = create_new_grid_node_subcluster(gn, value0);
    listnode_add(gn->list_of_grid_node_subcluster, gn_subcluster);
  }
  else
  {
    vty_out (vty, "Alredy exists!%s", VTY_NEWLINE);
    return CMD_WARNING;
  }
  if (OspfGRID.status == enabled)
  {
    if (gn->area != NULL)
    {
      ospf_grid_subcluster_lsa_schedule (gn_subcluster, GRID_REORIGINATE_PER_AREA);
      zlog_debug("[DBG] ospf_grid_subcluster_lsa_schedule (gn_subcluster, GRID_REORIGINATE_PER_AREA)");
    }
  }
  return CMD_SUCCESS;
}

DEFUN(set_cli_grid_tlv_GridComputingElement_Name,
      set_cli_grid_tlv_GridComputingElement_Name_cmd,
      "computing ID name NAME",
      "Grid Computing Element Property TLV\n"
      "Grid Computing Element ID uint32_t\n"
      "Human-readable name\n"
      "Name (string)\n")
{
  struct grid_node            *gn = (struct grid_node *) vty->index;
  struct grid_node_computing  *gn_computing;

  if ((gn_computing = lookup_grid_node_computing_by_grid_node_and_sub_id (gn, strtoul(argv[0], NULL, 0)))==NULL)
  {
    vty_out (vty, "no computing element with ID %d, add new command before%s", (uint32_t) strtoul(argv[0], NULL, 0), VTY_NEWLINE);
    return CMD_WARNING;
  }

  if (1)
  {
    set_grid_tlv_GridComputingElement_Name(gn_computing, argv[1]);
    if (OspfGRID.status == enabled)
      if (gn->area != NULL)
      {
        if (gn_computing->base.flags & GRIDFLG_GRID_LSA_ENGAGED)
        {
          ospf_grid_computing_lsa_schedule (gn_computing, GRID_REFRESH_THIS_LSA);
          zlog_debug("[DBG] ospf_grid_computing_lsa_schedule (gn_computing, GRID_REFRESH_THIS_LSA)");
        }
        else
        {
          ospf_grid_computing_lsa_schedule (gn_computing, GRID_REORIGINATE_PER_AREA);
          zlog_debug("[DBG] ospf_grid_computing_lsa_schedule (gn_computing, GRID_REORIGINATE_PER_AREA)");
        }
      }
  }
  return CMD_SUCCESS;
}

DEFUN(set_cli_grid_tlv_GridComputingElement_CeCalendar,
      set_cli_grid_tlv_GridComputingElement_CeCalendar_cmd,
      "computing ID ce_calendar (add|clear|skip) [TIME] [FREE_JOB_SLOTS]",
      "Grid Computing Element Property TLV\n"
      "Grid Computing Element ID uint32_t\n"
      "The jobs scheduling calendar reporting the available FreeJobsSlots for each timestamp\n"
      "Add new element to the list\n"
      "Clear the list\n"
      "Skip the list modiffication\n"
      "New timestamp\n"
      "New Free Job Slots\n")
{
  struct grid_node            *gn = (struct grid_node *) vty->index;
  struct grid_node_computing  *gn_computing;

  if ((gn_computing = lookup_grid_node_computing_by_grid_node_and_sub_id (gn, strtoul(argv[0], NULL, 0)))==NULL)
  {
    vty_out (vty, "no storage element with ID %d, add new storage before%s", (uint32_t) strtoul(argv[0], NULL, 0), VTY_NEWLINE);
    return CMD_WARNING;
  }


  enum list_opcode value0;
  struct ce_calendar* ce_cal = NULL;
  if (strcmp(argv[1], "add") == 0)
  {
    value0 = ADD;
    ce_cal = XMALLOC (MTYPE_OSPF_GRID_COMPUTING_CALENDAR, sizeof(struct ce_calendar));
    unsigned int time;
    unsigned int freeJobSlots;
    if (argc <= 1)
    {
      vty_out (vty, "Please write value to add to the list%s", VTY_NEWLINE);
      return CMD_WARNING;   
    }
    if (sscanf (argv[2], "%u", &time) != 1)
    {
      vty_out (vty, "set_cli_grid_tlv_GridComputingElement_CeCalendar: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
      return CMD_WARNING;
    }
    ce_cal->time = htonl((uint32_t)time);
    if (sscanf (argv[3], "%u", &freeJobSlots) != 1)
    {
      vty_out (vty, "set_cli_grid_tlv_GridComputingElement_CeCalendar: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
      return CMD_WARNING;
    }
    ce_cal->freeJobSlots = htons((uint16_t)freeJobSlots);
  }
  else
  {
    if (strcmp(argv[1], "clear") == 0)
      value0 = CLEAR;
    else
      value0 = LEAVE;
  }

  if (1)
  {
    set_grid_tlv_GridComputingElement_CeCalendar(gn_computing, value0, (void *) ce_cal);

    if (OspfGRID.status == enabled)
      if (gn->area != NULL)
      {
        if (gn_computing->base.flags & GRIDFLG_GRID_LSA_ENGAGED)
        {
          ospf_grid_computing_lsa_schedule (gn_computing, GRID_REFRESH_THIS_LSA);
          zlog_debug("[DBG] ospf_grid_computing_lsa_schedule (gn_computing, GRID_REFRESH_THIS_LSA)");
        }
        else
        {
          ospf_grid_computing_lsa_schedule (gn_computing, GRID_REORIGINATE_PER_AREA);
          zlog_debug("[DBG] ospf_grid_computing_lsa_schedule (gn_computing, GRID_REORIGINATE_PER_AREA)");
        }
      }
  }
  return CMD_SUCCESS;
}
DEFUN(set_cli_grid_tlv_GridComputingElement_JobsLoadPolicy,
      set_cli_grid_tlv_GridComputingElement_JobsLoadPolicy_cmd,
      "computing ID jobs_load_policy MAX_TOTAL_JOBS MAX_RUN_JOBS MAX_WAIT_JOBS ASSIGN_JOB_SLOTS MAX_SLOTS_PER_JOB PRIORITY PREEMPTION_FLAG",
      "Grid Computing Element Property TLV\n"
      "Grid Computing Element ID uint32_t\n"
      "Jobs Load Policy\n"
      "The maximum allowed number of jobs in the CE\n"
      "The maximum allowed number of jobs in running state in the CE\n"
      "The maximum allowed number of jobs in waiting state in the CE\n"
      "Number of slots for jobs to be in running state\n"
      "The maximum number of slots per single job\n"
      "The jobs priority (7 bits)\n"
      "The pre-emption flag (1 bit)\n")
{
  struct grid_node            *gn = (struct grid_node *) vty->index;
  struct grid_node_computing  *gn_computing;

  if ((gn_computing = lookup_grid_node_computing_by_grid_node_and_sub_id(gn, strtoul(argv[0], NULL, 0)))==NULL)
  {
    vty_out (vty, "no computing element with ID %d, add new computing before%s", (uint32_t) strtoul(argv[0], NULL, 0), VTY_NEWLINE);
    return CMD_WARNING;
  }


  long unsigned int value0;
  if (sscanf (argv[1], "%lu", &value0) != 1)
  {
    vty_out (vty, "set_cli_grid_tlv_GridComputingElement_JobsLoadPolicy: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
    return CMD_WARNING;
  }
  long unsigned int value1;
  if (sscanf (argv[2], "%lu", &value1) != 1)
  {
    vty_out (vty, "set_cli_grid_tlv_GridComputingElement_JobsLoadPolicy: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
    return CMD_WARNING;
  }
  long unsigned int value2;
  if (sscanf (argv[3], "%lu", &value2) != 1)
  {
    vty_out (vty, "set_cli_grid_tlv_GridComputingElement_JobsLoadPolicy: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
    return CMD_WARNING;
  }
  unsigned int value3;
  if (sscanf (argv[4], "%u", &value3) != 1)
  {
    vty_out (vty, "set_cli_grid_tlv_GridComputingElement_JobsLoadPolicy: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
    return CMD_WARNING;
  }
  unsigned int value4;
  if (sscanf (argv[5], "%u", &value4) != 1)
  {
    vty_out (vty, "set_cli_grid_tlv_GridComputingElement_JobsLoadPolicy: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
    return CMD_WARNING;
  }
  unsigned int temp;
  unsigned int  value5;
  if (sscanf (argv[6], "%u", &value5) != 1)
  {
    vty_out (vty, "set_cli_grid_tlv_GridComputingElement_JobsLoadPolicy: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
    return CMD_WARNING;
  }
  if (sscanf (argv[7], "%u", &temp) != 1)
  {
    vty_out (vty, "set_cli_grid_tlv_GridComputingElement_JobsLoadPolicy: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
    return CMD_WARNING;
  }

  value5 <<= 1;
  value5 |= temp;

  if ((ntohs(gn_computing->gridCompElement.jobsLoadPolicy.header.type) == 0)
     ||(ntohl(gn_computing->gridCompElement.jobsLoadPolicy.maxTotalJobs) != value0)
     ||(ntohl(gn_computing->gridCompElement.jobsLoadPolicy.maxRunJobs) != value1)
     ||(ntohl(gn_computing->gridCompElement.jobsLoadPolicy.maxWaitJobs) != value2)
     ||(ntohs(gn_computing->gridCompElement.jobsLoadPolicy.assignJobSlots) != value3)
     ||(ntohs(gn_computing->gridCompElement.jobsLoadPolicy.maxSlotsPerJob) != value4)
     ||((gn_computing->gridCompElement.jobsLoadPolicy.priorityPreemptionFlag) != (char) value5))
  {
    set_grid_tlv_GridComputingElement_JobsLoadPolicy(gn_computing,(uint32_t) value0,(uint32_t) value1,(uint32_t) value2,(uint16_t) value3,(uint16_t) value4,(uint8_t) value5);

    if (OspfGRID.status == enabled)
      if (gn->area != NULL)
      {
        if (gn_computing->base.flags & GRIDFLG_GRID_LSA_ENGAGED)
        {
          ospf_grid_computing_lsa_schedule (gn_computing, GRID_REFRESH_THIS_LSA);
          zlog_debug("[DBG] ospf_grid_computing_lsa_schedule (gn_computing, GRID_REFRESH_THIS_LSA)");
        }
        else
        {
          ospf_grid_computing_lsa_schedule (gn_computing, GRID_REORIGINATE_PER_AREA);
          zlog_debug("[DBG] ospf_grid_computing_lsa_schedule (gn_computing, GRID_REORIGINATE_PER_AREA)");
        }
      }
  }
  return CMD_SUCCESS;
}
DEFUN(set_cli_grid_tlv_GridComputingElement_JobsTimePolicy,
      set_cli_grid_tlv_GridComputingElement_JobsTimePolicy_cmd,
      "computing ID jobs_time_policy MAX_WC_TIME MAX_OBT_WC_TIME MAX_CPU_TIME MAX_OBT_CPU_TIME",
      "Grid Computing Element Property TLV\n"
      "Grid Computing Element ID uint32_t\n"
      "The maximum wall clock time, the maximum obtainable wall clock time, the default maximum CPU time allowed to each job by the batch system and finally the maximum obtainable CPU time that can be granted to the job upon user request\n"
      "The default maximum wall clock time\n"
      "The maximum obtainable wall clock time\n"
      "The default maximum CPU time\n"
      "The maximum obtainable CPU time\n")
{
  struct grid_node            *gn = (struct grid_node *) vty->index;
  struct grid_node_computing  *gn_computing;

  if ((gn_computing = lookup_grid_node_computing_by_grid_node_and_sub_id(gn, strtoul(argv[0], NULL, 0)))==NULL)
  {
    vty_out (vty, "no computing element with ID %d, add new computing before%s", (uint32_t) strtoul(argv[0], NULL, 0), VTY_NEWLINE);
    return CMD_WARNING;
  }

  long unsigned int value0;
  if (sscanf (argv[1], "%lu", &value0) != 1)
  {
    vty_out (vty, "set_cli_grid_tlv_GridComputingElement_JobsTimePolicy: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
    return CMD_WARNING;
  }
  long unsigned int value1;
  if (sscanf (argv[2], "%lu", &value1) != 1)
  {
    vty_out (vty, "set_cli_grid_tlv_GridComputingElement_JobsTimePolicy: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
    return CMD_WARNING;
  }
  long unsigned int value2;
  if (sscanf (argv[3], "%lu", &value2) != 1)
  {
    vty_out (vty, "set_cli_grid_tlv_GridComputingElement_JobsTimePolicy: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
    return CMD_WARNING;
  }
  long unsigned int value3;
  if (sscanf (argv[4], "%lu", &value3) != 1)
  {
    vty_out (vty, "set_cli_grid_tlv_GridComputingElement_JobsTimePolicy: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
    return CMD_WARNING;
  }

  if ((ntohs(gn_computing->gridCompElement.jobsTimePolicy.header.type) == 0)
     ||(ntohl(gn_computing->gridCompElement.jobsTimePolicy.maxWcTime) != value0)
     ||(ntohl(gn_computing->gridCompElement.jobsTimePolicy.maxObtWcTime) != value1)
     ||(ntohl(gn_computing->gridCompElement.jobsTimePolicy.maxCpuTime) != value2)
     ||(ntohl(gn_computing->gridCompElement.jobsTimePolicy.maxObtCpuTime) != value3))
  {
    set_grid_tlv_GridComputingElement_JobsTimePolicy(gn_computing,(uint32_t) value0,(uint32_t) value1,(uint32_t) value2,(uint32_t) value3);

    if (OspfGRID.status == enabled)
      if (gn->area != NULL)
      {
        if (gn_computing->base.flags & GRIDFLG_GRID_LSA_ENGAGED)
        {
          ospf_grid_computing_lsa_schedule (gn_computing, GRID_REFRESH_THIS_LSA);
          zlog_debug("[DBG] ospf_grid_computing_lsa_schedule (gn_computing, GRID_REFRESH_THIS_LSA)");
        }
        else
        {
          ospf_grid_computing_lsa_schedule (gn_computing, GRID_REORIGINATE_PER_AREA);
          zlog_debug("[DBG] ospf_grid_computing_lsa_schedule (gn_computing, GRID_REORIGINATE_PER_AREA)");
        }
      }
  }
  return CMD_SUCCESS;
}
DEFUN(set_cli_grid_tlv_GridComputingElement_JobsTimePerformances,
      set_cli_grid_tlv_GridComputingElement_JobsTimePerformances_cmd,
      "computing ID jobs_time_performances EST_RESP_TIME WORST_RESP_TIME",
      "Grid Computing Element Property TLV\n"
      "Grid Computing Element ID uint32_t\n"
      "The estimated time and the worst time to last for a new job from the acceptance to the start of its execution\n"
      "Estimated response time\n"
      "Worst response time\n")
{
  struct grid_node            *gn = (struct grid_node *) vty->index;
  struct grid_node_computing  *gn_computing;

  if ((gn_computing = lookup_grid_node_computing_by_grid_node_and_sub_id(gn, strtoul(argv[0], NULL, 0)))==NULL)
  {
    vty_out (vty, "no computing element with ID %d, add new computing before%s", (uint32_t) strtoul(argv[0], NULL, 0), VTY_NEWLINE);
    return CMD_WARNING;
  }

  long unsigned int value0;
  if (sscanf (argv[1], "%lu", &value0) != 1)
  {
    vty_out (vty, "set_cli_grid_tlv_GridComputingElement_JobsTimePerformances: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
    return CMD_WARNING;
  }
  long unsigned int value1;
  if (sscanf (argv[2], "%lu", &value1) != 1)
  {
    vty_out (vty, "set_cli_grid_tlv_GridComputingElement_JobsTimePerformances: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
    return CMD_WARNING;
  }

  if ((ntohs(gn_computing->gridCompElement.jobsTimePerformances.header.type) == 0)
     ||(ntohl(gn_computing->gridCompElement.jobsTimePerformances.estRespTime) != value0)
     ||(ntohl(gn_computing->gridCompElement.jobsTimePerformances.worstRespTime) != value1))
  {
    set_grid_tlv_GridComputingElement_JobsTimePerformances(gn_computing,(uint32_t) value0,(uint32_t) value1);

    if (OspfGRID.status == enabled)
      if (gn->area != NULL)
      {
        if (gn_computing->base.flags & GRIDFLG_GRID_LSA_ENGAGED)
        {
          ospf_grid_computing_lsa_schedule (gn_computing, GRID_REFRESH_THIS_LSA);
          zlog_debug("[DBG] ospf_grid_computing_lsa_schedule (gn_computing, GRID_REFRESH_THIS_LSA)");
        }
        else
        {
          ospf_grid_computing_lsa_schedule (gn_computing, GRID_REORIGINATE_PER_AREA);
          zlog_debug("[DBG] ospf_grid_computing_lsa_schedule (gn_computing, GRID_REORIGINATE_PER_AREA)");
        }
      }
  }
  return CMD_SUCCESS;
}
DEFUN(set_cli_grid_tlv_GridComputingElement_JobsStats,
      set_cli_grid_tlv_GridComputingElement_JobsStats_cmd,
      "computing ID jobs_stats RUNNING_JOBS WAITING_JOBS TOTAL_JOBS",
      "Grid Computing Element Property TLV\n"
      "Grid Computing Element ID uint32_t\n"
      "It contains the number of jobs in running, waiting, any state\n"
      "Number of jobs in running state\n"
      "Number of jobs in waiting state\n"
      "Number of jobs in any state\n")
{
  struct grid_node            *gn = (struct grid_node *) vty->index;
  struct grid_node_computing  *gn_computing;

  if ((gn_computing = lookup_grid_node_computing_by_grid_node_and_sub_id(gn, strtoul(argv[0], NULL, 0)))==NULL)
  {
    vty_out (vty, "no computing element with ID %d, add new computing before%s", (uint32_t) strtoul(argv[0], NULL, 0), VTY_NEWLINE);
    return CMD_WARNING;
  }

  long unsigned int value0;
  if (sscanf (argv[1], "%lu", &value0) != 1)
  {
    vty_out (vty, "set_cli_grid_tlv_GridComputingElement_JobsStats: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
    return CMD_WARNING;
  }
  long unsigned int value1;
  if (sscanf (argv[2], "%lu", &value1) != 1)
  {
    vty_out (vty, "set_cli_grid_tlv_GridComputingElement_JobsStats: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
    return CMD_WARNING;
  }
  long unsigned int value2;
  if (sscanf (argv[3], "%lu", &value2) != 1)
  {
    vty_out (vty, "set_cli_grid_tlv_GridComputingElement_JobsStats: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
    return CMD_WARNING;
  }

  if ((ntohs(gn_computing->gridCompElement.jobsStats.header.type) == 0)
     ||(ntohl(gn_computing->gridCompElement.jobsStats.runningJobs) != value0)
     ||(ntohl(gn_computing->gridCompElement.jobsStats.waitingJobs) != value1)
     ||(ntohl(gn_computing->gridCompElement.jobsStats.totalJobs) != value2))
  {
    set_grid_tlv_GridComputingElement_JobsStats(gn_computing,(uint32_t) value0,(uint32_t) value1,(uint32_t) value2);

    if (OspfGRID.status == enabled)
      if (gn->area != NULL)
      {
        if (gn_computing->base.flags & GRIDFLG_GRID_LSA_ENGAGED)
        {
          ospf_grid_computing_lsa_schedule (gn_computing, GRID_REFRESH_THIS_LSA);
          zlog_debug("[DBG] ospf_grid_computing_lsa_schedule (gn_computing, GRID_REFRESH_THIS_LSA)");
        }
        else
        {
          ospf_grid_computing_lsa_schedule (gn_computing, GRID_REORIGINATE_PER_AREA);
          zlog_debug("[DBG] ospf_grid_computing_lsa_schedule (gn_computing, GRID_REORIGINATE_PER_AREA)");
        }
      }
  }
  return CMD_SUCCESS;
}
DEFUN(set_cli_grid_tlv_GridComputingElement_JobsStates,
      set_cli_grid_tlv_GridComputingElement_JobsStates_cmd,
      "computing ID jobs_states FREE_JOB_SLOTS STATUS",
      "Grid Computing Element Property TLV\n"
      "Grid Computing Element ID uint32_t\n"
      "It contains the number of free job slots, and the queue status\n"
      "The number of free job slots\n"
      "Status\n")
{
  struct grid_node            *gn = (struct grid_node *) vty->index;
  struct grid_node_computing  *gn_computing;

  if ((gn_computing = lookup_grid_node_computing_by_grid_node_and_sub_id(gn, strtoul(argv[0], NULL, 0)))==NULL)
  {
    vty_out (vty, "no computing element with ID %d, add new computing before%s", (uint32_t) strtoul(argv[0], NULL, 0), VTY_NEWLINE);
    return CMD_WARNING;
  }

  unsigned int value0;
  if (sscanf (argv[1], "%u", &value0) != 1)
  {
    vty_out (vty, "set_cli_grid_tlv_GridComputingElement_JobsStates: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
    return CMD_WARNING;
  }
  unsigned int  value1;
  if (sscanf (argv[2], "%u", &value1) != 1)
  {
    vty_out (vty, "set_cli_grid_tlv_GridComputingElement_JobsStates: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
    return CMD_WARNING;
  }

  if ((ntohs(gn_computing->gridCompElement.jobsStates.header.type) == 0)
     ||(ntohs(gn_computing->gridCompElement.jobsStates.freeJobSlots) != value0)
     ||((gn_computing->gridCompElement.jobsStates.status) != (char) value1))
  {
    set_grid_tlv_GridComputingElement_JobsStates(gn_computing,(uint16_t) value0,(uint8_t) value1);

    if (OspfGRID.status == enabled)
      if (gn->area != NULL)
      {
        if (gn_computing->base.flags & GRIDFLG_GRID_LSA_ENGAGED)
        {
          ospf_grid_computing_lsa_schedule (gn_computing, GRID_REFRESH_THIS_LSA);
          zlog_debug("[DBG] ospf_grid_computing_lsa_schedule (gn_computing, GRID_REFRESH_THIS_LSA)");
        }
        else
        {
          ospf_grid_computing_lsa_schedule (gn_computing, GRID_REORIGINATE_PER_AREA);
          zlog_debug("[DBG] ospf_grid_computing_lsa_schedule (gn_computing, GRID_REORIGINATE_PER_AREA)");
        }
      }
  }
  return CMD_SUCCESS;
}
DEFUN(set_cli_grid_tlv_GridComputingElement_DefaultStorageElement,
      set_cli_grid_tlv_GridComputingElement_DefaultStorageElement_cmd,
      "computing ID default_se DEFAULT_SE",
      "Grid Computing Element Property TLV\n"
      "Grid Computing Element ID uint32_t\n"
      "The unique identifier of the default Storage Element\n"
      "The unique identifier of the default Storage Element\n")
{
  struct grid_node            *gn = (struct grid_node *) vty->index;
  struct grid_node_computing  *gn_computing;

  if ((gn_computing = lookup_grid_node_computing_by_grid_node_and_sub_id(gn, strtoul(argv[0], NULL, 0)))==NULL)
  {
    vty_out (vty, "no computing element with ID %d, add new computing before%s", (uint32_t) strtoul(argv[0], NULL, 0), VTY_NEWLINE);
    return CMD_WARNING;
  }

  long unsigned int value0;
  if (sscanf (argv[1], "%lu", &value0) != 1)
  {
    vty_out (vty, "set_cli_grid_tlv_GridComputingElement_DefaultStorageElement: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
    return CMD_WARNING;
  }

  if ((ntohs(gn_computing->gridCompElement.defaultSe.header.type) == 0)
     ||(ntohl(gn_computing->gridCompElement.defaultSe.defaultSelement) != value0))
  {
    set_grid_tlv_GridComputingElement_DefaultStorageElement(gn_computing,(uint32_t) value0);

    if (OspfGRID.status == enabled)
      if (gn->area != NULL)
      {
        if (gn_computing->base.flags & GRIDFLG_GRID_LSA_ENGAGED)
        {
          ospf_grid_computing_lsa_schedule (gn_computing, GRID_REFRESH_THIS_LSA);
          zlog_debug("[DBG] ospf_grid_computing_lsa_schedule (gn_computing, GRID_REFRESH_THIS_LSA)");
        }
        else
        {
          ospf_grid_computing_lsa_schedule (gn_computing, GRID_REORIGINATE_PER_AREA);
          zlog_debug("[DBG] ospf_grid_computing_lsa_schedule (gn_computing, GRID_REORIGINATE_PER_AREA)");
        }
      }
  }
  return CMD_SUCCESS;
}
DEFUN(set_cli_grid_tlv_GridComputingElement_DataDir,
      set_cli_grid_tlv_GridComputingElement_DataDir_cmd,
      "computing ID data_dir DATA_DIR",
      "Grid Computing Element Property TLV\n"
      "Grid Computing Element ID uint32_t\n"
      "String representing the path of a run directory\n"
      "Data Dir (string)\n")
{
  struct grid_node            *gn = (struct grid_node *) vty->index;
  struct grid_node_computing  *gn_computing;

  if ((gn_computing = lookup_grid_node_computing_by_grid_node_and_sub_id(gn, strtoul(argv[0], NULL, 0)))==NULL)
  {
    vty_out (vty, "no computing element with ID %d, add new computing before%s", (uint32_t) strtoul(argv[0], NULL, 0), VTY_NEWLINE);
    return CMD_WARNING;
  }

//  if ((ntohs(gn->gridCompElement.dataDir.header.type) == 0)
//     ||(ntohl(gn->gridCompElement.dataDir.dataDirStr) != value0))
//  {
    set_grid_tlv_GridComputingElement_DataDir(gn_computing,argv[1]);

    if (OspfGRID.status == enabled)
      if (gn->area != NULL)
      {
        if (gn_computing->base.flags & GRIDFLG_GRID_LSA_ENGAGED)
        {
          ospf_grid_computing_lsa_schedule (gn_computing, GRID_REFRESH_THIS_LSA);
          zlog_debug("[DBG] ospf_grid_computing_lsa_schedule (gn_computing, GRID_REFRESH_THIS_LSA)");
        }
        else
        {
          ospf_grid_computing_lsa_schedule (gn_computing, GRID_REORIGINATE_PER_AREA);
          zlog_debug("[DBG] ospf_grid_computing_lsa_schedule (gn_computing, GRID_REORIGINATE_PER_AREA)");
        }
      }
//  }
  return CMD_SUCCESS;
}
DEFUN(set_cli_grid_tlv_GridComputingElement_JobManager,
      set_cli_grid_tlv_GridComputingElement_JobManager_cmd,
      "computing ID job_manager JOB_MANAGER",
      "Grid Computing Element Property TLV\n"
      "The job manager used by the gatekeeper\n"
      "Job Manager (string)\n")
{
  struct grid_node            *gn = (struct grid_node *) vty->index;
  struct grid_node_computing  *gn_computing;

  if ((gn_computing = lookup_grid_node_computing_by_grid_node_and_sub_id(gn, strtoul(argv[0], NULL, 0)))==NULL)
  {
    vty_out (vty, "no computing element with ID %d, add new computing before%s", (uint32_t) strtoul(argv[0], NULL, 0), VTY_NEWLINE);
    return CMD_WARNING;
  }

//  if ((ntohs(gn->gridCompElement.jobManager.header.type) == 0)
//     ||(ntohl(gn->gridCompElement.jobManager.jobManag) != value0))
//  {
    set_grid_tlv_GridComputingElement_JobManager(gn_computing,argv[1]);

    if (OspfGRID.status == enabled)
      if (gn->area != NULL)
      {
        if (gn_computing->base.flags & GRIDFLG_GRID_LSA_ENGAGED)
        {
          ospf_grid_computing_lsa_schedule (gn_computing, GRID_REFRESH_THIS_LSA);
          zlog_debug("[DBG] ospf_grid_computing_lsa_schedule (gn_computing, GRID_REFRESH_THIS_LSA)");
        }
        else
        {
          ospf_grid_computing_lsa_schedule (gn_computing, GRID_REORIGINATE_PER_AREA);
          zlog_debug("[DBG] ospf_grid_computing_lsa_schedule (gn_computing, GRID_REORIGINATE_PER_AREA)");
        }
      }
//  }
  return CMD_SUCCESS;
}
DEFUN(set_cli_grid_tlv_GridComputingElement_GatekeeperPort,
      set_cli_grid_tlv_GridComputingElement_GatekeeperPort_cmd,
      "computing ID gatekeeper_port GATEKEEPER_PORT",
      "Grid Computing Element Property TLV\n"
      "Grid Computing Element ID uint32_t\n"
      "Set gatekeeper port\n"
      "Gatekeeper port value\n")
{
  struct grid_node            *gn = (struct grid_node *) vty->index;
  struct grid_node_computing  *gn_computing;

  if ((gn_computing = lookup_grid_node_computing_by_grid_node_and_sub_id(gn, strtoul(argv[0], NULL, 0)))==NULL)
  {
    vty_out (vty, "no computing element with ID %d, add new computing before%s", (uint32_t) strtoul(argv[0], NULL, 0), VTY_NEWLINE);
    return CMD_WARNING;
  }

  long unsigned int value0;
  if (sscanf (argv[1], "%lu", &value0) != 1)
  {
    vty_out (vty, "set_cli_grid_tlv_GridComputingElement_GatekeeperPort: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
    return CMD_WARNING;
  }

  if ((ntohs(gn_computing->gridCompElement.gatekeeperPort.header.type) == 0)
     ||(ntohl(gn_computing->gridCompElement.gatekeeperPort.gateKPort) != value0))
  {
    set_grid_tlv_GridComputingElement_GatekeeperPort(gn_computing,(uint32_t) value0);

    if (OspfGRID.status == enabled)
      if (gn->area != NULL)
      {
        if (gn_computing->base.flags & GRIDFLG_GRID_LSA_ENGAGED)
        {
          ospf_grid_computing_lsa_schedule (gn_computing, GRID_REFRESH_THIS_LSA);
          zlog_debug("[DBG] ospf_grid_computing_lsa_schedule (gn_computing, GRID_REFRESH_THIS_LSA)");
        }
        else
        {
          ospf_grid_computing_lsa_schedule (gn_computing, GRID_REORIGINATE_PER_AREA);
          zlog_debug("[DBG] ospf_grid_computing_lsa_schedule (gn_computing, GRID_REORIGINATE_PER_AREA)");
        }
      }
  }
  return CMD_SUCCESS;
}
DEFUN(set_cli_grid_tlv_GridComputingElement_NsapHostName,
      set_cli_grid_tlv_GridComputingElement_NsapHostName_cmd,
      "computing ID nsap_host_name ADD_PART1 ADD_PART2 ADD_PART3 ADD_PART4 ADD_PART5",
      "Grid Computing Element Property TLV\n"
      "Grid Computing Element ID uint32_t\n"
      "Host name of the machine running this service (NSAP address)\n"
      "(32-bit Hexadecimal value; ex. a1b2c3d4) First part of the address\n"
      "(32-bit Hexadecimal value; ex. a1b2c3d4) Second part of the address\n"
      "(32-bit Hexadecimal value; ex. a1b2c3d4) Third part of the address\n"
      "(32-bit Hexadecimal value; ex. a1b2c3d4) Fourth part of the address\n"
      "(32-bit Hexadecimal value; ex. a1b2c3d4) Fifth part of the address\n"
      "<cr>\n")
{
  struct grid_node            *gn = (struct grid_node *) vty->index;
  struct grid_node_computing  *gn_computing;

  if ((gn_computing = lookup_grid_node_computing_by_grid_node_and_sub_id(gn, strtoul(argv[0], NULL, 0)))==NULL)
  {
    vty_out (vty, "no computing element with ID %d, add new computing before%s", (uint32_t) strtoul(argv[0], NULL, 0), VTY_NEWLINE);
    return CMD_WARNING;
  }

  u_int32_t nsap_address[5];

  if (sscanf (argv[1], "%x", &nsap_address[4]) != 1)
  {
    vty_out (vty, "set_cli_grid_tlv_GridComputingElement_NsapHostName: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
    return CMD_WARNING;
  }
  if (sscanf (argv[2], "%x", &nsap_address[3]) != 1)
  {
    vty_out (vty, "set_cli_grid_tlv_GridComputingElement_NsapHostName: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
    return CMD_WARNING;
  }
  if (sscanf (argv[3], "%x", &nsap_address[2]) != 1)
  {
    vty_out (vty, "set_cli_grid_tlv_GridComputingElement_NsapHostName: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
    return CMD_WARNING;
  }
  if (sscanf (argv[4], "%x", &nsap_address[1]) != 1)
  {
    vty_out (vty, "set_cli_grid_tlv_GridComputingElement_NsapHostName: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
    return CMD_WARNING;
  }
  if (sscanf (argv[5], "%x", &nsap_address[0]) != 1)
  {
    vty_out (vty, "set_cli_grid_tlv_GridComputingElement_NsapHostName: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
    return CMD_WARNING;
  }

//  if ((ntohs(gn->gridCompElement.nsapHostName.header.type) == 0)
//     ||(ntohl(gn->gridCompElement.nsapHostName.nsapHostNam) != value0))
//  {
    set_grid_tlv_GridComputingElement_NsapHostName(gn_computing,nsap_address);

    if (OspfGRID.status == enabled)
      if (gn->area != NULL)
      {
        if (gn_computing->base.flags & GRIDFLG_GRID_LSA_ENGAGED)
        {
          ospf_grid_computing_lsa_schedule (gn_computing, GRID_REFRESH_THIS_LSA);
          zlog_debug("[DBG] ospf_grid_computing_lsa_schedule (gn_computing, GRID_REFRESH_THIS_LSA)");
        }
        else
        {
          ospf_grid_computing_lsa_schedule (gn_computing, GRID_REORIGINATE_PER_AREA);
          zlog_debug("[DBG] ospf_grid_computing_lsa_schedule (gn_computing, GRID_REORIGINATE_PER_AREA)");
        }
      }
//  }
  return CMD_SUCCESS;
}
DEFUN(set_cli_grid_tlv_GridComputingElement_IPv6HostName,
      set_cli_grid_tlv_GridComputingElement_IPv6HostName_cmd,
      "computing ID ipv6_host_name IPV6_HOST_NAME",
      "Grid Computing Element Property TLV\n"
      "Grid Computing Element ID uint32_t\n"
      "Host name of the machine running this service\n"
      "IPv6 address\n")
{
  struct grid_node            *gn = (struct grid_node *) vty->index;
  struct grid_node_computing  *gn_computing;

  if ((gn_computing = lookup_grid_node_computing_by_grid_node_and_sub_id(gn, strtoul(argv[0], NULL, 0)))==NULL)
  {
    vty_out (vty, "no computing element with ID %d, add new computing before%s", (uint32_t) strtoul(argv[0], NULL, 0), VTY_NEWLINE);
    return CMD_WARNING;
  }

  struct in6_addr address;

  str2in6_addr (argv[1], &address);

//  if ((ntohs(gn->gridCompElement.ipv6HostName.header.type) == 0)
//     ||(ntohl(gn->gridCompElement.ipv6HostName.ipv6HostNam) != value0))
//  {
    set_grid_tlv_GridComputingElement_IPv6HostName(gn_computing, address);

    if (OspfGRID.status == enabled)
      if (gn->area != NULL)
      {
        if (gn_computing->base.flags & GRIDFLG_GRID_LSA_ENGAGED)
        {
          ospf_grid_computing_lsa_schedule (gn_computing, GRID_REFRESH_THIS_LSA);
          zlog_debug("[DBG] ospf_grid_computing_lsa_schedule (gn_computing, GRID_REFRESH_THIS_LSA)");
        }
        else
        {
          ospf_grid_computing_lsa_schedule (gn_computing, GRID_REORIGINATE_PER_AREA);
          zlog_debug("[DBG] ospf_grid_computing_lsa_schedule (gn_computing, GRID_REORIGINATE_PER_AREA)");
        }
      }
//  }
  return CMD_SUCCESS;
}
DEFUN(set_cli_grid_tlv_GridComputingElement_IPv4HostName,
      set_cli_grid_tlv_GridComputingElement_IPv4HostName_cmd,
      "computing ID ipv4_host_name IPV4_HOST_NAME",
      "Grid Computing Element Property TLV\n"
      "Grid Computing Element ID uint32_t\n"
      "Host name of the machine running this service\n"
      "IPv4 address\n")
{
  struct grid_node            *gn = (struct grid_node *) vty->index;
  struct grid_node_computing  *gn_computing;

  if ((gn_computing = lookup_grid_node_computing_by_grid_node_and_sub_id(gn, strtoul(argv[0], NULL, 0)))==NULL)
  {
    vty_out (vty, "no computing element with ID %d, add new computing before%s", (uint32_t) strtoul(argv[0], NULL, 0), VTY_NEWLINE);
    return CMD_WARNING;
  }

  struct in_addr address;
  if (! inet_aton (argv[1], &address))
  {
    vty_out (vty, "set_cli_grid_tlv_GridComputingElement_IPv4HostName: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
    return CMD_WARNING;
  }

//  if ((ntohs(gn->gridCompElement.ipv4HostName.header.type) == 0)
//     ||(ntohl(gn->gridCompElement.ipv4HostName.ipv4HostNam) != value0))
//  {
    set_grid_tlv_GridComputingElement_IPv4HostName(gn_computing,address);

    if (OspfGRID.status == enabled)
      if (gn->area != NULL)
      {
        if (gn_computing->base.flags & GRIDFLG_GRID_LSA_ENGAGED)
        {
          ospf_grid_computing_lsa_schedule (gn_computing, GRID_REFRESH_THIS_LSA);
          zlog_debug("[DBG] ospf_grid_computing_lsa_schedule (gn_computing, GRID_REFRESH_THIS_LSA)");
        }
        else
        {
          ospf_grid_computing_lsa_schedule (gn_computing, GRID_REORIGINATE_PER_AREA);
          zlog_debug("[DBG] ospf_grid_computing_lsa_schedule (gn_computing, GRID_REORIGINATE_PER_AREA)");
        }
      }
//  }
  return CMD_SUCCESS;
}
DEFUN(set_cli_grid_tlv_GridComputingElement_AddressLength,
      set_cli_grid_tlv_GridComputingElement_AddressLength_cmd,
      "computing ID address_length ADDRESS_LENGTH",
      "Grid Computing Element Property TLV\n"
      "Grid Computing Element ID uint32_t\n"
      "Length of the host name address\n"
      "Length of the host name address\n")
{
  struct grid_node            *gn = (struct grid_node *) vty->index;
  struct grid_node_computing  *gn_computing;

  if ((gn_computing = lookup_grid_node_computing_by_grid_node_and_sub_id(gn, strtoul(argv[0], NULL, 0)))==NULL)
  {
    vty_out (vty, "no computing element with ID %d, add new computing before%s", (uint32_t) strtoul(argv[0], NULL, 0), VTY_NEWLINE);
    return CMD_WARNING;
  }

  unsigned int value0;
  if (sscanf (argv[1], "%u", &value0) != 1)
  {
    vty_out (vty, "set_cli_grid_tlv_GridComputingElement_AddressLength: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
    return CMD_WARNING;
  }

  if ((ntohs(gn_computing->gridCompElement.addressLength.header.type) == 0)
     ||((gn_computing->gridCompElement.addressLength.addrLength) != (char) value0))
  {
    set_grid_tlv_GridComputingElement_AddressLength(gn_computing,(uint8_t) value0);

    if (OspfGRID.status == enabled)
      if (gn->area != NULL)
      {
        if (gn_computing->base.flags & GRIDFLG_GRID_LSA_ENGAGED)
        {
          ospf_grid_computing_lsa_schedule (gn_computing, GRID_REFRESH_THIS_LSA);
          zlog_debug("[DBG] ospf_grid_computing_lsa_schedule (gn_computing, GRID_REFRESH_THIS_LSA)");
        }
        else
        {
          ospf_grid_computing_lsa_schedule (gn_computing, GRID_REORIGINATE_PER_AREA);
          zlog_debug("[DBG] ospf_grid_computing_lsa_schedule (gn_computing, GRID_REORIGINATE_PER_AREA)");
        }
      }
  }
  return CMD_SUCCESS;
}
DEFUN(set_cli_grid_tlv_GridComputingElement_LrmsInfo,
      set_cli_grid_tlv_GridComputingElement_LrmsInfo_cmd,
      "computing ID lrms_info LRMS_TYPE LRMS_VERSION",
      "Grid Computing Element Property TLV\n"
      "Grid Computing Element ID uint32_t\n"
      "Type and version of the underlying LRMS\n"
      "LRMS Type\n"
      "LRMS Version\n")
{
  struct grid_node            *gn = (struct grid_node *) vty->index;
  struct grid_node_computing  *gn_computing;

  if ((gn_computing = lookup_grid_node_computing_by_grid_node_and_sub_id(gn, strtoul(argv[0], NULL, 0)))==NULL)
  {
    vty_out (vty, "no computing element with ID %d, add new computing before%s", (uint32_t) strtoul(argv[0], NULL, 0), VTY_NEWLINE);
    return CMD_WARNING;
  }

  unsigned int value0;
  if (sscanf (argv[1], "%u", &value0) != 1)
  {
    vty_out (vty, "set_cli_grid_tlv_GridComputingElement_LrmsInfo: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
    return CMD_WARNING;
  }
  unsigned int value1;
  if (sscanf (argv[2], "%u", &value1) != 1)
  {
    vty_out (vty, "set_cli_grid_tlv_GridComputingElement_LrmsInfo: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
    return CMD_WARNING;
  }

  if ((ntohs(gn_computing->gridCompElement.lrmsInfo.header.type) == 0)
     ||(ntohs(gn_computing->gridCompElement.lrmsInfo.lrmsType) != value0)
     ||(ntohs(gn_computing->gridCompElement.lrmsInfo.lrmsVersion) != value1))
  {
    set_grid_tlv_GridComputingElement_LrmsInfo(gn_computing,(uint16_t) value0,(uint16_t) value1);

    if (OspfGRID.status == enabled)
      if (gn->area != NULL)
      {
        if (gn_computing->base.flags & GRIDFLG_GRID_LSA_ENGAGED)
        {
          ospf_grid_computing_lsa_schedule (gn_computing, GRID_REFRESH_THIS_LSA);
          zlog_debug("[DBG] ospf_grid_computing_lsa_schedule (gn_computing, GRID_REFRESH_THIS_LSA)");
        }
        else
        {
          ospf_grid_computing_lsa_schedule (gn_computing, GRID_REORIGINATE_PER_AREA);
          zlog_debug("[DBG] ospf_grid_computing_lsa_schedule (gn_computing, GRID_REORIGINATE_PER_AREA)");
        }
      }
  }
  return CMD_SUCCESS;
}
DEFUN(set_cli_grid_tlv_GridComputingElement_ParentSiteID,
      set_cli_grid_tlv_GridComputingElement_ParentSiteID_cmd,
      "computing ID parent_site_id PARENT_SITE_ID",
      "Grid Computing Element Property TLV\n"
      "Grid Computing Element ID uint32_t\n"
      "Identifier of the Grid Site that is exporting this computing element\n"
      "Identifier of the Grid Site\n")
{
  struct grid_node            *gn = (struct grid_node *) vty->index;
  struct grid_node_computing  *gn_computing;

  if ((gn_computing = lookup_grid_node_computing_by_grid_node_and_sub_id(gn, strtoul(argv[0], NULL, 0)))==NULL)
  {
    vty_out (vty, "no computing element with ID %d, add new computing before%s", (uint32_t) strtoul(argv[0], NULL, 0), VTY_NEWLINE);
    return CMD_WARNING;
  }

  long unsigned int value0;
  if (sscanf (argv[1], "%lu", &value0) != 1)
  {
    vty_out (vty, "set_cli_grid_tlv_GridComputingElement_ParentSiteID: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
    return CMD_WARNING;
  }

  if ((ntohs(gn_computing->gridCompElement.parentSiteId.header.type) == 0)
     ||(ntohl(gn_computing->gridCompElement.parentSiteId.parSiteId) != value0))
  {
    set_grid_tlv_GridComputingElement_ParentSiteID(gn_computing,(uint32_t) value0);

    if (OspfGRID.status == enabled)
      if (gn->area != NULL)
      {
        if (gn_computing->base.flags & GRIDFLG_GRID_LSA_ENGAGED)
        {
          ospf_grid_computing_lsa_schedule (gn_computing, GRID_REFRESH_THIS_LSA);
          zlog_debug("[DBG] ospf_grid_computing_lsa_schedule (gn_computing, GRID_REFRESH_THIS_LSA)");
        }
        else
        {
          ospf_grid_computing_lsa_schedule (gn_computing, GRID_REORIGINATE_PER_AREA);
          zlog_debug("[DBG] ospf_grid_computing_lsa_schedule (gn, GRID_REORIGINATE_PER_AREA)");
        }
      }
  }
  return CMD_SUCCESS;
}

//FIXME
DEFUN(set_cli_grid_tlv_GridComputingElement_ID,
      set_cli_grid_tlv_GridComputingElement_ID_cmd,
      "computing add ID",
      "Grid Computing Element Property TLV\n"
      "Add new Computing Element\n"
      "Identifier of the new Computing Element\n")
{
  struct grid_node            *gn = (struct grid_node *) vty->index;
  struct grid_node_computing  *gn_computing;

  long unsigned int value0;
  if (sscanf (argv[0], "%lu", &value0) != 1)
  {
    vty_out (vty, "set_cli_grid_tlv_GridComputingElement_ID: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
    return CMD_WARNING;
  }


  if ((gn_computing = lookup_grid_node_computing_by_grid_node_and_sub_id(gn, value0))==NULL)
  {
    gn_computing = create_new_grid_node_computing(gn, value0);
    listnode_add(gn->list_of_grid_node_computing, gn_computing);
  }
  else
  {
    vty_out (vty, "Alredy exists!%s", VTY_NEWLINE);
    return CMD_WARNING;
  }

  if (OspfGRID.status == enabled)
  {
    if (gn->area != NULL)
    {
      ospf_grid_computing_lsa_schedule (gn_computing, GRID_REORIGINATE_PER_AREA);
      zlog_debug("[DBG] ospf_grid_computing_lsa_schedule (gn_computing, GRID_REORIGINATE_PER_AREA)");
    }
  }
  return CMD_SUCCESS;
}
DEFUN(set_cli_grid_tlv_GridService_NsapEndpoint,
      set_cli_grid_tlv_GridService_NsapEndpoint_cmd,
      "service ID nsap_endpoint ADD_PART1 ADD_PART2 ADD_PART3 ADD_PART4 ADD_PART5",
      "Grid Service Property TLV\n"
      "Grid Service id uint32_t\n"
      "Network endpoint for this service\n"
      "(32-bit Hexadecimal value; ex. a1b2c3d4) First part of the address\n"
      "(32-bit Hexadecimal value; ex. a1b2c3d4) Second part of the address\n"
      "(32-bit Hexadecimal value; ex. a1b2c3d4) Third part of the address\n"
      "(32-bit Hexadecimal value; ex. a1b2c3d4) Fourth part of the address\n"
      "(32-bit Hexadecimal value; ex. a1b2c3d4) Fifth part of the address\n"
      "<cr>\n")
{
  struct grid_node          *gn = (struct grid_node *) vty->index;
  struct grid_node_service  *gn_service;

  if ((gn_service = lookup_grid_node_service_by_grid_node_and_sub_id(gn, strtoul(argv[0], NULL, 0)))==NULL)
  {
    vty_out (vty, "no service element with ID %d, add new service before%s", (uint32_t) strtoul(argv[0], NULL, 0), VTY_NEWLINE);
    return CMD_WARNING;
  }

  u_int32_t nsap_address[5];

  if (sscanf (argv[1], "%x", &nsap_address[4]) != 1)
  {
    vty_out (vty, "set_cli_grid_tlv_GridService_NsapEndpoint: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
    return CMD_WARNING;
  }
  if (sscanf (argv[2], "%x", &nsap_address[3]) != 1)
  {
    vty_out (vty, "set_cli_grid_tlv_GridService_NsapEndpoint: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
    return CMD_WARNING;
  }
  if (sscanf (argv[3], "%x", &nsap_address[2]) != 1)
  {
    vty_out (vty, "set_cli_grid_tlv_GridService_NsapEndpoint: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
    return CMD_WARNING;
  }
  if (sscanf (argv[4], "%x", &nsap_address[1]) != 1)
  {
    vty_out (vty, "set_cli_grid_tlv_GridService_NsapEndpoint: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
    return CMD_WARNING;
  }
  if (sscanf (argv[5], "%x", &nsap_address[0]) != 1)
  {
    vty_out (vty, "set_cli_grid_tlv_GridService_NsapEndpoint: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
    return CMD_WARNING;
  }

//  if ((ntohs(gn_service->gridService.nsapEndpoint.header.type) == 0)
//     ||(ntohl(gn_service->gridService.nsapEndpoint.nsapEndp) != value0))
//  {
    set_grid_tlv_GridService_NsapEndpoint(gn_service,nsap_address);

    if (OspfGRID.status == enabled)
      if (gn->area != NULL)
      {
        if (gn_service->base.flags & GRIDFLG_GRID_LSA_ENGAGED)
        {
          ospf_grid_service_lsa_schedule (gn_service, GRID_REFRESH_THIS_LSA);
          zlog_debug("[DBG] ospf_grid_service_lsa_schedule (gn_service, GRID_REFRESH_THIS_LSA)");
        }
        else
        {
          ospf_grid_service_lsa_schedule (gn_service, GRID_REORIGINATE_PER_AREA);
          zlog_debug("[DBG] ospf_grid_service_lsa_schedule (gn_service, GRID_REORIGINATE_PER_AREA)");
        }
      }
//  }
  return CMD_SUCCESS;
}
DEFUN(set_cli_grid_tlv_GridService_IPv6Endpoint,
      set_cli_grid_tlv_GridService_IPv6Endpoint_cmd,
      "service ID ipv6_endpoint IPV6_ENDPOINT",
      "Grid Service id uint32_t\n"
      "Grid Service Property TLV\n"
      "Network endpoint for this service\n"
      "IPv6 address\n")
{
  struct grid_node          *gn = (struct grid_node *) vty->index;
  struct grid_node_service  *gn_service;

  if ((gn_service = lookup_grid_node_service_by_grid_node_and_sub_id(gn, strtoul(argv[0], NULL, 0)))==NULL)
  {
    vty_out (vty, "no service element with ID %d, add new service before%s", (uint32_t) strtoul(argv[0], NULL, 0), VTY_NEWLINE);
    return CMD_WARNING;
  }

  struct in6_addr address;

  str2in6_addr (argv[1], &address);

  set_grid_tlv_GridService_IPv6Endpoint(gn_service, address);

  if (OspfGRID.status == enabled)
    if (gn->area != NULL)
    {
      if (gn_service->base.flags & GRIDFLG_GRID_LSA_ENGAGED)
      {
        ospf_grid_service_lsa_schedule (gn_service, GRID_REFRESH_THIS_LSA);
        zlog_debug("[DBG] ospf_grid_service_lsa_schedule (gn, GRID_REFRESH_THIS_LSA)");
      }
      else
      {
        ospf_grid_service_lsa_schedule (gn_service, GRID_REORIGINATE_PER_AREA);
        zlog_debug("[DBG] ospf_grid_service_lsa_schedule (gn_service, GRID_REORIGINATE_PER_AREA)");
      }
    }
  return CMD_SUCCESS;
}
DEFUN(set_cli_grid_tlv_GridService_IPv4Endpoint,
      set_cli_grid_tlv_GridService_IPv4Endpoint_cmd,
      "service ID ipv4_endpoint IPV4_ENDPOINT",
      "Grid Service id uint32_t\n"
      "Grid Service Property TLV\n"
      "Network endpoint for this service\n"
      "IPv4 address\n")
{
  struct grid_node          *gn = (struct grid_node *) vty->index;
  struct grid_node_service  *gn_service;

  if ((gn_service = lookup_grid_node_service_by_grid_node_and_sub_id(gn, strtoul(argv[0], NULL, 0)))==NULL)
  {
    vty_out (vty, "no service element with ID %d, add new service before%s", (uint32_t) strtoul(argv[0], NULL, 0), VTY_NEWLINE);
    return CMD_WARNING;
  }

  struct in_addr address;
  if (! inet_aton (argv[1], &address))
  {
    vty_out (vty, "set_cli_grid_tlv_GridService_IPv4Endpoint: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
    return CMD_WARNING;
  }
//  if ((ntohs(gn->gridService.ipv4Endpoint.header.type) == 0)
//     ||(ntohl(gn->gridService.ipv4Endpoint.ipv4Endp) != value0))
//  {
    set_grid_tlv_GridService_IPv4Endpoint(gn_service, address);

    if (OspfGRID.status == enabled)
      if (gn->area != NULL)
      {
        if (gn_service->base.flags & GRIDFLG_GRID_LSA_ENGAGED)
        {
          ospf_grid_service_lsa_schedule (gn_service, GRID_REFRESH_THIS_LSA);
          zlog_debug("[DBG] ospf_grid_service_lsa_schedule (gn, GRID_REFRESH_THIS_LSA)");
        }
        else
        {
          ospf_grid_service_lsa_schedule (gn_service, GRID_REORIGINATE_PER_AREA);
          zlog_debug("[DBG] ospf_grid_service_lsa_schedule (gn, GRID_REORIGINATE_PER_AREA)");
        }
      }
//  }
  return CMD_SUCCESS;
}
DEFUN(set_cli_grid_tlv_GridService_AddressLength,
      set_cli_grid_tlv_GridService_AddressLength_cmd,
      "service ID address_length ADDRESS_LENGTH",
      "Grid Service Property TLV\n"
      "Grid Service id uint32_t\n"
      "Length of the endpoint address\n"
      "(8 bits)\n")
{
  struct grid_node          *gn = (struct grid_node *) vty->index;
  struct grid_node_service  *gn_service;

  if ((gn_service = lookup_grid_node_service_by_grid_node_and_sub_id(gn, strtoul(argv[0], NULL, 0)))==NULL)
  {
    vty_out (vty, "no service element with ID %d, add new service before%s", (uint32_t) strtoul(argv[0], NULL, 0), VTY_NEWLINE);
    return CMD_WARNING;
  }

  unsigned int  value0;
  if (sscanf (argv[1], "%u", &value0) != 1)
  {
    vty_out (vty, "set_cli_grid_tlv_GridService_AddressLength: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
    return CMD_WARNING;
  }

  if ((ntohs(gn_service->gridService.addressLength.header.type) == 0)
     ||((gn_service->gridService.addressLength.addressLength) != (char) value0))
  {
    set_grid_tlv_GridService_AddressLength(gn_service,(uint8_t) value0);

    if (OspfGRID.status == enabled)
      if (gn->area != NULL)
      {
        if (gn_service->base.flags & GRIDFLG_GRID_LSA_ENGAGED)
        {
          ospf_grid_service_lsa_schedule (gn_service, GRID_REFRESH_THIS_LSA);
          zlog_debug("[DBG] ospf_grid_service_lsa_schedule (gn, GRID_REFRESH_THIS_LSA)");
        }
        else
        {
          ospf_grid_service_lsa_schedule (gn_service, GRID_REORIGINATE_PER_AREA);
          zlog_debug("[DBG] ospf_grid_service_lsa_schedule (gn_service, GRID_REORIGINATE_PER_AREA)");
        }
      }
  }
  return CMD_SUCCESS;
}
DEFUN(set_cli_grid_tlv_GridService_Status,
      set_cli_grid_tlv_GridService_Status_cmd,
      "service ID status STATUS",
      "Grid Service Property TLV\n"
      "Grid Service id uint32_t\n"
      "Status of the service\n"
      "(8 bits)\n")
{
  struct grid_node          *gn = (struct grid_node *) vty->index;
  struct grid_node_service  *gn_service;

  if ((gn_service = lookup_grid_node_service_by_grid_node_and_sub_id(gn, strtoul(argv[0], NULL, 0)))==NULL)
  {
    vty_out (vty, "no service element with ID %d, add new service before%s", (uint32_t) strtoul(argv[0], NULL, 0), VTY_NEWLINE);
    return CMD_WARNING;
  }

  unsigned int  value0;
  if (sscanf (argv[1], "%u", &value0) != 1)
  {
    vty_out (vty, "set_cli_grid_tlv_GridService_Status: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
    return CMD_WARNING;
  }

  if ((ntohs(gn_service->gridService.status.header.type) == 0)
     ||((gn_service->gridService.status.status) != (char) value0))
  {
    set_grid_tlv_GridService_Status(gn_service,(uint8_t) value0);

    if (OspfGRID.status == enabled)
      if (gn->area != NULL)
      {
        if (gn_service->base.flags & GRIDFLG_GRID_LSA_ENGAGED)
        {
          ospf_grid_service_lsa_schedule (gn_service, GRID_REFRESH_THIS_LSA);
          zlog_debug("[DBG] ospf_grid_service_lsa_schedule (gn, GRID_REFRESH_THIS_LSA)");
        }
        else
        {
          ospf_grid_service_lsa_schedule (gn_service, GRID_REORIGINATE_PER_AREA);
          zlog_debug("[DBG] ospf_grid_service_lsa_schedule (gn, GRID_REORIGINATE_PER_AREA)");
        }
      }
  }
  return CMD_SUCCESS;
}
DEFUN(set_cli_grid_tlv_GridService_ServiceInfo,
      set_cli_grid_tlv_GridService_ServiceInfo_cmd,
      "service ID service_info TYPE VERSION",
      "Grid Service Property TLV\n"
      "Grid Service id uint32_t\n"
      "The service info including service type and version\n"
      "The service type\n"
      "Version of the service\n")
{
  struct grid_node          *gn = (struct grid_node *) vty->index;
  struct grid_node_service  *gn_service;

  if ((gn_service = lookup_grid_node_service_by_grid_node_and_sub_id(gn, strtoul(argv[0], NULL, 0)))==NULL)
  {
    vty_out (vty, "no service element with ID %d, add new service before%s", (uint32_t) strtoul(argv[0], NULL, 0), VTY_NEWLINE);
    return CMD_WARNING;
  }

  unsigned int value0;
  if (sscanf (argv[1], "%u", &value0) != 1)
  {
    vty_out (vty, "set_cli_grid_tlv_GridService_ServiceInfo: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
    return CMD_WARNING;
  }
  unsigned int value1;
  if (sscanf (argv[2], "%u", &value1) != 1)
  {
    vty_out (vty, "set_cli_grid_tlv_GridService_ServiceInfo: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
    return CMD_WARNING;
  }

  if ((ntohs(gn_service->gridService.serviceInfo.header.type) == 0)
     ||(ntohs(gn_service->gridService.serviceInfo.type) != value0)
     ||(ntohs(gn_service->gridService.serviceInfo.version) != value1))
  {
    set_grid_tlv_GridService_ServiceInfo(gn_service,(uint16_t) value0,(uint16_t) value1);

    if (OspfGRID.status == enabled)
      if (gn->area != NULL)
      {
        if (gn_service->base.flags & GRIDFLG_GRID_LSA_ENGAGED)
        {
          ospf_grid_service_lsa_schedule (gn_service, GRID_REFRESH_THIS_LSA);
          zlog_debug("[DBG] ospf_grid_service_lsa_schedule (gn, GRID_REFRESH_THIS_LSA)");
        }
        else
        {
          ospf_grid_service_lsa_schedule (gn_service, GRID_REORIGINATE_PER_AREA);
          zlog_debug("[DBG] ospf_grid_service_lsa_schedule (gn, GRID_REORIGINATE_PER_AREA)");
        }
      }
  }
  return CMD_SUCCESS;
}
DEFUN(set_cli_grid_tlv_GridService_ParentSite_ID,
      set_cli_grid_tlv_GridService_ParentSite_ID_cmd,
      "service ID parent_site_id PARENT_SITE_ID",
      "Grid Service Property TLV\n"
      "Grid Service id uint32_t\n"
      "Identifier of the Grid Site that is exporting this service\n"
      "Identifier of the Grid Site\n")
{
  struct grid_node          *gn = (struct grid_node *) vty->index;
  struct grid_node_service  *gn_service;

  if ((gn_service = lookup_grid_node_service_by_grid_node_and_sub_id(gn, strtoul(argv[0], NULL, 0)))==NULL)
  {
    vty_out (vty, "no service element with ID %d, add new service before%s", (uint32_t) strtoul(argv[0], NULL, 0), VTY_NEWLINE);
    return CMD_WARNING;
  }

  long unsigned int value0;
  if (sscanf (argv[1], "%lu", &value0) != 1)
  {
    vty_out (vty, "set_cli_grid_tlv_GridService_ParentSite_ID: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
    return CMD_WARNING;
  }

  if ((ntohs(gn_service->gridService.parentSite_id.header.type) == 0)
     ||(ntohl(gn_service->gridService.parentSite_id.parent_site_id) != value0))
  {
    set_grid_tlv_GridService_ParentSite_ID(gn_service,(uint32_t) value0);

    if (OspfGRID.status == enabled)
      if (gn->area != NULL)
      {
        if (gn_service->base.flags & GRIDFLG_GRID_LSA_ENGAGED)
        {
          ospf_grid_service_lsa_schedule (gn_service, GRID_REFRESH_THIS_LSA);
          zlog_debug("[DBG] ospf_grid_service_lsa_schedule (gn_service, GRID_REFRESH_THIS_LSA)");
        }
        else
        {
          ospf_grid_service_lsa_schedule (gn_service, GRID_REORIGINATE_PER_AREA);
          zlog_debug("[DBG] ospf_grid_service_lsa_schedule (gn_service, GRID_REORIGINATE_PER_AREA)");
        }
      }
  }
  return CMD_SUCCESS;
}
DEFUN(set_cli_grid_tlv_GridService_ID,
      set_cli_grid_tlv_GridService_ID_cmd,
      "service add ID",
      "Grid Service Property TLV\n"
      "add new Service\n"
      "Identifier of the new Service\n")
{
  struct grid_node          *gn = (struct grid_node *) vty->index;
  struct grid_node_service  *gn_service;

  long unsigned int value0;
  if (sscanf (argv[0], "%lu", &value0) != 1)
  {
    vty_out (vty, "set_cli_grid_tlv_GridService_ID: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
    return CMD_WARNING;
  }

  if ((gn_service = lookup_grid_node_service_by_grid_node_and_sub_id(gn, value0))==NULL)
  {
    gn_service = create_new_grid_node_service(gn, value0);
    listnode_add(gn->list_of_grid_node_service, gn_service);
  }
  else
  {
    vty_out (vty, "Alredy exists!%s", VTY_NEWLINE);
    return CMD_WARNING;
  }

  if (OspfGRID.status == enabled)
  {
    if (gn->area != NULL)
    {
      ospf_grid_service_lsa_schedule (gn_service, GRID_REORIGINATE_PER_AREA);
      zlog_debug("[DBG] ospf_grid_service_lsa_schedule (gn_service, GRID_REORIGINATE_PER_AREA)");
    }
  }
  return CMD_SUCCESS;
}
DEFUN(set_cli_grid_tlv_GridSite_PE_Router_ID,
      set_cli_grid_tlv_GridSite_PE_Router_ID_cmd,
      "site pe_router_id PE_ROUTER_ID ",
      "Grid Side Property TLV\n"
      "Provider Edge router ID\n"
      "IPv4 address\n"
      "<cr>\n")
{
  struct grid_node *gn = (struct grid_node *) vty->index;

  struct in_addr address;
  if (! inet_aton (argv[0], &address))
  {
    vty_out (vty, "set_cli_grid_tlv_GridSite_PE_Router_ID: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
    return CMD_WARNING;
  }

  set_grid_tlv_GridSite_PE_Router_ID(gn->gn_site,address);
  if (OspfGRID.status == enabled)
    if (gn->area != NULL)
    {
      if (gn->gn_site->base.flags & GRIDFLG_GRID_LSA_ENGAGED)
      {
        ospf_grid_site_lsa_schedule (gn->gn_site, GRID_REFRESH_THIS_LSA);
        zlog_debug("[DBG] ospf_grid_site_lsa_schedule (gn->gn_site, GRID_REFRESH_THIS_LSA)");
      }
      else
      {
        ospf_grid_site_lsa_schedule (gn->gn_site, GRID_REORIGINATE_PER_AREA);
        zlog_debug("[DBG] ospf_grid_site_lsa_schedule (gn->gn_site, GRID_REORIGINATE_PER_AREA)");
      }
    }
  return CMD_SUCCESS;
}
DEFUN(set_cli_grid_tlv_GridSite_Longitude,
      set_cli_grid_tlv_GridSite_Longitude_cmd,
      "site longitude RESOLUTION INTEGER_PART FRACTIONAL_PART",
      "Grid Side Property TLV\n"
      "Degree the position of a place east or west of Greenwich\n"
      "Resolution (6 bits) ex. 0xa1\n"
      "Integer part (9 bits) ex. 0xa1\n"
      "Fractional part (25 bits) ex. 0xa1\n"
      "<cr>\n")
{
  struct grid_node *gn = (struct grid_node *) vty->index;

  uint8_t longitude[5];
  uint64_t temp;
  uint64_t val = 0;

  temp = strtoul(argv[0], NULL, 0);
  temp <<= 58;
  temp &= 0xfc00000000000000;
  val &=  0x03ffffffffffffff;
  val |= temp;

  temp = strtoul(argv[1], NULL, 0);
  temp <<= 49;
  temp &= 0x03fe000000000000;
  val &=  0xfc01ffffffffffff;
  val |= temp;
  temp = strtoul(argv[2], NULL, 0);
  temp <<= 24;
  temp &= 0x0001ffffff000000;
  val &=  0xfffe000000ffffff;
  val |= temp;

  val >>= 24;

  longitude[0] = (uint8_t)val; val >>= 8;
  longitude[1] = (uint8_t)val; val >>= 8;
  longitude[2] = (uint8_t)val; val >>= 8;
  longitude[3] = (uint8_t)val; val >>= 8;
  longitude[4] = (uint8_t)val;

  set_grid_tlv_GridSite_Longitude(gn->gn_site, longitude);

  if (OspfGRID.status == enabled)
    if (gn->area != NULL)
    {
      if (gn->gn_site->base.flags & GRIDFLG_GRID_LSA_ENGAGED)
      {
        ospf_grid_site_lsa_schedule (gn->gn_site, GRID_REFRESH_THIS_LSA);
        zlog_debug("[DBG] ospf_grid_site_lsa_schedule (gn->gn_site, GRID_REFRESH_THIS_LSA)");
      }
      else
      {
        ospf_grid_site_lsa_schedule (gn->gn_site, GRID_REORIGINATE_PER_AREA);
        zlog_debug("[DBG] ospf_grid_site_lsa_schedule (gn->gn_site, GRID_REORIGINATE_PER_AREA)");
      }
    }

  return CMD_SUCCESS;
}
DEFUN(set_cli_grid_tlv_GridSite_Latitude,
      set_cli_grid_tlv_GridSite_Latitude_cmd,
      "site latitude RESOLUTION INTEGER_PART FRACTIONAL_PART",
      "Grid Side Property TLV\n"
      "Degree the position of a place north or south of the equator\n"
      "Resolution (6 bits) ex. 0xa1\n"
      "Integer part (9 bits) ex. 0xa1\n"
      "Fractional part (25 bits) ex. 0xa1\n"
      "<cr>\n")
{
  struct grid_node *gn = (struct grid_node *) vty->index;

  uint8_t  latitude[5];
  uint64_t temp;
  uint64_t val = 0;

  temp = strtoul(argv[0], NULL, 0);
  temp <<= 58;
  temp &= 0xfc00000000000000;
  val &=  0x03ffffffffffffff;
  val |= temp;
  temp = strtoul(argv[1], NULL, 0);
  temp <<= 49;
  temp &= 0x03fe000000000000;
  val &=  0xfc01ffffffffffff;
  val |= temp;
  temp = strtoul(argv[2], NULL, 0);
  temp <<= 24;
  temp &= 0x0001ffffff000000;
  val &=  0xfffe000000ffffff;
  val |= temp;

  val >>= 24;

  latitude[0] = (uint8_t)val; val >>= 8;
  latitude[1] = (uint8_t)val; val >>= 8;
  latitude[2] = (uint8_t)val; val >>= 8;
  latitude[3] = (uint8_t)val; val >>= 8;
  latitude[4] = (uint8_t)val;


//  if ((ntohs(gn->gridSite.latitude.header.type) == 0)
//     ||(ntohl(gn->gridSite.latitude.latitude) != value0))
//  {
    set_grid_tlv_GridSite_Latitude(gn->gn_site, latitude);

    if (OspfGRID.status == enabled)
      if (gn->area != NULL)
      {
        if (gn->gn_site->base.flags & GRIDFLG_GRID_LSA_ENGAGED)
        {
          ospf_grid_site_lsa_schedule (gn->gn_site, GRID_REFRESH_THIS_LSA);
          zlog_debug("[DBG] ospf_grid_site_lsa_schedule (gn->gn_site, GRID_REFRESH_THIS_LSA)");
        }
        else
        {
          ospf_grid_site_lsa_schedule (gn->gn_site, GRID_REORIGINATE_PER_AREA);
          zlog_debug("[DBG] ospf_grid_site_lsa_schedule (gn->gn_site, GRID_REORIGINATE_PER_AREA)");
        }
      }
//  }
  return CMD_SUCCESS;
}
DEFUN(set_cli_grid_tlv_GridSite_Name,
      set_cli_grid_tlv_GridSite_Name_cmd,
      "site name NAME",
      "Grid Side Property TLV\n"
      "Human-readable name\n"
      "Name (string)\n")
{
  struct grid_node *gn = (struct grid_node *) vty->index;

  if (1)//((ntohs(gn->gridSite.name.header.type) == 0)
     //||(ntohl(gn->gridSite.name.name) != value0))
  {
    set_grid_tlv_GridSite_Name(gn->gn_site, argv[0]);
    if (OspfGRID.status == enabled)
      if (gn->area != NULL)
      {
        if (gn->gn_site->base.flags & GRIDFLG_GRID_LSA_ENGAGED)
        {
          ospf_grid_site_lsa_schedule (gn->gn_site, GRID_REFRESH_THIS_LSA);
          zlog_debug("[DBG] ospf_grid_site_lsa_schedule (gn->gn_site, GRID_REFRESH_THIS_LSA)");
        }
        else
        {
          ospf_grid_site_lsa_schedule (gn->gn_site, GRID_REORIGINATE_PER_AREA);
          zlog_debug("[DBG] ospf_grid_site_lsa_schedule (gn->gn_site, GRID_REORIGINATE_PER_AREA)");
        }
      }
  }
  return CMD_SUCCESS;
}
DEFUN(set_cli_grid_tlv_GridSite_ID,
      set_cli_grid_tlv_GridSite_ID_cmd,
      "site id ID",
      "Grid Side Property TLV\n"
      "Set identifier of the Site\n"
      "Identifier of the Site\n")
{
  struct grid_node *gn = (struct grid_node *) vty->index;

  long unsigned int value0;
  if (sscanf (argv[0], "%lu", &value0) != 1)
  {
    vty_out (vty, "set_cli_grid_tlv_GridSite_ID: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
    return CMD_WARNING;
  }

  if ((ntohs(gn->gn_site->gridSite.id.header.type) == 0)
     ||(ntohl(gn->gn_site->gridSite.id.id) != value0))
  {
    set_grid_tlv_GridSite_ID(gn->gn_site,(uint32_t) value0);

    if (OspfGRID.status == enabled)
      if (gn->area != NULL)
      {
        if (gn->gn_site->base.flags & GRIDFLG_GRID_LSA_ENGAGED)
        {
          ospf_grid_site_lsa_schedule (gn->gn_site, GRID_REFRESH_THIS_LSA);
          zlog_debug("[DBG] ospf_grid_site_lsa_schedule (gn->gn_site, GRID_REFRESH_THIS_LSA)");
        }
        else
        {
          ospf_grid_site_lsa_schedule (gn->gn_site, GRID_REORIGINATE_PER_AREA);
          zlog_debug("[DBG] ospf_grid_site_lsa_schedule (gn->gn_site, GRID_REORIGINATE_PER_AREA)");
        }
      }
  }
  return CMD_SUCCESS;
}

#if USE_UNTESTED_OSPF_GRID_CORBA_UPDATE
DEFUN(corba_update_g2pcera_grid_lsdb,
      corba_update_g2pcera_grid_lsdb_cmd,
      "corba update grid g2pcera",
      "Corba related functions\n"
      "Update information\n"
      "Update Grid information\n"
      "Update g2pcera\n")
{
  update_grid_inf_from_lsdb(UPDATE_G2PCERA);
  return CMD_SUCCESS;
}

DEFUN(corba_update_gunigw_grid_lsdb,
      corba_update_gunigw_grid_lsdb_cmd,
      "corba update grid gunigw",
      "Corba related functions\n"
      "Update information\n"
      "Update Grid information\n"
      "Update gunigw\n")
{
  update_grid_inf_from_lsdb(UPDATE_GUNIGW);
  return CMD_SUCCESS;
}
#endif /* USE_UNTESTED_OSPF_GRID_CORBA_UPDATE */

DEFUN(cli_add_grid_node,
      cli_add_grid_node_cmd,
      "grid-node add ID",
      "GRID-NODE specyfic command\n"
      "add new node\n"
      "node ID\n")
{
  //nodeAdd
  long unsigned int id;
  if (sscanf (argv[0], "%lu", &id) != 1)
  {
    if (vty)
      vty_out (vty, "cli_add_grid_node_cmd: wrong grid node id %s%s", argv[0], VTY_NEWLINE);
    else
      zlog_warn("[WRN] cli_add_grid_node_cmd: Wrong grid node id %s", argv[0]);
    return CMD_WARNING;
  }

  struct grid_node *gn;
  struct interface *ifp = uni_interface_lookup();

  if (ifp == NULL)
  {
    if (vty)
      vty_out (vty, "There is no UNI interface, can't add grid node.%s", VTY_NEWLINE);
    else
      zlog_warn ("[WRN] cli_add_grid_node: There is no UNI interface, can't add grid node.");
    return CMD_WARNING;
  }

  struct ospf_interface *oi = lookup_oi_by_ifp (ifp);
  if (oi == NULL)
  {
    if (vty)
      vty_out (vty, "Can't find ospf interface.%s", VTY_NEWLINE);
    else
      zlog_warn ("[WRN] cli_add_grid_node: Can't find OSPF interface.");
    return CMD_WARNING;
  }

  if ((gn = lookup_grid_node_by_site_id (id))!= NULL)
  {
    if (vty)
      vty_out (vty, "cli_add_grid_node_cmd: node %lu already exists. Use grid-node configure command%s", id, VTY_NEWLINE);
    else
      zlog_warn("[WRN] cli_add_grid_node_cmd: Node %lu already exists. Use grid-node configure command", id);
    return CMD_WARNING;
  }

  if ((gn = XMALLOC (MTYPE_OSPF_GRID_NODE, sizeof (struct grid_node))) == NULL)
  {
    if (vty)
      vty_out (vty, "cli_add_grid_node_cmd: XMALLOC: %s%s", safe_strerror (errno), VTY_NEWLINE);
    else
      zlog_warn ("[WRN] cli_add_grid_node_cmd: XMALLOC: %s", safe_strerror (errno));
    return CMD_WARNING;
  }
  memset (gn, 0, sizeof (struct grid_node));

  gn->ifp = ifp;
  gn->area = oi->area;

  if (initialize_grid_node_params (gn) != 0)
  {
    if (vty)
      vty_out (vty, "cli_add_grid_node_cmd: initialize_grid_node_params failed%s", VTY_NEWLINE);
    else
      zlog_warn ("[WRN] cli_add_grid_node_cmd: initialize_grid_node_params failed");
    return CMD_WARNING;
  }

  set_grid_tlv_GridSite_ID(gn->gn_site,(uint32_t) id);
  listnode_add (OspfGRID.iflist, gn);

  if (OspfGRID.status == enabled)
  {
    if (gn->area != NULL)
    {
      if (gn->gn_site->base.flags & GRIDFLG_GRID_LSA_ENGAGED)
      {
        ospf_grid_site_lsa_schedule (gn->gn_site, GRID_REFRESH_THIS_LSA);
        zlog_debug("[DBG] ospf_grid_site_lsa_schedule (gn->gn_site, GRID_REFRESH_THIS_LSA)");
      }
      else
      {
        ospf_grid_site_lsa_schedule (gn->gn_site, GRID_REORIGINATE_PER_AREA);
        zlog_debug("[DBG] ospf_grid_site_lsa_schedule (gn->gn_site, GRID_REORIGINATE_PER_AREA)");
      }
    }
  }

  return CMD_SUCCESS;
}

DEFUN(cli_delete_grid_node,
      cli_delete_grid_node_cmd,
      "grid-node delete ID",
      "GRID-NODE specyfic command\n"
      "delete node\n"
      "node ID\n")
{
  int id = strtoul(argv[0], NULL, 10);
  struct grid_node *gn = lookup_grid_node_by_site_id(id);
  if (gn == NULL)
  {
    if (vty)
      vty_out (vty, "cli_delete_grid_node_cmd: Can't find grid node id: %d%s", id, VTY_NEWLINE);
    else
      zlog_warn("[WRN] cli_delete_grid_node_cmd: Can't find grid node id: %d", id);
    return CMD_WARNING;
  }

  int result = grid_node_delete_node(gn);
  switch(result)
  {
    case -1:
      if (vty)
        vty_out (vty, "cli_delete_grid_node_cmd: Can't delete grid node%s", VTY_NEWLINE);
      else
        zlog_warn("[WRN] cli_delete_grid_node_cmd: Can't delete grid node");
      break;
    default:
      break;
  }
  if (result != 0)
    return CMD_WARNING;
  return CMD_SUCCESS;
}

DEFUN(cli_configure_grid_node,
      cli_configure_grid_node_cmd,
      "grid-node configure ID",
      "GRID-NODE specyfic command\n"
      "configure node\n"
      "node ID\n")
{
  long unsigned int id;
  if (sscanf (argv[0], "%lu", &id) != 1)
  {
    if (vty)
      vty_out (vty, "cli_configure_grid_node_cmd: wrong grid node id %s%s", argv[0], VTY_NEWLINE);
    else
      zlog_warn("[WRN] cli_configure_grid_node_cmd: Wrong grid node id %s", argv[0]);
    return CMD_WARNING;
  }
  struct grid_node *gn = lookup_grid_node_by_site_id(id);
  if (gn == NULL)
  {
    if (vty)
      vty_out (vty, "cli_add_grid_node_cmd: XMALLOC: %s%s", safe_strerror (errno), VTY_NEWLINE);
    else
      zlog_warn ("[WRN] cli_add_grid_node_cmd: XMALLOC: %s", safe_strerror (errno));
    return CMD_WARNING;
  }
  vty->index = gn;
  vty->node = OSPF_GN_NODE;
  return CMD_SUCCESS;
}


static int
gn_config_write (struct vty *vty)
{
  int write=0;

  return write;
}

struct cmd_node ospf_gn_node =
{
  OSPF_GN_NODE,
  "%s(config-grid-node)# ",
  1
};

static void
ospf_grid_register_vty (void)
{
  install_node (&ospf_gn_node, gn_config_write);

  install_element (CONFIG_NODE, &cli_add_grid_node_cmd);
  install_element (CONFIG_NODE, &cli_delete_grid_node_cmd);
  install_element (CONFIG_NODE, &cli_configure_grid_node_cmd);

  install_element (VIEW_NODE, &no_debug_ospf_grid_node_cmd);
  install_element (ENABLE_NODE, &no_debug_ospf_grid_node_cmd);
  install_element (CONFIG_NODE, &no_debug_ospf_grid_node_cmd);

  install_element (VIEW_NODE, &debug_ospf_grid_node_cmd);
  install_element (ENABLE_NODE, &debug_ospf_grid_node_cmd);
  install_element (CONFIG_NODE, &debug_ospf_grid_node_cmd);

#if USE_UNTESTED_OSPF_GRID_CORBA_UPDATE
  install_element (INTERFACE_NODE, &corba_update_g2pcera_grid_lsdb_cmd);
  install_element (INTERFACE_NODE, &corba_update_gunigw_grid_lsdb_cmd);
#endif /* USE_UNTESTED_OSPF_GRID_CORBA_UPDATE */

  install_element (VIEW_NODE, &show_cli_grid_tlv_GridSite_cmd);
  install_element (VIEW_NODE, &show_cli_grid_tlv_GridService_cmd);
  install_element (VIEW_NODE, &show_cli_grid_tlv_GridComputingElement_cmd);
  install_element (VIEW_NODE, &show_cli_grid_tlv_GridSubCluster_cmd);
  install_element (VIEW_NODE, &show_cli_grid_tlv_GridStorage_cmd);

  install_element (ENABLE_NODE, &show_cli_grid_tlv_GridSite_cmd);
  install_element (ENABLE_NODE, &show_cli_grid_tlv_GridService_cmd);
  install_element (ENABLE_NODE, &show_cli_grid_tlv_GridComputingElement_cmd);
  install_element (ENABLE_NODE, &show_cli_grid_tlv_GridSubCluster_cmd);
  install_element (ENABLE_NODE, &show_cli_grid_tlv_GridStorage_cmd);

  install_element (OSPF_NODE, &reoriginate_grid_cmd);
  install_element (OSPF_GN_NODE, &reoriginate_grid_cmd);

  install_element (OSPF_GN_NODE, &set_cli_grid_tlv_GridStorage_Name_cmd);
  install_element (OSPF_GN_NODE, &set_cli_grid_tlv_GridStorage_SeCalendar_cmd);
  install_element (OSPF_GN_NODE, &set_cli_grid_tlv_GridStorage_StorageArea_cmd);
  install_element (OSPF_GN_NODE, &set_cli_grid_tlv_GridStorage_NearlineSize_cmd);
  install_element (OSPF_GN_NODE, &set_cli_grid_tlv_GridStorage_OnlineSize_cmd);
  install_element (OSPF_GN_NODE, &set_cli_grid_tlv_GridStorage_StorageInfo_cmd);
  install_element (OSPF_GN_NODE, &set_cli_grid_tlv_GridStorage_ParentSiteID_cmd);
  install_element (OSPF_GN_NODE, &set_cli_grid_tlv_GridStorage_ID_cmd);
  install_element (OSPF_GN_NODE, &set_cli_grid_tlv_GridSubCluster_Name_cmd);
  install_element (OSPF_GN_NODE, &set_cli_grid_tlv_GridSubCluster_SubClusterCalendar_cmd);
  install_element (OSPF_GN_NODE, &set_cli_grid_tlv_GridSubCluster_SoftwarePackage_cmd);
  install_element (OSPF_GN_NODE, &set_cli_grid_tlv_GridSubCluster_MemoryInfo_cmd);
  install_element (OSPF_GN_NODE, &set_cli_grid_tlv_GridSubCluster_OsInfo_cmd);
  install_element (OSPF_GN_NODE, &set_cli_grid_tlv_GridSubCluster_CpuInfo_cmd);
  install_element (OSPF_GN_NODE, &set_cli_grid_tlv_GridSubCluster_ParentSiteID_cmd);
  install_element (OSPF_GN_NODE, &set_cli_grid_tlv_GridSubCluster_ID_cmd);
  install_element (OSPF_GN_NODE, &set_cli_grid_tlv_GridComputingElement_Name_cmd);
  install_element (OSPF_GN_NODE, &set_cli_grid_tlv_GridComputingElement_CeCalendar_cmd);
  install_element (OSPF_GN_NODE, &set_cli_grid_tlv_GridComputingElement_JobsLoadPolicy_cmd);
  install_element (OSPF_GN_NODE, &set_cli_grid_tlv_GridComputingElement_JobsTimePolicy_cmd);
  install_element (OSPF_GN_NODE, &set_cli_grid_tlv_GridComputingElement_JobsTimePerformances_cmd);
  install_element (OSPF_GN_NODE, &set_cli_grid_tlv_GridComputingElement_JobsStats_cmd);
  install_element (OSPF_GN_NODE, &set_cli_grid_tlv_GridComputingElement_JobsStates_cmd);
  install_element (OSPF_GN_NODE, &set_cli_grid_tlv_GridComputingElement_DefaultStorageElement_cmd);
  install_element (OSPF_GN_NODE, &set_cli_grid_tlv_GridComputingElement_DataDir_cmd);
  install_element (OSPF_GN_NODE, &set_cli_grid_tlv_GridComputingElement_JobManager_cmd);
  install_element (OSPF_GN_NODE, &set_cli_grid_tlv_GridComputingElement_GatekeeperPort_cmd);
  install_element (OSPF_GN_NODE, &set_cli_grid_tlv_GridComputingElement_NsapHostName_cmd);
  install_element (OSPF_GN_NODE, &set_cli_grid_tlv_GridComputingElement_IPv6HostName_cmd);
  install_element (OSPF_GN_NODE, &set_cli_grid_tlv_GridComputingElement_IPv4HostName_cmd);
  install_element (OSPF_GN_NODE, &set_cli_grid_tlv_GridComputingElement_AddressLength_cmd);
  install_element (OSPF_GN_NODE, &set_cli_grid_tlv_GridComputingElement_LrmsInfo_cmd);
  install_element (OSPF_GN_NODE, &set_cli_grid_tlv_GridComputingElement_ParentSiteID_cmd);
  install_element (OSPF_GN_NODE, &set_cli_grid_tlv_GridComputingElement_ID_cmd);
  install_element (OSPF_GN_NODE, &set_cli_grid_tlv_GridService_NsapEndpoint_cmd);
  install_element (OSPF_GN_NODE, &set_cli_grid_tlv_GridService_IPv6Endpoint_cmd);
  install_element (OSPF_GN_NODE, &set_cli_grid_tlv_GridService_IPv4Endpoint_cmd);
  install_element (OSPF_GN_NODE, &set_cli_grid_tlv_GridService_AddressLength_cmd);
  install_element (OSPF_GN_NODE, &set_cli_grid_tlv_GridService_Status_cmd);
  install_element (OSPF_GN_NODE, &set_cli_grid_tlv_GridService_ServiceInfo_cmd);
  install_element (OSPF_GN_NODE, &set_cli_grid_tlv_GridService_ParentSite_ID_cmd);
  install_element (OSPF_GN_NODE, &set_cli_grid_tlv_GridService_ID_cmd);
  install_element (OSPF_GN_NODE, &set_cli_grid_tlv_GridSite_PE_Router_ID_cmd);
  install_element (OSPF_GN_NODE, &set_cli_grid_tlv_GridSite_Longitude_cmd);
  install_element (OSPF_GN_NODE, &set_cli_grid_tlv_GridSite_Latitude_cmd);
  install_element (OSPF_GN_NODE, &set_cli_grid_tlv_GridSite_Name_cmd);
  install_element (OSPF_GN_NODE, &set_cli_grid_tlv_GridSite_ID_cmd);
  return;
}

inline static uint16_t
stream_to_struct_grid_tlv_header (struct grid_tlv_header *tlvh)
{
  return GRID_TLV_HDR_SIZE;    /* Here is special, not "GRID_TLV_SIZE". */
}

uint16_t
stream_to_struct_unknown_tlv (struct grid_tlv_header *tlvh)
{
  return GRID_TLV_SIZE (tlvh);
}

static uint16_t
stream_to_struct_grid_tlv_GridSite_ID(struct grid_node_site *gn_site, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridSite_ID *top;
  top = (struct grid_tlv_GridSite_ID *) tlvh;
  set_grid_tlv_GridSite_ID(gn_site, ntohl(top->id));
  return GRID_TLV_SIZE (tlvh);
}

static uint16_t
stream_to_struct_grid_tlv_GridSite_Name_FromTlv(struct grid_node_site *gn_site, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridSite_Name *top;
  top = (struct grid_tlv_GridSite_Name *) tlvh;

  int len = ntohs(top->header.length);
  char *name = XMALLOC(MTYPE_OSPF_STR_CHAR, len+1);
  int i;
  char* ptr = (char*) &top->name;
  for (i=0; i< len; i++)
  {
    name[i] = *(ptr++);
  }
  name[len] = '\0';
  set_grid_tlv_GridSite_Name(gn_site, name);
  XFREE(MTYPE_OSPF_STR_CHAR, name);
  return GRID_TLV_SIZE (tlvh);
}

static uint16_t
stream_to_struct_grid_tlv_GridSite_Latitude(struct grid_node_site *gn_site, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridSite_Latitude *top;
  top = (struct grid_tlv_GridSite_Latitude *) tlvh;
  int i;
  u_int8_t lat[5];

  for (i=0; i<5; i++)
  {
    lat[i] = (u_int8_t)top->latitude[4-i];
  }
  set_grid_tlv_GridSite_Latitude(gn_site,lat);

  return GRID_TLV_SIZE (tlvh);
}

static uint16_t
stream_to_struct_grid_tlv_GridSite_Longitude(struct grid_node_site *gn_site, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridSite_Longitude *top;
  top = (struct grid_tlv_GridSite_Longitude *) tlvh;
  int i;
  u_int8_t lon[5];

  for (i=0; i<5; i++)
  {
    lon[i] = (uint8_t)top->longitude[4-i];
  }
  set_grid_tlv_GridSite_Longitude(gn_site,lon);

  return GRID_TLV_SIZE (tlvh);
}

static uint16_t
stream_to_struct_grid_tlv_GridSite_PE_Router_ID(struct grid_node_site *gn_site, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridSite_PE_Router_ID *top;
  top = (struct grid_tlv_GridSite_PE_Router_ID *) tlvh;
  set_grid_tlv_GridSite_PE_Router_ID(gn_site, top->routerID);
  return GRID_TLV_SIZE (tlvh);
}

uint16_t
stream_to_struct_grid_tlv_GridSite (struct grid_node_site *gn_site, struct grid_tlv_header *tlvh0, u_int16_t subtotal, u_int16_t total)
{
  struct grid_tlv_header *tlvh;
  u_int16_t sum = subtotal;
  for (tlvh = tlvh0; sum < total; tlvh = GRID_TLV_HDR_NEXT (tlvh))
  {
    switch (ntohs (tlvh->type))
    {
      case GRID_TLV_GRIDSITE_ID:      /* Unique Identifier of the Site */
        sum += stream_to_struct_grid_tlv_GridSite_ID(gn_site, tlvh);
        break;
      case GRID_TLV_GRIDSITE_NAME:      /* Human-readable name */
        sum += stream_to_struct_grid_tlv_GridSite_Name_FromTlv(gn_site, tlvh);
        break;
      case GRID_TLV_GRIDSITE_LATITUDE:      /* Degree the position of a place north or south of the equator */
        sum += stream_to_struct_grid_tlv_GridSite_Latitude(gn_site, tlvh);
        break;
      case GRID_TLV_GRIDSITE_LONGITUDE:      /* Degree the position of a place east or west of Greenwich */
        sum += stream_to_struct_grid_tlv_GridSite_Longitude(gn_site, tlvh);
        break;
      case GRID_TLV_GRIDSITE_PEROUTERID:      /* PE router ID */
        sum += stream_to_struct_grid_tlv_GridSite_PE_Router_ID(gn_site, tlvh);
        break;
      default:
        sum += stream_to_struct_unknown_tlv (tlvh);
    }
  }
  return sum - subtotal;
}

static uint16_t
stream_to_struct_grid_tlv_GridService_ID(struct grid_node_service *gn_service, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridService_ID *top;
  top = (struct grid_tlv_GridService_ID *) tlvh;
  set_grid_tlv_GridService_ID(gn_service, ntohl(top->id));
  return GRID_TLV_SIZE (tlvh);
}
static uint16_t
stream_to_struct_grid_tlv_GridService_ParentSite_ID(struct grid_node_service *gn_service, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridService_ParentSite_ID *top;
  top = (struct grid_tlv_GridService_ParentSite_ID *) tlvh;
  set_grid_tlv_GridService_ParentSite_ID(gn_service, ntohl(top->parent_site_id));
  return GRID_TLV_SIZE (tlvh);
}
static uint16_t
stream_to_struct_grid_tlv_GridService_ServiceInfo(struct grid_node_service *gn_service, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridService_ServiceInfo *top;
  top = (struct grid_tlv_GridService_ServiceInfo *) tlvh;
  set_grid_tlv_GridService_ServiceInfo(gn_service, ntohs(top->type), ntohs(top->version));
  return GRID_TLV_SIZE (tlvh);
}
static uint16_t
stream_to_struct_grid_tlv_GridService_Status(struct grid_node_service *gn_service, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridService_Status *top;
  top = (struct grid_tlv_GridService_Status *) tlvh;
  set_grid_tlv_GridService_Status(gn_service, top->status);
  return GRID_TLV_SIZE (tlvh);
}
static uint16_t
stream_to_struct_grid_tlv_GridService_AddressLength(struct grid_node_service *gn_service, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridService_AddressLength *top;
  top = (struct grid_tlv_GridService_AddressLength *) tlvh;
  set_grid_tlv_GridService_AddressLength(gn_service, top->addressLength);
  return GRID_TLV_SIZE (tlvh);
}
static uint16_t
stream_to_struct_grid_tlv_GridService_IPv4Endpoint(struct grid_node_service *gn_service, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridService_IPv4Endpoint *top;
  top = (struct grid_tlv_GridService_IPv4Endpoint *) tlvh;
  set_grid_tlv_GridService_IPv4Endpoint(gn_service, top->ipv4Endp);
  return GRID_TLV_SIZE (tlvh);
}
static uint16_t
stream_to_struct_grid_tlv_GridService_IPv6Endpoint(struct grid_node_service *gn_service, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridService_IPv6Endpoint *top;
  top = (struct grid_tlv_GridService_IPv6Endpoint *) tlvh;
  set_grid_tlv_GridService_IPv6Endpoint(gn_service, top->ipv6Endp);
  return GRID_TLV_SIZE (tlvh);
}
static uint16_t
stream_to_struct_grid_tlv_GridService_NsapEndpoint(struct grid_node_service *gn_service, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridService_NsapEndpoint *top;
  top = (struct grid_tlv_GridService_NsapEndpoint *) tlvh;
  int i;
  u_int32_t adr[5];
  for (i=0; i<5; i++)
  {
     adr[i] = (u_int32_t) ntohl (top->nsapEndp[4-i]);
  }
  set_grid_tlv_GridService_NsapEndpoint(gn_service, adr);
  return GRID_TLV_SIZE (tlvh);
}

uint16_t
stream_to_struct_grid_tlv_GridService (struct grid_node_service *gn_service, struct grid_tlv_header *tlvh0, u_int16_t subtotal, u_int16_t total)
{
  struct grid_tlv_header *tlvh;
  u_int16_t sum = subtotal;

  for (tlvh = tlvh0; sum < total; tlvh = GRID_TLV_HDR_NEXT (tlvh))
  {
    switch (ntohs (tlvh->type))
    {
      case GRID_TLV_GRIDSERVICE_ID:      /* Unique Identifier of the Service */
        sum += stream_to_struct_grid_tlv_GridService_ID(gn_service, tlvh);
        break;
      case GRID_TLV_GRIDSERVICE_PARENTSITE_ID:      /* Identifier of the Grid Site that is exporting this service */
        sum += stream_to_struct_grid_tlv_GridService_ParentSite_ID(gn_service, tlvh);
        break;
      case GRID_TLV_GRIDSERVICE_SERVICEINFO:      /* The service info including service type and version */
        sum += stream_to_struct_grid_tlv_GridService_ServiceInfo(gn_service, tlvh);
        break;
      case GRID_TLV_GRIDSERVICE_STATUS:      /* Status of the service */
        sum += stream_to_struct_grid_tlv_GridService_Status(gn_service, tlvh);
        break;
      case GRID_TLV_GRIDSERVICE_ADDRESSLENGTH:      /* Length of the endpoint address */
        sum += stream_to_struct_grid_tlv_GridService_AddressLength(gn_service, tlvh);
        break;
      case GRID_TLV_GRIDSERVICE_IPV4ENDPOINT:      /* Network endpoint for this service */
        sum += stream_to_struct_grid_tlv_GridService_IPv4Endpoint(gn_service, tlvh);
        break;
      case GRID_TLV_GRIDSERVICE_IPV6ENDPOINT:      /* Network endpoint for this service */
        sum += stream_to_struct_grid_tlv_GridService_IPv6Endpoint(gn_service, tlvh);
        break;
      case GRID_TLV_GRIDSERVICE_NSAPENDPOINT:      /* Network endpoint for this service */
        sum += stream_to_struct_grid_tlv_GridService_NsapEndpoint(gn_service, tlvh);
        break;
      default:
        sum += stream_to_struct_unknown_tlv (tlvh);
    }
  }
  return sum - subtotal;
}

static uint16_t
stream_to_struct_grid_tlv_GridComputingElement_ID(struct grid_node_computing *gn_computing, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridComputingElement_ID *top;
  top = (struct grid_tlv_GridComputingElement_ID *) tlvh;
  set_grid_tlv_GridComputingElement_ID(gn_computing, ntohl(top->id));
  return GRID_TLV_SIZE (tlvh);
}

static uint16_t
stream_to_struct_grid_tlv_GridComputingElement_ParentSiteID(struct grid_node_computing *gn_computing, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridComputingElement_ParentSiteID *top;
  top = (struct grid_tlv_GridComputingElement_ParentSiteID *) tlvh;
  set_grid_tlv_GridComputingElement_ParentSiteID(gn_computing, ntohl(top->parSiteId));
  return GRID_TLV_SIZE (tlvh);
}
static uint16_t
stream_to_struct_grid_tlv_GridComputingElement_LrmsInfo(struct grid_node_computing *gn_computing, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridComputingElement_LrmsInfo *top;
  top = (struct grid_tlv_GridComputingElement_LrmsInfo *) tlvh;
  set_grid_tlv_GridComputingElement_LrmsInfo(gn_computing, ntohs(top->lrmsType), ntohs(top->lrmsVersion));
  return GRID_TLV_SIZE (tlvh);
}
static uint16_t
stream_to_struct_grid_tlv_GridComputingElement_AddressLength(struct grid_node_computing *gn_computing, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridComputingElement_AddressLength *top;
  top = (struct grid_tlv_GridComputingElement_AddressLength *) tlvh;
  set_grid_tlv_GridComputingElement_AddressLength(gn_computing, top->addrLength);
  return GRID_TLV_SIZE (tlvh);
}
static uint16_t
stream_to_struct_grid_tlv_GridComputingElement_IPv4HostName(struct grid_node_computing *gn_computing, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridComputingElement_IPv4HostName *top;
  top = (struct grid_tlv_GridComputingElement_IPv4HostName *) tlvh;
  set_grid_tlv_GridComputingElement_IPv4HostName(gn_computing, top->ipv4HostNam);
  return GRID_TLV_SIZE (tlvh);
}
static uint16_t
stream_to_struct_grid_tlv_GridComputingElement_IPv6HostName(struct grid_node_computing *gn_computing, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridComputingElement_IPv6HostName *top;
  top = (struct grid_tlv_GridComputingElement_IPv6HostName *) tlvh;
  set_grid_tlv_GridComputingElement_IPv6HostName(gn_computing, top->ipv6HostNam);
  return GRID_TLV_SIZE (tlvh);
}
static uint16_t
stream_to_struct_grid_tlv_GridComputingElement_NsapHostName(struct grid_node_computing *gn_computing, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridComputingElement_NsapHostName *top;
  top = (struct grid_tlv_GridComputingElement_NsapHostName *) tlvh;
  int i;
  u_int32_t adr[5];
  for (i=0; i<5; i++)
  {
    adr[i] = (u_int32_t) ntohl (top->nsapHostNam[4-i]);
  }
  set_grid_tlv_GridComputingElement_NsapHostName(gn_computing, adr);
  return GRID_TLV_SIZE (tlvh);
}
static u_int16_t
stream_to_struct_grid_tlv_GridComputingElement_GatekeeperPort(struct grid_node_computing *gn_computing, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridComputingElement_GatekeeperPort *top;
  top = (struct grid_tlv_GridComputingElement_GatekeeperPort *) tlvh;
  set_grid_tlv_GridComputingElement_GatekeeperPort(gn_computing, ntohl(top->gateKPort));
  return GRID_TLV_SIZE (tlvh);
}

static uint16_t
stream_to_struct_grid_tlv_GridComputingElement_JobManager_FromTlv(struct grid_node_computing *gn_computing, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridComputingElement_JobManager *top;
  top = (struct grid_tlv_GridComputingElement_JobManager *) tlvh;
  int len = ntohs(top->header.length);
  char* jman = XMALLOC(MTYPE_OSPF_STR_CHAR, len+1);
  int i;
  char* ptr = (char*) &top->jobManag;
  for (i=0; i< len; i++)
  {
    jman[i] = *(ptr++);
  }
  jman[len] = '\0';
  set_grid_tlv_GridComputingElement_JobManager(gn_computing, jman);
  XFREE(MTYPE_OSPF_STR_CHAR, jman);
  return GRID_TLV_SIZE (tlvh);
}

static uint16_t
stream_to_struct_grid_tlv_GridComputingElement_DataDir_FromTlv(struct grid_node_computing *gn_computing, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridComputingElement_DataDir *top;
  top = (struct grid_tlv_GridComputingElement_DataDir *) tlvh;
  int len = ntohs(top->header.length);
  char* datd = XMALLOC(MTYPE_OSPF_STR_CHAR, len+1);
  int i;
  char* ptr = (char*) &top->dataDirStr;
  for (i=0; i< len; i++)
  {
    datd[i] = *(ptr++);
  }
  datd[len] = '\0';
  set_grid_tlv_GridComputingElement_DataDir(gn_computing, datd);
  XFREE(MTYPE_OSPF_STR_CHAR, datd);
  return GRID_TLV_SIZE (tlvh);
}
static uint16_t
stream_to_struct_grid_tlv_GridComputingElement_DefaultStorageElement(struct grid_node_computing *gn_computing, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridComputingElement_DefaultStorageElement *top;
  top = (struct grid_tlv_GridComputingElement_DefaultStorageElement *) tlvh;
  set_grid_tlv_GridComputingElement_DefaultStorageElement(gn_computing, ntohl(top->defaultSelement));
  return GRID_TLV_SIZE (tlvh);
}
static uint16_t
stream_to_struct_grid_tlv_GridComputingElement_JobsStates(struct grid_node_computing *gn_computing, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridComputingElement_JobsStates *top;
  top = (struct grid_tlv_GridComputingElement_JobsStates *) tlvh;
  set_grid_tlv_GridComputingElement_JobsStates(gn_computing, ntohs(top->freeJobSlots), top->status);
  return GRID_TLV_SIZE (tlvh);
}

static uint16_t
stream_to_struct_grid_tlv_GridComputingElement_JobsStats(struct grid_node_computing *gn_computing, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridComputingElement_JobsStats *top;
  top = (struct grid_tlv_GridComputingElement_JobsStats *) tlvh;
  set_grid_tlv_GridComputingElement_JobsStats(gn_computing, ntohl(top->runningJobs), ntohl(top->waitingJobs), ntohl(top->totalJobs));
  return GRID_TLV_SIZE (tlvh);
}
static uint16_t
stream_to_struct_grid_tlv_GridComputingElement_JobsTimePerformances(struct grid_node_computing *gn_computing, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridComputingElement_JobsTimePerformances *top;
  top = (struct grid_tlv_GridComputingElement_JobsTimePerformances *) tlvh;
  set_grid_tlv_GridComputingElement_JobsTimePerformances(gn_computing, ntohl(top->estRespTime), ntohl(top->worstRespTime));
  return GRID_TLV_SIZE (tlvh);
}
static uint16_t
stream_to_struct_grid_tlv_GridComputingElement_JobsTimePolicy(struct grid_node_computing *gn_computing, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridComputingElement_JobsTimePolicy *top;
  top = (struct grid_tlv_GridComputingElement_JobsTimePolicy *) tlvh;
  set_grid_tlv_GridComputingElement_JobsTimePolicy(gn_computing, ntohl(top->maxWcTime), ntohl(top->maxObtWcTime), ntohl(top->maxCpuTime), ntohl(top->maxObtCpuTime));
  return GRID_TLV_SIZE (tlvh);
}
static uint16_t
stream_to_struct_grid_tlv_GridComputingElement_JobsLoadPolicy(struct grid_node_computing *gn_computing, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridComputingElement_JobsLoadPolicy *top;
  top = (struct grid_tlv_GridComputingElement_JobsLoadPolicy *) tlvh;
  set_grid_tlv_GridComputingElement_JobsLoadPolicy(gn_computing, ntohl(top->maxTotalJobs), ntohl(top->maxRunJobs), ntohl(top->maxWaitJobs), ntohs(top->assignJobSlots), ntohs(top->maxSlotsPerJob), top->priorityPreemptionFlag);
  return GRID_TLV_SIZE (tlvh);
}

static uint16_t
stream_to_struct_grid_tlv_GridComputingElement_CeCalendar_FromTlv(struct grid_node_computing *gn_computing, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridComputingElement_CeCalendar *top;
  top = (struct grid_tlv_GridComputingElement_CeCalendar *) tlvh;
  set_grid_tlv_GridComputingElement_CeCalendar(gn_computing, CLEAR, NULL);
  struct ce_calendar* ce_cal = NULL;
  int len = ntohs(top->header.length) - GRID_TLV_GRIDCOMPUTINGELEMENT_CECALENDAR_CONST_DATA_LENGTH;
  int i;
  struct ce_calendar* ptr = (struct ce_calendar*) (void *) &top->ceCalend;
  for (i=0; i< len-2; i=i+6)
  {
    ce_cal = XMALLOC (MTYPE_OSPF_GRID_COMPUTING_CALENDAR, sizeof(struct ce_calendar));
    ce_cal->time = ptr->time;
    ce_cal->freeJobSlots = ptr->freeJobSlots;
    set_grid_tlv_GridComputingElement_CeCalendar(gn_computing, ADD, (void *) ce_cal);
    ptr++;
  }
  return GRID_TLV_SIZE (tlvh);
}

uint16_t
stream_to_struct_grid_tlv_GridComputingElement (struct grid_node_computing *gn_computing, struct grid_tlv_header *tlvh0, u_int16_t subtotal, u_int16_t total)
{
  struct grid_tlv_header *tlvh;
  u_int16_t sum = subtotal;
  for (tlvh = tlvh0; sum < total; tlvh = GRID_TLV_HDR_NEXT (tlvh))
  {
    switch (ntohs (tlvh->type))
    {
      case GRID_TLV_GRIDCOMPUTINGELEMENT_ID:      /* Unique Identifier of the Computing Element */
        sum += stream_to_struct_grid_tlv_GridComputingElement_ID(gn_computing, tlvh);
        break;
      case GRID_TLV_GRIDCOMPUTINGELEMENT_PARENTSITEID:      /* Identifier of the Grid Site that is exporting this computing element */
        sum += stream_to_struct_grid_tlv_GridComputingElement_ParentSiteID(gn_computing, tlvh);
        break;
      case GRID_TLV_GRIDCOMPUTINGELEMENT_LRMSINFO:      /* Type and version of the underlying LRMS */
        sum += stream_to_struct_grid_tlv_GridComputingElement_LrmsInfo(gn_computing, tlvh);
        break;
      case GRID_TLV_GRIDCOMPUTINGELEMENT_ADDRESSLENGTH:      /* Length of the host name address */
        sum += stream_to_struct_grid_tlv_GridComputingElement_AddressLength(gn_computing, tlvh);
        break;
      case GRID_TLV_GRIDCOMPUTINGELEMENT_IPV4HOSTNAME:      /* Host name of the machine running this service */
        sum += stream_to_struct_grid_tlv_GridComputingElement_IPv4HostName(gn_computing, tlvh);
        break;
      case GRID_TLV_GRIDCOMPUTINGELEMENT_IPV6HOSTNAME:      /* Host name of the machine running this service */
        sum += stream_to_struct_grid_tlv_GridComputingElement_IPv6HostName(gn_computing, tlvh);
        break;
      case GRID_TLV_GRIDCOMPUTINGELEMENT_NSAPHOSTNAME:      /* Host name of the machine running this service */
        sum += stream_to_struct_grid_tlv_GridComputingElement_NsapHostName(gn_computing, tlvh);
        break;
      case GRID_TLV_GRIDCOMPUTINGELEMENT_GATEKEEPERPORT:      /* Gatekeeper port */
        sum += stream_to_struct_grid_tlv_GridComputingElement_GatekeeperPort(gn_computing, tlvh);
        break;
      case GRID_TLV_GRIDCOMPUTINGELEMENT_JOBMANAGER:      /* The job manager used by the gatekeeper */
        sum += stream_to_struct_grid_tlv_GridComputingElement_JobManager_FromTlv(gn_computing, tlvh);
        break;
      case GRID_TLV_GRIDCOMPUTINGELEMENT_DATADIR:      /* String representing the path of a run directory */
        sum += stream_to_struct_grid_tlv_GridComputingElement_DataDir_FromTlv(gn_computing, tlvh);
        break;
      case GRID_TLV_GRIDCOMPUTINGELEMENT_DEFAULTSTORAGEELEMENT:      /* The unique identifier of the default Storage Element */
        sum += stream_to_struct_grid_tlv_GridComputingElement_DefaultStorageElement(gn_computing, tlvh);
        break;
      case GRID_TLV_GRIDCOMPUTINGELEMENT_JOBSSTATES:      /* It contains the number of free job slots, and the queue status */
        sum += stream_to_struct_grid_tlv_GridComputingElement_JobsStates(gn_computing, tlvh);
        break;
      case GRID_TLV_GRIDCOMPUTINGELEMENT_JOBSSTATS:      /* It contains the number of jobs in running, waiting, any state */
        sum += stream_to_struct_grid_tlv_GridComputingElement_JobsStats(gn_computing, tlvh);
        break;
      case GRID_TLV_GRIDCOMPUTINGELEMENT_JOBSTIMEPERFORMANCES:      /* The estimated time and the worst time to last for a new job from the acceptance to the start of its execution */
        sum += stream_to_struct_grid_tlv_GridComputingElement_JobsTimePerformances(gn_computing, tlvh);
        break;
      case GRID_TLV_GRIDCOMPUTINGELEMENT_JOBSTIMEPOLICY:
        sum += stream_to_struct_grid_tlv_GridComputingElement_JobsTimePolicy(gn_computing, tlvh);
        break;
      case GRID_TLV_GRIDCOMPUTINGELEMENT_JOBSLOADPOLICY:      /* Jobs Load Policy */
        sum += stream_to_struct_grid_tlv_GridComputingElement_JobsLoadPolicy(gn_computing, tlvh);
        break;
      case GRID_TLV_GRIDCOMPUTINGELEMENT_CECALENDAR:
        sum += stream_to_struct_grid_tlv_GridComputingElement_CeCalendar_FromTlv(gn_computing, tlvh);
        break;
      default:
        sum += stream_to_struct_unknown_tlv (tlvh);
    }
  }
  return sum - subtotal;
}

static uint16_t
stream_to_struct_grid_tlv_GridSubCluster_ID(struct grid_node_subcluster *gn_subcluster, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridSubCluster_ID *top;
  top = (struct grid_tlv_GridSubCluster_ID *) tlvh;
  set_grid_tlv_GridSubCluster_ID(gn_subcluster, ntohl(top->id));
  return GRID_TLV_SIZE (tlvh);
}
static uint16_t
stream_to_struct_grid_tlv_GridSubCluster_ParentSiteID(struct grid_node_subcluster *gn_subcluster, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridSubCluster_ParentSiteID *top;
  top = (struct grid_tlv_GridSubCluster_ParentSiteID *) tlvh;
  set_grid_tlv_GridSubCluster_ParentSiteID(gn_subcluster, ntohl(top->parSiteId));
  return GRID_TLV_SIZE (tlvh);
}
static uint16_t
stream_to_struct_grid_tlv_GridSubCluster_CpuInfo(struct grid_node_subcluster *gn_subcluster, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridSubCluster_CpuInfo *top;
  top = (struct grid_tlv_GridSubCluster_CpuInfo *) tlvh;
  set_grid_tlv_GridSubCluster_CpuInfo(gn_subcluster, ntohl(top->physicalCpus), ntohl(top->logicalCpus), (top->cpuArch));
  return GRID_TLV_SIZE (tlvh);
}
static uint16_t
stream_to_struct_grid_tlv_GridSubCluster_OsInfo(struct grid_node_subcluster *gn_subcluster, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridSubCluster_OsInfo *top;
  top = (struct grid_tlv_GridSubCluster_OsInfo *) tlvh;
  set_grid_tlv_GridSubCluster_OsInfo(gn_subcluster, ntohs(top->osType), ntohs(top->osVersion));
  return GRID_TLV_SIZE (tlvh);
}
static uint16_t
stream_to_struct_grid_tlv_GridSubCluster_MemoryInfo(struct grid_node_subcluster *gn_subcluster, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridSubCluster_MemoryInfo *top;
  top = (struct grid_tlv_GridSubCluster_MemoryInfo *) tlvh;
  set_grid_tlv_GridSubCluster_MemoryInfo(gn_subcluster, ntohl(top->ramSize), ntohl(top->virtualMemorySize));
  return GRID_TLV_SIZE (tlvh);
}

static uint16_t
stream_to_struct_grid_tlv_GridSubCluster_SoftwarePackage_FromTlv(struct grid_node_subcluster *gn_subcluster, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridSubCluster_SoftwarePackage *top;
  top = (struct grid_tlv_GridSubCluster_SoftwarePackage *) tlvh;
  int len = ntohs(top->header.length);
  char* env = XMALLOC(MTYPE_OSPF_STR_CHAR, len+1);
  int i;
  char* ptr = (char*) &top->environmentSetup;
  for (i=0; i< len; i++)
  {
    env[i] = *(ptr++);
  }
  env[len] = '\0';
  struct grid_tlv_GridSubCluster_SoftwarePackage *sp= create_grid_tlv_GridSubCluster_SoftwarePackage(ntohs(top->softType), ntohs(top->softVersion), env);
  set_grid_tlv_GridSubCluster_SoftwarePackage(gn_subcluster, ADD, sp);
  return GRID_TLV_SIZE (tlvh);
}

static uint16_t
stream_to_struct_grid_tlv_GridSubCluster_SubClusterCalendar_FromTlv(struct grid_node_subcluster *gn_subcluster, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridSubCluster_SubClusterCalendar *top;
  top = (struct grid_tlv_GridSubCluster_SubClusterCalendar *) tlvh;
  set_grid_tlv_GridSubCluster_SubClusterCalendar(gn_subcluster, CLEAR, NULL);
  struct sc_calendar *sc_cal = NULL;
  int len = ntohs(top->header.length) - GRID_TLV_GRIDSUBCLUSTER_SUBCLUSTERCALENDAR_CONST_DATA_LENGTH;
  int i;
  struct sc_calendar* ptr = (struct sc_calendar*) (void *) &top->subcluster_calendar;
  for (i=0; i< len; i=i+8)
  {
    sc_cal = XMALLOC (MTYPE_OSPF_GRID_SUBCLUSTER_CALENDAR, sizeof(struct sc_calendar));
    sc_cal->time = ptr->time;
    sc_cal->physical_cpus = ptr->physical_cpus;
    sc_cal->logical_cpus = ptr->logical_cpus;
    set_grid_tlv_GridSubCluster_SubClusterCalendar(gn_subcluster, ADD, (void *) sc_cal);
    ptr++;
  }
  return GRID_TLV_SIZE (tlvh);
}

uint16_t
stream_to_struct_grid_tlv_GridSubCluster (struct grid_node_subcluster *gn_subcluster, struct grid_tlv_header *tlvh0, u_int16_t subtotal, u_int16_t total)
{
  struct grid_tlv_header *tlvh;
  u_int16_t sum = subtotal;

  for (tlvh = tlvh0; sum < total; tlvh = GRID_TLV_HDR_NEXT (tlvh))
  {
    switch (ntohs (tlvh->type))
    {
      case GRID_TLV_GRIDSUBCLUSTER_ID:      /* Unique Identifier of the Sub-Cluster */
        sum += stream_to_struct_grid_tlv_GridSubCluster_ID(gn_subcluster, tlvh);
        break;
      case GRID_TLV_GRIDSUBCLUSTER_PARENTSITEID:      /* Identifier of the Grid Site that is exporting this sub-cluster */
        sum += stream_to_struct_grid_tlv_GridSubCluster_ParentSiteID(gn_subcluster, tlvh);
        break;
      case GRID_TLV_GRIDSUBCLUSTER_CPUINFO:      /* The CPU architecture, the total and the effective number of CPUs */
        sum += stream_to_struct_grid_tlv_GridSubCluster_CpuInfo(gn_subcluster, tlvh);
        break;
      case GRID_TLV_GRIDSUBCLUSTER_OSINFO:      /* Information about the type of the OS and its version */
        sum += stream_to_struct_grid_tlv_GridSubCluster_OsInfo(gn_subcluster, tlvh);
        break;
      case GRID_TLV_GRIDSUBCLUSTER_MEMORYINFO:      /* The amount of RAM and Virtual Memory (in MB) */
        sum += stream_to_struct_grid_tlv_GridSubCluster_MemoryInfo(gn_subcluster, tlvh);
        break;
      case GRID_TLV_GRIDSUBCLUSTER_SOFTWAREPACKAGE:
        sum += stream_to_struct_grid_tlv_GridSubCluster_SoftwarePackage_FromTlv(gn_subcluster, tlvh);
        break;
      case GRID_TLV_GRIDSUBCLUSTER_SUBCLUSTERCALENDAR:
        sum += stream_to_struct_grid_tlv_GridSubCluster_SubClusterCalendar_FromTlv(gn_subcluster, tlvh);
        break;
      default:
        sum += stream_to_struct_unknown_tlv (tlvh);
    }
  }
  return sum - subtotal;
}

static uint16_t
stream_to_struct_grid_tlv_GridStorage_ID(struct grid_node_storage *gn_storage, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridStorage_ID *top;
  top = (struct grid_tlv_GridStorage_ID *) tlvh;
  set_grid_tlv_GridStorage_ID(gn_storage, ntohl(top->id));
  return GRID_TLV_SIZE (tlvh);
}
static u_int16_t
stream_to_struct_grid_tlv_GridStorage_ParentSiteID(struct grid_node_storage *gn_storage, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridStorage_ParentSiteID *top;
  top = (struct grid_tlv_GridStorage_ParentSiteID *) tlvh;
  set_grid_tlv_GridStorage_ParentSiteID(gn_storage, ntohl(top->parSiteId));
  return GRID_TLV_SIZE(tlvh);
}
static u_int16_t
stream_to_struct_grid_tlv_GridStorage_StorageInfo(struct grid_node_storage *gn_storage, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridStorage_StorageInfo *top;
  top = (struct grid_tlv_GridStorage_StorageInfo *) tlvh;
  set_grid_tlv_GridStorage_StorageInfo(gn_storage, ntohl(top->storInfo));
  return GRID_TLV_SIZE (tlvh);
}
static u_int16_t
stream_to_struct_grid_tlv_GridStorage_OnlineSize(struct grid_node_storage *gn_storage, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridStorage_OnlineSize *top;
  top = (struct grid_tlv_GridStorage_OnlineSize *) tlvh;
  set_grid_tlv_GridStorage_OnlineSize(gn_storage, ntohl(top->totalSize), ntohl(top->usedSize));
  return GRID_TLV_SIZE (tlvh);
}
static uint16_t
stream_to_struct_grid_tlv_GridStorage_NearlineSize(struct grid_node_storage *gn_storage, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridStorage_NearlineSize *top;
  top = (struct grid_tlv_GridStorage_NearlineSize *) tlvh;
  set_grid_tlv_GridStorage_NearlineSize(gn_storage, ntohl(top->totalSize), ntohl(top->usedSize));
  return GRID_TLV_SIZE (tlvh);
}

static uint16_t
stream_to_struct_grid_tlv_GridStorage_StorageArea_FromTlv(struct grid_node_storage *gn_storage, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridStorage_StorageArea *top, *top_after_lists;
  top = (struct grid_tlv_GridStorage_StorageArea *) tlvh;

  int i;
  i = 0;
  int len = ntohs(top->header.length);
  char *nam = XMALLOC(MTYPE_OSPF_STR_CHAR, len);
  char *pat = XMALLOC(MTYPE_OSPF_STR_CHAR, len);

  char* ptr = (char*) &top->name;
  int write_list = 1;
  while ((write_list == 1) || (i%4 != 0))
  {
    if (*(ptr) == '\0')
      write_list = 0;
    else
      nam[i] = *(ptr);
    ptr++;
    i++;
  }
  nam[i] = '\0';

  int off = i;
  write_list = 1;
  while ((write_list == 1) || (i%4 != 0))
  {
    if (*(ptr) == '\0')
      write_list = 0;
    else
      pat[i-off] =  *(ptr);
    ptr++;
    i++;
  }
  pat[i-off] = '\0';

  char *offset = (char *)(top) + i - 2 * sizeof(struct zlist);
  top_after_lists = (struct grid_tlv_GridStorage_StorageArea *) offset;

  struct grid_tlv_GridStorage_StorageArea* sa = create_grid_tlv_GridStorage_StorageArea ( nam, pat, ntohl(top_after_lists->totalOnlineSize), ntohl(top_after_lists->freeOnlineSize), ntohl(top_after_lists->resTotalOnlineSize), ntohl(top_after_lists->totalNearlineSize), ntohl(top_after_lists->freeNearlineSize), ntohl(top_after_lists->resNearlineSize), top_after_lists->retPolAccLat, top_after_lists->expirationMode);

  set_grid_tlv_GridStorage(gn_storage, ADD, sa);

  return GRID_TLV_SIZE (tlvh);
}

static uint16_t
stream_to_struct_grid_tlv_GridStorage_SeCalendar_FromTlv(struct grid_node_storage *gn_storage, struct grid_tlv_header *tlvh)
{
  struct grid_tlv_GridStorage_SeCalendar *top;
  top = (struct grid_tlv_GridStorage_SeCalendar *) tlvh;
  set_grid_tlv_GridStorage_SeCalendar(gn_storage, CLEAR, NULL);
  struct se_calendar *se_cal = NULL;
  int len = ntohs(top->header.length) - GRID_TLV_GRIDSTORAGE_SECALENDAR_CONST_DATA_LENGTH;
  int i;
  struct se_calendar* ptr = (struct se_calendar*) (void *) &top->seCalendar;
  for (i=0; i< len; i=i+12)
  {
    se_cal = XMALLOC(MTYPE_OSPF_GRID_SERVICE_CALENDAR, sizeof(struct se_calendar));
    se_cal->time = ptr->time;
    se_cal->freeOnlineSize = ptr->freeOnlineSize;
    se_cal->freeNearlineSize = ptr->freeNearlineSize;
    set_grid_tlv_GridStorage_SeCalendar(gn_storage, ADD, (void *)se_cal);
    ptr++;
  }
  return GRID_TLV_SIZE (tlvh);
}
uint16_t
stream_to_struct_grid_tlv_GridStorage (struct grid_node_storage *gn_storage, struct grid_tlv_header *tlvh0, u_int16_t subtotal, u_int16_t total)
{
  struct grid_tlv_header *tlvh;
  u_int16_t sum = subtotal;

  set_grid_tlv_GridStorage(gn_storage, CLEAR, NULL);
  for (tlvh = tlvh0; sum < total; tlvh = GRID_TLV_HDR_NEXT (tlvh))
  {
    switch (ntohs (tlvh->type))
    {
      case GRID_TLV_GRIDSTORAGE_ID:      /* Unique Identifier of the Storage Element */
        sum += stream_to_struct_grid_tlv_GridStorage_ID(gn_storage, tlvh);
        break;
      case GRID_TLV_GRIDSTORAGE_PARENTSITEID:      /* Identifier of the Grid Site that is exporting this storage */
        sum += stream_to_struct_grid_tlv_GridStorage_ParentSiteID(gn_storage, tlvh);
        break;
      case GRID_TLV_GRIDSTORAGE_STORAGEINFO:
        sum += stream_to_struct_grid_tlv_GridStorage_StorageInfo(gn_storage, tlvh);
        break;
      case GRID_TLV_GRIDSTORAGE_ONLINESIZE:      /* The online storage sizes (total + used) in GB */
        sum += stream_to_struct_grid_tlv_GridStorage_OnlineSize(gn_storage, tlvh);
        break;
      case GRID_TLV_GRIDSTORAGE_NEARLINESIZE:      /* The nearline storage sizes (total + used) in GB */
        sum += stream_to_struct_grid_tlv_GridStorage_NearlineSize(gn_storage, tlvh);
        break;
      case GRID_TLV_GRIDSTORAGE_STORAGEAREA:
        sum += stream_to_struct_grid_tlv_GridStorage_StorageArea_FromTlv(gn_storage, tlvh);
        break;
      case GRID_TLV_GRIDSTORAGE_SECALENDAR:
        sum += stream_to_struct_grid_tlv_GridStorage_SeCalendar_FromTlv(gn_storage, tlvh);
        break;
      default:
        sum += stream_to_struct_unknown_tlv (tlvh);
    }
  }
  return sum - subtotal;
}

static int
is_grid_site_id_in_tlv(uint32_t id, struct grid_tlv_header* tlvh)
{
  int len = ntohs(tlvh->length);
  int sum = 4;
  while (sum < len)
  {
    tlvh = (struct grid_tlv_header *)((char *)(tlvh) + sum);
    sum += ROUNDUP(ntohs(tlvh->length),4);
    if (ntohs(tlvh->type) == GRID_TLV_GRIDSITE_ID)
    {
      struct grid_tlv_GridSite_ID* tlvh0 = (struct grid_tlv_GridSite_ID*) tlvh;
      if (ntohl(tlvh0->id) == id)
        return 1;
    }
  }
  return 0;
}

static int
is_grid_service_id_in_tlv(uint32_t siteId, uint32_t id, struct grid_tlv_header* tlvh)
{
  int len = ntohs(tlvh->length);
  int sum = 4;
  int matchId = 0;
  int matchSiteId = 0;

  while (sum < len)
  {
    tlvh = (struct grid_tlv_header *)((char *)(tlvh) + sum);
    sum += ROUNDUP(ntohs(tlvh->length),4);
    if (ntohs(tlvh->type) == GRID_TLV_GRIDSERVICE_PARENTSITE_ID)
    {
      struct grid_tlv_GridService_ParentSite_ID* tlvh0 = (struct grid_tlv_GridService_ParentSite_ID*) tlvh;
      if (ntohl(tlvh0->parent_site_id) == id)
    {
      if (matchId == 1)
        return 1;
      matchSiteId = 1;
    }
    }

  if (ntohs(tlvh->type) == GRID_TLV_GRIDSERVICE_ID)
    {
      struct grid_tlv_GridService_ID* tlvh0 = (struct grid_tlv_GridService_ID*) tlvh;
      if (ntohl(tlvh0->id) == id)
    {
      if (matchSiteId == 1)
        return 1;
      matchId = 1;
    }
    }
  }
  return 0;
}

static int
is_grid_storage_id_in_tlv(uint32_t siteId, uint32_t id, struct grid_tlv_header* tlvh)
{
  int len = ntohs(tlvh->length);
  int sum = 4;
  int matchId = 0;
  int matchSiteId = 0;

  while (sum < len)
  {
    tlvh = (struct grid_tlv_header *)((char *)(tlvh) + sum);
    sum += ROUNDUP(ntohs(tlvh->length),4);
    if (ntohs(tlvh->type) == GRID_TLV_GRIDSTORAGE_PARENTSITEID)
    {
      struct grid_tlv_GridStorage_ParentSiteID* tlvh0 = (struct grid_tlv_GridStorage_ParentSiteID*) tlvh;
      if (ntohl(tlvh0->parSiteId) == id)
    {
      if (matchId == 1)
        return 1;
      matchSiteId = 1;
    }
    }

  if (ntohs(tlvh->type) == GRID_TLV_GRIDSTORAGE_ID)
    {
      struct grid_tlv_GridStorage_ID* tlvh0 = (struct grid_tlv_GridStorage_ID*) tlvh;
      if (ntohl(tlvh0->id) == id)
    {
      if (matchSiteId == 1)
        return 1;
      matchId = 1;
    }
    }
  }
  return 0;
}

static int
is_grid_computingElement_id_in_tlv(uint32_t siteId, uint32_t id, struct grid_tlv_header* tlvh)
{
  int len = ntohs(tlvh->length);
  int sum = 4;
  int matchId = 0;
  int matchSiteId = 0;

  while (sum < len)
  {
    tlvh = (struct grid_tlv_header *)((char *)(tlvh) + sum);
    sum += ROUNDUP(ntohs(tlvh->length),4);
    if (ntohs(tlvh->type) == GRID_TLV_GRIDCOMPUTINGELEMENT_PARENTSITEID)
    {
      struct grid_tlv_GridComputingElement_ParentSiteID* tlvh0 = (struct grid_tlv_GridComputingElement_ParentSiteID*) tlvh;
      if (ntohl(tlvh0->parSiteId) == id)
    {
      if (matchId == 1)
        return 1;
      matchSiteId = 1;
    }
    }

  if (ntohs(tlvh->type) == GRID_TLV_GRIDCOMPUTINGELEMENT_ID)
    {
      struct grid_tlv_GridComputingElement_ID* tlvh0 = (struct grid_tlv_GridComputingElement_ID*) tlvh;
      if (ntohl(tlvh0->id) == id)
    {
      if (matchSiteId == 1)
        return 1;
      matchId = 1;
    }
    }
  }
  return 0;
}

static int
is_grid_subcluster_id_in_tlv(uint32_t siteId, uint32_t id, struct grid_tlv_header* tlvh)
{
  int len = ntohs(tlvh->length);
  int sum = 4;
  int matchId = 0;
  int matchSiteId = 0;

  while (sum < len)
  {
    tlvh = (struct grid_tlv_header *)((char *)(tlvh) + sum);
    sum += ROUNDUP(ntohs(tlvh->length),4);
    if (ntohs(tlvh->type) == GRID_TLV_GRIDSUBCLUSTER_PARENTSITEID)
    {
      struct grid_tlv_GridSubCluster_ParentSiteID* tlvh0 = (struct grid_tlv_GridSubCluster_ParentSiteID*) tlvh;
      if (ntohl(tlvh0->parSiteId) == id)
    {
      if (matchId == 1)
        return 1;
      matchSiteId = 1;
    }
    }

  if (ntohs(tlvh->type) == GRID_TLV_GRIDSUBCLUSTER_ID)
    {
      struct grid_tlv_GridSubCluster_ID* tlvh0 = (struct grid_tlv_GridSubCluster_ID*) tlvh;
      if (ntohl(tlvh0->id) == id)
    {
      if (matchSiteId == 1)
        return 1;
      matchId = 1;
    }
    }
  }
  return 0;
}


struct grid_tlv_header*
get_grid_tlv_from_uni_database(uint16_t type, uint32_t siteId, uint32_t id)
{
  struct prefix_ls lp;
  struct route_node *rn, *start;
  struct ospf_lsa *lsa;
  struct ospf *ospf;
  struct ospf_area *area;
  struct zlistnode *node;
  struct lsa_header *lsah;
  struct grid_tlv_header *tlvh;

  uint16_t sum, total;

  ospf = ospf_uni_lookup();

  memset (&lp, 0, sizeof (struct prefix_ls));
  lp.family = 0;
  lp.prefixlen = 0;

  for (ALL_LIST_ELEMENTS_RO (ospf->areas, node, area))
  {
    start = route_node_get ( AREA_LSDB (area, OSPF_OPAQUE_AREA_LSA), (struct prefix *) &lp);
    if (start)
    {
      route_lock_node (start);
      for (rn = start; rn; rn = route_next_until (rn, start))
    {
    if ((lsa = rn->info))
        {
          lsah = (struct lsa_header*)(lsa->data);

          total = ntohs (lsah->length) - OSPF_LSA_HEADER_SIZE;
          sum = 0;
          tlvh = GRID_TLV_HDR_TOP (lsah);

          while (sum < total)
          {
            if (ntohs (tlvh->type) == type)
            {
              switch (type)
              {
                case GRID_TLV_GRIDSITE:
                {
                  if (is_grid_site_id_in_tlv(siteId, tlvh))
                    return tlvh;
                  break;
                }

                case GRID_TLV_GRIDSERVICE:
                {
                  if (is_grid_service_id_in_tlv(siteId, id, tlvh))
                    return tlvh;
                  break;
                }

                case GRID_TLV_GRIDSUBCLUSTER:
                {
                  if (is_grid_subcluster_id_in_tlv(siteId, id, tlvh))
                    return tlvh;
                  break;
                }

                case GRID_TLV_GRIDSTORAGE:
                {
                  if (is_grid_storage_id_in_tlv(siteId, id, tlvh))
                    return tlvh;
                  break;
                }

                case GRID_TLV_GRIDCOMPUTINGELEMENT:
                {
                  if (is_grid_computingElement_id_in_tlv(siteId, id, tlvh))
                    return tlvh;
                  break;
                }
              }
            }
            else
            {
              sum += stream_to_struct_unknown_tlv (tlvh);
            }
            tlvh = (struct grid_tlv_header *)((char *)(GRID_TLV_HDR_TOP (lsah)) + sum);
          }
        }
    }
    }
  }
  return NULL;
}

// static int update_grid_node(struct grid_node *gn, struct ospf_lsa *lsa)
// {
//   struct lsa_header *lsah = (struct lsa_header *) lsa->data;
//   struct grid_tlv_header *tlvh;
//   u_int16_t sum, total, l;
//   total = ntohs (lsah->length) - OSPF_LSA_HEADER_SIZE;
//   sum = 0;
//   tlvh = GRID_TLV_HDR_TOP (lsah);
//   while (sum < total)
//   {
//     switch (ntohs (tlvh->type))
//     {
//       case GRID_TLV_GRIDSITE:      /* Grid Side Property TLV */
//         l = ntohs (tlvh->length);
//         sum += stream_to_struct_grid_tlv_header (gn, tlvh);
//         sum += stream_to_struct_grid_tlv_GridSite (gn, tlvh+1, sum, sum + l);
//         break;
//       case GRID_TLV_GRIDSERVICE:      /* Grid Service Property TLV */
//         l = ntohs (tlvh->length);
//         sum += stream_to_struct_grid_tlv_header (gn, tlvh);
//         sum += stream_to_struct_grid_tlv_GridService (gn, tlvh+1, sum, sum + l);
//         break;
//       case GRID_TLV_GRIDCOMPUTINGELEMENT:      /* Grid Computing Element Property TLV */
//         l = ntohs (tlvh->length);
//         sum += stream_to_struct_grid_tlv_header (gn, tlvh);
//         sum += stream_to_struct_grid_tlv_GridComputingElement (gn, tlvh+1, sum, sum + l);
//         break;
//       case GRID_TLV_GRIDSUBCLUSTER:      /* Grid SubCluster Property TLV */
//         l = ntohs (tlvh->length);
// //  set_grid_tlv_GridSubCluster_SoftwarePackage(gn, CLEAR, NULL); //TODO fixit and uncomment
//         sum += stream_to_struct_grid_tlv_header (gn, tlvh);
//         sum += stream_to_struct_grid_tlv_GridSubCluster (gn, tlvh+1, sum, sum + l);
//         break;
//       case GRID_TLV_GRIDSTORAGE:      /* Grid Storage Element Property TLV */
//         l = ntohs (tlvh->length);
//         sum += stream_to_struct_grid_tlv_header (gn, tlvh);
//         sum += stream_to_struct_grid_tlv_GridStorage (gn, tlvh+1, sum, sum + l);
//         break;
//       default:
//         sum += stream_to_struct_unknown_tlv (tlvh);
//     }
//     tlvh = (struct grid_tlv_header *)((char *)(GRID_TLV_HDR_TOP (lsah)) + sum);
//   }
//   return 0;
// }

