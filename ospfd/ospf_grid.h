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

#ifndef _ZEBRA_OSPF_GRID
#define _ZEBRA_OSPF_GRID

#define USE_UNTESTED_OSPF_GRID               1
#define USE_UNTESTED_OSPF_GRID_CORBA_UPDATE  1

#ifndef TLV_HEADER_SIZE
#define TLV_HEADER_SIZE 4
#endif

#define OSPF_DEBUG_GRID_NODE_GENERATE     0x0001
#define OSPF_DEBUG_GRID_NODE_ORIGINATE    0x0002
#define OSPF_DEBUG_GRID_NODE_FLUSH        0x0004
#define OSPF_DEBUG_GRID_NODE_REFRESH      0x0008
#define OSPF_DEBUG_GRID_NODE_FEED_UP      0x0010
#define OSPF_DEBUG_GRID_NODE_FEED_DOWN    0x0020
#define OSPF_DEBUG_GRID_NODE_UNI_TO_INNI  0x0040
#define OSPF_DEBUG_GRID_NODE_INNI_TO_UNI  0x0080
#define OSPF_DEBUG_GRID_NODE_LSA_NEW      0x0100
#define OSPF_DEBUG_GRID_NODE_LSA_DELETE   0x0200
#define OSPF_DEBUG_GRID_NODE_ISM_CHANGE   0x0400
#define OSPF_DEBUG_GRID_NODE_NSM_CHANGE   0x0800
#define OSPF_DEBUG_GRID_NODE_DELETE       0x1000
#define OSPF_DEBUG_GRID_NODE_CORBA        0x2000
#define OSPF_DEBUG_GRID_NODE_CORBA_ALL    0x4000
#define OSPF_DEBUG_GRID_NODE_USER         0x8000
#define OSPF_DEBUG_GRID_NODE_ALL          0xFFFF

#define IS_DEBUG_GRID_NODE(a) \
  (OspfGRID.debug & OSPF_DEBUG_GRID_NODE_ ## a)

#define GRID_NODE_DEBUG_ON(a)  OspfGRID.debug |= (OSPF_DEBUG_GRID_NODE_ ## a)
#define GRID_NODE_DEBUG_OFF(a) OspfGRID.debug &= ~(OSPF_DEBUG_GRID_NODE_ ## a)

#ifndef TLV_GRID_HDR_TOP
#define TLV_GRID_HDR_TOP(lsah) \
  (struct grid_tlv_header *)((char *)(lsah) + OSPF_LSA_HEADER_SIZE)
#endif

/** OSPF-GRID Management */
struct ospf_grid
{
  enum { disabled, enabled } status;
  struct zlist *iflist;
  struct interface *grid_ifp;

#ifdef USE_UNTESTED_OSPF_GRID
  struct zlist *map_inni;
  struct zlist *map_enni;
  struct zlist *map_uni;
#endif /* USE_UNTESTED_OSPF_GRID */
  int debug;
};

#ifdef USE_UNTESTED_OSPF_GRID
struct instance_map_element
{
  uint32_t old_instance_no;
  uint32_t new_instance_no;
  struct in_addr adv_router;
};
#endif /* USE_UNTESTED_OSPF_GRID */

/**
 * scheduler operations
 */
enum grid_sched_opcode {
    GRID_REORIGINATE_PER_AREA, GRID_REFRESH_THIS_LSA, GRID_FLUSH_THIS_LSA
};

enum list_opcode {
    LEAVE, CLEAR, ADD, CREATE
};

/**
 * Following section defines TLV (type, length, value) structures,
 * for grid
 **/
struct grid_tlv_header
{
  u_int16_t    type;            /* GRID_TLV_XXX (see below) */
  u_int16_t    length;          /* Value portion only, in octets */
};
/*
 *        24       16        8        0
 * +--------+--------+--------+--------+ ---
 * |   LS age        |Options |   10   |  A
 * +--------+--------+--------+--------+  |
 * |   248  |         Instance         |  |
 * +--------+--------+--------+--------+  |
 * |        Advertising router         |  |  Standard (Opaque) LSA header;
 * +--------+--------+--------+--------+  |  Only type-10 is used.
 * |        LS sequence number         |  |
 * +--------+--------+--------+--------+  |
 * |   LS checksum   |     Length      |  V
 * +--------+--------+--------+--------+ ---
 * |      Type       |     Length      |  A
 * +--------+--------+--------+--------+  |  TLV part for TE; Values might be
 * |              Values ...           |  V  structured as a set of sub-TLVs.
 * +--------+--------+--------+--------+ ---
 */
#undef ROUNDUP
#define ROUNDUP(val, gran)  ((((val) - 1) | ((gran) - 1)) + 1)

#define GRID_TLV_HDR_SIZE \
    (sizeof (struct grid_tlv_header))
#define GRID_TLV_BODY_SIZE(tlvh) \
    (uint16_t)(ROUNDUP (ntohs ((tlvh)->length), sizeof (u_int32_t)))
#define GRID_TLV_SIZE(tlvh) \
    (GRID_TLV_HDR_SIZE + GRID_TLV_BODY_SIZE(tlvh))
#define GRID_TLV_HDR_TOP(lsah) \
    (struct grid_tlv_header *)((char *)(lsah) + OSPF_LSA_HEADER_SIZE)
#define GRID_TLV_HDR_NEXT(tlvh) \
    (struct grid_tlv_header *)((char *)(tlvh) + GRID_TLV_SIZE(tlvh))
#define    LEGAL_GRID_INSTANCE_RANGE(i)    (0 <= (i) && (i) <= 0xffffff)



/** *** Grid Side Property TLV *********************************** */

/**
* the routerID, as advertised by OSPF, of the  Provider Edge (PE) network element which this Grid site is attached to 
*/
#define GRID_TLV_GRIDSITE_PEROUTERID 5
#define GRID_TLV_GRIDSITE_PEROUTERID_CONST_DATA_LENGTH 4
struct grid_tlv_GridSite_PE_Router_ID
{
  struct grid_tlv_header                   header;
  struct in_addr                           routerID;
};

/**
 * Degree the position of a place east or west of Greenwich
 */
#define GRID_TLV_GRIDSITE_LONGITUDE 4
#define GRID_TLV_GRIDSITE_LONGITUDE_CONST_DATA_LENGTH 5
struct grid_tlv_GridSite_Longitude
{
  struct grid_tlv_header                   header;
  char                                     longitude[5];            /** Longitude (40 bits) */
  char                                     reserved[3];             /** Reserved */
};

/**
 * Degree the position of a place north or south of the equator
 */
#define GRID_TLV_GRIDSITE_LATITUDE 3
#define GRID_TLV_GRIDSITE_LATITUDE_CONST_DATA_LENGTH 5
struct grid_tlv_GridSite_Latitude
{
  struct grid_tlv_header                   header;
  char                                     latitude[5];             /** Latitude (40 bits) */
  char                                     reserved[3];             /** Reserved */
};

/**
 * Human-readable name
 */
#define GRID_TLV_GRIDSITE_NAME 2
#define GRID_TLV_GRIDSITE_NAME_CONST_DATA_LENGTH 0
struct grid_tlv_GridSite_Name
{
  struct grid_tlv_header                   header;
  struct zlist                              name;                    /** Grid Site Name (list of chars) */
};

/**
 * Unique Identifier of the Site
 */
#define GRID_TLV_GRIDSITE_ID 1
#define GRID_TLV_GRIDSITE_ID_CONST_DATA_LENGTH 4
struct grid_tlv_GridSite_ID
{
  struct grid_tlv_header                   header;
  uint32_t                                 id;                      /** Unique Identifier of the Site */
};

/**
 * Grid Side Property TLV
 */
#define GRID_TLV_GRIDSITE 1
#define GRID_TLV_GRIDSITE_CONST_DATA_LENGTH 44
struct grid_tlv_GridSite
{
  struct grid_tlv_header                   header;
  struct grid_tlv_GridSite_ID              id;                      /** Unique Identifier of the Site */
  struct grid_tlv_GridSite_Name            name;                    /** Human-readable name */
  struct grid_tlv_GridSite_Latitude        latitude;                /** Degree the position of a place north or south of the equator */
  struct grid_tlv_GridSite_Longitude       longitude;               /** Degree the position of a place east or west of Greenwich */
  struct grid_tlv_GridSite_PE_Router_ID    peRouter_id;             /** the routerID, as advertised by OSPF, of the  Provider Edge (PE) network element which this Grid site is attached to */
};

/** *** Grid Service Property TLV *********************************** */

/**
 * Network endpoint for this service
 */
#define GRID_TLV_GRIDSERVICE_NSAPENDPOINT 8
#define GRID_TLV_GRIDSERVICE_NSAPENDPOINT_CONST_DATA_LENGTH 20
struct grid_tlv_GridService_NsapEndpoint
{
  struct grid_tlv_header                   header;
  uint32_t                                 nsapEndp[5];             /** Network endpoint for this service (NSAP address)*/
};

/**
 * Network endpoint for this service
 */
#define GRID_TLV_GRIDSERVICE_IPV6ENDPOINT 7
#define GRID_TLV_GRIDSERVICE_IPV6ENDPOINT_CONST_DATA_LENGTH 16
struct grid_tlv_GridService_IPv6Endpoint
{
  struct grid_tlv_header                   header;
  struct in6_addr                          ipv6Endp;                /** Network endpoint for this service (IPv6 address)*/
};

/**
 * Network endpoint for this service
 */
#define GRID_TLV_GRIDSERVICE_IPV4ENDPOINT 6
#define GRID_TLV_GRIDSERVICE_IPV4ENDPOINT_CONST_DATA_LENGTH 4
struct grid_tlv_GridService_IPv4Endpoint
{
  struct grid_tlv_header                   header;
  struct in_addr                           ipv4Endp;                /** Network endpoint for this service (IPv4 address)*/
};

/**
 * Length of the endpoint address
 */
#define GRID_TLV_GRIDSERVICE_ADDRESSLENGTH 5
#define GRID_TLV_GRIDSERVICE_ADDRESSLENGTH_CONST_DATA_LENGTH 1
struct grid_tlv_GridService_AddressLength
{
  struct grid_tlv_header                   header;
  char                                     addressLength;           /** Length of the endpoint address */
  char                                     padding[3];
};

/**
 * Status of the service
 */
#define GRID_TLV_GRIDSERVICE_STATUS 4
#define GRID_TLV_GRIDSERVICE_STATUS_CONST_DATA_LENGTH 1
struct grid_tlv_GridService_Status
{
  struct grid_tlv_header                   header;
  char                                     status;                  /** Status of the service */
  char                                     reserved[3];             /** Reserved */
};

/**
 * The service info including service type and version
 */
#define GRID_TLV_GRIDSERVICE_SERVICEINFO 3
#define GRID_TLV_GRIDSERVICE_SERVICEINFO_CONST_DATA_LENGTH 4
struct grid_tlv_GridService_ServiceInfo
{
  struct grid_tlv_header                   header;
  uint16_t                                 type;                    /** The service type */
  uint16_t                                 version;                 /** Version of the service */
};

/**
 * Identifier of the Grid Site that is exporting this service
 */
#define GRID_TLV_GRIDSERVICE_PARENTSITE_ID 2
#define GRID_TLV_GRIDSERVICE_PARENTSITE_ID_CONST_DATA_LENGTH 4
struct grid_tlv_GridService_ParentSite_ID
{
  struct grid_tlv_header                   header;
  uint32_t                                 parent_site_id;          /** Identifier of the Grid Site */
};

/**
 * Unique Identifier of the Service
 */
#define GRID_TLV_GRIDSERVICE_ID 1
#define GRID_TLV_GRIDSERVICE_ID_CONST_DATA_LENGTH 4
struct grid_tlv_GridService_ID
{
  struct grid_tlv_header                   header;
  uint32_t                                 id;                      /** Unique Identifier of the Service */
};

/**
 * Grid Service Property TLV
 */
#define GRID_TLV_GRIDSERVICE 2
#define GRID_TLV_GRIDSERVICE_CONST_DATA_LENGTH 92
struct grid_tlv_GridService
{
  struct grid_tlv_header                    header;
  struct grid_tlv_GridService_ID            id;                     /** Unique Identifier of the Service */
  struct grid_tlv_GridService_ParentSite_ID parentSite_id;          /** Identifier of the Grid Site that is exporting this service */
  struct grid_tlv_GridService_ServiceInfo   serviceInfo;            /** The service info including service type and version */
  struct grid_tlv_GridService_Status        status;                 /** Status of the service */
  struct grid_tlv_GridService_AddressLength addressLength;          /** Length of the endpoint address */
  struct grid_tlv_GridService_IPv4Endpoint  ipv4Endpoint;           /** Network endpoint for this service */
  struct grid_tlv_GridService_IPv6Endpoint  ipv6Endpoint;           /** Network endpoint for this service */
  struct grid_tlv_GridService_NsapEndpoint  nsapEndpoint;           /** Network endpoint for this service */
};

/** *** Grid Computing Element Property TLV *********************************** */

/**
 * Human-readable name
 */
#define GRID_TLV_GRIDCOMPUTINGELEMENT_NAME 18
#define GRID_TLV_GRIDCOMPUTINGELEMENT_NAME_CONST_DATA_LENGTH 0
struct grid_tlv_GridComputingElement_Name
{
  struct grid_tlv_header                   header;
  struct zlist                             name;           /** Grid Computing Element Name (list of chars) */
};

/**
 * The jobs scheduling calendar reporting the available FreeJobsSlots for each timestamp
 */
#define GRID_TLV_GRIDCOMPUTINGELEMENT_CECALENDAR 17
#define GRID_TLV_GRIDCOMPUTINGELEMENT_CECALENDAR_CONST_DATA_LENGTH 0
struct grid_tlv_GridComputingElement_CeCalendar
{
  struct grid_tlv_header                   header;
  struct zlist                             ceCalend;                /** The jobs scheduling calendar reporting the available FreeJobsSlots for each timestamp */
};

struct ce_calendar
{
  uint32_t                                 time;                    /** timestamp */
  uint16_t                                 freeJobSlots;            /** FreeJobsSlots */
};

/**
 * Jobs Load Policy
 */
#define GRID_TLV_GRIDCOMPUTINGELEMENT_JOBSLOADPOLICY 16
#define GRID_TLV_GRIDCOMPUTINGELEMENT_JOBSLOADPOLICY_CONST_DATA_LENGTH 17
struct grid_tlv_GridComputingElement_JobsLoadPolicy
{
  struct grid_tlv_header                   header;
  uint32_t                                 maxTotalJobs;            /** The maximum allowed number of jobs in the CE */
  uint32_t                                 maxRunJobs;              /** The maximum allowed number of jobs in running state in the CE */
  uint32_t                                 maxWaitJobs;             /** The maximum allowed number of jobs in waiting state in the CE */
  uint16_t                                 assignJobSlots;          /** Number of slots for jobs to be in running state */
  uint16_t                                 maxSlotsPerJob;          /** The maximum number of slots per single job */
  char                                     priorityPreemptionFlag;  /** The jobs priority and the pre emption flag */
  char                                     reserved[3];             /** Reserved */
};

/**
 * The maximum wall clock time, the maximum obtainable wall clock time, the default maximum CPU time allowed to each job by the batch system and finally the maximum obtainable CPU time that can be granted to the job upon user request
 */
#define GRID_TLV_GRIDCOMPUTINGELEMENT_JOBSTIMEPOLICY 15
#define GRID_TLV_GRIDCOMPUTINGELEMENT_JOBSTIMEPOLICY_CONST_DATA_LENGTH 16
struct grid_tlv_GridComputingElement_JobsTimePolicy
{
  struct grid_tlv_header                   header;
  uint32_t                                 maxWcTime;               /** The default maximum wall clock time */
  uint32_t                                 maxObtWcTime;            /** The maximum obtainable wall clock time */
  uint32_t                                 maxCpuTime;              /** The default maximum CPU time */
  uint32_t                                 maxObtCpuTime;           /** The maximum obtainable CPU time */
};

/**
 * The estimated time and the worst time to last for a new job from the acceptance to the start of its execution
 */
#define GRID_TLV_GRIDCOMPUTINGELEMENT_JOBSTIMEPERFORMANCES 14
#define GRID_TLV_GRIDCOMPUTINGELEMENT_JOBSTIMEPERFORMANCES_CONST_DATA_LENGTH 8
struct grid_tlv_GridComputingElement_JobsTimePerformances
{
  struct grid_tlv_header                   header;
  uint32_t                                 estRespTime;             /** Estimated response time */
  uint32_t                                 worstRespTime;           /** Worst response time */
};

/**
 * It contains the number of jobs in running, waiting, any state
 */
#define GRID_TLV_GRIDCOMPUTINGELEMENT_JOBSSTATS 13
#define GRID_TLV_GRIDCOMPUTINGELEMENT_JOBSSTATS_CONST_DATA_LENGTH 12
struct grid_tlv_GridComputingElement_JobsStats
{
  struct grid_tlv_header                   header;
  uint32_t                                 runningJobs;             /** Number of jobs in running state */
  uint32_t                                 waitingJobs;             /** Number of jobs in waiting state */
  uint32_t                                 totalJobs;               /** Number of jobs in any state */
};

/**
 * It contains the number of free job slots, and the queue status
 */
#define GRID_TLV_GRIDCOMPUTINGELEMENT_JOBSSTATES 12
#define GRID_TLV_GRIDCOMPUTINGELEMENT_JOBSSTATES_CONST_DATA_LENGTH 3
struct grid_tlv_GridComputingElement_JobsStates
{
  struct grid_tlv_header                   header;
  uint16_t                                 freeJobSlots;            /** The number of free job slots */
  char                                     status;                  /** Status */
  char                                     padding[1];              /** Padding */
};

/**
 * The unique identifier of the default Storage Element
 */
#define GRID_TLV_GRIDCOMPUTINGELEMENT_DEFAULTSTORAGEELEMENT 11
#define GRID_TLV_GRIDCOMPUTINGELEMENT_DEFAULTSTORAGEELEMENT_CONST_DATA_LENGTH 4
struct grid_tlv_GridComputingElement_DefaultStorageElement
{
  struct grid_tlv_header                   header;
  uint32_t                                 defaultSelement; /** The unique identifier of the default Storage Element */
};

/**
 * String representing the path of a run directory
 */
#define GRID_TLV_GRIDCOMPUTINGELEMENT_DATADIR 10
#define GRID_TLV_GRIDCOMPUTINGELEMENT_DATADIR_CONST_DATA_LENGTH 0
struct grid_tlv_GridComputingElement_DataDir
{
  struct grid_tlv_header                   header;
  struct zlist                             dataDirStr;      /** The path of a run directory (list of chars) */
};

/**
 * The job manager used by the gatekeeper
 */
#define GRID_TLV_GRIDCOMPUTINGELEMENT_JOBMANAGER 9
#define GRID_TLV_GRIDCOMPUTINGELEMENT_JOBMANAGER_CONST_DATA_LENGTH 0
struct grid_tlv_GridComputingElement_JobManager
{
  struct grid_tlv_header                   header;
  struct zlist                             jobManag;        /** Job Manager (list of chars) */
};

/**
 * Gatekeeper port
 */
#define GRID_TLV_GRIDCOMPUTINGELEMENT_GATEKEEPERPORT 8
#define GRID_TLV_GRIDCOMPUTINGELEMENT_GATEKEEPERPORT_CONST_DATA_LENGTH 4
struct grid_tlv_GridComputingElement_GatekeeperPort
{
  struct grid_tlv_header                   header;
  uint32_t                                 gateKPort;       /** Gatekeeper port */
};

/**
 * Host name of the machine running this service
 */
#define GRID_TLV_GRIDCOMPUTINGELEMENT_NSAPHOSTNAME 7
#define GRID_TLV_GRIDCOMPUTINGELEMENT_NSAPHOSTNAME_CONST_DATA_LENGTH 20
struct grid_tlv_GridComputingElement_NsapHostName
{
  struct grid_tlv_header                   header;
  uint32_t                                 nsapHostNam[5];  /** Host name of the machine (NSAP address) */
};

/**
 * Host name of the machine running this service
 */
#define GRID_TLV_GRIDCOMPUTINGELEMENT_IPV6HOSTNAME 6
#define GRID_TLV_GRIDCOMPUTINGELEMENT_IPV6HOSTNAME_CONST_DATA_LENGTH 16
struct grid_tlv_GridComputingElement_IPv6HostName
{
  struct grid_tlv_header                   header;
  struct in6_addr                          ipv6HostNam;  /** Host name of the machine (IPv6 address) */
};

/**
 * Host name of the machine running this service
 */
#define GRID_TLV_GRIDCOMPUTINGELEMENT_IPV4HOSTNAME 5
#define GRID_TLV_GRIDCOMPUTINGELEMENT_IPV4HOSTNAME_CONST_DATA_LENGTH 4
struct grid_tlv_GridComputingElement_IPv4HostName
{
  struct grid_tlv_header                   header;
  struct in_addr                           ipv4HostNam;  /** Host name of the machine (IPv4 address) */
};

/**
 * Length of the host name address
 */
#define GRID_TLV_GRIDCOMPUTINGELEMENT_ADDRESSLENGTH 4
#define GRID_TLV_GRIDCOMPUTINGELEMENT_ADDRESSLENGTH_CONST_DATA_LENGTH 1
struct grid_tlv_GridComputingElement_AddressLength
{
  struct grid_tlv_header                   header;
  char                                     addrLength;  /** Length of the host name address */
  char                                     padding[3];
};

/**
 * Type and version of the underlying LRMS
 */
#define GRID_TLV_GRIDCOMPUTINGELEMENT_LRMSINFO 3
#define GRID_TLV_GRIDCOMPUTINGELEMENT_LRMSINFO_CONST_DATA_LENGTH 4
struct grid_tlv_GridComputingElement_LrmsInfo
{
  struct grid_tlv_header                   header;
  uint16_t                                 lrmsType;  /** LRMS Type */
  uint16_t                                 lrmsVersion;  /** LRMS Version */
};

/**
 * Identifier of the Grid Site that is exporting this computing element
 */
#define GRID_TLV_GRIDCOMPUTINGELEMENT_PARENTSITEID 2
#define GRID_TLV_GRIDCOMPUTINGELEMENT_PARENTSITEID_CONST_DATA_LENGTH 4
struct grid_tlv_GridComputingElement_ParentSiteID
{
  struct grid_tlv_header                   header;
  uint32_t                                 parSiteId;  /** Identifier of the Grid Site */
};

/**
 * Unique Identifier of the Computing Element
 */
#define GRID_TLV_GRIDCOMPUTINGELEMENT_ID 1
#define GRID_TLV_GRIDCOMPUTINGELEMENT_ID_CONST_DATA_LENGTH 4
struct grid_tlv_GridComputingElement_ID
{
  struct grid_tlv_header                   header;
  uint32_t                                 id;  /** Unique Identifier of the Computing Element */
};

/**
 * Grid Computing Element Property TLV
 */
#define GRID_TLV_GRIDCOMPUTINGELEMENT 3
#define GRID_TLV_GRIDCOMPUTINGELEMENT_CONST_DATA_LENGTH 192
struct grid_tlv_GridComputingElement
{
  struct grid_tlv_header                                     header;
  struct grid_tlv_GridComputingElement_ID                    id;                   /** Unique Identifier of the Computing Element */
  struct grid_tlv_GridComputingElement_ParentSiteID          parentSiteId;         /** Identifier of the Grid Site that is exporting this computing element */
  struct grid_tlv_GridComputingElement_LrmsInfo              lrmsInfo;             /** Type and version of the underlying LRMS */
  struct grid_tlv_GridComputingElement_AddressLength         addressLength;        /** Length of the host name address */
  struct grid_tlv_GridComputingElement_IPv4HostName          ipv4HostName;         /** Host name of the machine running this service */
  struct grid_tlv_GridComputingElement_IPv6HostName          ipv6HostName;         /** Host name of the machine running this service */
  struct grid_tlv_GridComputingElement_NsapHostName          nsapHostName;         /** Host name of the machine running this service */
  struct grid_tlv_GridComputingElement_GatekeeperPort        gatekeeperPort;       /** Gatekeeper port */
  struct grid_tlv_GridComputingElement_JobManager            jobManager;           /** The job manager used by the gatekeeper */
  struct grid_tlv_GridComputingElement_DataDir               dataDir;              /** String representing the path of a run directory */
  struct grid_tlv_GridComputingElement_DefaultStorageElement defaultSe;            /** The unique identifier of the default Storage Element */
  struct grid_tlv_GridComputingElement_JobsStates            jobsStates;           /** It contains the number of free job slots, and the queue status */
  struct grid_tlv_GridComputingElement_JobsStats             jobsStats;            /** It contains the number of jobs in running, waiting, any state */
  struct grid_tlv_GridComputingElement_JobsTimePerformances  jobsTimePerformances; /** The estimated time and the worst time to last for a new job from the acceptance to the start of its execution */
  struct grid_tlv_GridComputingElement_JobsTimePolicy        jobsTimePolicy;       /** The maximum wall clock time, the maximum obtainable wall clock time, the default maximum CPU time allowed to each job by the batch system and finally the maximum obtainable CPU time that can be granted to the job upon user request */
  struct grid_tlv_GridComputingElement_JobsLoadPolicy        jobsLoadPolicy;       /** Jobs Load Policy */
  struct grid_tlv_GridComputingElement_CeCalendar            ceCalendar;           /** The jobs scheduling calendar reporting the available FreeJobsSlots for each timestamp */
  struct grid_tlv_GridComputingElement_Name                  name;
};

/** *** Grid SubCluster Property TLV *********************************** */

/**
 * Human-readable name
 */
#define GRID_TLV_GRIDSUBCLUSTER_NAME 8
#define GRID_TLV_GRIDSUBCLUSTER_NAME_CONST_DATA_LENGTH 0
struct grid_tlv_GridSubCluster_Name
{
  struct grid_tlv_header                   header;
  struct zlist                             name;           /** Grid SubCluster Name (list of chars) */
};

/**
 * The PhysicalCPUs and LogicalCPUs scheduling calendar for each timestamp
 */
#define GRID_TLV_GRIDSUBCLUSTER_SUBCLUSTERCALENDAR 7
#define GRID_TLV_GRIDSUBCLUSTER_SUBCLUSTERCALENDAR_CONST_DATA_LENGTH 0
struct grid_tlv_GridSubCluster_SubClusterCalendar
{
  struct grid_tlv_header                   header;
  struct zlist                             subcluster_calendar;  /** The PhysicalCPUs and LogicalCPUs scheduling calendar for each timestamp */
};

struct sc_calendar
{
  uint32_t                                 time;                 /** timestamp */
  uint16_t                                 physical_cpus;
  uint16_t                                 logical_cpus;
};

/**
 * Software Package
 */
#define GRID_TLV_GRIDSUBCLUSTER_SOFTWAREPACKAGE 6
#define GRID_TLV_GRIDSUBCLUSTER_SOFTWAREPACKAGE_CONST_DATA_LENGTH 4
struct grid_tlv_GridSubCluster_SoftwarePackage
{
  struct grid_tlv_header                   header;
  uint16_t                                 softType;             /** Software Type */
  uint16_t                                 softVersion;          /** Software Version */
  struct zlist                             environmentSetup;     /** Environment Setup */
};

/**
 * The amount of RAM and Virtual Memory (in MB)
 */
#define GRID_TLV_GRIDSUBCLUSTER_MEMORYINFO 5
#define GRID_TLV_GRIDSUBCLUSTER_MEMORYINFO_CONST_DATA_LENGTH 8
struct grid_tlv_GridSubCluster_MemoryInfo
{
  struct grid_tlv_header                   header;
  uint32_t                                 ramSize;              /** RAM Size in MB */
  uint32_t                                 virtualMemorySize;    /** Virtual Memory Size in MB */
};

/**
 * Information about the type of the OS and its version
 */
#define GRID_TLV_GRIDSUBCLUSTER_OSINFO 4
#define GRID_TLV_GRIDSUBCLUSTER_OSINFO_CONST_DATA_LENGTH 4
struct grid_tlv_GridSubCluster_OsInfo
{
  struct grid_tlv_header                            header;
  uint16_t                                          osType;               /** OS Type */
  uint16_t                                          osVersion;            /** OS Version */
};

/**
 * The CPU architecture, the total and the effective number of CPUs
 */
#define GRID_TLV_GRIDSUBCLUSTER_CPUINFO 3
#define GRID_TLV_GRIDSUBCLUSTER_CPUINFO_CONST_DATA_LENGTH 9
struct grid_tlv_GridSubCluster_CpuInfo
{
  struct grid_tlv_header                            header;
  uint32_t                                          physicalCpus;         /** Total number of CPUs */
  uint32_t                                          logicalCpus;          /** Effective number of CPUs */
  char                                              cpuArch;              /** The CPU architecture */
  char                                              reserved[3];          /** Reserved */
};

/**
 * Identifier of the Grid Site that is exporting this sub-cluster
 */
#define GRID_TLV_GRIDSUBCLUSTER_PARENTSITEID 2
#define GRID_TLV_GRIDSUBCLUSTER_PARENTSITEID_CONST_DATA_LENGTH 4
struct grid_tlv_GridSubCluster_ParentSiteID
{
  struct grid_tlv_header                             header;
  uint32_t                                           parSiteId;           /** Identifier of the Grid Site */
};

/**
 * Unique Identifier of the Sub-Cluster
 */
#define GRID_TLV_GRIDSUBCLUSTER_ID 1
#define GRID_TLV_GRIDSUBCLUSTER_ID_CONST_DATA_LENGTH 4
struct grid_tlv_GridSubCluster_ID
{
  struct grid_tlv_header                             header;
  uint32_t                                           id;                  /** UniqueIdentifier of the Sub-Cluster */
};

/**
 * Grid SubCluster Property TLV
 */
#define GRID_TLV_GRIDSUBCLUSTER 4
#define GRID_TLV_GRIDSUBCLUSTER_CONST_DATA_LENGTH 68
struct grid_tlv_GridSubCluster
{
  struct grid_tlv_header                             header;
  struct grid_tlv_GridSubCluster_ID                  id;                  /** Unique Identifier of the Sub-Cluster */
  struct grid_tlv_GridSubCluster_ParentSiteID        parentSiteId;        /** Identifier of the Grid Site that is exporting this sub-cluster */
  struct grid_tlv_GridSubCluster_CpuInfo             cpuInfo;             /** The CPU architecture, the total and the effective number of CPUs */
  struct grid_tlv_GridSubCluster_OsInfo              osInfo;              /** Information about the type of the OS and its version */
  struct grid_tlv_GridSubCluster_MemoryInfo          memoryInfo;          /** The amount of RAM and Virtual Memory (in MB) */
  struct zlist                                       softwarePackage;     /** list of SubTLV - grid_tlv_GridSubCluster_SoftwarePackage */
  struct grid_tlv_GridSubCluster_SubClusterCalendar  subclusterCalendar;  /** The PhysicalCPUs and LogicalCPUs scheduling calendar for each timestamp */
  struct grid_tlv_GridSubCluster_Name                name;
};

/** *** Grid Storage Element Property TLV *********************************** */

/**
 * Human-readable name
 */
#define GRID_TLV_GRIDSTORAGE_NAME 8
#define GRID_TLV_GRIDSTORAGE_NAME_CONST_DATA_LENGTH 0
struct grid_tlv_GridStorage_Name
{
  struct grid_tlv_header                   header;
  struct zlist                             name;           /** Grid Storage Name (list of chars) */
};

/**
 * The FreeOnlineSize and FreeNearlineSize scheduling calendar for each timestamp
 */
#define GRID_TLV_GRIDSTORAGE_SECALENDAR 7
#define GRID_TLV_GRIDSTORAGE_SECALENDAR_CONST_DATA_LENGTH 0
struct grid_tlv_GridStorage_SeCalendar
{
  struct grid_tlv_header                   header;
  struct zlist                             seCalendar;                    /** The FreeOnlineSize and FreeNearlineSize scheduling calendar for each timestamp */
};

struct se_calendar
{
  uint32_t                                 time;                          /** timestamp */
  uint32_t                                 freeOnlineSize;
  uint32_t                                 freeNearlineSize;
};


/**
 * Storage Area
 */
#define GRID_TLV_GRIDSTORAGE_STORAGEAREA 6
#define GRID_TLV_GRIDSTORAGE_STORAGEAREA_CONST_DATA_LENGTH 28
struct grid_tlv_GridStorage_StorageArea
{
  struct grid_tlv_header                   header;
  struct zlist                             name;                          /** Name (list of chars '\0' sign determines list end. List is padded by '\0' signs to the )*/
  struct zlist                             path;                          /** Path (list of chars) (max. 20 letters)*/
  uint32_t                                 totalOnlineSize;               /** Total online size */
  uint32_t                                 freeOnlineSize;                /** Free online size */
  uint32_t                                 resTotalOnlineSize;            /** Reserved total online size */
  uint32_t                                 totalNearlineSize;             /** Total nearline size */
  uint32_t                                 freeNearlineSize;              /** Free nearline size */
  uint32_t                                 resNearlineSize;               /** Reserved nearline size */
  char                                     retPolAccLat;                  /** Retention policy (4 bits), Access latency (4 bits) */
  char                                     expirationMode;                /** Expiration mode (4 bits) */
  char                                     reserved[2];                   /** Reserved */
};

/**
 * The nearline storage sizes (total + used) in GB
 */
#define GRID_TLV_GRIDSTORAGE_NEARLINESIZE 5
#define GRID_TLV_GRIDSTORAGE_NEARLINESIZE_CONST_DATA_LENGTH 8
struct grid_tlv_GridStorage_NearlineSize
{
  struct grid_tlv_header                   header;
  uint32_t                                 totalSize;                     /** Total Size in GB */
  uint32_t                                 usedSize;                      /** Used  Size in GB */
};

/**
 * The online storage sizes (total + used) in GB
 */
#define GRID_TLV_GRIDSTORAGE_ONLINESIZE 4
#define GRID_TLV_GRIDSTORAGE_ONLINESIZE_CONST_DATA_LENGTH 8
struct grid_tlv_GridStorage_OnlineSize
{
  struct grid_tlv_header                   header;
  uint32_t                                 totalSize;                     /** Total Size in GB */
  uint32_t                                 usedSize;                      /** Used Size  in GB */
};

/**
 * Information about the storage architecture the status of the SE the access and control protocols
 */
#define GRID_TLV_GRIDSTORAGE_STORAGEINFO 3
#define GRID_TLV_GRIDSTORAGE_STORAGEINFO_CONST_DATA_LENGTH 4
struct grid_tlv_GridStorage_StorageInfo
{
  struct grid_tlv_header                   header;
  uint32_t                                 storInfo;  /** The storage architecture (4 bits) status (4 bits) access protocol (12 bits) control protocol (12 bits) */
};

/**
 * Identifier of the Grid Site that is exporting this storage
 */
#define GRID_TLV_GRIDSTORAGE_PARENTSITEID 2
#define GRID_TLV_GRIDSTORAGE_PARENTSITEID_CONST_DATA_LENGTH 4
struct grid_tlv_GridStorage_ParentSiteID
{
  struct grid_tlv_header                   header;
  uint32_t                                 parSiteId;  /** Identifier of the Grid Site */
};

/**
 * Unique Identifier of the Storage Element
 */
#define GRID_TLV_GRIDSTORAGE_ID 1
#define GRID_TLV_GRIDSTORAGE_ID_CONST_DATA_LENGTH 4
struct grid_tlv_GridStorage_ID
{
  struct grid_tlv_header                   header;
  uint32_t                                 id;  /** Unique Identifier of the Storage Element */
};

/**
 * Grid Storage Element Property TLV
 */
#define GRID_TLV_GRIDSTORAGE 5
#define GRID_TLV_GRIDSTORAGE_CONST_DATA_LENGTH 84
struct grid_tlv_GridStorage
{
  struct grid_tlv_header                   header;
  struct grid_tlv_GridStorage_ID           id;            /** Unique Identifier of the Storage Element */
  struct grid_tlv_GridStorage_ParentSiteID parentSiteId;  /** Identifier of the Grid Site that is exporting this storage */
  struct grid_tlv_GridStorage_StorageInfo  storageInfo;   /** Information about the storage architecture the status of the SE the access and control protocols */
  struct grid_tlv_GridStorage_OnlineSize   onlineSize;    /** The online storage sizes (total + used) in GB */
  struct grid_tlv_GridStorage_NearlineSize nearlineSize;  /** The nearline storage sizes (total + used) in GB */
  struct zlist  storageArea;                              /** list of sub-tlvs grid_tlv_GridStorage_StorageArea */
  struct grid_tlv_GridStorage_SeCalendar   seCalendar;    /** The FreeOnlineSize and FreeNearlineSize scheduling calendar for each timestamp */
  struct grid_tlv_GridStorage_Name         name;
};

/** *************************************** */

extern int ospf_grid_init (void);
extern void ospf_grid_term (void);

struct grid_node_resource
{
/** According to D2.2 the instance is a 24 bit field */
  uint32_t                      instance_no;
  uint32_t                      flags;
  struct grid_node              *gn;
};

struct grid_node_site
{
  struct grid_node_resource             base;
  struct grid_tlv_GridSite              gridSite;
};

struct grid_node_service
{
  struct grid_node_resource             base;
  struct grid_tlv_GridService           gridService;
};

struct grid_node_computing
{
  struct grid_node_resource             base;
  struct grid_tlv_GridComputingElement  gridCompElement;
};

struct grid_node_subcluster
{
  struct grid_node_resource             base;
  struct grid_tlv_GridSubCluster        gridSubcluster;
};

struct grid_node_storage
{
  struct grid_node_resource             base;
  struct grid_tlv_GridStorage           gridStorage;
};


struct grid_node
{
/**
 * Reference pointer to:
 * - Zebra-interface in MPLS architecture type
 * - Zebra-virtual-interface in GMPLS / G2MPLS architecture type
 */
  struct interface *ifp;

/**
  * Area info in which this MPLS-GRID belongs to.
 */
  struct ospf_area *area; 

#define GRIDFLG_GRID_LSA_LOOKUP_DONE         0x1
#define GRIDFLG_GRID_LSA_ENGAGED             0x2
#define GRIDFLG_GRID_LSA_FORCED_REFRESH      0x4

 /** Grid Side Property TLV */
  struct grid_node_site                           *gn_site;

 /** Grid Service Property TLV */
  struct zlist                                    *list_of_grid_node_service;

 /** Grid Computing Element Property TLV */
  struct zlist                                    *list_of_grid_node_computing;

 /** Grid SubCluster Property TLV */
  struct zlist                                    *list_of_grid_node_subcluster;

 /** Grid Storage Element Property TLV */
  struct zlist                                    *list_of_grid_node_storage;
};

/**
 * Global variable to manage Opaque-LSA/MPLS-GRID on this node.
 */
extern struct ospf_grid OspfGRID;

#ifdef __cplusplus
extern "C" {
#endif

struct grid_tlv_header* get_grid_tlv_from_uni_database(uint16_t type, uint32_t siteId, uint32_t id);

extern void delete_grid_node_service           (struct grid_node *gn, struct grid_node_service *gn_service);
extern void delete_grid_node_storage           (struct grid_node *gn, struct grid_node_storage *gn_storage);
extern void delete_grid_node_computing         (struct grid_node *gn, struct grid_node_computing *gn_computing);
extern void delete_grid_node_subcluster        (struct grid_node *gn, struct grid_node_subcluster *gn_subcluster);

extern void set_grid_tlv_GridSite_ID               (struct grid_node_site *gn_site, uint32_t id);
extern void set_grid_tlv_GridSite_Name             (struct grid_node_site *gn_site, const char* name);
extern void set_grid_tlv_GridSite_Latitude         (struct grid_node_site *gn_site, uint8_t *latitude);
extern void set_grid_tlv_GridSite_Longitude        (struct grid_node_site *gn_site, uint8_t *longitude);
extern void set_grid_tlv_GridSite_PE_Router_ID     (struct grid_node_site *gn_site, struct in_addr id);
extern void set_grid_tlv_GridService_ID            (struct grid_node_service *gn_service, uint32_t id);
extern void set_grid_tlv_GridService_ParentSite_ID (struct grid_node_service *gn_service, uint32_t parent_site_id);
extern void set_grid_tlv_GridService_ServiceInfo   (struct grid_node_service *gn_service, uint16_t type, uint16_t version);
extern void set_grid_tlv_GridService_Status        (struct grid_node_service *gn_service, char status);
extern void set_grid_tlv_GridService_AddressLength (struct grid_node_service *gn_service, char addressLength);
extern void set_grid_tlv_GridService_IPv4Endpoint  (struct grid_node_service *gn_service, struct in_addr ipv4Endp);
extern void set_grid_tlv_GridService_IPv6Endpoint  (struct grid_node_service *gn_service, struct in6_addr ipv6Endp);
extern void set_grid_tlv_GridService_NsapEndpoint  (struct grid_node_service *gn_service, uint32_t nsapEndp[]);
extern void set_grid_tlv_GridComputingElement_ID   (struct grid_node_computing *gn_computing, uint32_t id);
extern void set_grid_tlv_GridComputingElement_Name (struct grid_node_computing *gn_computing, const char* name);
extern void set_grid_tlv_GridComputingElement_ParentSiteID          (struct grid_node_computing *gn_computing, uint32_t parSiteId);
extern void set_grid_tlv_GridComputingElement_LrmsInfo              (struct grid_node_computing *gn_computing, uint16_t lrmsType, uint16_t lrmsVersion);
extern void set_grid_tlv_GridComputingElement_AddressLength         (struct grid_node_computing *gn_computing, char addrLength);
extern void set_grid_tlv_GridComputingElement_IPv4HostName          (struct grid_node_computing *gn_computing, struct in_addr ipv4HostNam);
extern void set_grid_tlv_GridComputingElement_IPv6HostName          (struct grid_node_computing *gn_computing, struct in6_addr ipv6HostNam);
extern void set_grid_tlv_GridComputingElement_NsapHostName          (struct grid_node_computing *gn_computing, uint32_t nsapHostNam[]);
extern void set_grid_tlv_GridComputingElement_GatekeeperPort        (struct grid_node_computing *gn_computing, uint32_t gateKPort);
extern void set_grid_tlv_GridComputingElement_JobManager            (struct grid_node_computing *gn_computing, const char* jobManag);
extern void set_grid_tlv_GridComputingElement_DataDir               (struct grid_node_computing *gn_computing, const char* dataDirStr);
extern void set_grid_tlv_GridComputingElement_DefaultStorageElement (struct grid_node_computing *gn_computing, uint32_t defaultSelement);
extern void set_grid_tlv_GridComputingElement_JobsStates            (struct grid_node_computing *gn_computing, uint16_t freeJobSlots, char status);
extern void set_grid_tlv_GridComputingElement_JobsStats             (struct grid_node_computing *gn_computing, uint32_t runningJobs, uint32_t waitingJobs, uint32_t totalJobs);
extern void set_grid_tlv_GridComputingElement_JobsTimePerformances  (struct grid_node_computing *gn_computing, uint32_t estRespTime, uint32_t worstRespTime);
extern void set_grid_tlv_GridComputingElement_JobsTimePolicy (struct grid_node_computing *gn_computing, uint32_t maxWcTime, uint32_t maxObtWcTime, uint32_t maxCpuTime, uint32_t maxObtCpuTime);
extern void set_grid_tlv_GridComputingElement_JobsLoadPolicy (struct grid_node_computing *gn_computing, uint32_t maxTotalJobs, uint32_t maxRunJobs, uint32_t maxWaitJobs, uint16_t assignJobSlots, uint16_t maxSlotsPerJob, char priorityPreemptionFlag);
extern void set_grid_tlv_GridComputingElement_CeCalendar     (struct grid_node_computing *gn_computing, enum list_opcode l_opcode, void *list_arg);
extern void set_grid_tlv_GridSubCluster_ID                   (struct grid_node_subcluster *gn_subcluster, uint32_t id);
extern void set_grid_tlv_GridSubCluster_ParentSiteID         (struct grid_node_subcluster *gn_subcluster, uint32_t parSiteId);
extern void set_grid_tlv_GridSubCluster_CpuInfo              (struct grid_node_subcluster *gn_subcluster, uint32_t physicalCpus, uint32_t logicalCpus, char cpuArch);
extern void set_grid_tlv_GridSubCluster_OsInfo               (struct grid_node_subcluster *gn_subcluster, uint16_t osType, uint16_t osVersion);
extern void set_grid_tlv_GridSubCluster_MemoryInfo           (struct grid_node_subcluster *gn_subcluster, uint32_t ramSize, uint32_t virtualMemorySize);
extern void set_grid_tlv_GridSubCluster_SoftwarePackage      (struct grid_node_subcluster *gn_subcluster, enum list_opcode l_opcode, void* list_arg);
extern void set_grid_tlv_GridSubCluster_SubClusterCalendar   (struct grid_node_subcluster *gn_subcluster, enum list_opcode l_opcode, void *list_arg);
extern void set_grid_tlv_GridSubCluster_Name                 (struct grid_node_subcluster *gn_subcluster, const char* name);
extern void set_grid_tlv_GridStorage                         (struct grid_node_storage *gn_storage, enum list_opcode l_opcode, void *list_arg);
extern void set_grid_tlv_GridStorage_ID                      (struct grid_node_storage *gn_storage, uint32_t id);
extern void set_grid_tlv_GridStorage_ParentSiteID            (struct grid_node_storage *gn_storage, uint32_t parSiteId);
extern void set_grid_tlv_GridStorage_StorageInfo             (struct grid_node_storage *gn_storage, uint32_t storInfo);
extern void set_grid_tlv_GridStorage_OnlineSize              (struct grid_node_storage *gn_storage, uint32_t totalSize, uint32_t usedSize);
extern void set_grid_tlv_GridStorage_NearlineSize            (struct grid_node_storage *gn_storage, uint32_t totalSize, uint32_t usedSize);
extern void set_grid_tlv_GridStorage_SeCalendar              (struct grid_node_storage *gn_storage, enum list_opcode l_opcode, void *list_arg);
extern void set_grid_tlv_GridStorage_Name                    (struct grid_node_storage *gn_storage, const char* name);

extern struct grid_node*            lookup_grid_node_by_site_id                         (uint32_t id);
extern struct grid_node_service*    lookup_grid_node_service_by_grid_node_and_sub_id    (struct grid_node *gn, uint32_t id);
extern struct grid_node_computing*  lookup_grid_node_computing_by_grid_node_and_sub_id  (struct grid_node *gn, uint32_t id);
extern struct grid_node_subcluster* lookup_grid_node_subcluster_by_grid_node_and_sub_id (struct grid_node *gn, uint32_t id);
extern struct grid_node_storage*    lookup_grid_node_storage_by_grid_node_and_sub_id    (struct grid_node *gn, uint32_t id);

extern struct grid_node_service*    create_new_grid_node_service    (struct grid_node *gn, uint32_t id);
extern struct grid_node_computing*  create_new_grid_node_computing  (struct grid_node *gn, uint32_t id);
extern struct grid_node_subcluster* create_new_grid_node_subcluster (struct grid_node *gn, uint32_t id);
extern struct grid_node_storage*    create_new_grid_node_storage    (struct grid_node *gn, uint32_t id);

extern void                         ospf_grid_site_lsa_schedule     (struct grid_node_site       *gn_site,       enum grid_sched_opcode opcode);
extern void                         ospf_grid_storage_lsa_schedule  (struct grid_node_storage    *gn_storage,    enum grid_sched_opcode opcode);
extern void                         ospf_grid_computing_lsa_schedule(struct grid_node_computing  *gn_computing,  enum grid_sched_opcode opcode);
extern void                         ospf_grid_subcluster_lsa_schedule(struct grid_node_subcluster *gn_subcluster, enum grid_sched_opcode opcode);
extern void                         ospf_grid_service_lsa_schedule  (struct grid_node_service    *gn_service,    enum grid_sched_opcode opcode);

extern uint16_t                     stream_to_struct_grid_tlv_GridSite    (struct grid_node_site *gn_site, struct grid_tlv_header *tlvh0, u_int16_t subtotal, u_int16_t total);
extern uint16_t                     stream_to_struct_grid_tlv_GridService (struct grid_node_service *gn_service, struct grid_tlv_header *tlvh0, u_int16_t subtotal, u_int16_t total);
extern uint16_t                     stream_to_struct_grid_tlv_GridComputingElement (struct grid_node_computing *gn_computing, struct grid_tlv_header *tlvh0, u_int16_t subtotal, u_int16_t total);
extern uint16_t                     stream_to_struct_grid_tlv_GridStorage (struct grid_node_storage *gn_storage, struct grid_tlv_header *tlvh0, u_int16_t subtotal, u_int16_t total);
extern uint16_t                     stream_to_struct_grid_tlv_GridSubCluster (struct grid_node_subcluster *gn_subcluster, struct grid_tlv_header *tlvh0, u_int16_t subtotal, u_int16_t total);

extern uint16_t                     stream_to_struct_unknown_tlv    (struct grid_tlv_header *tlvh);
extern struct interface*            uni_interface_lookup            (void);
extern struct ospf_interface*       lookup_oi_by_ifp                (struct interface *ifp);
extern int                          initialize_grid_node_params     (struct grid_node *gn);
extern int                          grid_node_delete_node           (struct grid_node *gn);

#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_OSPF_GRID */
/* End of automaticaly generated code */
