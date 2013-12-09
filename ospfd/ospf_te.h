/*
 * This is an implementation of draft-katz-yeung-ospf-traffic-06.txt
 * Copyright (C) 2001 KDD R&D Laboratories, Inc.
 * http://www.kddlabs.co.jp/
 *
 * Copyright (C) 2008 Adam Kaliszan     (PSNC) <kaliszan_at_man.poznan.pl>
 * Copyright (C) 2008 Damian Parniewicz (PSNC) <damianp_at_man.poznan.pl>
 * Copyright (C) 2008 Lukasz Lopatowski (PSNC) <llopat_at_man.poznan.pl>
 * Copyright (C) 2008 Jakub Gutkowski   (PSNC) <jgutkow_at_man.poznan.pl>
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 * 
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

/* TODO Adam: move it to memtypes.h file*/
#define MTYPE_OSPF_TE_RA_HARMONY 1

#define OSPF_DEBUG_TE_GENERATE        0x00000001
#define OSPF_DEBUG_TE_ORIGINATE       0x00000002
#define OSPF_DEBUG_TE_FLUSH           0x00000004
#define OSPF_DEBUG_TE_REFRESH         0x00000008

#define OSPF_DEBUG_TE_FEED_UP         0x00000010
#define OSPF_DEBUG_TE_FEED_DOWN       0x00000020
#define OSPF_DEBUG_TE_UNI_TO_INNI     0x00000040
#define OSPF_DEBUG_TE_INNI_TO_UNI     0x00000080
#define OSPF_DEBUG_TE_LSA_NEW         0x00000100
#define OSPF_DEBUG_TE_LSA_DELETE      0x00000200
#define OSPF_DEBUG_TE_ISM_CHANGE      0x00000400
#define OSPF_DEBUG_TE_NSM_CHANGE      0x00000800
#define OSPF_DEBUG_TE_INITIALIZATION  0x00001000
#define OSPF_DEBUG_TE_READ_IFP        0x00002000
#define OSPF_DEBUG_TE_CORBA_UPDATE    0x00004000
#define OSPF_DEBUG_TE_CORBA_SET       0x00008000
#define OSPF_DEBUG_TE_USER            0x00010000
#define OSPF_DEBUG_TE_ALL             0xFFFFFFFF

#define IS_DEBUG_TE(a) \
  (OspfTE.debug & OSPF_DEBUG_TE_ ## a)

#define TE_DEBUG_ON(a)  OspfTE.debug |= (OSPF_DEBUG_TE_ ## a)
#define TE_DEBUG_OFF(a) OspfTE.debug &= ~(OSPF_DEBUG_TE_ ## a)


#ifndef _ZEBRA_OSPF_MPLS_TE_H
#define _ZEBRA_OSPF_MPLS_TE_H

#define USE_UNTESTED_OSPF_TE               1
#define USE_UNTESTED_OSPF_TE_CORBA_UPDATE  1
#define USE_UNTESTED_OSPF_TE_CORBA_HARMONY 1

/*
 * Opaque LSA's link state ID for Traffic Engineering is
 * structured as follows.
 *
 *        24       16        8        0
 * +--------+--------+--------+--------+
 * |    1   |........|........|........|
 * +--------+--------+--------+--------+
 * |<-Type->|<------- Instance ------->|
 *
 *
 * Type:      IANA has assigned '1' for Traffic Engineering.
 * Instance:  User may select an arbitrary 24-bit value. [IETF-RFC4940]
 *
 */

#define	LEGAL_TE_INSTANCE_RANGE(i)	(0 <= (i) && (i) <= 0xffff)

/*
 *        24       16        8        0
 * +--------+--------+--------+--------+ ---
 * |   LS age        |Options |   10   |  A
 * +--------+--------+--------+--------+  |
 * |    1   |   0    |    Instance     |  |
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

/*
 * Following section defines TLV (tag, length, value) structures,
 * used for Traffic Engineering.
 */
struct te_tlv_header
{
  u_int16_t	type;			/* TE_TLV_XXX (see below) */
  u_int16_t	length;			/* Value portion only, in octets */
};

#ifndef TLV_HDR_SIZE
#define TLV_HDR_SIZE \
	(sizeof (struct te_tlv_header))
#endif

#ifndef TLV_BODY_SIZE
#define TLV_BODY_SIZE(tlvh) \
	(uint16_t)(ROUNDUP (ntohs ((tlvh)->length), sizeof (u_int32_t)))
#endif

#ifndef TLV_SIZE
#define TLV_SIZE(tlvh) \
	(TLV_HDR_SIZE + TLV_BODY_SIZE(tlvh))
#endif

#ifndef TLV_HDR_TOP
#define TLV_HDR_TOP(lsah) \
	(struct te_tlv_header *)((char *)(lsah) + OSPF_LSA_HEADER_SIZE)
#endif

#ifndef TLV_HDR_NEXT
#define TLV_HDR_NEXT(tlvh) \
	(struct te_tlv_header *)((char *)(tlvh) + TLV_SIZE(tlvh))
#endif

#ifndef TLV_HEADER_SIZE
#define TLV_HEADER_SIZE 4
#endif

/*
 * Following section defines TLV body parts.
 */

#define TE_TLV_ROUTER_ADDR                      1
/** Router Address TLV *//* Mandatory */
struct te_tlv_router_addr
{
  struct te_tlv_header  header;             /* Value length is 4 octets. */
  /*FIXME Adam: is this TLV empty ??? */
};

#define TE_ROUTER_ADDR_SUBTLV_ROUTER_ADDR       1
/** Router Address Sub-TLV: Router Address *//* Mandatory */
struct te_router_addr_subtlv_router_addr
{
  struct te_tlv_header  header;
  struct in_addr        value;
};

#define TE_ROUTER_ADDR_SUBTLV_AA_ID             100
/** Router Address Sub-TLV: Associated Area ID *//* Optional */
struct te_router_addr_subtlv_aa_id	
{
  struct te_tlv_header  header;
  u_int32_t             area_id;
};

/*
 * Start of Geysers GMPLS OSPF-TE parameters
 */

#define TE_ROUTER_ADDR_SUBTLV_POWER_CONSUMPTION  150    
/** Router Address Sub-TLV: Power Consumption *//* Optional */
struct te_router_addr_subtlv_power_consumption	
{
  struct te_tlv_header  header;
  float             	power_consumption;
};

/*
 * End of Geysers GMPLS OSPF-TE parameters
 */

/** *********************************************************/

#define TE_TLV_TNA_ADDR                         32768
/** TNA Address TLV */
struct te_tlv_tna_addr
{
  struct te_tlv_header   header;
  struct zlist           tna_addr_data;
};

#define TE_TNA_ADDR_SUBTLV_TNA_ADDR_IPV4        32776
/** TNA Address Sub-TLV: TNA Address IPv4 *//* Optional */
struct te_tna_addr_subtlv_tna_addr_ipv4
{
  struct te_tlv_header   header;             /** Value length is 8 octets. */
  u_char                 addr_length;	       /** Value specifies the length of TNA address specified in number of bits */
  u_char                 reserved[3];
  struct in_addr         value;              /** TNA address IPv4 */
};

#define TE_TNA_ADDR_SUBTLV_TNA_ADDR_IPV6        32778
/** TNA Address Sub-TLV: TNA Address IPv6 *//* Optional */
struct te_tna_addr_subtlv_tna_addr_ipv6
{
  struct te_tlv_header   header;              /** Value length is 20 octets. */
  u_char                 addr_length;         /** Value specifies the length of TNA address specified in number of bits */
  u_char                 reserved[3];
  struct in6_addr        value;               /** TNA address IPv6 */
};

#define TE_TNA_ADDR_SUBTLV_TNA_ADDR_NSAP        32779
/** TNA Address Sub-TLV: TNA Address NSAP *//* Optional */
struct te_tna_addr_subtlv_tna_addr_nsap
{
  struct te_tlv_header   header;              /** Value length is 24 octets. */
  u_char                 addr_length;         /** Value specifies the length of TNA address specified in number of bits */
  u_char                 reserved[3];
  u_int32_t              value[5];            /** TNA address NSAP */
};

#define TE_TNA_ADDR_SUBTLV_NODE_ID              32777
/** TNA Address Sub-TLV: Node ID *//* Optional */
struct te_tna_addr_subtlv_node_id
{
  struct te_tlv_header   header;            /** Value length is 4 octets. */
  struct in_addr         value;             /** node IP address */
};

#define TE_TNA_ADDR_SUBTLV_ANC_RC_ID                32792
/** TNA Address Sub-TLV: Ancestor RC (Routing Controller) ID *//* Don't sent it in LEVEL1 (ENNI instance) */
struct te_tna_addr_subtlv_anc_rc_id           /** temporary TLV-Type */
{
  struct te_tlv_header   header;            /** Value length is 4 octets. */
  struct in_addr         value;             /** 0.0.0.0 default */
};

struct tna_addr_data_element
{
  struct te_tna_addr_subtlv_node_id        node_id;        /** Node ID */
  struct te_tna_addr_subtlv_anc_rc_id      anc_rc_id;      /** Ancestor RC ID */
  struct zlist                             tna_addr;
};

struct tna_addr_value
{
  struct te_tna_addr_subtlv_tna_addr_ipv4  tna_addr_ipv4;  /** TNA Address IPv4 */
  struct te_tna_addr_subtlv_tna_addr_ipv6  tna_addr_ipv6;  /** TNA Address IPv6 */
  struct te_tna_addr_subtlv_tna_addr_nsap  tna_addr_nsap;  /** TNA Address NSAP */
};

/** ********************************************************/
/* Node Attribute TLV */
#define	TE_TLV_NODE_ATTR         4
struct te_tlv_node_attr
{
  struct te_tlv_header	header;
  /* FIXME Adam. Is this TLV empty ??? */
  /* A set of node-attr-sub-TLVs will follow. */
};

#define TE_NODE_ATTR_SUBTLV_NODE_IP4_LCL_PREFIX 3
/** Node Attribute Sub-TLV: Node IPv4 Local Prefix *//* Optional */
struct te_node_attr_subtlv_node_ip4_lcl_prefix
{
  struct te_tlv_header   header;            /** Value length is variable (8*n) octets. */	
  struct zlist           prefix_list;       /** each value is 8-octets of struct prefix_ip4 */
};

/** supporting for struct te_node_attr_subtlv_node_ip4_lcl_prefix */
struct prefix_ip4
{
  struct in_addr         netmask;           /** Network mask */
  struct in_addr         address_ip4;       /** IPv4 Address */		
};

#define TE_NODE_ATTR_SUBTLV_NODE_IP6_LCL_PREFIX 4
/** Node Attribute Sub-TLV: Node IPv6 Local Prefix *//* Optional */
struct te_node_attr_subtlv_node_ip6_lcl_prefix
{
  struct te_tlv_header   header;            /** Value length is variable (n*20) octets. */
  struct zlist           prefix_list;       /** each value is 20-octets of struct prefix_ip6 */
};

/** supporting for struct te_node_attr_subtlv_node_ip6_lcl_prefix */
struct prefix_ip6
{
  u_char                 prefixlen;         /** Prefix Length */
  u_char                 prefixopt;	        /** Prefix Options */
  u_char                 reserved[2];
  struct in6_addr        address_ip6;       /** IPv6 Address */
};

#define TE_NODE_ATTR_SUBTLV_LCL_TE_ROUTER_ID    5
/** Node Attribute Sub-TLV: Local TE Router ID *//* Optional */
struct te_node_attr_subtlv_lcl_te_router_id
{
  struct te_tlv_header   header;            /** Value length is 4 octets. */
  u_int32_t              lcl_te_router_id;  /** Local TE Router ID Identifier */
};

#define TE_NODE_ATTR_SUBTLV_AA_ID               40005
/** Node Attribute Sub-TLV: Associated Area ID *//* Optional */
struct te_node_attr_subtlv_aa_id            /** temporary TLV-Type */
{
  struct te_tlv_header   header;            /** Value length is 4 octets. */
  u_int32_t              area_id;           /** Associated Area ID */
};

/** ****************************************************** **/

/* Link TLV */
#define	TE_TLV_LINK         2
struct te_tlv_link
{
  struct te_tlv_header	header;
  /* A set of link-sub-TLVs will follow. */
};

#define TE_LINK_SUBTLV_LINK_TYPE                1
/** Link Type Sub-TLV *//* Mandatory */
struct te_link_subtlv_link_type
{
  struct te_tlv_header  header;             /** Value length is 1 octet. */
  struct {
#define	LINK_TYPE_SUBTLV_VALUE_PTP  1
#define	LINK_TYPE_SUBTLV_VALUE_MA   2
      u_char            value;
      u_char            padding[3];
  } link_type;
};

#define TE_LINK_SUBTLV_LINK_ID                  2
/** Link Sub-TLV: Link ID *//* Mandatory */
struct te_link_subtlv_link_id
{
  struct te_tlv_header  header;             /** Value length is 4 octets. */
  struct in_addr        value;              /** Same as router-lsa's link-id. */
};

#define TE_LINK_SUBTLV_LCLIF_IPADDR             3
/** Link Sub-TLV: Local Interface IP Address *//* Optional */
struct te_link_subtlv_lclif_ipaddr
{
  struct te_tlv_header  header;             /** Value length is 4 x N octets. */
  struct in_addr        value[1];           /** Local IP address(es). */
};

#define TE_LINK_SUBTLV_RMTIF_IPADDR             4
/** Link Sub-TLV: Remote Interface IP Address *//* Optional */
struct te_link_subtlv_rmtif_ipaddr
{
  struct te_tlv_header  header;             /** Value length is 4 x N octets. */
  struct in_addr        value[1];           /** Neighbor's IP address(es). */
};

#define TE_LINK_SUBTLV_TE_METRIC                5
/** Link Sub-TLV: Traffic Engineering Metric *//* Optional */
struct te_link_subtlv_te_metric
{
  struct te_tlv_header  header;             /** Value length is 4 octets. */
  u_int32_t             value;              /** Link metric for TE purpose. */
};

#define TE_LINK_SUBTLV_MAX_BW                   6
/** Link Sub-TLV: Maximum Bandwidth *//* Optional */
struct te_link_subtlv_max_bw
{
  struct te_tlv_header   header;            /** Value length is 4 octets. */
  float                  value;             /** bytes/sec */
};

#define TE_LINK_SUBTLV_MAX_RSV_BW               7
/** Link Sub-TLV: Maximum Reservable Bandwidth *//* Optional */
struct te_link_subtlv_max_rsv_bw
{
  struct te_tlv_header   header;            /** Value length is 4 octets. */
  float                  value;             /** bytes/sec */
};

#define TE_LINK_SUBTLV_UNRSV_BW                 8
/** Link Sub-TLV: Unreserved Bandwidth *//* Optional */
struct te_link_subtlv_unrsv_bw
{
  struct te_tlv_header   header;            /** Value length is 32 octets. */
  float                  value[8];          /** One for each priority level. */
};

#define TE_LINK_SUBTLV_RSC_CLSCLR               9
/** Link Sub-TLV: Resource Class/Color *//* Optional */
struct te_link_subtlv_rsc_clsclr
{
  struct te_tlv_header   header;            /** Value length is 4 octets. */
  u_int32_t              value;             /** Admin. group membership. */
};

/* Here are "non-official" architechtual constants. */
#define MPLS_TE_MINIMUM_BANDWIDTH	1.0	/* Reasonable? *//* XXX */

/*
 * Phosphorus GMPLS OSPF-TE parameters
 */

#define TE_LINK_SUBTLV_LINK_LCL_RMT_IDS         11
/** Link Sub-TLV: Link Local/Remote Identifiers *//* Optional */
struct te_link_subtlv_link_lcl_rmt_ids
{
  struct te_tlv_header   header;            /** Value length is 8 octets. */
  u_int32_t              local_id;          /** Link local ID */
  u_int32_t              remote_id;         /** Link remote ID */
};

#define TE_LINK_SUBTLV_LINK_PROTECT_TYPE        14
/** Link Sub-TLV: Link Protection Type *//* Optional */
struct te_link_subtlv_link_protect_type
{
  struct te_tlv_header   header;            /** Value length is 1 octets. */
  u_char                 value;             /** Protection Capability */
  u_char                 padding[3];        /**to have a 4 bytes length of the subTLV*/
};

#define PROTECTION_EXTRA_TRAFFIC    0x01
#define PROTECTION_UNPROTECTED      0x02
#define PROTECTION_SHARED           0x04
#define PROTECTION_DEDICATED_1_1    0x08
#define PROTECTION_DEDICATED_1PLUS1 0x10
#define PROTECTION_ENHANCED         0x20

#define TE_LINK_SUBTLV_IF_SW_CAP_DESC           15
/** Link Sub-TLV: Interface Switching Capability Descriptor *//* Optional */
struct te_link_subtlv_if_sw_cap_desc
{
  struct te_tlv_header   header;            /** Value length is variable. */
#define CAPABILITY_PSC1 1
#define CAPABILITY_PSC2 2
#define CAPABILITY_PSC3 3
#define CAPABILITY_PSC4 4
#define CAPABILITY_L2SC 51
#define CAPABILITY_TDM 100
#define CAPABILITY_LSC 150
#define CAPABILITY_FSC 200
  u_char                 switching_cap;     /** Switching Capability */
#define LINK_IFSWCAP_SUBTLV_ENC_PKT         1
#define LINK_IFSWCAP_SUBTLV_ENC_ETH         2
#define LINK_IFSWCAP_SUBTLV_ENC_PDH         3
#define LINK_IFSWCAP_SUBTLV_ENC_SONETSDH    5
#define LINK_IFSWCAP_SUBTLV_ENC_DIGIWRAP    7
#define LINK_IFSWCAP_SUBTLV_ENC_LAMBDA      8
#define LINK_IFSWCAP_SUBTLV_ENC_FIBER       9
#define LINK_IFSWCAP_SUBTLV_ENC_FIBRCHNL    11
  u_char                 encoding;          /** Encoding */
  u_char                 reserved[2];
#define LINK_MAX_PRIORITY 8
  float                  maxLSPbw[LINK_MAX_PRIORITY]; /** Max LSP Bandwidth 8 x 4 bytes of IEEE floating point format (bytes/sec) */

  union {
    struct {
      float              min_lsp_bw;        /** Minimul LSP Bandwidth */
      u_int16_t          mtu;               /** Interface MTU */
      u_char             padding[2];
    } swcap_specific_psc;

    struct {
      float              min_lsp_bw;        /** Minimul LSP Bandwidth */
      u_char             indication;        /** Indication */
      u_char             padding[3];
    } swcap_specific_tdm;

  } swcap_specific_info;
};

#define	TE_LINK_SUBTLV_SHARED_RISK_LINK_GRP     16
/** Link Sub-TLV: Shared Risk Link Group *//* Optional */
struct te_link_subtlv_shared_risk_link_grp
{
  struct te_tlv_header   header;            /** Value length is variable (n*4 octets). */
  struct zlist           values;            /** each value is 4-octet of Shared Risk Link Group Value */
};

#define TE_LINK_SUBTLV_LCL_RMT_TE_ROUTER_ID     17
/** Link Sub-TLV: Local and Remote TE Router ID *//* Optional */
struct te_link_subtlv_lcl_rmt_te_router_id
{
  struct te_tlv_header   header;            /** Value length is 8 octets. */
  u_int32_t              lcl_router_id;     /** Local router ID */
  u_int32_t              rmt_router_id;     /** Remote router ID */
};


#define TE_LINK_SUBTLV_LCL_NODE_ID              32773
/** Link Sub-TLV: Local Node ID *//* Optional */
struct te_link_subtlv_lcl_node_id
{
  struct te_tlv_header   header;            /** Value length is 4 octets. */
  struct in_addr         value;             /** Local node IP address. */
};

#define TE_LINK_SUBTLV_RMT_NODE_ID              32774
/** Link Sub-TLV: Remote Node ID *//* Optional */
struct te_link_subtlv_rmt_node_id
{
  struct te_tlv_header   header;            /** Value length is 4 octets. */
  struct in_addr         value;             /** Remote node IP address. */
};

#define TE_LINK_SUBTLV_SSDH_IF_SW_CAP_DESC      32775
/** Link Sub-TLV: Sonet/SDH Interface Switching Capability Descriptor *//* Optional */
struct te_link_subtlv_ssdh_if_sw_cap_desc
{
#define SSDH_SIGNAL_TYPE_VT1_5_SPE_VC_11        1
#define SSDH_SIGNAL_TYPE_VT2_SPE_VC_12          2
#define SSDH_SIGNAL_TYPE_VT3_SPE                3
#define SSDH_SIGNAL_TYPE_VT6_SPE_VC_2           4
#define SSDH_SIGNAL_TYPE_STS_1_SPE_VC_3         5
#define SSDH_SIGNAL_TYPE_STS_3c_SPE_VC_4        6
#define SSDH_SIGNAL_TYPE_STS_12c_SPE_VC_4_4c    21
#define SSDH_SIGNAL_TYPE_STS_48c_SPE_VC_4_16c   22
#define SSDH_SIGNAL_TYPE_STS_192c_SPE_VC_4_64c  23
  struct te_tlv_header   header;            /** Value length is variable (4+n*4 octets). */
  u_char                 switching_cap;     /** Switching Capability */
  u_char                 encoding;          /** Encoding */
  u_char                 reserved[2];
  struct zlist           signals_list;      /** each value is 4-octets of struct signal_unalloc_tslots */
};

/** supporting for struct te_link_subtlv_ssdh_if_sw_cap_desc */
struct signal_unalloc_tslots
{
  u_char                 signal_type;       /** Signal type */
  u_char                 unalloc_tslots[3]; /** Number of unallocated timeslots */
};

#define TE_LINK_SUBTLV_GENERAL_CAP              32790
/** Link Sub-TLV: General Capabilities *//* Optional */
struct te_link_subtlv_general_cap          /** temporary TLV-Type */	
{
  struct te_tlv_header   header;           /** Value length is 1 octets. */

#define GEN_CAP_S_RESERVED		0
#define GEN_CAP_S_SONET_SW_CAP		1
#define GEN_CAP_S_SDH_SW_CAP		2
#define GEN_CAP_S_SONET_SDH_SW_CAP	3
#define GEN_CAP_T			4
#define GEN_CAP_M			8

  u_char                 flags;
  u_char                 padding[3];
};

#define TE_LINK_SUBTLV_HIERARCHY_LIST           32791
/** Link Sub-TLV: Hierarchy List *//* Optional */
struct te_link_subtlv_hierarchy_list       /** temporary TLV-Type */
{
  struct te_tlv_header   header;           /** Value length is variable (n*4) octets. */
  struct zlist           hierarchy_list;   /** each value is 4-octet Routing Controller ID ( in_addr ) */
};

#define TE_LINK_SUBTLV_ANC_RC_ID                32792
/** Link Sub-TLV: Ancestor RC (Routing Controller) ID *//* Optional */
struct te_link_subtlv_anc_rc_id           /** temporary TLV-Type */
{
  struct te_tlv_header   header;          /** Value length is variable (n*4) octets. */
  struct in_addr         value;           /** ??????? */
};

/** *************** GMPLS ASON Routing ******************************** */

#define TE_LINK_SUBTLV_BAND_ACCOUNT             32793
/** Link Sub-TLV: Technology Specific Bandwidth Accounting *//* Optional */
struct te_link_subtlv_band_account        /** temporary TLV-Type */
{
  struct te_tlv_header   header;          /** Value length is variable (n*4) octets. */
  struct zlist           signals_list;    /** each value is 4-octets of struct signal_unalloc_tslots */
};

#define TE_LINK_SUBTLV_OSPF_DOWN_AA_ID          32794
/** Link Sub-TLV: OSPF Downstream Associated Area ID *//* Optional */
struct te_link_subtlv_ospf_down_aa_id     /** temporary TLV-Type */
{
  struct te_tlv_header   header;          /** Value length is variable (n*4) octets. */
  struct zlist           area_id_list;    /** each value is 4-octet Associated Area ID ( u_int32_t )*/
};

#define TE_LINK_SUBTLV_AA_ID                    32795
/** Link Sub-TLV: Associated Area ID *//* Optional */
struct te_link_subtlv_aa_id               /** temporary TLV-Type */
{
  struct te_tlv_header   header;          /** Value length is 4 octets. */
  u_int32_t              area_id;         /** Associated Area ID */
};

/** *************** GMPLS All-optical Extensions ********************** */

#define TE_LINK_SUBTLV_BER_ESTIMATE             32796
/** Link Sub-TLV: BER Estimate *//* Optional */
struct te_link_subtlv_ber_estimate        /** temporary TLV-Type */
{
  struct te_tlv_header   header;          /** Value length is 1 octets. */
  u_char                 value;           /** The exponent from the BER representation */
  u_char                 padding[3];
};

#define TE_LINK_SUBTLV_SPAN_LENGTH              32781
/** Link Sub-TLV: Span Length *//* Optional */
struct te_link_subtlv_span_length
{
  struct te_tlv_header   header;          /** Value length is 4 octets. */
  u_int32_t              value;           /** The total length of the WDM span in meters. */
};

#define TE_LINK_SUBTLV_OSNR                     32798
/** Link Sub-TLV: OSNR *//* Optional */
struct te_link_subtlv_osnr                /** temporary TLV-Type */
{
  struct te_tlv_header   header;          /** Value length is 4 octets. */
  u_int32_t              value;           /** The value in dB of the signal to noise ratio.*/
};

#define TE_LINK_SUBTLV_D_PDM                    32780
/** Link Sub-TLV: Dpdm *//* Optional */
struct te_link_subtlv_d_pdm
{
  struct te_tlv_header   header;          /** Value length is 4 octets. */
  float                  value;           /** The fiber PDM parameter in ps per sqrt(km) of the k-th span in the circuit */
};

#define TE_LINK_SUBTLV_AMP_LIST                 32782
/** Link Sub-TLV: Amplifiers List *//* Optional */
struct te_link_subtlv_amp_list
{
  struct te_tlv_header   header;          /** Value length is variable (n*8) octets. */	
  struct zlist           amp_list;        /** each value is 8-octets of struct amp_par */
};

/** supporting for struct te_link_subtlv_amp_list */
struct amp_par
{
  /*TODO Adam: Make sure, that alvays all is stored in network order */
  u_int32_t  gain;                        /** Amplifier gain */
  float      noise;                       /** Amplifier noise figure */
};

#define TE_LINK_SUBTLV_AV_WAVE_MASK             32783
/** Link Sub-TLV: Available Wavelength Mask *//* Optional */
struct te_link_subtlv_av_wave_mask
{
  struct te_tlv_header   header;          /** Value length is variable (n*4) octets. */
  u_char                 action;
  u_char                 reserved;
  u_int16_t              num_wavelengths; /** Number of wavelengths represented by the bit map */
  u_int32_t              label_set_desc;  /** Label set description  */
  struct zlist           bitmap_list;     /** Each bit in the bit map represents a particular frequency indicating the frequency is available / not-available (u_int32_t)*/
};

#define TE_LINK_SUBTLV_TE_LINK_CALENDAR         32784
/** Link Sub-TLV: TE-link Calendar */
struct te_link_subtlv_te_link_calendar
{
  struct te_tlv_header   header;          /** Value length is variable (n*36) octets. */
  struct zlist           te_calendar;     /** each value is struct te_link_calendar )*/
};

struct te_link_calendar
{
  /*TODO Adam: Make sure, that alvays all is stored in network order */
  u_int32_t              time;
  float                  value[8];
};

/*
 * End of Phosphorus GMPLS OSPF-TE parameters
 */

/*
 * Start of GEYSERS GMPLS OSPF-TE parameters
 */

#define TE_LINK_SUBTLV_POWER_CONSUMPTION  32785    
/** Link Sub-TLV: Power Consumption *//* Optional */
struct te_link_subtlv_power_consumption	
{
  struct te_tlv_header  header;
  float            	power_consumption;
};

#define TE_LINK_SUBTLV_DYNAMIC_REPLANNING  32786    
/** Link Sub-TLV: Dynamic re-planning *//* Optional */
struct te_link_subtlv_dynanic_replanning	
{
  struct te_tlv_header  header;
  float                 max_bandwidth_upgrade;             /** bytes/sec */
  float                 max_bandwidth_downgrade;           /** bytes/sec */
};

/*
 * End of GEYSERS GMPLS OSPF-TE parameters
 */

struct te_link
{
/**
 * According to MPLS-TE (draft) specification, 24-bit Opaque-ID field
 * is subdivided into 8-bit "unused" field and 16-bit "instance" field.
 * In this implementation, each Link-TLV has its own instance.
 */
  u_int32_t instance_na;
  u_int32_t instance_li;
  u_int32_t instance_tna;

  int harmony_ifp;       ///1 - this is te_link harmony

/**
 * Reference pointer to:
 * - Zebra-interface in MPLS architecture type
 * - Control Plane interface in GMPLS / G2MPLS architecture type
 */
  struct interface *ifp;
/**
 * Area info in which this MPLS-TE link belongs to.
 */
  struct ospf_area *area;

/**
 * Flags to manage this link parameters:
 */
  u_int32_t flags;
#define LPFLG_LI_LOOKUP_DONE		0x01
#define LPFLG_TNA_LOOKUP_DONE		0x02
#define LPFLG_LSA_LI_ENGAGED		0x04
#define LPFLG_LSA_TNA_ENGAGED		0x08
#define LPFLG_LSA_LI_FORCED_REFRESH	0x10
#define LPFLG_LSA_TNA_FORCED_REFRESH	0x20

#define LPFLG_LSA_ORIGINATED		0x80000000

  struct in_addr area_adr;

  uint16_t is_set_linkparams_link_type;


  /* Store Link-TLV in network byte order. */
  struct te_tlv_link                             link_header;
  struct te_link_subtlv_link_type                link_type;            /** Link Type */
  struct te_link_subtlv_link_id                  link_id;              /** Link ID */
  struct te_link_subtlv_lclif_ipaddr             lclif_ipaddr;         /** Local Interface IP Address */
  struct te_link_subtlv_rmtif_ipaddr             rmtif_ipaddr;         /** Remote Interface IP Address */
  struct te_link_subtlv_te_metric                te_metric;            /** Traffic Engineering Metric */
  struct te_link_subtlv_max_bw                   max_bw;               /** Link Maximum Bandwidth */
  struct te_link_subtlv_max_rsv_bw               max_rsv_bw;           /** Maximum Reservable Bandwidth */
  struct te_link_subtlv_unrsv_bw                 unrsv_bw;             /** Unreserved Bandwidth */
  struct te_link_subtlv_rsc_clsclr               rsc_clsclr;           /** Resource Class/Color */

  struct te_link_subtlv_link_lcl_rmt_ids         link_lcl_rmt_ids;     /** Link Local/Remote Identifiers */
  struct te_link_subtlv_link_protect_type        link_protect_type;    /** Link Protection Type */
  struct zlist                                   if_sw_cap_descs;      /** LIST of Interface Switching Capability Descriptors */
  struct te_link_subtlv_shared_risk_link_grp     shared_risk_link_grp; /** Shared Risk Link Group */
  struct te_link_subtlv_lcl_rmt_te_router_id     lcl_rmt_te_router_id; /** Local and Remote TE Router ID */

/** **************** OIF E-NNI Routing ************************************* */
  struct te_link_subtlv_lcl_node_id              lcl_node_id;          /** Local Node ID */
  struct te_link_subtlv_rmt_node_id              rmt_node_id;          /** Remote Node ID */
  struct te_link_subtlv_ssdh_if_sw_cap_desc      ssdh_if_sw_cap_desc;  /** Sonet/SDH Interface Switching Capability Descriptor */
  struct te_link_subtlv_general_cap              general_cap;          /** General Capabilities */
  struct te_link_subtlv_hierarchy_list           hierarchy_list;       /** Hierarchy List */
  struct te_link_subtlv_anc_rc_id                anc_rc_id;            /** Ancestor Routing Controller ID */

/** **************** GMPLS ASON Routing ************************************ */
  struct te_link_subtlv_band_account             band_account;         /** Technology Specific Bandwidth Accounting */
  struct te_link_subtlv_ospf_down_aa_id          ospf_down_aa_id;      /** OSPF Downstream Associated Area ID */	
  struct te_link_subtlv_aa_id                    aa_id;                /** Associated Area ID */

/** **************** GMPLS All-optical Extensions ************************** */
  struct te_link_subtlv_ber_estimate             ber_estimate;         /** BER Estimate */
  struct te_link_subtlv_span_length              span_length;          /** Span Length */
  struct te_link_subtlv_osnr                     osnr;                 /** OSNR */
  struct te_link_subtlv_d_pdm                    d_pdm;                /** D_PDM */
  struct te_link_subtlv_amp_list                 amp_list;             /** Amplifiers List */
  struct te_link_subtlv_av_wave_mask             av_wave_mask;         /** Available Wavelength Mask */
  struct te_link_subtlv_te_link_calendar         te_link_calendar;     /** TE-link Calendar */

  /** *************** TNA Address TLV **************************************** */
  struct te_tlv_tna_addr                         tna_address;          /** TNA Address */

  /** *************** GEYSERS-project extensions ***************************** */
  struct te_link_subtlv_power_consumption        power_consumption;    /** Power consumption */
  struct te_link_subtlv_dynanic_replanning	     dynamic_replanning;   /** Dynamic re-planning */
};

struct te_node_attr	/** Node Attribute */
{
  struct te_tlv_node_attr                        link_header;
  struct te_node_attr_subtlv_node_ip4_lcl_prefix node_ip4_lcl_prefix;  /** Node IPv4 Local Prefix */
  struct te_node_attr_subtlv_node_ip6_lcl_prefix node_ip6_lcl_prefix;  /** Node IPv6 Local Prefix */
  struct te_node_attr_subtlv_lcl_te_router_id    lcl_te_router_id;     /** Local TE Router ID */
  struct te_node_attr_subtlv_aa_id               aa_id;                /** Associated Area ID */
};

struct te_router_addr	/** Router Address */
{
  struct te_tlv_router_addr                      link_header;
  struct te_router_addr_subtlv_router_addr       router_addr;          /** Router Address */
  struct te_router_addr_subtlv_aa_id             aa_id;                /** Associated Area ID */
  struct te_router_addr_subtlv_power_consumption power_consumption;    /** Power consumption */
};

struct raHarmony
{
  int                   lookup_done;
  int                   engaged;
  int                   forced_refresh;
  unsigned int          instance_id;
  struct te_router_addr router_addr;
};

/*
 * End of Phosphorus GMPLS OSPF-TE parameters
 */


extern struct ospf_te OspfTE;

enum type_of_lsa_info {
  ROUTE_ADDRESS, NODE_ATRIBUTE, LINK, TNA_ADDRESS
};

enum sched_opcode {
  REORIGINATE_PER_AREA, REFRESH_THIS_LSA, FLUSH_THIS_LSA, ORIGINATE
};

/* Prototypes. */
extern void ospf_te_config_write_router1 (struct vty *vty, adj_type_t interface_type);
extern int  te_link_node_write(struct vty *vty);
extern int  ospf_te_init (void);
extern void ospf_te_term (void);
#ifdef GMPLS
int         read_te_params_from_ifp(struct interface *ifp);
void        router_id_update_te(adj_type_t adj, uint32_t energyConsumption);
#endif

typedef enum {
  TNA_IP4,
  TNA_IP6,
  TNA_NSAP,
  TNA_NODE
} tna_addr_type_t;

#ifdef __cplusplus
extern "C" {
#endif

extern void update_corba_te_inf (uint8_t option, struct ospf_lsa *lsa);
extern struct te_tlv_header *te_tlv_lookup(struct ospf_lsa *lsa, uint16_t type);
extern struct te_tlv_header *te_subtlv_lookup(struct ospf_lsa *lsa, uint16_t type, uint16_t subtype);
extern int has_lsa_tlv_type(struct ospf_lsa *lsa, uint16_t type, uint16_t *length);
extern struct zlist lookup_lsas_from_lsdb(uint16_t type);

extern struct raHarmony*      lookup_hnode(struct in_addr ra, uint32_t area_id);
extern struct te_link*        lookup_hlink(struct in_addr node_id, uint32_t local_id);
extern struct te_link*        lookup_htna (struct in_addr node, struct tna_addr_value tna);

extern struct raHarmony* add_hnode (struct in_addr ra, uint32_t area_id);
extern int               del_hnode (struct in_addr ra, uint32_t area_id);
extern struct te_link*   add_hlink (struct in_addr node_id, uint32_t local_id);
extern int               del_hlink (struct te_link *link);
extern struct te_link*   add_htna  (struct in_addr node, struct tna_addr_value tna);
extern int               del_htna  (struct in_addr node, struct tna_addr_value tna);
extern struct ospf*      get_hospf (void);

extern void ospf_te_lsa_schedule (struct te_link *lp, enum sched_opcode opcode, enum type_of_lsa_info lsa_info);
extern void ospf_te_ra_harmony_lsa_schedule (enum sched_opcode opcode, struct ospf *ospf, struct ospf_area * area, struct raHarmony *rah);

extern void set_link_lcl_rmt_ids (struct te_link *lp, u_int32_t lcl_id, u_int32_t rmt_id);
extern void set_oif_lcl_node_id  (struct te_link *lp, struct in_addr address);
extern void set_oif_rmt_node_id  (struct te_link *lp, struct in_addr address);
extern void set_oif_anc_rc_id    (struct te_link *lp, struct in_addr address);

extern void set_linkparams_te_metric (struct te_link *lp, u_int32_t te_metric);
extern void set_link_protect_type(struct te_link *lp, u_char value);
extern void set_linkparams_max_bw (struct te_link *lp, float *fp);
extern void set_linkparams_max_rsv_bw (struct te_link *lp, float *fp);
extern void set_linkparams_unrsv_bw (struct te_link *lp, int priority, float *fp);
extern void set_linkparams_rsc_clsclr (struct te_link *lp, u_int32_t classcolor);

extern void set_all_opt_ext_d_pdm (struct te_link *lp, float *value);
extern void set_all_opt_ext_span_length (struct te_link *lp, u_int32_t value);
extern void add_all_opt_ext_amp_list (struct te_link *lp, u_int32_t gain_val, float *noise_val);
extern int clear_all_opt_ext_amp_list (struct te_link *lp);

extern void set_oif_ssdh_if_sw_cap_desc (struct te_link *lp);
extern void add_oif_ssdh_if_sw_cap_desc_signal (struct te_link *lp, u_char signal_type, u_char unalloc_tsl[]);
extern int  clear_oif_ssdh_if_sw_cap_desc_signal (struct te_link *lp);

extern void set_all_opt_ext_av_wave_mask (struct te_link *lp, u_int16_t num, u_int32_t label_set_desc);
extern void add_all_opt_ext_av_wave_mask_bitmap (struct te_link *lp, u_int32_t value);
extern int  clear_all_opt_ext_av_wave_mask (struct te_link *lp);

extern void set_linkparams_power_consumption (struct te_link *lp, float *fp);
extern void set_linkparams_dynanic_replanning (struct te_link *lp, float *upgrade, float *downgrade);

extern int  add_shared_risk_link_grp(struct te_link *lp, u_int32_t value);
extern int  del_shared_risk_link_grp(struct te_link *lp, u_int32_t value);
extern void add_all_opt_ext_te_link_calendar (struct te_link *lp, u_int32_t time, float *band);
extern int  del_all_opt_ext_te_link_calendar (struct te_link *lp, u_int32_t time, float *band);

extern uint8_t create_te_link_subtlv_if_sw_cap_desc (struct te_link *lp, u_char sw_cap, u_int8_t enc);
extern uint8_t delete_te_link_subtlv_if_sw_cap_desc (struct te_link *lp, u_char sw_cap, u_int8_t enc);
extern void set_if_sw_cap_max_bands (struct te_link *lp, u_char sw_cap, u_int8_t enc, float *maxBand);
extern void set_if_sw_cap_desc_psc (struct te_link *lp, u_char sw_cap, u_int8_t enc, float *min_lsp_bw, u_int16_t mtu);
extern void set_if_sw_cap_desc_tdm (struct te_link *lp, u_char sw_cap, u_int8_t enc, float *min_lsp_bw, u_int8_t indication);

extern void set_oif_tna_addr_ipv4 (struct tna_addr_value * tna_addr, u_char addr_length, struct in_addr *address);
extern void set_oif_tna_addr_ipv6 (struct tna_addr_value * tna_addr, u_char addr_length, struct in6_addr *address);
extern void set_oif_tna_addr_nsap (struct tna_addr_value * tna_addr, u_char addr_length, u_int32_t value[]);
extern void set_oif_node_id       (struct tna_addr_data_element *tna_addr, struct in_addr address);
extern void set_oif_tna_anc_rc_id (struct tna_addr_data_element *tna_addr, struct in_addr anc_rc_id);
extern int  add_tna_addr (struct te_link *lp, tna_addr_type_t type, struct in_addr node_id, struct in_addr anc_rc_id, u_char address_len, void *address);

#ifdef __cplusplus
}
#endif


#endif /* _ZEBRA_OSPF_MPLS_TE_H */
