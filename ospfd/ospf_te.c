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


#include <zebra.h>

#ifdef HAVE_OSPF_TE
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
#include "sockunion.h"    /* for inet_aton() */

#include "ospfd/ospfd.h"
#include "ospfd/ospf_interface.h"
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
#include "ospfd/ospf_te.h"
#include "ospfd/ospf_corba.h"
#include "ospfd/ospf_opaque.h"

#define OSPF_INST_TO_STR(X) ((X)==INNI ? "INNI" : ((X)==ENNI ? "ENNI" : ((X)==UNI ? "UNI" : "unknown"  )))


char Ospf_Te_link_prompt[50] = "%s(te-link)# ";

struct cmd_node ospf_te_link_node =
{
  OSPF_TE_LINK_NODE,

  Ospf_Te_link_prompt,
  1
};

/** Link Protection Type values */
struct pair_val_str pair_val_str_protection = 
{
    6,
    {{ "extra",     PROTECTION_EXTRA_TRAFFIC,      2},
      { "none",     PROTECTION_UNPROTECTED,        1},
      { "shared",   PROTECTION_SHARED,             1},
      { "1:1",      PROTECTION_DEDICATED_1_1,      2},
      { "1+1",      PROTECTION_DEDICATED_1PLUS1,   2},
      {"en",        PROTECTION_ENHANCED,           2}}
};

/** Interface Switching Capability types */
struct pair_val_str pair_val_str_swcap =
{
    8,
    {{ "psc1",      CAPABILITY_PSC1,         4},
    {  "psc2",      CAPABILITY_PSC2,         4}, 
    {  "psc3",      CAPABILITY_PSC3,         4}, 
    {  "psc4",      CAPABILITY_PSC4,         4},
    {  "l2sc",      CAPABILITY_L2SC,         2},
    {  "tdm",       CAPABILITY_TDM,          1}, 
    {  "lsc",       CAPABILITY_LSC,          2}, 
    {  "fsc",       CAPABILITY_FSC,          1}}
};

/** Sonet/SDH Signal Types*/
struct pair_val_str pair_val_str_signal_types =
{
    9,
    {{ "vt1.5",     SSDH_SIGNAL_TYPE_VT1_5_SPE_VC_11,          3},
    {  "vt2",       SSDH_SIGNAL_TYPE_VT2_SPE_VC_12,            3},
    {  "vt3",       SSDH_SIGNAL_TYPE_VT3_SPE,                  3},
    {  "vt6",       SSDH_SIGNAL_TYPE_VT6_SPE_VC_2,             3},
    {  "sts-1.",    SSDH_SIGNAL_TYPE_STS_1_SPE_VC_3,           6},
    {  "sts-3c",    SSDH_SIGNAL_TYPE_STS_3c_SPE_VC_4,          5},
    {  "sts-12c",   SSDH_SIGNAL_TYPE_STS_12c_SPE_VC_4_4c,      6},
    {  "sts-48c",   SSDH_SIGNAL_TYPE_STS_48c_SPE_VC_4_16c,     5},
    {  "sts-192c",  SSDH_SIGNAL_TYPE_STS_192c_SPE_VC_4_64c,    6}}
};

/** General Capability Flag S Values */
struct pair_val_str pair_val_str_flags_values =
{
    4,
    {{ "reserved",  GEN_CAP_S_RESERVED,            1},
    {  "sonet",     GEN_CAP_S_SONET_SW_CAP,        2},
    {  "sdh",       GEN_CAP_S_SDH_SW_CAP,          2},
    {  "ssdh",      GEN_CAP_S_SONET_SDH_SW_CAP,    2}}
};

/** Interface Encoding types */
struct pair_val_str pair_val_str_encoding = 
{
    8,
    {{ "packet",    LINK_IFSWCAP_SUBTLV_ENC_PKT,            2}, 
    { "ethernet",   LINK_IFSWCAP_SUBTLV_ENC_ETH,            1}, 
    { "pdh",        LINK_IFSWCAP_SUBTLV_ENC_PDH,            2}, 
    { "sdh",        LINK_IFSWCAP_SUBTLV_ENC_SONETSDH,       1},
    { "dwrapper",   LINK_IFSWCAP_SUBTLV_ENC_DIGIWRAP,       1}, 
    { "lambda",     LINK_IFSWCAP_SUBTLV_ENC_LAMBDA,         1}, 
    { "fiber",      LINK_IFSWCAP_SUBTLV_ENC_FIBER,          2}, 
    { "fchannel",   LINK_IFSWCAP_SUBTLV_ENC_FIBRCHNL,       2}}
};

/** OSPF-TE Management */
struct ospf_te
{
/**
 * there is possibility to switch off ospf-te functionality
*/
  enum { disabled, enabled } status;

/**
 * a particular quagga deamon can use only one type of interfaces
 */

/**ospf_te_ra_lsa_schedule
 * option to change architecture type 
 */
  enum { mpls, gmpls, g2mpls } architecture_type;

  struct zlist *iflist;
  struct zlist*     harmonyIflist;
  struct interface* harmonyIfp;
/** 
 *List elements are te_link interpreted as:
 * - zebra-interfaces (ifp) not ospf-interfaces (oi) for mpls architecture type,
 * - te_link for gmpls or g2mpls architecture type.
 */
  struct zlist *map_inni;
  struct zlist *map_enni;
  struct zlist *map_uni;

  /* Store Router-TLV in network byte order. */
  struct zlist*     harmonyRaList;

  struct te_router_addr router_addr[3];       /** for INNI, ENNI and UNI ospf instances */
  struct te_node_attr   node_attr[3];         /** for INNI, ENNI and UNI ospf instances */
  unsigned int ra_instance_id[3];             /** Router address  opaque instance number for INNI, ENNI and UNI*/
  unsigned int na_instance_id[3];             /** Node Attribute opaque instance number for INNI, ENNI and UNI*/

  int ra_engaged[3];                          /** Router address  engaged for INNI, ENNI and UNI*/
  int na_engaged[3];                          /** Node attribute engaged for INNI, ENNI and UNI*/

  int ra_lookup_done[3];                      /** Router address  engaged for INNI, ENNI and UNI*/
  int na_lookup_done[3];                      /** Node attribute engaged for INNI, ENNI and UNI*/

  int ra_force_refreshed[3];                  /** Router address  engaged for INNI, ENNI and UNI*/
  int na_force_refreshed[3];                  /** Node attribute engaged for INNI, ENNI and UNI*/

  int debug;
};

/**
 * Global variable to manage Opaque-LSA/MPLS-TE on this node.
 */
struct ospf_te OspfTE;

/**
 * ospf interface state 
 */
enum oifstate {
  OI_ANY, OI_DOWN, OI_UP
};

/**
 * scheduler operations
 */
static int    ospf_te_new_if                (struct interface *ifp);
static int    ospf_te_del_if                (struct interface *ifp);
static void   ospf_te_ism_change            (struct ospf_interface *oi, int old_status);
static void   ospf_te_nsm_change            (struct ospf_neighbor *nbr, int old_status);
static void   ospf_te_config_write_router   (struct vty *vty);
static void   ospf_te_config_write_if       (struct vty *vty, struct interface *ifp);
static void   ospf_te_show_info             (struct vty *vty, struct ospf_lsa *lsa);
static int    ospf_te_lsa_originate         (void *arg);
static void   ospf_te_lsa_refresh           (struct ospf_lsa *lsa);
void          ospf_te_lsa_schedule          (struct te_link *lp, enum sched_opcode, enum type_of_lsa_info);
static void   ospf_te_register_vty          (void);
static int    ospf_te_new_lsa               (struct ospf_lsa *lsa);                                    /** Feed up or down opaque */
static int    ospf_te_del_lsa               (struct ospf_lsa *lsa);                                    /** Removing feeded up or down opaque */

static void   uni_to_inni_tna    (struct ospf_lsa *lsa, struct te_tlv_tna_addr *tna_tlv, int flush);
static void   inni_to_uni_tna    (struct ospf_lsa *lsa, struct te_tlv_tna_addr *tna_tlv, int flush);
static void   enni_to_inni_tna   (struct ospf_lsa *lsa, struct te_tlv_tna_addr *tna_tlv, int flush);   /** feed DOWN TNA     */
static void   inni_to_enni_tna   (struct ospf_lsa *lsa, struct te_tlv_tna_addr *tna_tlv, int flush);   /** feed UP   TNA     */
static void   inni_to_enni_link  (struct ospf_lsa *lsa, uint16_t te_link_start, int flush);            /** feed UP   te-link */
static void   enni_to_inni_link  (struct ospf_lsa *lsa, uint16_t link_start,    int flush);            /** feed DOWN te-link */

static void   ospf_te_ra_lsa_schedule       (enum sched_opcode opcode, struct ospf *ospf, struct ospf_area * area);
static void   ospf_te_na_lsa_schedule       (enum sched_opcode opcode, struct ospf *ospf, struct ospf_area * area);

int           has_lsa_tlv_type              (struct ospf_lsa *lsa, uint16_t type, uint16_t *length);
static int    has_tlv_subtlv                (struct te_tlv_header *tlvh, uint16_t subtlv_type);

void          show_vty_tna_address_tlv      (struct vty *vty, struct te_tlv_header *tlvh);

static u_int32_t   get_te_instance_value    (void);

static void     del_te_link                 (void *val);
static void     del_raHarmony               (void *val);
static void     del_te_shared_risk_l        (u_int32_t *value);
static void     log_summary_te_lsa          (char *buf, struct ospf_lsa *lsa);
static uint16_t log_summary_te_link         (char *buf, struct te_tlv_link     *link_tlv);
static uint16_t log_summary_te_tna          (char *buf, struct te_tlv_tna_addr *tna_tlv);

static int      is_router_id_in_ospf        (adj_type_t instance, struct in_addr id);

static int                 assing_new_interface_to_harmony_te_links(void);
static struct interface*   chose_ifp_for_harmony_te_links(void);

/**
 * disabling Te-TLVs types (link_lcl_rmt_ids, link_protect_type, if_sw_cap_desc, shared_risk_link_grp)
 */

static void ospf_te_set_architecture_mpls()
{
  struct zlistnode *node, *nnode;
  struct te_link *lp;
  for (ALL_LIST_ELEMENTS (OspfTE.iflist, node, nnode, lp))
  {
    lp->link_lcl_rmt_ids.header.type=htons(0);
    lp->link_protect_type.header.type=htons(0);
    lp->shared_risk_link_grp.header.type=htons(0);

    OspfTE.router_addr[0].aa_id.header.type=htons(0);
    OspfTE.router_addr[1].aa_id.header.type=htons(0);
    OspfTE.router_addr[2].aa_id.header.type=htons(0);

    OspfTE.node_attr[0].node_ip6_lcl_prefix.header.type=htons(0);
    OspfTE.node_attr[1].node_ip6_lcl_prefix.header.type=htons(0);
    OspfTE.node_attr[2].node_ip6_lcl_prefix.header.type=htons(0);

    OspfTE.node_attr[0].node_ip4_lcl_prefix.header.type=htons(0);
    OspfTE.node_attr[1].node_ip4_lcl_prefix.header.type=htons(0);
    OspfTE.node_attr[2].node_ip4_lcl_prefix.header.type=htons(0);

    OspfTE.node_attr[0].lcl_te_router_id.header.type=htons(0);
    OspfTE.node_attr[1].lcl_te_router_id.header.type=htons(0);
    OspfTE.node_attr[2].lcl_te_router_id.header.type=htons(0);

    OspfTE.node_attr[0].aa_id.header.type=htons(0);
    OspfTE.node_attr[1].aa_id.header.type=htons(0);
    OspfTE.node_attr[2].aa_id.header.type=htons(0);

    lp->lcl_rmt_te_router_id.header.type=htons(0);
/** **************** OIF E-NNI Routing ************************************* */
    lp->lcl_node_id.header.type=htons(0);
    lp->rmt_node_id.header.type=htons(0);
    lp->ssdh_if_sw_cap_desc.header.type=htons(0);
    lp->general_cap.header.type=htons(0);
    lp->hierarchy_list.header.type=htons(0);
    lp->anc_rc_id.header.type=htons(0);
/** **************** GMPLS ASON Routing ************************************ */
    lp->band_account.header.type=htons(0);
    lp->ospf_down_aa_id.header.type=htons(0);
    lp->aa_id.header.type=htons(0);
/** **************** GMPLS All-optical Extensions ************************** */
    lp->ber_estimate.header.type=htons(0);
    lp->span_length.header.type=htons(0);
    lp->osnr.header.type=htons(0);
    lp->d_pdm.header.type=htons(0);
    lp->amp_list.header.type=htons(0);
    lp->av_wave_mask.header.type=htons(0);
    lp->te_link_calendar.header.type=htons(0);
  }
  OspfTE.architecture_type=mpls;
}

/**
 * enabling Te-TLVs types (link_lcl_rmt_ids, link_protect_type, if_sw_cap_desc, shared_risk_link_grp)
 */
static void  ospf_te_set_architecture_gmpls()
{
  struct zlistnode *node, *nnode;
  struct te_link *lp;  
  for (ALL_LIST_ELEMENTS (OspfTE.iflist, node, nnode, lp))
  {
    if (ntohs(lp->link_lcl_rmt_ids.header.length) > 0)
      lp->link_lcl_rmt_ids.header.type=htons(TE_LINK_SUBTLV_LINK_LCL_RMT_IDS );
    if (ntohs(lp->link_protect_type.header.length) > 0)
      lp->link_protect_type.header.type=htons(TE_LINK_SUBTLV_LINK_PROTECT_TYPE);
    if (ntohs(lp->shared_risk_link_grp.header.length) > 0)
      lp->shared_risk_link_grp.header.type=htons(TE_LINK_SUBTLV_SHARED_RISK_LINK_GRP);

    if (ntohs(OspfTE.router_addr[0].aa_id.header.length) > 0)
      OspfTE.router_addr[0].aa_id.header.type=htons(TE_ROUTER_ADDR_SUBTLV_AA_ID);
    if (ntohs(OspfTE.router_addr[1].aa_id.header.length) > 0)
      OspfTE.router_addr[1].aa_id.header.type=htons(TE_ROUTER_ADDR_SUBTLV_AA_ID);
    if (ntohs(OspfTE.router_addr[2].aa_id.header.length) > 0)
      OspfTE.router_addr[2].aa_id.header.type=htons(TE_ROUTER_ADDR_SUBTLV_AA_ID);
      
/** **************** Geysers project Extensions ************************** */
    if (ntohs(OspfTE.router_addr[0].power_consumption.header.length) > 0)
      OspfTE.router_addr[0].power_consumption.header.type=htons(TE_ROUTER_ADDR_SUBTLV_POWER_CONSUMPTION);
    if (ntohs(OspfTE.router_addr[1].power_consumption.header.length) > 0)
      OspfTE.router_addr[1].power_consumption.header.type=htons(TE_ROUTER_ADDR_SUBTLV_POWER_CONSUMPTION);
    if (ntohs(OspfTE.router_addr[2].power_consumption.header.length) > 0)
      OspfTE.router_addr[2].power_consumption.header.type=htons(TE_ROUTER_ADDR_SUBTLV_POWER_CONSUMPTION);

    if (ntohs(OspfTE.node_attr[0].node_ip6_lcl_prefix.header.length) > 0)
      OspfTE.node_attr[0].node_ip6_lcl_prefix.header.type=htons(TE_NODE_ATTR_SUBTLV_NODE_IP6_LCL_PREFIX);
    if (ntohs(OspfTE.node_attr[0].node_ip4_lcl_prefix.header.length) > 0)
      OspfTE.node_attr[0].node_ip4_lcl_prefix.header.type=htons(TE_NODE_ATTR_SUBTLV_NODE_IP4_LCL_PREFIX);
    if (ntohs(OspfTE.node_attr[0].lcl_te_router_id.header.length) > 0)
      OspfTE.node_attr[0].lcl_te_router_id.header.type=htons(TE_NODE_ATTR_SUBTLV_LCL_TE_ROUTER_ID);
    if (ntohs(OspfTE.node_attr[0].aa_id.header.length) > 0)
      OspfTE.node_attr[0].aa_id.header.type=htons(TE_NODE_ATTR_SUBTLV_AA_ID);

    if (ntohs(OspfTE.node_attr[1].node_ip6_lcl_prefix.header.length) > 0)
      OspfTE.node_attr[1].node_ip6_lcl_prefix.header.type=htons(TE_NODE_ATTR_SUBTLV_NODE_IP6_LCL_PREFIX);
    if (ntohs(OspfTE.node_attr[1].node_ip4_lcl_prefix.header.length) > 0)
      OspfTE.node_attr[1].node_ip4_lcl_prefix.header.type=htons(TE_NODE_ATTR_SUBTLV_NODE_IP4_LCL_PREFIX);
    if (ntohs(OspfTE.node_attr[1].lcl_te_router_id.header.length) > 0)
      OspfTE.node_attr[1].lcl_te_router_id.header.type=htons(TE_NODE_ATTR_SUBTLV_LCL_TE_ROUTER_ID);
    if (ntohs(OspfTE.node_attr[1].aa_id.header.length) > 0)
      OspfTE.node_attr[1].aa_id.header.type=htons(TE_NODE_ATTR_SUBTLV_AA_ID);

    if (ntohs(OspfTE.node_attr[2].node_ip6_lcl_prefix.header.length) > 0)
      OspfTE.node_attr[2].node_ip6_lcl_prefix.header.type=htons(TE_NODE_ATTR_SUBTLV_NODE_IP6_LCL_PREFIX);
    if (ntohs(OspfTE.node_attr[2].node_ip4_lcl_prefix.header.length) > 0)
      OspfTE.node_attr[2].node_ip4_lcl_prefix.header.type=htons(TE_NODE_ATTR_SUBTLV_NODE_IP4_LCL_PREFIX);
    if (ntohs(OspfTE.node_attr[2].lcl_te_router_id.header.length) > 0)
      OspfTE.node_attr[2].lcl_te_router_id.header.type=htons(TE_NODE_ATTR_SUBTLV_LCL_TE_ROUTER_ID);
    if (ntohs(OspfTE.node_attr[2].aa_id.header.length) > 0)
      OspfTE.node_attr[2].aa_id.header.type=htons(TE_NODE_ATTR_SUBTLV_AA_ID);

    if (ntohs(lp->lcl_rmt_te_router_id.header.length) > 0)
      lp->lcl_rmt_te_router_id.header.type=htons(TE_LINK_SUBTLV_LCL_RMT_TE_ROUTER_ID);  
/** **************** OIF E-NNI Routing ************************************* */
    if (ntohs(lp->lcl_node_id.header.length) > 0)
      lp->lcl_node_id.header.type=htons(TE_LINK_SUBTLV_LCL_NODE_ID);
    if (ntohs(lp->rmt_node_id.header.length) > 0)
      lp->rmt_node_id.header.type=htons(TE_LINK_SUBTLV_RMT_NODE_ID);
    if (ntohs(lp->ssdh_if_sw_cap_desc.header.length) > 0)
      lp->ssdh_if_sw_cap_desc.header.type=htons(TE_LINK_SUBTLV_SSDH_IF_SW_CAP_DESC); 
    if (ntohs(lp->general_cap.header.length) > 0)
      lp->general_cap.header.type=htons(TE_LINK_SUBTLV_GENERAL_CAP);
    if (ntohs(lp->hierarchy_list.header.length) > 0)
      lp->hierarchy_list.header.type=htons(TE_LINK_SUBTLV_HIERARCHY_LIST);
    if (ntohs(lp->anc_rc_id.header.length) > 0)
      lp->anc_rc_id.header.type=htons(TE_LINK_SUBTLV_ANC_RC_ID);
/** **************** GMPLS ASON Routing ************************************ */
    if (ntohs(lp->band_account.header.length) > 0)
      lp->band_account.header.type=htons(TE_LINK_SUBTLV_BAND_ACCOUNT);      
    if (ntohs(lp->ospf_down_aa_id.header.length) > 0)
      lp->ospf_down_aa_id.header.type=htons(TE_LINK_SUBTLV_OSPF_DOWN_AA_ID);    
    if (ntohs(lp->aa_id.header.length) > 0)
      lp->aa_id.header.type=htons(TE_LINK_SUBTLV_AA_ID);          
/** **************** GMPLS All-optical Extensions ************************** */
    if (ntohs(lp->ber_estimate.header.length) > 0)
      lp->ber_estimate.header.type=htons(TE_LINK_SUBTLV_BER_ESTIMATE);      
    if (ntohs(lp->span_length.header.length) > 0)
      lp->span_length.header.type=htons(TE_LINK_SUBTLV_SPAN_LENGTH);      
    if (ntohs(lp->osnr.header.length) > 0)
      lp->osnr.header.type=htons(TE_LINK_SUBTLV_OSNR);          
    if (ntohs(lp->d_pdm.header.length) > 0)
      lp->d_pdm.header.type=htons(TE_LINK_SUBTLV_D_PDM);          
    if (ntohs(lp->amp_list.header.length) > 0)
      lp->amp_list.header.type=htons(TE_LINK_SUBTLV_AMP_LIST);
    if (ntohs(lp->av_wave_mask.header.length) > 0)
      lp->av_wave_mask.header.type=htons(TE_LINK_SUBTLV_AV_WAVE_MASK);
    if (ntohs(lp->te_link_calendar.header.length) > 0)
      lp->te_link_calendar.header.type=htons(TE_LINK_SUBTLV_TE_LINK_CALENDAR);
/** **************** Geysers project Extensions ************************** */
    if (ntohs(lp->power_consumption.header.length) > 0)
      lp->power_consumption.header.type=htons(TE_LINK_SUBTLV_POWER_CONSUMPTION);
    if (ntohs(lp->dynamic_replanning.header.length) > 0)
      lp->dynamic_replanning.header.type=htons(TE_LINK_SUBTLV_DYNAMIC_REPLANNING);

  }
  OspfTE.architecture_type=gmpls;
}

/**
 * enabling Te-TLVs types (link_lcl_rmt_ids, link_protect_type, if_sw_cap_desc, shared_risk_link_grp)
 */
static void ospf_te_set_architecture_g2mpls()
{
  struct zlistnode *node, *nnode;
  struct te_link *lp;
  for (ALL_LIST_ELEMENTS (OspfTE.iflist, node, nnode, lp))
  {
    if (ntohs(lp->link_lcl_rmt_ids.header.length) > 0)
      lp->link_lcl_rmt_ids.header.type=htons(TE_LINK_SUBTLV_LINK_LCL_RMT_IDS );
    if (ntohs(lp->link_protect_type.header.length) > 0)
      lp->link_protect_type.header.type=htons(TE_LINK_SUBTLV_LINK_PROTECT_TYPE);
    if (ntohs(lp->shared_risk_link_grp.header.length) > 0)
      lp->shared_risk_link_grp.header.type=htons(TE_LINK_SUBTLV_SHARED_RISK_LINK_GRP);

    if (ntohs(OspfTE.router_addr[0].aa_id.header.length) > 0)
      OspfTE.router_addr[0].aa_id.header.type=htons(TE_ROUTER_ADDR_SUBTLV_AA_ID);
    if (ntohs(OspfTE.router_addr[1].aa_id.header.length) > 0)
      OspfTE.router_addr[1].aa_id.header.type=htons(TE_ROUTER_ADDR_SUBTLV_AA_ID);
    if (ntohs(OspfTE.router_addr[2].aa_id.header.length) > 0)
      OspfTE.router_addr[2].aa_id.header.type=htons(TE_ROUTER_ADDR_SUBTLV_AA_ID);

    if (ntohs(OspfTE.node_attr[0].node_ip6_lcl_prefix.header.length) > 0)
      OspfTE.node_attr[0].node_ip6_lcl_prefix.header.type=htons(TE_NODE_ATTR_SUBTLV_NODE_IP6_LCL_PREFIX);
    if (ntohs(OspfTE.node_attr[0].node_ip4_lcl_prefix.header.length) > 0)
      OspfTE.node_attr[0].node_ip4_lcl_prefix.header.type=htons(TE_NODE_ATTR_SUBTLV_NODE_IP4_LCL_PREFIX);
    if (ntohs(OspfTE.node_attr[0].lcl_te_router_id.header.length) > 0)
      OspfTE.node_attr[0].lcl_te_router_id.header.type=htons(TE_NODE_ATTR_SUBTLV_LCL_TE_ROUTER_ID);
    if (ntohs(OspfTE.node_attr[0].aa_id.header.length) > 0)
      OspfTE.node_attr[0].aa_id.header.type=htons(TE_NODE_ATTR_SUBTLV_AA_ID);

    if (ntohs(OspfTE.node_attr[1].node_ip6_lcl_prefix.header.length) > 0)
      OspfTE.node_attr[1].node_ip6_lcl_prefix.header.type=htons(TE_NODE_ATTR_SUBTLV_NODE_IP6_LCL_PREFIX);
    if (ntohs(OspfTE.node_attr[1].node_ip4_lcl_prefix.header.length) > 0)
      OspfTE.node_attr[1].node_ip4_lcl_prefix.header.type=htons(TE_NODE_ATTR_SUBTLV_NODE_IP4_LCL_PREFIX);
    if (ntohs(OspfTE.node_attr[1].lcl_te_router_id.header.length) > 0)
      OspfTE.node_attr[1].lcl_te_router_id.header.type=htons(TE_NODE_ATTR_SUBTLV_LCL_TE_ROUTER_ID);
    if (ntohs(OspfTE.node_attr[1].aa_id.header.length) > 0)
      OspfTE.node_attr[1].aa_id.header.type=htons(TE_NODE_ATTR_SUBTLV_AA_ID);

    if (ntohs(OspfTE.node_attr[2].node_ip6_lcl_prefix.header.length) > 0)
      OspfTE.node_attr[2].node_ip6_lcl_prefix.header.type=htons(TE_NODE_ATTR_SUBTLV_NODE_IP6_LCL_PREFIX);
    if (ntohs(OspfTE.node_attr[2].node_ip4_lcl_prefix.header.length) > 0)
      OspfTE.node_attr[2].node_ip4_lcl_prefix.header.type=htons(TE_NODE_ATTR_SUBTLV_NODE_IP4_LCL_PREFIX);
    if (ntohs(OspfTE.node_attr[2].lcl_te_router_id.header.length) > 0)
      OspfTE.node_attr[2].lcl_te_router_id.header.type=htons(TE_NODE_ATTR_SUBTLV_LCL_TE_ROUTER_ID);
    if (ntohs(OspfTE.node_attr[2].aa_id.header.length) > 0)
      OspfTE.node_attr[2].aa_id.header.type=htons(TE_NODE_ATTR_SUBTLV_AA_ID);


    if (ntohs(lp->lcl_rmt_te_router_id.header.length) > 0)
      lp->lcl_rmt_te_router_id.header.type=htons(TE_LINK_SUBTLV_LCL_RMT_TE_ROUTER_ID);  
/** **************** OIF E-NNI Routing ************************************* */
    if (ntohs(lp->lcl_node_id.header.length) > 0)
      lp->lcl_node_id.header.type=htons(TE_LINK_SUBTLV_LCL_NODE_ID);
    if (ntohs(lp->rmt_node_id.header.length) > 0)
      lp->rmt_node_id.header.type=htons(TE_LINK_SUBTLV_RMT_NODE_ID);
    if (ntohs(lp->ssdh_if_sw_cap_desc.header.length) > 0)
      lp->ssdh_if_sw_cap_desc.header.type=htons(TE_LINK_SUBTLV_SSDH_IF_SW_CAP_DESC);
    if (ntohs(lp->general_cap.header.length) > 0)
      lp->general_cap.header.type=htons(TE_LINK_SUBTLV_GENERAL_CAP);
    if (ntohs(lp->hierarchy_list.header.length) > 0)
      lp->hierarchy_list.header.type=htons(TE_LINK_SUBTLV_HIERARCHY_LIST);
    if (ntohs(lp->anc_rc_id.header.length) > 0)
      lp->anc_rc_id.header.type=htons(TE_LINK_SUBTLV_ANC_RC_ID);
/** **************** GMPLS ASON Routing ************************************ */
    if (ntohs(lp->band_account.header.length) > 0)
      lp->band_account.header.type=htons(TE_LINK_SUBTLV_BAND_ACCOUNT);          
    if (ntohs(lp->ospf_down_aa_id.header.length) > 0)
      lp->ospf_down_aa_id.header.type=htons(TE_LINK_SUBTLV_OSPF_DOWN_AA_ID);    
    if (ntohs(lp->aa_id.header.length) > 0)
      lp->aa_id.header.type=htons(TE_LINK_SUBTLV_AA_ID);          
/** **************** GMPLS All-optical Extensions ************************** */
    if (ntohs(lp->ber_estimate.header.length) > 0)
      lp->ber_estimate.header.type=htons(TE_LINK_SUBTLV_BER_ESTIMATE);      
    if (ntohs(lp->span_length.header.length) > 0)
      lp->span_length.header.type=htons(TE_LINK_SUBTLV_SPAN_LENGTH);      
    if (ntohs(lp->osnr.header.length) > 0)
      lp->osnr.header.type=htons(TE_LINK_SUBTLV_OSNR);
    if (ntohs(lp->d_pdm.header.length) > 0)
      lp->d_pdm.header.type=htons(TE_LINK_SUBTLV_D_PDM);
    if (ntohs(lp->amp_list.header.length) > 0)
      lp->amp_list.header.type=htons(TE_LINK_SUBTLV_AMP_LIST);
    if (ntohs(lp->av_wave_mask.header.length) > 0)
      lp->av_wave_mask.header.type=htons(TE_LINK_SUBTLV_AV_WAVE_MASK);
    if (ntohs(lp->te_link_calendar.header.length) > 0)
      lp->te_link_calendar.header.type=htons(TE_LINK_SUBTLV_TE_LINK_CALENDAR);
/** **************** Geysers project Extensions ************************** */
    if (ntohs(lp->power_consumption.header.length) > 0)
      lp->power_consumption.header.type=htons(TE_LINK_SUBTLV_POWER_CONSUMPTION);
    if (ntohs(lp->dynamic_replanning.header.length) > 0)
      lp->dynamic_replanning.header.type=htons(TE_LINK_SUBTLV_DYNAMIC_REPLANNING);
  }
  OspfTE.architecture_type=g2mpls;
}

/**
 * Used when ospf-te is enabled. Function register new function table concerned with ospf-te, and sets main te object OspfTE.
 * @return init result
 */
int
ospf_te_init (void)
{
  int rc;
  zlog_info("[INF] Inside ospf_te_init");
  rc = ospf_register_opaque_functab (
                OSPF_OPAQUE_AREA_LSA,
                OPAQUE_TYPE_TRAFFIC_ENGINEERING_LSA,
                ospf_te_new_if,                 /*  int  (* new_if_hook)(struct interface *ifp)                          */
                ospf_te_del_if,                 /*  int  (* del_if_hook)(struct interface *ifp)                          */
                ospf_te_ism_change,             /*  void (* ism_change_hook)(struct ospf_interface *oi, int old_status)  */
                ospf_te_nsm_change,             /*  void (* nsm_change_hook)(struct ospf_neighbor *nbr, int old_status)  */
                ospf_te_config_write_router,    /*  void (* config_write_router)(struct vty *vty)                        */
                ospf_te_config_write_if,        /*  void (* config_write_if    )(struct vty *vty, struct interface *ifp) */
                NULL,                           /*  ospf_mpls_te_config_write_debug                                      */
                ospf_te_show_info,              /*  void (* show_opaque_info   )(struct vty *vty, struct ospf_lsa *lsa)  */
                ospf_te_lsa_originate,          /*  int  (* lsa_originator)(void *arg)                                   */
                ospf_te_lsa_refresh,            /*  void (* lsa_refresher )(struct ospf_lsa *lsa)                        */
                ospf_te_new_lsa,                /*  int  (* new_lsa_hook)(struct ospf_lsa *lsa)                          */
                ospf_te_del_lsa                 /*  int  (* del_lsa_hook)(struct ospf_lsa *lsa)                          */
                );

  if (rc != 0)
    {
      zlog_warn ("[WRN] ospf_te_init: Failed to register functions");
      goto out;
    }

  memset (&OspfTE, 0, sizeof (struct ospf_te));

  OspfTE.harmonyIfp = chose_ifp_for_harmony_te_links();

  OspfTE.status = disabled;
  OspfTE.iflist = list_new ();
  OspfTE.iflist->del = del_te_link;

  OspfTE.harmonyRaList = list_new ();
  OspfTE.harmonyRaList->del = del_raHarmony;

  OspfTE.harmonyIflist = list_new ();
  OspfTE.harmonyIflist->del = del_te_link;

  OspfTE.map_inni      = list_new ();
  OspfTE.map_inni->del = del_mytype_instance_map_element;

  OspfTE.map_enni      = list_new ();
  OspfTE.map_enni->del = del_mytype_instance_map_element;

  OspfTE.map_uni       = list_new ();
  OspfTE.map_uni->del  = del_mytype_instance_map_element;

  OspfTE.architecture_type = mpls;

  OspfTE.ra_instance_id[0] = OspfTE.ra_instance_id[1] = OspfTE.ra_instance_id[2] = get_te_instance_value ();
  OspfTE.na_instance_id[0] = OspfTE.na_instance_id[1] = OspfTE.na_instance_id[2] = get_te_instance_value ();

  OspfTE.debug = 0;

  ospf_te_register_vty ();

  OspfTE.status = enabled;
  ospf_te_set_architecture_gmpls();

out:
  return rc;
}

/** 
 * Used when ospf-te is disabled 
 */
void
ospf_te_term (void)
{
  list_delete (OspfTE.iflist);
  list_delete (OspfTE.harmonyIflist);

  OspfTE.iflist = NULL;
  OspfTE.harmonyIflist = NULL;
  OspfTE.status = disabled;

  ospf_delete_opaque_functab (OSPF_OPAQUE_AREA_LSA,
                              OPAQUE_TYPE_TRAFFIC_ENGINEERING_LSA);
  return;
}

/*------------------------------------------------------------------------*
 * Followings are control functions for OSPF-TE parameters management.
 *------------------------------------------------------------------------*/

/**
 * release allocated memory of TE-link object 
 */
static void
del_te_link (void *val)
{
  XFREE (MTYPE_OSPF_TE_LINKPARAMS, val);
  return;
}

static void
del_raHarmony (void *val)
{
  XFREE (MTYPE_OSPF_TE_RA_HARMONY, val);
  return;
}

/** 
 * release allocated memory of a parameter on the shared risk list 
 * @param value - pointer to value removed from the list
 */
static void
del_te_shared_risk_l(u_int32_t *value)
{
     XFREE (MTYPE_OSPF_TE_SHARED_RISK_L, value);
}
/** 
 * release allocated memory of a parameter on tna_addr list 
 * @param value - pointer to value removed from the list
 */
static void
del_te_tna_addr(u_int32_t *value)
{
  XFREE (MTYPE_OSPF_TE_TNA_ADDR_DATA_ELEM, value);
}
/**
 * Function returns 24 bit unique value.
 */
static u_int32_t
get_te_instance_value (void)
{
  static u_int32_t seqno = 0;

  seqno += 1;

  if (!LEGAL_TE_INSTANCE_RANGE (seqno))
    seqno  = 1; /* Avoid zero. */

  return seqno;
}

/**
 * Search a first ospf interface related to Zebra interface in particular state and area
 * @param ifp - pointer to Zebra interface
 * @param area - area filter for ospf interfaces belongs to
 * @param oifstate - state filter for ospf interfaces
 * @return  ospf interface or null 
 */
static struct ospf_interface *
lookup_oi_by_ifp (struct interface *ifp,
                  struct ospf_area *area, enum oifstate oifstate)
{
  struct ospf_interface *oi = NULL;
  struct route_node *rn;

  for (rn = route_top (IF_OIFS (ifp)); rn; rn = route_next (rn))
  {
    if ((oi = rn->info) == NULL)
      continue;

    switch (oifstate)
    {
      case OI_ANY:
        break;
      case OI_DOWN:
        if (ospf_if_is_enable (oi))
          continue;
        break;
      case OI_UP:
        if (! ospf_if_is_enable (oi))
          continue;
        break;
      default:
        zlog_warn ("[WRN] lookup_oi_by_ifp: Unknown oifstate: %x", oifstate);
        goto out;
    }

    if (area == NULL || oi->area == area)
      return oi;
  }
out:
  return NULL;
}

/** Search TE-link adherent to Zebra interface. Ignore te_link on harmonyIflist */
static struct te_link *
lookup_linkparams_by_ifp (struct interface *ifp)
{
  struct zlistnode *node, *nnode;
  struct te_link *lp;

  for (ALL_LIST_ELEMENTS (OspfTE.iflist, node, nnode, lp))
    if (lp->ifp == ifp)
      return lp;

  return NULL;
}

/*
static struct te_link *
te_link_lookup_by_data_link_name(const char *li_name)
{
  struct zlistnode *node, *nnode;
  struct te_link *lp;

  for (ALL_LIST_ELEMENTS (OspfTE.iflist, node, nnode, lp))
    if (strcmp (lp->data_link_name, li_name) == 0)
      return lp;

  return NULL;
} */

static struct raHarmony *
lookup_rah_by_lsa(struct ospf_lsa *lsa)
{
  struct zlistnode *node;
  struct raHarmony *rah;
  unsigned int key = GET_OPAQUE_ID (ntohl (lsa->data->id.s_addr));

  for (ALL_LIST_ELEMENTS_RO (OspfTE.harmonyRaList, node, rah))
    if (rah->instance_id == key)
      return rah;

  return NULL;
}

/** Search TE-link with particular instance */
static struct te_link *
lookup_linkparams_by_instance (struct ospf_lsa *lsa)
{
  struct zlistnode *node;
  struct te_link *lp;
  unsigned int key = GET_OPAQUE_ID (ntohl (lsa->data->id.s_addr));

  for (ALL_LIST_ELEMENTS_RO (OspfTE.iflist, node, lp))
    if ((lp->instance_li == key) || (lp->instance_tna == key))
      return lp;

  for (ALL_LIST_ELEMENTS_RO (OspfTE.harmonyIflist, node, lp))
  {
    if ((lp->instance_li == key) || (lp->instance_tna == key))
    {
      if (lp->ifp != NULL)
        return lp;
      else
      {
        zlog_warn("[WRN] Harmony te-link has no assigned interface");
        return NULL;
      }
    }
  }
  /* zlog_warn ("[WRN] lookup_linkparams_by_instance: Entry not found: key(%x)", key); */
  return NULL;
}

/**
 * Execute specyfic function on all areas
 * @param (*func) (struct te_link *lp, enum sched_opcode) - pointer to the function
 * @param sched_opcode - REORIGINATE_PER_AREA, REFRESH_THIS_LSA, FLUSH_THIS_LSA
*/
static void
ospf_te_foreach_area (
  void (*func)(struct te_link *lp, enum sched_opcode, enum type_of_lsa_info),
  enum sched_opcode sched_opcode, enum type_of_lsa_info lsa_type)
{
  struct zlistnode *node, *nnode; 
  struct zlistnode *node2;
  struct te_link *lp, *lp2;
  struct ospf_area *area;

  for (ALL_LIST_ELEMENTS (OspfTE.iflist, node, nnode, lp))
  {
    if ((area = lp->area) == NULL)
      continue;

    if ((lsa_type == LINK) && (lp->flags & LPFLG_LI_LOOKUP_DONE))
      continue;

    if ((lsa_type == TNA_ADDRESS) && (lp->flags & LPFLG_TNA_LOOKUP_DONE))
      continue;

    if (func != NULL)
      (* func)(lp, sched_opcode, lsa_type);

    for (node2 = listnextnode (node); node2; node2 = listnextnode (node2))
      if ((lp2 = listgetdata (node2)) != NULL)
        if (lp2->area != NULL)
          if (IPV4_ADDR_SAME (&lp2->area->area_id, &area->area_id))
            switch (lsa_type)
            {
              case LINK:
                lp2->flags |= LPFLG_LI_LOOKUP_DONE;
                break;
              case TNA_ADDRESS:
                lp2->flags |= LPFLG_TNA_LOOKUP_DONE;
                break;
              default:
                break;
            }
  }
  for (ALL_LIST_ELEMENTS (OspfTE.harmonyIflist, node, nnode, lp))
  {
    if (lp->ifp == NULL)
    {
      zlog_warn("[WRN] ospf_te_foreach_area: Harmony te-link has no assigned interface");
      continue;
    }
    if ((area = lp->area) == NULL)
      continue;

    if ((lsa_type == LINK) && (lp->flags & LPFLG_LI_LOOKUP_DONE))
      continue;

    if ((lsa_type == TNA_ADDRESS) && (lp->flags & LPFLG_TNA_LOOKUP_DONE))
      continue;

    if (func != NULL)
      (* func)(lp, sched_opcode, lsa_type);

    for (node2 = listnextnode (node); node2; node2 = listnextnode (node2))
      if ((lp2 = listgetdata (node2)) != NULL)
        if (lp2->area != NULL)
          if (IPV4_ADDR_SAME (&lp2->area->area_id, &area->area_id))
            switch (lsa_type)
            {
              case LINK:
                lp2->flags |= LPFLG_LI_LOOKUP_DONE;
                break;
              case TNA_ADDRESS:
                lp2->flags |= LPFLG_TNA_LOOKUP_DONE;
                break;
              default:
                break;
            }
  }

  switch (lsa_type)
  {
    case LINK:
      for (ALL_LIST_ELEMENTS_RO (OspfTE.iflist, node, lp))
        if (lp->area != NULL)
          lp->flags &= ~LPFLG_LI_LOOKUP_DONE;
      for (ALL_LIST_ELEMENTS_RO (OspfTE.harmonyIflist, node, lp))
        if ((lp->area != NULL) && (lp->ifp != NULL))
          lp->flags &= ~LPFLG_LI_LOOKUP_DONE;
      break;
    case TNA_ADDRESS:
      for (ALL_LIST_ELEMENTS_RO (OspfTE.iflist, node, lp))
        if (lp->area != NULL)
          lp->flags &= ~LPFLG_TNA_LOOKUP_DONE;
      for (ALL_LIST_ELEMENTS_RO (OspfTE.harmonyIflist, node, lp))
        if ((lp->area != NULL) && (lp->ifp != NULL))
          lp->flags &= ~LPFLG_TNA_LOOKUP_DONE;
      break;
    default:
      break;
  }
  return;
}

/** 
 * calculates TE Router Address TLV data length and create TE Router Address TLV header
 */
static void
set_linkparams_router_addr_header (adj_type_t te_adj_type)
{
  if ((uint16_t)te_adj_type > 2)
  {
    zlog_err("[ERR] set_linkparams_router_addr_header: Wrong adjacency type %d", te_adj_type);
    return;
  }
  u_int16_t length = 0;

  if (ntohs (OspfTE.router_addr[(uint16_t)te_adj_type].router_addr.header.type) !=0)
     length += TLV_SIZE (&OspfTE.router_addr[(uint16_t)te_adj_type].router_addr.header);
  if (ntohs (OspfTE.router_addr[(uint16_t)te_adj_type].aa_id.header.type) !=0)
     length += TLV_SIZE (&OspfTE.router_addr[(uint16_t)te_adj_type].aa_id.header);
  if (ntohs (OspfTE.router_addr[(uint16_t)te_adj_type].power_consumption.header.type) !=0)
     length += TLV_SIZE (&OspfTE.router_addr[(uint16_t)te_adj_type].power_consumption.header);

  /* this is TE Router Address TLV */
  OspfTE.router_addr[(uint16_t)te_adj_type].link_header.header.type   = htons (TE_TLV_ROUTER_ADDR);
  /* set calculated length */
  OspfTE.router_addr[(uint16_t)te_adj_type].link_header.header.length = htons (length);

  return;
}

/**
 * Set router address TLV for ospf-te module 
 * @param ipv4
 */
static void
set_te_router_addr (struct in_addr ipv4, adj_type_t interface_type)
{
  OspfTE.router_addr[(uint16_t)interface_type].router_addr.header.type   = htons (TE_ROUTER_ADDR_SUBTLV_ROUTER_ADDR);
  OspfTE.router_addr[(uint16_t)interface_type].router_addr.header.length = htons (sizeof (ipv4));
  OspfTE.router_addr[(uint16_t)interface_type].router_addr.value = ipv4;
  return;
}

/**
 * Add associated area ID
 * @param value - associated area ID
 */
static void
set_ason_aa_id_router_addr (u_int32_t value, adj_type_t interface_type)
{
  OspfTE.router_addr[(uint16_t)interface_type].aa_id.header.type   = htons (TE_ROUTER_ADDR_SUBTLV_AA_ID);
  OspfTE.router_addr[(uint16_t)interface_type].aa_id.header.length = htons (sizeof (OspfTE.router_addr[(uint16_t)interface_type].aa_id.area_id));
  OspfTE.router_addr[(uint16_t)interface_type].aa_id.area_id = htonl (value);
  return;
}

/**
 * Add power consumtion
 * @param value - power consumption
 */
static void
set_router_power_consumption (uint32_t* value, adj_type_t interface_type)
{
  OspfTE.router_addr[(uint16_t)interface_type].power_consumption.header.type   = htons (TE_ROUTER_ADDR_SUBTLV_POWER_CONSUMPTION);
  OspfTE.router_addr[(uint16_t)interface_type].power_consumption.header.length = htons (sizeof (OspfTE.router_addr[(uint16_t)interface_type].power_consumption.power_consumption));
  float tmp;
  memcpy(&tmp, value, 4);
  htonf (&tmp, &OspfTE.router_addr[(uint16_t)interface_type].power_consumption.power_consumption);
  //zlog_debug("[DBG] Values: in x%x - fl %.3f", *value, tmp);
  //zlog_debug("[DBG] Setting router power consumption %d", (u_int32_t) ntohl(OspfTE.router_addr[(uint16_t)interface_type].power_consumption.power_consumption));
  return;
}

/** 
 * calculates TE Node Attribute TLV data length and create TE Node Attribute TLV header
 */
static void
set_linkparams_node_attr_header (adj_type_t interface_type)
{
  if ((uint16_t)interface_type > 2)
    return;

  u_int16_t length = 0;

  if ((ntohs (OspfTE.node_attr[(uint16_t)interface_type].node_ip4_lcl_prefix.header.type) !=0) && (ntohs (OspfTE.node_attr[(uint16_t)interface_type].node_ip4_lcl_prefix.header.length) !=0))
    length += TLV_SIZE (&OspfTE.node_attr[(uint16_t)interface_type].node_ip4_lcl_prefix.header);
  if ((ntohs (OspfTE.node_attr[(uint16_t)interface_type].node_ip6_lcl_prefix.header.type) !=0) && (ntohs (OspfTE.node_attr[(uint16_t)interface_type].node_ip6_lcl_prefix.header.length) !=0))
    length += TLV_SIZE (&OspfTE.node_attr[(uint16_t)interface_type].node_ip6_lcl_prefix.header);
  if (ntohs (OspfTE.node_attr[(uint16_t)interface_type].lcl_te_router_id.header.type) !=0)
     length += TLV_SIZE (&OspfTE.node_attr[(uint16_t)interface_type].lcl_te_router_id.header);
  if (ntohs (OspfTE.node_attr[(uint16_t)interface_type].aa_id.header.type) !=0)
     length += TLV_SIZE (&OspfTE.node_attr[(uint16_t)interface_type].aa_id.header);

  /* this is TE Node Attribute TLV */
  OspfTE.node_attr[(uint16_t)interface_type].link_header.header.type   = htons (TE_TLV_NODE_ATTR);
  /* set calculated length */
  OspfTE.node_attr[(uint16_t)interface_type].link_header.header.length = htons (length);

  return;
}

/**
 * Set local TE router ID for ospf-te module
 * @param value - router ID
 */

static void
set_ason_lcl_te_router_id (u_int32_t value, adj_type_t interface_type)
{
  OspfTE.node_attr[(uint16_t)interface_type].lcl_te_router_id.header.type   = htons (TE_NODE_ATTR_SUBTLV_LCL_TE_ROUTER_ID);
  OspfTE.node_attr[(uint16_t)interface_type].lcl_te_router_id.header.length = htons (sizeof (OspfTE.node_attr[(uint16_t)interface_type].lcl_te_router_id.lcl_te_router_id));
  OspfTE.node_attr[(uint16_t)interface_type].lcl_te_router_id.lcl_te_router_id = htonl (value);
  return;
}

/**
 * Add associated area ID
 * @param value - associated area ID
 */
static void
set_ason_aa_id_node_attr (u_int32_t value, adj_type_t interface_type)
{
  OspfTE.node_attr[(uint16_t)interface_type].aa_id.header.type   = htons (TE_NODE_ATTR_SUBTLV_AA_ID);
  OspfTE.node_attr[(uint16_t)interface_type].aa_id.header.length = htons (sizeof (OspfTE.node_attr[interface_type].aa_id.area_id));
  OspfTE.node_attr[(uint16_t)interface_type].aa_id.area_id = htonl (value);
  return;
}

/**
 * Set node IPv4 local prefix
 * @param mask - network mask
 * @param address - IPv4 address
 */

static void
add_ason_node_ip4_lcl_prefix (struct in_addr mask, struct in_addr address, adj_type_t interface_type)
{
  struct prefix_ip4 *n_value = XMALLOC (MTYPE_OSPF_TE_PREFIX_IP4, sizeof(struct prefix_ip4));
  n_value->netmask = mask;
  n_value->address_ip4 = address;
  listnode_add (&OspfTE.node_attr[(uint16_t)interface_type].node_ip4_lcl_prefix.prefix_list, n_value);
  OspfTE.node_attr[(uint16_t)interface_type].node_ip4_lcl_prefix.header.type   = htons (TE_NODE_ATTR_SUBTLV_NODE_IP4_LCL_PREFIX);
  OspfTE.node_attr[(uint16_t)interface_type].node_ip4_lcl_prefix.header.length = htons (8* listcount(&OspfTE.node_attr[(uint16_t)interface_type].node_ip4_lcl_prefix.prefix_list));
  return;
}

/**
 * Clear node IPv4 local prefix
 * @param lp - TE-link
 */

static int
clear_ason_node_ip4_lcl_prefix (adj_type_t interface_type)
{
  int result = -1;
  if ((uint16_t)interface_type > 2)
  {
    zlog_err("[ERR] clear_ason_node_ip4_lcl_prefix: Wrong interface type %d", (uint16_t)interface_type > 2);
    return result;
  }
  if (listcount(&OspfTE.node_attr[(uint16_t)interface_type].node_ip4_lcl_prefix.prefix_list) ==0)
    return result;

  result = 0;
  list_delete_all_node(&OspfTE.node_attr[(uint16_t)interface_type].node_ip4_lcl_prefix.prefix_list);
  OspfTE.node_attr[(uint16_t)interface_type].node_ip4_lcl_prefix.header.type   =0;
  OspfTE.node_attr[(uint16_t)interface_type].node_ip4_lcl_prefix.header.length =0;
  return result;
}

/**
 * Set node IPv6 local prefix
 * @param prefixlen - prefix length
 * @param prefixopt - prefix options
 * @param address - IPv6 address
 */

static void
add_ason_node_ip6_lcl_prefix (u_char prefixlen, u_char prefixopt, struct in6_addr address, adj_type_t interface_type)
{
  struct prefix_ip6 *n_value = XMALLOC (MTYPE_OSPF_TE_PREFIX_IP6, sizeof(struct prefix_ip6));
  n_value->prefixlen = prefixlen;
  n_value->prefixopt = prefixopt;
  n_value->reserved[0] = 0;
  n_value->reserved[1] = 0;
  n_value->address_ip6 = address;
  listnode_add (&OspfTE.node_attr[(uint16_t)interface_type].node_ip6_lcl_prefix.prefix_list, n_value);
  OspfTE.node_attr[(uint16_t)interface_type].node_ip6_lcl_prefix.header.type   = htons (TE_NODE_ATTR_SUBTLV_NODE_IP6_LCL_PREFIX);
  OspfTE.node_attr[(uint16_t)interface_type].node_ip6_lcl_prefix.header.length = htons (20* listcount(&OspfTE.node_attr[(uint16_t)interface_type].node_ip6_lcl_prefix.prefix_list));
  return;
}

/**
 * Clear node IPv6 local prefix
 */

static int
clear_ason_node_ip6_lcl_prefix (adj_type_t interface_type)
{
  int result = -1;
  if (listcount(&OspfTE.node_attr[(uint16_t)interface_type].node_ip6_lcl_prefix.prefix_list) ==0)
    return result;

  result = 0;
  list_delete_all_node(&OspfTE.node_attr[(uint16_t)interface_type].node_ip6_lcl_prefix.prefix_list);
  OspfTE.node_attr[(uint16_t)interface_type].node_ip6_lcl_prefix.header.type   =0;
  OspfTE.node_attr[(uint16_t)interface_type].node_ip6_lcl_prefix.header.length =0;
  return result;
}

/** *************** TNA Address TLV *************************************** **/

/**
 * Set TNA address IPv4
 * @param tna_addr - TNA address structure
 * @param addr_length - the length of TNA address
 * @param address - IPv4 address
 */
void
set_oif_tna_addr_ipv4 (struct tna_addr_value * tna_addr, u_char addr_length, struct in_addr *address)
{
  tna_addr->tna_addr_ipv4.header.type = htons (TE_TNA_ADDR_SUBTLV_TNA_ADDR_IPV4);
  tna_addr->tna_addr_ipv4.header.length = htons (8);
  tna_addr->tna_addr_ipv4.addr_length = addr_length;
  tna_addr->tna_addr_ipv4.reserved[0] = 0;
  tna_addr->tna_addr_ipv4.reserved[1] = 0;
  tna_addr->tna_addr_ipv4.reserved[2] = 0;
  tna_addr->tna_addr_ipv4.value = *address;
  return;
}

/**
 * Set TNA address IPv6
 * @param tna_addr - TNA address structure
 * @param addr_length - the length of TNA address
 * @param address - IPv6 address (128 bit)
 */
void
set_oif_tna_addr_ipv6 (struct tna_addr_value * tna_addr, u_char addr_length, struct in6_addr *address)
{
  tna_addr->tna_addr_ipv6.header.type = htons (TE_TNA_ADDR_SUBTLV_TNA_ADDR_IPV6);
  tna_addr->tna_addr_ipv6.header.length = htons (20);
  tna_addr->tna_addr_ipv6.addr_length   = addr_length;
  tna_addr->tna_addr_ipv6.reserved[0] = 0;
  tna_addr->tna_addr_ipv6.reserved[1] = 0;
  tna_addr->tna_addr_ipv6.reserved[2] = 0;
  tna_addr->tna_addr_ipv6.value = *address;
  return;
}

/**
 * Set TNA address NSAP
 * @param tna_addr - TNA address structure
 * @param addr_length - the length of TNA address
 * @param address - NSAP address (160 bit)
 */
void
set_oif_tna_addr_nsap (struct tna_addr_value * tna_addr, u_char addr_length, u_int32_t value[])
{
  int i;
  tna_addr->tna_addr_nsap.header.type   = htons (TE_TNA_ADDR_SUBTLV_TNA_ADDR_NSAP);
  tna_addr->tna_addr_nsap.header.length = htons (24);
  tna_addr->tna_addr_nsap.addr_length   = addr_length;
  tna_addr->tna_addr_nsap.reserved[0] = 0;
  tna_addr->tna_addr_nsap.reserved[1] = 0;
  tna_addr->tna_addr_nsap.reserved[2] = 0;
  for (i = 0;i < 5;i++) tna_addr->tna_addr_nsap.value[i] = htonl (value[4-i]);
  return;
}

/**
 * Set node ID
 * @param tna_addr - TNA address structure
 * @param address - IPv4 address
 */
void
set_oif_node_id (struct tna_addr_data_element *tna_addr, struct in_addr address)
{
  tna_addr->node_id.header.type   = htons (TE_TNA_ADDR_SUBTLV_NODE_ID);
  tna_addr->node_id.header.length = htons (4);
  tna_addr->node_id.value = address;
  return;
}

/**
 * Set TNA ancestor RC id
 * @param tna_addr - TNA address structure
 * @param address - IPv4 address
 */
void
set_oif_tna_anc_rc_id (struct tna_addr_data_element *tna_addr, struct in_addr anc_rc_id)
{
  tna_addr->anc_rc_id.header.type   = htons (TE_TNA_ADDR_SUBTLV_ANC_RC_ID);
  tna_addr->anc_rc_id.header.length = htons (4);
  tna_addr->anc_rc_id.value = anc_rc_id;
  return;
}

/**
 * calculates TNA Address TLV data length and create TNA Address TLV header
 * @param *lp
 */
static void
set_linkparams_tna_addr_header (struct te_link *lp)
{
  u_int16_t length = 0;
  struct zlistnode *node;
  struct tna_addr_data_element *l_value;
  struct zlistnode *node_in;
  struct tna_addr_value *l_value_in;

  for (ALL_LIST_ELEMENTS_RO (&lp->tna_address.tna_addr_data, node, l_value))
  {
    length += TLV_SIZE(&l_value->node_id.header);
    for (ALL_LIST_ELEMENTS_RO (&l_value->tna_addr, node_in, l_value_in))
    {
      length += TLV_BODY_SIZE(&l_value_in->tna_addr_ipv4.header);
      length += TLV_BODY_SIZE(&l_value_in->tna_addr_ipv6.header);
      length += TLV_BODY_SIZE(&l_value_in->tna_addr_nsap.header);
      length += 4;
    }
    if ((ntohs(l_value->anc_rc_id.header.length) > 0) && (ntohs(l_value->anc_rc_id.header.type) != 0))
      length += TLV_SIZE(&l_value->anc_rc_id.header);
  }

  /* this is TE-link TLV */
  lp->tna_address.header.type   = htons (TE_TLV_TNA_ADDR);
  /* set calculated length */
  lp->tna_address.header.length = htons (length);
  return;
}

static uint8_t isTnaAddrInList(struct tna_addr_value *Addr, struct zlist* tnaAddresses)
{
  struct zlistnode *node, *nnode;
  struct tna_addr_value *tmp;
  uint8_t opt;

  for (ALL_LIST_ELEMENTS (tnaAddresses, node, nnode, tmp))
  {
    if (Addr->tna_addr_ipv4.header.length != 0)
    {
      if (tmp->tna_addr_ipv4.header.length == 0)
        continue;

      if (   Addr->tna_addr_ipv4.addr_length  == tmp->tna_addr_ipv4.addr_length
          && Addr->tna_addr_ipv4.value.s_addr == tmp->tna_addr_ipv4.value.s_addr)
        return 1;
    }
    else if (Addr->tna_addr_ipv6.header.length != 0)
    {
      if (tmp->tna_addr_ipv6.header.length == 0)
        continue;

      if (Addr->tna_addr_ipv6.addr_length != tmp->tna_addr_ipv6.addr_length)
        continue;

      opt = 1;
      for (int i=0; i<16; i++)
        if (Addr->tna_addr_ipv6.value.s6_addr[i] != tmp->tna_addr_ipv6.value.s6_addr[i])
          opt = 0;

      if (opt)
        return 1;
    }
    else if (Addr->tna_addr_nsap.header.length != 0)
    {
      if (tmp->tna_addr_nsap.header.length == 0)
        continue;

      if (Addr->tna_addr_nsap.addr_length != tmp->tna_addr_nsap.addr_length)
        continue;

      opt = 1;
      for (int i=0; i<5; i++)
        if (Addr->tna_addr_nsap.value[i] != tmp->tna_addr_nsap.value[i])
          opt = 0;
      if (opt)
        return 1;
    }
  }

  return 0;
}

int
add_tna_addr (struct te_link *lp, tna_addr_type_t type, struct in_addr node_id, struct in_addr anc_rc_id, u_char address_len, void *address)
{
  struct zlistnode *node, *nnode;

  struct tna_addr_data_element  *l_value;
  struct tna_addr_data_element  *n_value       = XMALLOC (MTYPE_OSPF_TE_TNA_ADDR_DATA_ELEM, sizeof(struct tna_addr_data_element));
  struct tna_addr_value         *n_value_in    = XMALLOC (MTYPE_OSPF_TE_TNA_ADDR_VALUE,     sizeof(struct tna_addr_value));

  memset (&n_value->anc_rc_id, 0, sizeof (struct te_tna_addr_subtlv_anc_rc_id));
  memset (&n_value->tna_addr, 0, sizeof (struct zlist));

  set_oif_node_id (n_value, node_id);
  if (anc_rc_id.s_addr != 0)
    set_oif_tna_anc_rc_id (n_value, anc_rc_id);

  uint8_t addNode = 0;
  switch (type){
    case TNA_IP4:
      set_oif_tna_addr_ipv4 (n_value_in, address_len, (struct in_addr *) address);
      n_value_in->tna_addr_ipv6.header.length = 0;
      n_value_in->tna_addr_nsap.header.length = 0;
      break;
    case TNA_IP6:
      set_oif_tna_addr_ipv6 (n_value_in, address_len, (struct in6_addr *) address);
      n_value_in->tna_addr_ipv4.header.length = 0;
      n_value_in->tna_addr_nsap.header.length = 0;
      break;
    case TNA_NSAP:
      set_oif_tna_addr_nsap (n_value_in, address_len, (u_int32_t *) address);
      n_value_in->tna_addr_ipv4.header.length = 0;
      n_value_in->tna_addr_ipv6.header.length = 0;
      break;
    case TNA_NODE:
      n_value_in->tna_addr_ipv4.header.length = 0;
      n_value_in->tna_addr_ipv6.header.length = 0;
      n_value_in->tna_addr_nsap.header.length = 0;
      addNode = 1;
      //zlog_warn("[WRN] add_tna_addr: Adding node %d", type);
      break;
    default:
      zlog_err("[ERR] add_tna_addr: Wrong TNA address type");
      return -1;
      break;
  }

  for (ALL_LIST_ELEMENTS (&lp->tna_address.tna_addr_data, node, nnode, l_value))
  {
    if (IPV4_ADDR_SAME(&l_value->node_id.value, &n_value->node_id.value))
    {
      if (addNode) {
        XFREE(MTYPE_OSPF_TE_TNA_ADDR_VALUE, n_value_in);
        XFREE(MTYPE_OSPF_TE_TNA_ADDR_DATA_ELEM, n_value);
        return 0;
      }
      else {
        if (!isTnaAddrInList(n_value_in, &l_value->tna_addr)) {
          listnode_add (&l_value->tna_addr, n_value_in);
          set_linkparams_tna_addr_header (lp);
          XFREE(MTYPE_OSPF_TE_TNA_ADDR_DATA_ELEM, n_value);

        }
        else {
          XFREE(MTYPE_OSPF_TE_TNA_ADDR_VALUE, n_value_in);
          XFREE(MTYPE_OSPF_TE_TNA_ADDR_DATA_ELEM, n_value);
        }
        return 0;
      }
    }
  }

  if (addNode == 0)
    listnode_add (&n_value->tna_addr, n_value_in);
  else
    XFREE(MTYPE_OSPF_TE_TNA_ADDR_VALUE, n_value_in);
  listnode_add (&lp->tna_address.tna_addr_data, n_value);
  set_linkparams_tna_addr_header (lp);

  return 0;
}

static int
clear_tna_addr (struct te_link *lp)
{
  int result = -1;
  if (lp->tna_address.tna_addr_data.count == 0)
    return result;

  result = 0;
  list_delete_all_node(&lp->tna_address.tna_addr_data);
  lp->tna_address.header.length =0;

  return 1;
}

/** *************** TE-link TLV *************************************** **/

/** 
 * calculates TE-link TLV data length and create TE-link TLV header
 * @param *lp
 */
static void
set_linkparams_link_header (struct te_link *lp)
{
  u_int16_t length = 0;

  /* TE_LINK_SUBTLV_LINK_TYPE */
  if (ntohs (lp->link_type.header.type) != 0 && (ntohs (lp->link_type.header.length) != 0))
    length += TLV_SIZE (&lp->link_type.header);

  /* TE_LINK_SUBTLV_LINK_ID */
  if (ntohs (lp->link_id.header.type) != 0 && ntohs (lp->link_id.header.length) != 0)
    length += TLV_SIZE (&lp->link_id.header);

  /* TE_LINK_SUBTLV_LCLIF_IPADDR */
  if (ntohs(lp->lclif_ipaddr.header.type) != 0 && ntohs(lp->lclif_ipaddr.header.length) != 0)
    length += TLV_SIZE (&lp->lclif_ipaddr.header);

  /* TE_LINK_SUBTLV_RMTIF_IPADDR */
  if (ntohs(lp->rmtif_ipaddr.header.type) != 0 && ntohs(lp->rmtif_ipaddr.header.length) != 0)
    length += TLV_SIZE (&lp->rmtif_ipaddr.header);

  /* TE_LINK_SUBTLV_TE_METRIC */
  if (ntohs (lp->te_metric.header.type) != 0 && ntohs (lp->te_metric.header.length) != 0)
    length += TLV_SIZE (&lp->te_metric.header);

  /* TE_LINK_SUBTLV_MAX_BW */
  if (ntohs (lp->max_bw.header.type) != 0 && ntohs (lp->max_bw.header.length) != 0)
    length += TLV_SIZE (&lp->max_bw.header);

  /* TE_LINK_SUBTLV_MAX_RSV_BW */
  if (ntohs (lp->max_rsv_bw.header.type) != 0 && ntohs (lp->max_rsv_bw.header.length) != 0)
    length += TLV_SIZE (&lp->max_rsv_bw.header);

  /* TE_LINK_SUBTLV_UNRSV_BW */
  if (ntohs (lp->unrsv_bw.header.type) != 0 && ntohs (lp->unrsv_bw.header.length) != 0)
    length += TLV_SIZE (&lp->unrsv_bw.header);

  /* TE_LINK_SUBTLV_RSC_CLSCLR */
  if (ntohs (lp->rsc_clsclr.header.type) != 0 && ntohs (lp->rsc_clsclr.header.length) != 0)
    length += TLV_SIZE (&lp->rsc_clsclr.header);

  /* link_lcl_rmt_ids -- gmpls extension*/
  if (ntohs (lp->link_lcl_rmt_ids.header.type) != 0 && ntohs (lp->link_lcl_rmt_ids.header.length) != 0)
    length += TLV_SIZE (&lp->link_lcl_rmt_ids.header);

  /*link_protect_type -- gmpls extension*/
  if (ntohs (lp->link_protect_type.header.type) != 0 && ntohs (lp->link_protect_type.header.length) != 0)
    length += TLV_SIZE (&lp->link_protect_type.header);

  /* if_sw_cap_desc -- gmpls extension*/
  struct zlistnode *node, *nnode;
  struct te_link_subtlv_ssdh_if_sw_cap_desc* if_sw_cap_desc;
  for (ALL_LIST_ELEMENTS(&lp->if_sw_cap_descs, node, nnode, if_sw_cap_desc))
    length += TLV_SIZE (&if_sw_cap_desc->header);

  /* shared_risk_link_grp -- gmpls extension*/
  if (ntohs (lp->shared_risk_link_grp.header.type) != 0 && ntohs (lp->shared_risk_link_grp.header.length) != 0)
    length += TLV_SIZE (&lp->shared_risk_link_grp.header);

  /* lcl_rmt_te_router_id.header -- gmpls extension*/
  if (ntohs (lp->lcl_rmt_te_router_id.header.type) != 0 && ntohs (lp->lcl_rmt_te_router_id.header.length) != 0)
    length += TLV_SIZE (&lp->lcl_rmt_te_router_id.header);

/* **************** OIF E-NNI Routing ************************************* */

  /* lcl_node_id -- gmpls extension*/
  if (ntohs (lp->lcl_node_id.header.type) != 0 && ntohs (lp->lcl_node_id.header.length) != 0)
    length += TLV_SIZE (&lp->lcl_node_id.header);
  /* rmt_node_id -- gmpls extension*/
  if (ntohs (lp->rmt_node_id.header.type) != 0 && ntohs (lp->rmt_node_id.header.length) != 0)
    length += TLV_SIZE (&lp->rmt_node_id.header);
  /* ssdh_if_sw_cap_desc -- gmpls extension*/
  if (ntohs (lp->ssdh_if_sw_cap_desc.header.type) !=0 && ntohs (lp->ssdh_if_sw_cap_desc.header.length) !=0)
    length += TLV_SIZE (&lp->ssdh_if_sw_cap_desc.header);
  /* general_cap -- gmpls extension*/
  if (ntohs (lp->general_cap.header.type) !=0 && ntohs (lp->general_cap.header.length) !=0)
    length += TLV_SIZE (&lp->general_cap.header);
  /* hierarchy_list -- gmpls extension*/
  if (ntohs (lp->hierarchy_list.header.type) !=0 && ntohs (lp->hierarchy_list.header.length) !=0)
    length += TLV_SIZE (&lp->hierarchy_list.header);
  /* anc_rc_id -- gmpls extension*/
  if (ntohs (lp->anc_rc_id.header.type) !=0 && ntohs (lp->anc_rc_id.header.length) !=0)
    length += TLV_SIZE (&lp->anc_rc_id.header);

/* *************** GMPLS ASON Routing ******************************** */

  /* band_account -- gmpls extension*/
  if (ntohs (lp->band_account.header.type) !=0 && ntohs (lp->band_account.header.length) !=0)
    length += TLV_SIZE (&lp->band_account.header);
  /* ospf_down_aa_id -- gmpls extension*/
  if (ntohs (lp->ospf_down_aa_id.header.type) !=0 && ntohs (lp->ospf_down_aa_id.header.length) !=0)
    length += TLV_SIZE (&lp->ospf_down_aa_id.header);
  /* aa_id -- gmpls extension*/
  if (ntohs (lp->aa_id.header.type) !=0 && ntohs (lp->aa_id.header.length) !=0)
    length += TLV_SIZE (&lp->aa_id.header);

/* *************** GMPLS All-optical Extensions ********************** */

  /* ber_estimate -- gmpls extension*/
  if (ntohs (lp->ber_estimate.header.type) !=0 && ntohs (lp->ber_estimate.header.length) !=0)
    length += TLV_SIZE (&lp->ber_estimate.header);
  /* span_length -- gmpls extension*/
  if (ntohs (lp->span_length.header.type) !=0 && ntohs (lp->span_length.header.length) !=0)
    length += TLV_SIZE (&lp->span_length.header);
  /* osnr -- gmpls extension*/
  if (ntohs (lp->osnr.header.type) !=0 && ntohs (lp->osnr.header.length) !=0)
    length += TLV_SIZE (&lp->osnr.header);
  /* d_pdm -- gmpls extension*/
  if (ntohs (lp->d_pdm.header.type) !=0 && ntohs (lp->d_pdm.header.length) !=0)
    length += TLV_SIZE (&lp->d_pdm.header);
  /* amp_list -- gmpls extension*/
  if (ntohs (lp->amp_list.header.type) !=0 && ntohs (lp->amp_list.header.length) !=0)
    length += TLV_SIZE (&lp->amp_list.header);
  /* av_wave_mask -- gmpls extension*/
  if (ntohs (lp->av_wave_mask.header.type) !=0 && ntohs (lp->av_wave_mask.header.length) !=0)
    length += TLV_SIZE (&lp->av_wave_mask.header);
  /* te_link_calendar -- gmpls extension*/
  if (ntohs (lp->te_link_calendar.header.type) !=0 && ntohs (lp->te_link_calendar.header.length) != 0)
    length += TLV_SIZE (&lp->te_link_calendar.header);

/* *************** Geysers Extensions ********************** */
  /* power_consumption -- geysers extension*/
  if (ntohs (lp->power_consumption.header.type) !=0 && ntohs (lp->power_consumption.header.length) !=0)
    length += TLV_SIZE (&lp->power_consumption.header);
  /* dynamic_replanning -- geysers extension*/
  if (ntohs (lp->dynamic_replanning.header.type) !=0 && ntohs (lp->dynamic_replanning.header.length) != 0)
    length += TLV_SIZE (&lp->dynamic_replanning.header);

  /* this is TE-link TLV */
  lp->link_header.header.type   = htons (TE_TLV_LINK);
  /* set calculated length */
  lp->link_header.header.length = htons (length);

  return;
}

/**
 * Set TE-link type in relation to ospf interface type
 * @param oi - ospf interface 
 * @param lp - TE-link for which link type is set
 */
static void
set_linkparams_link_type (struct ospf_interface *oi, struct te_link *lp)
{
  lp->link_type.header.type   = htons (TE_LINK_SUBTLV_LINK_TYPE);
  lp->link_type.header.length = htons (sizeof (lp->link_type.link_type.value));

  switch (oi->type)
  {
    case OSPF_IFTYPE_POINTOPOINT:
      lp->link_type.link_type.value = LINK_TYPE_SUBTLV_VALUE_PTP;
      break;
    case OSPF_IFTYPE_BROADCAST:
    case OSPF_IFTYPE_NBMA:
      lp->link_type.link_type.value = LINK_TYPE_SUBTLV_VALUE_MA;
      break;
    default:
      zlog_warn("[WRN] set_linkparams_link_type: Unknown oi type: %d", oi->type);
      /* Not supported yet. *//* XXX */
      lp->link_type.header.type = htons (0);
      break;
  }
  return;
}

/**
 * Set TE-link ID in relation to ospf interface type
 * @param oi - ospf interface 
 * @param lp - TE-link for which identifier is set
 */
static void
set_linkparams_link_id (struct ospf_interface *oi, struct te_link *lp)
{
  struct ospf_neighbor *nbr;
  int done = 0;

  lp->link_id.header.type   = htons (TE_LINK_SUBTLV_LINK_ID);
  lp->link_id.header.length = htons (sizeof (lp->link_id.value));

/**
 * The Link ID is identical to the contents of the Link ID field
 * in the Router LSA for these link types.
 */
  switch (oi->type)
    {
    case OSPF_IFTYPE_POINTOPOINT:
      /* Take the router ID of the neighbor. */
      if ((nbr = ospf_nbr_lookup_ptop (oi)) && nbr->state == NSM_Full)
      {
        lp->link_id.value = nbr->router_id;
        if (IS_DEBUG_TE(ORIGINATE))
          zlog_debug("[DBG] Setting link id: %s", inet_ntoa(lp->link_id.value));
        done = 1;
      }
      break;
    case OSPF_IFTYPE_BROADCAST:
    case OSPF_IFTYPE_NBMA:
      /* Take the interface address of the designated router. */
      if ((nbr = ospf_nbr_lookup_by_addr (oi->nbrs, &DR (oi))) == NULL)
        break;

      if (nbr->state == NSM_Full || (IPV4_ADDR_SAME (&oi->address->u.prefix4, &DR (oi)) &&  ospf_nbr_count (oi, NSM_Full) > 0))
      {
        lp->link_id.value = DR (oi);
        if (IS_DEBUG_TE(ORIGINATE))
          zlog_debug("[DBG] Setting link id: %s", inet_ntoa(lp->link_id.value));
        done = 1;
      }
      break;
    default:
      /* Not supported yet. *//* XXX */
      zlog_warn("[WRN] set_linkparams_link_id: Not supported oi->type: %d", oi->type);
      lp->link_id.header.type = htons (0);
      break;
    }

  if (! done)
  {
    struct in_addr mask;
    masklen2ip (oi->address->prefixlen, &mask);
    lp->link_id.value.s_addr = oi->address->u.prefix4.s_addr & mask.s_addr;
  }
  return;
}

/**
 * Set TE-link metric
 * @param lp - TE-link for which metric is set
 * @param te_metric - metric for TE-link
 */
void
set_linkparams_te_metric (struct te_link *lp, u_int32_t te_metric)
{
  lp->te_metric.header.type   = htons (TE_LINK_SUBTLV_TE_METRIC);
  lp->te_metric.header.length = htons (sizeof (lp->te_metric.value));
  lp->te_metric.value = htonl (te_metric);
  return;
}

/**
 * Set TE-link maximum bandwidth
 * @param lp - TE-link for which maximum bandwidth is set
 * @param fp - maximum bandwidth for TE-link
 */
void
set_linkparams_max_bw (struct te_link *lp, float *fp)
{
  lp->max_bw.header.type   = htons (TE_LINK_SUBTLV_MAX_BW);
  lp->max_bw.header.length = htons (sizeof (lp->max_bw.value));
  htonf (fp, &lp->max_bw.value);
  return;
}

/**
 * Set TE-link local and remote TE router ID
 * @param lp - TE-link for which local and remote TE router ID is set
 * @param lcl_id - local router ID for TE-link
 * @param rmt_id - remote router ID for TE-link
 */
void
set_link_lcl_rmt_ids (struct te_link *lp, u_int32_t lcl_id, u_int32_t rmt_id)
{
  lp->link_lcl_rmt_ids.header.type   = htons (TE_LINK_SUBTLV_LINK_LCL_RMT_IDS);
  lp->link_lcl_rmt_ids.header.length = htons (8);
  lp->link_lcl_rmt_ids.local_id = htonl (lcl_id);
  lp->link_lcl_rmt_ids.remote_id = htonl (rmt_id);
  return;
}

/**
 * Set TE-link protection type
 * @param lp - TE-link for which protection type is set
 * @param value - protection type for TE-link
 */
void
set_link_protect_type(struct te_link *lp, u_char value)
{
  lp->link_protect_type.header.type   = htons (TE_LINK_SUBTLV_LINK_PROTECT_TYPE);
  lp->link_protect_type.header.length = htons (1);
  lp->link_protect_type.value = value;
  return;
}

/**
 * Creaate new TE-link interface switching capability descriptor
 * @param lp - TE-link for which interface switching capability is set
 * @param sw_cap - interface switching capability for TE-link
 * @param enc - interface encoding for TE-link
 */
uint8_t
create_te_link_subtlv_if_sw_cap_desc (struct te_link *lp, u_char sw_cap, u_int8_t enc)
{
  struct zlistnode *node, *nnode;
  void *data;
  struct te_link_subtlv_if_sw_cap_desc* tmp;

  for (ALL_LIST_ELEMENTS(&lp->if_sw_cap_descs, node, nnode, data))
  {
    tmp = (struct te_link_subtlv_if_sw_cap_desc *) data;
    if (tmp->switching_cap == sw_cap && tmp->encoding == enc)
      return -1;
  }

  struct te_link_subtlv_if_sw_cap_desc *ifswcap = XMALLOC(0, sizeof(struct  te_link_subtlv_if_sw_cap_desc));
  memset(ifswcap, 0, sizeof(struct te_link_subtlv_if_sw_cap_desc));
  ifswcap->header.type   = htons (TE_LINK_SUBTLV_IF_SW_CAP_DESC);
  ifswcap->header.length = htons (4+4*LINK_MAX_PRIORITY);
  ifswcap->switching_cap = sw_cap;
  ifswcap->encoding      = enc;
  listnode_add(&lp->if_sw_cap_descs, ifswcap);

  return 0;
}

/**
 * Delete TE-link interface switching capability descriptor
 * @param lp - TE-link for which interface switching capability is set
 * @param sw_cap - interface switching capability for TE-link
 * @param enc - interface encoding for TE-link
 */
uint8_t
delete_te_link_subtlv_if_sw_cap_desc (struct te_link *lp, u_char sw_cap, u_int8_t enc)
{
  struct zlistnode *node, *nnode;
  void *data;
  struct te_link_subtlv_if_sw_cap_desc* tmp;
  uint8_t found;

  found = 0;
  for (ALL_LIST_ELEMENTS(&lp->if_sw_cap_descs, node, nnode, data))
  {
    tmp = (struct te_link_subtlv_if_sw_cap_desc *) data;
    if (tmp->switching_cap == sw_cap && tmp->encoding == enc) {
      found = 1;
      break;
    }
  }

  if (found) {
    listnode_delete(&lp->if_sw_cap_descs, tmp);
    return 0;
  }

  return -1;
}

/**
 * clearing TE-link interface switching capability descriptors list
 * @param lp - te_link
 */
static int
clear_if_sw_cap_descs_list (struct te_link *lp)
{
  int result = -1;
  if (listcount(&lp->if_sw_cap_descs) == 0)
    return result;

  result = 0;
  list_delete_all_node(&lp->if_sw_cap_descs);

  return result;
}

/**
 * Set TE-link interface max LSP bandwidths
 * @param lp - TE-link for which max LSP bandwidth is set
 * @param maxBand[] - maximum LSP bandwidths
 */
void
set_if_sw_cap_max_bands (struct te_link *lp, u_char sw_cap, u_int8_t enc, float *maxBand)
{
  struct zlistnode *node, *nnode;
  struct te_link_subtlv_if_sw_cap_desc* tmp;
  struct te_link_subtlv_if_sw_cap_desc* ifswcap;

  ifswcap = NULL;
  for (ALL_LIST_ELEMENTS(&lp->if_sw_cap_descs, node, nnode, tmp))
  {
    if (tmp->switching_cap == sw_cap && tmp->encoding == enc)
      ifswcap = tmp;
  }
  if (ifswcap == NULL)
    return;

  for (int i=0; i<8; i++)
    htonf(&maxBand[i], &ifswcap->maxLSPbw[i]);

  return;
}

/**
 * Set TE-link interface max LSP bandwidth for particular priority
 * @param lp - TE-link for which max LSP bandwidth is set
 * @param sw_cap - interface switching capability for TE-link
 * @param enc - interface encoding for TE-link
 * @param priority - LSP priority
 * @param maxBand - maximum LSP bandwidth
 */
static void
set_if_sw_cap_max_band (struct te_link *lp, u_char sw_cap, u_int8_t enc, u_int8_t priority, float *maxBand)
{
  struct zlistnode *node, *nnode;
  struct te_link_subtlv_if_sw_cap_desc* tmp;
  struct te_link_subtlv_if_sw_cap_desc* ifswcap;

  ifswcap = NULL;
  for (ALL_LIST_ELEMENTS(&lp->if_sw_cap_descs, node, nnode, tmp))
  {
    if (tmp->switching_cap == sw_cap && tmp->encoding == enc)
      ifswcap = tmp;
  }
  if (ifswcap == NULL)
    return;

  if (priority < LINK_MAX_PRIORITY)
  {
    htonf(maxBand, &ifswcap->maxLSPbw[priority]);
  }
  return;
}

/**
 * Set TE-link interface psc-switching capability descriptor
 * @param lp - TE-link for which psc-switching capability descriptor is set
 * @param sw_cap - interface switching capability for TE-link
 * @param enc - interface encoding for TE-link
 * @param min_lsp_bw - minimum LSP bandwidth for TE-link
 * @param mtu - MTU for TE-link
 */
void
set_if_sw_cap_desc_psc(struct te_link *lp, u_char sw_cap, u_int8_t enc, float *min_lsp_bw, u_int16_t mtu)
{
  struct zlistnode *node, *nnode;
  struct te_link_subtlv_if_sw_cap_desc* tmp;
  struct te_link_subtlv_if_sw_cap_desc* ifswcap;

  ifswcap = NULL;
  for (ALL_LIST_ELEMENTS(&lp->if_sw_cap_descs, node, nnode, tmp))
  {
    if (tmp->switching_cap == sw_cap && tmp->encoding == enc)
      ifswcap = tmp;
  }
  if (ifswcap == NULL)
    return;

  ifswcap->header.length = htons (4+4*LINK_MAX_PRIORITY+6);     /*value overriding */

  htonf (min_lsp_bw, &ifswcap->swcap_specific_info.swcap_specific_psc.min_lsp_bw);
  ifswcap->swcap_specific_info.swcap_specific_psc.mtu = htons(mtu);
  return;
}

/**
 * Set TE-link interface tdm-switching capability descriptor
 * @param lp - TE-link for which tdm-switching capability descriptor is set
 * @param sw_cap - interface switching capability for TE-link
 * @param enc - interface encoding for TE-link
 * @param min_lsp_bw - minimum LSP bandwidth for TE-link
 * @param indication - indication for TE-link
 */
void
set_if_sw_cap_desc_tdm(struct te_link *lp, u_char sw_cap, u_int8_t enc, float *min_lsp_bw, u_int8_t indication)
{
  struct zlistnode *node, *nnode;
  struct te_link_subtlv_if_sw_cap_desc* tmp;
  struct te_link_subtlv_if_sw_cap_desc* ifswcap;

  ifswcap = NULL;
  for (ALL_LIST_ELEMENTS(&lp->if_sw_cap_descs, node, nnode, tmp))
  {
    if (tmp->switching_cap == sw_cap && tmp->encoding == enc)
      ifswcap = tmp;
  }
  if (ifswcap == NULL)
    return;

  ifswcap->header.length = htons (4+4*LINK_MAX_PRIORITY+5);      //value overriding

  htonf (min_lsp_bw, &ifswcap->swcap_specific_info.swcap_specific_tdm.min_lsp_bw);
  ifswcap->swcap_specific_info.swcap_specific_tdm.indication=indication;
  return;
}

/**
 * Add shared link for TE-link
 * @param lp - TE-link
 * @param value - shared link for TE-link
 */
int
add_shared_risk_link_grp(struct te_link *lp, u_int32_t value)
{
  int result = -1;

  struct zlistnode *node;
  struct zlistnode *nnode;
  u_int32_t *l_value;
  u_int32_t tmp_value=htonl(value);

  for (ALL_LIST_ELEMENTS(&lp->shared_risk_link_grp.values, node, nnode, l_value))
    if (tmp_value == (*l_value))
      goto add_exit;

  result = 0;

  u_int32_t *n_value=XMALLOC (MTYPE_OSPF_TE_SHARED_RISK_L, sizeof(u_int32_t));
  (*n_value)=tmp_value;
  listnode_add(&lp->shared_risk_link_grp.values, n_value);

  lp->shared_risk_link_grp.header.length = htons(4 * (lp->shared_risk_link_grp.values.count));
  lp->shared_risk_link_grp.header.type = htons(TE_LINK_SUBTLV_SHARED_RISK_LINK_GRP);

add_exit:
  return result;
}

/**
 * deleting shared link list group
 * @param lp - te_link
 * @param value - shared link for TE-link
 */
int
del_shared_risk_link_grp(struct te_link *lp, u_int32_t value)
{
  int result = -1;
  if (lp->shared_risk_link_grp.values.count == 0)
    return result;

  struct zlistnode *node;
  struct zlistnode *nnode;
  u_int8_t  found = 0;
  u_int32_t *l_value;
  u_int32_t tmp_value=htonl(value);

  for (ALL_LIST_ELEMENTS(&lp->shared_risk_link_grp.values, node, nnode, l_value))
    if (tmp_value == (*l_value)) {
      found = 1;
      break;
    }

  if (found) {
    listnode_delete(&lp->shared_risk_link_grp.values, l_value);
    lp->shared_risk_link_grp.header.length = htons(4 * (lp->shared_risk_link_grp.values.count));
    result = 0;
  }

  return result;
}

/**
 * clearing shared link list group
 * @param lp - te_link
 */
static int
clear_shared_risk_link_grp(struct te_link *lp)
{
  int result = -1;
  if (lp->shared_risk_link_grp.values.count == 0)
    return result;

  result = 0;
  list_delete_all_node(&lp->shared_risk_link_grp.values);
  lp->shared_risk_link_grp.header.length =0;

  return result;
}

/**
 * Set local and remote TE Router ID 
 * @param lp - TE-link 
 * @param lcl_id - Local router ID for TE-link
 * @param rmt_id - Remote router ID for TE-link
 */
static void
set_lcl_rmt_te_router_id(struct te_link *lp, u_int32_t lcl_id, u_int32_t rmt_id)
{
  lp->lcl_rmt_te_router_id.header.type   = htons (TE_LINK_SUBTLV_LCL_RMT_TE_ROUTER_ID);
  lp->lcl_rmt_te_router_id.header.length = htons (8);
  lp->lcl_rmt_te_router_id.lcl_router_id = htonl (lcl_id);
  lp->lcl_rmt_te_router_id.rmt_router_id = htonl (rmt_id);
  return;
}

/** ************************************************************************ */
/** **************************** OFI E-NNI Routing ************************* */
/** ************************************************************************ */ 

/**
 * Set local node ID 
 * @param lp - TE-link
 * @param address - Local node IP address for TE-link
 */
void
set_oif_lcl_node_id (struct te_link *lp, struct in_addr address)
{
  lp->lcl_node_id.header.type = htons (TE_LINK_SUBTLV_LCL_NODE_ID);
  lp->lcl_node_id.header.length = htons (sizeof (lp->lcl_node_id.value));
  lp->lcl_node_id.value = address;
  return;
}

/**
 * Set remote node ID 
 * @param lp - TE-link
 * @param address - Remote node IP address for TE-link
 */
void
set_oif_rmt_node_id (struct te_link *lp, struct in_addr address)
{
  lp->rmt_node_id.header.type = htons (TE_LINK_SUBTLV_RMT_NODE_ID);
  lp->rmt_node_id.header.length = htons (sizeof (lp->rmt_node_id.value));
  lp->rmt_node_id.value = address;
  return;
}

/**
 * Set Sonet/SDH interface switching capability descriptor
 * @param lp - TE-link
 */
void
set_oif_ssdh_if_sw_cap_desc (struct te_link *lp)
{
  lp->ssdh_if_sw_cap_desc.header.type   = htons (TE_LINK_SUBTLV_SSDH_IF_SW_CAP_DESC);
  lp->ssdh_if_sw_cap_desc.switching_cap = CAPABILITY_TDM;
  lp->ssdh_if_sw_cap_desc.encoding      = LINK_IFSWCAP_SUBTLV_ENC_SONETSDH;
  lp->ssdh_if_sw_cap_desc.header.length = htons (4 + 4*listcount(&lp->ssdh_if_sw_cap_desc.signals_list));
  return;
}

/**
 * Add signal to Sonet/SDH interface switching capability descriptor
 * @param lp - TE-link
 * @param signal_type - signal type 
 * @param unalloc_tsl[] - number of unallocated time slots
 */
void
add_oif_ssdh_if_sw_cap_desc_signal (struct te_link *lp, u_char signal_type, u_char unalloc_tsl[])
{
  struct signal_unalloc_tslots *n_value = XMALLOC (MTYPE_OSPF_TE_SIGNAL_UNALLOC_TSLOTS, sizeof(struct signal_unalloc_tslots));
  n_value->signal_type = signal_type;
  n_value->unalloc_tslots[2] = unalloc_tsl[0];
  n_value->unalloc_tslots[1] = unalloc_tsl[1];
  n_value->unalloc_tslots[0] = unalloc_tsl[2];
  listnode_add (&lp->ssdh_if_sw_cap_desc.signals_list, n_value);
  lp->ssdh_if_sw_cap_desc.header.type = htons (TE_LINK_SUBTLV_SSDH_IF_SW_CAP_DESC);
  lp->ssdh_if_sw_cap_desc.header.length = htons (4 + 4*listcount(&lp->ssdh_if_sw_cap_desc.signals_list));
  return;
}

/**
 * Clear Sonet/SDH interface switching capability descriptor
 * @param lp - TE-link
 */
int
clear_oif_ssdh_if_sw_cap_desc_signal (struct te_link *lp)
{
  int result = -1;
  if (listcount(&lp->ssdh_if_sw_cap_desc.signals_list) ==0)
    return result;

  result = 0;
  list_delete_all_node(&lp->ssdh_if_sw_cap_desc.signals_list);
  lp->ssdh_if_sw_cap_desc.header.length =0;
  return result;
}

/**
 * Set general capabilities flag S
 * @param lp - TE-link
 * @param flag_val - flag S value
 */
static void 
set_oif_general_cap_flag_s (struct te_link *lp, u_char flag_val)
{
  lp->general_cap.header.type   = htons (TE_LINK_SUBTLV_GENERAL_CAP);
  lp->general_cap.header.length = htons (1);
  lp->general_cap.flags &= 0xFC;
  lp->general_cap.flags |= flag_val;
  return;
}

/**
 * Set general capabilities flag T
 * @param lp - TE-link
 * @param flag_val - flag T value
 */
static void
set_oif_general_cap_flag_t (struct te_link *lp, u_char flag_val)
{
  lp->general_cap.header.type   = htons (TE_LINK_SUBTLV_GENERAL_CAP);
  lp->general_cap.header.length = htons (1);
  lp->general_cap.flags &= 0xFB;
  lp->general_cap.flags |= flag_val;
  return;
}

/**
 * Set general capabilities flag M
 * @param lp - TE-link
 * @param flag_val - flag M value
 */
static void
set_oif_general_cap_flag_m (struct te_link *lp, u_char flag_val)
{
  lp->general_cap.header.type   = htons (TE_LINK_SUBTLV_GENERAL_CAP);
  lp->general_cap.header.length = htons (1);
  lp->general_cap.flags &= 0xF7;
  lp->general_cap.flags |= flag_val;
  return;
}

/**
 * Add ID to hierarchy list 
 * @param lp - TE-link
 * @param address - IPv4 address
 */
static void
add_oif_hierarchy_list_id (struct te_link *lp, struct in_addr address)
{
  struct in_addr *n_value = XMALLOC (MTYPE_OSPF_TE_ADDRESS_IP4, 4);
  *n_value = address;
  listnode_add (&lp->hierarchy_list.hierarchy_list, n_value);
  lp->hierarchy_list.header.type   = htons (TE_LINK_SUBTLV_HIERARCHY_LIST);
  lp->hierarchy_list.header.length = htons (4* listcount(&lp->hierarchy_list.hierarchy_list));
  return;
}

/**
 * Clear hierarchy list 
 * @param lp - TE-link
 */
static int
clear_oif_hierarchy_list_id (struct te_link *lp)
{
  int result = -1;
  if (listcount(&lp->hierarchy_list.hierarchy_list) ==0)
    return result;

  result = 0;
  list_delete_all_node(&lp->hierarchy_list.hierarchy_list);
  lp->hierarchy_list.header.length =0;
  return result;
}

/**
 * Set ancestor RC (Routing Controller) ID 
 * @param lp - TE-link
 * @param address - IPv4 address
 */
void
set_oif_anc_rc_id (struct te_link *lp, struct in_addr address)
{
  lp->anc_rc_id.header.type   = htons (TE_LINK_SUBTLV_ANC_RC_ID);
  lp->anc_rc_id.header.length = htons (sizeof (lp->anc_rc_id.value));
  lp->anc_rc_id.value = address;
  return;
}

/** ************************************************************************ */
/** **************************** GMPLS ASON Routing ************************ */
/** ************************************************************************ */


/**
 * Add signal to technology specific bandwidth accounting
 * @param lp - TE-link
 * @param signal_type - signal type 
 * @param unalloc_tsl[] - number of unallocated time slots
 */
static void
add_ason_band_account (struct te_link *lp, u_char signal_type, u_char unalloc_tsl[])
{
  struct signal_unalloc_tslots *n_value = XMALLOC (MTYPE_OSPF_TE_SIGNAL_UNALLOC_TSLOTS, sizeof(struct signal_unalloc_tslots));
  n_value->signal_type = signal_type;
  n_value->unalloc_tslots[2] = unalloc_tsl[0];
  n_value->unalloc_tslots[1] = unalloc_tsl[1];
  n_value->unalloc_tslots[0] = unalloc_tsl[2];
  listnode_add (&lp->band_account.signals_list, n_value);
  lp->band_account.header.type   = htons (TE_LINK_SUBTLV_BAND_ACCOUNT);
  lp->band_account.header.length = htons (4*listcount(&lp->band_account.signals_list));
  return;
}

/**
 * Clear technology specific bandwidth accounting
 * @param lp - TE-link
 */
static int
clear_ason_band_account (struct te_link *lp)
{
  int result = -1;
  if (listcount(&lp->band_account.signals_list) ==0)
    return result;

  result = 0;
  list_delete_all_node(&lp->band_account.signals_list);
  lp->band_account.header.length =0;
  return result;
}

/**
 * Add OSPF downstream associated area ID
 * @param lp - TE-link
 * @param value - associated area ID
 */
static void
add_ason_ospf_down_aa_id (struct te_link *lp, u_int32_t value)
{
  u_int32_t *n_value = XMALLOC (MTYPE_OSPF_TE_AA_ID, sizeof(u_int32_t));
  *n_value = htonl (value);
  listnode_add (&lp->ospf_down_aa_id.area_id_list, n_value);
  lp->ospf_down_aa_id.header.type   = htons (TE_LINK_SUBTLV_OSPF_DOWN_AA_ID);
  lp->ospf_down_aa_id.header.length = htons (4* listcount(&lp->ospf_down_aa_id.area_id_list));
  return;
}

/**
 * Clear OSPF downstream associated area ID
 * @param lp - TE-link
 */
static int
clear_ason_ospf_down_aa_id (struct te_link *lp)
{
  int result = -1;
  if (listcount(&lp->ospf_down_aa_id.area_id_list) ==0)
    return result;

  result = 0;
  list_delete_all_node(&lp->ospf_down_aa_id.area_id_list);
  lp->ospf_down_aa_id.header.length =0;
  return result;
}

/**
 * Set associated area ID
 * @param lp - TE-link
 * @param value - associated area ID
 */
static void
set_ason_aa_id (struct te_link *lp, u_int32_t value)
{
  lp->aa_id.header.type   = htons (TE_LINK_SUBTLV_AA_ID);
  lp->aa_id.header.length = htons (sizeof (lp->aa_id.area_id));
  lp->aa_id.area_id = htonl (value);
  return;
}

/** ************************************************************************ */
/** **************************** GMPLS All-optical Extensions ************** */
/** ************************************************************************ */

/**
 * Set BER estimate
 * @param lp - TE-link
 * @param value - The exponent from the BER representation
 */
static void
set_all_opt_ext_ber_estimate (struct te_link *lp, u_int8_t value)
{
  lp->ber_estimate.header.type   = htons (TE_LINK_SUBTLV_BER_ESTIMATE);
  lp->ber_estimate.header.length = htons (1);
  lp->ber_estimate.value = value;
  return;
}

/**
 * Set span length
 * @param lp - TE-link
 * @param value - The total length of the WDM span in meters
 */
void
set_all_opt_ext_span_length (struct te_link *lp, u_int32_t value)
{
  lp->span_length.header.type = htons (TE_LINK_SUBTLV_SPAN_LENGTH);
  lp->span_length.header.length = htons (4);
  lp->span_length.value = htonl (value);
  return;
}

/**
 * Set OSNR
 * @param lp - TE-link
 * @param value - The total length of the WDM span in meters
 */
static void
set_all_opt_ext_osnr (struct te_link *lp, u_int32_t value)
{
  lp->osnr.header.type   = htons (TE_LINK_SUBTLV_OSNR);
  lp->osnr.header.length = htons (sizeof (lp->osnr.value));
  lp->osnr.value = htonl (value);
  return;
}

/**
 * Set D_pdm
 * @param lp - TE-link
 * @param value - The fiber PDM parameter
 */
void
set_all_opt_ext_d_pdm (struct te_link *lp, float *value)
{
  lp->d_pdm.header.type   = htons (TE_LINK_SUBTLV_D_PDM);
  lp->d_pdm.header.length = htons (sizeof (lp->d_pdm.value));
  htonf (value, &lp->d_pdm.value);
  return;
}

/**
 * Add amplifier
 * @param lp - TE-link
 * @param gain_val - Amplifier gain
 * @param noise_val - Amplifier noise figure
 */
void
add_all_opt_ext_amp_list (struct te_link *lp, u_int32_t gain_val, float *noise_val)
{
  struct amp_par *n_value = XMALLOC (MTYPE_OSPF_TE_AMP_PAR, sizeof(struct amp_par));
  n_value->gain = htonl (gain_val);
  htonf (noise_val, &n_value->noise);
  listnode_add (&lp->amp_list.amp_list, n_value);
  lp->amp_list.header.type   = htons (TE_LINK_SUBTLV_AMP_LIST);
  lp->amp_list.header.length = htons (8* listcount(&lp->amp_list.amp_list));
  return;
}

/**
 * Clear amplifiers list
 * @param lp - TE-link
 */
int
clear_all_opt_ext_amp_list (struct te_link *lp)
{
  int result = -1;
  if (listcount(&lp->amp_list.amp_list) ==0)
    return result;

  result = 0;
  list_delete_all_node(&lp->amp_list.amp_list);
  lp->amp_list.header.length =0;
  return result;
}

/**
 * Set Available Wavelength Mask
 * @param lp - TE-link
 * @param num - Number of wavelengths represented by the bit map
 * @param label_set_desc - Label set description
 */
void
set_all_opt_ext_av_wave_mask (struct te_link *lp, u_int16_t num, u_int32_t label_set_desc)
{
  lp->av_wave_mask.header.type   = htons (TE_LINK_SUBTLV_AV_WAVE_MASK);
  lp->av_wave_mask.header.length = htons (8 + 4*listcount(&lp->av_wave_mask.bitmap_list));
  lp->av_wave_mask.action = 4; // Bitmap set
  lp->av_wave_mask.num_wavelengths = htons(num);
  lp->av_wave_mask.label_set_desc = htonl(label_set_desc);
  return;
}

/**
 * Add Available Wavelength Mask bitmap
 * @param lp - TE-link
 * @param value - Each bit in the bit map represents a particular frequency (available / not-available)
 */
void
add_all_opt_ext_av_wave_mask_bitmap (struct te_link *lp, u_int32_t value)
{
  u_int32_t tmp_value=htonl(value);

  u_int32_t *n_value=XMALLOC (MTYPE_OSPF_TE_AV_WAVE_MASK, sizeof(u_int32_t));
  (*n_value)=tmp_value;
  listnode_add (&lp->av_wave_mask.bitmap_list, n_value);
  lp->av_wave_mask.header.type   = htons (TE_LINK_SUBTLV_AV_WAVE_MASK);
  lp->av_wave_mask.header.length = htons (8 + 4* listcount(&lp->av_wave_mask.bitmap_list));

  return;
}

/**
 * Clear Available Wavelength Mask bitmap list
 * @param lp - TE-link
 */
int
clear_all_opt_ext_av_wave_mask (struct te_link *lp)
{
  int result = 0;
  if (listcount(&lp->av_wave_mask.bitmap_list) ==0)
    return -1;

  list_delete_all_node(&lp->av_wave_mask.bitmap_list);
  lp->av_wave_mask.header.length = htons(8);
  return result;
}

/**
 * Add item to TE-link Calendar
 * @param lp - TE-link
 * @param time - Time
 * @param band - Available bandwidth
 */
#define MTYPE_TE_LINK_CALENDAR 0
void
add_all_opt_ext_te_link_calendar (struct te_link *lp, u_int32_t time, float *band)
{
  struct te_link_calendar *n_value = XMALLOC (MTYPE_TE_LINK_CALENDAR, sizeof(struct te_link_calendar));
  int i;

  n_value->time = htonl (time);
  for (i=0; i<8; i++)
    htonf (&band[i], &n_value->value[i]);

  struct zlistnode *node;
  struct zlistnode *nnode;
  u_int8_t found;
  struct te_link_calendar *l_value;

  for (ALL_LIST_ELEMENTS(&lp->te_link_calendar.te_calendar, node, nnode, l_value)) {
    found = 1;

    if (n_value->time != l_value->time)
      continue;

    for (i=0; i<8; i++)
      if (n_value->value[i] != l_value->value[i])
        found = 0;

    if (found)
      goto add_exit;
  }

  listnode_add (&lp->te_link_calendar.te_calendar, n_value);
  lp->te_link_calendar.header.type   = htons (TE_LINK_SUBTLV_TE_LINK_CALENDAR);
  lp->te_link_calendar.header.length = htons (36* listcount(&lp->te_link_calendar.te_calendar));

add_exit:
  return;
}

/**
 * Delete item from TE-link Calendar
 * @param lp - TE-link
 * @param time - Time
 * @param band - Available bandwidth
 */
int
del_all_opt_ext_te_link_calendar (struct te_link *lp, u_int32_t time, float *band)
{
  int result = -1;
  if (listcount(&lp->te_link_calendar.te_calendar) == 0)
    return result;

  struct zlistnode *node;
  struct zlistnode *nnode;
  u_int8_t  found, found2;
  struct te_link_calendar *l_value;
  struct te_link_calendar tmp_value;
  int i;

  tmp_value.time = htonl (time);
  for (i=0; i<8; i++)
    htonf (&band[i], &tmp_value.value[i]);

  found = 0;
  for (ALL_LIST_ELEMENTS(&lp->te_link_calendar.te_calendar, node, nnode, l_value)) {
    found2 = 1;

    if (tmp_value.time != l_value->time)
      continue;

    for (i=0; i<8; i++)
      if (tmp_value.value[i] != l_value->value[i])
        found2 = 0;

    if (found2) {
      found = 1;
      break;
    }
  }

  if (found) {
    listnode_delete (&lp->te_link_calendar.te_calendar, l_value);
    lp->te_link_calendar.header.length = htons (36* listcount(&lp->te_link_calendar.te_calendar));
    result = 0;
  }

  return result;
}

/**
 * Clear TE-link Calendar
 * @param lp - TE-link
 */
static int
clear_all_opt_ext_te_link_calendar (struct te_link *lp)
{
  int result = -1;
  if (listcount(&lp->te_link_calendar.te_calendar) ==0)
    return result;

  result = 0;
  list_delete_all_node(&lp->te_link_calendar.te_calendar);
  lp->te_link_calendar.header.length =0;
  return result;
}

/** ************************************************************************ */
/** **************************** Geysers Extensions ************************ */
/** ************************************************************************ */

/**
 * Set TE-link power consumption
 * @param lp - TE-link for which power consumption is set
 * @param fp - power consumption for TE-link
 */
void
set_linkparams_power_consumption (struct te_link *lp, float *fp)
{
  //zlog_debug("[DBG] seting link power consumption %g", &fp);
  lp->max_bw.header.type   = htons (TE_LINK_SUBTLV_POWER_CONSUMPTION);
  lp->max_bw.header.length = htons (sizeof (lp->power_consumption.power_consumption));
  htonf (fp, &lp->power_consumption.power_consumption);
  return;
}

/**
 * Set TE-link dynamic re-planning
 * @param lp - TE-link for which dynamic re-planning is set
 * @param fp1 - max bandwidth upgrade for TE-link
 * @param fp2 - max bandwidth downgrade for TE-link
 */
void
set_linkparams_dynanic_replanning (struct te_link *lp, float *upgrade, float *downgrade)
{
  lp->max_bw.header.type   = htons (TE_LINK_SUBTLV_DYNAMIC_REPLANNING); 
  lp->max_bw.header.length = htons (sizeof (lp->dynamic_replanning.max_bandwidth_upgrade))
			   + htons (sizeof (lp->dynamic_replanning.max_bandwidth_downgrade));
  htonf (upgrade,   &lp->dynamic_replanning.max_bandwidth_upgrade);
  htonf (downgrade, &lp->dynamic_replanning.max_bandwidth_downgrade);
  //zlog_debug("[DBG] Setting link replanning downgrade: %g, upgrade: %g", &downgrade, &upgrade);
  return;
}

/** ************************************************************************ */

void
set_linkparams_max_rsv_bw (struct te_link *lp, float *fp)
{
  lp->max_rsv_bw.header.type   = htons (TE_LINK_SUBTLV_MAX_RSV_BW);
  lp->max_rsv_bw.header.length = htons (sizeof (lp->max_rsv_bw.value));
  htonf (fp, &lp->max_rsv_bw.value);
  return;
}

void
set_linkparams_unrsv_bw (struct te_link *lp, int priority, float *fp)
{
  /* Note that TLV-length field is the size of array. */
  lp->unrsv_bw.header.type   = htons (TE_LINK_SUBTLV_UNRSV_BW);
  lp->unrsv_bw.header.length = htons (4*8);
  htonf (fp, &lp->unrsv_bw.value [priority]);
  return;
}

void
set_linkparams_rsc_clsclr (struct te_link *lp, u_int32_t classcolor)
{
  lp->rsc_clsclr.header.type   = htons (TE_LINK_SUBTLV_RSC_CLSCLR);
  lp->rsc_clsclr.header.length = htons (sizeof (lp->rsc_clsclr.value));
  lp->rsc_clsclr.value = htonl (classcolor);
  return;
}

static void
initialize_linkparams (struct te_link *lp)
{
  lp->harmony_ifp = 0;

  struct interface *ifp = lp->ifp;
  if (ifp == NULL)
    return;

  struct ospf_interface *oi;
  float fval;
  int i;

  if ((oi = lookup_oi_by_ifp (ifp, NULL, OI_ANY)) == NULL)
  {
    zlog_warn("[WRN] INITIALIZE_LINKPARAMS: oi = NULL (ifp: %s)", ifp->name);
    lp->is_set_linkparams_link_type = htons(0);
    return;
  }
  if (IS_DEBUG_TE(INITIALIZATION))
    zlog_debug ("[DBG] INITIALIZE_LINKPARAMS: Found oi (ifp: %s)", ifp->name);

  /*
   * Try to set initial values those can be derived from
   * zebra-interface information.
   */
  set_linkparams_link_type (oi, lp);
  lp->is_set_linkparams_link_type = 1;

  /*
   * Linux and *BSD kernel holds bandwidth parameter as an "int" type.
   * We may have to reconsider, if "ifp->bandwidth" type changes to float.
   */
  fval = (float)((ifp->bandwidth ? ifp->bandwidth : OSPF_DEFAULT_BANDWIDTH) * 1000 / 8);

  set_linkparams_max_bw (lp, &fval);
  set_linkparams_max_rsv_bw (lp, &fval);

  for (i = 0; i < 8; i++)
    set_linkparams_unrsv_bw (lp, i, &fval);

  lp->shared_risk_link_grp.header.type   = htons (TE_LINK_SUBTLV_SHARED_RISK_LINK_GRP);
  lp->shared_risk_link_grp.header.length = htons(0);
  memset (&lp->shared_risk_link_grp.values, 0, sizeof (struct zlist));
  lp->shared_risk_link_grp.values.del = (void (*) (void *))del_te_shared_risk_l;

  lp->tna_address.header.type   = htons (TE_TLV_TNA_ADDR);
  lp->tna_address.header.length = htons(0);
  memset (&lp->tna_address.tna_addr_data, 0, sizeof (struct zlist));
  lp->tna_address.tna_addr_data.del = (void (*) (void *))del_te_tna_addr;

  return;
}

#ifdef GMPLS
/**
 * Reading Intra domain TE-links parameters
 */
static void 
read_te_numbered(struct te_link *lp, struct interface *ifp)
{
  lp->lclif_ipaddr.header.type      = htons (TE_LINK_SUBTLV_LCLIF_IPADDR);
  lp->lclif_ipaddr.header.length    = htons (4);
  lp->lclif_ipaddr.value[0].s_addr  = ifp->te_local_id;

  lp->rmtif_ipaddr.header.type      = htons (TE_LINK_SUBTLV_RMTIF_IPADDR);
  lp->rmtif_ipaddr.header.length    = htons (4);
  lp->rmtif_ipaddr.value[0].s_addr  = ifp->te_remote_id;

  return;
}

/**
 * Reading Inter domain TE-links parameters
 */
static void 
read_te_unnumbered(struct te_link *lp, struct interface *ifp)
{
  lp->link_lcl_rmt_ids.header.type   = htons (TE_LINK_SUBTLV_LINK_LCL_RMT_IDS);
  lp->link_lcl_rmt_ids.header.length = htons (8);
  lp->link_lcl_rmt_ids.local_id      = ifp->te_local_id;
  lp->link_lcl_rmt_ids.remote_id     = ifp->te_remote_id;

  struct ospf *ospf;
  switch (ifp->ospf_instance)
  {
    case INNI:
      if ((ospf = ospf_inni_get()) == NULL)
      {
        zlog_warn("[WRN] read_te_unnumbered: Can't retrive ospf INNI");
        return;
      }
      break;
    case ENNI:
      if ((ospf = ospf_enni_get()) == NULL)
      {
        zlog_warn("[WRN] read_te_unnumbered: Can't retrive ospf ENNI");
        return;
      }
      break;
    case UNI:
      if ((ospf = ospf_uni_get()) == NULL)
      {
        zlog_warn("[WRN] read_te_unnumbered: Can't retrive ospf UNI");
        return;
      }
      break;
    default:
      zlog_err("[ERR] read_te_unnumbered: Wrong OSPF instance %d", ifp->ospf_instance);
      return;
      break;
  }

  set_oif_lcl_node_id(lp, ospf->router_id);

  struct in_addr address;
  address.s_addr = htonl(ifp->te_remote_node_id);
  set_oif_rmt_node_id(lp, address);

  if (IS_DEBUG_TE(USER))
  {
    zlog_debug("[DBG]   Set te-link (int: %s) Local node id to %s", ifp->name, inet_ntoa(ospf->router_id));
    zlog_debug("[DBG]   Set te-link (int: %s) Remote node id to %s", ifp->name, inet_ntoa(address));
  }
  return;
}

static void 
read_te_local_remote_if(struct te_link *lp, struct interface *ifp)
{
  if (ifp->adj_type == INNI)
    read_te_numbered(lp, ifp);
  else
    read_te_unnumbered(lp, ifp);
  return;
}

static void
read_te_metric_from_ifp(struct te_link *lp, struct interface *ifp)
{
  lp->te_metric.header.type = htons(TE_LINK_SUBTLV_TE_METRIC );
  lp->te_metric.header.length = htons (sizeof (lp->te_metric.value)); 
  if (lp->te_metric.value != htonl(ifp->te_metric))
  {
    if (IS_DEBUG_TE(USER) || IS_DEBUG_TE(READ_IFP))
      zlog_debug("[DBG]   Set te-link (int: %s) Metric to %d (old value: %d)", ifp->name, ifp->te_metric, ntohl(lp->te_metric.value));
    lp->te_metric.value = htonl(ifp->te_metric);
  }
  return;
}

static void
read_te_link_rsc_clsclr_from_ifp(struct te_link *lp, struct interface *ifp)
{
  lp->rsc_clsclr.header.type = htons(TE_LINK_SUBTLV_RSC_CLSCLR);
  lp->rsc_clsclr.header.length = htons (sizeof (lp->rsc_clsclr.value)); 
  lp->rsc_clsclr.value = htonl(ifp->te_link_color);
  if (lp->rsc_clsclr.value != htonl(ifp->te_link_color))
  {
    if (IS_DEBUG_TE(USER) || IS_DEBUG_TE(READ_IFP))
      zlog_debug("[DBG]   Set te-link (int: %s) Color to %d (old value: %d)", ifp->name, ntohl(ifp->te_link_color), ntohl(lp->rsc_clsclr.value));
    lp->rsc_clsclr.value = htonl(ifp->te_link_color);
  }
  return;
}

static void
read_te_sw_capability_from_ifp (struct te_link *lp, struct interface *ifp)
{
  if (IS_DEBUG_TE(USER))
  {
    float *temp;
    switch(ifp->te_swcap)
    {
      case CAPABILITY_PSC1:
        temp = (float *)(&ifp->te_min_LSP_bw);
        zlog_debug("[DBG]   Set te-link (int: %s) Switching capability to PSC1 (min LSP BW: %f, encoding type: 0x%x, MTU: 0x%x)", ifp->name, *temp, ifp->te_enctype, ifp->te_swcap_options);
        break;
      case CAPABILITY_PSC2:
        temp = (float *)(&ifp->te_min_LSP_bw);
        zlog_debug("[DBG]   Set te-link (int: %s) Switching capability to PSC2 (min LSP BW: %f, encoding type: 0x%x, MTU: 0x%x)", ifp->name, *temp, ifp->te_enctype, ifp->te_swcap_options);
        break;
      case CAPABILITY_PSC3:
        temp = (float *)(&ifp->te_min_LSP_bw);
        zlog_debug("[DBG]   Set te-link (int: %s) Switching capability to PSC3 (min LSP BW: %f, encoding type: 0x%x, MTU: 0x%x)", ifp->name, *temp, ifp->te_enctype, ifp->te_swcap_options);
        break;
      case CAPABILITY_PSC4:
        temp = (float *)(&ifp->te_min_LSP_bw);
        zlog_debug("[DBG]   Set te-link (int: %s) Switching capability to PSC4 (min LSP BW: %f, encoding type: 0x%x, MTU: 0x%x)", ifp->name, *temp, ifp->te_enctype, ifp->te_swcap_options);
        break;
      case CAPABILITY_L2SC:
        temp = (float *)(&ifp->te_min_LSP_bw);
        zlog_debug("[DBG]   Set te-link (int: %s) Switching capability to L2SC (min LSP BW: %f, encoding type: 0x%x, MTU: 0x%x)", ifp->name, *temp, ifp->te_enctype, ifp->te_swcap_options);
        break;
      case CAPABILITY_TDM:
        temp = (float *)(&ifp->te_min_LSP_bw);
        zlog_debug("[DBG]   Set te-link (int: %s) Switching capability to TDM (min LSP BW: %f, encoding type: 0x%x, indication: 0x%x)", ifp->name, *temp, ifp->te_enctype, ifp->te_swcap_options);
        break;
      case CAPABILITY_LSC:
        zlog_debug("[DBG]   Set te-link (int: %s) Switching capability to LSC", ifp->name);
        break;
      case CAPABILITY_FSC:
        zlog_debug("[DBG]   Set te-link (int: %s) Switching capability to FSC", ifp->name);
        break;
      default:
        zlog_debug("[DBG]   Set te-link (int: %s) Switching capability to UNKNOWN (0x%x)",ifp->name, ifp->te_swcap);
        break;
    }

    struct zlistnode *node, *nnode;
    struct te_link_subtlv_if_sw_cap_desc* tmp;
    struct te_link_subtlv_if_sw_cap_desc* ifswcap;

    ifswcap = NULL;
    for (ALL_LIST_ELEMENTS(&lp->if_sw_cap_descs, node, nnode, tmp))
    {
      if ((tmp->switching_cap == ifp->te_swcap) && (tmp->encoding == ifp->te_enctype))
      {
        ifswcap = tmp;
        break;
      }
    }
    if (ifswcap != NULL)
    {
      float old_value;
      float new_value;
      for (int i=0; i < MAX_BW_PRIORITIES; i++)
      {
        ntohf(&ifswcap->maxLSPbw[i], &old_value);
        new_value = *((float *)(void *)(&ifp->te_max_LSP_bw[i]));
        if (old_value != new_value)
          zlog_debug("[DBG]   Set te-link (int: %s) Maximum LSP bandwidth [%d] to %f (old value: %f)",ifp->name, i, new_value, old_value);
      }
    }
    else
    {
      float new_value;
      for (int i=0; i < MAX_BW_PRIORITIES; i++)
      {
        new_value = *((float *)(void *)(&ifp->te_max_LSP_bw[i]));
        zlog_debug("[DBG]   Set te-link (int: %s) Maximum LSP bandwidth [%d] to %f",ifp->name, i, new_value);
      }
    }
  }

  create_te_link_subtlv_if_sw_cap_desc(lp, (u_char) ifp->te_swcap, (u_char) ifp->te_enctype);

  float temp;

  set_if_sw_cap_max_bands(lp, (u_char) ifp->te_swcap, (u_char) ifp->te_enctype, (float *)((void *)(ifp->te_max_LSP_bw)));

  switch(ifp->te_swcap)
  {
    case CAPABILITY_PSC1:
    case CAPABILITY_PSC2:
    case CAPABILITY_PSC3:
    case CAPABILITY_PSC4:
    case CAPABILITY_L2SC:
      htonf((float *)(void *) &ifp->te_min_LSP_bw, &temp);
      set_if_sw_cap_desc_psc(lp, (u_char) ifp->te_swcap, (u_char) ifp->te_enctype, &temp, htons(ifp->te_swcap_options));
      break;
    case CAPABILITY_TDM:
      htonf((float *)(void *) &ifp->te_min_LSP_bw, &temp);
      set_if_sw_cap_desc_tdm(lp, (u_char) ifp->te_swcap, (u_char) ifp->te_enctype, &temp, (uint8_t) ifp->te_swcap_options);
      break;
    case CAPABILITY_LSC:
    case CAPABILITY_FSC:
    default:
      break;
  }
  return;
}

static void
read_te_max_bw (struct te_link *lp, struct interface *ifp)
{
  lp->max_bw.header.type = htons(TE_LINK_SUBTLV_MAX_BW);
  lp->max_bw.header.length = htons (sizeof (lp->max_bw.value));


  if (IS_DEBUG_TE(USER))
  {
    float temp;
    ntohf((float *) &lp->max_bw.value, &temp);
    float *temp2 = (float *)(void *)(&ifp->te_max_bw);
    if (temp != *temp2)
      zlog_debug("[DBG]   Set te-link (int: %s) Maximum bandwidth to %f", ifp->name, *temp2);
  }
  htonf((float *)(void *) &ifp->te_max_bw, &lp->max_bw.value);
  return;
}

static void
read_te_link_energy_consumption (struct te_link *lp, struct interface *ifp)
{
  lp->power_consumption.header.type = htons(TE_LINK_SUBTLV_POWER_CONSUMPTION);
  lp->power_consumption.header.length = htons (sizeof (lp->max_bw.value));


  if (IS_DEBUG_TE(USER))
  {
    float temp;
    ntohf((float *) &lp->power_consumption.power_consumption, &temp);
    float *temp2 = (float *)(void *)(&ifp->te_energy_consumption);
    if (temp != *temp2)
      zlog_debug("[DBG]   Set te-link (int: %s) Energy consumption to %f", ifp->name, *temp2);
  }
  htonf((float *)(void *) &ifp->te_energy_consumption, &lp->power_consumption.power_consumption);
  return;
}

static void
read_te_link_bw_replanning (struct te_link *lp, struct interface *ifp)
{
  lp->dynamic_replanning.header.type = htons(TE_LINK_SUBTLV_DYNAMIC_REPLANNING);
  lp->dynamic_replanning.header.length = htons (sizeof (lp->dynamic_replanning.max_bandwidth_upgrade)
                                               + sizeof (lp->dynamic_replanning.max_bandwidth_downgrade));


  if (IS_DEBUG_TE(USER))
  {
    float temp;
    ntohf((float *) &lp->dynamic_replanning.max_bandwidth_upgrade, &temp);
    float *temp2 = (float *)(void *)(&ifp->te_max_bw_upgrade);
    if (temp != *temp2)
      zlog_debug("[DBG]   Set te-link (int: %s) Max bandwidth upgrade to %f", ifp->name, *temp2);

    ntohf((float *) &lp->dynamic_replanning.max_bandwidth_downgrade, &temp);
    temp2 = (float *)(void *)(&ifp->te_max_bw_downgrade);
    if (temp != *temp2)
      zlog_debug("[DBG]   Set te-link (int: %s) Max bandwidth downgrade to %f", ifp->name, *temp2);

  }
  htonf((float *)(void *) &ifp->te_max_bw_upgrade, &lp->dynamic_replanning.max_bandwidth_upgrade);
  htonf((float *)(void *) &ifp->te_max_bw_downgrade, &lp->dynamic_replanning.max_bandwidth_downgrade);
  return;
}

static void
read_te_max_rsv_bw (struct te_link *lp, struct interface *ifp)
{
  lp->max_rsv_bw.header.type = htons(TE_LINK_SUBTLV_MAX_RSV_BW);
  lp->max_rsv_bw.header.length = htons (sizeof (lp->max_rsv_bw.value));

  if (IS_DEBUG_TE(USER))
  {
    float old_value;
    float *temp2 = (float *)(void *)(&ifp->te_max_res_bw);
    ntohf((float *) &lp->max_rsv_bw.value, &old_value);
    if (old_value != *temp2)
      zlog_debug("[DBG]   Set te-link (int: %s) Maximum reservable bandwidth to %f (old value: %f)", ifp->name, *temp2, old_value);
  }
  htonf((float *)(void *) &ifp->te_max_res_bw , &lp->max_rsv_bw.value);
  return;
}

static void
read_te_avail_bw_per_prio (struct te_link *lp, struct interface *ifp)
{
  lp->unrsv_bw.header.type=htons(TE_LINK_SUBTLV_UNRSV_BW);
  lp->unrsv_bw.header.length = htons (4*MAX_BW_PRIORITIES); 
  int i; 
  for (i=0; i < MAX_BW_PRIORITIES; i++)
  {
    if (IS_DEBUG_TE(USER))
    {
      float old_value;
      ntohf((float *) &lp->unrsv_bw.value[i], &old_value);
      if (old_value != *((float *)(void *) &ifp->te_avail_bw_per_prio[i]))
        zlog_debug("[DBG]   Set te-link (int: %s) Maximum bandwidth (priority: %d) to %f (old value: %f)", ifp->name, i, *((float *)(void *) &ifp->te_avail_bw_per_prio[i]), old_value);
    }
    htonf((float *) &ifp->te_avail_bw_per_prio[i], &lp->unrsv_bw.value[i]);
  }
  return;
}

static void
read_te_srg (struct te_link *lp, struct interface *ifp)
{
  clear_shared_risk_link_grp(lp);

  struct zlistnode *node, *nnode;
  uint32_t *data;

  for(ALL_LIST_ELEMENTS(ifp->te_SRLG_ids, node, nnode, data))
  {
    add_shared_risk_link_grp(lp, *data);
    if ((IS_DEBUG_TE(USER)))
      zlog_debug("[DBG] READ_TE_SRG (%s) SRLG: 0x%x", ifp->name, *data);
  }
  return;
}

static void
read_te_tna_from_ifp(struct te_link *lp, struct interface *ifp)
{
  if (lp->ifp != ifp)
  {
    zlog_err("[ERR] READ_TE_TNA_FROM_IFP (%s): Wrong TE-link (lp->ifp %s)", ifp->name, lp->ifp->name);
  }

  if (ifp->ospf_instance != UNI)
  {
    if (IS_DEBUG_TE(READ_IFP ))
      zlog_debug("[DBG]  READ_TE_TNA_FROM_IFP (%s): OSPF instance is not UNI, reading skipped", ifp->name);
    return;
  }

  struct ospf *ospf_uni = ospf_uni_lookup();
  if (ospf_uni == NULL)
  {
    zlog_warn("[WRN] READ_TE_TNA_FROM_IFP (%s): Can't find OSPF INNI instance", ifp->name);
    return;
  }

  if (ospf_uni->interface_side != NETWORK)
  {
    if (IS_DEBUG_TE(READ_IFP ))
      zlog_debug("[DBG]  READ_TE_TNA_FROM_IFP (%s): OSPF instance is UNI, but side is not NETWORK, reading skipped", ifp->name);
    return;
  }

  struct ospf *ospf_inni = ospf_inni_lookup();
  if (ospf_inni == NULL)
  {
    zlog_warn("[WRN] READ_TE_TNA_FROM_IFP (%s): Can't find OSPF INNI instance", ifp->name);
    return;
  }

  if ((IS_DEBUG_TE(READ_IFP)) || IS_DEBUG_TE(USER))
    zlog_debug("[DBG] READ_TE_TNA_FROM_IFP (%s): Set TNA Node id to %s", ifp->name, inet_ntoa(ospf_inni->router_id));

  struct in_addr tmp_adr;
  tmp_adr.s_addr = *ifp->te_TNA_address;

  if ((ifp->te_TNA_address != NULL) && (ospf_inni->router_id.s_addr != htonl(0)))
  {
    if ((IS_DEBUG_TE(USER)) || (IS_DEBUG_TE(READ_IFP)))
      zlog_debug("[DBG] READ_TE_TNA_FROM_IFP (%s): Add new TNA Address: %s", ifp->name, inet_ntoa(tmp_adr));
    struct in_addr empty;
    empty.s_addr = 0;
    add_tna_addr (lp, ifp->te_TNA_address_type, ospf_inni->router_id, empty, ifp->te_TNA_prefix_length, ifp->te_TNA_address);
  }
  else
  {
    zlog_warn("[WRN] READ_TE_TNA_FROM_IFP (%s): Address is NULL", ifp->name);
    return;
  }

  if (lp->area)
  {
    if (lp->flags & LPFLG_LSA_TNA_ENGAGED)
    {
      ospf_te_lsa_schedule (lp, REFRESH_THIS_LSA, TNA_ADDRESS);
      if ((IS_DEBUG_TE(USER)) || (IS_DEBUG_TE(READ_IFP)))
        zlog_debug("[DBG] READ_TE_TNA_FROM_IFP (%s): lsa refresh", ifp->name);
    }
    else
      ospf_te_lsa_schedule (lp, REORIGINATE_PER_AREA, TNA_ADDRESS);
      if ((IS_DEBUG_TE(USER)) || (IS_DEBUG_TE(READ_IFP)))
        zlog_debug("[DBG] READ_TE_TNA_FROM_IFP (%s): lsa reoriginate", ifp->name);
  }
}

static void
read_bitmask_from_ifp(struct te_link *lp, struct interface *ifp)
{
  clear_all_opt_ext_av_wave_mask(lp);

  int i=0;
  for (i=0; i < ifp->lambdas_bitmap.bitmap_size; i++)
    add_all_opt_ext_av_wave_mask_bitmap(lp, ifp->lambdas_bitmap.bitmap_word[i]);

  set_all_opt_ext_av_wave_mask (lp, ifp->lambdas_bitmap.num_wavelengths, ifp->lambdas_bitmap.base_lambda_label);
  if ((IS_DEBUG_TE(USER)) || (IS_DEBUG_TE(READ_IFP)))
  {
     char buf[300];
     char bitmap[200];
     for (int i=0; i<= ifp->lambdas_bitmap.bitmap_size; i++)
       sprintf(bitmap+i*8 , "%x", ifp->lambdas_bitmap.bitmap_word[i]);
     sprintf(buf, "base lambda label: 0x%x, num of wavelengths: %d, bitmap: 0x%s", ifp->lambdas_bitmap.base_lambda_label, ifp->lambdas_bitmap.num_wavelengths, bitmap);

     zlog_debug("[DBG]   Set te-link (int: %s) Bitmask (%s)", ifp->name, buf);
  }
  return;
}

static int
read_te_link_id(struct te_link *lp, struct interface *ifp)
{
  int result = 0;
  lp->link_id.header.type   = htons (TE_LINK_SUBTLV_LINK_ID);
  lp->link_id.header.length = htons (sizeof (lp->link_id.value));

  if (ifp->adj_type == ENNI)
  {
    if (lp->link_id.value.s_addr != ifp->rem_rc_id)
    {
      if (IS_DEBUG_TE(USER) || IS_DEBUG_TE(READ_IFP))
      {
        char buf[20];
        sprintf(buf, "%s", inet_ntoa(lp->link_id.value));
        struct in_addr tmp;
        tmp.s_addr = ifp->rem_rc_id;
        zlog_debug("[DBG]   Set te-link (int: %s) Id to %s (old value: %s)", ifp->name, inet_ntoa(tmp), buf);
      }
      lp->link_id.value.s_addr = ifp->rem_rc_id;
      result = 1;
    }
  }
  else
  {
    if (lp->link_id.value.s_addr != htonl(ifp->te_remote_node_id))
    {
      if (IS_DEBUG_TE(USER))
      {
        char buf[20];
        sprintf(buf, "%s", inet_ntoa(lp->link_id.value));
        struct in_addr tmp;
        tmp.s_addr = htonl(ifp->te_remote_node_id);
        zlog_debug("[DBG]   Set te-link (int: %s) Id to %s (old value: %s)", ifp->name, inet_ntoa(tmp), buf);
      }
      lp->link_id.value.s_addr = htonl(ifp->te_remote_node_id);
      result = 1;
    }
  }
  return result;
}

static int
read_te_link_protection(struct te_link *lp, struct interface *ifp)
{
  int result = 0;
  lp->link_protect_type.header.type   = htons (TE_LINK_SUBTLV_LINK_PROTECT_TYPE);
  lp->link_protect_type.header.length = htons (4);

  if (lp->link_protect_type.value != (char) ifp->te_protection_type)
  {
    if (IS_DEBUG_TE(USER) || IS_DEBUG_TE(READ_IFP))
    {
      zlog_debug("[DBG]   Set te-link (int: %s) Protection type to %d (old value: %d)", ifp->name, (char) ifp->te_protection_type, lp->link_protect_type.value);
    }
    lp->link_protect_type.value = (char) ifp->te_protection_type;
    result = 1;
  }
  return result;
}

/** 
 * this function is a callbacshow ip ospf database called from zclient (the library one) all the te params have been 
 * received from lrmd
 */
int read_te_params_from_ifp(struct interface *ifp)
{
  struct te_link *lp = NULL;
  if(ifp)
  {
    if (strcmp(ifp->name, "Level1") == 0)
    {
      /*FIXME Adam: WE don't want to read and create te-link for Level1 interface */ 
      return 1;
    }
    if (IS_DEBUG_TE(USER))
      zlog_debug("[DBG] Reading te-link parameters from interface %s (ospf: %s, adj_type: %s)", ifp->name, OSPF_INST_TO_STR(ifp->ospf_instance), OSPF_INST_TO_STR(ifp->adj_type));
    lp = lookup_linkparams_by_ifp(ifp);
    if (lp)
    {
      read_te_link_id(lp, ifp);
      read_te_local_remote_if(lp, ifp);
      read_te_metric_from_ifp (lp, ifp);
      read_te_link_rsc_clsclr_from_ifp (lp, ifp);
      read_te_avail_bw_per_prio(lp, ifp);

      if(ifp->te_SRLG_ids)
      {
        read_te_srg (lp, ifp);
      }

      if (ifp->te_swcap == SWCAP_LSC)
      {
        read_bitmask_from_ifp(lp, ifp);
      }

      if (ifp->ospf_instance == UNI)
      {
        read_te_tna_from_ifp(lp, ifp);
      }

      read_te_sw_capability_from_ifp (lp, ifp);
      read_te_max_bw(lp, ifp);
      read_te_max_rsv_bw(lp, ifp);
      read_te_link_protection(lp, ifp);

      read_te_link_energy_consumption(lp, ifp);
      read_te_link_bw_replanning(lp, ifp);

      if (lp->area)
      {
        if (lp->flags & LPFLG_LSA_LI_ENGAGED)
        {
          ospf_te_lsa_schedule (lp, REFRESH_THIS_LSA, LINK);
          if (IS_DEBUG_TE(USER) || IS_DEBUG_TE(READ_IFP))
            zlog_debug("[DBG] read_te_params_from_ifp: REFRESH LINK LSA");
        }
        else
        {
          ospf_te_lsa_schedule (lp, REORIGINATE_PER_AREA, LINK);
          if (IS_DEBUG_TE(USER) || IS_DEBUG_TE(READ_IFP))
            zlog_debug("[DBG] read_te_params_from_ifp: REORIGINATE LINK LSA");
        }
      }
    }
    else{
      zlog_warn("[WRN] read_te_params_from_ifp: Could not find te-link associated with interface %s", ifp->name);
      return 0;
    }
  }
  else{
    zlog_err("[ERR] read_te_params_from_ifp: ifp = NULL"); //should not happen
    return 0;
  }

  struct ospf *ospf = NULL;
  if (ifp->ospf_instance == INNI)
    ospf = ospf_inni_get();
  if (ifp->ospf_instance == ENNI)
    ospf = ospf_enni_get();
  if (ifp->ospf_instance == UNI)
    ospf = ospf_uni_get();

  if (ospf != NULL)
  {
    if (!CHECK_FLAG (ospf->config, OSPF_OPAQUE_CAPABLE))
    {
      SET_FLAG (ospf->config, OSPF_OPAQUE_CAPABLE);
      ospf_renegotiate_optional_capabilities (ospf);
    }
  }

  return 1;
}

void
router_id_update_te(adj_type_t adj, uint32_t energyConsumption)
{
  int updated_ra = 0;
  struct ospf *ospf;
  uint32_t powCons = energyConsumption;

  switch(adj)
  {
    case INNI:
      ospf = ospf_inni_lookup();
      if (OspfTE.router_addr[(uint16_t)adj].router_addr.value.s_addr == htonl(0))
      {
        set_te_router_addr(ospf->router_id, adj);
        //zlog_debug("Router_id update with power consumption 0x%x", powCons);
        set_router_power_consumption(&powCons, adj);
        updated_ra = 1;
      }
      break;
    case ENNI:
      ospf = ospf_enni_lookup();
      if (OspfTE.router_addr[(uint16_t)adj].router_addr.value.s_addr == htonl(0))
      {
        set_te_router_addr(ospf->router_id, adj);
        set_router_power_consumption(&powCons, adj);
        updated_ra = 1;
      }
      break;
    case UNI:
      ospf = ospf_uni_lookup();
      if (OspfTE.router_addr[(uint16_t)adj].router_addr.value.s_addr == htonl(0))
      {
        set_te_router_addr(ospf->router_id, adj);
        set_router_power_consumption(&powCons, adj);
        updated_ra = 1;
      }
      break;
    default:
      ospf = NULL;
      break;
  }

  if (ospf == NULL)
  {
    zlog_warn("[WRN] router_id_update: Can't find OSPF INNI");
    return;
  }
  struct zlistnode *node, *nnode;
  struct te_link *lp;

  if (adj == INNI)
  {
    for (ALL_LIST_ELEMENTS(OspfTE.iflist, node, nnode, lp))
    {
      if ((lp->ifp->adj_type == ENNI) && (lp->ifp->ospf_instance == INNI))
      {
        set_oif_lcl_node_id(lp, ospf->router_id);
        if (lp->area)
        {
          if (lp->flags & LPFLG_LSA_LI_ENGAGED)
          {
            ospf_te_lsa_schedule (lp, REFRESH_THIS_LSA, LINK);
            if (IS_DEBUG_TE(USER))
              zlog_debug("[DBG] Assign to te-link (int: %s) new Id %s and schedule REFRESH", lp->ifp->name, inet_ntoa(ospf->router_id));
          }
          else
          {
            ospf_te_lsa_schedule (lp, REORIGINATE_PER_AREA, LINK);
            if (IS_DEBUG_TE(USER))
              zlog_debug("[DBG] Assign to te-link (int: %s) new Id %s and schedule REORIGINATE", lp->ifp->name, inet_ntoa(ospf->router_id));
          }
        }
      }
      if (lp->ifp->adj_type == UNI)
      {
        if (IS_DEBUG_TE(READ_IFP))
          zlog_debug("[DBG] router_id_update_te: Setting TNA");

        struct in_addr empty;
        empty.s_addr = 0;
        add_tna_addr (lp, lp->ifp->te_TNA_address_type, ospf->router_id, empty, lp->ifp->te_TNA_prefix_length, lp->ifp->te_TNA_address);

        if (lp->area)
        {
          if (lp->flags & LPFLG_LSA_TNA_ENGAGED)
            ospf_te_lsa_schedule (lp, REFRESH_THIS_LSA, TNA_ADDRESS);
          else
            ospf_te_lsa_schedule (lp, REORIGINATE_PER_AREA, TNA_ADDRESS);
        }
      }
    }
    for (ALL_LIST_ELEMENTS(OspfTE.harmonyIflist, node, nnode, lp))
    {
      if (lp->ifp == NULL)
      {
        zlog_warn("[WRN] router_id_update: Harmony te-link has no own interface");
        continue;
      }
      if ((lp->ifp->adj_type == ENNI) && (lp->ifp->ospf_instance == INNI))
      {
        set_oif_lcl_node_id(lp, ospf->router_id);
        if (lp->area)
        {
          if (lp->flags & LPFLG_LSA_LI_ENGAGED)
          {
            ospf_te_lsa_schedule (lp, REFRESH_THIS_LSA, LINK);
            if (IS_DEBUG_TE(USER))
              zlog_debug("[DBG] Assign to te-link (int: %s) new Id %s and schedule REFRESH", lp->ifp->name, inet_ntoa(ospf->router_id));
          }
          else
          {
            ospf_te_lsa_schedule (lp, REORIGINATE_PER_AREA, LINK);
            if (IS_DEBUG_TE(USER))
              zlog_debug("[DBG] Assign to te-link (int: %s) new Id %s and schedule REORIGINATE", lp->ifp->name, inet_ntoa(ospf->router_id));
          }
        }
      }
      if ((lp->ifp->adj_type == UNI) && (lp->area))
      {
        if (IS_DEBUG_TE(READ_IFP))
          zlog_debug("[DBG] router_id_update_te: Setting TNA");

        struct in_addr empty;
        empty.s_addr = 0;
        add_tna_addr (lp, lp->ifp->te_TNA_address_type, ospf->router_id, empty, lp->ifp->te_TNA_prefix_length, lp->ifp->te_TNA_address);

        if (lp->flags & LPFLG_LSA_TNA_ENGAGED)
          ospf_te_lsa_schedule (lp, REFRESH_THIS_LSA, TNA_ADDRESS);
        else
          ospf_te_lsa_schedule (lp, REORIGINATE_PER_AREA, TNA_ADDRESS);
      }
    }
  }

  struct ospf_area *area;
  if (updated_ra == 1)
  {
    for (ALL_LIST_ELEMENTS_RO(ospf->areas, node, area))
    {
      if (OspfTE.ra_engaged[(int)ospf->instance] == 1)
      {
        OspfTE.ra_force_refreshed[(int)ospf->instance] = 1;
        ospf_te_ra_lsa_schedule (REFRESH_THIS_LSA, ospf, area);
      }
      else
       ospf_te_ra_lsa_schedule (REORIGINATE_PER_AREA, ospf, area);
    }
  }
}

#endif /* GMPLS */

static int
is_mandated_params_set (struct te_link *lp)
{
  int rc = 1;
  if ((uint16_t)lp->ifp->ospf_instance > 2)
  {
    zlog_err("[ERR] is_mandated_params_set: Unknown interface_type: %d", (uint16_t)lp->ifp->ospf_instance);
    return 0;
  }

  if (ntohs (OspfTE.router_addr[(uint16_t)lp->ifp->ospf_instance].router_addr.header.type) == 0)
  {
    if (IS_DEBUG_TE(ORIGINATE))
      zlog_debug("[DBG] is_mandated_params_set: router_addr.header.type = 0");
    rc = 0;
  }

  if (ntohs (lp->link_type.header.type) == 0)
  {
    if (IS_DEBUG_TE(ORIGINATE))
      zlog_debug("[DBG] is_mandated_params_set: lp->link_type.header.type = 0");
    rc = 0;
  }

  if (ntohs (lp->link_id.header.type) == 0)
  {
    if (IS_DEBUG_TE(ORIGINATE))
      zlog_debug("[DBG] is_mandated_params_set: lp->link_id.header.type = 0");
    rc = 0;
  }
  return rc;
}

static int
is_mandated_params_set_ra (uint16_t instance_no)
{
  int rc = 1;
  if (instance_no > 2)
  {
    zlog_err("[ERR] is_mandated_params_set_ra: te_link: interface_type > 2");
    return 0;
  }

  if ((ntohs (OspfTE.router_addr[instance_no].router_addr.header.type) == 0) && (ntohs (OspfTE.router_addr[instance_no].router_addr.header.length) == 0))
  {
    if (IS_DEBUG_TE(ORIGINATE))
      zlog_debug("[DBG] is_mandated_params_set_ra: Router address header: length = %d, type = %d", ntohs(OspfTE.router_addr[instance_no].router_addr.header.type), ntohs (OspfTE.router_addr[instance_no].router_addr.header.length));
    rc = 0;
  }
  return rc;
}

static int
is_mandated_params_set_na (uint16_t instance_no)
{
  int rc = 1;
  if (instance_no > 2)
  {
    zlog_err("[ERR] is_mandated_params_set_na: Wrong OSPF instance: %d", instance_no);
    return 0;
  }
  if (ntohs (OspfTE.node_attr[instance_no].link_header.header.length) == 0)
  {
    if (IS_DEBUG_TE(ORIGINATE))
      zlog_debug("[DBG] is_mandated_params_set_na: OSPF %s header length = %d", OSPF_INST_TO_STR(instance_no),  ntohs(OspfTE.node_attr[instance_no].link_header.header.length));
    rc = 0;
  }
  return rc;
}

/** *** Update PCE & UNIGW TE information *** */

#define UPDATE_G2PCERA      1
#define UPDATE_GUNIGW       2

#define REMOVE_FROM_SERVER  0
#define ADD_TO_SERVER       1

/** *** TNA Adresses related updates *** */

#if USE_UNTESTED_OSPF_TE_CORBA_UPDATE
static u_int16_t
update_corba_info_tna_addr_ipv4 (struct te_tlv_header *tlvh)
{
  struct te_tna_addr_subtlv_tna_addr_ipv4 *top;
  top = (struct te_tna_addr_subtlv_tna_addr_ipv4 *) tlvh;
  g2mpls_addr_t tnaAddr;
  tnaAddr.type = IPv4;
  tnaAddr.value.ipv4 = top->value;
  tnaAddr.preflen = top->addr_length;
  corba_update_te_tna_addr(tnaAddr);
  return TLV_SIZE (tlvh);
}

static u_int16_t
update_corba_info_tna_addr_ipv6 (struct te_tlv_header *tlvh)
{
  struct te_tna_addr_subtlv_tna_addr_ipv6 *top;
  top = (struct te_tna_addr_subtlv_tna_addr_ipv6 *) tlvh;
  g2mpls_addr_t tnaAddr;
  tnaAddr.type = IPv6;
  tnaAddr.value.ipv6 = top->value;
  tnaAddr.preflen = top->addr_length;
  corba_update_te_tna_addr(tnaAddr);
  return TLV_SIZE (tlvh);
}

static u_int16_t
update_corba_info_tna_addr_nsap (struct te_tlv_header *tlvh)
{
  struct te_tna_addr_subtlv_tna_addr_nsap *top;
  top = (struct te_tna_addr_subtlv_tna_addr_nsap *) tlvh;
  g2mpls_addr_t tnaAddr;
  tnaAddr.type = NSAP;
  for (int i=0; i <5; i++)
    tnaAddr.value.nsap.nsap_addr32[i] = (u_int32_t) top->value[i];
  tnaAddr.preflen = top->addr_length;
  corba_update_te_tna_addr(tnaAddr);
  return TLV_SIZE (tlvh);
}

static u_int16_t
update_corba_info_node_id (struct te_tlv_header *tlvh)
{
  struct te_tna_addr_subtlv_node_id *top;
  top = (struct te_tna_addr_subtlv_node_id *) tlvh;
  corba_update_te_tna_node(top->value);
  return TLV_SIZE (tlvh);
}

static u_int16_t
update_corba_info_anc_rc_id (struct te_tlv_header *tlvh)
{
  struct te_tna_addr_subtlv_anc_rc_id *top;
  top = (struct te_tna_addr_subtlv_anc_rc_id *) tlvh;
  corba_update_te_tna_anc_rc_id(top->value);
  return TLV_SIZE (tlvh);
}

/* === Link Information related Corba updates: update_corba_link_xxx    ======= */

#define REC_LINK_TYPE             0x00000001
#define REC_LINK_ID               0x00000002
#define REC_LCLIF_IPADDR          0x00000004
#define REC_RMTIF_IPADDR          0x00000008
#define REC_TE_METRIC             0x00000010
#define REC_MAX_BW                0x00000020
#define REC_MAX_RSV_BW            0x00000040
#define REC_UNRSV_BW              0x00000080
#define REC_RSC_CLSCLR            0x00000100
#define REC_LINK_LCL_RMT_IDS      0x00000200
#define REC_LINK_PROTECT_TYPE     0x00000400
#define REC_IF_SW_CAP_DESC        0x00000800
#define REC_SHARED_RISK_LINK_GRP  0x00001000
#define REC_LCL_RMT_TE_ROUTER_ID  0x00002000
#define REC_LCL_NODE_ID           0x00004000
#define REC_RMT_NODE_ID           0x00008000
#define REC_SSDH_IF_SW_CAP_DESC   0x00010000
#define REC_GENERAL_CAP           0x00020000
#define REC_HIERARCHY_LIST        0x00040000
#define REC_ANC_RC_ID             0x00080000
#define REC_BAND_ACCOUNT          0x00100000
#define REC_OSPF_DOWN_AA_ID       0x00200000
#define REC_AA_ID                 0x00400000
#define REC_BER_ESTIMATE          0x00800000
#define REC_SPAN_LENGTH           0x01000000
#define REC_OSNR                  0x02000000
#define REC_D_PDM                 0x04000000
#define REC_AMP_LIST              0x08000000
#define REC_AV_WAVE_MASK          0x10000000
#define REC_TE_LINK_CALENDAR      0x20000000
#define REC_POWER_CONSUMPTION     0x40000000
#define REC_DYNAMIC_REPLANNING    0x80000000

uint32_t mask;

static u_int16_t
update_corba_link_type (struct te_tlv_header *tlvh)
{
  struct te_link_subtlv_link_type *top = (struct te_link_subtlv_link_type *) tlvh;
  corba_update_te_link_type(top->link_type.value);
  mask |= REC_LINK_TYPE;
  return TLV_SIZE (tlvh);
}

static u_int16_t
update_corba_link_id (struct te_tlv_header *tlvh)
{
  struct te_link_subtlv_link_id *top = (struct te_link_subtlv_link_id *) tlvh;
  corba_update_te_link_id(top->value);
  mask |= REC_LINK_ID;
  return TLV_SIZE (tlvh);
}

static u_int16_t
update_corba_link_lclif_ipaddr (struct te_tlv_header *tlvh)
{
  struct te_link_subtlv_lclif_ipaddr *top = (struct te_link_subtlv_lclif_ipaddr *) tlvh;
  corba_update_te_link_lclif_ipaddr(top->value[0]);
  mask |= REC_LCLIF_IPADDR;
  return TLV_SIZE (tlvh);
}

static u_int16_t
update_corba_link_rmtif_ipaddr (struct te_tlv_header *tlvh)
{
  struct te_link_subtlv_rmtif_ipaddr *top = (struct te_link_subtlv_rmtif_ipaddr *) tlvh;
  corba_update_te_link_rmtif_ipaddr(top->value[0]);
  mask |= REC_RMTIF_IPADDR;
  return TLV_SIZE (tlvh);
}

static u_int16_t
update_corba_link_metric (struct te_tlv_header *tlvh)
{
  struct te_link_subtlv_te_metric *top = (struct te_link_subtlv_te_metric *) tlvh;
  corba_update_te_link_metric((u_int32_t) ntohl (top->value));
  mask |= REC_TE_METRIC;
  return TLV_SIZE (tlvh);
}

static u_int16_t
update_corba_link_max_bw (struct te_tlv_header *tlvh)
{
  struct te_link_subtlv_max_bw *top = (struct te_link_subtlv_max_bw *) tlvh;
  float fval;
  ntohf (&top->value, &fval);
  corba_update_te_link_max_bw(fval);
  mask |= REC_MAX_BW;
  return TLV_SIZE (tlvh);
}

static u_int16_t
update_corba_link_max_rsv_bw (struct te_tlv_header *tlvh)
{
  struct te_link_subtlv_max_rsv_bw *top;
  float fval;
  top = (struct te_link_subtlv_max_rsv_bw *) tlvh;
  ntohf (&top->value, &fval);
  corba_update_te_link_max_res_bw(fval);
  mask |= REC_MAX_RSV_BW;
  return TLV_SIZE (tlvh);
}

static u_int16_t
update_corba_link_unrsv_bw (struct te_tlv_header *tlvh)
{
  struct te_link_subtlv_unrsv_bw *top;
  float fval;
  float avBand[8];
  top = (struct te_link_subtlv_unrsv_bw *) tlvh;
  for (int i = 0; i < 8; i++)
  {
    ntohf (&top->value[i], &fval);
    avBand[i] = fval;
  }
  corba_update_te_link_unrsv_bw(avBand);
  mask |= REC_UNRSV_BW;
  return TLV_SIZE (tlvh);
}

static u_int16_t
update_corba_link_rsc_clsclr (struct te_tlv_header *tlvh)
{
  struct te_link_subtlv_rsc_clsclr *top;
  top = (struct te_link_subtlv_rsc_clsclr *) tlvh;
  corba_update_te_link_rsc_clsclr((u_int32_t) ntohl (top->value));
  mask |= REC_RSC_CLSCLR;
  return TLV_SIZE (tlvh);
}

static u_int16_t
update_corba_link_lcl_rmt_ids (struct te_tlv_header *tlvh)
{
  struct te_link_subtlv_link_lcl_rmt_ids *top;
  top = (struct te_link_subtlv_link_lcl_rmt_ids *) tlvh;
  corba_update_te_link_lcl_rmt_ids (top->local_id, top->remote_id);
  mask |= REC_LINK_LCL_RMT_IDS;
  return TLV_SIZE (tlvh);
}

static u_int16_t
update_corba_link_protect_type (struct te_tlv_header *tlvh)
{
  struct te_link_subtlv_link_protect_type *top;
  top = (struct te_link_subtlv_link_protect_type *) tlvh;
  corba_update_te_link_protect_type((uint8_t)top->value);
  mask |= REC_LINK_PROTECT_TYPE;
  return TLV_SIZE (tlvh);
}

static u_int16_t
update_corba_link_if_sw_cap_desc (struct te_tlv_header *tlvh)
{
  struct te_link_subtlv_if_sw_cap_desc *top = (struct te_link_subtlv_if_sw_cap_desc *) tlvh;
  float maxLSPbw[8]; uint8_t switching_cap; uint8_t encoding;
  float minLSPbw; uint32_t mtu; uint8_t indication;
  float temp;

  switching_cap = (uint8_t)top->switching_cap;
  encoding = (uint8_t)top->encoding;
  for(int i=0; i<8; i++){
    ntohf(&top->maxLSPbw[i], &temp);
    maxLSPbw[i] = temp;
  }

  switch (top->switching_cap)
  {
    case CAPABILITY_PSC1:
    case CAPABILITY_PSC2:
    case CAPABILITY_PSC3:
    case CAPABILITY_PSC4:
      ntohf(&top->swcap_specific_info.swcap_specific_psc.min_lsp_bw, &minLSPbw);
      mtu = (uint32_t)ntohs(top->swcap_specific_info.swcap_specific_psc.mtu);
      corba_update_te_link_if_sw_cap_desc_pscisc(switching_cap, encoding, maxLSPbw, minLSPbw, mtu);
      break;
    case CAPABILITY_TDM:
      ntohf(&top->swcap_specific_info.swcap_specific_tdm.min_lsp_bw, &minLSPbw);
      indication = (uint8_t)(top->swcap_specific_info.swcap_specific_tdm.indication);
      corba_update_te_link_if_sw_cap_desc_tdmisc(switching_cap, encoding, maxLSPbw, minLSPbw, indication);
      break;
    case CAPABILITY_L2SC:
    case CAPABILITY_LSC:
    case CAPABILITY_FSC:
      corba_update_te_link_if_sw_cap_desc_genisc(switching_cap, encoding, maxLSPbw);
      break;
  }
  mask |= REC_IF_SW_CAP_DESC;
  return TLV_SIZE (tlvh);
}

static u_int16_t
update_corba_link_shared_risk_link_grp (struct te_tlv_header *tlvh)
{
  struct te_link_subtlv_shared_risk_link_grp *top = (struct te_link_subtlv_shared_risk_link_grp *) tlvh;

  u_int16_t len= (u_int16_t) (TLV_BODY_SIZE(tlvh) / 4);
  uint32_t *srlg = XMALLOC(0, 4*len);

  uint32_t *value = (uint32_t *)((char *)(top) + TLV_HDR_SIZE);
  for (int i=0; i < len; i++)
    srlg[i]=ntohl(value[i]);

  corba_update_te_link_shared_risk_link_grp(srlg, len);
  XFREE(0, srlg);
  mask |= REC_SHARED_RISK_LINK_GRP;
  return TLV_SIZE (tlvh);
}

static u_int16_t
update_corba_link_lcl_node_id (struct te_tlv_header *tlvh)
{
  struct te_link_subtlv_lcl_node_id *top = (struct te_link_subtlv_lcl_node_id *) tlvh;
  corba_update_te_link_lcl_node_id (top->value);
  mask |= REC_LCL_NODE_ID;
  return TLV_SIZE (tlvh);
}

static u_int16_t
update_corba_link_rmt_node_id (struct te_tlv_header *tlvh)
{
  struct te_link_subtlv_rmt_node_id *top = (struct te_link_subtlv_rmt_node_id *) tlvh;
  corba_update_te_link_rmt_node_id (top->value);
  mask |= REC_RMT_NODE_ID;
  return TLV_SIZE (tlvh);
}

static u_int16_t
update_corba_link_ssdh_if_sw_cap_desc (struct te_tlv_header *tlvh)
{
  struct te_link_subtlv_ssdh_if_sw_cap_desc *top = (struct te_link_subtlv_ssdh_if_sw_cap_desc *) tlvh;

  uint32_t signal_list_len = (uint32_t)((TLV_BODY_SIZE(tlvh) - 4) / 4);
  uint32_t *list_ptr = (uint32_t *)(&top->signals_list);

  struct zlist freeTS;
  memset (&freeTS, 0, sizeof (struct zlist));

  uint32_t value;
  struct signal_unalloc_tslots* temp;
  for (uint32_t i=0; i < signal_list_len; i++) {
    temp = XMALLOC(0, sizeof (struct signal_unalloc_tslots));
    value = *list_ptr;
    temp->signal_type =        value        & 0xff;
    temp->unalloc_tslots[0] = (value >>  8) & 0xff;
    temp->unalloc_tslots[1] = (value >> 16) & 0xff;
    temp->unalloc_tslots[2] = (value >> 24) & 0xff;
    listnode_add(&freeTS, temp);
    list_ptr++;
  }

  corba_update_te_link_ssdh_if_sw_cap_desc(&freeTS);

  mask |= REC_SSDH_IF_SW_CAP_DESC;
  return TLV_SIZE (tlvh);
}

static u_int16_t
update_corba_link_anc_rc_id (struct te_tlv_header *tlvh)
{
  struct te_link_subtlv_anc_rc_id *top = (struct te_link_subtlv_anc_rc_id *) tlvh;
  corba_update_te_link_anc_rc_id(top->value);
  mask |= REC_ANC_RC_ID;
  return TLV_SIZE (tlvh);
}

static u_int16_t
update_corba_link_band_account (struct te_tlv_header *tlvh)
{
  struct te_link_subtlv_band_account *top = (struct te_link_subtlv_band_account *) tlvh;
  uint16_t len   = (uint16_t) (TLV_BODY_SIZE(tlvh) / 4);
  uint32_t *tab  = XMALLOC(0, 4*len);
  uint32_t *temp = (uint32_t *) &top->signals_list;
  for (uint16_t i=0; i < len; i++)
    tab[i] = ntohl(temp[i]);

  corba_update_te_link_band_account(tab, len);
  XFREE(0, tab);
  mask |= REC_BAND_ACCOUNT;
  return TLV_SIZE (tlvh);
}

static u_int16_t
update_corba_link_span_length (struct te_tlv_header *tlvh)
{
  struct te_link_subtlv_span_length *top = (struct te_link_subtlv_span_length *) tlvh;
  corba_update_te_link_span_length((u_int32_t) ntohl (top->value));
  mask |= REC_SPAN_LENGTH;
  return TLV_SIZE (tlvh);
}

static u_int16_t
update_corba_link_d_pdm (struct te_tlv_header *tlvh)
{
  struct te_link_subtlv_d_pdm *top = (struct te_link_subtlv_d_pdm *) tlvh;
  float fval;
  ntohf (&top->value, &fval);
  corba_update_te_link_d_pdm((int)fval);
  mask |= REC_D_PDM;
  return TLV_SIZE (tlvh);
}

static u_int16_t
update_corba_link_amp_list (struct te_tlv_header *tlvh)
{
  u_int16_t len= (u_int16_t) (TLV_BODY_SIZE(tlvh) / 8);
  corba_update_te_link_amp_list((struct amp_par *)(tlvh+1), len);
  mask |= REC_AMP_LIST;
  return TLV_SIZE (tlvh);
}

static u_int16_t
update_corba_link_av_wave_mask (struct te_tlv_header *tlvh)
{
  struct te_link_subtlv_av_wave_mask *top = (struct te_link_subtlv_av_wave_mask *) tlvh;

  u_int16_t bitmap_len= (u_int16_t) ((TLV_BODY_SIZE(tlvh)-8)/4);

  u_int16_t num_wavelengths = ntohs(top->num_wavelengths);
  u_int32_t label_set_desc  = ntohl(top->label_set_desc);

  uint32_t *temp   = (uint32_t *) &top->bitmap_list;
  uint32_t *bitmap = XMALLOC(0, 4*bitmap_len);

  for (uint16_t i=0; i < bitmap_len; i++)
    bitmap[i] = ntohl(*(temp++));

  corba_update_te_link_av_wave_mask(num_wavelengths, label_set_desc, bitmap, bitmap_len);
  XFREE(0, bitmap);
  mask |= REC_AV_WAVE_MASK;
  return TLV_SIZE (tlvh);
}

static u_int16_t
update_corba_link_calendar (struct te_tlv_header *tlvh)
{
  u_int16_t calendar_len= (u_int16_t) (TLV_BODY_SIZE(tlvh) / 36);

  struct te_link_calendar* calendar = XMALLOC (0, calendar_len * sizeof(struct te_link_calendar));

  struct te_link_calendar *ln = (struct te_link_calendar *)((struct te_tlv_header *) (tlvh+1));
  float fval;

  for (int i=0; i<calendar_len; i++)
  {
    calendar[i].time = (u_int32_t) ntohl (ln->time);
    for (int j=0; j<8; j++)
    {
      ntohf (&ln->value[j], &fval);
      calendar[i].value[j] = fval;
    }
    ln++;
  }
  corba_update_te_link_callendar(calendar, calendar_len);
  XFREE(0, calendar);
  mask |= REC_TE_LINK_CALENDAR;
  return TLV_SIZE (tlvh);
}

static u_int16_t
update_corba_link_power_consumption (struct te_tlv_header *tlvh)
{

  struct te_link_subtlv_power_consumption *top = (struct te_link_subtlv_power_consumption *) tlvh;
  float fval;
  ntohf (&top->power_consumption, &fval);
  //zlog_debug("[DBG] updating corba with link power consumption %g", fval);
  corba_update_te_link_energy_consumption(fval);
  mask |= REC_POWER_CONSUMPTION;
  return TLV_SIZE (tlvh);
}

static u_int16_t
update_corba_link_dynamic_replanning (struct te_tlv_header *tlvh)
{
  struct te_link_subtlv_dynanic_replanning *top = (struct te_link_subtlv_dynanic_replanning *) tlvh;
  float fval_upgrade;
  ntohf (&top->max_bandwidth_upgrade, &fval_upgrade);
  float fval_downgrade;
  ntohf (&top->max_bandwidth_downgrade, &fval_downgrade);
  corba_update_te_link_bwReplanning(fval_upgrade, fval_downgrade);
  mask |= REC_DYNAMIC_REPLANNING;
  return TLV_SIZE (tlvh);
}

/* === Update CORBA Router Address: update_corba_ra_xxx ===================================================== */

static u_int16_t
update_corba_ra_addr (struct te_tlv_header *tlvh)
{
  struct te_router_addr_subtlv_router_addr *top = (struct te_router_addr_subtlv_router_addr *) tlvh;
  corba_update_te_ra_router_addr(top->value);
  return TLV_SIZE (tlvh);
}

static u_int16_t
update_corba_ra_energyConsumption (struct te_tlv_header *tlvh)
{
  struct te_router_addr_subtlv_power_consumption *top = (struct te_router_addr_subtlv_power_consumption *) tlvh;
  float fval;
  ntohf (&top->power_consumption, &fval);
  corba_update_te_ra_router_energy_consumption(fval);
  //zlog_debug("[DBG] Corba update router power consumption %.3f", fval);
  return TLV_SIZE (tlvh);
}

static u_int16_t
update_corba_info_tlv (struct te_tlv_header *tlvh)
{
  return TLV_SIZE (tlvh);
}

/* ========================================================================================================== */

static u_int16_t
update_corba_link (uint8_t option, struct te_tlv_header *tlvh0, u_int16_t subtotal, u_int16_t total)
{
  struct te_tlv_header *tlvh, *next;
  u_int16_t sum = subtotal;

  mask = 0;
  init_link_tmp_values();
  init_grid_TELink_Iscs();
  for (tlvh = tlvh0; sum < total; tlvh = (next ? next : TLV_HDR_NEXT (tlvh)))
  {
    next = NULL;
    switch (ntohs (tlvh->type))
    {
      case TE_LINK_SUBTLV_LINK_TYPE:
        sum += update_corba_link_type (tlvh);
        break;
      case TE_LINK_SUBTLV_LINK_ID:
        sum += update_corba_link_id (tlvh);
        break;
      case TE_LINK_SUBTLV_LCLIF_IPADDR:
        sum += update_corba_link_lclif_ipaddr (tlvh);
        break;
      case TE_LINK_SUBTLV_RMTIF_IPADDR:
        sum += update_corba_link_rmtif_ipaddr (tlvh);
        break;
      case TE_LINK_SUBTLV_TE_METRIC:
        sum += update_corba_link_metric (tlvh);
        break;
      case TE_LINK_SUBTLV_MAX_BW:
        sum += update_corba_link_max_bw (tlvh);
        break;
      case TE_LINK_SUBTLV_MAX_RSV_BW:
        sum += update_corba_link_max_rsv_bw (tlvh);
        break;
      case TE_LINK_SUBTLV_UNRSV_BW:
        sum += update_corba_link_unrsv_bw (tlvh);
        break;
      case TE_LINK_SUBTLV_RSC_CLSCLR:
        sum += update_corba_link_rsc_clsclr (tlvh);
        break;
      case TE_LINK_SUBTLV_LINK_LCL_RMT_IDS:
        sum += update_corba_link_lcl_rmt_ids (tlvh);
        break;
      case TE_LINK_SUBTLV_LINK_PROTECT_TYPE:
        sum += update_corba_link_protect_type (tlvh);
        break;
      case TE_LINK_SUBTLV_IF_SW_CAP_DESC:
        sum += update_corba_link_if_sw_cap_desc (tlvh);
        break;
      case TE_LINK_SUBTLV_SHARED_RISK_LINK_GRP:
        sum += update_corba_link_shared_risk_link_grp (tlvh);
        break;
      case TE_LINK_SUBTLV_LCL_NODE_ID:
        sum += update_corba_link_lcl_node_id (tlvh);
        break;
      case TE_LINK_SUBTLV_RMT_NODE_ID:
        sum += update_corba_link_rmt_node_id (tlvh);
        break;
      case TE_LINK_SUBTLV_SSDH_IF_SW_CAP_DESC:
        sum += update_corba_link_ssdh_if_sw_cap_desc (tlvh);
        break;
      case TE_LINK_SUBTLV_ANC_RC_ID:
        sum += update_corba_link_anc_rc_id (tlvh); 
        break;
      case TE_LINK_SUBTLV_BAND_ACCOUNT:
        sum += update_corba_link_band_account (tlvh);
        break;
      case TE_LINK_SUBTLV_SPAN_LENGTH:
        sum += update_corba_link_span_length (tlvh);
        break;
      case TE_LINK_SUBTLV_D_PDM:
        sum += update_corba_link_d_pdm (tlvh);
        break;
      case TE_LINK_SUBTLV_AMP_LIST:
        sum += update_corba_link_amp_list (tlvh);
        break;
      case TE_LINK_SUBTLV_AV_WAVE_MASK:
        sum += update_corba_link_av_wave_mask (tlvh);
        break;
      case TE_LINK_SUBTLV_TE_LINK_CALENDAR:
        sum += update_corba_link_calendar (tlvh);
        break;
      case TE_LINK_SUBTLV_POWER_CONSUMPTION:
        sum += update_corba_link_power_consumption (tlvh);
        break;
      case TE_LINK_SUBTLV_DYNAMIC_REPLANNING:
        sum += update_corba_link_dynamic_replanning (tlvh);
        break;
      default:
        sum += update_corba_info_tlv (tlvh);
        break;
    }
  }

  uint8_t ready2update = 0;

  if ((mask & REC_LINK_LCL_RMT_IDS) && (mask & REC_LCL_NODE_ID) && (mask & REC_RMT_NODE_ID))
    if (link_update(option, INTERDOM_TEL)) ready2update = 1;   // add/del/update interdomain telink

  if ((mask & REC_LINK_ID) && (mask & REC_LCLIF_IPADDR) && (mask & REC_RMTIF_IPADDR))
    if (link_update(option, INTRADOM_TEL)) ready2update = 1;   // add/del/update intradomain telink

  if (ready2update && (option == ADD_TO_SERVER))
  {
    link_update_states();

    if ((mask & REC_TE_METRIC) || (mask & REC_RSC_CLSCLR) || (mask & REC_LINK_PROTECT_TYPE) || (mask & REC_MAX_BW) || (mask & REC_MAX_RSV_BW))
      link_update_com();

    if ((mask & REC_D_PDM) || (mask & REC_SPAN_LENGTH) || (mask & REC_AMP_LIST))
      link_update_lscwdm();

    if (mask & REC_SHARED_RISK_LINK_GRP)
      corba_update_te_link_srlg();

    if (mask & REC_TE_LINK_CALENDAR)
      corba_update_te_link_tecal();

    if (mask & REC_IF_SW_CAP_DESC)
      corba_update_te_link_if_sw_cap_desc();

    if (mask & REC_UNRSV_BW)
      link_update_genbw();

    if (mask & REC_SSDH_IF_SW_CAP_DESC)
      link_update_tdmbw();

    if (mask & REC_AV_WAVE_MASK)
      link_update_lscwdm_bw();

    if (mask & REC_POWER_CONSUMPTION)
      link_update_power_consumption();

    if (mask & REC_DYNAMIC_REPLANNING)
      link_update_dynamic_replanning();
  }

  return sum - subtotal;
}

static u_int16_t
update_corba_info_tna_addr_tlv (uint8_t option, struct te_tlv_header *tlvh0, u_int16_t subtotal, u_int16_t total)
{
  struct te_tlv_header *tlvh, *next;
  u_int16_t sum = subtotal;

  int type;
  init_tna_ident();

  for (tlvh = tlvh0; sum < total; tlvh = (next ? next : TLV_HDR_NEXT (tlvh)))
  {
    next = NULL;
    type = ntohs(tlvh->type);
    switch (type)
    {
      case TE_TNA_ADDR_SUBTLV_TNA_ADDR_IPV4:
        sum += update_corba_info_tna_addr_ipv4 (tlvh);
        break;
      case TE_TNA_ADDR_SUBTLV_TNA_ADDR_IPV6:
        sum += update_corba_info_tna_addr_ipv6 (tlvh);
        break;
      case TE_TNA_ADDR_SUBTLV_TNA_ADDR_NSAP:
        sum += update_corba_info_tna_addr_nsap (tlvh);
        break;
      case TE_TNA_ADDR_SUBTLV_NODE_ID:
        sum += update_corba_info_node_id (tlvh);
        break;
      case TE_TNA_ADDR_SUBTLV_ANC_RC_ID:
        sum += update_corba_info_anc_rc_id (tlvh);
      default:
        sum += update_corba_info_tlv (tlvh);
        break;
    }
  }

  tna_ids_update(option);

  return sum - subtotal;
}

static u_int16_t
update_corba_info_router_addr_tlv (uint8_t option, struct te_tlv_header *tlvh0, u_int16_t subtotal, u_int16_t total)
{
  struct te_tlv_header *tlvh, *next;
  u_int16_t sum = subtotal;

  for (tlvh = tlvh0; sum < total; tlvh = (next ? next : TLV_HDR_NEXT (tlvh)))
  {
    next = NULL;
    switch (ntohs (tlvh->type))
    {
      case TE_ROUTER_ADDR_SUBTLV_ROUTER_ADDR:
        sum += update_corba_ra_addr(tlvh);
        break;
      case TE_ROUTER_ADDR_SUBTLV_POWER_CONSUMPTION:
        sum += update_corba_ra_energyConsumption(tlvh);
        break;
      default:
        sum += update_corba_info_tlv (tlvh);
        break;
    }
  }
  switch (option)
  {
    case ADD_TO_SERVER:
      node_add(UPDATE_G2PCERA, -1, NTYPE_NETWORK);
      update_net_node(-1, 0);
      break;
    case REMOVE_FROM_SERVER:
      node_del(UPDATE_G2PCERA, -1, NTYPE_NETWORK);
      break;
}
  return sum - subtotal;
}

void
update_corba_te_inf (uint8_t option, struct ospf_lsa *lsa)
{
  struct lsa_header *lsah = (struct lsa_header *) lsa->data;
  struct te_tlv_header *tlvh;
  u_int16_t sum, total, l;
  struct te_tlv_link *top;

  total = ntohs (lsah->length) - OSPF_LSA_HEADER_SIZE;
  sum = 0;
  tlvh = TLV_HDR_TOP (lsah);

  if (IS_DEBUG_TE(CORBA_UPDATE))
  {
    const char* str;
    switch (ntohs (tlvh->type))
    {
      case TE_TLV_ROUTER_ADDR:            str = "ROUTER ADDRESS LSA"; break;
      case TE_TLV_LINK:                   str = "TE LINK LSA"; break;
      case TE_TLV_TNA_ADDR:               str = "TNA ADDRESS LSA"; break;
      default:                            str = "UNKNOWN LSA"; break;
    }
    zlog_debug("[DBG]        LSA type: %s", str);
    zlog_debug("[DBG] CORBA: Preparing update for G2PCERA");
  }

  corba_update_advertising_router(lsa->data->adv_router);

  while (sum < total)
  {
    switch (ntohs (tlvh->type))
    {
      case TE_TLV_ROUTER_ADDR:
        top = (struct te_tlv_link *) tlvh;
        l = ntohs (top->header.length);
        sum += TLV_HEADER_SIZE;
        sum += update_corba_info_router_addr_tlv (option, tlvh+1, sum, sum + l);
        break;
      case TE_TLV_LINK:
        top = (struct te_tlv_link *) tlvh;
        l = ntohs (top->header.length);
        sum += TLV_HEADER_SIZE;
        sum += update_corba_link (option, tlvh+1, sum, sum + l);
        break;
      case TE_TLV_TNA_ADDR:
        top = (struct te_tlv_link *) tlvh;
        l = ntohs (top->header.length);
        sum += TLV_HEADER_SIZE;
        sum += update_corba_info_tna_addr_tlv (option, tlvh+1, sum, sum + l);
        break;
      default:
        sum += update_corba_info_tlv (tlvh);
        break;
    }
    tlvh = (struct te_tlv_header *)((char *) (TLV_HDR_TOP (lsah)) + sum);
  }
  return;
}

struct zlist lookup_lsas_from_lsdb(uint16_t type)
{
  if(IS_DEBUG_TE(CORBA_UPDATE))
    zlog_debug("[DBG] CORBA: Creating list of LSAs");

  struct zlist lsas;

  memset (&lsas, 0, sizeof (struct zlist));

  struct prefix_ls lp;
  struct route_node *rn, *start;
  struct ospf_lsa *lsa;
  struct ospf *ospf;
  struct ospf_area *area;
  struct zlistnode *node;
  uint16_t length;

  ospf = ospf_enni_lookup();
  if (ospf == NULL)
    return lsas;

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
          if (has_lsa_tlv_type(lsa, type, &length) > 0)
          {
            listnode_add(&lsas, ospf_lsa_dup(lsa));
          }
          route_unlock_node (start);
        }
    }
  }

  return lsas;
}

#endif /* USE_UNTESTED_OSPF_TE_CORBA_UPDATE */

/** Harmony related functions */

static struct te_link*   ospf_te_new_harmony_if (void);
static struct raHarmony* new_ra_harmony (struct in_addr ra, uint32_t area_id);

struct raHarmony* lookup_hnode(struct in_addr ra, uint32_t area_id)
{
  struct zlistnode *node;
  void *data;
  struct raHarmony *rah;

  for (ALL_LIST_ELEMENTS_RO(OspfTE.harmonyRaList, node, data)) {
    rah = (struct raHarmony *) data;
    if (rah->router_addr.router_addr.value.s_addr == ra.s_addr)
      return rah;
  }

  return NULL;
}

struct te_link* lookup_hlink(struct in_addr node_id, uint32_t local_id)
{
  struct zlistnode *node;
  void *data;
  struct te_link *link;

  for (ALL_LIST_ELEMENTS_RO(OspfTE.harmonyIflist, node, data)) {
    link = (struct te_link *) data;
    if ((link->lcl_node_id.header.length == 0) || (link->link_lcl_rmt_ids.header.length == 0))
      continue;

    if ((link->lcl_node_id.value.s_addr == node_id.s_addr)
      && (link->link_lcl_rmt_ids.local_id == htonl(local_id)))
      return link;
  }

  return NULL;
}

struct te_link* lookup_htna(struct in_addr node, struct tna_addr_value tna)
{
  struct zlistnode *no, *no1;
  void *data, *data1;
  struct te_link *link;
  struct tna_addr_data_element *tna_data;

  for (ALL_LIST_ELEMENTS_RO(OspfTE.harmonyIflist, no, data)) {
    link = (struct te_link *) data;

    if (!link->tna_address.header.length)
      continue;

    for (ALL_LIST_ELEMENTS_RO(&link->tna_address.tna_addr_data, no1, data1)) {
      tna_data = (struct tna_addr_data_element *) data1;
      if (tna_data->node_id.value.s_addr == node.s_addr) {
        if (isTnaAddrInList(&tna, &tna_data->tna_addr))
          return link;
      }
    }
  }

  return NULL;
}

struct raHarmony* add_hnode(struct in_addr ra, uint32_t area_id)
{
  if (lookup_hnode(ra, area_id))
    return NULL;

  return new_ra_harmony(ra, area_id);
}

int del_hnode(struct in_addr ra, uint32_t area_id)
{
  struct raHarmony *rah;
  rah = lookup_hnode(ra, area_id);
  if (!rah)
    return -1;   // ra doesn't exist

  listnode_delete(OspfTE.harmonyRaList, rah);
  return 0;
}

struct te_link* add_hlink(struct in_addr node_id, uint32_t local_id)
{
  if (lookup_hlink(node_id, local_id))
    return NULL;   // link already exists

  return ospf_te_new_harmony_if();
}

int del_hlink(struct te_link *link)
{
  if (!link)
    return -1;   // link doesn't exist

  listnode_delete(OspfTE.harmonyIflist, link);

  return 0;
}

struct te_link* add_htna(struct in_addr node, struct tna_addr_value tna)
{
  if (lookup_htna(node, tna))
    return NULL;   // tna already exists

  return ospf_te_new_harmony_if();
}

int del_htna(struct in_addr node, struct tna_addr_value tna)
{
  struct te_link *telink;
  telink = lookup_htna(node, tna);
  if (!telink)
    return -1;   // link doesn't exist

  listnode_delete(OspfTE.harmonyIflist, telink);
  return 0;
}

struct ospf* get_hospf()
{
  return ospf_enni_lookup();
}

/** ******************************************************************************** */

/**
 * Check if there is a TLV in lsa
 * @param tlv  Te TLV
 * @param sub_type sub type of searched subTLV in TLV
 * @return tlv_positpon, 0 if speciffied SubTLV doesn't exists, -1 if TLV is malformed 
 */
static int has_tlv_subtlv(struct te_tlv_header *tlvh, uint16_t subtlv_type)
{
  u_int16_t      sum   = TLV_HDR_SIZE;
  u_int16_t      total = TLV_SIZE(tlvh);
  struct te_tlv_header  *sub_tlv;

  while (sum < total)
  {
    sub_tlv = (struct te_tlv_header *)((char *)(tlvh) + sum);
    if (ntohs (sub_tlv->type) == subtlv_type)
    {
      return sum;
    }

    int len = TLV_SIZE(sub_tlv);
    if (len > 0)
      sum += len;
    else
    {
      zlog_err("[ERR] has_tlv_subtlv: Wrong SubTLV length. TLV corrupted");
      return -1;
    }
  }
  if (sum != total)
  {
    zlog_err("[ERR] has_tlv_subtlv: Malformed TLV (length: %d, sum of SubTLVs: %d)", total, sum);
    return -1;
  }
  return 0;
}


/**
 * Search in LSA if there is Te TLV with specyfied type
 * @param lsa ospf LSA
 * @param type type of searched in LSA Te TLV
 * @return pointer to Tlv or NULL if doesn't exists
 */
struct te_tlv_header *te_tlv_lookup(struct ospf_lsa *lsa, uint16_t type)
{
  uint16_t tlv_length;
  int tlv_pos = has_lsa_tlv_type(lsa, type, &tlv_length); 
  if (tlv_pos > 0)
  {
    struct te_tlv_header *tlvh = (struct te_tlv_header *)((char *)(lsa->data) + tlv_pos);
    return tlvh;
  }
  else
  {
    /* zlog_debug("Can't find TLV"); */
    return NULL;
  }
  return NULL;
}

/**
 * Search in LSA if there is Te Sub TLV with specyfied type and subtype
 * @param lsa ospf LSA
 * @param type type of searched in LSA Te TLV
 * @param subtype subtype of searched in LSA TLV sub type
 * @return pointer to SubTlv or NULL if doesn't exists
 */
struct te_tlv_header *te_subtlv_lookup(struct ospf_lsa *lsa, uint16_t type, uint16_t subtype)
{
  uint16_t tlv_length;
  int tlv_pos = has_lsa_tlv_type(lsa, type, &tlv_length); 
  if (tlv_pos > 0)
  {
    struct te_tlv_header *tlvh = (struct te_tlv_header *)((char *)(lsa->data) + tlv_pos);
    int sub_tlv_pos = has_tlv_subtlv(tlvh, subtype);
    if (sub_tlv_pos > 0)
    {
      return (struct te_tlv_header *)((char *)((char *)(tlvh) + sub_tlv_pos));
    }
    else
    {
      /* zlog_debug("Can't find subTlv in LSA"); */
      return NULL;
    }
  }
  else
  {
    /* zlog_debug("Can't find TLV"); */
    return NULL;
  }
  return NULL;
}


/**
 * Search in LSA if there is Te TLV with specyfied type
 * @param lsa ospf LSA
 * @param type type of searched in LSA Te TLV
 * @param length_ptr <OUT> length of searched TLV
 * @return tlv_positpon, 0 if speciffied TLV doesn't exists, -1 if LSA is malformed 
 */
int has_lsa_tlv_type(struct ospf_lsa *lsa, uint16_t type, uint16_t *length)
{
  struct lsa_header     *lsah = (struct lsa_header *) lsa->data;
  struct te_tlv_header  *tlvh = TLV_HDR_TOP (lsah);
  u_int16_t             sum   = 0;
  u_int16_t             total = ntohs (lsah->length) - OSPF_LSA_HEADER_SIZE;


/*if (IS_DEBUG_TE(TE_LSA_CPY))
    zlog_debug("has_lsa_tlv_type: length %d", total); */

  while (sum < total)
  {
    if (ntohs (tlvh->type) == type)
    {
      *length = TLV_BODY_SIZE(tlvh);
/*      if (IS_DEBUG_OSPF_EVENT)
        zlog_debug("has_lsa_tlv_type: result = %d", sum + OSPF_LSA_HEADER_SIZE); */
      return sum + OSPF_LSA_HEADER_SIZE;
    }

    u_int16_t len = TLV_BODY_SIZE(tlvh);
    len+=4;
/*if (IS_DEBUG_TE(TE_LSA_CPY))
    zlog_debug("has_lsa_tlv_type: sum+= %d", len); */

    if (len > 0)
      sum += len;
    else
    {
      zlog_err("[ERR] has_lsa_tlv_type: Wrong TLV length: %d. TLV corrupted", TLV_BODY_SIZE(tlvh));
      length = 0;
      return -1;
    }
    tlvh = (struct te_tlv_header *)((char *) (TLV_HDR_TOP (lsah)) + sum);
  }
  if (sum != total)
  {
    zlog_err("[ERR] has_lsa_tlv_type: Malformed LSA (LSA payload length: %d, sum of TLVs: %d)", total, sum);
    length = 0;
    return -1;
  }
  length = 0;
  return 0;
}

/**
 * Creates a copy of LSA with speciffied type. New LSA has only one TLV inside
 * @param source_ospf_lsa_ptr pointer to the source lsa
 * @param offset offset of the TLV in LSA that will be copied
 * @return new copy of LSA
 */
static struct ospf_lsa*
copy_lsa_by_Tlv(struct ospf_lsa *source, uint16_t offset)
{
  struct ospf_lsa      *lsa_new;
  struct te_tlv_header *tlvh     = (struct te_tlv_header *)((char *) (source->data) + offset);
  u_int16_t            length    = ROUNDUP(OSPF_LSA_HEADER_SIZE + 4 + ntohs(tlvh->length), 4);

  if ((lsa_new = ospf_lsa_new ()) == NULL)
  {
    zlog_warn ("[WRN] copy_lsa_by_Tlv: Creating of new LSA failed");
    return NULL;
  }

  if ((lsa_new->data = ospf_lsa_data_new (length)) == NULL)
  {
    zlog_warn ("[WRN] copy_lsa_by_Tlv: ospf_lsa_data_new() failed");
    ospf_lsa_unlock (&lsa_new);
    return NULL;
  }

  memcpy (lsa_new->data, source->data, OSPF_LSA_HEADER_SIZE); /* length value may be not correct */
  lsa_new->data->length = htons(length);

  memcpy (TLV_HDR_TOP(lsa_new->data), (char *)(source->data) + offset, ntohs(tlvh->length) + 4);


  return lsa_new;
}

/**
 * Creates a copy of LSA with speciffied type. New LSA has only one TLV inside
 * @param source_ospf_lsa_ptr pointer to the source lsa
 * @param tlvh pointer to tlv (this tlv has subtlvs)
 * @return new copy of LSA
 */
static struct ospf_lsa*
copy_lsa_by_Tlv_ptr(struct ospf_lsa *source, struct te_tlv_header *tlvh)
{
  struct ospf_lsa      *lsa_new;
  u_int16_t            length    = ROUNDUP(OSPF_LSA_HEADER_SIZE + 4 + ntohs(tlvh->length), 4);

  if ((lsa_new = ospf_lsa_new ()) == NULL)
  {
    zlog_warn ("[WRN] copy_lsa_by_Tlv_ptr: Creating of new LSA failed");
    return NULL;
  }

  if ((lsa_new->data = ospf_lsa_data_new (length)) == NULL)
  {
    zlog_warn ("[WRN] copy_lsa_by_Tlv_ptr: ospf_lsa_data_new() failed");
    ospf_lsa_unlock (&lsa_new);
    return NULL;
  }

  memcpy (lsa_new->data, source->data, OSPF_LSA_HEADER_SIZE); /* length value may be not correct */
  lsa_new->data->length = htons(length);

  memcpy (TLV_HDR_TOP(lsa_new->data), (char *)tlvh, ntohs(tlvh->length) + 4);

  return lsa_new;
}

/*------------------------------------------------------------------------*
 * Followings are callback functions against generic Opaque-LSAs handling.
 *------------------------------------------------------------------------*/

static uint32_t map_inni(struct in_addr adv_router, uint32_t old_instance_no)
{
/*  zlog_debug("map_inni %s, %d", inet_ntoa(adv_router), old_instance_no); */
  uint32_t instance_no = get_from_map(OspfTE.map_inni, adv_router, old_instance_no, get_te_instance_value);
  uint32_t id = SET_OPAQUE_LSID (OPAQUE_TYPE_TRAFFIC_ENGINEERING_LSA, instance_no);
  return id;
}

static uint32_t map_enni(struct in_addr adv_router, uint32_t old_instance_no)
{
  uint32_t instance_no = get_from_map(OspfTE.map_enni, adv_router, old_instance_no, get_te_instance_value);
  uint32_t id = SET_OPAQUE_LSID (OPAQUE_TYPE_TRAFFIC_ENGINEERING_LSA, instance_no);
  return id;
}

static uint32_t map_uni(struct in_addr adv_router, uint32_t old_instance_no)
{
  uint32_t instance_no = get_from_map(OspfTE.map_uni, adv_router, old_instance_no, get_te_instance_value);
  uint32_t id =SET_OPAQUE_LSID (OPAQUE_TYPE_TRAFFIC_ENGINEERING_LSA, instance_no);
  return id;
}

static void inni_to_enni_tna(struct ospf_lsa *lsa, struct te_tlv_tna_addr *tna_tlv, int flush)
{
//  if (IS_DEBUG_TE(FEED_UP))
//    zlog_debug("[DBG] INNI_TO_ENNI_TNA%s: START", (flush == 1) ? " (flush)" : "");
  struct ospf *ospf_inni, *ospf_enni;
  if ((ospf_inni = ospf_inni_lookup()) == NULL)
  {
    if (IS_DEBUG_TE(FEED_UP))
      zlog_debug("[DBG] INNI_TO_ENNI_TNA%s: OSPF INNI not found", (flush == 1) ? " (flush)" : "");
    goto out;
  }
  if (ospf_inni->router_id.s_addr == htonl(0))
  {
    if (IS_DEBUG_TE(FEED_UP))
      zlog_debug("[DBG] INNI_TO_ENNI_TNA%s: OSPF INNI router id is not configured", (flush == 1) ? " (flush)" : "");
    goto out;
  }

  if ((ospf_enni = ospf_enni_lookup()) == NULL)
  {
    if (IS_DEBUG_TE(FEED_UP))
      zlog_debug("[DBG] INNI_TO_ENNI_TNA%s: OSPF ENNI not found", (flush == 1) ? " (flush)" : "");
    goto out;
  }
  if (ospf_enni->router_id.s_addr == htonl(0))
  {
    if (IS_DEBUG_TE(FEED_UP))
      zlog_debug("[DBG] INNI_TO_ENNI_TNA%s: OSPF ENNI router id is not configured", (flush == 1) ? " (flush)" : "");
    goto out;
  }

  if ((flush == 1) && (lookup_from_map(OspfTE.map_enni, lsa->data->adv_router, lsa->data->id.s_addr) == 0))
  {
    if (IS_DEBUG_TE(FEED_UP))
      zlog_debug("[DBG] INNI_TO_ENNI_TNA flush: Opaque %s has no its copy in ENNI link state data base. Flushing skipped", inet_ntoa(lsa->data->id));
    goto out;
  }

  if (&ospf_enni->lsdb == NULL)
  {
    zlog_warn("[WRN] INNI_TO_ENNI_TNA%s: LSDB not found", (flush == 1) ? " (flush)" : "");
    goto out;
  }

  struct ospf_area *area    = NULL;
  struct ospf_area *tmp_area;
  struct zlistnode *node, *nnode;
  for(ALL_LIST_ELEMENTS(ospf_enni->areas, node, nnode, tmp_area))
    if (tmp_area->area_id.s_addr == lsa->area->area_id.s_addr)
      area = tmp_area;

  if (area == NULL)
  {
    if (IS_DEBUG_TE(FEED_UP))
      zlog_debug("[DBG] INNI_TO_ENNI_TNA%s: Can't find appropriate area in OSPF ENNI", (flush == 1) ? " (flush)" : "");
    goto out;
  }

  struct ospf_lsa  *lsa_new = copy_lsa_by_Tlv_ptr(lsa, (struct te_tlv_header *) tna_tlv);

  if (lsa_new == NULL)
  {
    zlog_warn ("[WRN] INNI_TO_ENNI_TNA%s: lsa_new == NULL", (flush == 1) ? " (flush)" : "");
    goto out;
  }

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
  lsa_new->data->id.s_addr  = htonl(map_enni(lsa->data->adv_router, lsa->data->id.s_addr));
  lsa_new->data->adv_router = ospf_enni->router_id;

/*  if (IS_DEBUG_TE(FEED_UP))
  {
    struct in_addr tmp;
    tmp.s_addr = lsa_new->data->id.s_addr;
    zlog_debug("[DBG] INNI_TO_ENNI_TNA%s: registering opaque %s", (flush == 1) ? " (flush)" : "", inet_ntoa(tmp));
  }
  register_opaque_lsa(lsa_new);
*/

  if (flush == 0)
  {
    if (IS_DEBUG_TE(FEED_UP))
    {
      char buf[50];
      log_summary_te_lsa(buf, lsa_new);
      zlog_debug("[DBG] INNI_TO_ENNI_TNA: Installing new LSA (%s)", buf);
    }
    ospf_lsa_checksum (lsa_new->data);
    ospf_lsa_install(ospf_enni, NULL, lsa_new);
    ospf_flood_through_area (area, NULL/*nbr*/, lsa_new);
  }
  else
  {
    if (IS_DEBUG_TE(FEED_UP))
    {
      char buf[50];
      log_summary_te_lsa(buf, lsa_new);
      struct in_addr tmp;
      tmp.s_addr = lsa_new->data->id.s_addr;
      zlog_debug("[DBG] INNI_TO_ENNI_TNA: (LSA %s id %s age %d -> %d) ospf_opaque_lsa_flush_schedule", buf, inet_ntoa(tmp), ntohs(lsa->data->ls_age), OSPF_LSA_MAXAGE);
    }
    lsa_new->data->ls_age = htons(OSPF_LSA_MAXAGE);
    ospf_lsa_checksum (lsa_new->data);
    ospf_opaque_lsa_flush_schedule(lsa_new);
  }
out:
//  if (IS_DEBUG_TE(FEED_UP))
//    zlog_debug("[DBG] INNI_TO_ENNI_TNA%s: OK", (flush == 1) ? " (flush)" : "");
  return;
}

//TODO not prepared for ifpHarmony
static int is_router_id_in_ospf(adj_type_t instance, struct in_addr id)
{
  struct ospf *ospf;
  switch (instance)
  {
    case INNI:
      ospf = ospf_inni_lookup();
      break;
    case ENNI:
      ospf = ospf_enni_lookup();
      break;
    case UNI:
      ospf = ospf_uni_lookup();
      break;
    default:
      ospf = NULL;
      break;
  }

  if (ospf == NULL)
    return 0;

/*zlog_debug("is_router_id_in_ospf id = %s", inet_ntoa(id)); */

  struct zlistnode        *node1, *nnode1;
  struct ospf_interface   *oi;

  struct ospf_neighbor    *nbr;
  struct route_node       *rn;

  if (IPV4_ADDR_SAME(&ospf->router_id, &id))
  {
    return 1;
  }
  for (ALL_LIST_ELEMENTS(ospf->oiflist, node1, nnode1, oi))
  {
    for (rn = route_top (oi->nbrs); rn; rn = route_next (rn))
    {
      if ((nbr = rn->info))
      {
/*        zlog_debug("  nbr id = %s", inet_ntoa(nbr->router_id)); */
        if (IPV4_ADDR_SAME (&nbr->router_id, &id))
        {
          return 1;
        }
      }
    }
  }
  return 0;
}

static void inni_to_enni_link(struct ospf_lsa *lsa, uint16_t te_link_start, int flush)
{
  struct ospf *ospf_inni, *ospf_enni;
  if ((ospf_inni = ospf_inni_lookup()) == NULL)
  {
    if (IS_DEBUG_TE(FEED_UP))
      zlog_debug("[DBG] INNI_TO_ENNI_LINK%s: OSPF INNI not found", (flush == 1) ? " (flush)" : "");
    goto out;
  }
  if (ospf_inni->router_id.s_addr == htonl(0))
  {
    if (IS_DEBUG_TE(FEED_UP))
      zlog_debug("[DBG] INNI_TO_ENNI_LINK%s: OSPF INNI router id is not configured", (flush == 1) ? " (flush)" : "");
    goto out;
  }
  if ((ospf_enni = ospf_enni_lookup()) == NULL)
  {
    if (IS_DEBUG_TE(FEED_UP))
      zlog_debug("[DBG] INNI_TO_ENNI%s: LSA type: LINK --> OSPF ENNI not found", (flush == 1) ? " (flush)" : "");
    goto out;
  }
  if (ospf_enni->router_id.s_addr == htonl(0))
  {
    if (IS_DEBUG_TE(FEED_UP))
      zlog_debug("[DBG] INNI_TO_ENNI%s: LSA type: LINK --> OSPF ENNI router id is not configured", (flush == 1) ? " (flush)" : "");
    goto out;
  }

  if (&ospf_enni->lsdb == NULL)
  {
    zlog_warn("[WRN] INNI_TO_ENNI%s: LSA type: LINK --> LSDB not found", (flush == 1) ? " (flush)" : "");
    goto out;
  }

  /* check if link id == enni neighbor if */

//  struct te_tlv_header           *tlvh         = NULL;
  struct te_link_subtlv_link_id  *link_id_tlvh;

  if ((link_id_tlvh = (struct te_link_subtlv_link_id *)te_subtlv_lookup(lsa, TE_TLV_LINK, TE_LINK_SUBTLV_LINK_ID)) == NULL)
  {
    if (IS_DEBUG_TE(FEED_UP))
      zlog_debug("[DBG] INNI_TO_ENNI%s: LSA type: LINK --> TLV subtype TE_LINK_SUBTLV_LINK_ID not found in lsa", (flush == 1) ? " (flush)" : "");
    goto out;
  }

  struct in_addr          *link_id = &link_id_tlvh->value;
  struct zlistnode        *node, *nnode;

  int found_rc_in_enni = is_router_id_in_ospf(ENNI, *link_id);
  int found_rc_in_inni = is_router_id_in_ospf(INNI, *link_id);

  if ((found_rc_in_enni == 0) && (found_rc_in_inni == 1))
  {
    if (IS_DEBUG_TE(FEED_UP))
      zlog_debug("[DBG] INNI_TO_ENNI%s: LSA type: LINK --> Link is no interdomain link or the RC is down", (flush == 1) ? " (flush)" : "");
    goto out;
  }

  if ((found_rc_in_enni == 1) && (found_rc_in_inni == 1))
  {
    zlog_err("[ERR] INNI_TO_ENNI%s: LSA type: LINK --> Router id conflict! There is a router with the same sid that RC in different domain", (flush == 1) ? " (flush)" : "");
    goto out;
  }

  if ((found_rc_in_enni == 0) && (found_rc_in_inni == 0))
  {
    if (IS_DEBUG_TE(FEED_UP))
      zlog_debug("[DBG] INNI_TO_ENNI%s: LSA type: LINK --> Could not find RC in and outside domain", (flush == 1) ? " (flush)" : "");
    goto out;
  }

  struct ospf_area *area    = NULL;
  struct ospf_area *tmp_area;
  for(ALL_LIST_ELEMENTS(ospf_enni->areas, node, nnode, tmp_area))
    if (tmp_area->area_id.s_addr == lsa->area->area_id.s_addr)
      area = tmp_area;

  if (area == NULL)
  {
    if (IS_DEBUG_TE(FEED_UP))
      zlog_debug("[DBG] INNI_TO_ENNI%s: LSA type: LINK --> Can't find appropriate area in OSPF ENNI", (flush == 1) ? " (flush)" : "");
    goto out;
  }

  struct ospf_lsa  *lsa_new = copy_lsa_by_Tlv(lsa, te_link_start);

  if (lsa_new == NULL)
  {
    zlog_warn ("[WRN] INNI_TO_ENNI%s: LSA type: LINK --> lsa_new == NULL", (flush == 1) ? " (flush)" : "");
    goto out;
  }

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
  lsa_new->data->id.s_addr  = htonl(map_enni(lsa->data->adv_router, lsa->data->id.s_addr));
  lsa_new->data->adv_router = ospf_enni->router_id;

/*
  if (IS_DEBUG_TE(FEED_UP))
  {
    struct in_addr tmp;
    tmp.s_addr = lsa_new->data->id.s_addr;
    zlog_debug("[DBG] INNI_TO_ENNI_LINK%s: registering opaque %s", (flush == 1) ? " (flush)" : "", inet_ntoa(tmp));
  }
  register_opaque_lsa(lsa_new);
*/
  if (flush == 0)
  {
    if (IS_DEBUG_TE(FEED_UP))
      zlog_debug("[DBG] INNI_TO_ENNI_LINK: Installing new LSA");

    ospf_lsa_checksum (lsa_new->data);
    ospf_lsa_install(ospf_enni, NULL, lsa_new);
    ospf_flood_through_area (area, NULL/*nbr*/, lsa_new);
  }
  else
  {
    if (IS_DEBUG_TE(FEED_UP))
    {
      char buf[50];
      log_summary_te_lsa(buf, lsa_new);
      struct in_addr tmp;
      tmp.s_addr = lsa_new->data->id.s_addr;
      zlog_debug("[DBG] INNI_TO_ENNI_LINK: Flushing (LSA %s age id age %s %d -> %d) ospf_opaque_lsa_flush_schedule", buf, inet_ntoa(tmp), ntohs(lsa->data->ls_age), OSPF_LSA_MAXAGE);
    }
    lsa_new->data->ls_age = htons(OSPF_LSA_MAXAGE);
    ospf_lsa_checksum (lsa_new->data);
    ospf_opaque_lsa_flush_schedule(lsa_new);
  }
out:
  ;
//  if (IS_DEBUG_TE(FEED_UP))
//    zlog_debug("[DBG] INNI_TO_ENNI_LINK%s: OK", (flush == 1) ? " (flush)" : "");
}

static void enni_to_inni_tna(struct ospf_lsa *lsa, struct te_tlv_tna_addr *tna_tlv, int flush)
{
  if (IS_DEBUG_TE(FEED_DOWN))
  {
    char lsa_info_buf[200];
    log_summary_te_lsa(lsa_info_buf, lsa);
    zlog_debug("[DBG] ENNI_TO_INNI_TNA%s: START adv router %s LSA: %s", (flush == 1) ? " (flush)" : "", inet_ntoa(lsa->data->adv_router), lsa_info_buf);
  }

  struct ospf          *ospf_inni;
  struct ospf          *ospf_enni;
  struct ospf_area     *area           = NULL;
  struct ospf_area     *tmp_area;
  struct zlistnode     *node, *nnode;
  struct ospf_lsa      *lsa_new        = NULL;
  u_int16_t            length          = ROUNDUP(OSPF_LSA_HEADER_SIZE + 4 + ntohs(tna_tlv->header.length), 4);

  if ((ospf_inni = ospf_inni_lookup()) == NULL)
  {
    if (IS_DEBUG_TE(FEED_DOWN))
      zlog_debug("[DBG] ENNI_TO_INNI_TNA%s: OSPF INNI not found", (flush == 1) ? " (flush)" : "");
    goto out;
  }
  if (ospf_inni->router_id.s_addr == htonl(0))
  {
    if (IS_DEBUG_TE(FEED_DOWN))
      zlog_debug("[DBG] ENNI_TO_INNI_TNA%s: OSPF INNI router id is not configured", (flush == 1) ? " (flush)" : "");
    goto out;
  }
  if ((ospf_enni = ospf_enni_lookup()) == NULL)
  {
    if (IS_DEBUG_TE(FEED_DOWN))
      zlog_debug("[DBG] ENNI_TO_INNI_TNA%s: OSPF ENNI not found", (flush == 1) ? " (flush)" : "");
    goto out;
  }
  if (ospf_enni->router_id.s_addr == htonl(0))
  {
    if (IS_DEBUG_TE(FEED_DOWN))
      zlog_debug("[DBG] ENNI_TO_INNI_TNA%s: OSPF ENNI router id is not configured", (flush == 1) ? " (flush)" : "");
    goto out;
  }
  if (&ospf_enni->lsdb == NULL)
  {
    zlog_warn("[WRN] ENNI_TO_INNI_TNA%s: LSDB not found", (flush == 1) ? " (flush)" : "");
    goto out;
  }

  if ((flush == 1) && (lookup_from_map(OspfTE.map_inni, lsa->data->adv_router, lsa->data->id.s_addr) == 0))
  {
    if (IS_DEBUG_TE(FEED_DOWN))
      zlog_debug("[DBG] ENNI_TO_INNI_TNA flush: Opaque %s has no its copy in INNI link state data base. Flushing skipped", inet_ntoa(lsa->data->id));
    goto out;
  }

  for(ALL_LIST_ELEMENTS(ospf_inni->areas, node, nnode, tmp_area))
    if (tmp_area->area_id.s_addr == lsa->area->area_id.s_addr)
      area = tmp_area;

  if (area == NULL)
  {
    zlog_warn("[WRN] ENNI_TO_INNI_TNA%s: Can't find appropriate area in OSPF INNI", (flush == 1) ? " (flush)" : "");
    goto out;
  }

  struct te_tna_addr_subtlv_anc_rc_id *ancestor_ptr = (struct te_tna_addr_subtlv_anc_rc_id*) te_subtlv_lookup(lsa, TE_TLV_TNA_ADDR, TE_TNA_ADDR_SUBTLV_ANC_RC_ID);

  if (flush == 1)
  {
//    if (IS_DEBUG_TE(FEED_DOWN))
//      zlog_debug("[DBG] ENNI_TO_INNI_TNA: copy_lsa_by_Tlv_ptr lengt: %d", ntohs(tna_tlv->header.length));
    lsa_new = copy_lsa_by_Tlv_ptr(lsa, (struct te_tlv_header *)tna_tlv);
  }
  else
  {
    if (ancestor_ptr != NULL)
    {
      zlog_warn("[WRN] ENNI_TO_INNI_TNA: Feed down own TNA opaque");
      goto out;
    }
    if ((lsa_new = ospf_lsa_new ()) == NULL)
    {
      zlog_warn("[WRN] ENNI_TO_INNI_TNA: Creating new LSA failed");
      goto out;
    }

    if ((lsa_new->data = ospf_lsa_data_new (length+sizeof(struct te_tna_addr_subtlv_anc_rc_id))) == NULL)
    {
      zlog_warn("[WRN] ENNI_TO_INNI_TNA: ospf_lsa_data_new() failed");
      ospf_lsa_unlock (&lsa_new);
      goto out;
    }

    memcpy (lsa_new->data, lsa->data, OSPF_LSA_HEADER_SIZE); /* length value may be not correct */
    memcpy (TLV_HDR_TOP(lsa_new->data), (char *)tna_tlv, ntohs(tna_tlv->header.length) + 4);

    struct te_tlv_tna_addr *new_tna_tlv = (struct te_tlv_tna_addr*)(TLV_HDR_TOP(lsa_new->data));

    if (ancestor_ptr == NULL)
    {
      struct te_tna_addr_subtlv_anc_rc_id ancestor;
      ancestor.header.type = htons(TE_TNA_ADDR_SUBTLV_ANC_RC_ID);
      ancestor.header.length = htons(4);
      ancestor.value.s_addr = lsa->data->adv_router.s_addr;

      memcpy ((char *)TLV_HDR_TOP(lsa_new->data) + ntohs(tna_tlv->header.length) + 4, (char *)(&ancestor), sizeof(struct te_tna_addr_subtlv_anc_rc_id));
      //Increasing length od TLV
      new_tna_tlv->header.length = htons(ntohs(tna_tlv->header.length) + sizeof(struct te_tna_addr_subtlv_anc_rc_id));
      //Increasing length of LSA
      lsa_new->data->length = htons(length + sizeof(struct te_tna_addr_subtlv_anc_rc_id));
    }
/*  else
    {
    ancestor_ptr->header.type = htons(TE_TNA_ADDR_SUBTLV_ANC_RC_ID);
      ancestor_ptr->header.length = htons(4);
      ancestor_ptr->value.s_addr = lsa->data->adv_router.s_addr;
    }
*/
  }
  if (lsa_new == NULL)
  {
    zlog_warn("[WRN] ENNI_TO_INNI_TNA%s: lsa_new == NULL", (flush == 1) ? " (flush)" : "");
    goto out;
  }

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
  lsa_new->data->id.s_addr  = htonl(map_inni(lsa->data->adv_router, lsa->data->id.s_addr));
  lsa_new->data->adv_router = ospf_inni->router_id;

/*
  if (IS_DEBUG_TE(FEED_DOWN))
  {
    struct in_addr tmp;
    tmp.s_addr = lsa_new->data->id.s_addr;
    zlog_debug("[DBG] ENNI_TO_INNI_TNA%s: registering opaque %s", (flush == 1) ? " (flush)" : "", inet_ntoa(tmp));
  }
  register_opaque_lsa(lsa_new);
*/
  if (flush == 0)
  {
    if (IS_DEBUG_TE(FEED_DOWN))
    {
      char buf[50];
      log_summary_te_lsa(buf, lsa_new);
      struct in_addr tmp;
      tmp.s_addr = lsa_new->data->id.s_addr;
      zlog_debug("[DBG] ENNI_TO_INNI_TNA: Installing new (LSA %s id %s)", buf, inet_ntoa(tmp));
    }
    ospf_lsa_checksum (lsa_new->data);
    ospf_lsa_install(ospf_inni, NULL, lsa_new);
    ospf_flood_through_area (area, NULL/*nbr*/, lsa_new);
  }
  else
  {
    if (IS_DEBUG_TE(FEED_DOWN))
    {
      char buf[50];
      log_summary_te_lsa(buf, lsa_new);
      struct in_addr tmp;
      tmp.s_addr = lsa_new->data->id.s_addr;
      zlog_debug("[DBG] ENNI_TO_INNI_TNA: Flushing LSA (%s id %s age %d -> %d) ospf_opaque_lsa_flush_schedule", buf, inet_ntoa(tmp), ntohs(lsa->data->ls_age), OSPF_LSA_MAXAGE);
    }
    lsa_new->data->ls_age = htons(OSPF_LSA_MAXAGE);
    ospf_lsa_checksum (lsa_new->data);
    ospf_opaque_lsa_flush_schedule(lsa_new);
  }
out:
  ;
//  if (IS_DEBUG_TE(FEED_DOWN))
//    zlog_debug("[DBG] ENNI_TO_INNI_TNA%s: OK", (flush == 1) ? " (flush)" : "");
}

static void enni_to_inni_link(struct ospf_lsa *lsa, uint16_t link_start, int flush)
{
  struct ospf          *ospf_inni;
  struct ospf          *ospf_enni;
  struct ospf_area     *area           = NULL;
  struct ospf_area     *tmp_area;
  struct zlistnode     *node, *nnode;
  struct ospf_lsa      *lsa_new;
  struct te_tlv_header *tlvh           = (struct te_tlv_header *)((char *) (lsa->data) + link_start);
  u_int16_t            length          = ROUNDUP(OSPF_LSA_HEADER_SIZE + 4 + ntohs(tlvh->length), 4);

  if ((ospf_inni = ospf_inni_lookup()) == NULL)
  {
    if (IS_DEBUG_TE(FEED_DOWN))
      zlog_debug("[DBG] ENNI_TO_INNI_LINK%s: OSPF INNI not found", (flush == 1) ? " (flush)" : "");
    goto out;
  }
  if (ospf_inni->router_id.s_addr == htonl(0))
  {
    if (IS_DEBUG_TE(FEED_DOWN))
      zlog_debug("[DBG] ENNI_TO_INNI_LINK%s: OSPF INNI router id is not configured", (flush == 1) ? " (flush)" : "");
    goto out;
  }
  if ((ospf_enni = ospf_enni_lookup()) == NULL)
  {
    if (IS_DEBUG_TE(FEED_DOWN))
      zlog_debug("[DBG] ENNI_TO_INNI_LINK%s: OSPF ENNI not found", (flush == 1) ? " (flush)" : "");
    goto out;
  }
  if (ospf_enni->router_id.s_addr == htonl(0))
  {
    if (IS_DEBUG_TE(FEED_DOWN))
      zlog_debug("[DBG] ENNI_TO_INNI_LINK%s: OSPF ENNI router id is not configured", (flush == 1) ? " (flush)" : "");
    goto out;
  }
  if (&ospf_enni->lsdb == NULL)
  {
    zlog_warn("[WRN] ENNI_TO_INNI_LINK%s: LSDB not found", (flush == 1) ? " (flush)" : "");
    goto out;
  }

  for(ALL_LIST_ELEMENTS(ospf_inni->areas, node, nnode, tmp_area))
    if (tmp_area->area_id.s_addr == lsa->area->area_id.s_addr)
      area = tmp_area;

  if (area == NULL)
  {
    zlog_warn("[WRN] ENNI_TO_INNI_LINK%s: Can't find appropriate area in OSPF INNI", (flush == 1) ? " (flush)" : "");
    goto out;
  }

  if ((lsa_new = ospf_lsa_new ()) == NULL)
  {
    zlog_warn("[WRN] ENNI_TO_INNI_LINK%s: Creating new LSA failed", (flush == 1) ? " (flush)" : "");
    goto out;
  }

  if ((lsa_new->data = ospf_lsa_data_new (length+sizeof(struct te_link_subtlv_anc_rc_id))) == NULL)
  {
    zlog_warn("[WRN] ENNI_TO_INNI_LINK%s: ospf_lsa_data_new() failed", (flush == 1) ? " (flush)" : "");
    ospf_lsa_unlock (&lsa_new);
    goto out;
  }

  memcpy (lsa_new->data, lsa->data, OSPF_LSA_HEADER_SIZE); /* length value may be not correct */
  memcpy (TLV_HDR_TOP(lsa_new->data), (char *)(lsa->data) + link_start, ntohs(tlvh->length) + 4);

  struct te_link_subtlv_link_id *tlv_link;
  tlv_link = (struct te_link_subtlv_link_id*)(te_subtlv_lookup(lsa_new, TE_TLV_LINK, TE_LINK_SUBTLV_LINK_ID));
  if (tlv_link != NULL)
  {
    if (IPV4_ADDR_SAME(&ospf_enni->router_id, &tlv_link->value))
    {
      tlv_link->value.s_addr = 0;
    }
  }

  struct te_link_subtlv_anc_rc_id ancestor;
  struct te_link_subtlv_anc_rc_id *ancestor_ptr = (struct te_link_subtlv_anc_rc_id *) te_subtlv_lookup(lsa_new, TE_TLV_LINK, TE_LINK_SUBTLV_ANC_RC_ID);
  if (ancestor_ptr == NULL)
  {
    ancestor_ptr = &ancestor;
    ancestor.header.type = htons(TE_LINK_SUBTLV_ANC_RC_ID);
    ancestor.header.length = htons(4);
    if (IPV4_ADDR_SAME(&ospf_enni->router_id, &lsa->data->adv_router))
    {
      ancestor.value.s_addr = 0;
      zlog_err("[ERR] ENNI_TO_INNI_LINK%s: Feed down self originated in level 1 opaque", (flush == 1) ? " (flush)" : "");
    }
    else
      ancestor.value.s_addr = lsa->data->adv_router.s_addr;

    memcpy ((char *)TLV_HDR_TOP(lsa_new->data) + ntohs(tlvh->length) + 4, (char *)(&ancestor), sizeof(struct te_link_subtlv_anc_rc_id));

    lsa_new->data->length = htons(length + sizeof(struct te_link_subtlv_anc_rc_id));

    struct te_tlv_header *tlvh_new     = (struct te_tlv_header *)((char *) (lsa_new->data) + link_start);
    tlvh_new->length = htons(ntohs(tlvh->length) + sizeof(struct te_link_subtlv_anc_rc_id));
  }
/*  else
  {
    ancestor_ptr->header.type = htons(TE_LINK_SUBTLV_ANC_RC_ID);
    ancestor_ptr->header.length = htons(4);
    if (IPV4_ADDR_SAME(&ospf_enni->router_id, &lsa->data->adv_router))
    {
      ancestor_ptr->value.s_addr = 0;
      zlog_err("[ERR] enni_to_inni_link: feed down self originated in level 1 opaque");
    }
    else
      ancestor_ptr->value.s_addr = lsa->data->adv_router.s_addr;
  } */

  if (lsa_new == NULL)
  {
    zlog_warn ("[WRN] ENNI_TO_INNI_LINK%s: lsa_new == NULL", (flush == 1) ? " (flush)" : "");
    goto out;
  }

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
  lsa_new->data->id.s_addr  = htonl(map_inni(lsa->data->adv_router, lsa->data->id.s_addr));
  lsa_new->data->adv_router = ospf_inni->router_id;

/*
  if (IS_DEBUG_TE(FEED_DOWN))
  {
    struct in_addr tmp;
    tmp.s_addr = lsa_new->data->id.s_addr;
    zlog_debug("[DBG] INNI_TO_ENNI_LINK%s: registering opaque %s", (flush == 1) ? " (flush)" : "", inet_ntoa(tmp));
  }
  register_opaque_lsa(lsa_new);
*/
  if (flush == 0)
  {
    if (IS_DEBUG_TE(FEED_DOWN))
    {
      char buf[50];
      log_summary_te_lsa(buf, lsa_new);
      zlog_debug("[DBG] ENNI_TO_INNI_LINK: Installing new LSA %s with ancestor %s", buf, inet_ntoa(ancestor_ptr->value));
    }
    ospf_lsa_checksum (lsa_new->data);
    ospf_lsa_install(ospf_inni, NULL, lsa_new);
    ospf_flood_through_area (area, NULL/*nbr*/, lsa_new);
  }
  else
  {
    if (IS_DEBUG_TE(FEED_DOWN))
    {
      char buf[50];
      log_summary_te_lsa(buf, lsa_new);
      struct in_addr tmp;
      tmp.s_addr = lsa_new->data->id.s_addr;
      zlog_debug("[DBG] ENNI_TO_INNI_LINK: Flushing (LSA %s id %s age %d -> %d) ospf_opaque_lsa_flush_schedule", buf, inet_ntoa(tmp), ntohs(lsa->data->ls_age), OSPF_LSA_MAXAGE);
    }
    lsa_new->data->ls_age = htons(OSPF_LSA_MAXAGE);
    ospf_lsa_checksum (lsa_new->data);
    ospf_opaque_lsa_flush_schedule(lsa_new);
  }
out:
  ;
//  if (IS_DEBUG_TE(FEED_DOWN))
//    zlog_debug("[DBG] ENNI_TO_INNI_LINK: OK");
}

static void uni_to_inni_tna(struct ospf_lsa *lsa, struct te_tlv_tna_addr *tna_tlv, int flush)
{
  struct ospf *ospf_uni, *ospf_inni;
  if ((ospf_uni = ospf_uni_lookup()) == NULL)
  {
    if (IS_DEBUG_TE(UNI_TO_INNI))
      zlog_debug("[DBG] UNI_TO_INNI_TNA%s: OSPF UNI not found", (flush == 1) ? " (flush)" : "");
    goto out;
  }
  if (ospf_uni->router_id.s_addr == htonl(0))
  {
    if (IS_DEBUG_TE(UNI_TO_INNI))
      zlog_debug("[DBG] UNI_TO_INNI_TNA%s: OSPF UNI router id is not configured", (flush == 1) ? " (flush)" : "");
    goto out;
  }
  if ((ospf_inni = ospf_inni_lookup()) == NULL)
  {
    if (IS_DEBUG_TE(UNI_TO_INNI))
      zlog_debug("[DBG] UNI_TO_INNI_TNA%s: OSPF INNI not found", (flush == 1) ? " (flush)" : "");
    goto out;
  }
  if (ospf_inni->router_id.s_addr == htonl(0))
  {
    if (IS_DEBUG_TE(UNI_TO_INNI))
      zlog_debug("[DBG] UNI_TO_INNI_TNA%s: OSPF INNI router id is not configured", (flush == 1) ? " (flush)" : "");
    goto out;
  }
  if (&ospf_inni->lsdb == NULL)
  {
    zlog_warn("[WRN] UNI_TO_INNI_TNA%s: LSDB not found", (flush == 1) ? " (flush)" : "");
    goto out;
  }

  struct ospf_area *area    = NULL;
  struct ospf_area *tmp_area;
  struct zlistnode *node, *nnode;
  for(ALL_LIST_ELEMENTS(ospf_inni->areas, node, nnode, tmp_area))
    if (tmp_area->area_id.s_addr == lsa->area->area_id.s_addr)
      area = tmp_area;

  if (area == NULL)
  {
    zlog_warn("[WRN] UNI_TO_INNI_TNA%s: Can't find appropriate area in OSPF INNI", (flush == 1) ? " (flush)" : "");
    goto out;
  }

  struct ospf_lsa  *lsa_new = copy_lsa_by_Tlv_ptr(lsa, (struct te_tlv_header *) tna_tlv);

  if (lsa_new == NULL)
  {
    zlog_warn("[WRN] UNI_TO_INNI_TNA%s: lsa_new == NULL", (flush == 1) ? " (flush)" : "");
    goto out;
  }

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
  lsa_new->data->id.s_addr  = htonl(map_inni(lsa->data->adv_router, lsa->data->id.s_addr));
  lsa_new->data->adv_router = ospf_inni->router_id;

/*
  register_opaque_lsa(lsa_new);
*/

  if (IS_DEBUG_TE(UNI_TO_INNI))
  {
    struct in_addr tmp;
    tmp.s_addr = lsa_new->data->id.s_addr;
    char buf[50];
    log_summary_te_lsa(buf, lsa_new);
    zlog_debug("[DBG] UNI_TO_INNI_TNA: %s (%s id %s)", (flush == 0) ? "Installing new LSA" : "Flushing LSA", buf, inet_ntoa(tmp));
  }

  if (flush == 0)
  {
    ospf_lsa_checksum (lsa_new->data);
    ospf_lsa_install(ospf_inni, NULL, lsa_new);
    ospf_flood_through_area (area, NULL/*nbr*/, lsa_new);
  }
  else
  {
    if (IS_DEBUG_TE(UNI_TO_INNI))
    {
      char buf[50];
      log_summary_te_lsa(buf, lsa_new);
      struct in_addr tmp;
      tmp.s_addr = lsa_new->data->id.s_addr;
      zlog_debug("[DBG] UNI_TO_INNI_TNA flush: (LSA %s id %s age %d -> %d) ospf_opaque_lsa_flush_schedule", buf, inet_ntoa(tmp), ntohs(lsa->data->ls_age), OSPF_LSA_MAXAGE);
    }
    lsa_new->data->ls_age = htons(OSPF_LSA_MAXAGE);
    ospf_lsa_checksum (lsa_new->data);
    ospf_opaque_lsa_flush_schedule(lsa_new);
  }
out:
  ;
//  if (IS_DEBUG_TE(UNI_TO_INNI))
//    zlog_debug("[DBG] UNI_TO_INNI_TNA%s: OK", (flush == 1) ? " flush" : "");
}

static void inni_to_uni_tna(struct ospf_lsa *lsa, struct te_tlv_tna_addr *tna_tlv, int flush)
{
  struct ospf *ospf_inni, *ospf_uni;
  if ((ospf_uni = ospf_uni_lookup()) == NULL)
  {
    if (IS_DEBUG_TE(INNI_TO_UNI))
      zlog_debug("[DBG] INNI_TO_UNI_TNA%s: OSPF UNI not found", (flush == 1) ? " flush" : "");
    goto out;
  }
  if (ospf_uni->router_id.s_addr == htonl(0))
  {
    if (IS_DEBUG_TE(INNI_TO_UNI))
      zlog_debug("[DBG] INNI_TO_UNI_TNA%s: OSPF UNI router id is not configured", (flush == 1) ? " flush" : "");
    goto out;
  }

  if ((ospf_inni = ospf_inni_lookup()) == NULL)
  {
    if (IS_DEBUG_TE(INNI_TO_UNI))
      zlog_debug("[DBG] INNI_TO_UNI_TNA%s: Ospf INNI not found", (flush == 1) ? " flush" : "");
    goto out;
  }
  if (ospf_inni->router_id.s_addr == htonl(0))
  {
    if (IS_DEBUG_TE(INNI_TO_UNI))
      zlog_debug("[DBG] INNI_TO_UNI_TNA%s: Ospf INNI router id is not configured", (flush == 1) ? " flush" : "");
    goto out;
  }
  if (&ospf_inni->lsdb == NULL)
  {
    zlog_warn("[WRN] INNI_TO_UNI_TNA%s: LSDB not found", (flush == 1) ? " flush" : "");
    goto out;
  }

  struct ospf_area *area    = NULL;
  struct ospf_area *tmp_area;
  struct zlistnode *node, *nnode;
  for(ALL_LIST_ELEMENTS(ospf_uni->areas, node, nnode, tmp_area))
    if (tmp_area->area_id.s_addr == lsa->area->area_id.s_addr)
      area = tmp_area;

  if (area == NULL)
  {
    zlog_warn("[WRN] INNI_TO_UNI_TNA%s: Can't find appropriate area in OSPF INNI", (flush == 1) ? " flush" : "");
    goto out;
  }

  struct ospf_lsa  *lsa_new = copy_lsa_by_Tlv_ptr(lsa, (struct te_tlv_header *)tna_tlv);

  if (lsa_new == NULL)
  {
    zlog_warn("[WRN] INNI_TO_UNI_TNA%s: lsa_new == NULL", (flush == 1) ? " flush" : "");
    goto out;
  }

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
  lsa_new->data->id.s_addr  = htonl(map_uni(lsa->data->adv_router, lsa->data->id.s_addr));
  lsa_new->data->adv_router = ospf_uni->router_id;

/*
  if (IS_DEBUG_TE(INNI_TO_UNI))
  {
    struct in_addr tmp;
    tmp.s_addr = lsa_new->data->id.s_addr;
    zlog_debug("[DBG] INNI_TO_UNI_TNA%s: registering opaque %s", (flush == 1) ? " flush" : "", inet_ntoa(tmp));
  }
  register_opaque_lsa(lsa_new);
*/

  if (flush == 0)
  {
    if (IS_DEBUG_TE(INNI_TO_UNI))
    {
      char buf[50];
      log_summary_te_lsa(buf, lsa_new);
      struct in_addr tmp;
      tmp.s_addr = lsa_new->data->id.s_addr;
      zlog_debug("[DBG] INNI_TO_UNI_TNA: Installing new (LSA %s, id %s)", buf, inet_ntoa(tmp));
    }
    ospf_lsa_checksum (lsa_new->data);
    ospf_lsa_install(ospf_uni, NULL, lsa_new);
    ospf_flood_through_area (area, NULL/*nbr*/, lsa_new);
  }
  else
  {
    if (IS_DEBUG_TE(INNI_TO_UNI))
    {
      char buf[50];
      log_summary_te_lsa(buf, lsa_new);
      struct in_addr tmp;
      tmp.s_addr = lsa_new->data->id.s_addr;
      zlog_debug("[DBG] INNI_TO_UNI_TNA flush: Flushing (LSA %s id %s age %d -> %d) ospf_opaque_lsa_flush_schedule", buf, inet_ntoa(tmp), ntohs(lsa->data->ls_age), OSPF_LSA_MAXAGE);
    }
    lsa_new->data->ls_age = htons(OSPF_LSA_MAXAGE);
    ospf_lsa_checksum (lsa_new->data);

    ospf_opaque_lsa_flush_schedule(lsa_new);
  }
out:
  ;
//  if (IS_DEBUG_TE(INNI_TO_UNI))
//    zlog_debug("[DBG] INNI_TO_UNI_TNA%s: OK", (flush == 1) ? " flush" : "");
}

static int ospf_te_new_lsa(struct ospf_lsa *lsa)
{
  /* Check the opaque id */ 
  if ((((ntohl(lsa->data->id.s_addr)) >> 24) & 0xFF) != OPAQUE_TYPE_TRAFFIC_ENGINEERING_LSA)
  {
    goto out;
  }
  if (lsa->data->type != OSPF_OPAQUE_AREA_LSA)
  {
    char buf[200];
    log_summary_te_lsa(buf, lsa);
    zlog_warn("[WRN] OSPF_TE_NEW_LSA: Ignoring non OSPF_OPAQUE_AREA_LSA TE opaques (LSA: %s, id %s)", buf, inet_ntoa(lsa->data->id));
    goto out;
  }

  if ((IS_DEBUG_TE(USER)) || (IS_DEBUG_TE(READ_IFP)))
  {
    char lsa_info_buf[200];
    log_summary_te_lsa(lsa_info_buf, lsa);
    zlog_debug("[DBG] OSPF_TE_NEW_LSA: TE LSA (%s, id %s) %s added to OSPF %s database", lsa_info_buf, inet_ntoa(lsa->data->id), IS_LSA_MAXAGE (lsa) ? "MAXAGE " : "", OSPF_INST_TO_STR(lsa->area->ospf->instance));
  }

  register_opaque_lsa(lsa);
  int pos;
  uint16_t length;

  char buf[50];
  struct te_tlv_tna_addr *tna_tlv;

  switch (lsa->area->ospf->instance)
  {
    case INNI:

      #if USE_UNTESTED_OSPF_TE_CORBA_UPDATE
      if (IS_DEBUG_TE(CORBA_UPDATE))
        zlog_debug("[DBG] CORBA: Received new TE LSA");

      update_corba_te_inf(ADD_TO_SERVER, lsa);  // Update G2PCERA information
      #endif /* USE_UNTESTED_OSPF_TE_CORBA_UPDATE */

/* INNI -> UNI */
      if ((CHECK_FLAG (lsa->instance_copy, OSPF_LSA_FROM_UNI_COPY) == 0) && (ospf_uni_lookup() != NULL))
      {
        if ((tna_tlv = (struct te_tlv_tna_addr*) te_tlv_lookup(lsa, TE_TLV_TNA_ADDR)) != NULL)
        {
          struct ospf *ospf_inni = ospf_inni_lookup();
          if (ospf_inni != NULL)
          {
            inni_to_uni_tna(lsa, tna_tlv, 0);
/*            if (lsa->data->adv_router.s_addr != ospf_inni->router_id.s_addr)
            {
              if (IS_DEBUG_TE(INNI_TO_UNI))
              {
                log_summary_te_tna(buf, tna_tlv);
                zlog_debug("[DBG] INNI_TO_UNI: lsa %s", buf);
              }
              inni_to_uni_tna(lsa, tna_tlv, 0);
            }
            else
            {
              if (IS_DEBUG_TE(FEED_DOWN))
              {
                log_summary_te_tna(buf, tna_tlv);
                zlog_debug("[DBG] INNI_TO_UNI: skipped because INNI router id = LSA adv router (LSA %s)", buf);
              }
            }*/
          }
        }
      }
/* INNI -> ENNI */
      if ((CHECK_FLAG (lsa->instance_copy, OSPF_LSA_FROM_ENNI_COPY) == 0) && (ospf_enni_lookup() != NULL))
      {
         struct te_tlv_tna_addr *tna_tlv = (struct te_tlv_tna_addr*) te_tlv_lookup(lsa, TE_TLV_TNA_ADDR);
         if (tna_tlv != NULL)
         {
           if (IS_DEBUG_TE(FEED_UP))
           {
             char buf[50];
             log_summary_te_tna(buf, tna_tlv);
             zlog_debug("[DBG] INNI_TO_ENNI: lsa %s", buf);
           }
           inni_to_enni_tna(lsa, tna_tlv, 0);
         }

        if ((pos = has_lsa_tlv_type(lsa, TE_TLV_LINK, &length)) > 0)
        {
          if (length > 0)
          {
            if (IS_DEBUG_TE(FEED_UP))
            {
              char buf[50];
              struct te_tlv_link *link_tlv = (struct te_tlv_link *) te_tlv_lookup(lsa, TE_TLV_LINK);
              log_summary_te_link(buf, link_tlv);
              zlog_debug("[DBG] INNI_TO_ENNI: LSA type: LINK --> %s", buf);
            }
            inni_to_enni_link(lsa, pos, 0);
          }
          else if (IS_DEBUG_TE(FEED_UP))
            zlog_debug("[DBG] INNI_TO_ENNI: LSA type: LINK --> Skipped because TE_TLV_LINK TLV length == 0");
        }
      }
      break;
    case ENNI:
/* ENNI -> INNI */
      if ((CHECK_FLAG (lsa->instance_copy, OSPF_LSA_FROM_INNI_COPY) == 0) && (ospf_inni_lookup() != NULL))
      {
        if ((tna_tlv = (struct te_tlv_tna_addr *) te_tlv_lookup(lsa, TE_TLV_TNA_ADDR)) != NULL)
        {
          struct ospf *ospf_enni = ospf_enni_lookup();
          if (ospf_enni != NULL)
          {
            if (lsa->data->adv_router.s_addr != ospf_enni->router_id.s_addr)
            {
              if (IS_DEBUG_TE(FEED_DOWN))
              {
                log_summary_te_tna(buf, tna_tlv);
                zlog_debug("[DBG] ENNI_TO_INNI: lsa %s, adv router %s", buf, inet_ntoa(lsa->data->adv_router));
              }
              enni_to_inni_tna(lsa, tna_tlv, 0);
            }
            else
            {
              if (IS_DEBUG_TE(FEED_DOWN))
              {
                log_summary_te_tna(buf, tna_tlv);
                zlog_debug("[DBG] ENNI_TO_INNI: skipped because ENNI router id = LSA adv router (LSA %s)", buf);
              }
            }
          }
        }
        if ((pos = has_lsa_tlv_type(lsa, TE_TLV_LINK, &length)) > 0)
        {
          if (length > 0)
          {
            if (IS_DEBUG_TE(FEED_DOWN))
            {
              char buf[50];
              struct te_tlv_link *link_tlv = (struct te_tlv_link *) te_tlv_lookup(lsa, TE_TLV_LINK);
              log_summary_te_link(buf, link_tlv);
              zlog_debug("[DBG] ENNI_TO_INNI: LSA type: LINK --> %s", buf);
            }
            enni_to_inni_link(lsa, pos, 0);
          }
          else if (IS_DEBUG_TE(FEED_DOWN))
            zlog_debug("[DBG] ENNI_TO_INNI: LSA type: LINK --> Skipped because TE_TLV_TNA_ADDR TLV length = 0");
        }
      }
      break;
    case UNI:
      if ((CHECK_FLAG (lsa->instance_copy, OSPF_LSA_FROM_INNI_COPY) == 0) && (ospf_inni_lookup() != NULL))
      {
        if ((tna_tlv = (struct te_tlv_tna_addr*) te_tlv_lookup(lsa, TE_TLV_TNA_ADDR)) != NULL)
        {
          if (IS_DEBUG_TE(UNI_TO_INNI))
          {
            log_summary_te_tna(buf, tna_tlv);
            zlog_debug("[DBG] UNI_TO_INNI: lsa %s", buf);
          }
          uni_to_inni_tna(lsa, tna_tlv, 0);
        }
      }
      else if (ospf_inni_lookup() != NULL)
      {
        if ((tna_tlv = (struct te_tlv_tna_addr*) te_tlv_lookup(lsa, TE_TLV_TNA_ADDR)) != NULL)
        {
          if (IS_DEBUG_TE(UNI_TO_INNI))
          {
            log_summary_te_tna(buf, tna_tlv);
            zlog_debug("[DBG] UNI_TO_INNI: skipped lsa %s is copy from INNI", buf);
          }
        }
      }
      break;
    default:
      zlog_err("[ERR] OSPF_TE_NEW_LSA: Unknown interface");
      goto out;
  }
/*
  UNSET_FLAG(lsa->instance_copy, OSPF_LSA_FROM_UNI_COPY);
  UNSET_FLAG(lsa->instance_copy, OSPF_LSA_FROM_INNI_COPY);
  UNSET_FLAG(lsa->instance_copy, OSPF_LSA_FROM_ENNI_COPY); */
out:
  return 0;
}

static int ospf_te_del_lsa(struct ospf_lsa *lsa)
{
  char buf[50];
  if ((IS_DEBUG_TE(USER)) || (IS_DEBUG_TE(LSA_DELETE)) || IS_DEBUG_TE(CORBA_UPDATE) || (IS_DEBUG_TE(CORBA_SET)))
  {
    log_summary_te_lsa(buf, lsa);
  }

  if ((((ntohl(lsa->data->id.s_addr)) >> 24) & 0xFF) != OPAQUE_TYPE_TRAFFIC_ENGINEERING_LSA)
  {
    goto out;
  }

  if (ntohs(lsa->data->ls_age) != OSPF_LSA_MAXAGE)
    goto out;

  if (IS_DEBUG_TE(LSA_DELETE))
  {
    zlog_debug("[DBG] OSPF_TE_DEL_LSA: OSPF instance: %s, LSA age: %d", SHOW_ADJTYPE(lsa->area->ospf->instance), ntohs(lsa->data->ls_age));
  }
#if USE_UNTESTED_OSPF_TE
  uint16_t pos;
  uint16_t length;

  struct te_tlv_tna_addr *tna_tlv;
  switch (lsa->area->ospf->instance)
  {
    case UNI:
      if ((CHECK_FLAG (lsa->instance_copy, OSPF_LSA_FROM_INNI_COPY) == 0)  && (ospf_inni_lookup() != NULL))
      {
        if ((tna_tlv = (struct te_tlv_tna_addr*) te_tlv_lookup(lsa, TE_TLV_TNA_ADDR)) != NULL)
        {
          if (IS_DEBUG_TE(LSA_DELETE))
            zlog_debug("[DBG] OSPF_TE_DEL_LSA: OSPF interface: UNI, side: NETWORK, LSA: %s", buf);
          uni_to_inni_tna(lsa, tna_tlv, 1);
        }
      }
      break;

    case INNI:

      #if USE_UNTESTED_OSPF_TE_CORBA_UPDATE
      if (IS_DEBUG_TE(CORBA_UPDATE))
      {
        zlog_debug("[DBG] CORBA: Removing TE LSA (%s)", buf);
      }
      update_corba_te_inf(REMOVE_FROM_SERVER, lsa);  // Update G2PCERA information
      #endif /* USE_UNTESTED_OSPF_TE_CORBA_UPDATE */

      if (CHECK_FLAG (lsa->instance_copy, OSPF_LSA_FROM_ENNI_COPY) == 0)
      {
        if (((pos = has_lsa_tlv_type(lsa, TE_TLV_LINK, &length)) > 0) && (ospf_enni_lookup() != NULL))
        {
          if (length > 0)
          {
            if ((IS_DEBUG_TE(USER)) || (IS_DEBUG_TE(CORBA_SET)) || (IS_DEBUG_TE(LSA_DELETE)))
            {
              zlog_debug("[DBG] OSPF_TE_DEL_LSA: Removing LSA (%s) opaque from OSPF ENNI instance", buf);
            }
            inni_to_enni_link(lsa, pos, 1);
          }
        }
        if (((tna_tlv = (struct te_tlv_tna_addr*) te_tlv_lookup(lsa, TE_TLV_TNA_ADDR)) != NULL) && (ospf_enni_lookup() != NULL))
        {
          if ((IS_DEBUG_TE(USER)) || (IS_DEBUG_TE(CORBA_SET)) || (IS_DEBUG_TE(LSA_DELETE)))
          {
            zlog_debug("[DBG] OSPF_TE_DEL_LSA: Removing LSA (%s) opaque from OSPF ENNI instance", buf);
          }
          inni_to_enni_tna(lsa, tna_tlv, 1);
        }
      }
      if ((CHECK_FLAG (lsa->instance_copy, OSPF_LSA_FROM_UNI_COPY) == 0) && (ospf_uni_lookup() != NULL))
      {
        if ((tna_tlv = (struct te_tlv_tna_addr*)te_tlv_lookup(lsa, TE_TLV_TNA_ADDR)) != NULL)
        {
          if (length > 0)
          {
            if ((IS_DEBUG_TE(USER)) || (IS_DEBUG_TE(CORBA_SET)) || (IS_DEBUG_TE(LSA_DELETE)))
            {
              zlog_debug("[DBG] OSPF_TE_DEL_LSA: Removing LSA (%s) opaque from OSPF UNI instance", buf);
            }
            inni_to_uni_tna(lsa, tna_tlv, 1);
          }
        }
      }
      break;

    case ENNI:
      if (CHECK_FLAG (lsa->instance_copy, OSPF_LSA_FROM_INNI_COPY) == 0)
      {
        if ((pos = has_lsa_tlv_type(lsa, TE_TLV_LINK, &length)) > 0)
        {
          enni_to_inni_link(lsa, pos, 1);
        }
      }
      if (CHECK_FLAG (lsa->instance_copy, OSPF_LSA_FROM_INNI_COPY) == 0)
      {
        if (((tna_tlv = (struct te_tlv_tna_addr*) te_tlv_lookup(lsa, TE_TLV_TNA_ADDR)) != NULL) && (ospf_inni_lookup() != NULL))
        {
          if ((IS_DEBUG_TE(USER)) || (IS_DEBUG_TE(CORBA_SET)) || (IS_DEBUG_TE(LSA_DELETE)))
          {
            zlog_debug("[DBG] OSPF_TE_DEL_LSA: Removing LSA (%s) opaque from OSPF INNI instance", buf);
          }
          enni_to_inni_tna(lsa, tna_tlv, 1);
        }
      }
      break;

    default:
      zlog_warn("[WRN] OSPF_TE_DEL_LSA: Unknown interface");
      goto out;
  }
/*UNSET_FLAG(lsa->instance_copy, OSPF_LSA_FROM_UNI_COPY);
  UNSET_FLAG(lsa->instance_copy, OSPF_LSA_FROM_INNI_COPY);
  UNSET_FLAG(lsa->instance_copy, OSPF_LSA_FROM_ENNI_COPY);*/

#endif /* USE_UNTESTED_OSPF_TE */

out:
  return 0;
}

/**
 * Adding new structure te_link to OspfTE assosiated with new interface. If such structure exists, function do nothing.
 * Creating and setting new structure te_link.
 * @param ifp - pointer to noe interface that is being added to te system
 * @return 0 - succes, -1 memory allocation problem 
 */

static int
ospf_te_new_if (struct interface *ifp)
{
  if (ifp == NULL)
  {
    zlog_err("[ERR] OSPF_TE_NEW_IF: Interface ptr is NULL");
    return -1;
  }

  /** For gmpls, g2mpls there is separated data and controll plane. PC's interfaces belongs to the control plane */
//  if (OspfTE.architecture_type != mpls)
//    return 0;

  if (strcmp(ifp->name, "Level1")==0)
  {
    zlog_debug("[DBG] OSPF_TE_NEW_IF: Skipping creation of te-link for %s interface", ifp->name);
    return 0;
    struct ospf *ospf = ospf_enni_get();

    if (ospf != NULL)
    {
      if (!CHECK_FLAG (ospf->config, OSPF_OPAQUE_CAPABLE))
      {
        SET_FLAG (ospf->config, OSPF_OPAQUE_CAPABLE);
        ospf_renegotiate_optional_capabilities (ospf);
      }
    }
  }

  if (IS_DEBUG_TE(USER))
    zlog_debug("[DBG] OSPF_TE_NEW_IF: Adding new te-link (interface: %s, ospf: %s, adj_type: %s)", ifp->name, OSPF_INST_TO_STR(ifp->ospf_instance), OSPF_INST_TO_STR(ifp->adj_type));

  struct te_link *new;
  int rc = -1;

/*  if ((new = lookup_linkparams_by_ifp (ifp))!= NULL)
  {
    if (IS_DEBUG_TE(REFRESH))
      zlog_debug ("updating te_link information concerned with interface %s", ifp->name);
    rc = 0; // Do nothing here. 
    //goto updateInterfaceData;
  }
  else
    zlog_warn ("[WRN] Can not find appropriate te-link");
*/
  if ((new = XMALLOC (MTYPE_OSPF_TE_LINKPARAMS,
                  sizeof (struct te_link))) == NULL)
  {
    zlog_warn ("[WRN] OSPF_TE_NEW_IF: XMALLOC: %s", safe_strerror (errno));
    goto out;
  }
  memset (new, 0, sizeof (struct te_link));

  new->area = NULL;
  new->flags = 0;
  new->instance_li = get_te_instance_value ();
  new->instance_tna = get_te_instance_value ();
  new->ifp = ifp;

  initialize_linkparams (new);

  listnode_add (OspfTE.iflist, new);

  /* Schedule Opaque-LSA refresh. *//* XXX */

  rc = 0;

  struct zlistnode *node, *nnode;
  struct ospf_area *area;
  struct ospf_interface *oi = lookup_oi_by_ifp(ifp, NULL, OI_ANY);
  if (oi != NULL)
  {
    for (ALL_LIST_ELEMENTS (oi->ospf->areas, node, nnode, area))
      ospf_te_lsa_originate(area);
  }
out:
  assing_new_interface_to_harmony_te_links();
  return rc;

//updateInterfaceData:
  //read_te_linkparams_from_ifp(new);
  //rc=0;
  //return rc;
}

static struct te_link*
ospf_te_new_harmony_if()
{
  if (IS_DEBUG_TE(USER))
    zlog_debug("[DBG] Adding new harmony te-link");

  struct te_link *new;
  if ((new = XMALLOC (MTYPE_OSPF_TE_LINKPARAMS,
                  sizeof (struct te_link))) == NULL)
  {
    zlog_warn ("[WRN] ospf_te_new_harmony_if: XMALLOC: %s", safe_strerror (errno));
    return NULL;
  }
  memset (new, 0, sizeof (struct te_link));

  if (OspfTE.harmonyIfp != NULL)
  {
    struct ospf_interface *oi = lookup_oi_by_ifp(OspfTE.harmonyIfp, NULL, OI_ANY);
    new->area = oi->area;
  }

  new->flags = 0;
  new->instance_li = get_te_instance_value ();
  new->instance_tna = get_te_instance_value ();
  new->ifp = OspfTE.harmonyIfp;
  new->harmony_ifp = 1;

  listnode_add (OspfTE.harmonyIflist, new);
  return new;
}

static struct raHarmony*
new_ra_harmony(struct in_addr ra, uint32_t area_id)
{
  struct raHarmony* rah = XMALLOC(MTYPE_OSPF_TE_RA_HARMONY, sizeof(struct raHarmony));
  if (rah == NULL)
  {
    zlog_warn("[WRN] new_ra_harmony: XMALLOC: %s", safe_strerror(errno));
    return NULL; 
  }

  memset(rah, 0, sizeof(struct raHarmony));

  u_int16_t length = 0;

  rah->router_addr.router_addr.header.type   = htons(TE_ROUTER_ADDR_SUBTLV_ROUTER_ADDR);
  rah->router_addr.router_addr.header.length = htons(sizeof(struct in_addr));
  rah->router_addr.router_addr.value = ra;
  length += TLV_SIZE(&rah->router_addr.router_addr.header);

  rah->router_addr.aa_id.header.type   = htons(TE_ROUTER_ADDR_SUBTLV_AA_ID);
  rah->router_addr.aa_id.header.length = htons(4);
  rah->router_addr.aa_id.area_id = area_id;
  length += TLV_SIZE(&rah->router_addr.aa_id.header);

  rah->router_addr.link_header.header.type = htons(TE_TLV_ROUTER_ADDR);
  rah->router_addr.link_header.header.length = htons(length);

  rah->instance_id = get_te_instance_value();
  listnode_add(OspfTE.harmonyRaList, rah);
  return rah;
}

static uint16_t
log_summary_te_link(char *buf, struct te_tlv_link *link_tlv)
{
  struct te_tlv_header *tlvh1;
  struct te_tlv_header *tlvh = (struct te_tlv_header*) link_tlv;
  struct te_link_subtlv_lclif_ipaddr     *lcllif;
  struct te_link_subtlv_link_lcl_rmt_ids *lclid;
  struct in_addr tmp;

  uint16_t sum = 0;
  uint16_t l = ntohs (link_tlv->header.length);
  sprintf(buf, "TE link length %d", l);

  for (tlvh1 = tlvh+1; sum < l; tlvh1 = TLV_HDR_NEXT (tlvh1))
  {
    switch (ntohs (tlvh1->type))
    {
      case TE_LINK_SUBTLV_LCLIF_IPADDR:
        lcllif = (struct te_link_subtlv_lclif_ipaddr *) tlvh1;
        sprintf(buf, "TE link: %s",  inet_ntoa (lcllif->value[0]));
        break;
      case TE_LINK_SUBTLV_LINK_LCL_RMT_IDS:
        lclid = (struct te_link_subtlv_link_lcl_rmt_ids *) tlvh1;
        tmp.s_addr = lclid->local_id;
        sprintf(buf, "TE link: %s", inet_ntoa(tmp));
        break;
    }
    sum +=TLV_SIZE (tlvh1);
  }
  return sum;
}

static uint16_t
log_summary_te_tna(char *buf, struct te_tlv_tna_addr *tna_tlv)
{
  uint16_t sum                = 0;
  uint16_t l                  = ntohs (tna_tlv->header.length);

  struct te_tlv_header                    *tlvh  = (struct te_tlv_header *) tna_tlv;
  struct te_tlv_header                    *tlvh1;
  struct te_tna_addr_subtlv_tna_addr_ipv4 *tna_ipv4;

  sprintf(buf, "TNA without address (length %d)", l);
  for (tlvh1 = tlvh+1; sum < l; tlvh1 = TLV_HDR_NEXT (tlvh1))
  {
    switch (ntohs (tlvh1->type))
    {
      case TE_TNA_ADDR_SUBTLV_TNA_ADDR_IPV4:
        tna_ipv4 = (struct te_tna_addr_subtlv_tna_addr_ipv4 *) tlvh1;
        sprintf(buf, "TNA: %s",  inet_ntoa(tna_ipv4->value));
        break;
      case TE_TNA_ADDR_SUBTLV_TNA_ADDR_IPV6:
        sprintf(buf, "TNA IPv6");
        break;
      case TE_TNA_ADDR_SUBTLV_TNA_ADDR_NSAP:
        sprintf(buf, "TNA NSAP");
        break;
      default:
        break;
    }
    sum += TLV_SIZE (tlvh1);
  }
  return sum;
}

static void
log_summary_te_lsa(char *buf, struct ospf_lsa *lsa)
{
  struct lsa_header                         *lsah = (struct lsa_header *) lsa->data;
  struct te_tlv_header                      *tlvh = TLV_HDR_TOP (lsah);
//  struct te_tlv_link                        *top;
  struct te_router_addr                     *top_routerLSA;
//  struct te_tna_addr_subtlv_tna_addr_ipv4   *tna_ipv4;
//  struct te_tlv_header                      *tlvh1, *next = NULL;
//  struct te_link_subtlv_lclif_ipaddr        *lcllif;
//  struct te_link_subtlv_link_lcl_rmt_ids    *lclid;

  sprintf(buf, "UNKNOWN (type %d, length %d)", ntohs(tlvh->type), ntohs(tlvh->length));

//  u_int16_t l;
  u_int16_t sum = 0;
//  struct in_addr tmp;

  switch (ntohs (tlvh->type))
  {
    case TE_TLV_ROUTER_ADDR:
      top_routerLSA = (struct te_router_addr *)(tlvh);
      sprintf(buf, "RouterAddr: %s", inet_ntoa(top_routerLSA->router_addr.value));
      break;
    case TE_TLV_NODE_ATTR:
      //TODO
      sprintf(buf, "Node Attr");
      break;
    case TE_TLV_LINK:
      sum+=log_summary_te_link(buf, (struct te_tlv_link *)tlvh);
      break;
    case TE_TLV_TNA_ADDR:
      sum += log_summary_te_tna(buf, (struct te_tlv_tna_addr *)tlvh);
      break;
    default:
      break;
  }
}

/**
 * Deleting structure te_link associated with specyfied interface.
 * Remowing te_link from list
 */

static int
ospf_te_del_if (struct interface *ifp)
{
  if (ifp == OspfTE.harmonyIfp)
    assing_new_interface_to_harmony_te_links();

  if (IS_DEBUG_TE(USER))
    zlog_debug("[DBG] OSPF_TE_DEL_IF: Deleting te-link (interface: %s, ospf: %s, adj_type: %s)", ifp->name, OSPF_INST_TO_STR(ifp->ospf_instance), OSPF_INST_TO_STR(ifp->adj_type));

  struct te_link *lp;
  int rc = -1;

  while ((lp = lookup_linkparams_by_ifp (ifp)) != NULL)
  {
    struct zlist *iflist = OspfTE.iflist;

    /* Dequeue listnode entry from the list. */
    listnode_delete (iflist, lp);

    /* Avoid misjudgement in the next lookup. */
    if (listcount (iflist) == 0)
      iflist->head = iflist->tail = NULL;

    XFREE (MTYPE_OSPF_TE_LINKPARAMS, lp);
  }

  /* Schedule Opaque-LSA refresh. *//* XXX */

  rc = 0;
/*out:*/
  return rc;
}

static void flush_neighbor_opaques(struct ospf_interface *oi)
{
  struct zlistnode *node, *nnode;
  struct te_link *lp;
  for(ALL_LIST_ELEMENTS(OspfTE.iflist, node, nnode, lp))
  {
    if (oi->ifp != lp->ifp)
      continue;
    if ((lp->flags & LPFLG_LSA_LI_ENGAGED) && (lp->area))
    {
      zlog_debug("[DBG] Flushing LINK opaque (interface: %s)", oi->ifp->name);
      ospf_te_lsa_schedule (lp, FLUSH_THIS_LSA, LINK);
      lp->flags &= ~LPFLG_LSA_LI_ENGAGED;
    }
    if ((lp->flags & LPFLG_LSA_TNA_ENGAGED) && (lp->area))
    {
      zlog_debug("[DBG] Flushing TNA opaque (interface: %s)", oi->ifp->name);
      ospf_te_lsa_schedule (lp, FLUSH_THIS_LSA, TNA_ADDRESS);
      lp->flags &= ~LPFLG_LSA_TNA_ENGAGED;
    }
  }
  zlog_debug("[DBG] Flushing neighbous opaques OK");
}

/**
 * changing the state of the ospf interface
 * @param *oi pointer to the ospf interface
 * @param  old_state
 */
static void
ospf_te_ism_change (struct ospf_interface *oi, int old_state)
{
  struct te_link_subtlv_link_type old_type;
  struct te_link_subtlv_link_id   old_id;
  struct te_link *lp;

  if(IS_DEBUG_TE(ISM_CHANGE))
  {
    zlog_debug("[DEB] ISM change %s -> %s interface %s", 
          LOOKUP (ospf_ism_state_msg, old_state),
          LOOKUP (ospf_ism_state_msg, oi->state),
          oi->ifp->name);
  }

  if(oi->ifp == OspfTE.harmonyIfp)
  {
    struct zlistnode *node, *nnode;
    struct te_link *lp;
    for (ALL_LIST_ELEMENTS(OspfTE.harmonyIflist, node, nnode, lp))
    {
      lp->area = oi->area;
      if (lp->flags & LPFLG_LSA_LI_ENGAGED)
        ospf_te_lsa_schedule (lp, REFRESH_THIS_LSA, LINK);
      else
        ospf_te_lsa_schedule (lp, REORIGINATE_PER_AREA, LINK);
    }
  }

  if ((lp = lookup_linkparams_by_ifp (oi->ifp)) == NULL)
  {
    if (oi->ifp->ospf_instance == ENNI)
    {
      struct zlistnode *node, *nnode;
      struct te_link *lp;
      for (ALL_LIST_ELEMENTS(OspfTE.iflist, node, nnode, lp))
      {
        if ((lp->ifp->adj_type==ENNI) && (lp->area))
        {
          if (lp->flags & LPFLG_LSA_LI_ENGAGED)
          {
            if(IS_DEBUG_TE(ISM_CHANGE))
            {
              zlog_debug("[DEB] ISM change refreshing TE-LINK (ENNI interface %s)", lp->ifp->name); 
            }
            ospf_te_lsa_schedule (lp, REFRESH_THIS_LSA, LINK);
          }
          else
          {
            if(IS_DEBUG_TE(ISM_CHANGE))
            {
              zlog_debug("[DEB] ISM change reoriginate TE-LINK (ENNI interface %s)", lp->ifp->name); 
            }
            ospf_te_lsa_schedule (lp, REORIGINATE_PER_AREA, LINK);
          }
        }
      }
      goto out;
    }
    else
    {
      zlog_warn ("[WRN] ospf_te_ism_change: Cannot get linkparams from OI(%s)?", IF_NAME (oi));
      goto out;
    }
  }
  if (oi->area == NULL || oi->area->ospf == NULL)
  {
    zlog_warn ("[WRN] ospf_te_ism_change: Cannot refer to OSPF from OI(%s)?", IF_NAME (oi));
    goto out;
  }
#ifdef notyet
  if ((lp->area != NULL
  &&   ! IPV4_ADDR_SAME (&lp->area->area_id, &oi->area->area_id))
  || (lp->area != NULL && oi->area == NULL))
  {
      /* How should we consider this case? */
      zlog_warn ("[WRN] ospf_te_ism_change: Area for OI(%s) has changed to [%s], flush previous LSAs", IF_NAME (oi), oi->area ? inet_ntoa (oi->area->area_id) : "N/A");
      ospf_te_ra_lsa_schedule (FLUSH_THIS_LSA, oi->ospf, lp->area);
  }
#endif
  /* Keep Area information in conbination with linkparams. */
  lp->area = oi->area;

  switch (oi->state)
  {
    case ISM_PointToPoint:
    case ISM_DROther:
    case ISM_Backup:
    case ISM_DR:
      old_type = lp->link_type;
      old_id   = lp->link_id;

      set_linkparams_link_type (oi, lp);
#ifndef GMPLS
      set_linkparams_link_id (oi, lp);
#endif /* GMPLS */

      if ((lp->area) && ((ntohs (old_type.header.type) != ntohs (lp->link_type.header.type)
      ||   old_type.link_type.value     != lp->link_type.link_type.value)
      ||  (ntohs (old_id.header.type)   != ntohs (lp->link_id.header.type)
      ||   ntohl (old_id.value.s_addr)  != ntohl (lp->link_id.value.s_addr))))
      {
        if (lp->flags & LPFLG_LSA_LI_ENGAGED)
        {
          if(IS_DEBUG_TE(ISM_CHANGE))
          {
            zlog_debug("[DEB] ISM change refreshing TE-LINK (interface %s)", lp->ifp->name); 
          }
          ospf_te_lsa_schedule (lp, REFRESH_THIS_LSA, LINK);
        }
        else
        {
          if(IS_DEBUG_TE(ISM_CHANGE))
          {
            zlog_debug("[DEB] ISM change refreshing TE-LINK (interface %s)", lp->ifp->name); 
          }
          ospf_te_lsa_schedule (lp, REORIGINATE_PER_AREA, LINK);
        }
      }
      if (lp->area != NULL)
      {
        if (OspfTE.ra_engaged[lp->ifp->ospf_instance])
        {
          if(IS_DEBUG_TE(ISM_CHANGE))
          {
            zlog_debug("[DEB] ISM change refreshing ROUTER ADDRESS (interface %s)", lp->ifp->name); 
          }
          ospf_te_ra_lsa_schedule(REFRESH_THIS_LSA, lp->area->ospf, lp->area);
        }
        else
        {
          if(IS_DEBUG_TE(ISM_CHANGE))
          {
            zlog_debug("[DEB] ISM change reoriginating ROUTER ADDRESS (interface %s)", lp->ifp->name);
          }
          ospf_te_ra_lsa_schedule(REORIGINATE_PER_AREA, lp->area->ospf, lp->area);
        }
      }
      break;
    default:
//      flush_neighbor_opaques(oi);
      lp->link_type.header.type = htons (0);
      lp->link_id.header.type   = htons (0);

      if ((lp->flags & LPFLG_LSA_LI_ENGAGED) && (lp->area))
      {
        if(IS_DEBUG_TE(ISM_CHANGE))
        {
          zlog_debug("[DEB] ISM change flushing TE-LINK (interface %s)", lp->ifp->name); 
        }
        ospf_te_lsa_schedule (lp, FLUSH_THIS_LSA, LINK);
      }
      if ((lp->ifp->ospf_instance == UNI) && (lp->flags & LPFLG_LSA_TNA_ENGAGED) && (lp->area))
      {
        if(IS_DEBUG_TE(ISM_CHANGE))
        {
          zlog_debug("[DEB] ISM change flushing TNA ADDRESS (interface %s)", lp->ifp->name); 
        }
        ospf_te_lsa_schedule (lp, FLUSH_THIS_LSA, TNA_ADDRESS);
      }
      break;
  }
out:
  return;
}

static void
originate_tna_without_clients(struct ospf *ospf)
{
  struct zlistnode  *node, *nnode;
  struct ospf_area *area;

  for (ALL_LIST_ELEMENTS (ospf->areas, node, nnode, area))
    ospf_te_lsa_originate(area);

  return;
}

static void
ospf_te_nsm_change (struct ospf_neighbor *nbr, int old_state)
{
  struct ospf      *top = oi_to_top (nbr->oi);
  struct ospf *ospf_inni = ospf_inni_lookup();

  if (top == NULL)
    return;

  if (CHECK_FLAG (top->opaque, OPAQUE_OPERATION_READY_BIT))
  {
    if (IS_DEBUG_TE(NSM_CHANGE))
      zlog_debug("[DBG] NSM_STATE_CHANGE: %s->%s ospf_te_nsm_change callback function.",
        LOOKUP (ospf_nsm_state_msg, old_state),
        LOOKUP (ospf_nsm_state_msg, nbr->state));

    if (IS_OPAQUE_LSA_ORIGINATION_BLOCKED (top->opaque))
    {
      if (IS_DEBUG_TE(NSM_CHANGE))
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
          if ((((((ntohl(lsa->data->id.s_addr)) >> 24) & 0xFF) != OPAQUE_TYPE_TRAFFIC_ENGINEERING_LSA))
               || (ntohs(lsa->data->ls_age) >= OSPF_LSA_MAXAGE))
             continue;

          if (lsa->data->adv_router.s_addr == nbr->router_id.s_addr)              /* LSA was generated by deleted neighbour */
          {
            if ((IS_DEBUG_TE(NSM_CHANGE))||(IS_DEBUG_TE(USER)))
            {
              char buf[50];
              log_summary_te_lsa(buf, lsa);
              struct in_addr temp;
              temp.s_addr = lsa->data->id.s_addr;
              zlog_debug("[DBG] NSM_STATE_CHANGE: %s -> %s flushing opaque (%s, id %s) generated by not existing neighbor (ospf %s)",
                LOOKUP (ospf_nsm_state_msg, old_state),
                LOOKUP (ospf_nsm_state_msg, nbr->state),
                buf,
                inet_ntoa(temp),
                OSPF_INST_TO_STR(top->instance));
            }
//          ospf_opaque_lsa_flush_schedule(lsa);
            lsa->data->ls_age = htons (OSPF_LSA_MAXAGE);
            ospf_lsa_maxage (top, lsa);
          }
          else if ((top->instance == UNI)                                          /* UNI-Client has been deleted */
                && (lsa->data->adv_router.s_addr == top->router_id.s_addr)         /* LSA LSA was generated by us (not by deleted neighbour) */  
                && (ospf_inni != NULL))                                            /* We have ospf INNI instance */
          {
            struct te_tlv_tna_addr* tna_tlv;
            if ((tna_tlv = (struct te_tlv_tna_addr*) te_tlv_lookup(lsa, TE_TLV_TNA_ADDR)) != NULL)
            {
              int tna_match = 0;
              struct te_tlv_header                    *tlvh      = (struct te_tlv_header *) tna_tlv;
              struct te_tlv_header                    *tlvh1;
              struct te_tna_addr_subtlv_node_id       *tna_node_id;
              uint16_t                                l          = ntohs (tna_tlv->header.length);
              uint16_t                                sum        = 0;
              for (tlvh1 = tlvh+1; sum < l; tlvh1 = TLV_HDR_NEXT (tlvh1))
              {
                switch (ntohs (tlvh1->type))
                {
                  case TE_TNA_ADDR_SUBTLV_NODE_ID:
                    tna_node_id = (struct te_tna_addr_subtlv_node_id *) tlvh1;
                    if (tna_node_id->value.s_addr == ospf_inni->router_id.s_addr)
                    {
                      tna_match = 1;
                      sum = l;
                    }
                    break;
                  default:
                    break;
                }
                sum += TLV_SIZE (tlvh1);
              }
              if (tna_match == 1)
              {
                if ((IS_DEBUG_TE(NSM_CHANGE))||(IS_DEBUG_TE(USER)))
                {
                  char buf[50];
                  log_summary_te_lsa(buf, lsa);
                  struct in_addr temp;
                  temp.s_addr = lsa->data->id.s_addr;
                  zlog_debug("[DBG] NSM_STATE_CHANGE: %s -> %s flushing TNA (%s, id %s) with information about client that is DOWN",
                    LOOKUP (ospf_nsm_state_msg, old_state),
                    LOOKUP (ospf_nsm_state_msg, nbr->state),
                    buf,
                    inet_ntoa(temp));
                }
                //lsa->data->ls_age = htons (OSPF_LSA_MAXAGE);
                //ospf_lsa_maxage (top, lsa);
                struct te_link *lp = lookup_linkparams_by_instance(lsa);
                if (lp != NULL)
                {
                  if (IS_DEBUG_TE(NSM_CHANGE))
                  {
                    zlog_debug("[DBG] NSM_STATE_CHANGE (%s): clearing flag TNA ENGAGED", lp->ifp->name);
                  }
                  lp->flags &= ~LPFLG_LSA_TNA_ENGAGED;
                }
                ospf_opaque_lsa_flush_schedule(lsa);
              }
            }
          }
        }
      }
    }
    else
    {
      struct te_link *lp=lookup_linkparams_by_ifp(nbr->oi->ifp);
      if (lp != NULL) 
      {
        if ((OspfTE.status == enabled) && (lp->area != NULL))
        {
          if (IS_DEBUG_TE(NSM_CHANGE))
            zlog_debug("[DBG] NSM_STATE_CHANGE: NSM force te opaque originating");
          if (lp->flags & LPFLG_LSA_LI_ENGAGED)
          {
            ospf_te_lsa_schedule (lp, REFRESH_THIS_LSA, LINK);
            if (IS_DEBUG_TE(REFRESH))
              zlog_debug("[DBG] NSM_STATE_CHANGE: ospf_te_lsa_schedule (lp, REFRESH_THIS_LSA, LINK)");
          }
          else
          {
            ospf_te_lsa_schedule (lp, REORIGINATE_PER_AREA, LINK);
            if (IS_DEBUG_TE(REFRESH))
              zlog_debug("[DBG] NSM_STATE_CHANGE: ospf_te_lsa_schedule (lp, REORIGINATE_PER_AREA, LINK)");
          }

          if (lp->flags & LPFLG_LSA_TNA_ENGAGED)
          {
            ospf_te_lsa_schedule (lp, REFRESH_THIS_LSA, TNA_ADDRESS);
            if (IS_DEBUG_TE(REFRESH))
              zlog_debug("[DBG] NSM_STATE_CHANGE: ospf_te_lsa_schedule (lp, REFRESH_THIS_LSA, TNA_ADDRESS)");
          }
          else
          {
            ospf_te_lsa_schedule (lp, REORIGINATE_PER_AREA, TNA_ADDRESS);
            if (IS_DEBUG_TE(REFRESH))
            zlog_debug("[DBG] NSM_STATE_CHANGE: ospf_te_lsa_schedule (lp, REORIGINATE_PER_AREA, TNA_ADDRESS)");
          }

          if (OspfTE.ra_engaged[(int)lp->ifp->ospf_instance] == 1)
          {
            ospf_te_ra_lsa_schedule (REFRESH_THIS_LSA, top, lp->area);
            if (IS_DEBUG_TE(REFRESH))
              zlog_debug("[DBG] NSM_STATE_CHANGE: ospf_te_ra_lsa_schedule REORIGINATE_PER_AREA instance %d", lp->ifp->ospf_instance);
          }
          else
          {
            ospf_te_ra_lsa_schedule (REORIGINATE_PER_AREA, top, lp->area);
            if (IS_DEBUG_TE(REFRESH))
              zlog_debug("[DBG] NSM_STATE_CHANGE: ospf_te_ra_lsa_schedule REORIGINATE_PER_AREA instance %d", lp->ifp->ospf_instance);
          }

          if (OspfTE.na_engaged[(int)lp->ifp->ospf_instance] == 1)
          {
            ospf_te_na_lsa_schedule (REFRESH_THIS_LSA, top, lp->area);
            if (IS_DEBUG_TE(REFRESH))
              zlog_debug("[DBG] NSM_STATE_CHANGE: ospf_te_na_lsa_schedule (REFRESH_THIS_LSA, top, lp->area)");
          }
          else
          {
            ospf_te_na_lsa_schedule (REORIGINATE_PER_AREA, top, lp->area);
            if (IS_DEBUG_TE(REFRESH))
              zlog_debug("[DBG] NSM_STATE_CHANGE: ospf_te_na_lsa_schedule (REORIGINATE_PER_AREA, top, lp->area)");
          }
        }
      }
    }
  }
  else
  {
    if (IS_DEBUG_TE(NSM_CHANGE))
      zlog_debug("[DBG] NSM_STATE_CHANGE: %s->%s ospf_te_nsm_change callback function, neighbor's OSPF is still not operational",
    LOOKUP (ospf_nsm_state_msg, old_state),
    LOOKUP (ospf_nsm_state_msg, nbr->state));
    if (nbr->state == NSM_Down)
    {
      struct route_node *rn;
      struct ospf_lsa   *lsa;

      struct ospf_area  *area;
      struct zlistnode  *node;
      for (ALL_LIST_ELEMENTS_RO (top->areas, node, area))
      {
        LSDB_LOOP (OPAQUE_AREA_LSDB (area), rn, lsa)
        {
          if (lsa->data->adv_router.s_addr == top->router_id.s_addr)
          {
            if ((IS_DEBUG_TE(NSM_CHANGE))||(IS_DEBUG_TE(USER)))
            {
              char buf[50];
              log_summary_te_lsa(buf, lsa);
              struct in_addr temp;
              temp.s_addr = lsa->data->id.s_addr;
              zlog_debug("[DBG] NSM_STATE_CHANGE: %s -> %s flushing opaque (%s, id %s) generated by not existing neighbor (ospf %s)",
                LOOKUP (ospf_nsm_state_msg, old_state),
                LOOKUP (ospf_nsm_state_msg, nbr->state),
                buf,
                inet_ntoa(temp),
                OSPF_INST_TO_STR(top->instance));
            }
            ospf_opaque_lsa_flush_schedule(lsa);
          }
        }
      }
    }
  }

  if ((top->instance == ENNI) && (nbr->state == NSM_Full))
  {
    struct ospf *ospf = ospf_inni_lookup();
    if (ospf == NULL)
    {
      zlog_warn("[WRN] NSM_STATE_CHANGE: OSPF INNI not found");
      return;
    }
    if (top->lsdb == NULL)
    {
      zlog_warn("[WRN] NSM_STATE_CHANGE: OSPF ENNI have no Link State Database");
      return;
    }

    struct route_node *rn;
    struct ospf_lsa   *lsa;
    struct ospf_area  *area;
    struct zlistnode  *node, *nnode;
    struct te_link    *lp;

    for (ALL_LIST_ELEMENTS_RO (ospf->areas, node, area))
    {
      LSDB_LOOP (OPAQUE_AREA_LSDB (area), rn, lsa)
      {
        struct te_link_subtlv_link_id  *link_id_tlvh = (struct te_link_subtlv_link_id*) te_subtlv_lookup(lsa, TE_TLV_LINK, TE_LINK_SUBTLV_LINK_ID);
        if (link_id_tlvh != NULL)
        {
          struct in_addr link_id       = link_id_tlvh->value;

          int found_rc_in_enni         = is_router_id_in_ospf(ENNI, link_id);
          int found_adv_router_in_inni = is_router_id_in_ospf(INNI, lsa->data->adv_router);

          if ((found_adv_router_in_inni == 1)  /*adv router is from INNI domain*/
              && !IPV4_ADDR_SAME(&ospf->router_id, &lsa->data->adv_router) /* but no router with RC (this router) */
              && (found_rc_in_enni == 1))      /*te-link is interdomain link */
          {
            if (IS_DEBUG_TE(NSM_CHANGE))
            {
              char lsa_info_buf[200];
              log_summary_te_lsa(lsa_info_buf, lsa);
              zlog_debug("[DBG] NSM_STATE_CHANGE: OSPF ENNI state changed, feeding up LSA (%s)", lsa_info_buf);
            }
            uint16_t lsa_sub_len;
            int tlv_pos = has_lsa_tlv_type(lsa, TE_TLV_LINK, &lsa_sub_len);
            inni_to_enni_link(lsa, tlv_pos, 0);
          }
        }
      }
    }
    for (ALL_LIST_ELEMENTS (OspfTE.iflist, node, nnode, lp))
    {
      if ((lp->area != NULL) && (lp->ifp->ospf_instance == INNI) && (lp->ifp->adj_type == ENNI))
      {
        if (lp->flags & LPFLG_LSA_LI_ENGAGED)
          ospf_te_lsa_schedule (lp, REFRESH_THIS_LSA, LINK);
        else
          ospf_te_lsa_schedule (lp, REORIGINATE_PER_AREA, LINK);
      }
    }
  }

  if ((top->instance == INNI) && (nbr->state == NSM_Full))
  {
    struct ospf *ospf_uni = ospf_uni_lookup();
    if (ospf_uni != NULL)
    {
//        if ((ospf_uni->interface_side == NETWORK) && (ospf_uni->read_tna == 1))
      if (ospf_uni->read_tna == 1)
      {
        originate_tna_without_clients(ospf_uni);
      }
    }
  }
  if ((top->instance == ENNI) && (nbr->state == NSM_Full))
  {
    struct ospf *ospf = ospf_enni_lookup();
    if (ospf != NULL)
    {
//        if ((ospf_uni->interface_side == NETWORK) && (ospf_uni->read_tna == 1))
      if (ospf->read_tna == 1)
      {
        originate_tna_without_clients(ospf);
      }
    }
  }

  /* So far, nothing to do here. */
  return;
}

/*------------------------------------------------------------------------*
 * Followings are OSPF protocol processing functions for MPLS-TE.
 *------------------------------------------------------------------------*/

static void
build_tlv_header (struct stream *s, struct te_tlv_header *tlvh)
{
  stream_put (s, tlvh, sizeof (struct te_tlv_header));
  return;
}

/** ************************************************************ */

static void
build_router_addr_subtlv_router_addr_ptr (struct stream *s, struct te_router_addr_subtlv_router_addr *ra_subtlv)
{
  struct te_tlv_header *tlvh = &ra_subtlv->header;
  if ((ntohs (tlvh->type) != 0) && (ntohs (tlvh->length) != 0))
  {
    build_tlv_header (s, tlvh);
    stream_put (s, tlvh+1, TLV_BODY_SIZE (tlvh));
  }
  else if (IS_DEBUG_TE(GENERATE))
  {
    zlog_debug("[DBG] build_router_addr_subtlv_router_addr_ptr: Skipped - type = %d, length = %d", ntohs(tlvh->type), ntohs(tlvh->length));
  }
  return;
}

static void
build_router_addr_subtlv_router_addr (struct stream *s, uint16_t instance_no)
{
  if ((uint16_t)instance_no > 2)
  {
    zlog_err("[ERR] build_router_addr_subtlv_router_addr: Wrong instance no: %d", instance_no);
    return;
  }
  struct te_router_addr_subtlv_router_addr *ra_subtlv = &OspfTE.router_addr[instance_no].router_addr;
  build_router_addr_subtlv_router_addr_ptr(s, ra_subtlv);
}

static void
build_router_addr_subtlv_aa_id_ptr (struct stream *s, struct te_router_addr_subtlv_aa_id *aa_subtlv)
{
  struct te_tlv_header *tlvh = &aa_subtlv->header;
  if ((ntohs (tlvh->type) != 0) && (ntohs (tlvh->length) != 0))
  {
    build_tlv_header (s, tlvh);
    stream_put (s, tlvh+1, TLV_BODY_SIZE (tlvh));
  }
  return;
}

static void            /** Associated Area ID */
build_router_addr_subtlv_aa_id (struct stream *s, uint16_t instance_no)
{
  if ((uint16_t)instance_no > 2)
  {
    zlog_err("[ERR] build_router_addr_subtlv_aa_id: Wrong instance no: %d", instance_no);
    return;
  }
  struct te_router_addr_subtlv_aa_id *aa_subtlv = &OspfTE.router_addr[instance_no].aa_id;
  build_router_addr_subtlv_aa_id_ptr (s, aa_subtlv);
  return;
}

/** *********** Geysers extenstions *************************************** */

static void
build_router_addr_subtlv_power_consumption_ptr (struct stream *s, struct te_router_addr_subtlv_power_consumption *power_subtlv)
{
  //zlog_debug("Building router power consumption TLV with value %d", (u_int32_t) ntohl(power_subtlv->power_consumption));
  struct te_tlv_header *tlvh = &power_subtlv->header;
  if ((ntohs (tlvh->type) != 0) && (ntohs (tlvh->length) != 0))
  {
    build_tlv_header (s, tlvh);
    stream_put (s, tlvh+1, TLV_BODY_SIZE (tlvh));
    //zlog_debug("Router power consumption written to OSPF packet");
  }
  return;
}

static void            /** Power consumption */
build_router_addr_subtlv_power_consumption (struct stream *s, uint16_t instance_no)
{
  if ((uint16_t)instance_no > 2)
  {
    zlog_err("[ERR] build_router_addr_subtlv_power_consumption: Wrong instance no: %d", instance_no);
    return;
  }
  struct te_router_addr_subtlv_power_consumption *power_subtlv = &OspfTE.router_addr[instance_no].power_consumption;
  build_router_addr_subtlv_power_consumption_ptr (s, power_subtlv);
  return;
}

static void
build_router_addr_tlv (struct stream *s, uint16_t instance_no)
{
  if (instance_no > 2)
  {
    zlog_err("[ERR] build_router_addr_tlv: Wrong instance no: %d", instance_no);
    return;
  }

  set_linkparams_router_addr_header (instance_no);
  build_tlv_header (s, &OspfTE.router_addr[instance_no].link_header.header);

  if (IS_DEBUG_TE(GENERATE))
    zlog_debug("[DBG] build_router_addr_tlv: RA_INSTANCE: %s", OSPF_INST_TO_STR(instance_no));
  build_router_addr_subtlv_router_addr (s, instance_no);
  build_router_addr_subtlv_aa_id (s, instance_no);
  build_router_addr_subtlv_power_consumption (s, instance_no);
  return;
}

/** ******************************************* */

static void            /** Local TE Router ID */
build_node_attr_subtlv_lcl_te_router_id (struct stream *s, uint16_t instance_no)
{
  struct te_tlv_header *tlvh;

  tlvh = &OspfTE.node_attr[instance_no].lcl_te_router_id.header;

  if ((ntohs (tlvh->type) != 0) && (ntohs (tlvh->length) != 0))
  {
    build_tlv_header (s, tlvh);
    stream_put (s, tlvh+1, TLV_BODY_SIZE (tlvh));
  }
  return;
}

static void            /** Associated Area ID */
build_node_attr_subtlv_aa_id (struct stream *s, uint16_t instance_no)
{
  struct te_tlv_header *tlvh = &OspfTE.node_attr[instance_no].aa_id.header;
  if ((ntohs (tlvh->type) != 0) && (ntohs (tlvh->length) != 0))
  {
    build_tlv_header (s, tlvh);
    stream_put (s, tlvh+1, TLV_BODY_SIZE (tlvh));
  }
  return;
}

static void
build_node_attr_subtlv_node_ip4_lcl_prefix (struct stream *s, uint16_t instance_no)
{
  struct te_tlv_header *tlvh = &OspfTE.node_attr[instance_no].node_ip4_lcl_prefix.header;
  if ((ntohs (tlvh->type) != 0) && (ntohs (tlvh->length) != 0))
  {
    build_tlv_header (s, tlvh);

    struct zlistnode *node, *nnode;
    struct prefix_ip4 *pref_ip4;
    for (ALL_LIST_ELEMENTS (&OspfTE.node_attr[instance_no].node_ip4_lcl_prefix.prefix_list, node, nnode, pref_ip4))
    {
      stream_put(s, pref_ip4, (sizeof (struct prefix_ip4)));
    }
  }
  return;
}

static void
build_node_attr_subtlv_node_ip6_lcl_prefix (struct stream *s, uint16_t instance_no)
{
  struct te_tlv_header *tlvh = &OspfTE.node_attr[instance_no].node_ip6_lcl_prefix.header;
  if ((ntohs (tlvh->type) != 0) && (ntohs (tlvh->length) != 0))
  {
    build_tlv_header (s, tlvh);

    struct zlistnode *node, *nnode;
    struct prefix_ip6 *pref_ip6;
    for (ALL_LIST_ELEMENTS (&OspfTE.node_attr[instance_no].node_ip6_lcl_prefix.prefix_list, node, nnode, pref_ip6))
    {
      stream_put(s, pref_ip6, (sizeof (struct prefix_ip6)));
    }
  }
  return;
}

static void
build_node_attr_tlv (struct stream *s, uint16_t instance_no)
{
  if (instance_no > 2)
  {
    zlog_err("[ERR] build_node_attr_tlv: Wrong instance no: %d", instance_no);
    return;
  }

  if (IS_DEBUG_TE(GENERATE))
    zlog_debug("[DBG] build_node_attr_tlv");

  set_linkparams_node_attr_header (instance_no);
  build_tlv_header (s, &OspfTE.node_attr[instance_no].link_header.header);

  build_node_attr_subtlv_node_ip4_lcl_prefix (s, instance_no);
  build_node_attr_subtlv_node_ip6_lcl_prefix (s, instance_no);
  build_node_attr_subtlv_lcl_te_router_id (s, instance_no);
  build_node_attr_subtlv_aa_id (s, instance_no);
  return;
}

/** ************************************************************************** */

static void
build_tna_addr_subtlv_tna_addr_ipv4 (struct stream *s, struct te_tna_addr_subtlv_tna_addr_ipv4 *tna_addr_ipv4)
{
  struct te_tlv_header *tlvh = &tna_addr_ipv4->header;
  if ((ntohs (tlvh->type) != 0) && (ntohs (tlvh->length) != 0))
  {
    build_tlv_header (s, tlvh);
    stream_put (s, tlvh+1, TLV_BODY_SIZE (tlvh));
  }
  return;
}

static void
build_tna_addr_subtlv_tna_addr_ipv6 (struct stream *s, struct te_tna_addr_subtlv_tna_addr_ipv6 *tna_addr_ipv6)
{
  struct te_tlv_header *tlvh = &tna_addr_ipv6->header;
  if ((ntohs (tlvh->type) != 0) && (ntohs (tlvh->length) != 0))
  {
    build_tlv_header (s, tlvh);
    stream_put (s, tlvh+1, TLV_BODY_SIZE (tlvh));
  }
  return;
}

static void
build_tna_addr_subtlv_tna_addr_nsap (struct stream *s, struct te_tna_addr_subtlv_tna_addr_nsap *tna_addr_nsap)
{
  struct te_tlv_header *tlvh = &tna_addr_nsap->header;
  if ((ntohs (tlvh->type) != 0) && (ntohs (tlvh->length) != 0))
  {
    build_tlv_header (s, tlvh);
    stream_put (s, tlvh+1, TLV_BODY_SIZE (tlvh));
  }
  return;
}

static void
build_tna_addr_subtlv_node_id (struct stream *s, struct te_tna_addr_subtlv_node_id *node_id)
{
  struct te_tlv_header *tlvh = &node_id->header;
  if ((ntohs (tlvh->type) != 0) && (ntohs (tlvh->length) != 0))
  {
    build_tlv_header (s, tlvh);
    stream_put (s, tlvh+1, TLV_BODY_SIZE (tlvh));
  }
  return;
}

static void
build_tna_addr_subtlv_anc_rc_id (struct stream *s, struct te_tna_addr_subtlv_anc_rc_id *anc_rc_id)
{
  struct te_tlv_header *tlvh = &anc_rc_id->header;
  if ((ntohs (tlvh->type) != 0) && (ntohs (tlvh->length) != 0))
  {
    build_tlv_header (s, tlvh);
    stream_put (s, tlvh+1, TLV_BODY_SIZE (tlvh));
  }
  return;
}

static void
build_tna_addr_tlv (struct stream *s, struct te_link *lp)
{
  //set_linkparams_tna_addr_header (lp);

  struct zlistnode *node;
  struct tna_addr_data_element *l_value;
  struct zlistnode *node_in;
  struct tna_addr_value *l_value_in;

  build_tlv_header (s, &lp->tna_address.header);

  for (ALL_LIST_ELEMENTS_RO (&lp->tna_address.tna_addr_data, node, l_value))
  {
    build_tna_addr_subtlv_node_id (s, &l_value->node_id);     /** Node ID */
    for (ALL_LIST_ELEMENTS_RO (&l_value->tna_addr, node_in, l_value_in))
    {
      build_tna_addr_subtlv_tna_addr_ipv4 (s, &l_value_in->tna_addr_ipv4);    /** TNA Address IPv4 */
      build_tna_addr_subtlv_tna_addr_ipv6 (s, &l_value_in->tna_addr_ipv6);    /** TNA Address IPv6 */
      build_tna_addr_subtlv_tna_addr_nsap (s, &l_value_in->tna_addr_nsap);    /** TNA Address NSAP */
    }
    build_tna_addr_subtlv_anc_rc_id (s, &l_value->anc_rc_id); /** Ancestor RC ID */
  }
  return;
}


/** ************************************************************************** */
static void
build_link_subtlv_link_type (struct stream *s, struct te_link *lp)
{
  struct te_tlv_header *tlvh = &lp->link_type.header;
  if ((ntohs (tlvh->type) != 0) && (ntohs (tlvh->length) != 0))
    {
      build_tlv_header (s, tlvh);
      stream_put (s, tlvh+1, TLV_BODY_SIZE (tlvh));
    }
  return;
}

static void
build_link_subtlv_link_id (struct stream *s, struct te_link *lp)
{
  struct te_tlv_header *tlvh = &lp->link_id.header;
  if ((ntohs (tlvh->type) != 0) && (ntohs (tlvh->length) != 0))
    {
      build_tlv_header (s, tlvh);
      stream_put (s, tlvh+1, TLV_BODY_SIZE (tlvh));
    }
  return;
}

static void
build_link_subtlv_lclif_ipaddr (struct stream *s, struct te_link *lp)
{
  struct te_tlv_header *tlvh = (struct te_tlv_header *) &lp->lclif_ipaddr;
  if (tlvh != NULL && ntohs (tlvh->type) != 0 && (ntohs (tlvh->length) != 0))
  {
    build_tlv_header (s, tlvh);
    stream_put (s, tlvh+1, TLV_BODY_SIZE (tlvh));
  }
  return;
}

static void
build_link_subtlv_rmtif_ipaddr (struct stream *s, struct te_link *lp)
{
  struct te_tlv_header *tlvh = (struct te_tlv_header *) &lp->rmtif_ipaddr;
  if (tlvh != NULL && ntohs (tlvh->type) != 0 && (ntohs (tlvh->length) != 0))
    {
      build_tlv_header (s, tlvh);
      stream_put (s, tlvh+1, TLV_BODY_SIZE (tlvh));
    }
  return;
}

static void
build_link_subtlv_te_metric (struct stream *s, struct te_link *lp)
{
  struct te_tlv_header *tlvh = &lp->te_metric.header;
  if ((ntohs (tlvh->type) != 0) && (ntohs (tlvh->length) != 0))
    {
      build_tlv_header (s, tlvh);
      stream_put (s, tlvh+1, TLV_BODY_SIZE (tlvh));
    }
  return;
}

static void
build_link_subtlv_max_bw (struct stream *s, struct te_link *lp)
{
  struct te_tlv_header *tlvh = &lp->max_bw.header;
  if ((ntohs (tlvh->type) != 0) && (ntohs (tlvh->length) != 0))
    {
      build_tlv_header (s, tlvh);
      stream_put (s, tlvh+1, TLV_BODY_SIZE (tlvh));
    }
  return;
}

static void
build_link_subtlv_max_rsv_bw (struct stream *s, struct te_link *lp)
{
  struct te_tlv_header *tlvh = &lp->max_rsv_bw.header;
  if ((ntohs (tlvh->type) != 0) && (ntohs (tlvh->length) != 0))
    {
      build_tlv_header (s, tlvh);
      stream_put (s, tlvh+1, TLV_BODY_SIZE (tlvh));
    }
  return;
}

static void
build_link_subtlv_unrsv_bw (struct stream *s, struct te_link *lp)
{
  struct te_tlv_header *tlvh = &lp->unrsv_bw.header;
  if ((ntohs (tlvh->type) != 0) && (ntohs (tlvh->length) != 0))
    {
      build_tlv_header (s, tlvh);
      stream_put (s, tlvh+1, TLV_BODY_SIZE (tlvh));
    }
  return;
}

static void
build_link_subtlv_rsc_clsclr (struct stream *s, struct te_link *lp)
{
  struct te_tlv_header *tlvh = &lp->rsc_clsclr.header;
  if ((ntohs (tlvh->type) != 0) && (ntohs (tlvh->length) != 0))
  {
    build_tlv_header (s, tlvh);
    stream_put (s, tlvh+1, TLV_BODY_SIZE (tlvh));
  }
  return;
}

static void                                       /* Link Local/Remote Identifiers */
build_link_subtlv_link_lcl_rmt_ids (struct stream *s, struct te_link *lp)
{
  struct te_tlv_header *tlvh = &lp->link_lcl_rmt_ids.header;
  if ((ntohs (tlvh->type) != 0) && (ntohs (tlvh->length) != 0))
  {
    build_tlv_header (s, tlvh);
    stream_put (s, tlvh+1, TLV_BODY_SIZE (tlvh));
  }
  return;
}

static void                                       /* Link Protection Type */
build_link_subtlv_link_protect_type (struct stream *s, struct te_link *lp)
{
  struct te_tlv_header *tlvh = &lp->link_protect_type.header;
  if ((ntohs (tlvh->type) != 0) && (ntohs (tlvh->length) != 0))
    {
      build_tlv_header (s, tlvh);
      stream_put (s, tlvh+1, TLV_BODY_SIZE (tlvh));
    }
  return;
}

static void                                       /* Interface Switching Capability Descr*/
build_link_subtlv_if_sw_cap_desc (struct stream *s, struct te_link_subtlv_if_sw_cap_desc *ifswcap)
{
  struct te_tlv_header *tlvh = &ifswcap->header;
  if ((ntohs (tlvh->type) != 0) && (ntohs (tlvh->length) != 0))
    {
      build_tlv_header (s, tlvh);
      stream_put (s, tlvh+1, TLV_BODY_SIZE (tlvh));
    }
  return;
}

static void                                       /* Shared Risk Link Group*/
build_link_subtlv_shared_risk_link_grp (struct stream *s, struct te_link *lp)
{
  struct te_tlv_header *tlvh = &lp->shared_risk_link_grp.header;
  if ((ntohs (tlvh->type) != 0) && (ntohs (tlvh->length) != 0))
  {
    build_tlv_header (s, tlvh);

    struct zlistnode *node, *nnode;
    u_int32_t *risk_link;
    for (ALL_LIST_ELEMENTS (&lp->shared_risk_link_grp.values, node, nnode, risk_link))
    {
      stream_putl(s, htonl(*(risk_link)));
    }
  }
  return;
}

static void            /** Local and Remote TE Router ID */
build_link_subtlv_lcl_rmt_te_router_id (struct stream *s, struct te_link *lp)
{
  struct te_tlv_header *tlvh = &lp->lcl_rmt_te_router_id.header;
  if ((ntohs (tlvh->type) != 0) && (ntohs (tlvh->length) != 0))
    {
      build_tlv_header (s, tlvh);
      stream_put (s, tlvh+1, TLV_BODY_SIZE (tlvh));
    }
  return;
}

/** ************************************************************************ */
/** **************************** OFI E-NNI Routing ************************* */
/** ************************************************************************ */ 

static void          /** Local Node ID */
build_link_subtlv_lcl_node_id (struct stream *s, struct te_link *lp)
{
  struct te_tlv_header *tlvh = &lp->lcl_node_id.header;
  if ((ntohs (tlvh->type) != 0) && (ntohs (tlvh->length) != 0)) 
  {
    build_tlv_header (s,tlvh);
    stream_put (s, tlvh+1, TLV_BODY_SIZE (tlvh));
  }
  return;
}

static void          /** Remote Node ID */
build_link_subtlv_rmt_node_id (struct stream *s, struct te_link *lp)
{
  struct te_tlv_header *tlvh = &lp->rmt_node_id.header;
  if ((ntohs (tlvh->type) != 0) && (ntohs (tlvh->length) != 0))
  {
    build_tlv_header (s,tlvh);
    stream_put (s, tlvh+1, TLV_BODY_SIZE (tlvh));
  }
  return;
}

static void          /** Sonet/SDH Interface Switching Capability Descriptor */
build_link_subtlv_ssdh_if_sw_cap_desc (struct stream *s, struct te_link *lp)
{
  struct te_tlv_header *tlvh = &lp->ssdh_if_sw_cap_desc.header;
  if ((ntohs (tlvh->type) != 0) && (ntohs (tlvh->length) != 0) && (ntohs (tlvh->length) != 4) )
  {
    build_tlv_header (s, tlvh);
    stream_putc (s, lp->ssdh_if_sw_cap_desc.switching_cap);
    stream_putc (s, lp->ssdh_if_sw_cap_desc.encoding);
    stream_putc (s, lp->ssdh_if_sw_cap_desc.reserved[0]);
    stream_putc (s, lp->ssdh_if_sw_cap_desc.reserved[1]);

    struct zlistnode *node, *nnode;


    struct signal_unalloc_tslots *signal_unalloc_tsl;
    for (ALL_LIST_ELEMENTS (&lp->ssdh_if_sw_cap_desc.signals_list, node, nnode, signal_unalloc_tsl))
    {
      stream_putc (s, signal_unalloc_tsl->signal_type);
      stream_putc (s, signal_unalloc_tsl->unalloc_tslots[0]);
      stream_putc (s, signal_unalloc_tsl->unalloc_tslots[1]);
      stream_putc (s, signal_unalloc_tsl->unalloc_tslots[2]); 
    }
  }
  return;
}

static void            /** General Capabilities */
build_link_subtlv_general_cap (struct stream *s, struct te_link *lp)
{
  struct te_tlv_header *tlvh = &lp->general_cap.header;
  if ((ntohs (tlvh->type) != 0) && (ntohs (tlvh->length) != 0))
  {
    build_tlv_header (s, tlvh);
    stream_put (s, tlvh+1, TLV_BODY_SIZE (tlvh));
  }
  return;
}

static void            /** Hierarchy List */
build_link_subtlv_hierarchy_list (struct stream *s, struct te_link *lp)
{
  struct te_tlv_header *tlvh = &lp->hierarchy_list.header;
  if ((ntohs (tlvh->type) != 0) && (ntohs (tlvh->length) != 0))
  {
    build_tlv_header (s, tlvh);

    struct zlistnode *node, *nnode;
    struct in_addr *rc_id;
    for (ALL_LIST_ELEMENTS (&lp->hierarchy_list.hierarchy_list, node, nnode, rc_id))
    {
      stream_put(s, rc_id, 4);
    }
  }
  return;
}

static void            /** Ancestor RC (Routing Controller) ID */
build_link_subtlv_anc_rc_id (struct stream *s, struct te_link *lp)
{
  struct te_tlv_header *tlvh = &lp->anc_rc_id.header;
  if ((ntohs (tlvh->type) != 0) && (ntohs (tlvh->length) != 0))
  {
    build_tlv_header (s, tlvh);
    stream_put (s, tlvh+1, TLV_BODY_SIZE (tlvh));
  }
  return;
}

/** ************************************************************************ */
/** **************************** GMPLS ASON Routing ************************ */
/** ************************************************************************ */ 

static void            /** Technology Specific Bandwidth Accounting */
build_link_subtlv_band_account (struct stream *s, struct te_link *lp)
{
  struct te_tlv_header *tlvh = &lp->band_account.header;
  if ((ntohs (tlvh->type) != 0) && (ntohs (tlvh->length) != 0))
  {
    build_tlv_header (s, tlvh);

    struct zlistnode *node, *nnode;
    struct signal_unalloc_tslots *signal_unalloc_tsl;
    for (ALL_LIST_ELEMENTS (&lp->band_account.signals_list, node, nnode, signal_unalloc_tsl))
    {
      stream_putc (s, signal_unalloc_tsl->signal_type);
      stream_putc (s, signal_unalloc_tsl->unalloc_tslots[0]);
      stream_putc (s, signal_unalloc_tsl->unalloc_tslots[1]);
      stream_putc (s, signal_unalloc_tsl->unalloc_tslots[2]); 
    }
  }
  return;
}

static void                                        /** OSPF Downstream Associated Area ID */
build_link_subtlv_ospf_down_aa_id (struct stream *s, struct te_link *lp)
{
  struct te_tlv_header *tlvh = &lp->ospf_down_aa_id.header;
  if ((ntohs (tlvh->type) != 0) && (ntohs (tlvh->length) != 0))
  {
    build_tlv_header (s, tlvh);

    struct zlistnode *node, *nnode;
    u_int32_t *area_id;
    for (ALL_LIST_ELEMENTS (&lp->ospf_down_aa_id.area_id_list, node, nnode, area_id))
    {
      stream_putl(s, htonl(*(area_id)));
    }
  }
  return;
}


static void            /** Associated Area ID */
build_link_subtlv_aa_id (struct stream *s, struct te_link *lp)
{
  struct te_tlv_header *tlvh = &lp->aa_id.header;
  if ((ntohs (tlvh->type) != 0) && (ntohs (tlvh->length) != 0))
  {
    build_tlv_header (s, tlvh);
    stream_put (s, tlvh+1, TLV_BODY_SIZE (tlvh));
  }
  return;
}

/** ************************************************************************ */
/** **************************** GMPLS All-optical Extensions ************** */
/** ************************************************************************ */ 

static void            /** BER Estimate */
build_link_subtlv_ber_estimate (struct stream *s, struct te_link *lp)
{
  struct te_tlv_header *tlvh = &lp->ber_estimate.header;
  if ((ntohs (tlvh->type) != 0) && (ntohs (tlvh->length) != 0))
  {
    build_tlv_header (s, tlvh);
    stream_put (s, tlvh+1, TLV_BODY_SIZE (tlvh));
  }
  return;
}

static void            /** Span Length */
build_link_subtlv_span_length (struct stream *s, struct te_link *lp)
{
  struct te_tlv_header *tlvh = &lp->span_length.header;
  if ((ntohs (tlvh->type) != 0) && (ntohs (tlvh->length) != 0))
  {
    build_tlv_header (s, tlvh);
    stream_put (s, tlvh+1, TLV_BODY_SIZE (tlvh));
  }
  return;
}

static void            /** OSNR */
build_link_subtlv_osnr (struct stream *s, struct te_link *lp)
{
  struct te_tlv_header *tlvh = &lp->osnr.header;
  if ((ntohs (tlvh->type) != 0) && (ntohs (tlvh->length) != 0))
  {
    build_tlv_header (s, tlvh);
    stream_put (s, tlvh+1, TLV_BODY_SIZE (tlvh));
  }
  return;
}

static void            /** Dpdm */
build_link_subtlv_d_pdm (struct stream *s, struct te_link *lp)
{
  struct te_tlv_header *tlvh = &lp->d_pdm.header;
  if ((ntohs (tlvh->type) != 0) && (ntohs (tlvh->length) != 0))
  {
    build_tlv_header (s, tlvh);
    stream_put (s, tlvh+1, TLV_BODY_SIZE (tlvh));
  }
  return;
}

static void            /** Amplifiers List */
build_link_subtlv_amp_list (struct stream *s, struct te_link *lp)
{
  float *des;
  struct te_tlv_header *tlvh = &lp->amp_list.header;
  if ((ntohs (tlvh->type) != 0) && (ntohs (tlvh->length) != 0))
  {
    build_tlv_header (s, tlvh);

    struct zlistnode *node, *nnode;
    struct amp_par *amplifier_par;
    for (ALL_LIST_ELEMENTS (&lp->amp_list.amp_list, node, nnode, amplifier_par))
    {
      stream_putl(s, htonl(amplifier_par->gain));
      des = &amplifier_par->noise;
      stream_put(s, des, 4);
    }
  }
  return;
}

static void            /** Available Wavelength Mask */
build_link_subtlv_av_wave_mask (struct stream *s, struct te_link *lp)
{
  struct te_tlv_header *tlvh = &lp->av_wave_mask.header;
  if ((ntohs (tlvh->type) != 0) && (ntohs (tlvh->length) != 0))
  {
    build_tlv_header (s, tlvh);
    stream_putc (s, lp->av_wave_mask.action);
    stream_putc (s, lp->av_wave_mask.reserved);
    stream_putw (s, ntohs(lp->av_wave_mask.num_wavelengths));
    stream_putl (s, ntohl(lp->av_wave_mask.label_set_desc));

    struct zlistnode *node, *nnode;
    u_int32_t *bitmap_mask;
    for (ALL_LIST_ELEMENTS (&lp->av_wave_mask.bitmap_list, node, nnode, bitmap_mask))
    {
      stream_putl(s, htonl(*(bitmap_mask)));
    }
  }
  return;

}

/**
 * TE-link Calendar
 */
static void
build_link_subtlv_te_link_calendar (struct stream *s, struct te_link *lp)
{
  float *des; int i;
  struct te_tlv_header *tlvh = &lp->te_link_calendar.header;
  if ((ntohs (tlvh->type) != 0) && (ntohs (tlvh->length) != 0))
  {
    build_tlv_header (s, tlvh);

    struct zlistnode *node, *nnode;
    struct te_link_calendar *calendar;
    for (ALL_LIST_ELEMENTS (&lp->te_link_calendar.te_calendar, node, nnode, calendar))
    {
      stream_putl(s, htonl(calendar->time));
      for (i=0; i<8; i++)
      {
        des = &calendar->value[i];
        stream_put(s, des, 4);
      }
    }
  }
  return;
}

static void            /** Power consumption */
build_link_subtlv_power_consumption (struct stream *s, struct te_link *lp)
{
  struct te_tlv_header *tlvh = &lp->power_consumption.header;
  if ((ntohs (tlvh->type) != 0) && (ntohs (tlvh->length) != 0))
  {
    build_tlv_header (s, tlvh);
    stream_put (s, tlvh+1, TLV_BODY_SIZE (tlvh));
  }
  return;
}

static void            /** Dynamic re-planning */
build_link_subtlv_dynamic_replanning (struct stream *s, struct te_link *lp)
{
  struct te_tlv_header *tlvh = &lp->dynamic_replanning.header;
  if ((ntohs (tlvh->type) != 0) && (ntohs (tlvh->length) != 0))
  {
    build_tlv_header (s, tlvh);
    stream_put (s, tlvh+1, TLV_BODY_SIZE (tlvh));
  }
  return;
}

static void
build_link_tlv (struct stream *s, struct te_link *lp)
{
  set_linkparams_link_header (lp);
  build_tlv_header (s, &lp->link_header.header);

  build_link_subtlv_link_type (s, lp);
  build_link_subtlv_link_id (s, lp);
  build_link_subtlv_lclif_ipaddr (s, lp);
  build_link_subtlv_rmtif_ipaddr (s, lp);
  build_link_subtlv_te_metric (s, lp);
  build_link_subtlv_max_bw (s, lp);
  build_link_subtlv_max_rsv_bw (s, lp);
  build_link_subtlv_unrsv_bw (s, lp);
  build_link_subtlv_rsc_clsclr (s, lp);
/** GMPLS extensions */
/** GMPLS Generic */
  build_link_subtlv_link_lcl_rmt_ids (s, lp);     /** Link Local/Remote Identifiers*/
  build_link_subtlv_link_protect_type (s, lp);    /** Link Protection Type*/

  struct zlistnode *node, *nnode;
  struct te_link_subtlv_if_sw_cap_desc *ifswcap;
  for (ALL_LIST_ELEMENTS(&lp->if_sw_cap_descs, node, nnode, ifswcap))
    build_link_subtlv_if_sw_cap_desc(s, ifswcap);

  build_link_subtlv_shared_risk_link_grp (s, lp); /** Shared Risk Link Group*/
  build_link_subtlv_lcl_rmt_te_router_id (s, lp); /** Local/Remote TE Router ID */
/** OFI E-NNI Routing */
  build_link_subtlv_lcl_node_id (s, lp);          /** Local Node ID */
  build_link_subtlv_rmt_node_id (s, lp);          /** Remote Node ID */
  build_link_subtlv_ssdh_if_sw_cap_desc (s, lp);  /** Sonet/SDH Interface Switching Capability Descriptor */
  build_link_subtlv_general_cap (s, lp);          /** General Capabilities */
  build_link_subtlv_hierarchy_list (s, lp);       /** Hierarchy List */
  build_link_subtlv_anc_rc_id (s, lp);            /** Ancestor RC (Routing Controller) ID */
/** GMPLS ASON Routing */
  build_link_subtlv_band_account (s, lp);         /** Technology Specific Bandwidth Accounting */
  build_link_subtlv_ospf_down_aa_id (s, lp);      /** OSPF Downstream Associated Area ID */
  build_link_subtlv_aa_id (s, lp);                /** Associated Area ID */
/** GMPLS All-optical Extensions */
  build_link_subtlv_ber_estimate (s, lp);         /** BER Estimate */
  build_link_subtlv_span_length (s, lp);          /** Span Lenght */
  build_link_subtlv_osnr (s, lp);                 /** OSNR */
  build_link_subtlv_d_pdm (s, lp);                /** Dpdm */
  build_link_subtlv_amp_list (s, lp);             /** Amplifiers List */
  build_link_subtlv_av_wave_mask (s, lp);         /** Available Wavelenght Mask */
  build_link_subtlv_te_link_calendar (s, lp);     /** TE-link Calendar */
/** Geysers Extensions */
  build_link_subtlv_power_consumption (s, lp);         /** Power consumption */
  build_link_subtlv_dynamic_replanning (s, lp);          /** Dynamic re-planning */
  return;
}

static int
assing_new_interface_to_harmony_te_links()
{
  OspfTE.harmonyIfp = chose_ifp_for_harmony_te_links();

  struct zlistnode *node, *nnode;
  struct te_link *lp;

  for (ALL_LIST_ELEMENTS(OspfTE.harmonyIflist, node, nnode, lp))
  {
    lp->ifp=OspfTE.harmonyIfp;
    lp->area = lookup_oi_by_ifp(OspfTE.harmonyIfp, NULL, OI_ANY)->area;
  }
  return 1;
}

static struct interface*
chose_ifp_for_harmony_te_links()
{
  struct zlistnode *node;
  struct interface *ifp;
  for(ALL_LIST_ELEMENTS_RO(iflist, node, ifp))
  {
    if ((ifp->adj_type == ENNI) && (ifp->ospf_instance == ENNI))
      return ifp;
  }
  return NULL;
}


#if 0
static void
ospf_te_lsa_body_set (struct stream *s, struct te_link *lp)
{
  /*
   * The router address TLV is type 1, and ...
   *                                      It must appear in exactly one 
   * Traffic Engineering LSA originated by a router.
   */
  build_router_addr_tlv (s, lp);

  build_node_attr_tlv (s, lp);
  /*
   * Only one Link TLV shall be carried in each LSA, allowing for fine
   * granularity changes in topology.
   */
  build_link_tlv (s, lp);
  return;
}
#endif
/**
 * Create new opaque-LSA
 * @param *ospf_area pointer to the ospf area
 * @param *te_link pointer to the struct that stores all information about interface te parameters
 * @param *function_ptr pointer to the specyfic function for router id, node attribute, te link or tna tlv creation
 * @param instance_no nuber of instance
 */
static struct ospf_lsa *
ospf_te_xxx_lsa_new (struct ospf_area *area, struct te_link *lp, void (*xxx)(struct stream *s, struct te_link *lp), uint32_t lsa_instance_no)
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
      zlog_warn ("[WRN] OSPF_TE_XXX_LSA_NEW: stream_new() failed");
      goto out;
    }
  lsah = (struct lsa_header *) STREAM_DATA (s);

  options  = LSA_OPTIONS_GET (area);
  options |= LSA_OPTIONS_NSSA_GET (area);
  options |= OSPF_OPTION_O; /* Don't forget this :-) */

  lsa_type = OSPF_OPAQUE_AREA_LSA;
  tmp = SET_OPAQUE_LSID (OPAQUE_TYPE_TRAFFIC_ENGINEERING_LSA, lsa_instance_no);
  lsa_id.s_addr = htonl (tmp);

  if (IS_DEBUG_TE (GENERATE))
    zlog_debug ("[DBG] OSPF_TE_XXX_LSA_NEW: LSA[Type%d:%s]: Create an Opaque-LSA/TE instance", lsa_type, inet_ntoa (lsa_id)); 

  /* Set opaque-LSA header fields. */
  lsa_header_set (s, options, lsa_type, lsa_id, area->ospf->router_id);

  /* Set opaque-LSA body fields. */
  xxx (s, lp);

  /* Set length. */
  length = stream_get_endp (s);
  lsah->length = htons (length);

  /* Now, create an OSPF LSA instance. */
  if ((new = ospf_lsa_new ()) == NULL)
    {
      zlog_warn ("[WRN] OSPF_TE_XXX_LSA_NEW: ospf_lsa_new() failed");
      stream_free (s);
      goto out;
    }
  if ((new->data = ospf_lsa_data_new (length)) == NULL)
    {
      zlog_warn ("[WRN] OSPF_TE_XXX_LSA_NEW: ospf_lsa_data_new() failed");
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

/**
 * Create new opaque-LSA
 * @param *ospf_area pointer to the ospf area
 * @param *te_link pointer to the struct that stores all information about interface te parameters
 * @param *function_ptr pointer to the specyfic function for router id, node attribute, te link or tna tlv creation
 * @param instance_no nuber of instance
 */
static struct ospf_lsa *
ospf_te_xxx2_lsa_new (struct ospf_area *area, void (*build_func)(struct stream* s, uint16_t inst), uint32_t lsa_instance_no, uint16_t instance_no)
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
      zlog_warn ("[WRN] OSPF_TE_XXX2_LSA_NEW: stream_new() failed");
      goto out;
    }
  lsah = (struct lsa_header *) STREAM_DATA (s);

  options  = LSA_OPTIONS_GET (area);
  options |= LSA_OPTIONS_NSSA_GET (area);
  options |= OSPF_OPTION_O; /* Don't forget this :-) */

  lsa_type = OSPF_OPAQUE_AREA_LSA;
  tmp = SET_OPAQUE_LSID (OPAQUE_TYPE_TRAFFIC_ENGINEERING_LSA, lsa_instance_no);
  lsa_id.s_addr = htonl (tmp);

  if (IS_DEBUG_TE (GENERATE))
    zlog_debug ("[DBG] OSPF_TE_XXX2_LSA_NEW: LSA[Type %d:%s]: Create an Opaque-LSA/TE instance", lsa_type, inet_ntoa (lsa_id)); 

  /* Set opaque-LSA header fields. */
  lsa_header_set (s, options, lsa_type, lsa_id, area->ospf->router_id);

  /* Set opaque-LSA body fields. */
  build_func (s, instance_no);

  /* Set length. */
  length = stream_get_endp (s);

  lsah->length = htons (length);

  /* Now, create an OSPF LSA instance. */
  if ((new = ospf_lsa_new ()) == NULL)
  {
    zlog_warn ("[WRN] OSPF_TE_XXX2_LSA_NEW: ospf_lsa_new() failed");
    stream_free (s);
    goto out;
  }

  if ((new->data = ospf_lsa_data_new (length)) == NULL)
  {
    zlog_warn ("[WRN] OSPF_TE_XXX2_LSA_NEW: ospf_lsa_data_new() failed");
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

/**
 * Create new opaque-LSA
 * @param *ospf_area pointer to the ospf area
 * @param *te_link pointer to the struct that stores all information about interface te parameters
 * @param *function_ptr pointer to the specyfic function for router id, node attribute, te link or tna tlv creation
 * @param instance_no nuber of instance
 */
static struct ospf_lsa *
ospf_te_ra_harmony_lsa_new (struct ospf_area *area, struct raHarmony *rah)
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
    zlog_warn("[WRN] OSPF_TE_RA_HARMONY_LSA_NEW: stream_new() failed");
    return NULL;
  }
  lsah = (struct lsa_header *) STREAM_DATA (s);

  options  = LSA_OPTIONS_GET (area);
  options |= LSA_OPTIONS_NSSA_GET (area);
  options |= OSPF_OPTION_O; /* Don't forget this :-) */

  lsa_type = OSPF_OPAQUE_AREA_LSA;
  tmp = SET_OPAQUE_LSID (OPAQUE_TYPE_TRAFFIC_ENGINEERING_LSA, rah->instance_id);
  lsa_id.s_addr = htonl (tmp);

  if (IS_DEBUG_TE (GENERATE))
    zlog_debug("[DBG] OSPF_TE_RA_HARMONY_LSA_NEW: LSA[Type%d:%s]: Create an Opaque-LSA/TE instance", lsa_type, inet_ntoa (lsa_id));

  /* Set opaque-LSA header fields. */
  lsa_header_set (s, options, lsa_type, lsa_id, area->ospf->router_id);

  /* Set opaque-LSA body fields. */
  build_tlv_header (s, &rah->router_addr.link_header.header);

  if (IS_DEBUG_TE(GENERATE))
    zlog_debug("[DBG] OSPF_TE_RA_HARMONY_LSA_NEW: build_router_addr_tlv (RA Harmony)");
  build_router_addr_subtlv_router_addr_ptr (s, &rah->router_addr.router_addr);
  build_router_addr_subtlv_aa_id_ptr (s, &rah->router_addr.aa_id);
  build_router_addr_subtlv_power_consumption_ptr (s, &rah->router_addr.power_consumption);
  /* Set length. */
  length = stream_get_endp (s);

  if (IS_DEBUG_TE(GENERATE))
    zlog_debug("[DBG] OSPF_TE_RA_HARMONY_LSA_NEW: LSA length %d", length);

  lsah->length = htons (length);

  /* Now, create an OSPF LSA instance. */
  new = ospf_lsa_new ();
  if (new == NULL)
  {
    zlog_warn("[WRN] OSPF_TE_RA_HARMONY_LSA_NEW: ospf_lsa_new() failed");
    stream_free (s);
    return NULL;
  }

  if ((new->data = ospf_lsa_data_new (length)) == NULL)
  {
    zlog_warn ("[WRN] OSPF_TE_RA_HARMONY_LSA_NEW: ospf_lsa_data_new() failed");
    ospf_lsa_unlock (&new);
    new = NULL;
    stream_free (s);
    return NULL;
  }

  new->area = area;
  SET_FLAG (new->flags, OSPF_LSA_SELF);
  memcpy (new->data, lsah, length);
  stream_free (s);

  return new;
}

/**
 * Originates TE-Link or TNA-Address
 * @return 0: all OK, -1: error, 1: LSA length 0, 2: Originating on this interface is forbiden
 */
static int
ospf_te_lsa_originate1 (struct ospf_area *area, struct te_link *lp, enum type_of_lsa_info lsa_info)
{
  struct ospf_lsa *new;
  int rc = -1;

  struct in_addr tmp;
  if (ntohs(lp->lclif_ipaddr.header.type) != 0)
    tmp = lp->lclif_ipaddr.value[0];
  else
    tmp.s_addr = lp->link_lcl_rmt_ids.local_id;

  if (IS_DEBUG_TE(ORIGINATE))
    zlog_debug("[DBG] OSPF_TE_LSA_ORIGINATE1 (%s): OSPF instance %s START)",
    lp->ifp->name, OSPF_INST_TO_STR(lp->ifp->ospf_instance));

  switch (lsa_info)
  {
    case ROUTE_ADDRESS:
      zlog_err("[ERR] OSPF_TE_LSA_ORIGINATE1 (%s): Use ospf_te_lsa_originate2 for ROUTE_ADDRESS", lp->ifp->name);
      goto out;
      break;

    case NODE_ATRIBUTE:
      zlog_err("[ERR] OSPF_TE_LSA_ORIGINATE1 (%s): Use ospf_te_lsa_originate2 for NODE_ATRIBUTE", lp->ifp->name);
      goto out;
      break;

    case LINK:
      if ((new = ospf_te_xxx_lsa_new (area, lp, build_link_tlv, lp->instance_li)) == NULL)
      {
        zlog_warn ("[WRN] OSPF_TE_LSA_ORIGINATE1 (%s): ospf_te_xxx_lsa_new( , , build_link_tlv, ) ?", lp->ifp->name);
        goto out;
      }
      if (IS_DEBUG_TE(USER))
        zlog_debug("[DBG] OSPF_TE_LSA_ORIGINATE1 (%s): Originate te-link: %s (ospf: %s)", lp->ifp->name, inet_ntoa(tmp), OSPF_INST_TO_STR(lp->ifp->ospf_instance));

      break;

    case TNA_ADDRESS:
      if (((lp->ifp->ospf_instance != UNI) || (area->ospf->interface_side != NETWORK)) && (lp->harmony_ifp != 1))
      {
        if (IS_DEBUG_TE(ORIGINATE))
          zlog_debug("[DBG] OSPF_TE_LSA_ORIGINATE1 (%s): skipping TNA originating on non UNI_N interface (all OK)", lp->ifp->name);
          rc = 2;
          goto out;
      }
      if (lp->tna_address.header.length == 0)
      {
        if (IS_DEBUG_TE(ORIGINATE))
          zlog_debug("[DBG] OSPF_TE_LSA_ORIGINATE1 (%s): tna.header.length = 0", lp->ifp->name);
        rc = 1;
        goto out;       // don't send empty TNA TLV
      }
      if ((new = ospf_te_xxx_lsa_new (area, lp, build_tna_addr_tlv, lp->instance_tna)) == NULL)
      {
        zlog_warn ("[WRN] OSPF_TE_LSA_ORIGINATE1 (%s): ospf_te_xxx_lsa_new( , , build_tna_addr_tlv, ) ?", lp->ifp->name);
        goto out;
      }
      if ((IS_DEBUG_TE(USER)) && (IS_DEBUG_TE(ORIGINATE)))
        zlog_debug("[DBG] OSPF_TE_LSA_ORIGINATE1 (%s): originate TNA (ospf: %s)%s", lp->ifp->name, OSPF_INST_TO_STR(lp->ifp->ospf_instance), (lp->harmony_ifp == 1) ? " HARMONY":"");
      break;

    default:
      zlog_warn("[WRN] OSPF_TE_LSA_ORIGINATE1 (%s): Can't find appropriate instance number", lp->ifp->name);
      goto out;
  }

  /* Install this LSA into LSDB. */
  if (ospf_lsa_install (area->ospf, NULL /*oi*/, new) == NULL)
  {
    zlog_warn ("[WRN] OSPF_TE_LSA_ORIGINATE1 (%s): ospf_lsa_install() failed", lp->ifp->name);
    ospf_lsa_unlock (&new);
    goto out;
  }

  /* Now this linkparameter entry has associated LSA. */
  switch (lsa_info)
  {
    case ROUTE_ADDRESS:
    case NODE_ATRIBUTE:
      break;
    case LINK:
      lp->flags |= LPFLG_LSA_LI_ENGAGED;
      break;
    case TNA_ADDRESS:
      lp->flags |= LPFLG_LSA_TNA_ENGAGED;
      break;
  }
  SET_FLAG(lp->flags, LPFLG_LSA_ORIGINATED);

  /* Update new LSA origination count. */
  area->ospf->lsa_originate_count++;

  /* Flood new LSA through area. */
  ospf_flood_through_area (area, NULL/*nbr*/, new);

  if (IS_DEBUG_OSPF(lsa, LSA_GENERATE))
  {
    char area_id[INET_ADDRSTRLEN];
    strcpy (area_id, inet_ntoa (area->area_id));
    zlog_debug ("[DBG] OSPF_TE_LSA_ORIGINATE1 (%s): LSA[Type%d:%s]: Originate Opaque-LSA/TE: Area(%s)", lp->ifp->name, new->data->type, inet_ntoa (new->data->id), area_id);
    ospf_lsa_header_dump (new->data);
  }
  rc = 0;
out:
  return rc;
}

static int
ospf_te_lsa_originate2 (struct ospf_area *area, enum type_of_lsa_info lsa_info)
{
  char area_id_asc[20];
  sprintf(area_id_asc, "%s", inet_ntoa(area->area_id));
  struct ospf_lsa *new;
  int rc = -1;
  uint16_t instance_no = area->ospf->instance;

  if  (instance_no > 2)
  {
    zlog_err("[ERR] OSPF_TE_LSA_ORIGINATE2 (%s): Wrong OSPF instance: %d", area_id_asc, instance_no);
    goto out;
  }

  if (IS_DEBUG_TE(GENERATE))
    zlog_debug("[DBG] OSPF_TE_LSA_ORIGINATE2 (%s): OSPF instance: %s", area_id_asc, OSPF_INST_TO_STR(instance_no));

  switch (lsa_info)
  {
    case ROUTE_ADDRESS:
      if ((new = ospf_te_xxx2_lsa_new(area, build_router_addr_tlv, OspfTE.ra_instance_id[instance_no], instance_no)) == NULL)
      {
        zlog_warn ("[WRN] OSPF_TE_LSA_ORIGINATE2 (%s): ospf_te_xxx_lsa_new(, , build_router_addr_tlv, ) ?", area_id_asc);
        goto out;
      }
      if (IS_DEBUG_TE(USER))
      {
        zlog_debug("[DBG] OSPF_TE_LSA_ORIGINATE2 (%s): Originating RA: %s (OSPF %s)", area_id_asc, inet_ntoa(OspfTE.router_addr[instance_no].router_addr.value), OSPF_INST_TO_STR(area->ospf->instance));
      }
    break;

    case NODE_ATRIBUTE:
      if (IS_DEBUG_TE(USER))
        zlog_debug("[DBG] OSPF_TE_LSA_ORIGINATE2 (%s): Originating NA (OSPF %s)", area_id_asc, OSPF_INST_TO_STR(area->ospf->instance));
      if ((OspfTE.node_attr[instance_no].link_header.header.length) == 0)
      {
        rc = 1;
        goto out;   //don't send empty Node Attribute TLV
      }
      if ((new = ospf_te_xxx2_lsa_new (area, build_node_attr_tlv, OspfTE.na_instance_id[instance_no], instance_no)) == NULL)
      {
        zlog_warn ("[WRN] OSPF_TE_LSA_ORIGINATE2 (%s): ospf_te_xxx_lsa_new( , , build_node_attr_tlv, ) ?", area_id_asc);
        goto out;
      }
      break;

    case LINK:
      zlog_err("[ERR] OSPF_TE_LSA_ORIGINATE2 (%s): Use ospf_te_lsa_originate1 for LINK", area_id_asc);
      goto out;
      break;

    case TNA_ADDRESS:
      zlog_err("[ERR] OSPF_TE_LSA_ORIGINATE2 (%s): Use ospf_te_lsa_originate1 for LINK", area_id_asc);
      goto out;
      break;

    default:
      zlog_warn("[WRN] OSPF_TE_LSA_ORIGINATE2 (%s): Can't find appropriate instance number", area_id_asc);
      goto out;
  }

  /* Install this LSA into LSDB. */
  if (ospf_lsa_install (area->ospf, NULL /*oi*/, new) == NULL)
  {
    zlog_warn ("[WRN] OSPF_TE_LSA_ORIGINATE2 (%s): ospf_lsa_install() ?", area_id_asc);
    ospf_lsa_unlock (&new);
    goto out;
  }

  /* Now this linkparameter entry has associated LSA. */
  switch (lsa_info)
  {
    case ROUTE_ADDRESS:
      OspfTE.ra_engaged[instance_no] = 1;
      break;
    case NODE_ATRIBUTE:
      OspfTE.na_engaged[instance_no] = 1;
      break;
    case LINK:
    case TNA_ADDRESS:
      break;
  }

  /* Update new LSA origination count. */
  area->ospf->lsa_originate_count++;

  /* Flood new LSA through area. */
  ospf_flood_through_area (area, NULL/*nbr*/, new);

  if (IS_DEBUG_OSPF(lsa, LSA_GENERATE))
  {
    char area_id[INET_ADDRSTRLEN];
    strcpy (area_id, inet_ntoa (area->area_id));
    zlog_debug ("[DBG] OSPF_TE_LSA_ORIGINATE2 (%s): LSA[Type%d:%s]: Originate Opaque-LSA/TE: Area(%s)", area_id_asc, new->data->type, inet_ntoa (new->data->id), area_id);
    ospf_lsa_header_dump (new->data);
  }
  rc = 0;

  struct zlistnode *node, *nnode;
  struct raHarmony *rah;
  if ((area->ospf->instance == ENNI) && (lsa_info == ROUTE_ADDRESS))
  {
    for (ALL_LIST_ELEMENTS(OspfTE.harmonyRaList, node, nnode, rah))
    {
      if ((new = ospf_te_ra_harmony_lsa_new(area, rah)) != NULL)
      {
        if (IS_DEBUG_TE(USER))
          zlog_debug("[DBG] OSPF_TE_LSA_ORIGINATE2 (Harmony %s): Originating RA %s - LSA created", area_id_asc, inet_ntoa(rah->router_addr.router_addr.value));
        ospf_lsa_checksum (new->data);
        if (ospf_lsa_install (area->ospf, NULL /*oi*/, new) == NULL)
        {
          char buf[50];
          log_summary_te_lsa(buf, new);
          zlog_warn ("[WRN] OSPF_TE_LSA_ORIGINATE2 (Harmony %s): ospf_lsa_install(), LSA: %s", area_id_asc, buf);
          ospf_lsa_unlock (&new);
          goto out;
        }
        ospf_flood_through_area (area, NULL/*nbr*/, new);
        rah->engaged = 1;
      }
      else
      {
        zlog_warn("[WRN] OSPF_TE_LSA_ORIGINATE2 (Harmony %s): Originating RA harmony: %s - LSA creation failed", area_id_asc, inet_ntoa(rah->router_addr.router_addr.value));
      }
    }
  }

out:
  return rc;
}


static int
ospf_te_lsa_originate (void *arg)
{
  struct ospf_area *area = (struct ospf_area *) arg;
  struct zlistnode *node, *nnode;
  struct te_link *lp;
  int rc = -1;
  int ret;
  int ospf_instance_no = 3;
  struct ospf     *ospf_uni = ospf_uni_lookup();

  if (OspfTE.status == disabled)
  {
    if (IS_DEBUG_TE(ORIGINATE))
      zlog_debug ("[DBG] OSPF_TE_LSA_ORIGINATE: TE is disabled now.");
    rc = 0; /* This is not an error case. */
    goto out;
  }

  ospf_instance_no = area->ospf->instance;
  if (IS_DEBUG_TE(ORIGINATE))
    zlog_debug ("[DBG] OSPF_TE_LSA_ORIGINATE: OSPF instance: %s START",  OSPF_INST_TO_STR(ospf_instance_no));

  if (ospf_instance_no > 2)
  {
    zlog_err("[ERR] OSPF_TE_LSA_ORIGINATE: Wrong OSPF instance: %d", ospf_instance_no);
    return -1;
  }

  if ((OspfTE.ra_force_refreshed[ospf_instance_no] == 1) && (OspfTE.ra_engaged[ospf_instance_no] == 1))
  {
    OspfTE.ra_force_refreshed[ospf_instance_no] = 0;
    ospf_te_ra_lsa_schedule (REFRESH_THIS_LSA, area->ospf, area);
  }

  if (is_mandated_params_set_ra(ospf_instance_no))
  {
    if (OspfTE.ra_engaged[ospf_instance_no] == 0)
    {
      int ret = ospf_te_lsa_originate2 (area, ROUTE_ADDRESS);
      if (ret != 0)
      {
        if (ret == -1)
        {
          zlog_warn("[WRN] OSPF_TE_LSA_ORIGINATE: build_router_addr_tlv(...) failed");
          goto out;
        }
      }
      else
        OspfTE.ra_engaged[ospf_instance_no] = 1;
    }
    else if (ospf_instance_no == ENNI)
    {
      int do_originate = 0;
      struct zlistnode *node, *nnode;
      struct raHarmony *rah;
      for (ALL_LIST_ELEMENTS(OspfTE.harmonyRaList, node, nnode, rah))
      {
        if (rah->engaged == 0)
        {
          do_originate = 1;
          break;
        }
      }
      if (do_originate == 1)
      {
        int ret = ospf_te_lsa_originate2 (area, ROUTE_ADDRESS);
        if (ret != 0)
        {
          if (ret == -1)
          {
            zlog_warn("[WRN] OSPF_TE_LSA_ORIGINATE: build_router_addr_tlv(...) in lsa harmony originate failed");
            goto out;
          }
        }
      }
    }
  }
  else
  {
    zlog_warn("[WRN] OSPF_TE_LSA_ORIGINATE: Lacks some nandated parameters for RA originate (instance %s)", SHOW_ADJTYPE(ospf_instance_no));
  }

  if ((OspfTE.na_force_refreshed[ospf_instance_no] == 1) && (OspfTE.na_engaged[ospf_instance_no] == 1))
  {
    OspfTE.na_force_refreshed[ospf_instance_no] = 0;
    ospf_te_na_lsa_schedule (REFRESH_THIS_LSA, area->ospf, area);
  }

  if (is_mandated_params_set_na(ospf_instance_no))
  {
    if (OspfTE.na_engaged[ospf_instance_no] == 0)
    {
//    zlog_debug("build_node_attr_tlv in lsa originate");
      int ret = ospf_te_lsa_originate2 (area, NODE_ATRIBUTE);
      if (ret != 0)
      {
        if (ret == -1)
        {
          zlog_warn("[WRN] OSPF_TE_LSA_ORIGINATE: build_node_attr_tlv(...) in lsa originate failed");
          goto out;
        }
      }
      else
        OspfTE.na_engaged[ospf_instance_no] = 1;
    }
  }

  for (ALL_LIST_ELEMENTS (OspfTE.iflist, node, nnode, lp))
  {
    if (lp->ifp->ospf_instance  != ospf_instance_no)
    {
      continue;
    }

    if (lp->area == NULL)
    {
      if (IS_DEBUG_TE(ORIGINATE))
        zlog_warn("[WRN] OSPF_TE_LSA_ORIGINATE (%s): NO AREA for this interface", lp->ifp->name);
      continue;
    }

    if (! IPV4_ADDR_SAME (&lp->area->area_id, &area->area_id))
    {
      continue;
    }

    if ((lp->flags & LPFLG_LSA_LI_FORCED_REFRESH) && (lp->flags & LPFLG_LSA_LI_ENGAGED))
    {
      lp->flags &= ~LPFLG_LSA_LI_FORCED_REFRESH;
      ospf_te_lsa_schedule (lp, REFRESH_THIS_LSA, LINK);
      if (IS_DEBUG_TE(ORIGINATE))
        zlog_debug("[DBG] OSPF_TE_LSA_ORIGINATE (%s): FORCED refresh LINK", lp->ifp->name);
      continue;
    }

    if ((lp->flags & LPFLG_LSA_TNA_FORCED_REFRESH) && (lp->flags & LPFLG_LSA_TNA_ENGAGED))
    {
      lp->flags &= ~LPFLG_LSA_TNA_FORCED_REFRESH;
      ospf_te_lsa_schedule (lp, REFRESH_THIS_LSA, TNA_ADDRESS);
      if (IS_DEBUG_TE(ORIGINATE))
        zlog_debug("[DBG] OSPF_TE_LSA_ORIGINATE (%s): FORCED refresh TNA_ADDRESS", lp->ifp->name);
      continue;
    }

    //if( lp->tna_address.tna_addr_header.length == 0)
     //  continue;

    if (lp->is_set_linkparams_link_type == 0)
    {
        struct ospf_interface *oi;
        if ((oi = lookup_oi_by_ifp (lp->ifp, NULL, OI_ANY)) != NULL)
        {
          set_linkparams_link_type (oi, lp);
          lp->is_set_linkparams_link_type = 1;
        }
        else
          continue;
    }

    /* Ok, let's try to originate an LSA for this area and Link. */
    if (! is_mandated_params_set (lp))
    {
      struct in_addr tmp;
      if (ntohs(lp->lclif_ipaddr.header.type) != 0)
        tmp = lp->lclif_ipaddr.value[0];
      else
        tmp.s_addr = lp->link_lcl_rmt_ids.local_id;

      zlog_warn ("[WRN] OSPF_TE_LSA_ORIGINATE (%s): lacks some mandated TE parameters in te-link %s", lp->ifp ? lp->ifp->name : "?", inet_ntoa(tmp));
      continue;
    }

    if ((lp->flags & LPFLG_LSA_LI_ENGAGED) == 0)
    {
//      zlog_debug("build_link_tlv in lsa originate");
      if (ospf_te_lsa_originate1 (area, lp, LINK) != 0)
      {
        zlog_warn("[WRN] OSPF_TE_LSA_ORIGINATE (%s): build_link_tlv(...) in lsa originate failed", lp->ifp->name);
        goto out;
      }
      else
        lp->flags |= LPFLG_LSA_LI_ENGAGED;
    }
    if ((lp->flags & LPFLG_LSA_TNA_ENGAGED) == 0)
    {
      int tna_originated = 0;
      if (ospf_uni != NULL)
      {
        if ((ospf_uni->interface_side == NETWORK) && (lp->ifp->ospf_instance == UNI))
        {
          tna_originated = 1;
          ret = ospf_te_lsa_originate1 (area, lp, TNA_ADDRESS);
          if (ret == -1)
          {
            zlog_warn("[WRN] OSPF_TE_LSA_ORIGINATE (%s): build_tna_addr_tlv(...) in lsa originate failed", lp->ifp->name);
            goto out;
          }
          else if (ret == 1)
          {
            if (IS_DEBUG_TE(ORIGINATE))
              zlog_debug("[DBG] OSPF_TE_LSA_ORIGINATE (%s): TNA length = 0. LSA will not sent", lp->ifp->name);
          }
          else if (ret == 0)
          {
            if (IS_DEBUG_TE(ORIGINATE))
              zlog_debug("[DBG] OSPF_TE_LSA_ORIGINATE (%s): TNA engaged ", lp->ifp->name);
            lp->flags |= LPFLG_LSA_TNA_ENGAGED;
          }
          else
          {
            if (IS_DEBUG_TE(ORIGINATE))
              zlog_debug("[DBG] OSPF_TE_LSA_ORIGINATE (%s) not originated. (code %d)", lp->ifp->name, ret);
          }
        }
      }
      if (tna_originated == 0)
      {
        struct ospf *ospf_tmp = NULL;
        switch (lp->ifp->ospf_instance)
        {
          case UNI:
            ospf_tmp = ospf_uni_lookup();
            break;
          case INNI:
            ospf_tmp = ospf_inni_lookup();
            break;
          case ENNI:
            ospf_tmp = ospf_enni_lookup();
            break;
        }
        if (ospf_tmp != NULL)
        {
          if (ospf_tmp->read_tna == 1)
          {
            ospf_te_lsa_originate1 (area, lp, TNA_ADDRESS);
            if (ret == -1)
            {
              zlog_warn("[WRN] OSPF_TE_LSA_ORIGINATE (force) (%s): build_tna_addr_tlv(...) in lsa originate failed", lp->ifp->name);
              goto out;
            }
            else if (ret == 1)
            {
              if (IS_DEBUG_TE(ORIGINATE))
                zlog_debug("[DBG] OSPF_TE_LSA_ORIGINATE (force) (%s): TNA length = 0. LSA will not sent", lp->ifp->name);
            }
            else if (ret == 0)
            {
              if (IS_DEBUG_TE(ORIGINATE))
                zlog_debug("[DBG] OSPF_TE_LSA_ORIGINATE (force) (%s): TNA engaged ", lp->ifp->name);
              lp->flags |= LPFLG_LSA_TNA_ENGAGED;
            }
            else
            {
              if (IS_DEBUG_TE(ORIGINATE))
                zlog_debug("[DBG] OSPF_TE_LSA_ORIGINATE (force) (%s) not originated. (code %d)", lp->ifp->name, ret);
            }
          }
        }
      }
    }
  }

  for (ALL_LIST_ELEMENTS (OspfTE.harmonyIflist, node, nnode, lp))
  {
    if (lp->ifp == NULL)
      continue;

    if (lp->ifp->ospf_instance  != ospf_instance_no)
    {
      continue;
    }

    if (lp->area == NULL)
    {
      if (IS_DEBUG_TE(ORIGINATE))
        zlog_debug("[DBG] OSPF_TE_LSA_ORIGINATE (Harmony %s): NO AREA for this interface", lp->ifp->name);
      continue;
    }

    if (! IPV4_ADDR_SAME (&lp->area->area_id, &area->area_id))
    {
      continue;
    }

    if ((lp->flags & LPFLG_LSA_LI_FORCED_REFRESH) && (lp->flags & LPFLG_LSA_LI_ENGAGED))
    {
      lp->flags &= ~LPFLG_LSA_LI_FORCED_REFRESH;
      ospf_te_lsa_schedule (lp, REFRESH_THIS_LSA, LINK);
      if (IS_DEBUG_TE(ORIGINATE))
        zlog_debug("[DBG] OSPF_TE_LSA_ORIGINATE (Harmony %s): FORCED refresh LINK", lp->ifp->name);
      continue;
    }

    if ((lp->flags & LPFLG_LSA_TNA_FORCED_REFRESH) && (lp->flags & LPFLG_LSA_TNA_ENGAGED))
    {
      lp->flags &= ~LPFLG_LSA_TNA_FORCED_REFRESH;
      ospf_te_lsa_schedule (lp, REFRESH_THIS_LSA, TNA_ADDRESS);
      if (IS_DEBUG_TE(ORIGINATE))
        zlog_debug("[DBG] OSPF_TE_LSA_ORIGINATE (Harmony %s): FORCED refresh TNA_ADDRESS", lp->ifp->name);
      continue;
    }

    //if( lp->tna_address.tna_addr_header.length == 0)
     //  continue;

    if ((lp->flags & LPFLG_LSA_TNA_ENGAGED) == 0)
    {
       ret = ospf_te_lsa_originate1 (area, lp, TNA_ADDRESS);
       if (ret == -1)
       {
          zlog_warn("[WRN] OSPF_TE_LSA_ORIGINATE (Harmony %s): build_tna_addr_tlv(...) in lsa originate failed", lp->ifp->name);
          goto out;
       }
       else if (ret == 1)
       {
        if (IS_DEBUG_TE(ORIGINATE))
         zlog_debug("[DBG] OSPF_TE_LSA_ORIGINATE (Harmony %s): TNA length = 0. LSA will not sent", lp->ifp->name);
       }
       else
       {
         lp->flags |= LPFLG_LSA_TNA_ENGAGED;
         if (IS_DEBUG_TE(ORIGINATE))
           zlog_debug("[DBG] OSPF_TE_LSA_ORIGINATE (Harmony %s): LPFLG_LSA_TNA_ENGAGED", lp->ifp->name);
       }
    }

    if (lp->is_set_linkparams_link_type == 0)
    {
        struct ospf_interface *oi;
        if ((oi = lookup_oi_by_ifp (lp->ifp, NULL, OI_ANY)) != NULL)
        {
          set_linkparams_link_type (oi, lp);
          lp->is_set_linkparams_link_type = 1;
        }
        else
          continue;
    }


    if (IS_DEBUG_TE(ORIGINATE))
      zlog_debug ("[DBG] OSPF_TE_LSA_ORIGINATE (Harmony %s): OSPF instance %s",  lp->ifp->name, OSPF_INST_TO_STR(ospf_instance_no));

    /* Ok, let's try to originate an LSA for this area and Link. */
    if (! is_mandated_params_set (lp))
    {
      struct in_addr tmp;
      if (ntohs(lp->lclif_ipaddr.header.type) != 0)
        tmp = lp->lclif_ipaddr.value[0];
      else
        tmp.s_addr = lp->link_lcl_rmt_ids.local_id;

      zlog_warn ("[WRN] OSPF_TE_LSA_ORIGINATE (Harmony %s): lacks some mandated TE parameters in te-link %s", lp->ifp ? lp->ifp->name : "?", inet_ntoa(tmp));
      continue;
    }

    if ((lp->flags & LPFLG_LSA_LI_ENGAGED) == 0)
    {
      if (ospf_te_lsa_originate1 (area, lp, LINK) != 0)
      {
        zlog_warn("[WRN] OSPF_TE_LSA_ORIGINATE (Harmony %s): build_link_tlv(...) in lsa originate failed", lp->ifp->name);
        goto out;
      }
      else
      {
        lp->flags |= LPFLG_LSA_LI_ENGAGED;
        if (IS_DEBUG_TE(ORIGINATE))
          zlog_debug ("[DBG] OSPF_TE_LSA_ORIGINATE (Harmony %s): LPFLG_LSA_LI_ENGAGED",  lp->ifp->name);
      }
    }
  }
  rc = 0;
out:
  if (IS_DEBUG_TE(ORIGINATE))
    zlog_debug ("[DBG] OSPF_TE_LSA_ORIGINATE: OSPF instance: %s OK",  OSPF_INST_TO_STR(ospf_instance_no));
  return rc;
}


static int
ospf_te_ra_lsa_refresh (struct ospf_lsa *lsa, uint16_t instance_no)
{
  //zlog_debug("ospf_te_ra_lsa_refresh");
  int result = -1;
  struct ospf_lsa *new = NULL;
  struct ospf_area *area = lsa->area;

  unsigned int lsa_instance_no = GET_OPAQUE_ID (ntohl (lsa->data->id.s_addr));

  if ((new = ospf_te_xxx2_lsa_new (area, build_router_addr_tlv , lsa_instance_no, instance_no)) == NULL)
  {
    zlog_warn ("[WRN] OSPF_TE_RA_LSA_REFRESH: ospf_xxx_link_lsa_new() ?");
    goto out;
  }
  new->data->ls_seqnum = lsa_seqnum_increment (lsa);

  /* Install this LSA into LSDB. */
  /* Given "lsa" will be freed in the next function. */
  if (ospf_lsa_install (area->ospf, NULL/*oi*/, new) == NULL)
  {
    zlog_warn ("[WRN] OSPF_TE_RA_LSA_REFRESH: ospf_lsa_install() ?");
    ospf_lsa_unlock (&new);
    goto out;
  }

  /* Flood updated LSA through area. */
  ospf_flood_through_area (area, NULL/*nbr*/, new);

  /* Debug logging. */
  if (IS_DEBUG_OSPF (lsa, LSA_GENERATE))
  {
    if (IS_DEBUG_TE(REFRESH))
      zlog_debug ("[DBG] OSPF_TE_RA_LSA_REFRESH: LSA[Type%d:%s]: Refresh Opaque-LSA/TE",
    new->data->type, inet_ntoa (new->data->id));
    ospf_lsa_header_dump (new->data);
  }

  //zlog_debug("ospf_te_ra_lsa_refresh OK");
  result =0;
out:
  return result;
}

static int
ospf_te_na_lsa_refresh (struct ospf_lsa *lsa, uint16_t instance_no)
{
  int result = -1;
  struct ospf_lsa *new = NULL;
  struct ospf_area *area = lsa->area;

  unsigned int lsa_instance_no = GET_OPAQUE_ID (ntohl (lsa->data->id.s_addr));

  if ((new = ospf_te_xxx2_lsa_new (area, build_node_attr_tlv, lsa_instance_no, instance_no)) == NULL)
    {
      zlog_warn ("[WRN] OSPF_TE_NA_LSA_REFRESH: ospf_xxx_link_lsa_new() ?");
      goto out;
    }
  new->data->ls_seqnum = lsa_seqnum_increment (lsa);

  /* Install this LSA into LSDB. */
  /* Given "lsa" will be freed in the next function. */
  if (ospf_lsa_install (area->ospf, NULL/*oi*/, new) == NULL)
  {
    zlog_warn ("[WRN] OSPF_TE_NA_LSA_REFRESH: ospf_lsa_install() ?");
    ospf_lsa_unlock (&new);
    goto out;
  }

  /* Flood updated LSA through area. */
  ospf_flood_through_area (area, NULL/*nbr*/, new);

  /* Debug logging. */
  if (IS_DEBUG_OSPF (lsa, LSA_GENERATE))
    {
      if (IS_DEBUG_TE(REFRESH))
        zlog_debug ("[DBG] OSPF_TE_NA_LSA_REFRESH: LSA[Type%d:%s]: Refresh Opaque-LSA/TE",
      new->data->type, inet_ntoa (new->data->id));
      ospf_lsa_header_dump (new->data);
    }
  result =0;
out:
  return result;
}
static int
ospf_te_ra_harmony_refresh(struct ospf_lsa *lsa, struct raHarmony *rah)
{
  int result = -1;
  struct ospf_lsa *new = NULL;
  struct ospf_area *area = lsa->area;


  if ((new = ospf_te_ra_harmony_lsa_new(area, rah)) == NULL)
  {
    zlog_warn ("[WRN] OSPF_TE_RA_HARMONY_REFRESH: ospf_te_ra_harmony_lsa_new ?");
    goto out;
  }
  new->data->ls_seqnum = lsa_seqnum_increment (lsa);

  /* Install this LSA into LSDB. */
  /* Given "lsa" will be freed in the next function. */
  if (ospf_lsa_install (area->ospf, NULL/*oi*/, new) == NULL)
  {
    zlog_warn ("[WRN] OSPF_TE_RA_HARMONY_REFRESH: ospf_te_lsa_refresh: ospf_lsa_install() ?");
    ospf_lsa_unlock (&new);
    goto out;
  }

  /* Flood updated LSA through area. */
  ospf_flood_through_area (area, NULL/*nbr*/, new);

  /* Debug logging. */
  if (IS_DEBUG_OSPF (lsa, LSA_GENERATE))
  {
    if (IS_DEBUG_TE(REFRESH))
      zlog_debug ("[DBG] OSPF_TE_RA_HARMONY_REFRESH: LSA[Type%d:%s]: Refresh Opaque-LSA/TE",
    new->data->type, inet_ntoa (new->data->id));
    ospf_lsa_header_dump (new->data);
  }
  result =0;
out:
  return result;
}

static int
ospf_te_xxx_lsa_refresh (struct ospf_lsa *lsa, struct te_link *lp, void (*xxx)(struct stream *s, struct te_link *lp), uint16_t instance_no)
{
  int result = -1;
  struct ospf_lsa *new = NULL;
  struct ospf_area *area = lsa->area;


  if ((new = ospf_te_xxx_lsa_new (area, lp, xxx, instance_no)) == NULL)
    {
      zlog_warn ("[WRN] OSPF_TE_XXX_LSA_REFRESH: ospf_xxx_link_lsa_new() ?");
      goto out;
    }
  new->data->ls_seqnum = lsa_seqnum_increment (lsa);

  /* Install this LSA into LSDB. */
  /* Given "lsa" will be freed in the next function. */
  if (ospf_lsa_install (area->ospf, NULL/*oi*/, new) == NULL)
  {
    zlog_warn ("[WRN] OSPF_TE_XXX_LSA_REFRESH: ospf_te_lsa_refresh: ospf_lsa_install() ?");
    ospf_lsa_unlock (&new);
    goto out;
  }

  /* Flood updated LSA through area. */
  ospf_flood_through_area (area, NULL/*nbr*/, new);

  /* Debug logging. */
  if (IS_DEBUG_OSPF (lsa, LSA_GENERATE))
    {
      if (IS_DEBUG_TE(REFRESH))
        zlog_debug ("[DBG] OSPF_TE_XXX_LSA_REFRESH: LSA[Type%d:%s]: Refresh Opaque-LSA/TE",
      new->data->type, inet_ntoa (new->data->id));
      ospf_lsa_header_dump (new->data);
    }
  result =0;
out:
  return result;
}

static void
ospf_te_lsa_refresh (struct ospf_lsa *lsa)
{
  if (GET_OPAQUE_TYPE(ntohl(lsa->data->id.s_addr)) != OPAQUE_TYPE_TRAFFIC_ENGINEERING_LSA)
    goto out;

  char lsa_info_buf[200];
  log_summary_te_lsa(lsa_info_buf, lsa);
  zlog_debug("[DBG] ospf_te_lsa_refresh: (adv router %s) %s", inet_ntoa(lsa->data->adv_router), lsa_info_buf);

  if (lsa->area->ospf->router_id.s_addr != lsa->data->adv_router.s_addr)
  {
    if (IS_LSA_MAXAGE (lsa))
    {
      if (IS_DEBUG_TE(USER))
      {
        char lsa_info_buf[200];
        log_summary_te_lsa(lsa_info_buf, lsa);
        zlog_debug("[DBG] Flushing not self originated LSA (adv router %s, %s) with Max Age.", inet_ntoa(lsa->data->adv_router), lsa_info_buf);
      }
      ospf_opaque_lsa_flush_schedule (lsa);
    }
    goto out;
  }

  struct ospf *ospf_inni = ospf_inni_lookup();
  struct ospf *ospf_enni = ospf_enni_lookup();
  struct ospf *ospf_uni  = ospf_uni_lookup();

  struct te_link *lp = NULL;
  struct raHarmony *rah = NULL;

  if (OspfTE.status == disabled)
  {
    /*
     * This LSA must have flushed before due to MPLS-TE status change.
     * It seems a slip among routers in the routing domain.
     */
    if (IS_DEBUG_TE(GENERATE))
      zlog_debug ("[DBG] OSPF_TE_LSA_REFRESH: TE is disabled now.");
    lsa->data->ls_age = htons (OSPF_LSA_MAXAGE); /* Flush it anyway. */
    ospf_lsa_checksum (lsa->data);
  }

  unsigned int key = GET_OPAQUE_ID (ntohl (lsa->data->id.s_addr));
  if ((key == OspfTE.ra_instance_id[0]) &&  (lsa->area->ospf == ospf_inni))
    zlog_debug("[DBG] OSPF_TE_LSA_REFRESH: Refreshing RA INNI, key = %d", key);
  else if ((key == OspfTE.ra_instance_id[1]) && (lsa->area->ospf == ospf_enni))
    zlog_debug("[DBG] OSPF_TE_LSA_REFRESH: Refreshing RA ENNI, key = %d", key);
  else if ((key == OspfTE.ra_instance_id[2]) && (lsa->area->ospf == ospf_uni))
    zlog_debug("[DBG] OSPF_TE_LSA_REFRESH: Refreshing RA UNI, key = %d", key);
  else if ((key == OspfTE.na_instance_id[0]) && (lsa->area->ospf == ospf_inni))
    zlog_debug("[DBG] OSPF_TE_LSA_REFRESH: Refreshing NA INNI, key = %d", key);
  else if ((key == OspfTE.na_instance_id[1]) && (lsa->area->ospf == ospf_enni))
    zlog_debug("[DBG] OSPF_TE_LSA_REFRESH: Refreshing NA ENNI, key = %d", key);
  else if ((key == OspfTE.na_instance_id[2]) && (lsa->area->ospf == ospf_uni))
    zlog_debug("[DBG] OSPF_TE_LSA_REFRESH: Refreshing NA UNI, key = %d", key);
  else if (((lp = lookup_linkparams_by_instance (lsa)) == NULL) && ((rah = lookup_rah_by_lsa (lsa)) == NULL))
  {
    //zlog_warn ("[WRN] ospf_te_lsa_refresh: Invalid parameter?");
    //lsa->data->ls_age = htons (OSPF_LSA_MAXAGE); /* Flush it anyway. */

    if (1) /* Check id this LSA if not own LSA moved to differed instance */
    {
      lsa->data->ls_age = htons (OSPF_LSA_MAXAGE); /* Flush it anyway. */
      ospf_lsa_checksum (lsa->data);
    }

    if (IS_LSA_MAXAGE (lsa))
    {
      if (IS_DEBUG_TE(USER))
      {
        char lsa_info_buf[200];
        log_summary_te_lsa(lsa_info_buf, lsa);
        unsigned int key = GET_OPAQUE_ID (ntohl (lsa->data->id.s_addr));
        struct in_addr temp;
        temp.s_addr = htonl(key);
        char lsa_id_buf[17];
        sprintf(lsa_id_buf, "%s", inet_ntoa(temp));
        zlog_debug("[DBG] Flushing LSA (adv router %s, id %s %s) with Max Age: Can't find local struct represented by this LSA", inet_ntoa(lsa->data->adv_router), lsa_id_buf, lsa_info_buf);
      }
      ospf_opaque_lsa_flush_schedule (lsa);
      //ospf_lsa_maxage (lsa->area->ospf, lsa);
    }
    goto out;
  }

  /* If the lsa's age reached to MaxAge, start flushing procedure. */
  if (IS_LSA_MAXAGE (lsa))
  {
    zlog_debug("[DBG] OSPF_TE_LSA_REFRESH: MAXAGE");
    if ((key == OspfTE.ra_instance_id[0]) && (lsa->area->ospf == ospf_inni))
      OspfTE.ra_engaged[0] = 1;
    else if ((key == OspfTE.ra_instance_id[1]) && (lsa->area->ospf == ospf_enni))
      OspfTE.ra_engaged[1] = 1;
    else if ((key == OspfTE.ra_instance_id[2]) && (lsa->area->ospf == ospf_uni))
      OspfTE.ra_engaged[2] = 1;
    else if ((key == OspfTE.na_instance_id[0]) && (lsa->area->ospf == ospf_inni))
      OspfTE.na_engaged[0] = 1;
    else if ((key == OspfTE.na_instance_id[1]) && (lsa->area->ospf == ospf_enni))
      OspfTE.na_engaged[1] = 1;
    else if ((key == OspfTE.na_instance_id[2]) && (lsa->area->ospf == ospf_uni))
      OspfTE.na_engaged[2] = 1;
    else if (lp != NULL)
    {
      if (key == lp->instance_li)
        lp->flags &= ~LPFLG_LSA_LI_ENGAGED;
      else if (key == lp->instance_tna)
        lp->flags &= ~LPFLG_LSA_TNA_ENGAGED;
    }
    else if (rah != NULL)
    {
      rah->engaged = 0;
    }
    else
      zlog_warn("[WRN] OSPF_TE_LSA_REFRESH: Orphant LSA");


    if (IS_DEBUG_TE(USER))
    {
      char lsa_info_buf[200];
      log_summary_te_lsa(lsa_info_buf, lsa);
      zlog_debug("[DBG] Flushing LSA (adv router %s, %s) with Max Age", inet_ntoa(lsa->data->adv_router), lsa_info_buf);
    }
    ospf_opaque_lsa_flush_schedule (lsa);
    goto out;
  }

  if ((key == OspfTE.ra_instance_id[0]) && (lsa->area->ospf == ospf_inni))
  {
    zlog_debug("[DBG] OSPF_TE_XXX_LSA_REFRESH: RA INNI");
    if (ospf_te_ra_lsa_refresh(lsa, 0) == -1)
      goto out;
  }
  else if ((key == OspfTE.ra_instance_id[1]) && (lsa->area->ospf == ospf_enni))
  {
    zlog_debug("[DBG] OSPF_TE_XXX_LSA_REFRESH: RA ENNI");
    if (ospf_te_ra_lsa_refresh(lsa, 1) == -1)
      goto out;
  }
  else if ((key == OspfTE.ra_instance_id[2]) && (lsa->area->ospf == ospf_uni))
  {
    zlog_debug("[DBG] OSPF_TE_XXX_LSA_REFRESH: RA UNI");
    if (ospf_te_ra_lsa_refresh(lsa, 2) == -1)
      goto out;
  }
  else if ((key == OspfTE.na_instance_id[0]) && (lsa->area->ospf == ospf_inni))
  {
    zlog_debug("[DBG] OSPF_TE_XXX_LSA_REFRESH: NA INNI");
    if (ospf_te_na_lsa_refresh(lsa, 0) == -1)
      goto out;
  }
  else if ((key == OspfTE.na_instance_id[1]) && (lsa->area->ospf == ospf_enni))
  {
    zlog_debug("[DBG] OSPF_TE_XXX_LSA_REFRESH: NA ENNI");
    if (ospf_te_na_lsa_refresh(lsa, 1) == -1)
      goto out;
  }
  else if ((key == OspfTE.na_instance_id[2]) && (lsa->area->ospf == ospf_uni))
  {
    zlog_debug("[DBG] OSPF_TE_XXX_LSA_REFRESH: NA UNI");
    if (ospf_te_na_lsa_refresh(lsa, 2) == -1)
      goto out;
  }

  if (lp != NULL)
  {
    if (key == lp->instance_li)
    {
      if (ospf_te_xxx_lsa_refresh(lsa, lp, build_link_tlv, lp->instance_li) == -1)
        goto out;
    }
    if (key == lp->instance_tna)
    {
      if (ospf_te_xxx_lsa_refresh(lsa, lp, build_tna_addr_tlv, lp->instance_tna) == -1)
        goto out;
    }
    /* Create new Opaque-LSA/MPLS-TE instance. */
  }
  if (rah != NULL)
  {
    if (ospf_te_ra_harmony_refresh(lsa, rah) == -1)
      goto out;
  }
out:
  return;
}

void
ospf_te_lsa_schedule (struct te_link *lp, enum sched_opcode opcode, enum type_of_lsa_info lsa_info)
{
  if (lp->area == NULL)
  {
    zlog_err("[ERR] OSPF_TE_LSA_SCHEDULE: lp->area = NULL");
    return;
  }

  struct ospf_lsa lsa;
  struct lsa_header lsah;
  u_int32_t tmp;

  memset (&lsa, 0, sizeof (lsa));
  memset (&lsah, 0, sizeof (lsah));

  lsa.area = lp->area;
  lsa.data = &lsah;
  lsah.type = OSPF_OPAQUE_AREA_LSA;

  switch (lsa_info)
  {
    case ROUTE_ADDRESS:
      tmp = SET_OPAQUE_LSID (OPAQUE_TYPE_TRAFFIC_ENGINEERING_LSA, OspfTE.ra_instance_id[(int)lp->ifp->ospf_instance]);
      break;
    case NODE_ATRIBUTE:
      tmp = SET_OPAQUE_LSID (OPAQUE_TYPE_TRAFFIC_ENGINEERING_LSA, OspfTE.na_instance_id[(int)lp->ifp->ospf_instance]);
      break;
    case LINK:
      tmp = SET_OPAQUE_LSID (OPAQUE_TYPE_TRAFFIC_ENGINEERING_LSA, lp->instance_li);
      break;
    case TNA_ADDRESS:
      tmp = SET_OPAQUE_LSID (OPAQUE_TYPE_TRAFFIC_ENGINEERING_LSA, lp->instance_tna);
      break;
    default:
      zlog_warn("[WRN] OSPF_TE_LSA_SCHEDULE: Can't find appropriate instance number");
      return;
  }

  lsah.id.s_addr = htonl (tmp);

  switch (opcode)
  {
    case REORIGINATE_PER_AREA:
      ospf_opaque_lsa_reoriginate_schedule ((void *) lp->area, 
          OSPF_OPAQUE_AREA_LSA, OPAQUE_TYPE_TRAFFIC_ENGINEERING_LSA);
      break;
    case REFRESH_THIS_LSA:
      ospf_opaque_lsa_refresh_schedule (&lsa);
      break;
    case FLUSH_THIS_LSA:
      switch (lsa_info)
      {
        case ROUTE_ADDRESS:
          OspfTE.ra_engaged[(int)lp->ifp->ospf_instance] = 1;
          break;
        case NODE_ATRIBUTE:
          OspfTE.na_engaged[(int)lp->ifp->ospf_instance] = 1;
          break;
        case LINK:
          lp->flags &= ~LPFLG_LSA_LI_ENGAGED;
          break;
        case TNA_ADDRESS:
          lp->flags &= ~LPFLG_LSA_TNA_ENGAGED;
          break;
      }
      ospf_opaque_lsa_flush_schedule (&lsa);
      break;
    default:
      zlog_warn ("[WRN] OSPF_TE_LSA_SCHEDULE: Unknown opcode (%u)", opcode);
      break;
  }

  return;
}

void
ospf_te_ra_harmony_lsa_schedule (enum sched_opcode opcode, struct ospf *ospf, struct ospf_area * area, struct raHarmony *rah)
{
  struct ospf_lsa lsa;
  struct lsa_header lsah;
  u_int32_t tmp;

  memset (&lsa, 0, sizeof (lsa));
  memset (&lsah, 0, sizeof (lsah));

  lsa.area = area;
  lsa.data = &lsah;
  lsah.type = OSPF_OPAQUE_AREA_LSA;

  tmp = SET_OPAQUE_LSID (OPAQUE_TYPE_TRAFFIC_ENGINEERING_LSA, rah->instance_id);
  lsah.id.s_addr = htonl (tmp);

  switch (opcode)
  {
    case REORIGINATE_PER_AREA:
      if (IS_DEBUG_TE(ORIGINATE))
        zlog_debug("[DBG] OSPF_TE_RA_HARMONY_LSA_SCHEDULE: REORIGINATE_PER_AREA");
      ospf_opaque_lsa_reoriginate_schedule ((void *) area, OSPF_OPAQUE_AREA_LSA, OPAQUE_TYPE_TRAFFIC_ENGINEERING_LSA);
      break;
    case REFRESH_THIS_LSA:
      if (IS_DEBUG_TE(REFRESH))
        zlog_debug("[DBG] OSPF_TE_RA_HARMONY_LSA_SCHEDULE: REFRESH_THIS_LSA");
      ospf_opaque_lsa_refresh_schedule (&lsa);
      break;
    case FLUSH_THIS_LSA:
      if (IS_DEBUG_TE(LSA_DELETE))
        zlog_debug("[DBG] OSPF_TE_RA_HARMONY_LSA_SCHEDULE: FLUSH_THIS_LSA");
      rah->engaged = 0;
      ospf_opaque_lsa_flush_schedule (&lsa);
      break;
    default:
      zlog_warn ("[WRN] OSPF_TE_RA_HARMONY_LSA_SCHEDULE: Unknown opcode (%u)", opcode);
      break;
  }
  return;
}


static void
ospf_te_ra_lsa_schedule (enum sched_opcode opcode, struct ospf *ospf, struct ospf_area * area)
{
  struct ospf_lsa lsa;
  struct lsa_header lsah;
  u_int32_t tmp;

  memset (&lsa, 0, sizeof (lsa));
  memset (&lsah, 0, sizeof (lsah));

  lsa.area = area;
  lsa.data = &lsah;
  lsah.type = OSPF_OPAQUE_AREA_LSA;

  int ospf_instance_no = (int)(ospf->instance);
  if ((ospf_instance_no < 0) || (ospf_instance_no > 2))
  {
    zlog_err("[ERR] OSPF_TE_RA_LSA_SCHEDULE: Wrong OSPF instance");
    return;
  }

  tmp = SET_OPAQUE_LSID (OPAQUE_TYPE_TRAFFIC_ENGINEERING_LSA, OspfTE.ra_instance_id[ospf_instance_no]);
  lsah.id.s_addr = htonl (tmp);

  switch (opcode)
  {
    case REORIGINATE_PER_AREA:
      if (IS_DEBUG_TE(ORIGINATE))
        zlog_debug("[DBG] ospf_te_ra_lsa_schedule: REORIGINATE_PER_AREA, ospf: %s", OSPF_INST_TO_STR(ospf_instance_no));
      ospf_opaque_lsa_reoriginate_schedule ((void *) area, OSPF_OPAQUE_AREA_LSA, OPAQUE_TYPE_TRAFFIC_ENGINEERING_LSA);
      break;
    case REFRESH_THIS_LSA:
      if (IS_DEBUG_TE(REFRESH))
        zlog_debug("[DBG] ospf_te_ra_lsa_schedule: REFRESH_THIS_LSA, ospf: %s", OSPF_INST_TO_STR(ospf_instance_no));
      ospf_opaque_lsa_refresh_schedule (&lsa);
      break;
    case FLUSH_THIS_LSA:
      if (IS_DEBUG_TE(LSA_DELETE))
        zlog_debug("[DBG] ospf_te_ra_lsa_schedule: FLUSH_THIS_LSA, ospf: %s", OSPF_INST_TO_STR(ospf_instance_no));
      OspfTE.ra_engaged[ospf_instance_no] = 0;
      ospf_opaque_lsa_flush_schedule (&lsa);
      break;
    default:
      zlog_warn ("[WRN] ospf_te_ra_lsa_schedule: Unknown opcode (%u)", opcode);
      break;
  }
  return;
}

static void
ospf_te_na_lsa_schedule (enum sched_opcode opcode, struct ospf *ospf, struct ospf_area * area)
{
  struct ospf_lsa lsa;
  struct lsa_header lsah;
  u_int32_t tmp;

  memset (&lsa, 0, sizeof (lsa));
  memset (&lsah, 0, sizeof (lsah));

  lsa.area = area;
  lsa.data = &lsah;
  lsah.type = OSPF_OPAQUE_AREA_LSA;

  int ospf_instance_no = (int) ospf->instance;
  if ((ospf_instance_no < 0) || (ospf_instance_no > 2))
  {
    zlog_err("[ERR] OSPF_TE_NA_LSA_SCHEDULE: Wrong OSPF instance no: %d", ospf_instance_no);
    return;
  }

  tmp = SET_OPAQUE_LSID (OPAQUE_TYPE_TRAFFIC_ENGINEERING_LSA, OspfTE.na_instance_id[ospf_instance_no]);
  lsah.id.s_addr = htonl (tmp);

  switch (opcode)
  {
    case REORIGINATE_PER_AREA:
      ospf_opaque_lsa_reoriginate_schedule ((void *) area, OSPF_OPAQUE_AREA_LSA, OPAQUE_TYPE_TRAFFIC_ENGINEERING_LSA);
      break;
    case REFRESH_THIS_LSA:
      ospf_opaque_lsa_refresh_schedule (&lsa);
      break;
    case FLUSH_THIS_LSA:
      OspfTE.na_engaged[ospf_instance_no] = 0;
      ospf_opaque_lsa_flush_schedule (&lsa);
      break;
    default:
      zlog_warn ("[WRN] OSPF_TE_NA_LSA_SCHEDULE: Unknown opcode (%u)", opcode);
      break;
  }
  return;
}

/*------------------------------------------------------------------------*
 * Followings are vty session control functions.
 *------------------------------------------------------------------------*/

static u_int16_t
show_vty_router_addr_subtlv_router_addr (struct vty *vty, struct te_tlv_header *tlvh)
{
  struct te_router_addr_subtlv_router_addr *top = (struct te_router_addr_subtlv_router_addr *) tlvh;

  if (vty != NULL)
    vty_out (vty, "  Router-Address: %s%s", inet_ntoa (top->value), VTY_NEWLINE);
  else
    zlog_debug ("    Router-Address: %s", inet_ntoa (top->value));

  return TLV_SIZE (tlvh);
}

static u_int16_t
show_vty_router_addr_subtlv_aa_id (struct vty *vty, struct te_tlv_header *tlvh)
{
  struct te_router_addr_subtlv_aa_id *top;

  top = (struct te_router_addr_subtlv_aa_id *) tlvh;
  if (vty != NULL)
    vty_out (vty, "  Associated Area ID: 0x%x%s", (u_int32_t) ntohl (top->area_id), VTY_NEWLINE);
  else
    zlog_debug ("    Associated Area ID: 0x%x", (u_int32_t) ntohl (top->area_id));

  return TLV_SIZE (tlvh);
}


static u_int16_t
show_vty_router_addr_subtlv_power_consumption (struct vty *vty, struct te_tlv_header *tlvh)
{
  struct te_router_addr_subtlv_power_consumption *top;

  top = (struct te_router_addr_subtlv_power_consumption *) tlvh;

  float fval;
  ntohf(&top->power_consumption, &fval);
 
  if (vty != NULL)
    vty_out (vty, "  Power consumption: %g%s", fval, VTY_NEWLINE);
  else
    zlog_debug ("    Power consumption: %g", fval);

  return TLV_SIZE (tlvh);
}


static u_int16_t
show_vty_node_attr_subtlv_lcl_te_router_id (struct vty *vty, struct te_tlv_header *tlvh)
{
  struct te_node_attr_subtlv_lcl_te_router_id *top;

  top = (struct te_node_attr_subtlv_lcl_te_router_id *) tlvh;
  if (vty != NULL)
    vty_out (vty, "  Local TE Router ID: 0x%x%s", (u_int32_t) ntohl (top->lcl_te_router_id), VTY_NEWLINE);
  else
    zlog_debug ("    Local TE Router ID: 0x%x", (u_int32_t) ntohl (top->lcl_te_router_id));

  return TLV_SIZE (tlvh);
}

static u_int16_t
show_vty_node_attr_subtlv_aa_id (struct vty *vty, struct te_tlv_header *tlvh)
{
  struct te_node_attr_subtlv_aa_id *top;

  top = (struct te_node_attr_subtlv_aa_id *) tlvh;
  if (vty != NULL)
    vty_out (vty, "  Associated Area ID: 0x%x%s", (u_int32_t) ntohl (top->area_id), VTY_NEWLINE);
  else
    zlog_debug ("    Associated Area ID: 0x%x", (u_int32_t) ntohl (top->area_id));

  return TLV_SIZE (tlvh);
}

static u_int16_t
show_vty_node_attr_subtlv_node_ip4_lcl_prefix_parsed (struct vty *vty, struct te_tlv_header *tlvh)
{
  struct te_node_attr_subtlv_node_ip4_lcl_prefix *top;
  top = (struct te_node_attr_subtlv_node_ip4_lcl_prefix *) tlvh;

  u_int16_t n= listcount(&top->prefix_list);
  int i;

  if (vty != NULL)
  {
    vty_out (vty, "  Number of IPv4 Local Prefixes: %d%s", n, VTY_NEWLINE);
  }
  else
  {
    zlog_debug ("  Number of IPv4 Local Prefixes: %d", n);
  }

  if (n > 0)
  {
    struct zlistnode *tmp_node = listhead (&top->prefix_list);
    struct prefix_ip4 *data;
    for (i=1; i<=n; i++)
    {
      data = (struct prefix_ip4 *) tmp_node->data;
      if(vty != NULL)
      {
        vty_out (vty, "    Network mask %d: %s%s", i, inet_ntoa (data->netmask), VTY_NEWLINE);
        vty_out (vty, "    IPv4 Address %d: %s%s", i, inet_ntoa (data->address_ip4), VTY_NEWLINE);
      }
      else
      {
        zlog_debug ("    Network mask %d: %s", i, inet_ntoa (data->netmask));
        zlog_debug ("    IPv4 Address %d: %s", i, inet_ntoa (data->address_ip4));
      }
      tmp_node=listnextnode(tmp_node);
    }
  }
  return TLV_SIZE (tlvh);
}
#ifdef GMPLS
static u_int16_t
show_vty_node_attr_subtlv_node_ip6_lcl_prefix_parsed (struct vty *vty, struct te_tlv_header *tlvh)
{
  struct te_node_attr_subtlv_node_ip6_lcl_prefix *top;
  top = (struct te_node_attr_subtlv_node_ip6_lcl_prefix *) tlvh;

  u_int16_t n= listcount(&top->prefix_list);
  int i;

  if (vty != NULL)
  {
    vty_out (vty, "  Number of IPv6 Local Prefixes: %d%s", n, VTY_NEWLINE);
  }
  else
  {
    zlog_debug ("  Number of IPv6 Local Prefixes: %d", n);
  }

  if (n > 0)
  {
    struct zlistnode *tmp_node = listhead (&top->prefix_list);
    struct prefix_ip6 *data;
    for (i=1; i<=n; i++)
    {
      data = (struct prefix_ip6 *) tmp_node->data;
      if(vty != NULL)
      {
        vty_out (vty, "    Prefix Length %d: 0x%x%s", i, (data->prefixlen), VTY_NEWLINE);
        vty_out (vty, "    Prefix Options %d: 0x%x%s", i, (data->prefixopt), VTY_NEWLINE);
        vty_out (vty, "    IPv6 Address %d: %s%s", i, inet6_ntoa (data->address_ip6), VTY_NEWLINE);
      }
      else
      {
        zlog_debug ("    Prefix Length %d: 0x%x", i, (data->prefixlen));
        zlog_debug ("    Prefix Options %d: 0x%x", i, (data->prefixopt));
        zlog_debug ("    IPv6 Address %d: %s", i, inet6_ntoa (data->address_ip6));
      }
      tmp_node=listnextnode(tmp_node);
    }
  }
  return TLV_SIZE (tlvh);
}
#endif /* GMPLS */


static u_int16_t
show_vty_node_attr_subtlv_node_ip6_lcl_prefix_nonparsed (struct vty *vty, struct te_tlv_header *tlvh)
{
  u_int16_t n= (u_int16_t) (TLV_BODY_SIZE(tlvh) / 20);
  int i;

  if (vty != NULL)
  {
    vty_out (vty, "  Number of IPv6 Local Prefixes: %d%s", n, VTY_NEWLINE);
  }
  else
  {
    zlog_debug ("  Number of IPv6 Local Prefixes: %d", n);
  }

  if (n > 0)
  {
    struct prefix_ip6 *data = (struct prefix_ip6 *)((struct te_tlv_header *) (tlvh+1));
    for (i=1; i<=n; i++)
    {
      if(vty != NULL)
      {
        vty_out (vty, "    Prefix Length %d: 0x%x%s", i, (data->prefixlen), VTY_NEWLINE);
        vty_out (vty, "    Prefix Options %d: 0x%x%s", i, (data->prefixopt), VTY_NEWLINE);
        vty_out (vty, "    IPv6 Address %d: %s%s", i, inet6_ntoa (data->address_ip6), VTY_NEWLINE);
      }
      else
      {
        zlog_debug ("    Prefix Length %d: 0x%x", i, (data->prefixlen));
        zlog_debug ("    Prefix Options %d: 0x%x", i, (data->prefixopt));
        zlog_debug ("    IPv6 Address %d: %s", i, inet6_ntoa (data->address_ip6));
      }
      data++;
    }
  }
  return TLV_SIZE (tlvh);
}

static u_int16_t
show_vty_node_attr_subtlv_node_ip4_lcl_prefix_nonparsed (struct vty *vty, struct te_tlv_header *tlvh)
{
  u_int16_t n= (u_int16_t) (TLV_BODY_SIZE(tlvh) / 8);
  int i;

  if (vty != NULL)
  {
    vty_out (vty, "  Number of IPv4 Local Prefixes: %d%s", n, VTY_NEWLINE);
  }
  else
  {
    zlog_debug ("  Number of IPv4 Local Prefixes: %d", n);
  }

  if (n > 0)
  {
    struct prefix_ip4 *data = (struct prefix_ip4 *)((struct te_tlv_header *) (tlvh+1));
    for (i=1; i<=n; i++)
    {
      if(vty != NULL)
      {
        vty_out (vty, "    Network mask %d: %s%s", i, inet_ntoa (data->netmask), VTY_NEWLINE);
        vty_out (vty, "    IPv4 Address %d: %s%s", i, inet_ntoa (data->address_ip4), VTY_NEWLINE);
      }
      else
      {
        zlog_debug ("    Network mask %d: %s", i, inet_ntoa (data->netmask));
        zlog_debug ("    IPv4 Address %d: %s", i, inet_ntoa (data->address_ip4));
      }
      data++;
    }
  }
  return TLV_SIZE (tlvh);
}

/** ************************************************* **/
static u_int16_t
show_vty_tna_addr_subtlv_tna_addr_ipv4 (struct vty *vty, struct te_tlv_header *tlvh)
{
  struct te_tna_addr_subtlv_tna_addr_ipv4 *top = (struct te_tna_addr_subtlv_tna_addr_ipv4 *) tlvh;

  if (top->header.length == ntohs(0))
    return TLV_SIZE (tlvh);

  if (vty != NULL)
    vty_out (vty, "    TNA Address IPv4: %s  Address Length: %d%s", inet_ntoa (top->value), (top->addr_length),VTY_NEWLINE);
  else
    zlog_debug ("    TNA Address IPv4: %s  Address Length: %d", inet_ntoa (top->value), (top->addr_length));

  return TLV_SIZE (tlvh);
}

static u_int16_t
show_vty_tna_addr_subtlv_tna_addr_ipv6 (struct vty *vty, struct te_tlv_header *tlvh)
{
  struct te_tna_addr_subtlv_tna_addr_ipv6 *top = (struct te_tna_addr_subtlv_tna_addr_ipv6 *) tlvh;

  if (top->header.length == ntohs(0))
    return TLV_SIZE (tlvh);

  if (vty != NULL)
    vty_out (vty, "    TNA Address IPv6: %s  Address Length: %d%s", inet6_ntoa (top->value), (top->addr_length), VTY_NEWLINE);
  else
    zlog_debug ("    TNA Address IPv6: %s  Address Length: %d", inet6_ntoa (top->value), (top->addr_length));

  return TLV_SIZE (tlvh);
}

static u_int16_t
show_vty_tna_addr_subtlv_tna_addr_nsap (struct vty *vty, struct te_tlv_header *tlvh)
{
  struct te_tna_addr_subtlv_tna_addr_nsap *top = (struct te_tna_addr_subtlv_tna_addr_nsap *) tlvh;

  if (top->header.length == ntohs(0))
    return TLV_SIZE (tlvh);

  int i;

  if (vty != NULL)
  {
    vty_out (vty, "    TNA Address NSAP: ");
    for (i=0; i <5; i++)
    {
      vty_out (vty, "%x ", (u_int32_t) ntohl (top->value[i]));
    }
    vty_out (vty, "  Adress Length: %d%s",(top->addr_length),VTY_NEWLINE);
  }
  else
  {
    zlog_debug ("    TNA Address NSAP: ");
    for (i=0; i<5; i++)
    {
      zlog_debug ("0x%x", (u_int32_t) ntohl (top->value[i]));
    }
    zlog_debug ("  Address Length: %d",(top->addr_length));
  }
  return TLV_SIZE (tlvh);
}


static u_int16_t
show_vty_tna_addr_subtlv_node_id (struct vty *vty, struct te_tlv_header *tlvh)
{
  struct te_tna_addr_subtlv_node_id *top = (struct te_tna_addr_subtlv_node_id *) tlvh;

  if (top->header.length == ntohs(0))
    return TLV_SIZE (tlvh);

  if (vty != NULL)
    vty_out (vty, "  TNA Node ID: %s%s", inet_ntoa (top->value), VTY_NEWLINE);
  else
    zlog_debug ("  TNA Node ID: %s", inet_ntoa (top->value));

  return TLV_SIZE (tlvh);
}

static uint16_t
show_vty_tna_anc_tlv (struct vty *vty, struct te_tlv_header *tlvh)
{
  struct te_tna_addr_subtlv_anc_rc_id *top = (struct te_tna_addr_subtlv_anc_rc_id *) tlvh;

  if (top->header.length == ntohs(0))
    return TLV_SIZE (tlvh);

  if (vty != NULL)
    vty_out (vty, "  TNA Ancestor ID: %s%s", inet_ntoa (top->value), VTY_NEWLINE);
  else
    zlog_debug ("  TNA Ancestor ID: %s", inet_ntoa (top->value));

  return TLV_SIZE (tlvh);
}

void
show_vty_tna_address_tlv (struct vty *vty, struct te_tlv_header *tlvh)
{
  struct te_tlv_tna_addr *top = (struct te_tlv_tna_addr *) tlvh;

  if (top->header.length == ntohs(0))
    return;

  struct zlistnode *node;
  struct tna_addr_data_element *l_value;
  struct zlistnode *node_in;
  struct tna_addr_value *l_value_in;

  for (ALL_LIST_ELEMENTS_RO (&top->tna_addr_data, node, l_value))
  {
    show_vty_tna_addr_subtlv_node_id (vty, &l_value->node_id.header);
    for (ALL_LIST_ELEMENTS_RO (&l_value->tna_addr, node_in, l_value_in))
    {
      if (l_value_in->tna_addr_ipv4.header.length > 0) show_vty_tna_addr_subtlv_tna_addr_ipv4 (vty, &l_value_in->tna_addr_ipv4.header);
      if (l_value_in->tna_addr_ipv6.header.length > 0) show_vty_tna_addr_subtlv_tna_addr_ipv6 (vty, &l_value_in->tna_addr_ipv6.header);
      if (l_value_in->tna_addr_nsap.header.length > 0) show_vty_tna_addr_subtlv_tna_addr_nsap (vty, &l_value_in->tna_addr_nsap.header);
    }
    show_vty_tna_anc_tlv (vty, &l_value->anc_rc_id.header);
  }
}

/** *********************************************************************** */

static u_int16_t
show_vty_link_header (struct vty *vty, struct te_tlv_header *tlvh)
{
  struct te_tlv_link *top = (struct te_tlv_link *) tlvh;

  if (top->header.length == ntohs(0))
    return TLV_SIZE (tlvh);

  if (vty != NULL)
    vty_out (vty, "  Link: %u octets of data%s", ntohs (top->header.length), VTY_NEWLINE);
  else
    zlog_debug ("    Link: %u octets of data", ntohs (top->header.length));

  return TLV_HDR_SIZE;  /* Here is special, not "TLV_SIZE". */
}

static u_int16_t
show_vty_link_subtlv_link_type (struct vty *vty, struct te_tlv_header *tlvh)
{
  struct te_link_subtlv_link_type *top = (struct te_link_subtlv_link_type *) tlvh;

  if (top->header.length == ntohs(0))
    return TLV_SIZE (tlvh);

  const char *cp = "Unknown";

  switch (top->link_type.value)
    {
    case LINK_TYPE_SUBTLV_VALUE_PTP:
      cp = "Point-to-point";
      break;
    case LINK_TYPE_SUBTLV_VALUE_MA:
      cp = "Multiaccess";
      break;
    default:
      break;
    }

  if (vty != NULL)
    vty_out (vty, "  Link-Type: %s (%u)%s", cp, top->link_type.value, VTY_NEWLINE);
  else
    zlog_debug ("    Link-Type: %s (%u)", cp, top->link_type.value);

  return TLV_SIZE (tlvh);
}

static u_int16_t
show_vty_link_subtlv_link_id (struct vty *vty, struct te_tlv_header *tlvh)
{
  struct te_link_subtlv_link_id *top = (struct te_link_subtlv_link_id *) tlvh;

  if (top->header.length == ntohs(0))
    return TLV_SIZE (tlvh);

  if (vty != NULL)
    vty_out (vty, "  Link-ID: %s%s", inet_ntoa (top->value), VTY_NEWLINE);
  else
    zlog_debug ("    Link-ID: %s", inet_ntoa (top->value));

  return TLV_SIZE (tlvh);
}

static u_int16_t
show_vty_link_subtlv_lclif_ipaddr (struct vty *vty, struct te_tlv_header *tlvh)
{
  struct te_link_subtlv_lclif_ipaddr *top = (struct te_link_subtlv_lclif_ipaddr *) tlvh;

  if (top->header.length == ntohs(0))
    return TLV_SIZE (tlvh);

  int i, n;

  n = ntohs (tlvh->length) / sizeof (top->value[0]);

  if (vty != NULL)
    vty_out (vty, "  Local Interface IP Address(es): %d%s", n, VTY_NEWLINE);
  else
    zlog_debug ("    Local Interface IP Address(es): %d", n);

  for (i = 0; i < n; i++)
    {
      if (vty != NULL)
        vty_out (vty, "    #%d: %s%s", i, inet_ntoa (top->value[i]), VTY_NEWLINE);
      else
        zlog_debug ("      #%d: %s", i, inet_ntoa (top->value[i]));
    }
  return TLV_SIZE (tlvh);
}

static u_int16_t
show_vty_link_subtlv_rmtif_ipaddr (struct vty *vty, struct te_tlv_header *tlvh)
{
  struct te_link_subtlv_rmtif_ipaddr *top = (struct te_link_subtlv_rmtif_ipaddr *) tlvh;
  int i, n;

  if (top->header.length == ntohs(0))
    return TLV_SIZE (tlvh);

  n = ntohs (tlvh->length) / sizeof (top->value[0]);
  if (vty != NULL)
    vty_out (vty, "  Remote Interface IP Address(es): %d%s", n, VTY_NEWLINE);
  else
    zlog_debug ("    Remote Interface IP Address(es): %d", n);

  for (i = 0; i < n; i++)
    {
      if (vty != NULL)
        vty_out (vty, "    #%d: %s%s", i, inet_ntoa (top->value[i]), VTY_NEWLINE);
      else
        zlog_debug ("      #%d: %s", i, inet_ntoa (top->value[i]));
    }
  return TLV_SIZE (tlvh);
}

static u_int16_t
show_vty_link_subtlv_te_metric (struct vty *vty, struct te_tlv_header *tlvh)
{
  struct te_link_subtlv_te_metric *top = (struct te_link_subtlv_te_metric *) tlvh;

  if (top->header.length == ntohs(0))
    return TLV_SIZE (tlvh);

  if (vty != NULL)
    vty_out (vty, "  Traffic Engineering Metric: %u%s", (u_int32_t) ntohl (top->value), VTY_NEWLINE);
  else
    zlog_debug ("    Traffic Engineering Metric: %u", (u_int32_t) ntohl (top->value));

  return TLV_SIZE (tlvh);
}

static u_int16_t
show_vty_link_subtlv_max_bw (struct vty *vty, struct te_tlv_header *tlvh)
{
  struct te_link_subtlv_max_bw *top = (struct te_link_subtlv_max_bw *) tlvh;
  float fval;

  if (top->header.length == ntohs(0))
    return TLV_SIZE (tlvh);

  ntohf (&top->value, &fval);

  if (vty != NULL)
    vty_out (vty, "  Maximum Bandwidth: %g (Bytes/sec)%s", fval, VTY_NEWLINE);
  else
    zlog_debug (  "  Maximum Bandwidth: %g (Bytes/sec)", fval);

  return TLV_SIZE (tlvh);
}

static u_int16_t
show_vty_link_subtlv_max_rsv_bw (struct vty *vty, struct te_tlv_header *tlvh)
{
  struct te_link_subtlv_max_rsv_bw *top = (struct te_link_subtlv_max_rsv_bw *) tlvh;
  float fval;

  if (top->header.length == ntohs(0))
    return TLV_SIZE (tlvh);

  ntohf (&top->value, &fval);

  if (vty != NULL)
    vty_out (vty, "  Maximum Reservable Bandwidth: %g (Bytes/sec)%s", fval, VTY_NEWLINE);
  else
    zlog_debug   ("  Maximum Reservable Bandwidth: %g (Bytes/sec)", fval);

  return TLV_SIZE (tlvh);
}

static u_int16_t
show_vty_link_subtlv_unrsv_bw (struct vty *vty, struct te_tlv_header *tlvh)
{
  struct te_link_subtlv_unrsv_bw *top = (struct te_link_subtlv_unrsv_bw *) tlvh;

  if (top->header.length == ntohs(0))
    return TLV_SIZE (tlvh);

  float fval;
  int i;
  for (i = 0; i < 8; i++)
    {
      ntohf (&top->value[i], &fval);
      if (vty != NULL)
        vty_out (vty, "    Unreserved Bandwidth (pri %d): %g (Bytes/sec)%s", i, fval, VTY_NEWLINE);
      else
        zlog_debug (  "    Unreserved Bandwidth (pri %d): %g (Bytes/sec)", i, fval);
    }

  return TLV_SIZE (tlvh);
}

static u_int16_t
show_vty_link_subtlv_rsc_clsclr (struct vty *vty, struct te_tlv_header *tlvh)
{
  struct te_link_subtlv_rsc_clsclr *top = (struct te_link_subtlv_rsc_clsclr *) tlvh;

  if (top->header.length == ntohs(0))
    return TLV_SIZE (tlvh);

  if (vty != NULL)
    vty_out (vty, "  Resource class/color: 0x%x%s", (u_int32_t) ntohl (top->value), VTY_NEWLINE);
  else
    zlog_debug ("    Resource Class/Color: 0x%x", (u_int32_t) ntohl (top->value));

  return TLV_SIZE (tlvh);
}

static u_int16_t
show_vty_link_subtlv_link_lcl_rmt_ids (struct vty *vty, struct te_tlv_header *tlvh)
{
  struct te_link_subtlv_link_lcl_rmt_ids *top = (struct te_link_subtlv_link_lcl_rmt_ids *) tlvh;

  if (top->header.length == ntohs(0))
    return TLV_SIZE (tlvh);

  if (vty != NULL)
  {
    struct in_addr tmp;
    tmp.s_addr = top->local_id;
    vty_out (vty, "  Local ID: %s", inet_ntoa(tmp));
    tmp.s_addr = top->remote_id;
    vty_out (vty, " Remote ID: %s%s", inet_ntoa(tmp), VTY_NEWLINE);
  }
  else
  {
    struct in_addr tmp;
    tmp.s_addr = top->local_id;
    zlog_debug ("    Local ID: %s", inet_ntoa(tmp));
    tmp.s_addr = top->remote_id;
    zlog_debug (" Remote ID: %s",   inet_ntoa(tmp));
  }
  return TLV_SIZE (tlvh);
}

static u_int16_t
show_vty_link_subtlv_link_protect_type (struct vty *vty, struct te_tlv_header *tlvh)
{
  struct te_link_subtlv_link_protect_type *top = (struct te_link_subtlv_link_protect_type *) tlvh;

  if (top->header.length == ntohs(0))
    return TLV_SIZE (tlvh);

  if (vty != NULL)
    vty_out (vty, "  Protection type: %s%s", val2str(&pair_val_str_protection, top->value), VTY_NEWLINE);
  else
    zlog_debug ("    Protection type: %s", val2str(&pair_val_str_protection, top->value));
 return TLV_SIZE (tlvh);
}

static u_int16_t
show_vty_link_subtlv_if_sw_cap_desc (struct vty *vty, struct te_tlv_header *tlvh)
{
  struct te_link_subtlv_if_sw_cap_desc *top = (struct te_link_subtlv_if_sw_cap_desc *) tlvh;

  if (top->header.length == ntohs(0))
    return TLV_SIZE (tlvh);

  int i;
  float bw;
  if (vty != NULL)
    vty_out (vty, "  Sw. cap: %s, encoding: %s%s", val2str(&pair_val_str_swcap, top->switching_cap), val2str(&pair_val_str_encoding, top->encoding), VTY_NEWLINE);
  else
    zlog_debug ("    Sw. cap: %s, encoding: %s", val2str(&pair_val_str_swcap, top->switching_cap), val2str(&pair_val_str_encoding, top->encoding));

  for (i=0; i < LINK_MAX_PRIORITY; i++)
  {
    ntohf(&top->maxLSPbw[i], &bw);

    if (vty != NULL)
      vty_out (vty, "    max LSP (pri %d): %g (Bytes/sec)%s", i, bw, VTY_NEWLINE);
    else
      zlog_debug (  "    max LSP (pri %d): %g (Bytes/sec)"  , i, bw);
  }

  float minBw;
  switch (top->switching_cap)
  {
    case CAPABILITY_PSC1:
    case CAPABILITY_PSC2:
    case CAPABILITY_PSC3:
    case CAPABILITY_PSC4:
    case CAPABILITY_L2SC:
      ntohf(&top->swcap_specific_info.swcap_specific_psc.min_lsp_bw, &minBw);
      if (vty != NULL)
        vty_out (vty, "    , min lsp bw: %g, MTU: %d%s", minBw, ntohs(top->swcap_specific_info.swcap_specific_psc.mtu), VTY_NEWLINE); 
      else
        zlog_debug (  "    , min lsp bw: %g, MTU: %d", minBw, ntohs(top->swcap_specific_info.swcap_specific_psc.mtu));
      break;
    case CAPABILITY_TDM:
      ntohf(&top->swcap_specific_info.swcap_specific_tdm.min_lsp_bw, &minBw);
      if (vty != NULL)
        vty_out (vty, "    , min lsp bw: %g, indication: %d%s", minBw, (u_char)(top->swcap_specific_info.swcap_specific_tdm.indication), VTY_NEWLINE); 
      else
        zlog_debug (  "    , min lsp bw: %g, indication: %d", minBw, (u_char)(top->swcap_specific_info.swcap_specific_tdm.indication));
      break;
    case CAPABILITY_LSC:
    case CAPABILITY_FSC:
      break;
  }
  return TLV_SIZE (tlvh);
}

static u_int16_t
show_vty_link_subtlv_shared_risk_link_grp_parsed (struct vty *vty, struct te_tlv_header *tlvh)
{
  struct te_link_subtlv_shared_risk_link_grp *top = (struct te_link_subtlv_shared_risk_link_grp *) tlvh;

  if (top->header.length == ntohs(0))
    return TLV_SIZE (tlvh);

  //u_int16_t n= listcount(&top->values);
  u_int16_t n= top->values.count;

  if (vty != NULL)
    vty_out (vty, "  Number of shared risk links: %d%s", n, VTY_NEWLINE);
  else
    zlog_debug ("  Number of shared risk links: %d", n);


  struct zlistnode  *node;
  uint32_t          *data;

  int i=1;
  for(ALL_LIST_ELEMENTS_RO(&top->values, node, data))
  {
    if (vty != NULL)
      vty_out (vty, "   %d) 0x%x%s", i, (u_int32_t) ntohl (*data), VTY_NEWLINE);
    else
      zlog_debug ("     %d) 0x%x",   i, (u_int32_t) ntohl (*data));
    i++;
  }
  return TLV_SIZE (tlvh);
}

static u_int16_t
show_vty_link_subtlv_shared_risk_link_grp_nonparsed (struct vty *vty, struct te_tlv_header *tlvh)
{
//  struct te_link_subtlv_shared_risk_link_grp *top;

//  top = (struct te_link_subtlv_shared_risk_link_grp *) tlvh;

  u_int16_t n= (u_int16_t) (TLV_BODY_SIZE(tlvh) / 4);

  if (vty != NULL)
    vty_out (vty, "  Number of shared risk links: %d%s", n, VTY_NEWLINE);
  else
    zlog_debug ("  Number of shared risk links: %d", n);

  u_int32_t *link_number=(u_int32_t *)((struct te_tlv_header *) (tlvh+1));
  int i;
  for (i=1; i<= n; i++)
  {
    if (vty != NULL)
      vty_out (vty, "   %d) 0x%x%s", i, (u_int32_t) ntohl (*link_number++), VTY_NEWLINE);
    else
      zlog_debug ("     %d) 0x%x", i, (u_int32_t) ntohl (*link_number++));
  }

  return TLV_SIZE (tlvh);
}

static u_int16_t
show_vty_link_subtlv_lcl_rmt_te_router_id (struct vty *vty, struct te_tlv_header *tlvh)
{
  struct te_link_subtlv_lcl_rmt_te_router_id *top = (struct te_link_subtlv_lcl_rmt_te_router_id *) tlvh;

  if (top->header.length == ntohs(0))
    return TLV_SIZE (tlvh);

  if (vty != NULL)
  {
    vty_out (vty, "  Local router ID: 0x%x%s", (u_int32_t) ntohl (top->lcl_router_id), VTY_NEWLINE);
    vty_out (vty, "  Remote router ID: 0x%x%s", (u_int32_t) ntohl (top->rmt_router_id), VTY_NEWLINE);
  }
  else
  {
    zlog_debug ("  Local router ID: 0x%x", (u_int32_t) ntohl (top->lcl_router_id));
    zlog_debug ("  Remote router ID: 0x%x", (u_int32_t) ntohl (top->rmt_router_id));
  }

  return TLV_SIZE (tlvh);
}

/** **************** OIF E-NNI Routing ************************************* */

static u_int16_t
show_vty_link_subtlv_lcl_node_id (struct vty *vty, struct te_tlv_header *tlvh)
{
  struct te_link_subtlv_lcl_node_id *top = (struct te_link_subtlv_lcl_node_id *) tlvh;

  if (top->header.length == ntohs(0))
    return TLV_SIZE (tlvh);

  if (vty != NULL)
    vty_out (vty, "  Local Node ID: %s%s", inet_ntoa (top->value), VTY_NEWLINE);
  else
    zlog_debug ("    Local Node ID: %s", inet_ntoa (top->value));

  return TLV_SIZE (tlvh);
}

static u_int16_t
show_vty_link_subtlv_rmt_node_id (struct vty *vty, struct te_tlv_header *tlvh)
{
  struct te_link_subtlv_rmt_node_id *top = (struct te_link_subtlv_rmt_node_id *) tlvh;

  if (top->header.length == ntohs(0))
    return TLV_SIZE (tlvh);

  if (vty != NULL)
    vty_out (vty, "  Remote Node ID: %s%s", inet_ntoa (top->value), VTY_NEWLINE);
  else
    zlog_debug ("    Remote Node ID: %s", inet_ntoa (top->value));

  return TLV_SIZE (tlvh);
}

static u_int16_t
show_vty_link_subtlv_ssdh_if_sw_cap_desc_parsed (struct vty *vty, struct te_tlv_header *tlvh)
{
  struct te_link_subtlv_ssdh_if_sw_cap_desc *top = (struct te_link_subtlv_ssdh_if_sw_cap_desc *) tlvh;

  if (top->header.length == ntohs(0))
    return TLV_SIZE (tlvh);

  u_int16_t n = listcount (&top->signals_list);
  int i,val;

  if (vty != NULL)
  {
    vty_out (vty, "  Sonet/SDH Interface Switching Capability Descriptor: %s", VTY_NEWLINE);
    vty_out (vty, "    Switching Capability: %s%s" , val2str (&pair_val_str_swcap, top->switching_cap), VTY_NEWLINE);
    vty_out (vty, "    Encoding: %s%s" , val2str (&pair_val_str_encoding, top->encoding), VTY_NEWLINE);
    vty_out (vty, "    Number of Signals: %d%s", n, VTY_NEWLINE);
  }
  else
  {
    zlog_debug ("    Sonet/SDH Interface Switching Capability Descriptor:");
    zlog_debug ("    Switching Capability: %s" , val2str (&pair_val_str_swcap, top->switching_cap));
    zlog_debug ("    Encoding: %s" , val2str (&pair_val_str_encoding, top->encoding));
    zlog_debug ("    Number of Signals: %d", n);
  }

  if (n > 0)
  {
    struct zlistnode *tmp_node = listhead (&top->signals_list);
    struct signal_unalloc_tslots *data;
    for (i=1; i<=n; i++)
    {
      data = (struct signal_unalloc_tslots *) tmp_node->data;
      if(vty != NULL)
      {
        vty_out (vty, "     Signal type %d) %s%s", i, val2str (&pair_val_str_signal_types ,data->signal_type), VTY_NEWLINE);
        vty_out (vty, "     Number of unallocated timeslots %d) 0x", i);
        val = data->unalloc_tslots[0];
        val <<= 8;
        val |= data->unalloc_tslots[1];
        val <<= 8;
        val |= data->unalloc_tslots[2];
        vty_out (vty, "%x", val);
        vty_out (vty, "%s", VTY_NEWLINE);
      }
      else
      {
        zlog_debug ("    Signal type %d) %s",i, val2str (&pair_val_str_signal_types, data->signal_type));
        zlog_debug ("    Number of unallocated timeslots %d) 0x", i);
        val = data->unalloc_tslots[0];
        val <<= 8;
        val |= data->unalloc_tslots[1];
        val <<= 8;
        val |= data->unalloc_tslots[2];
        zlog_debug ("%x", val);
      }
      tmp_node = listnextnode(tmp_node);
    }
  }
  return TLV_SIZE (tlvh);
}

static u_int16_t
show_vty_link_subtlv_ssdh_if_sw_cap_desc_nonparsed (struct vty *vty, struct te_tlv_header *tlvh)
{
  u_int16_t n= (u_int16_t) ((TLV_BODY_SIZE(tlvh) / 4) - 1) ;
  int i,val;

  if (n > 0)
  {
    u_char *ln = (u_char *)((struct te_tlv_header *) (tlvh+1));
    if (vty != NULL)
    {
      vty_out (vty, "  Sonet/SDH Interface Switching Capability Descriptor: %s", VTY_NEWLINE);
      vty_out (vty, "    Switching Capability: %s%s" , val2str (&pair_val_str_swcap, *ln++), VTY_NEWLINE);
      vty_out (vty, "    Encoding: %s%s" , val2str (&pair_val_str_encoding, *ln), VTY_NEWLINE);
      vty_out (vty, "    Number of Signals: %d%s", n, VTY_NEWLINE);
    }
    else
    {
      zlog_debug ("  Sonet/SDH Interface Switching Capability Descriptor:");
      zlog_debug ("    Switching Capability: %s" , val2str (&pair_val_str_swcap, *ln++));
      zlog_debug ("    Encoding: %s" , val2str (&pair_val_str_encoding, *ln));
      zlog_debug ("    Number of Signals: %d", n);
    }
    struct signal_unalloc_tslots *link_number = (struct signal_unalloc_tslots *)((struct te_tlv_header *) (tlvh+2)); 
    for (i=1; i<= n; i++)
    {
      if (vty != NULL)
      {
        vty_out (vty, "     Signal type  %d) %s%s", i, val2str (&pair_val_str_signal_types ,link_number->signal_type), VTY_NEWLINE);
        vty_out (vty, "     Number of unallocated timeslots %d) 0x",i);
        val = link_number->unalloc_tslots[0];
        val <<= 8;
        val |= link_number->unalloc_tslots[1];
        val <<= 8;
        val |= link_number->unalloc_tslots[2];
        vty_out (vty, "%x", val);
        vty_out (vty, "%s", VTY_NEWLINE);
      }
      else
      {
        zlog_debug ("   Signal type %d) %s", i, val2str (&pair_val_str_signal_types, link_number->signal_type));
        zlog_debug ("   Number of unallocated timeslots %d) 0x", i);
        val = link_number->unalloc_tslots[0];
        val <<= 8;
        val |= link_number->unalloc_tslots[1];
        val <<= 8;
        val |= link_number->unalloc_tslots[2];
        zlog_debug ("%x", val);
      }
      link_number++;
    }
  }
  return TLV_SIZE (tlvh);
}

static u_int16_t
show_vty_link_subtlv_general_cap (struct vty *vty, struct te_tlv_header *tlvh)
{
  struct te_link_subtlv_general_cap *top = (struct te_link_subtlv_general_cap *) tlvh;

  if (top->header.length == ntohs(0))
    return TLV_SIZE (tlvh);

  u_int8_t temp,mask;

  if (vty != NULL)
  {
    vty_out (vty, "  General Capabilities: %s", VTY_NEWLINE);

    temp = (top->flags);
    mask = 0x01;
    temp &= 0x03;
    if (temp == mask)
      vty_out (vty, "     Flag S - SONET switching-capable %s",VTY_NEWLINE);

    temp = (top->flags);
    mask = 0x02;
    temp &= 0x03;
    if (temp == mask)
      vty_out (vty, "     Flag S - SDH switching-capable %s",VTY_NEWLINE);

    temp = (top->flags);
    mask = 0x03;
    temp &= 0x03;
    if (temp == mask)
      vty_out (vty, "     Flag S - SONET and SDH switching-capable %s",VTY_NEWLINE);

    temp = (top->flags);
    mask = 0x04;
    temp &= 0x04;
    if (temp == mask )
      vty_out (vty, "     Flag T - Transit control domain %s",VTY_NEWLINE);

    temp = (top->flags);
    mask = 0x08;
    temp &= 0x08;
    if (temp == mask)
      vty_out (vty, "     Flag M - Support branching for point-to-multipoint connections %s",VTY_NEWLINE);
  }
  else
  {
    zlog_debug ("    General Capabilities: ");

    temp = (top->flags);
    mask = 0x01;
    temp &= 0x03;
    if (temp == mask)
      zlog_debug ("     Flag S - SONET switching-capable ");

    temp = (top->flags);
    mask = 0x02;
    temp &= 0x03;
    if (temp == mask)
      zlog_debug ("     Flag S - SDH switching-capable ");

    temp = (top->flags);
    mask = 0x03;
    temp &= 0x03;
    if (temp != mask)
      zlog_debug ("     Flag S - SONET and SDH switching-capable ");

    temp = (top->flags);
    mask = 0x04;
    temp &= 0x04;
    if (temp == mask )
      zlog_debug ("     Flag T - Transit control domain ");

    temp = (top->flags);
    mask = 0x08;
    temp &= 0x08;
    if (temp == mask)
      zlog_debug ("     Flag M - Support branching for point-to-multipoint connections ");
  }
  return TLV_SIZE (tlvh);
}


static u_int16_t
show_vty_link_subtlv_hierarchy_list_parsed (struct vty *vty, struct te_tlv_header *tlvh)
{
  struct te_link_subtlv_hierarchy_list *top = (struct te_link_subtlv_hierarchy_list *) tlvh;

  if (top->header.length == ntohs(0))
    return TLV_SIZE (tlvh);

  u_int16_t n= listcount(&top->hierarchy_list);
  u_int16_t i;

  if (vty != NULL)
    vty_out (vty, "  Number of Routing Controller IDs: %d%s", n, VTY_NEWLINE);
  else
    zlog_debug ("  Number of Routing Controller IDs: %d", n);

  if (n > 0)
  {
    struct zlistnode *tmp_node = listhead(&top->hierarchy_list);
    for (i=1; i<= n; i++)
    {
      if (vty != NULL)
        vty_out (vty, "   %d) %s%s", i, inet_ntoa (*(struct in_addr *)(tmp_node->data)), VTY_NEWLINE);
      else
        zlog_debug ("     %d) %s", i, inet_ntoa (*(struct in_addr *)(tmp_node->data)));
      tmp_node=listnextnode(tmp_node);
    }
  }
  return TLV_SIZE (tlvh);
}

static u_int16_t
show_vty_link_subtlv_hierarchy_list_nonparsed (struct vty *vty, struct te_tlv_header *tlvh)
{

  u_int16_t n= (u_int16_t) (TLV_BODY_SIZE(tlvh) / 4);
  u_int16_t i;

  if (vty != NULL)
    vty_out (vty, "  Number of Routing Controller IDs: %d%s", n, VTY_NEWLINE);
  else
    zlog_debug ("  Number of Routing Controller IDs: %d", n);

  u_int32_t *link_number= (u_int32_t *)((struct te_tlv_header *) (tlvh+1));
  for (i=1; i<= n; i++)
  {
    if (vty != NULL)
        vty_out (vty, "   %d) %s%s", i, inet_ntoa (* ((struct in_addr *) (link_number))), VTY_NEWLINE);
    else
        zlog_debug ("     %d) %s", i, inet_ntoa (* ((struct in_addr *) (link_number))));
  link_number++;
  }
  return TLV_SIZE (tlvh);

}

static u_int16_t
show_vty_link_subtlv_anc_rc_id (struct vty *vty, struct te_tlv_header *tlvh)
{
  struct te_link_subtlv_anc_rc_id *top = (struct te_link_subtlv_anc_rc_id *) tlvh;

  if (top->header.length == ntohs(0))
    return TLV_SIZE (tlvh);

  if (vty != NULL)
    vty_out (vty, "  Ancestor RC (Routing Controller) ID: %s%s", inet_ntoa (top->value), VTY_NEWLINE);
  else
    zlog_debug ("    Ancestor RC (Routing Controller) ID: %s", inet_ntoa (top->value));

  return TLV_SIZE (tlvh);
}

/** *************** GMPLS ASON Routing ******************************** */

static u_int16_t
show_vty_link_subtlv_band_account_parsed (struct vty *vty, struct te_tlv_header *tlvh)
{
  struct te_link_subtlv_band_account *top = (struct te_link_subtlv_band_account *) tlvh;

  if (top->header.length == ntohs(0))
    return TLV_SIZE (tlvh);

  u_int16_t n = listcount (&top->signals_list);
  int i,val;

  if (vty != NULL)
  {
    vty_out (vty, "  Bandwidth Accounting: %s    Number of Signals: %d%s", VTY_NEWLINE, n, VTY_NEWLINE);
  }
  else
  {
    zlog_debug ("  Bandwidth Accounting:  Number of Signals: %d", n);
  }

  val = 0;
  if (n > 0)
  {
    struct zlistnode *tmp_node = listhead (&top->signals_list);
    struct signal_unalloc_tslots *data;
    for (i=1; i<=n; i++)
    {
      data = (struct signal_unalloc_tslots *) tmp_node->data;
      if(vty != NULL)
      {
        vty_out (vty, "    Signal type %d) 0x%x%s", i, (data->signal_type), VTY_NEWLINE);
        vty_out (vty, "    Number of unallocated timeslots %d) 0x", i);
        val = data->unalloc_tslots[0];
        val <<= 8;
        val |= data->unalloc_tslots[1];
        val <<= 8;
        val |= data->unalloc_tslots[2];
        vty_out (vty, "%x", val);
        vty_out (vty, "%s", VTY_NEWLINE);
      }
      else
      {
        zlog_debug ("  Signal type %d) 0x%x", i, (data->signal_type));
        zlog_debug ("  Number of unallocated timeslots %d) 0x", i);
        val = data->unalloc_tslots[0];
        val <<= 8;
        val |= data->unalloc_tslots[1];
        val <<= 8;
        val |= data->unalloc_tslots[2];
        zlog_debug ("%x", val);
      }
    tmp_node = listnextnode(tmp_node);
    }
  }
  return TLV_SIZE (tlvh);
}

static u_int16_t
show_vty_link_subtlv_band_account_nonparsed (struct vty *vty, struct te_tlv_header *tlvh)
{
  u_int16_t n= (u_int16_t) (TLV_BODY_SIZE(tlvh) / 4);
  int i,val;

  val = 0;
  if (n > 0)
  {
    if (vty != NULL)
    {
      vty_out (vty, "  Bandwidth Accounting: %s    Number of Signals: %d%s", VTY_NEWLINE, n, VTY_NEWLINE);
    }
    else
    {
      zlog_debug ("  Bandwidth Accounting:  Number of Signals: %d", n);
    }

    struct signal_unalloc_tslots *link_number = (struct signal_unalloc_tslots *)((struct te_tlv_header *) (tlvh+1)); 
    for (i=1; i<= n; i++)
    {
      if (vty != NULL)
      {
        vty_out (vty, "    Signal type %d) 0x%x%s", i, (link_number->signal_type), VTY_NEWLINE);
        vty_out (vty, "    Number of unallocated timeslots %d) 0x", i);
        val = link_number->unalloc_tslots[0];
        val <<= 8;
        val |= link_number->unalloc_tslots[1];
        val <<= 8;
        val |= link_number->unalloc_tslots[2];
        vty_out (vty, "%x", val);
        vty_out (vty, "%s", VTY_NEWLINE);
      }
      else
      {
        zlog_debug ("  Signal type %d) 0x%x", i, (link_number->signal_type));
        zlog_debug ("  Number of unallocated timeslots %d) 0x", i);
        val = link_number->unalloc_tslots[0];
        val <<= 8;
        val |= link_number->unalloc_tslots[1];
        val <<= 8;
        val |= link_number->unalloc_tslots[2];
        zlog_debug ("%x", val);
      }
      link_number++;
    }
  }
  return TLV_SIZE (tlvh);
}

static u_int16_t
show_vty_link_subtlv_ospf_down_aa_id_parsed (struct vty *vty, struct te_tlv_header *tlvh)
{
  struct te_link_subtlv_ospf_down_aa_id *top = (struct te_link_subtlv_ospf_down_aa_id *) tlvh;

  if (top->header.length == ntohs(0))
    return TLV_SIZE (tlvh);

  u_int16_t n= listcount(&top->area_id_list);

  u_int16_t i;

  if (vty != NULL)
    vty_out (vty, "  Number of OSPF Downstream Associated Area IDs: %d%s", n, VTY_NEWLINE);
  else
    zlog_debug ("  Number of OSPF Downstream Associated Area IDs: %d", n);

  if (n > 0)
  {
    struct zlistnode *tmp_node = listhead(&top->area_id_list);
    for (i=1; i<= n; i++)
    {
      if (vty != NULL)
        vty_out (vty, "   %d) 0x%x%s", i, (u_int32_t) ntohl (*(u_int32_t *)(tmp_node->data)), VTY_NEWLINE);
      else
        zlog_debug ("     %d) 0x%x", i, (u_int32_t) ntohl (*(u_int32_t *)(tmp_node->data)));
      tmp_node=listnextnode(tmp_node);
    }
  } 

  return TLV_SIZE (tlvh);
}

static u_int16_t
show_vty_link_subtlv_ospf_down_aa_id_nonparsed (struct vty *vty, struct te_tlv_header *tlvh)
{
  u_int16_t n= (u_int16_t) (TLV_BODY_SIZE(tlvh) / 4);

  u_int16_t i;

  if (n > 0)
  {
    if (vty != NULL)
      vty_out (vty, "  Number of OSPF Downstream Associated Area IDs: %d%s", n, VTY_NEWLINE);
    else
      zlog_debug ("  Number of OSPF Downstream Associated Area IDs: %d", n);

    u_int32_t *link_number=(u_int32_t *)((struct te_tlv_header *) (tlvh+1));
    for (i=1; i<= n; i++)
    {
      if (vty != NULL)
        vty_out (vty, "   %d) 0x%x%s", i, (u_int32_t) ntohl (*link_number++), VTY_NEWLINE);
      else
        zlog_debug ("     %d) 0x%x", i, (u_int32_t) ntohl (*link_number++));
    }
  }

  return TLV_SIZE (tlvh);
}

static u_int16_t
show_vty_link_subtlv_aa_id (struct vty *vty, struct te_tlv_header *tlvh)
{
  struct te_link_subtlv_aa_id *top = (struct te_link_subtlv_aa_id *) tlvh;

  if (top->header.length == ntohs(0))
    return TLV_SIZE (tlvh);

  if (vty != NULL)
    vty_out (vty, "  Associated Area ID: 0x%x%s", (u_int32_t) ntohl (top->area_id), VTY_NEWLINE);
  else
    zlog_debug ("    Associated Area ID: 0x%x", (u_int32_t) ntohl (top->area_id));

  return TLV_SIZE (tlvh);
}

/** *************** GMPLS All-optical Extensions ********************** */

static u_int16_t
show_vty_link_subtlv_ber_estimate (struct vty *vty, struct te_tlv_header *tlvh)
{
  struct te_link_subtlv_ber_estimate *top = (struct te_link_subtlv_ber_estimate *) tlvh;

  if (top->header.length == ntohs(0))
    return TLV_SIZE (tlvh);

  if (vty != NULL)
    vty_out (vty, "  The exponent from the BER representation: 0x%x%s", (top->value), VTY_NEWLINE);
  else
    zlog_debug ("    The exponent from the BER representation: 0x%x", (top->value));
 return TLV_SIZE (tlvh);
}

static u_int16_t
show_vty_link_subtlv_span_length (struct vty *vty, struct te_tlv_header *tlvh)
{
  struct te_link_subtlv_span_length *top = (struct te_link_subtlv_span_length *) tlvh;

  if (top->header.length == ntohs(0))
    return TLV_SIZE (tlvh);

  if (vty != NULL)
    vty_out (vty, "  Span Lenght: %d [m]%s", (u_int32_t) ntohl (top->value), VTY_NEWLINE);
  else
    zlog_debug ("    Span Lenght: %d [m]", (u_int32_t) ntohl (top->value));

  return TLV_SIZE (tlvh);
}

static u_int16_t
show_vty_link_subtlv_osnr (struct vty *vty, struct te_tlv_header *tlvh)
{
  struct te_link_subtlv_osnr *top = (struct te_link_subtlv_osnr *) tlvh;

  if (top->header.length == ntohs(0))
    return TLV_SIZE (tlvh);

  if (vty != NULL)
    vty_out (vty, "  OSNR: %d [dB]%s", (u_int32_t) ntohl (top->value), VTY_NEWLINE);
  else
    zlog_debug ("    OSNR: %d [dB]", (u_int32_t) ntohl (top->value));

  return TLV_SIZE (tlvh);
}

static u_int16_t
show_vty_link_subtlv_d_pdm (struct vty *vty, struct te_tlv_header *tlvh)
{
  struct te_link_subtlv_d_pdm *top = (struct te_link_subtlv_d_pdm *) tlvh;

  if (top->header.length == ntohs(0))
    return TLV_SIZE (tlvh);

  float fval;
  ntohf (&top->value, &fval);

  if (vty != NULL)
    vty_out (vty, "  Dpdm: %g%s", fval, VTY_NEWLINE);
  else
    zlog_debug ("    Dpdm: %g", fval);

  return TLV_SIZE (tlvh);
}

static u_int16_t
show_vty_link_subtlv_amp_list_parsed (struct vty *vty, struct te_tlv_header *tlvh)
{
  struct te_link_subtlv_amp_list *top = (struct te_link_subtlv_amp_list *) tlvh;

  if (top->header.length == ntohs(0))
    return TLV_SIZE (tlvh);

  u_int16_t n = listcount (&top->amp_list);
  u_int16_t i;

  if (vty != NULL)
  {
    vty_out (vty, "  Number of Amplifiers: %d%s", n, VTY_NEWLINE);
  }
  else
  {
    zlog_debug ("    Number of Amplifiers: %d", n);
  }

  if (n > 0)
  {
    struct zlistnode *tmp_node = listhead (&top->amp_list);
    struct amp_par *data;
    float fval;
    for (i=1; i<=n; i++)
    {
      data = (struct amp_par *) tmp_node->data;
      ntohf (&data->noise, &fval);
      if(vty != NULL)
      {
        vty_out (vty, "    Amplifier %d) gain: %d%s", i,  (u_int32_t) ntohl (data->gain), VTY_NEWLINE);
        vty_out (vty, "    Amplifier %d) noise figure: %g%s", i,  fval, VTY_NEWLINE);
      }
      else
      {
        zlog_debug ("    Amplifier %d) gain: %d", i, (u_int32_t) ntohl (data->gain));
        zlog_debug ("    Amplifier %d) noise figure: %g", i, fval);
      }
      tmp_node=listnextnode(tmp_node);
    }
  }
  return TLV_SIZE (tlvh);
}

static u_int16_t
show_vty_link_subtlv_amp_list_nonparsed (struct vty *vty, struct te_tlv_header *tlvh)
{
  u_int16_t n= (u_int16_t) (TLV_BODY_SIZE(tlvh) / 8);
  int i;

  if (n > 0)
  {
    if (vty != NULL)
    {
      vty_out (vty, "  Number of Amplifiers: %d%s", n, VTY_NEWLINE);
    }
    else
    {
      zlog_debug ("    Number of Amplifiers: %d", n);
    }
    struct amp_par *ln = (struct amp_par *)((struct te_tlv_header *) (tlvh+1));
    float fval;
    for (i=1; i<=n; i++)
    {
      ntohf (&ln->noise, &fval);
      if(vty != NULL)
      {
        vty_out (vty, "    Amplifier %d) gain: %d%s", i, (u_int32_t) ntohl (ln->gain), VTY_NEWLINE);
        vty_out (vty, "    Amplifier %d) noise figure: %g%s", i, fval, VTY_NEWLINE);
      }
      else
      {
        zlog_debug ("    Amplifier %d) gain: %d", i, (u_int32_t) ntohl (ln->gain));
        zlog_debug ("    Amplifier %d) noise figure: %g", i, fval);
      }
      ln++;
    }
  }
  return TLV_SIZE (tlvh);
}

static u_int16_t
show_vty_link_subtlv_av_wave_mask_parsed (struct vty *vty, struct te_tlv_header *tlvh)
{
  struct te_link_subtlv_av_wave_mask *top = (struct te_link_subtlv_av_wave_mask *) tlvh;

  if (top->header.length == ntohs(0))
    return TLV_SIZE (tlvh);

  u_int16_t n= listcount(&top->bitmap_list);
  u_int16_t i;

  if (vty != NULL){
    vty_out (vty, "  Available Wavelegths: %s", VTY_NEWLINE);
    vty_out (vty, "    Action: %d%s", (u_int32_t) top->action, VTY_NEWLINE);
    vty_out (vty, "    Number of wavelengths: 0x%x%s", (u_int32_t) ntohs (top->num_wavelengths), VTY_NEWLINE);
    vty_out (vty, "    Label set description: 0x%x%s", (u_int32_t) ntohl (top->label_set_desc), VTY_NEWLINE);
    vty_out (vty, "    Bitmap: %s", VTY_NEWLINE);
  }
  else{
    zlog_debug ("  Available Wavelegths:");
    zlog_debug ("    Action: %d", (u_int32_t) top->action);
    zlog_debug ("    Number of wavelengths: %d",(u_int16_t) ntohs (top->num_wavelengths));
    zlog_debug ("    Label set description: 0x%x", (u_int32_t) ntohl (top->label_set_desc));
    zlog_debug ("    Bitmap:");
  }

  if (n > 0)
  {
    struct zlistnode *tmp_node = listhead(&top->bitmap_list);
    for (i=1; i<= n; i++)
    {
      if (vty != NULL)
        vty_out (vty, "      %d) 0x%x%s", i,(u_int32_t) ntohl (*(u_int32_t *)(tmp_node->data)), VTY_NEWLINE);
      else
        zlog_debug ("        %d) 0x%x", i, (u_int32_t) ntohl (*(u_int32_t *)(tmp_node->data)));
      tmp_node=listnextnode(tmp_node);
    }
  }
  return TLV_SIZE (tlvh);
}

static u_int16_t
show_vty_link_subtlv_av_wave_mask_nonparsed (struct vty *vty, struct te_tlv_header *tlvh)
{
  u_int16_t n= (u_int16_t) (TLV_BODY_SIZE(tlvh)/4 - 2);
  u_int16_t i;
  u_int16_t *num;
  u_int32_t *lab;

  u_char *ln = (u_char *)((struct te_tlv_header *) (tlvh+1));
  if (vty != NULL){
    vty_out (vty, "  Available Wavelegths: %s", VTY_NEWLINE);
    vty_out (vty, "    Action: %d%s", (u_int32_t) *ln++, VTY_NEWLINE);
    ln++;
    num = (u_int16_t *) ln;
    vty_out (vty, "    Number of wavelengths: %d%s",(u_int16_t) ntohs (*num++), VTY_NEWLINE);
    lab = (u_int32_t *) num;
    vty_out (vty, "    Label set description: 0x%x%s", (u_int32_t) ntohl (*lab++), VTY_NEWLINE);
    vty_out (vty, "    Bitmap: %s", VTY_NEWLINE);
  }
  else{
    zlog_debug ("  Available Wavelegths:");
    zlog_debug ("    Action: %d", (u_int32_t) *ln++);
    ln++;
    num = (u_int16_t *) ln;
    zlog_debug ("    Number of wavelengths: %d", (u_int16_t) ntohs (*num++));
    lab = (u_int32_t *) num;
    zlog_debug ("    Label set description: 0x%x", (u_int32_t) ntohl (*lab++));
    zlog_debug ("    Bitmap:");
  }

  for (i=1; i<= n; i++)
  {
    if (vty != NULL)
      vty_out (vty, "      %d) 0x%x%s", i, (u_int32_t) ntohl (*lab++), VTY_NEWLINE);
    else
      zlog_debug ("        %d) 0x%x", i, (u_int32_t) ntohl (*lab++));
  }
  return TLV_SIZE (tlvh);
}

static u_int16_t
show_vty_link_subtlv_te_link_calendar_parsed (struct vty *vty, struct te_tlv_header *tlvh)
{
  struct te_link_subtlv_te_link_calendar *top = (struct te_link_subtlv_te_link_calendar *) tlvh;

  if (top->header.length == ntohs(0))
    return TLV_SIZE (tlvh);

  u_int16_t n = listcount (&top->te_calendar);
  u_int16_t i,j;

  if (vty != NULL)
    vty_out (vty, "  TE-link Calendar (%d elements): %s", n, VTY_NEWLINE);
  else
    zlog_debug ("  TE-link Calendar (%d elements): ", n);

  if (n > 0)
  {
    struct zlistnode *tmp_node = listhead (&top->te_calendar);
    struct te_link_calendar *data;
    float fval;
    for (j=1; j<=n; j++)
    {
      data = (struct te_link_calendar *) tmp_node->data;
      if(vty != NULL)
      {
        vty_out (vty, "    Time: %d %s", ntohl (data->time), VTY_NEWLINE);
        for (i=0; i<8; i++)
        {
          ntohf (&data->value[i], &fval);
          vty_out (vty, "     Unreserved bandwidth[%d]: %g%s", i, fval, VTY_NEWLINE);
        }
      }
      else
      {
        zlog_debug ("    Time: %d", ntohl (data->time));
        for (i=0; i<8; i++)
        {
          ntohf (&data->value[i], &fval);
          zlog_debug ("     Unreserved bandwidth[%d]: %g", i, fval);
        }
      }
      tmp_node=listnextnode(tmp_node);
    }
  }
  return TLV_SIZE (tlvh);
}

static u_int16_t
show_vty_link_subtlv_te_link_calendar_nonparsed (struct vty *vty, struct te_tlv_header *tlvh)
{
  u_int16_t n= (u_int16_t) (TLV_BODY_SIZE(tlvh) / 36);
  int i,j;

  if (n > 0)
  {
    if (vty != NULL)
    {
      vty_out (vty, "  TE-link calendar (%d elements): %s", n, VTY_NEWLINE);
    }
    else
    {
      zlog_debug ("    TE-link calendar (%d elements): ", n);
    }

    struct te_link_calendar *ln = (struct te_link_calendar *)((struct te_tlv_header *) (tlvh+1));
    float fval;
    for (j=1; j<=n; j++)
    {
      if(vty != NULL)
      {
        vty_out (vty, "    Time: %d %s", (u_int32_t) ntohl (ln->time), VTY_NEWLINE);
        for (i=0; i<8; i++)
        {
          ntohf (&ln->value[i], &fval);
          vty_out (vty, "     Unreserved bandwidth[%d]: %g%s", i, fval, VTY_NEWLINE);
        }
      }
      else
      {
        zlog_debug ("    Time: %d ", (u_int32_t) ntohl (ln->time));
        for (i=0; i<8; i++)
        {
          ntohf (&ln->value[i], &fval);
          zlog_debug ("     Unreserved bandwidth[%d]: %g", i, fval);
        }
      }
      ln++;
    }
  }
  return TLV_SIZE (tlvh);
}

static u_int16_t
show_vty_link_subtlv_power_consumption (struct vty *vty, struct te_tlv_header *tlvh)
{
  struct te_link_subtlv_power_consumption *top = (struct te_link_subtlv_power_consumption *) tlvh;

  if (top->header.length == ntohs(0))
    return TLV_SIZE (tlvh);

  float fval;
  ntohf (&top->power_consumption, &fval);

  if (vty != NULL)
    vty_out (vty, "  Power consumption: %g%s", fval, VTY_NEWLINE);
  else
    zlog_debug ("    Power consumption: %g", fval);

  return TLV_SIZE (tlvh);
}

static u_int16_t
show_vty_link_subtlv_dynamic_replanning (struct vty *vty, struct te_tlv_header *tlvh)
{
  struct te_link_subtlv_dynanic_replanning *top = (struct te_link_subtlv_dynanic_replanning *) tlvh;
  if (top->header.length == ntohs(0))
    return TLV_SIZE (tlvh);

  float fval_upgrade;
  float fval_downgrade;
  ntohf (&top->max_bandwidth_upgrade,   &fval_upgrade);
  ntohf (&top->max_bandwidth_downgrade, &fval_downgrade);

  if (vty != NULL)
    vty_out (vty, "  Dynamic re-planning bandwidth upgrade: %g and downgrade: %g%s", fval_upgrade, fval_downgrade, VTY_NEWLINE);
  else
    zlog_debug ("    Dynamic re-planning bandwidth upgrade: %g and downgrade: %g", fval_upgrade, fval_downgrade);

  return TLV_SIZE (tlvh);
}

static u_int16_t
show_vty_unknown_tlv (struct vty *vty, struct te_tlv_header *tlvh)
{
  if (vty != NULL)
    vty_out (vty, "  Unknown TLV: [type(0x%x), length(0x%x)]%s", ntohs (tlvh->type), ntohs (tlvh->length), VTY_NEWLINE);
  else
    zlog_debug ("    Unknown TLV: [type(0x%x), length(0x%x)]", ntohs (tlvh->type), ntohs (tlvh->length));

  return TLV_SIZE (tlvh);
}


static u_int16_t
ospf_te_show_link_subtlv (struct vty *vty, struct te_tlv_header *tlvh0, u_int16_t subtotal, u_int16_t total)
{
  struct te_tlv_header *tlvh, *next;
  u_int16_t sum = subtotal;

  int type;
  uint16_t u_type;

  for (tlvh = tlvh0; sum < total; tlvh = (next ? next : TLV_HDR_NEXT (tlvh)))
  {
    next = NULL;
    type = ntohs(tlvh->type);
    u_type = (uint16_t)type;

    switch (type)
    {
      case TE_LINK_SUBTLV_LINK_TYPE:
        sum += show_vty_link_subtlv_link_type (vty, tlvh);
        break;
      case TE_LINK_SUBTLV_LINK_ID:
        sum += show_vty_link_subtlv_link_id (vty, tlvh);
        break;
      case TE_LINK_SUBTLV_LCLIF_IPADDR:
        sum += show_vty_link_subtlv_lclif_ipaddr (vty, tlvh);
        break;
      case TE_LINK_SUBTLV_RMTIF_IPADDR:
        sum += show_vty_link_subtlv_rmtif_ipaddr (vty, tlvh);
        break;
      case TE_LINK_SUBTLV_TE_METRIC:
        sum += show_vty_link_subtlv_te_metric (vty, tlvh);
        break;
      case TE_LINK_SUBTLV_MAX_BW:
        sum += show_vty_link_subtlv_max_bw (vty, tlvh);
        break;
      case TE_LINK_SUBTLV_MAX_RSV_BW:
        sum += show_vty_link_subtlv_max_rsv_bw (vty, tlvh);
        break;
      case TE_LINK_SUBTLV_UNRSV_BW:
        sum += show_vty_link_subtlv_unrsv_bw (vty, tlvh);
        break;
      case TE_LINK_SUBTLV_RSC_CLSCLR:
        sum += show_vty_link_subtlv_rsc_clsclr (vty, tlvh);
        break;

      case TE_LINK_SUBTLV_LINK_LCL_RMT_IDS:
        sum += show_vty_link_subtlv_link_lcl_rmt_ids (vty, tlvh);
        break;
      case TE_LINK_SUBTLV_LINK_PROTECT_TYPE:
        sum += show_vty_link_subtlv_link_protect_type (vty, tlvh);
        break;
      case TE_LINK_SUBTLV_IF_SW_CAP_DESC:
        sum += show_vty_link_subtlv_if_sw_cap_desc (vty, tlvh);
        break;
      case TE_LINK_SUBTLV_SHARED_RISK_LINK_GRP:
        sum += show_vty_link_subtlv_shared_risk_link_grp_nonparsed (vty, tlvh);
        break;
      case TE_LINK_SUBTLV_LCL_RMT_TE_ROUTER_ID:
        sum += show_vty_link_subtlv_lcl_rmt_te_router_id (vty, tlvh);
        break;
/** ******************************************************************************************/
      case TE_LINK_SUBTLV_LCL_NODE_ID:
        sum += show_vty_link_subtlv_lcl_node_id (vty, tlvh);
        break;
      case TE_LINK_SUBTLV_RMT_NODE_ID:
        sum += show_vty_link_subtlv_rmt_node_id (vty, tlvh);
        break;
      case TE_LINK_SUBTLV_SSDH_IF_SW_CAP_DESC:
        sum += show_vty_link_subtlv_ssdh_if_sw_cap_desc_nonparsed (vty, tlvh);
        break;
      case TE_LINK_SUBTLV_GENERAL_CAP:
        sum += show_vty_link_subtlv_general_cap (vty, tlvh);
        break;
      case TE_LINK_SUBTLV_HIERARCHY_LIST:
        sum += show_vty_link_subtlv_hierarchy_list_nonparsed (vty, tlvh);
        break;
      case TE_LINK_SUBTLV_ANC_RC_ID:
        sum += show_vty_link_subtlv_anc_rc_id (vty, tlvh); 
        break; 
/** ******************************************************************************************/
      case TE_LINK_SUBTLV_BAND_ACCOUNT:
        sum += show_vty_link_subtlv_band_account_nonparsed (vty, tlvh);
        break;
      case TE_LINK_SUBTLV_OSPF_DOWN_AA_ID:
        sum += show_vty_link_subtlv_ospf_down_aa_id_nonparsed (vty, tlvh);
        break;
      case TE_LINK_SUBTLV_AA_ID:
        sum += show_vty_link_subtlv_aa_id (vty, tlvh);
        break; 
/** ******************************************************************************************/
      case TE_LINK_SUBTLV_BER_ESTIMATE:
        sum += show_vty_link_subtlv_ber_estimate (vty, tlvh);
        break;
      case TE_LINK_SUBTLV_SPAN_LENGTH:
        sum += show_vty_link_subtlv_span_length (vty, tlvh);
        break;
      case TE_LINK_SUBTLV_OSNR:
        sum += show_vty_link_subtlv_osnr (vty, tlvh);
        break;
      case TE_LINK_SUBTLV_D_PDM:
        sum += show_vty_link_subtlv_d_pdm (vty, tlvh);
        break;
      case TE_LINK_SUBTLV_AMP_LIST:
        sum += show_vty_link_subtlv_amp_list_nonparsed (vty, tlvh);
        break;
      case TE_LINK_SUBTLV_AV_WAVE_MASK:
        sum += show_vty_link_subtlv_av_wave_mask_nonparsed (vty, tlvh);
        break;
      case TE_LINK_SUBTLV_TE_LINK_CALENDAR:
        sum += show_vty_link_subtlv_te_link_calendar_nonparsed (vty, tlvh);
        break;
      case TE_LINK_SUBTLV_POWER_CONSUMPTION:
        sum += show_vty_link_subtlv_power_consumption (vty, tlvh);
        break;
      case TE_LINK_SUBTLV_DYNAMIC_REPLANNING:
        sum += show_vty_link_subtlv_dynamic_replanning (vty, tlvh);
        break;

      default:
        zlog_warn("[WRN] ospf_te_show_link_subtlv: Unknown type: %d (0x%x), u_type: %d (0x%x)", type, type, u_type, u_type);
        sum += show_vty_unknown_tlv (vty, tlvh);
        break;
    }
  }
  return sum - subtotal;
}

static u_int16_t
ospf_te_show_tna_addr_subtlv (struct vty *vty, struct te_tlv_header *tlvh0, u_int16_t subtotal, u_int16_t total)
{
  struct te_tlv_header *tlvh, *next;
  u_int16_t sum = subtotal;

  int type;
  for (tlvh = tlvh0; sum < total; tlvh = (next ? next : TLV_HDR_NEXT (tlvh)))
  {
    next = NULL;
    type = ntohs(tlvh->type);
    switch (type)
    {
      case TE_TNA_ADDR_SUBTLV_TNA_ADDR_IPV4:
        sum += show_vty_tna_addr_subtlv_tna_addr_ipv4 (vty, tlvh);
        break;
      case TE_TNA_ADDR_SUBTLV_TNA_ADDR_IPV6:
        sum += show_vty_tna_addr_subtlv_tna_addr_ipv6 (vty, tlvh);
        break;
      case TE_TNA_ADDR_SUBTLV_TNA_ADDR_NSAP:
        sum += show_vty_tna_addr_subtlv_tna_addr_nsap (vty, tlvh);
        break;
      case TE_TNA_ADDR_SUBTLV_NODE_ID:
        sum += show_vty_tna_addr_subtlv_node_id (vty, tlvh);
        break;
      case TE_TNA_ADDR_SUBTLV_ANC_RC_ID:
        sum += show_vty_tna_anc_tlv(vty, tlvh);
        break;
      default:
        vty_out(vty, "TNA has unknown SubTLV: %s", VTY_NEWLINE);
        sum += show_vty_unknown_tlv (vty, tlvh);
        break;
    }
  }
  return sum - subtotal;
}

static u_int16_t
ospf_te_show_node_attr_subtlv (struct vty *vty, struct te_tlv_header *tlvh0,
                               u_int16_t subtotal, u_int16_t total)
{
  struct te_tlv_header *tlvh, *next;
  u_int16_t sum = subtotal;

  for (tlvh = tlvh0; sum < total; tlvh = (next ? next : TLV_HDR_NEXT (tlvh)))
  {
    next = NULL;
    switch (ntohs (tlvh->type))
    {
      case TE_NODE_ATTR_SUBTLV_LCL_TE_ROUTER_ID:
        sum += show_vty_node_attr_subtlv_lcl_te_router_id (vty, tlvh);
        break;
      case TE_NODE_ATTR_SUBTLV_AA_ID:
        sum += show_vty_node_attr_subtlv_aa_id (vty, tlvh);
        break;
      case TE_NODE_ATTR_SUBTLV_NODE_IP4_LCL_PREFIX:
        sum += show_vty_node_attr_subtlv_node_ip4_lcl_prefix_nonparsed (vty, tlvh);
        break; 
      case TE_NODE_ATTR_SUBTLV_NODE_IP6_LCL_PREFIX:
        sum += show_vty_node_attr_subtlv_node_ip6_lcl_prefix_nonparsed (vty, tlvh);
        break; 
      default:
        zlog_warn("[WRN] ospf_te_show_node_attr_subtlv: Unknown SubTLV type: 0x%x in TNA TLV", ntohs (tlvh->type));
        sum += show_vty_unknown_tlv (vty, tlvh);
        break;
    }
  }
  return sum - subtotal;
}

static u_int16_t
ospf_te_show_router_addr_subtlv (struct vty *vty, struct te_tlv_header *tlvh0,
                               u_int16_t subtotal, u_int16_t total)
{
  struct te_tlv_header *tlvh, *next;
  u_int16_t sum = subtotal;

  for (tlvh = tlvh0; sum < total; tlvh = (next ? next : TLV_HDR_NEXT (tlvh)))
  {
    next = NULL;
    switch (ntohs (tlvh->type))
    {
      case TE_ROUTER_ADDR_SUBTLV_ROUTER_ADDR:
        sum += show_vty_router_addr_subtlv_router_addr (vty, tlvh);
        break;
      case TE_ROUTER_ADDR_SUBTLV_AA_ID:
        sum += show_vty_router_addr_subtlv_aa_id (vty, tlvh);
        break;
      case TE_ROUTER_ADDR_SUBTLV_POWER_CONSUMPTION:
        sum += show_vty_router_addr_subtlv_power_consumption (vty, tlvh);
        break;
      default:
        zlog_warn("[WRN] ospf_te_show_router_addr_subtlv: Unknown SubTLV type: 0x%x in RA TLV", ntohs (tlvh->type));
        sum += show_vty_unknown_tlv (vty, tlvh);
        break;
    }
  }
  return sum - subtotal;
}

static void
ospf_te_show_info (struct vty *vty, struct ospf_lsa *lsa)
{
  struct lsa_header *lsah = (struct lsa_header *) lsa->data;
  struct te_tlv_header *tlvh;
  u_int16_t sum, total, l;
  struct te_tlv_link *top;

  total = ntohs (lsah->length) - OSPF_LSA_HEADER_SIZE;
  sum = 0;

  tlvh = TLV_HDR_TOP (lsah);

  while (sum < total)
  {
    switch (ntohs (tlvh->type))
    {
      case TE_TLV_ROUTER_ADDR:
        top = (struct te_tlv_link *) tlvh;
        l = ntohs (top->header.length);
        sum += show_vty_link_header (vty, tlvh);
        sum += ospf_te_show_router_addr_subtlv (vty, tlvh+1, sum, sum + l);
        break;
      case TE_TLV_NODE_ATTR:
        top = (struct te_tlv_link *) tlvh;
        l = ntohs (top->header.length);
        sum += show_vty_link_header (vty, tlvh);
        sum += ospf_te_show_node_attr_subtlv (vty, tlvh+1, sum, sum + l);
        break;
      case TE_TLV_LINK:
        top = (struct te_tlv_link *) tlvh;
        l = ntohs (top->header.length);
        sum += show_vty_link_header (vty, tlvh);
        sum += ospf_te_show_link_subtlv (vty, tlvh+1, sum, sum + l);
        break;
      case TE_TLV_TNA_ADDR:
        top = (struct te_tlv_link *) tlvh;
        l = ntohs (top->header.length);
        sum += show_vty_link_header (vty, tlvh);
        sum += ospf_te_show_tna_addr_subtlv (vty, tlvh+1, sum, sum + l);
        break;
      default:
        zlog_warn("[WRN] ospf_te_show_info: Unknown TLV type: 0x%x in LSA", ntohs (tlvh->type));
        sum += show_vty_unknown_tlv (vty, tlvh);
        break;
    }
    tlvh = (struct te_tlv_header *)((char *)(TLV_HDR_TOP (lsah)) + sum);
  }
  return;
}

/**
 * Writes configuration CLI commands to file or vty assosieted with specyfied interface
 * @param *vty - output
 * @param *interface_type - INNI / ENNI / UNI ospf instance
 */
void ospf_te_config_write_router1 (struct vty *vty, adj_type_t interface_type)
{
  if ((interface_type !=INNI) && (interface_type !=ENNI) && (interface_type !=UNI))
    return;

  vty_out (vty, " te router-address %s%s", inet_ntoa (OspfTE.router_addr[(uint16_t)interface_type].router_addr.value), VTY_NEWLINE);
  if ((ntohs(OspfTE.router_addr[(uint16_t)interface_type].aa_id.header.type) != 0) && (ntohs(OspfTE.router_addr[(uint16_t)interface_type].aa_id.header.length) != 0))
    vty_out (vty, " te router-aa-id 0x%x%s", (u_int32_t) ntohl (OspfTE.router_addr[(uint16_t)interface_type].aa_id.area_id), VTY_NEWLINE);
  if ((ntohs(OspfTE.router_addr[(uint16_t)interface_type].power_consumption.header.type) != 0) && (ntohs(OspfTE.router_addr[(uint16_t)interface_type].power_consumption.header.length) != 0))
    vty_out (vty, " router power consumption %g%s", (u_int32_t) ntohl (OspfTE.router_addr[(uint16_t)interface_type].power_consumption.power_consumption), VTY_NEWLINE);
  if ((ntohs(OspfTE.node_attr[(uint16_t)interface_type].node_ip4_lcl_prefix.header.type) != 0) && (ntohs(OspfTE.node_attr[(uint16_t)interface_type].node_ip4_lcl_prefix.header.length) != 0))
  {
    int i;
    u_int16_t n=listcount(&OspfTE.node_attr[(uint16_t)interface_type].node_ip4_lcl_prefix.prefix_list);
    struct zlistnode *tmp_node = listhead (&OspfTE.node_attr[(uint16_t)interface_type].node_ip4_lcl_prefix.prefix_list);
    struct prefix_ip4 *data;
    for (i=0; i<n; i++)
    {
        data = (struct prefix_ip4 *) tmp_node->data;
        vty_out (vty, " te node-ipv4-lcl-prefix add %s", inet_ntoa (data->netmask));
        vty_out (vty, " %s%s", inet_ntoa (data->address_ip4), VTY_NEWLINE);
        tmp_node=listnextnode(tmp_node);
    }
  } 
  if ((ntohs(OspfTE.node_attr[(uint16_t)interface_type].node_ip6_lcl_prefix.header.type) != 0) && (ntohs(OspfTE.node_attr[(uint16_t)interface_type].node_ip6_lcl_prefix.header.length) != 0))
  {
    int i,j;
    u_int16_t n=listcount(&OspfTE.node_attr[(uint16_t)interface_type].node_ip6_lcl_prefix.prefix_list);
    struct zlistnode *tmp_node = listhead (&OspfTE.node_attr[(uint16_t)interface_type].node_ip6_lcl_prefix.prefix_list);
    struct prefix_ip6 *data;
    for (i=0; i<n; i++)
    {
      data = (struct prefix_ip6 *) tmp_node->data;
      vty_out (vty, " te node-ipv6-lcl-prefix add 0x%x 0x%x ", (data->prefixlen), (data->prefixopt));

      for (j=0; j<=15; j++)
      {
        vty_out (vty, "%x", (data->address_ip6.s6_addr[j]));
      }
      vty_out (vty, "%s", VTY_NEWLINE);

      tmp_node=listnextnode(tmp_node);
    }
  }

  if ((ntohs(OspfTE.node_attr[(uint16_t)interface_type].lcl_te_router_id.header.type) != 0) && (ntohs(OspfTE.node_attr[(uint16_t)interface_type].lcl_te_router_id.header.length) != 0))
  {
    vty_out (vty, " te lcl-te-router-id 0x%x%s", (u_int32_t) ntohl (OspfTE.node_attr[(uint16_t)interface_type].lcl_te_router_id.lcl_te_router_id), VTY_NEWLINE);
  }
  if ((ntohs(OspfTE.node_attr[(uint16_t)interface_type].aa_id.header.type) != 0) && (ntohs(OspfTE.node_attr[(uint16_t)interface_type].aa_id.header.length) != 0))
  {
    vty_out (vty, " te aa-id 0x%x%s", (u_int32_t) ntohl (OspfTE.node_attr[(uint16_t)interface_type].aa_id.area_id), VTY_NEWLINE);
  }
}

static void
ospf_te_config_write_router (struct vty *vty)
{
  if (OspfTE.status == enabled)
  {
    switch(OspfTE.architecture_type)
    {
      case mpls:
        vty_out (vty, " te mpls%s", VTY_NEWLINE);
        break;
      case gmpls:
        vty_out (vty, " te gmpls%s", VTY_NEWLINE);
        break;
      case g2mpls:
        vty_out (vty, " te g2mpls%s", VTY_NEWLINE);
        break;
    }
#ifndef GMPLS 
    ospf_te_config_write_router1 (vty, 0);
#endif /* GMPLS */
  }
  return;
}

/**
 * Writes configuration CLI commands to file or vty assosieted with specyfied interface
 * @param *vty - output
 * @param *ifp - pointer do described interface
 */
static void
ospf_te_config_write_if (struct vty *vty, struct interface *ifp)
{
  struct te_link *lp;

  if ((OspfTE.status == enabled)
  &&  (! if_is_loopback (ifp) && if_is_up (ifp) && ospf_oi_count (ifp) > 0)
  &&  ((lp = lookup_linkparams_by_ifp (ifp)) != NULL))
  {
#ifdef TE_LINK_WRITE_CONFIG
    float fval;
    int i;

    vty_out (vty, " te-link metric %u%s", (u_int32_t) ntohl (lp->te_metric.value), VTY_NEWLINE);

    ntohf (&lp->max_bw.value, &fval);
    if (fval >= MPLS_TE_MINIMUM_BANDWIDTH)
      vty_out (vty, " te-link max-bw %g%s", fval, VTY_NEWLINE);

    ntohf (&lp->max_rsv_bw.value, &fval);
    if (fval >= MPLS_TE_MINIMUM_BANDWIDTH)
      vty_out (vty, " te-link max-rsv-bw %g%s", fval, VTY_NEWLINE);

    for (i = 0; i <  LINK_MAX_PRIORITY; i++)
    {
      ntohf (&lp->unrsv_bw.value[i], &fval);
      if (fval >= MPLS_TE_MINIMUM_BANDWIDTH)
        vty_out (vty, " te-link unrsv-bw %d %g%s", i, fval, VTY_NEWLINE);
    }

    vty_out (vty, " te-link rsc-clsclr 0x%x%s", (u_int32_t) ntohl (lp->rsc_clsclr.value), VTY_NEWLINE);

    if (ntohs(lp->link_lcl_rmt_ids.header.type) != 0)
    {
      vty_out (vty, " te-link local-identifier 0x%x%s", (u_int32_t) ntohl (lp->link_lcl_rmt_ids.local_id), VTY_NEWLINE);
      vty_out (vty, " te-link remote-identifier 0x%x%s", (u_int32_t) ntohl (lp->link_lcl_rmt_ids.remote_id), VTY_NEWLINE);
    }
    if ((ntohs(lp->link_protect_type.header.type) != 0)&&(lp->link_protect_type.value != 0))
      vty_out (vty, " te-link protection %s%s", val2str(&pair_val_str_protection, lp->link_protect_type.value), VTY_NEWLINE);
    float host_min_lsp_bw;
    if (ntohs(lp->if_sw_cap_desc.header.type) != 0)
    {
      switch(lp->if_sw_cap_desc.switching_cap)
      {
        case CAPABILITY_PSC1:
        case CAPABILITY_PSC2:
        case CAPABILITY_PSC3:
        case CAPABILITY_PSC4:
        case CAPABILITY_L2SC:
          ntohf (&lp->if_sw_cap_desc.swcap_specific_info.swcap_specific_psc.min_lsp_bw, &host_min_lsp_bw);
          vty_out (vty, " te-link capability %s %s %g 0x%x%s", val2str(&pair_val_str_swcap, lp->if_sw_cap_desc.switching_cap), val2str(&pair_val_str_encoding, lp->if_sw_cap_desc.encoding), host_min_lsp_bw, ntohs(lp->if_sw_cap_desc.swcap_specific_info.swcap_specific_psc.mtu), VTY_NEWLINE);
          break;
        case CAPABILITY_TDM:
          ntohf (&lp->if_sw_cap_desc.swcap_specific_info.swcap_specific_tdm.min_lsp_bw, &host_min_lsp_bw);
          vty_out (vty, " te-link capability %s %s %g 0x%x%s", val2str(&pair_val_str_swcap, lp->if_sw_cap_desc.switching_cap), val2str(&pair_val_str_encoding, lp->if_sw_cap_desc.encoding), host_min_lsp_bw, lp->if_sw_cap_desc.swcap_specific_info.swcap_specific_tdm.indication, VTY_NEWLINE);
          break;
        case CAPABILITY_LSC:
        case CAPABILITY_FSC:
          vty_out (vty, " te-link capability %s %s%s", val2str(&pair_val_str_swcap, lp->if_sw_cap_desc.switching_cap), val2str(&pair_val_str_encoding, lp->if_sw_cap_desc.encoding), VTY_NEWLINE);
          break;
      }
      for (i = 0; i < LINK_MAX_PRIORITY; i++)
      {
        ntohf (&lp->if_sw_cap_desc.maxLSPbw[i], &fval);
        if (fval >= MPLS_TE_MINIMUM_BANDWIDTH)
          vty_out (vty, " te-link capability maxlspband %d %g %s", i, fval, VTY_NEWLINE);
      }
    }
    if (ntohs(lp->shared_risk_link_grp.header.type) != 0)
    {
      u_int16_t n = lp->shared_risk_link_grp.values->count;
      struct zlistnode *tmp_node = listhead(lp->shared_risk_link_grp.values);
      for (i=0; i< n; i++)
      {
        vty_out (vty, " te-link sharedriscgroup add 0x%x%s", (u_int32_t) ntohl (*(u_int32_t *)(tmp_node->data)), VTY_NEWLINE);
        tmp_node=listnextnode(tmp_node);
      }
    }

    if ((ntohs(lp->lcl_rmt_te_router_id.header.type) != 0) && (ntohs(lp->lcl_rmt_te_router_id.header.length) != 0))
    {
      vty_out (vty, " te-link lcl-rmt-te-router-id 0x%x", (u_int32_t) ntohl (lp->lcl_rmt_te_router_id.lcl_router_id));
      vty_out (vty, " 0x%x%s", (u_int32_t) ntohl (lp->lcl_rmt_te_router_id.rmt_router_id), VTY_NEWLINE);
    }

/* **************** OIF E-NNI Routing ************************************* */
    if ((ntohs(lp->lcl_node_id.header.type) != 0) && (ntohs(lp->lcl_node_id.header.length) != 0))
      vty_out (vty, " te-link local-node-id %s%s", inet_ntoa (lp->lcl_node_id.value), VTY_NEWLINE);
    if ((ntohs(lp->rmt_node_id.header.type) != 0) && (ntohs(lp->rmt_node_id.header.length) != 0))
      vty_out (vty, " te-link remote-node-id %s%s", inet_ntoa (lp->rmt_node_id.value), VTY_NEWLINE);
    if ((ntohs(lp->ssdh_if_sw_cap_desc.header.type) != 0) && (ntohs(lp->ssdh_if_sw_cap_desc.header.length) != 0))
    {
      int j;
      u_int16_t n=listcount(&lp->ssdh_if_sw_cap_desc.signals_list);
      struct zlistnode *tmp_node = listhead (&lp->ssdh_if_sw_cap_desc.signals_list);
      struct signal_unalloc_tslots *data;
      for (i=0; i< n; i++)
      {
        data = (struct signal_unalloc_tslots *) tmp_node->data;
        vty_out (vty, " te-link ssdh-if-sw-cap-desc add %s 0x", val2str (&pair_val_str_signal_types, data->signal_type));
        for (j=2; j>=0; j--)
          vty_out (vty,"%x", data->unalloc_tslots[j]);
        vty_out (vty,"%s", VTY_NEWLINE);
        tmp_node=listnextnode(tmp_node);
      }
    }
    if ((ntohs(lp->general_cap.header.type) != 0) && (ntohs(lp->general_cap.header.length) != 0))
    {
      u_int8_t temp,mask;

      temp = (lp->general_cap.flags);
      mask = 0xFC;
      temp |= 0xFC;
      if (temp != mask)
      {
        temp = lp->general_cap.flags;
        temp &= 0x03;
        vty_out (vty, " te-link general-cap flag-s set %s%s", val2str (&pair_val_str_flags_values, temp), VTY_NEWLINE);
      }
      temp = (lp->general_cap.flags);
      mask = 0x04;
      temp &= 0x04;
      if (temp == mask )
        vty_out (vty, " te-link general-cap flag-t enable %s",VTY_NEWLINE);

      temp = (lp->general_cap.flags);
      mask = 0x08;
      temp &= 0x08;
      if (temp == mask)
        vty_out (vty, " te-link general-cap flag-m enable %s",VTY_NEWLINE);
    }
    if ((ntohs(lp->hierarchy_list.header.type) != 0) && (ntohs(lp->hierarchy_list.header.length) != 0))
    {
      u_int16_t n=listcount(&lp->hierarchy_list.hierarchy_list);
      struct zlistnode *tmp_node = listhead (&lp->hierarchy_list.hierarchy_list);
      for (i=0; i< n; i++)
      {
        vty_out (vty, " te-link hierarchy-list add %s%s", inet_ntoa (*(struct in_addr *)(tmp_node->data)), VTY_NEWLINE);
        tmp_node = listnextnode(tmp_node);
      }
    }
    if ((ntohs(lp->anc_rc_id.header.type) != 0) && (ntohs(lp->anc_rc_id.header.length) != 0))
    {
      vty_out (vty, " te-link ancestor-rc-id %s%s", inet_ntoa (lp->anc_rc_id.value), VTY_NEWLINE);
    }

/* **************** GMPLS ASON Routing ************************************ */
    if ((ntohs(lp->band_account.header.type) != 0) && (ntohs(lp->band_account.header.length) != 0))
    {
      int j;
      u_int16_t n=listcount(&lp->band_account.signals_list);
      struct zlistnode *tmp_node = listhead (&lp->band_account.signals_list);
      struct signal_unalloc_tslots *data;
      for (i=0; i< n; i++)
      {
        data = (struct signal_unalloc_tslots *) tmp_node->data;
        vty_out (vty, " te-link bandwidth-accounting add 0x%x 0x", data->signal_type);
        for (j=0; j<=2; j++)
        {
          vty_out (vty,"%x", data->unalloc_tslots[j]);
        }
        vty_out (vty,"%s", VTY_NEWLINE);
        tmp_node=listnextnode(tmp_node);
      }
    }
    if ((ntohs(lp->ospf_down_aa_id.header.type) != 0) && (ntohs(lp->ospf_down_aa_id.header.length) != 0))
    {
      u_int16_t n=listcount(&lp->ospf_down_aa_id.area_id_list);
      struct zlistnode *tmp_node = listhead (&lp->ospf_down_aa_id.area_id_list);
      for (i=0; i< n; i++)
      {
        vty_out (vty, " te-link ospf-down-aa-id add 0x%x%s", (u_int32_t) ntohl (*(u_int32_t *)tmp_node->data), VTY_NEWLINE);
        tmp_node = listnextnode(tmp_node);
      }
    }
    if ((ntohs(lp->aa_id.header.type) != 0) && (ntohs(lp->aa_id.header.length) != 0))
      vty_out (vty, " te-link aa-id 0x%x%s", (u_int32_t) ntohl (lp->aa_id.area_id), VTY_NEWLINE);

  /** **************** GMPLS All-optical Extensions ************************** */
    if ((ntohs(lp->ber_estimate.header.type) != 0) && (ntohs(lp->ber_estimate.header.length) != 0))
      vty_out (vty, " te-link ber-estimate 0x%x%s",lp->ber_estimate.value, VTY_NEWLINE);
    if ((ntohs(lp->span_length.header.type) != 0) && (ntohs(lp->span_length.header.length) != 0))
      vty_out (vty, " te-link span-length %d%s", (u_int32_t) ntohl (lp->span_length.value), VTY_NEWLINE);
    if ((ntohs(lp->osnr.header.type) != 0) && (ntohs(lp->osnr.header.length) != 0))
      vty_out (vty, " te-link osnr %d%s", (u_int32_t) ntohl (lp->osnr.value), VTY_NEWLINE);
    if ((ntohs(lp->d_pdm.header.type) != 0) && (ntohs(lp->d_pdm.header.length) != 0))
    {
      ntohf (&lp->d_pdm.value, &fval);
      vty_out (vty, " te-link d-pdm %g%s", fval, VTY_NEWLINE);
    }
    if ((ntohs(lp->amp_list.header.type) != 0) && (ntohs(lp->amp_list.header.length) != 0))
    {
      u_int16_t n=listcount(&lp->amp_list.amp_list);
      struct zlistnode *tmp_node = listhead (&lp->amp_list.amp_list);
      struct amp_par *data;
      for (i=0; i< n; i++)
      {
        data = (struct amp_par *) tmp_node->data;
        ntohf (&data->noise, &fval);
        vty_out (vty, " te-link amplifiers-list add %d %g%s", (u_int32_t) ntohl (data->gain), fval, VTY_NEWLINE);
        tmp_node=listnextnode(tmp_node);
      }
    }
    if ((ntohs(lp->av_wave_mask.header.type) != 0) && (ntohs(lp->av_wave_mask.header.length) != 0))
    {
      u_int16_t n=listcount(&lp->av_wave_mask.mask_list);
      struct zlistnode *tmp_node = listhead (&lp->av_wave_mask.mask_list);
      for (i=0; i< n; i++)
      {
        vty_out (vty, " te-link available-wave-mask add 0x%x%s", (u_int32_t) ntohl (*(u_int32_t *)(tmp_node->data)), VTY_NEWLINE);
        tmp_node = listnextnode(tmp_node);
      }
    }
    if ((ntohs(lp->te_link_calendar.header.type) != 0) && (ntohs(lp->te_link_calendar.header.length) != 0))
    {
      u_int16_t n=listcount(&lp->te_link_calendar.te_calendar);
      struct zlistnode *tmp_node = listhead (&lp->te_link_calendar.te_calendar);
      struct te_link_calendar *data;
      for (i=0; i< n; i++)
      {
        /*
        data = (struct amp_par *) tmp_node->data;
        ntohf (&data->noise, &fval);
        vty_out (vty, " te-link amplifiers-list add %d %g%s", (u_int32_t) ntohl (data->gain), fval, VTY_NEWLINE);
        tmp_node=listnextnode(tmp_node);
  */
      }
    }
  /** **************** Geysers Extensions ************************** */
    if ((ntohs(lp->power_consumption.header.type) != 0) && (ntohs(lp->power_consumption.header.length) != 0))
    {
      ntohf (&lp->power_consumption.power_consumption, &fval);
      vty_out (vty, " te-link power consumption %g%s", fval, VTY_NEWLINE);
    }
    if ((ntohs(lp->dynamic_replanning.header.type) != 0) && (ntohs(lp->dynamic_replanning.header.length) != 0))
    {
      float fval_upgrade, fval_downgrade;
      ntohf (&lp->dynamic_replanning.max_bandwidth_upgrade, &fval_upgrade);
      ntohf (&lp->dynamic_replanning.max_bandwidth_downgrade, &fval_downgrade);
      vty_out (vty, " te-link dynamic re-planning max bandwidth upgrade %g and downgrade %g%s", fval_upgrade, fval_downgrade, VTY_NEWLINE);
    }

    /** ****************** **/
    if ((ntohs(lp->tna_address.tna_addr_ipv4.header.type) != 0) && (ntohs(lp->tna_address.tna_addr_ipv4.header.length) != 0))
      vty_out (vty, " te-link tna-address-ipv4 %d %s%s", (lp->tna_address.tna_addr_ipv4.addr_length), inet_ntoa (lp->tna_address.tna_addr_ipv4.value), VTY_NEWLINE);
    if ((ntohs(lp->tna_address.tna_addr_ipv6.header.type) != 0) && (ntohs(lp->tna_address.tna_addr_ipv6.header.length) != 0))
    {
      vty_out (vty, " te-link tna-address-ipv6 %d ", (lp->tna_addr_ipv6.addr_length));
      for (i=0; i<=15; i++)
      {
        vty_out (vty, "%x", (lp->tna_address.tna_addr_ipv6.value.s6_addr[i]));
      }
      vty_out (vty, "%s", VTY_NEWLINE);
    }
    if ((ntohs(lp->tna_address.tna_addr_nsap.header.type) != 0) && (ntohs(lp->tna_address.tna_addr_nsap.header.length) != 0))
    {
      vty_out (vty, " te-link tna-address-nsap %d ", (lp->tna_address.tna_addr_nsap.addr_length));
      for (i=4; i>=0; i--)
      {
        vty_out (vty, "%x ", (u_int32_t) ntohl (lp->tna_address.tna_addr_nsap.value[i]));
      }
      vty_out (vty, "%s", VTY_NEWLINE);
    }
    if ((ntohs(lp->tna_address.node_id.header.type) != 0) && (ntohs(lp->tna_address.node_id.header.length) != 0))
      vty_out (vty, " te-link node-id %s%s", inet_ntoa (lp->tna_address.node_id.value), VTY_NEWLINE);
    /** ********************* **/

    if (CHECK_FLAG(lp->flags, LPFLG_LSA_ORIGINATED))
      vty_out (vty, " te-link area %s%s", inet_ntoa (lp->area_adr), VTY_NEWLINE);
#endif /* TE_LINK_WRITE_CONFIG */
  }
  return;
}


/*------------------------------------------------------------------------*
 * Followings are vty command functions.
 *------------------------------------------------------------------------*/

DEFUN (reoriginate_te,
       reoriginate_te_cmd,
       "te reoriginate",
       "Configure GMPLS-TE parameters\n"
       "Reoriginate TE links\n")
{
  if (OspfTE.status == disabled)
  {
    vty_out(vty, "Ospf Te is disabled. Enable Ospf Te first%s", VTY_NEWLINE);
    return CMD_WARNING;
  }

  struct zlistnode *node, *nnode;

  struct ospf *ospf = (struct ospf*) vty->index;
  struct ospf_area *area;

  for (ALL_LIST_ELEMENTS (ospf->areas, node, nnode, area))
    ospf_te_lsa_originate(area);

  return CMD_SUCCESS;
}

DEFUN (te_force_originate,
       te_force_originate_cmd,
       "te force-originate",
       "Configure TE parameters\n"
       "Originate without neighbors\n")
{
  struct ospf *ospf = (struct ospf *) vty->index;
  UNSET_FLAG (ospf->opaque, OPAQUE_BLOCK_TYPE_10_LSA_BIT);
  return CMD_SUCCESS;
}

DEFUN (te_tna_force,
       te_tna_force_cmd,
       "te tna force-originate",
       "Configure TE parameters\n"
       "Transport Network Address\n"
       "Originate without clients\n")
{
  struct ospf *ospf = (struct ospf *) vty->index;
  ospf->read_tna = 1;
  return CMD_SUCCESS;
}


DEFUN (te,
       te_cmd,
       "te",
       "Configure TE parameters\n"
       "Enable the TE functionality\n")
{
  struct ospf *ospf = (struct ospf *) vty->index;

  struct zlistnode *node, *nnode;
  struct te_link *lp;

  if (OspfTE.status == enabled)
    return CMD_SUCCESS;

  if (IS_DEBUG_OSPF_EVENT)
    zlog_debug ("[DBG] TE: OFF -> ON");

  OspfTE.status = enabled;

  /*
   * Following code is intended to handle two cases;
   *
   * 1) MPLS-TE was disabled at startup time, but now become enabled.
   * 2) MPLS-TE was once enabled then disabled, and now enabled again.
   */
  for (ALL_LIST_ELEMENTS (OspfTE.iflist, node, nnode, lp))
    initialize_linkparams (lp);

  ospf_te_foreach_area (ospf_te_lsa_schedule, REORIGINATE_PER_AREA, LINK);
  ospf_te_foreach_area (ospf_te_lsa_schedule, REORIGINATE_PER_AREA, TNA_ADDRESS);

  struct ospf_area *area;

  for (ALL_LIST_ELEMENTS_RO(ospf->areas, node, area))
  {
    ospf_te_ra_lsa_schedule (REORIGINATE_PER_AREA, ospf, area);
    ospf_te_na_lsa_schedule (REORIGINATE_PER_AREA, ospf, area);
  }

  if (IS_DEBUG_OSPF_EVENT)
    zlog_debug ("[DBG] TE: OFF -> ON OK");

  return CMD_SUCCESS;
}

DEFUN (mpls_te,
       mpls_te_cmd,
       "te mpls",
       "Configure MPLS-TE parameters\n"
       "Enable the MPLS-TE functionality\n")
{
  struct ospf *ospf = (struct ospf *) vty->index;

  struct zlistnode *node, *nnode;
  struct te_link *lp;

  if ((OspfTE.status == enabled)&&(OspfTE.architecture_type == mpls))
    return CMD_SUCCESS;

  if (IS_DEBUG_OSPF_EVENT)
    zlog_debug ("[DBG] TE: OFF -> ON");

  OspfTE.status = enabled;
  ospf_te_set_architecture_mpls();

  /*
   * Following code is intended to handle two cases;
   *
   * 1) MPLS-TE was disabled at startup time, but now become enabled.
   * 2) MPLS-TE was once enabled then disabled, and now enabled again.
   */
  for (ALL_LIST_ELEMENTS (OspfTE.iflist, node, nnode, lp))
    initialize_linkparams (lp);

  ospf_te_foreach_area (ospf_te_lsa_schedule, REORIGINATE_PER_AREA, LINK);
  ospf_te_foreach_area (ospf_te_lsa_schedule, REORIGINATE_PER_AREA, TNA_ADDRESS);

  struct ospf_area *area;

  for (ALL_LIST_ELEMENTS_RO(ospf->areas, node, area))
  {
    ospf_te_ra_lsa_schedule (REORIGINATE_PER_AREA, ospf, area);
    ospf_te_na_lsa_schedule (REORIGINATE_PER_AREA, ospf, area);
  }

  return CMD_SUCCESS;
}

DEFUN (gmpls_te,
       gmpls_te_cmd,
       "te gmpls",
       "Configure GMPLS-TE parameters\n"
       "Enable the GMPLS-TE functionality\n")
{
  struct ospf *ospf = (struct ospf *) vty->index;

  if ((OspfTE.status == enabled)&&(OspfTE.architecture_type == gmpls))
    return CMD_SUCCESS;

  struct ospf_area *area;
  struct zlistnode *node, *nnode;
  struct te_link *lp;

  if (IS_DEBUG_OSPF_EVENT)
    zlog_debug ("[DBG] TE: OFF -> ON");

  OspfTE.status = enabled;
  ospf_te_set_architecture_gmpls();
  /*
   * Following code is intended to handle two cases;
   *
   * 1) MPLS-TE was disabled at startup time, but now become enabled.
   * 2) MPLS-TE was once enabled then disabled, and now enabled again.
   */
  for (ALL_LIST_ELEMENTS (OspfTE.iflist, node, nnode, lp))
    initialize_linkparams (lp);

  ospf_te_foreach_area (ospf_te_lsa_schedule, REORIGINATE_PER_AREA, LINK);
  ospf_te_foreach_area (ospf_te_lsa_schedule, REORIGINATE_PER_AREA, TNA_ADDRESS);

  for (ALL_LIST_ELEMENTS(ospf->areas, node, nnode, area))
  {
    ospf_te_ra_lsa_schedule (REORIGINATE_PER_AREA, ospf, area);
    ospf_te_na_lsa_schedule (REORIGINATE_PER_AREA, ospf, area);
  }

  if (IS_DEBUG_OSPF_EVENT)
    zlog_debug ("[DBG] TE: OFF -> ON OK");

  return CMD_SUCCESS;
}

DEFUN (g2mpls_te,
       g2mpls_te_cmd,
       "te g2mpls",
       "Configure MPLS-TE parameters\n"
       "Enable the MPLS-TE functionality\n")
{
  struct ospf *ospf = (struct ospf*) vty->index;

  if ((OspfTE.status == enabled)&&(OspfTE.architecture_type == g2mpls))
    return CMD_SUCCESS;

  if (IS_DEBUG_OSPF_EVENT)
    zlog_debug ("[DBG] TE: OFF -> ON");

  OspfTE.status = enabled;
  ospf_te_set_architecture_g2mpls();

  /*
   * Following code is intended to handle two cases;
   *
   * 1) MPLS-TE was disabled at startup time, but now become enabled.
   * 2) MPLS-TE was once enabled then disabled, and now enabled again.
   */

  struct zlistnode *node;
  struct ospf_area *area;

  for (ALL_LIST_ELEMENTS_RO(ospf->areas, node, area))
  {
    ospf_te_ra_lsa_schedule (REORIGINATE_PER_AREA, ospf, area);
    ospf_te_na_lsa_schedule (REORIGINATE_PER_AREA, ospf, area);
  }
  ospf_te_foreach_area (ospf_te_lsa_schedule, REORIGINATE_PER_AREA, LINK);
  ospf_te_foreach_area (ospf_te_lsa_schedule, REORIGINATE_PER_AREA, TNA_ADDRESS);

  if (IS_DEBUG_OSPF_EVENT)
    zlog_debug ("[DBG] TE: OFF -> ON OK");

  return CMD_SUCCESS;
}

ALIAS (te,
       te_on_cmd,
       "te on",
       "Configure TE parameters\n"
       "Enable the TE functionality\n")

DEFUN (no_te,
       no_te_cmd,
       "no te",
       NO_STR
       "Configure TE parameters\n"
       "Disable the TE functionality\n")
{
  struct zlistnode *node, *nnode;
  struct te_link *lp;

  if (OspfTE.status == disabled)
    return CMD_SUCCESS;

  if (IS_DEBUG_OSPF_EVENT)
    zlog_debug ("[DBG] TE: ON -> OFF");

  OspfTE.status = disabled;

  for (ALL_LIST_ELEMENTS (OspfTE.iflist, node, nnode, lp))
    if (lp->area != NULL)
    {
      if (lp->flags & LPFLG_LSA_LI_ENGAGED)
        ospf_te_lsa_schedule (lp, FLUSH_THIS_LSA, LINK);
      if (lp->flags & LPFLG_LSA_TNA_ENGAGED)
        ospf_te_lsa_schedule (lp, FLUSH_THIS_LSA, TNA_ADDRESS);
    }
  return CMD_SUCCESS;
}

DEFUN (te_router_addr_subtlv_router_addr,
       te_router_addr_subtlv_router_addr_cmd,
       "te router-address A.B.C.D",
       "TE specific commands\n"
       "Stable IP address of the advertising router\n"
       "TE router address in IPv4 address format\n")
{
//  struct te_tlv_router_addr *ra = &OspfTE.router_addr;
  struct in_addr value;

  if (! inet_aton (argv[0], &value))
  {
    vty_out (vty, "Please specify Router-Addr by A.B.C.D%s", VTY_NEWLINE);
    return CMD_WARNING;
  }

  struct ospf *ospf = (struct ospf*) vty->index;
  set_te_router_addr (value, ospf->instance);

  if (OspfTE.status == disabled)
    goto out;

  struct zlistnode *node;
  struct ospf_area *area;
  for (ALL_LIST_ELEMENTS_RO(ospf->areas, node, area))
  {
    if (OspfTE.ra_engaged[(int)ospf->instance] == 1)
    {
      OspfTE.ra_force_refreshed[(int)ospf->instance] = 1;
      ospf_te_ra_lsa_schedule (REFRESH_THIS_LSA, ospf, area);
    }
    else
      ospf_te_ra_lsa_schedule (REORIGINATE_PER_AREA, ospf, area);
  }
out:
  return CMD_SUCCESS;
}

DEFUN (te_router_addr_subtlv_aa_id,
       te_router_addr_subtlv_aa_id_cmd,
       "te router-aa-id AREA-ID",
       "TE specific commands\n"
       "Configure Associated Area ID\n"
       "(32-bit Hexadecimal value; ex. 0xa1a1a1a1)\n"
       "<cr>\n")
{
  u_int32_t value;
  if (sscanf (argv[0], "0x%x", &value) != 1)
  {
    vty_out (vty, "te_router_addr_aa_id: %s%s", safe_strerror (errno), VTY_NEWLINE);
    return CMD_WARNING;
  }

  struct ospf *ospf = (struct ospf*) vty->index;
  set_ason_aa_id_router_addr (value, ospf->instance);

  if (OspfTE.status == disabled)
    goto out;


  struct zlistnode *node;
  struct ospf_area *area;

  for (ALL_LIST_ELEMENTS_RO(ospf->areas, node, area))
  {
    if (OspfTE.ra_engaged[(int)ospf->instance] == 1)
    {
      OspfTE.ra_force_refreshed[(int)ospf->instance] = 1;
      ospf_te_ra_lsa_schedule (REFRESH_THIS_LSA, ospf, area);
    }
    else
      ospf_te_ra_lsa_schedule (REORIGINATE_PER_AREA, ospf, area);
  }
out:
  return CMD_SUCCESS;
}

DEFUN (te_router_addr_subtlv_power_consumption,
       te_router_addr_subtlv_power_consumption_cmd,
       "te power-consumption POWER-CONSUMPTION",
       "TE specific commands\n"
       "Configure router power consumption\n"
       "Bytes/second (IEEE floating point format)\n"
       "<cr>\n")
{

  float value;
  if (sscanf (argv[0], "%g", &value) != 1)
  {
    vty_out (vty, "te_router_power_consumption: %s%s", safe_strerror (errno), VTY_NEWLINE);
    return CMD_WARNING;
  }

  struct ospf *ospf = (struct ospf*) vty->index;
  uint32_t tmp = 0;
  memcpy(&tmp, &value, 4);
  set_router_power_consumption (&tmp, ospf->instance);

  if (OspfTE.status == disabled)
    goto out;


  struct zlistnode *node;
  struct ospf_area *area;

  for (ALL_LIST_ELEMENTS_RO(ospf->areas, node, area))
  {
    if (OspfTE.ra_engaged[(int)ospf->instance] == 1)
    {
      OspfTE.ra_force_refreshed[(int)ospf->instance] = 1;
      ospf_te_ra_lsa_schedule (REFRESH_THIS_LSA, ospf, area);
    }
    else
      ospf_te_ra_lsa_schedule (REORIGINATE_PER_AREA, ospf, area);
  }
out:
  return CMD_SUCCESS;
}

DEFUN (te_node_attr_subtlv_lcl_te_router_id,
       te_node_attr_subtlv_lcl_te_router_id_cmd,
       "te lcl-te-router-id ROUTER-ID",
       "TE specific commands\n"
       "Configure Local TE Router ID\n"
       "(32-bit Hexadecimal value; ex. 0xa1a1a1a1)\n"
       "<cr>\n")
{
  u_int32_t value;
  if (sscanf (argv[0], "0x%x", &value) != 1)
  {
    vty_out (vty, "te_node_attr_lcl_te_router_id: %s%s", safe_strerror (errno), VTY_NEWLINE);
    return CMD_WARNING;
  }

  struct ospf *ospf = (struct ospf*) vty->index; 
  set_ason_lcl_te_router_id (value, ospf -> instance);

  if (OspfTE.status == disabled)
    goto out;

  struct zlistnode *node;
  struct ospf_area *area;

  for (ALL_LIST_ELEMENTS_RO(ospf->areas, node, area))
  {
    if (OspfTE.na_engaged[(int)ospf->instance] == 1)
      OspfTE.na_force_refreshed[(int)ospf->instance] = 1;
    else
      ospf_te_na_lsa_schedule (REFRESH_THIS_LSA, ospf, area);

    if (OspfTE.na_engaged[(int)ospf->instance] == 1)
      ospf_te_na_lsa_schedule (REORIGINATE_PER_AREA, ospf, area);
  }
out:
  return CMD_SUCCESS;
}

#ifdef GMPLS

DEFUN (te_node_attr_subtlv_aa_id,
       te_node_attr_subtlv_aa_id_cmd,
       "te aa-id AREA-ID",
       "TE specific commands\n"
       "Configure Associated Area ID\n"
       "(32-bit Hexadecimal value; ex. 0xa1a1a1a1)\n"
       "<cr>\n")
{
  u_int32_t value;
  if (sscanf (argv[0], "0x%x", &value) != 1)
  {
    vty_out (vty, "te_node_attr_aa_id: %s%s", safe_strerror (errno), VTY_NEWLINE);
    return CMD_WARNING;
  }
  struct ospf *ospf=(struct ospf*) vty->index;

  set_ason_aa_id_node_attr (value, ospf->instance);

  if (OspfTE.status == disabled)
    goto out;

  struct zlistnode *node;
  struct ospf_area *area;

  for (ALL_LIST_ELEMENTS_RO(ospf->areas, node, area))
  {
    if (OspfTE.na_engaged[(int)ospf->instance] == 1)
      OspfTE.na_force_refreshed[(int)ospf->instance] = 1;
    else
      ospf_te_na_lsa_schedule (REFRESH_THIS_LSA, ospf, area);

    if (OspfTE.na_engaged[(int)ospf->instance] == 1)
      ospf_te_na_lsa_schedule (REORIGINATE_PER_AREA, ospf, area);
  }
out:
  return CMD_SUCCESS;
}

DEFUN (te_node_attr_subtlv_node_ip4_lcl_prefix_add,
       te_node_attr_subtlv_node_ip4_lcl_prefix_add_cmd,
       "te node-ipv4-lcl-prefix add MASK ADDRESS",
       "TE specific commands\n"
       "Configure Node IPv4 Local Prefix\n"
       "Add Node IPv4 Local Prefix\n"
       "Network mask\n"
       "IPv4 address\n"
       "<cr>\n")
{
  struct in_addr mask, address;

  if (! inet_aton (argv[0], &mask))
  {
    vty_out (vty, "Please specify Network mask by A.B.C.D%s", VTY_NEWLINE);
    return CMD_WARNING;
  }
  if (! inet_aton (argv[1], &address))
  {
    vty_out (vty, "Please specify IPv4 address by A.B.C.D%s", VTY_NEWLINE);
    return CMD_WARNING;
  }

  struct ospf *ospf=(struct ospf*) vty->index;
  add_ason_node_ip4_lcl_prefix (mask, address, ospf->instance);

  if (OspfTE.status == disabled)
    goto out;

  struct zlistnode *node;
  struct ospf_area *area;

  for (ALL_LIST_ELEMENTS_RO(ospf->areas, node, area))
  {
    if (OspfTE.na_engaged[(int)ospf->instance] == 1)
      OspfTE.na_force_refreshed[(int)ospf->instance] = 1;
    else
      ospf_te_na_lsa_schedule (REFRESH_THIS_LSA, ospf, area);

    if (OspfTE.na_engaged[(int)ospf->instance] == 1)
      ospf_te_na_lsa_schedule (REORIGINATE_PER_AREA, ospf, area);
  }
out:
  return CMD_SUCCESS;
}


DEFUN (te_node_attr_subtlv_node_ip4_lcl_prefix_clear,
       te_node_attr_subtlv_node_ip4_lcl_prefix_clear_cmd,
       "te node-ipv4-lcl-prefix clear",
       "TE specific commands\n"
       "Configure Node IPv4 Local Prefix\n"
       "Clear Node IPv4 Local Prefix list\n"
       "<cr>\n")
{
  struct ospf *ospf=(struct ospf*) vty->index;

  int ret = clear_ason_node_ip4_lcl_prefix(ospf->instance);

  if (ret == -1)
    vty_out (vty, "  Node IPv4 local prefix: List is already empty!%s", VTY_NEWLINE);


  if ((ntohs(OspfTE.node_attr[(uint16_t)ospf->instance].node_ip4_lcl_prefix.header.type) == 0) || (ret == 0))
  {
    if (OspfTE.status == disabled)
      goto out;

    struct zlistnode *node;
    struct ospf_area *area;

    for (ALL_LIST_ELEMENTS_RO(ospf->areas, node, area))
    {
      if (OspfTE.na_engaged[(int)ospf->instance] == 1)
        OspfTE.na_force_refreshed[(int)ospf->instance] = 1;
      else
        ospf_te_na_lsa_schedule (REFRESH_THIS_LSA, ospf, area);

      if (OspfTE.na_engaged[(int)ospf->instance] == 1)
        ospf_te_na_lsa_schedule (REORIGINATE_PER_AREA, ospf, area);
    }
  }
out:
  return CMD_SUCCESS;
}

#ifdef GMPLS
DEFUN (te_node_attr_subtlv_node_ip6_lcl_prefix_add,
       te_node_attr_subtlv_node_ip6_lcl_prefix_add_cmd,
       "te node-ipv6-lcl-prefix add LENGTH OPTIONS ADDRESS",
       "TE specific commands\n"
       "Configure Node IPv6 Local Prefix\n"
       "Add Node IPv6 Local Prefix\n"
       "(8-bit Hexadecimal value ex. 0xa1) Prefix Length\n"
       "(8-bit Hexadecimal value ex. 0xa1) Prefix Options\n"
       "IPv6 address\n"
       "<cr>\n")
{

  u_int32_t length, options;

  if (sscanf (argv[0], "0x%x", &length) != 1)
  {
    vty_out (vty, "te_node_attr_node_ip6_lcl_prefix: %s%s", safe_strerror (errno), VTY_NEWLINE);
    return CMD_WARNING;
  }
  if (sscanf (argv[1], "0x%x", &options) != 1)
  {
    vty_out (vty, "te_node_attr_node_ip6_lcl_prefix: %s%s", safe_strerror (errno), VTY_NEWLINE);
    return CMD_WARNING;
  }

  struct in6_addr address;

  str2in6_addr (argv[2], &address);

  struct ospf *ospf=(struct ospf*) vty->index;
  add_ason_node_ip6_lcl_prefix(length, options, address, ospf->instance);

  if (OspfTE.status == disabled)
    goto out;

  struct zlistnode *node;
  struct ospf_area *area;
  for (ALL_LIST_ELEMENTS_RO(ospf->areas, node, area))
  {
    if (OspfTE.na_engaged[(int)ospf->instance] == 1)
      OspfTE.na_force_refreshed[(int)ospf->instance] = 1;
    else
      ospf_te_na_lsa_schedule (REFRESH_THIS_LSA, ospf, area);

    if (OspfTE.na_engaged[(int)ospf->instance] == 1)
      ospf_te_na_lsa_schedule (REORIGINATE_PER_AREA, ospf, area);
  }
out:
  return CMD_SUCCESS;
}
#endif /* GMPLS */


DEFUN (te_node_attr_subtlv_node_ip6_lcl_prefix_clear,
       te_node_attr_subtlv_node_ip6_lcl_prefix_clear_cmd,
       "te node-ipv6-lcl-prefix clear",
       "TE specific commands\n"
       "Configure Node IPv6 Local Prefix\n"
       "Clear Node IPv6 Local Prefix List\n"
       "<cr>\n")
{
  struct ospf *ospf=(struct ospf*) vty->index;

  int ret = clear_ason_node_ip6_lcl_prefix(ospf->instance);

  if (ret == -1)
    vty_out (vty, "  Node IPv6 local prefix: List is already empty!%s", VTY_NEWLINE);

  if ((ntohs(OspfTE.node_attr[(uint16_t)ospf->instance].node_ip6_lcl_prefix.header.type) == 0) || (ret == 0))
  {
    if (OspfTE.status == disabled)
      goto out;

    struct zlistnode *node;
    struct ospf_area *area;

    for (ALL_LIST_ELEMENTS_RO(ospf->areas, node, area))
    {
      if (OspfTE.na_engaged[(int)ospf->instance] == 1)
        OspfTE.na_force_refreshed[(int)ospf->instance] = 1;
      else
        ospf_te_na_lsa_schedule (REFRESH_THIS_LSA, ospf, area);

      if (OspfTE.na_engaged[(int)ospf->instance] == 1)
          ospf_te_na_lsa_schedule (REORIGINATE_PER_AREA, ospf, area);
    }
  }
out:
  return CMD_SUCCESS;
}

DEFUN (te_link_metric,
       te_link_metric_cmd,
       "te-link metric <0-4294967295>",
       "Configure TE link parameters\n"
       "Link metric for TE purpose\n"
       "Metric\n")
{
  struct interface *ifp = (struct interface *) vty->index;
  struct te_link *lp;
  u_int32_t value;

  if ((lp = lookup_linkparams_by_ifp (ifp)) == NULL)
    {
      vty_out (vty, "te_link_metric: Something wrong!%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  value = strtoul (argv[0], NULL, 10);

  if (ntohs (lp->te_metric.header.type) == 0
  ||  ntohl (lp->te_metric.value) != value)
  {
    set_linkparams_te_metric (lp, value);

    if (OspfTE.status == enabled)
      if (lp->area != NULL)
      {
        if (lp->flags & LPFLG_LSA_LI_ENGAGED)
        {
          ospf_te_lsa_schedule (lp, REFRESH_THIS_LSA, LINK);
          if (IS_DEBUG_TE(REFRESH))
            zlog_debug("[DBG] ospf_te_lsa_schedule (lp, REFRESH_THIS_LSA, LINK)");
        }
        else
        {
          ospf_te_lsa_schedule (lp, REORIGINATE_PER_AREA, LINK);
          if (IS_DEBUG_TE(REFRESH))
            zlog_debug("[DBG] ospf_te_lsa_schedule (lp, REORIGINATE_PER_AREA, LINK)");
        }
      }
  }
  return CMD_SUCCESS;
}

DEFUN (te_link_maxbw,
       te_link_maxbw_cmd,
       "te-link max-bw BANDWIDTH",
       "Configure TE link parameters\n"
       "Maximum bandwidth that can be used\n"
       "Bytes/second (IEEE floating point format)\n")
{
  struct interface *ifp = (struct interface *) vty->index;
  struct te_link *lp;
  float f1, f2;

  if ((lp = lookup_linkparams_by_ifp (ifp)) == NULL)
  {
    vty_out (vty, "te_link_maxbw: Something wrong!%s", VTY_NEWLINE);
    return CMD_WARNING;
  }

  ntohf (&lp->max_bw.value, &f1);
  if (sscanf (argv[0], "%g", &f2) != 1)
  {
    vty_out (vty, "te_link_maxbw: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
    return CMD_WARNING;
  }

  if (ntohs (lp->max_bw.header.type) == 0
  ||  f1 != f2)
    {
      set_linkparams_max_bw (lp, &f2);

      if (OspfTE.status == enabled)
        if (lp->area != NULL)
          {
            if (lp->flags & LPFLG_LSA_LI_ENGAGED)
              ospf_te_lsa_schedule (lp, REFRESH_THIS_LSA, LINK);
            else
              ospf_te_lsa_schedule (lp, REORIGINATE_PER_AREA, LINK);
          }
    }
  return CMD_SUCCESS;
}

DEFUN (te_link_max_rsv_bw,
       te_link_max_rsv_bw_cmd,
       "te-link max-rsv-bw BANDWIDTH",
       "Configure TE link parameters\n"
       "Maximum bandwidth that may be reserved\n"
       "Bytes/second (IEEE floating point format)\n")
{
  struct interface *ifp = (struct interface *) vty->index;
  struct te_link *lp;
  float f1, f2;

  if ((lp = lookup_linkparams_by_ifp (ifp)) == NULL)
  {
    vty_out (vty, "te_link_max_rsv_bw: Something wrong!%s", VTY_NEWLINE);
    return CMD_WARNING;
  }

  ntohf (&lp->max_rsv_bw.value, &f1);
  if (sscanf (argv[0], "%g", &f2) != 1)
  {
    vty_out (vty, "te_link_max_rsv_bw: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
    return CMD_WARNING;
  }

  if (ntohs (lp->max_rsv_bw.header.type) == 0 ||  f1 != f2)
  {
    set_linkparams_max_rsv_bw (lp, &f2);

    if (OspfTE.status == enabled)
      if (lp->area != NULL)
      {
        if (lp->flags & LPFLG_LSA_LI_ENGAGED)
          ospf_te_lsa_schedule (lp, REFRESH_THIS_LSA, LINK);
        else
          ospf_te_lsa_schedule (lp, REORIGINATE_PER_AREA, LINK);
      }
  }
  return CMD_SUCCESS;
}

DEFUN (te_link_unrsv_bw,
       te_link_unrsv_bw_cmd,
       "te-link unrsv-bw <0-7> BANDWIDTH",
       "TE specific commands\n"
       "Configure TE link parameters\n"
       "Unreserved bandwidth at each priority level\n"
       "Priority\n"
       "Bytes/second (IEEE floating point format)\n")
{
  struct interface *ifp = (struct interface *) vty->index;
  struct te_link *lp;
  int priority;
  float f1, f2;

  if ((lp = lookup_linkparams_by_ifp (ifp)) == NULL)
  {
    vty_out (vty, "te_link_unrsv_bw: Something wrong!%s", VTY_NEWLINE);
    return CMD_WARNING;
  }

  /* We don't have to consider about range check here. */
  if (sscanf (argv[0], "%d", &priority) != 1)
  {
    vty_out (vty, "te_link_unrsv_bw: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
    return CMD_WARNING;
  }

  ntohf (&lp->unrsv_bw.value [priority], &f1);
  if (sscanf (argv[1], "%g", &f2) != 1)
  {
    vty_out (vty, "te_link_unrsv_bw: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
    return CMD_WARNING;
  }

  if (ntohs (lp->unrsv_bw.header.type) == 0 ||  f1 != f2)
  {
    set_linkparams_unrsv_bw (lp, priority, &f2);

    if (OspfTE.status == enabled)
      if (lp->area != NULL)
      {
        if (lp->flags & LPFLG_LSA_LI_ENGAGED)
          ospf_te_lsa_schedule (lp, REFRESH_THIS_LSA, LINK);
        else
          ospf_te_lsa_schedule (lp, REORIGINATE_PER_AREA, LINK);
      }
  }
  return CMD_SUCCESS;
}

DEFUN (te_link_rsc_clsclr,
       te_link_rsc_clsclr_cmd,
       "te-link rsc-clsclr BITPATTERN",
       "Configure TE link parameters\n"
       "Administrative group membership\n"
       "32-bit Hexadecimal value (ex. 0xa1)\n")
{
  struct interface *ifp = (struct interface *) vty->index;
  struct te_link *lp;
  unsigned long value;

  if ((lp = lookup_linkparams_by_ifp (ifp)) == NULL)
  {
    vty_out (vty, "te_link_rsc_clsclr: Something wrong!%s", VTY_NEWLINE);
    return CMD_WARNING;
  }

  if (sscanf (argv[0], "0x%lx", &value) != 1)
  {
    vty_out (vty, "te_link_rsc_clsclr: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
    return CMD_WARNING;
  }

  if (ntohs (lp->rsc_clsclr.header.type) == 0 ||  ntohl (lp->rsc_clsclr.value) != value)
  {
    set_linkparams_rsc_clsclr (lp, value);

    if (OspfTE.status == enabled)
      if (lp->area != NULL)
      {
        if (lp->flags & LPFLG_LSA_LI_ENGAGED)
          ospf_te_lsa_schedule (lp, REFRESH_THIS_LSA, LINK);
        else
          ospf_te_lsa_schedule (lp, REORIGINATE_PER_AREA, LINK);
      }
  }
  return CMD_SUCCESS;
}

DEFUN (te_link_subtlv_link_lcl_rmt_ids_local,
       te_link_subtlv_link_lcl_rmt_ids_local_cmd,
       "te-link local-identifier Id",
       "Configure TE link parameters\n"
       "Configure TE link local identifier\n"
       "local identifier 32-bit Hexadecimal value (ex. 0xa1)\n")
{
  struct interface *ifp = (struct interface *) vty->index;
  struct te_link *lp;

  unsigned long value;
  if ((lp = lookup_linkparams_by_ifp (ifp)) == NULL)
  {
    vty_out (vty, "te_link_subtlv_link_lcl_rmt_ids_local: Something wrong!%s", VTY_NEWLINE);
    return CMD_WARNING;
  }

  if (sscanf (argv[0], "0x%lx", &value) != 1)
  {
    vty_out (vty, "te_link_subtlv_link_lcl_rmt_ids_local: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
    return CMD_WARNING;
  }

  if (ntohs (lp->link_lcl_rmt_ids.header.type) == 0 ||  ((ntohl (lp->link_lcl_rmt_ids.local_id) != value)))
  {
    set_link_lcl_rmt_ids (lp, value, ntohl(lp->link_lcl_rmt_ids.remote_id));

    if (OspfTE.status == enabled)
      if (lp->area != NULL)
      {
        if (lp->flags & LPFLG_LSA_LI_ENGAGED)
          ospf_te_lsa_schedule (lp, REFRESH_THIS_LSA, LINK);
        else
          ospf_te_lsa_schedule (lp, REORIGINATE_PER_AREA, LINK);
      }
  }
  return CMD_SUCCESS;
}

DEFUN (te_link_subtlv_link_lcl_rmt_ids_remote,
       te_link_subtlv_link_lcl_rmt_ids_remote_cmd,
       "te-link remote-identifier Id",
       "Configure TE link parameters\n"
       "Configure TE link remote identifier\n"
       "remote identifier 32-bit Hexadecimal value (ex. 0xa1)\n")
{
  struct interface *ifp = (struct interface *) vty->index;
  struct te_link *lp;

  unsigned long value;
  if ((lp = lookup_linkparams_by_ifp (ifp)) == NULL)
  {
    vty_out (vty, "te_link_subtlv_link_lcl_rmt_ids_remote: Something wrong!%s", VTY_NEWLINE);
    return CMD_WARNING;
  }

  if (sscanf (argv[0], "0x%lx", &value) != 1)
  {
    vty_out (vty, "te_link_subtlv_link_lcl_rmt_ids_remote: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
    return CMD_WARNING;
  }

  if (ntohs (lp->link_lcl_rmt_ids.header.type) == 0 || ((ntohl (lp->link_lcl_rmt_ids.remote_id) != value)))
  {
    set_link_lcl_rmt_ids (lp, ntohl(lp->link_lcl_rmt_ids.local_id), value);

    if (OspfTE.status == enabled)
      if (lp->area != NULL)
      {
        if (lp->flags & LPFLG_LSA_LI_ENGAGED)
          ospf_te_lsa_schedule (lp, REFRESH_THIS_LSA, LINK);
        else
          ospf_te_lsa_schedule (lp, REORIGINATE_PER_AREA, LINK);
      }
  }
  return CMD_SUCCESS;
}

DEFUN (te_link_area,
       te_link_area_cmd,
       "te-link area A.B.C.D",
       "Configure TE link parameters\n"
       "TE link area\n"
       "OSPF area ID in IP address format\n")
{
  struct interface *ifp = (struct interface *) vty->index;
  struct te_link *lp;
  struct ospf_area *ospf_area;
  struct in_addr new_area_id;
  struct zlistnode *node, *nnode;
  struct zlistnode *node1, *nnode1;
  struct ospf *ospf_inst;

  struct ospf *ospf_uni = ospf_uni_lookup();

  if ((lp = lookup_linkparams_by_ifp (ifp)) == NULL)
  {
    vty_out (vty, "area A.B.C.D: Something wrong!%s", VTY_NEWLINE);
    return CMD_WARNING;
  }

  int ret;
  ret = inet_aton (argv[0], &new_area_id);

  if (ret < 0)
  {
    vty_out (vty, "%% Invalid OSPF area ID%s", VTY_NEWLINE);
    return CMD_WARNING;
  }

  for (ALL_LIST_ELEMENTS (om->ospf, node, nnode, ospf_inst))
  {
    for (ALL_LIST_ELEMENTS (ospf_inst->areas, node1, nnode1, ospf_area))
    {
      if (IPV4_ADDR_SAME (&ospf_area->area_id, &new_area_id))
      {
        lp->area_adr=new_area_id;
        ospf_te_lsa_originate2(ospf_area, ROUTE_ADDRESS);
        ospf_te_lsa_originate2(ospf_area, NODE_ATRIBUTE);
        ospf_te_lsa_originate1(ospf_area, lp, LINK);
        if (ospf_uni != NULL)
        {
          if ((ospf_uni->interface_side == NETWORK) && (lp->ifp->ospf_instance == UNI))
            ospf_te_lsa_originate1(ospf_area, lp, TNA_ADDRESS);
        }
        return CMD_SUCCESS;
      }
    }
  }
  vty_out (vty, "area A.B.C.D: Area %s not found!%s", inet_ntoa (new_area_id), VTY_NEWLINE);
  return CMD_WARNING;;
}

DEFUN (te_link_subtlv_link_protect_type,
       te_link_subtlv_link_protect_type_cmd,
       "te-link protection (extra|none|shared|1:1|1+1|en)",
       "Configure TE link parameters\n"
       "Configure TE link protection type\n"
       "Extra traffic\n"
       "Unprotected\n"
       "Shared\n"
       "Dedicated 1:1\n"
       "Dedicated 1+1\n"
       "Enhanced (Ring, etc.)\n")
{
  struct interface *ifp = (struct interface *) vty->index;
  struct te_link *lp;

  if ((lp = lookup_linkparams_by_ifp (ifp)) == NULL)
    {
      vty_out (vty, "te_link_rsc_clsclr: Something wrong!%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  u_int32_t ptype;
  ptype = str2val(& pair_val_str_protection, argv[0]);
  if (ptype==0)
    {
      vty_out (vty, "unrecognized protection type: %s %s", argv[0], VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (ntohs (lp->link_protect_type.header.type) == 0
  ||  (lp->link_protect_type.value != ptype))
    {
      set_link_protect_type(lp, (u_char)ptype);
      if (OspfTE.status == enabled)
        if (lp->area != NULL)
          {
            if (lp->flags & LPFLG_LSA_LI_ENGAGED)
              ospf_te_lsa_schedule (lp, REFRESH_THIS_LSA, LINK);
            else
              ospf_te_lsa_schedule (lp, REORIGINATE_PER_AREA, LINK);
          }
    }
  return CMD_SUCCESS;
}

DEFUN (te_link_subtlv_if_sw_cap_desc_psc,
       te_link_subtlv_if_sw_cap_desc_psc_cmd,
       "te-link capability (psc1|psc2|psc3|psc4|l2sc) (packet|ethernet) MinBandwidth MTU",
       "Configure TE link parameters\n"
       "Configure link capability\n"
       "Configure Packet Switch Capable-1 interface\n"
       "Configure Packet Switch Capable-2 interface\n"
       "Configure Packet Switch Capable-3 interface\n"
       "Configure Packet Switch Capable-4 interface\n"
       "Configure Layer-2 Switch Capable interface\n"
       "Packet\n"
       "Ethernet\n"
       "MinBandwidth Bytes/second (IEEE floating point format)\n"
       "16-bit Hexadecimal value (ex. 0xa1)\n")
{
  struct interface *ifp = (struct interface *) vty->index;
  struct te_link *lp;

  u_int32_t mtu;
  float minLSPbw;

  if ((lp = lookup_linkparams_by_ifp (ifp)) == NULL)
    {
      vty_out (vty, "te_link_subtlv_if_sw_cap_desc_psc1: Something wrong!%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  u_int8_t swcap = str2val(&pair_val_str_swcap, argv[0]);
  if (swcap == 0)
  {
      vty_out (vty, "Invalid switching capability %s %s", argv[0], VTY_NEWLINE);
      return CMD_WARNING;
   }

  u_int8_t enc = str2val(&pair_val_str_encoding, argv[1]);
  if (enc == 0)
  {
      vty_out (vty, "Invalid encoding %s %s", argv[1], VTY_NEWLINE);
      return CMD_WARNING;
   }

  if (sscanf (argv[2], "%g", &minLSPbw) != 1)
  {
    vty_out (vty, "te_link_subtlv_if_sw_cap_desc_psc1: fscanf arg1: %s%s", safe_strerror (errno), VTY_NEWLINE);
    return CMD_WARNING;
  }

  if (sscanf (argv[3], "0x%x", &mtu) != 1)
  {
    vty_out (vty, "te_link_subtlv_if_sw_cap_desc_psc1: fscanf arg2: %s%s", safe_strerror (errno), VTY_NEWLINE);
    return CMD_WARNING;
  }
  float minLSPbw_rev;
  htonf(&minLSPbw, &minLSPbw_rev);

  create_te_link_subtlv_if_sw_cap_desc(lp, swcap, enc);
  set_if_sw_cap_desc_psc(lp, swcap, enc, &minLSPbw, (u_int16_t)mtu);

  if (OspfTE.status == enabled)
    if (lp->area != NULL)
    {
      if (lp->flags & LPFLG_LSA_LI_ENGAGED)
        ospf_te_lsa_schedule (lp, REFRESH_THIS_LSA, LINK);
      else
        ospf_te_lsa_schedule (lp, REORIGINATE_PER_AREA, LINK);
    }

  return CMD_SUCCESS;
}

DEFUN (te_link_subtlv_if_sw_cap_desc_tdm,
       te_link_subtlv_if_sw_cap_desc_tdm_cmd,
       "te-link capability tdm (pdh|sdh|dwrapper) MinBandwidth Indication",
       "Configure TE link parameters\n"
       "Configure TE link capability description\n"
       "Configure Time-Division Multiplex Capable interface\n"
       "ANSI/ETSI PDH\n"
       "SDH ITU-T G.707 / SONET ANSI T1.105\n"
       "Digital Wrapper\n"
       "MinBandwidth Bytes/second (IEEE floating point format)\n"
       "8-bit Hexadecimal value (ex. 0xa1)\n")
{
  struct interface *ifp = (struct interface *) vty->index;
  struct te_link *lp;

  u_int32_t indication;
  float minLSPbw;

  if ((lp = lookup_linkparams_by_ifp (ifp)) == NULL)
    {
      vty_out (vty, "te_link_subtlv_if_sw_cap_desc_tdm: Something wrong!%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  u_int8_t enc = str2val(&pair_val_str_encoding, argv[0]);
  if (enc == 0)
  {
      vty_out (vty, "Invalid encoding %s %s", argv[1], VTY_NEWLINE);
      return CMD_WARNING;
   }

  if (sscanf (argv[1], "%g", &minLSPbw) != 1)
  {
    vty_out (vty, "te_link_subtlv_if_sw_cap_desc_tdm: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
    return CMD_WARNING;
  }

  if (sscanf (argv[2], "0x%x", &indication) != 1)
  {
    vty_out (vty, "te_link_subtlv_if_sw_cap_desc_tdm: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
    return CMD_WARNING;
  }

  float minLSPbw_rev;
  htonf(&minLSPbw, &minLSPbw_rev);

  create_te_link_subtlv_if_sw_cap_desc(lp, CAPABILITY_TDM, enc);
  set_if_sw_cap_desc_tdm(lp, CAPABILITY_TDM, enc, &minLSPbw, indication);

  if (OspfTE.status == enabled)
    if (lp->area != NULL)
    {
      if (lp->flags & LPFLG_LSA_LI_ENGAGED)
        ospf_te_lsa_schedule (lp, REFRESH_THIS_LSA, LINK);
      else
        ospf_te_lsa_schedule (lp, REORIGINATE_PER_AREA, LINK);
    }

  return CMD_SUCCESS;
}

DEFUN (te_link_subtlv_if_sw_cap_desc_lsc_fsc,
       te_link_subtlv_if_sw_cap_desc_lsc_fsc_cmd,
       "te-link capability (lsc|fsc) (lambda|fiber|fchannel)",
       "Configure TE link parameters\n"
       "Configure TE link capability description\n"
       "Configure Lambda Switch Capable interface\n"
       "Configure Fiber  Switch Capable interface\n"
       "Lambda (photonic)\n"
       "Fiber\n"
       "FiberChannel\n")
{
  struct interface *ifp = (struct interface *) vty->index;
  struct te_link *lp;

  if ((lp = lookup_linkparams_by_ifp (ifp)) == NULL)
    {
      vty_out (vty, "te_link_subtlv_if_sw_cap_desc_lsc: Something wrong!%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  u_int8_t swcap = str2val(&pair_val_str_swcap, argv[0]);
  if (swcap == 0)
  {
    vty_out (vty, "Invalid switching capability %s %s", argv[0], VTY_NEWLINE);
    return CMD_WARNING;
  }

  u_int8_t enc = str2val(&pair_val_str_encoding, argv[1]);
  if (enc == 0)
  {
    vty_out (vty, "Invalid encoding %s %s", argv[1], VTY_NEWLINE);
    return CMD_WARNING;
  }

  create_te_link_subtlv_if_sw_cap_desc(lp, swcap, enc);

  if (OspfTE.status == enabled)
    if (lp->area != NULL)
    {
      if (lp->flags & LPFLG_LSA_LI_ENGAGED)
        ospf_te_lsa_schedule (lp, REFRESH_THIS_LSA, LINK);
      else
        ospf_te_lsa_schedule (lp, REORIGINATE_PER_AREA, LINK);
    }

 return CMD_SUCCESS;
}

DEFUN (te_link_subtlv_if_sw_cap_maxLSPbw,
       te_link_subtlv_if_sw_cap_maxLSPbw_cmd,
       "te-link capability (psc1|psc2|psc3|psc4|l2sc|tdm|lsc|fsc) (packet|ethernet|pdh|sdh|dwrapper|lambda|fiber|fchannel) maxlspband <0-7> BANDWIDTH",
       "Configure TE link parameters\n"
       "Configure Packet Switch Capable-1 interface\n"
       "Configure Packet Switch Capable-2 interface\n"
       "Configure Packet Switch Capable-3 interface\n"
       "Configure Packet Switch Capable-4 interface\n"
       "Configure Layer-2 Switch Capable interface\n"
       "Configure Tdm Switch Capable interface\n"
       "Configure Lambda Switch Capable interface\n"
       "Configure Fiber  Switch Capable interface\n"
       "Packet\n"
       "Ethernet\n"
       "Configure Time-Division Multiplex Capable interface\n"
       "ANSI/ETSI PDH\n"
       "SDH ITU-T G.707 / SONET ANSI T1.105\n"
       "Digital Wrapper\n"
       "Lambda (photonic)\n"
       "Fiber\n"
       "FiberChannel\n"
       "Maximum bandwidth at each priority level\n"
       "Priority\n"
       "Bytes/second (IEEE floating point format)\n")
{
  struct interface *ifp = (struct interface *) vty->index;
  struct te_link *lp;
  int priority;
  float f1;;

  if ((lp = lookup_linkparams_by_ifp (ifp)) == NULL)
    {
      vty_out (vty, "te_link_subtlv_if_sw_cap_maxLSPbw: Something wrong!%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  u_int8_t swcap = str2val(&pair_val_str_swcap, argv[0]);
  if (swcap == 0)
  {
      vty_out (vty, "Invalid switching capability %s %s", argv[0], VTY_NEWLINE);
      return CMD_WARNING;
   }

  u_int8_t enc = str2val(&pair_val_str_encoding, argv[1]);
  if (enc == 0)
  {
      vty_out (vty, "Invalid encoding %s %s", argv[1], VTY_NEWLINE);
      return CMD_WARNING;
  }

  /* We don't have to consider about range check here. */
  if (sscanf (argv[2], "%d", &priority) != 1)
    {
      vty_out (vty, "te_link_subtlv_if_sw_cap_maxLSPbw: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
      return CMD_WARNING;
    }
  if (priority > LINK_MAX_PRIORITY)     /*not necessirily because priority is limited to 7 by <0-7> */
  {
    vty_out (vty, "te_link_subtlv_if_sw_cap_maxLSPbw: priority out of range: %s", VTY_NEWLINE);
    return CMD_WARNING;
  }

  if (sscanf (argv[3], "%g", &f1) != 1)
  {
    vty_out (vty, "te_link_subtlv_if_sw_cap_maxLSPbw: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
    return CMD_WARNING;
  }

  set_if_sw_cap_max_band (lp, swcap, enc, priority, &f1);

  if (OspfTE.status == enabled)
    if (lp->area != NULL)
    {
      if (lp->flags & LPFLG_LSA_LI_ENGAGED)
        ospf_te_lsa_schedule (lp, REFRESH_THIS_LSA, LINK);
      else
        ospf_te_lsa_schedule (lp, REORIGINATE_PER_AREA, LINK);
    }

  return CMD_SUCCESS;
}

DEFUN (te_link_subtlv_if_sw_cap_desc_clear,
       te_link_subtlv_if_sw_cap_desc_clear_cmd,
       "te-link capability clear",
       "Configure TE link parameters\n"
       "Clear capabilities list\n")
{
  struct interface *ifp = (struct interface *) vty->index;
  struct te_link *lp;

  if ((lp = lookup_linkparams_by_ifp (ifp)) == NULL)
    {
      vty_out (vty, "te_link_subtlv_if_sw_cap_desc_lsc: Something wrong!%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  clear_if_sw_cap_descs_list(lp);

  if (OspfTE.status == enabled)
    if (lp->area != NULL)
    {
      if (lp->flags & LPFLG_LSA_LI_ENGAGED)
        ospf_te_lsa_schedule (lp, REFRESH_THIS_LSA, LINK);
      else
        ospf_te_lsa_schedule (lp, REORIGINATE_PER_AREA, LINK);
    }

 return CMD_SUCCESS;
}

DEFUN (te_link_subtlv_shared_risk_link_grp_add,
       te_link_subtlv_shared_risk_link_grp_add_cmd,
       "te-link sharedriscgroup add Link",
       "Configure TE link parameters\n"
       "Configure TE link shared risc group\n"
       "Add TE shared risc link\n"
       "32-bit Hexadecimal value (ex. 0xa1)\n")
{
  struct interface *ifp = (struct interface *) vty->index;
  struct te_link *lp;

  if ((lp = lookup_linkparams_by_ifp (ifp)) == NULL)
    {
      vty_out (vty, "te_link_rsc_clsclr: Something wrong!%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  u_int32_t value;
  if (sscanf (argv[0], "0x%x", &value) != 1)
    {
      vty_out (vty, "te_link_rsc_clsclr: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
      return CMD_WARNING;
    }

  int ret = add_shared_risk_link_grp(lp, value);

  if ((ntohs(lp->shared_risk_link_grp.header.type) == 0)|| (ret == 0))
    {

      if (OspfTE.status == enabled)
        if (lp->area != NULL)
          {
            if (lp->flags & LPFLG_LSA_LI_ENGAGED)
              ospf_te_lsa_schedule (lp, REFRESH_THIS_LSA, LINK);
            else
              ospf_te_lsa_schedule (lp, REORIGINATE_PER_AREA, LINK);
          }
    }
  return CMD_SUCCESS;
}

DEFUN (te_link_subtlv_shared_risk_link_grp_clear,
       te_link_subtlv_shared_risk_link_grp_clear_cmd,
       "te-link sharedriscgroup clear",
       "Configure TE link parameters\n"
       "Configure TE link shared risc group\n"
       "Clear shared risc group\n"
       "<cr>\n")
{
  struct interface *ifp = (struct interface *) vty->index;
  struct te_link *lp;

  if ((lp = lookup_linkparams_by_ifp (ifp)) == NULL)
    {
      vty_out (vty, "te_link_rsc_clsclr: Something wrong!%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  int ret = clear_shared_risk_link_grp(lp);

  if (ret == -1)
    vty_out (vty, "  Shared risc link group: List is already empty!%s", VTY_NEWLINE);

  if ((ntohs(lp->shared_risk_link_grp.header.type) == 0)||(ret == 0))
    {
      if (OspfTE.status == enabled)
        if (lp->area != NULL)
          {
            if (lp->flags & LPFLG_LSA_LI_ENGAGED)
              ospf_te_lsa_schedule (lp, REFRESH_THIS_LSA, LINK);
            else
              ospf_te_lsa_schedule (lp, REORIGINATE_PER_AREA, LINK);
          }
    }
  return CMD_SUCCESS;
}

DEFUN (te_link_subtlv_lcl_rmt_te_router_id,
       te_link_subtlv_lcl_rmt_te_router_id_cmd,
       "te-link lcl-rmt-te-router-id LOCAL-ID REMOTE-ID",
       "Configure TE link parameters\n"
       "Configure Local and Remote TE Router ID\n"
       "Local TE Router ID (32-bit Hexadecimal value; ex. 0xa1b2c3d4)\n"
       "Remote TE Router ID (32-bit Hexadecimal value; ex. 0xa1b2c3d4)\n"
       "<cr>\n")
{
  struct interface *ifp = (struct interface *) vty->index;
  struct te_link *lp;

  if ((lp = lookup_linkparams_by_ifp (ifp)) == NULL)
    {
      vty_out (vty, "te_link_lcl_rmt_te_router_id: Something wrong!%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  u_int32_t lcl_id, rmt_id;

  if (sscanf (argv[0], "0x%x", &lcl_id) != 1)
    {
      vty_out (vty, "te_link_lcl_rmt_te_router_id1: Something wrong!%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (sscanf (argv[1], "0x%x", &rmt_id) != 1)
    {
      vty_out (vty, "te_link_lcl_rmt_te_router_id2: Something wrong!%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  set_lcl_rmt_te_router_id(lp, lcl_id, rmt_id);

      if (OspfTE.status == enabled)
        if (lp->area != NULL)
          {
            if (lp->flags & LPFLG_LSA_LI_ENGAGED)
              ospf_te_lsa_schedule (lp, REFRESH_THIS_LSA, LINK);
            else
              ospf_te_lsa_schedule (lp, REORIGINATE_PER_AREA, LINK);
          }
  return CMD_SUCCESS;

}

/** **************** OIF E-NNI Routing ******************************** */

DEFUN (te_link_subtlv_lcl_node_id,
       te_link_subtlv_lcl_node_id_cmd,
       "te-link local-node-id ID",
       "Configure TE link parameters\n"
       "Configure Local Node ID\n"
       "IPv4 address\n"
       "<cr>\n")
{
  struct interface *ifp = (struct interface *) vty->index;
  struct te_link *lp;

  if ((lp = lookup_linkparams_by_ifp (ifp)) == NULL)
    {
      vty_out (vty, "te_link_lcl_node_id: Something wrong!%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  struct in_addr value;

  if (! inet_aton (argv[0], &value))
    {
      vty_out (vty, "Please specify Local Node ID by A.B.C.D%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

     set_oif_lcl_node_id (lp, value);

      if (OspfTE.status == enabled)
        if (lp->area != NULL)
          {
            if (lp->flags & LPFLG_LSA_LI_ENGAGED)
              ospf_te_lsa_schedule (lp, REFRESH_THIS_LSA, LINK);
            else
              ospf_te_lsa_schedule (lp, REORIGINATE_PER_AREA, LINK);
          }
  return CMD_SUCCESS;
}

DEFUN (te_link_subtlv_rmt_node_id,
       te_link_subtlv_rmt_node_id_cmd,
       "te-link remote-node-id ID",
       "Configure TE link parameters\n"
       "Remote Node ID\n"
       "IPv4 address\n"
       "<cr>\n")
{
  struct interface *ifp = (struct interface *) vty->index;
  struct te_link *lp;

  if ((lp = lookup_linkparams_by_ifp (ifp)) == NULL)
    {
      vty_out (vty, "te_link_rmt_node_id: Something wrong!%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  struct in_addr value;

  if (! inet_aton (argv[0], &value))
    {
      vty_out (vty, "Please specify Remote Node ID by A.B.C.D%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

     set_oif_rmt_node_id (lp, value);

      if (OspfTE.status == enabled)
        if (lp->area != NULL)
          {
            if (lp->flags & LPFLG_LSA_LI_ENGAGED)
              ospf_te_lsa_schedule (lp, REFRESH_THIS_LSA, LINK);
            else
              ospf_te_lsa_schedule (lp, REORIGINATE_PER_AREA, LINK);
          }
  return CMD_SUCCESS;
}

DEFUN (te_link_subtlv_ssdh_if_sw_cap_desc_add,
       te_link_subtlv_ssdh_if_sw_cap_desc_add_cmd,
       "te-link ssdh-if-sw-cap-desc add (vt1.5|vt2|vt3|vt6|sts-1.|sts-3c|sts-12c|sts-48c|sts-192c) TIME-SLOTS",
       "Configure TE link parameters\n"
       "Sonet/SDH Interface Switching Capability Descriptor\n"
       "Add signal\n"
       "VT1.5 SPE / VC-11\n"
       "VT2 SPE / VC-12\n"
       "VT3 SPE\n"
       "VT6 SPE / VC-2\n"
       "STS-1 SPE / VC-3\n"
       "STS-3c SPE / VC-4\n"
       "STS-12c SPE / VC-4-4c\n"
       "STS-48c SPE / VC-4-16c\n"
       "STS-192c SPE / VC-4-64c\n"
       "(24-bit Hexadecimal value; ex. 0xa1a1a1) Unallocated time slots\n"
       "<cr>\n")
{
  struct interface *ifp = (struct interface *) vty->index;
  struct te_link *lp;

  if ((lp = lookup_linkparams_by_ifp (ifp)) == NULL)
    {
      vty_out (vty, "te_link_ssdh_if_sw_cap_desc_add1: Something wrong!%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  u_char signal = str2val(&pair_val_str_signal_types, argv[0]);
  if (signal == 0)
  {
      vty_out (vty, "Invalid signal type %s %s", argv[0], VTY_NEWLINE);
      return CMD_WARNING;
  }

  u_int32_t value;
  if (sscanf (argv[1], "0x%x", &value) != 1)
    {
      vty_out (vty, "te_link_ssdh_if_sw_cap_desc_add2: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
      return CMD_WARNING;
    }

  u_char utslots[3];
  utslots[0] = value;
  value = value >> 8;
  utslots[1] = value;
  value = value >> 8;
  utslots[2] = value;

  set_oif_ssdh_if_sw_cap_desc (lp);
  add_oif_ssdh_if_sw_cap_desc_signal (lp,signal,utslots);

     if (OspfTE.status == enabled)
        if (lp->area != NULL)
          {
            if (lp->flags & LPFLG_LSA_LI_ENGAGED)
              ospf_te_lsa_schedule (lp, REFRESH_THIS_LSA, LINK);
            else
              ospf_te_lsa_schedule (lp, REORIGINATE_PER_AREA, LINK);
          }
  return CMD_SUCCESS;
}


DEFUN (te_link_subtlv_ssdh_if_sw_cap_desc_clear,
       te_link_subtlv_ssdh_if_sw_cap_desc_clear_cmd,
       "te-link ssdh-if-sw-cap-desc clear",
       "Configure TE link parameters\n"
       "Sonet/SDH Interface Switching Capability Descriptor\n"
       "Clear signal list\n"
       "<cr>\n")
{
  struct interface *ifp = (struct interface *) vty->index;
  struct te_link *lp;

  if ((lp = lookup_linkparams_by_ifp (ifp)) == NULL)
    {
      vty_out (vty, "te_link_ssdh-if-sw-cap-desc: Something wrong!%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  int ret = clear_oif_ssdh_if_sw_cap_desc_signal(lp);

  if (ret == -1)
    vty_out (vty, "  Sonet/SDH interface switching capability descriptor: List is already empty!%s", VTY_NEWLINE);

  if ((ntohs(lp->ssdh_if_sw_cap_desc.header.type) == 0) || (ret == 0))
    {
      if (OspfTE.status == enabled)
        if (lp->area != NULL)
          {
            if (lp->flags & LPFLG_LSA_LI_ENGAGED)
              ospf_te_lsa_schedule (lp, REFRESH_THIS_LSA, LINK);
            else
              ospf_te_lsa_schedule (lp, REORIGINATE_PER_AREA, LINK);
          }
    }
  return CMD_SUCCESS;
}

DEFUN (te_tna_addr_subtlv_tna_addr_ipv4,
       te_tna_addr_subtlv_tna_addr_ipv4_cmd,
       "te-link tna-address-ipv4 add NODE_ID <0-32> ADDRESS",
       "Configure TE link parameters\n"
       "TNA Address (IPv4)\n"
       "Add new IPv4 TNA Address\n"
       "Node ID (IPv4)\n"
       "Address length\n"
       "IPv4 address\n"
       "<cr>\n")
{
  struct interface *ifp = (struct interface *) vty->index;
  struct te_link *lp;

  if ((lp = lookup_linkparams_by_ifp (ifp)) == NULL)
  {
    vty_out (vty, "te_link_tna_addr_ipv4: Something wrong!%s", VTY_NEWLINE);
    return CMD_WARNING;
  }

  u_int32_t length;
  if (sscanf (argv[1], "%d", &length) != 1)
  {
    vty_out (vty, "te_link_tna_addr_ipv4: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
    return CMD_WARNING;
  }

  struct in_addr address;
  struct in_addr node_id;

  if (! inet_aton (argv[2], &address))
  {
    vty_out (vty, "Please specify TNA Address by A.B.C.D%s", VTY_NEWLINE);
    return CMD_WARNING;
  }

  if (! inet_aton (argv[0], &node_id))
  {
    vty_out (vty, "Please specify Node ID by A.B.C.D%s", VTY_NEWLINE);
    return CMD_WARNING;
  }

  struct in_addr empty;
  empty.s_addr = 0;
  add_tna_addr (lp, TNA_IP4, node_id, empty, length, (void *) &address);

  if (OspfTE.status == enabled)
    if (lp->area != NULL)
    {
      if (lp->flags & LPFLG_LSA_TNA_ENGAGED)
          ospf_te_lsa_schedule (lp, REFRESH_THIS_LSA, TNA_ADDRESS);
      else
          ospf_te_lsa_schedule (lp, REORIGINATE_PER_AREA, TNA_ADDRESS);
  }
  return CMD_SUCCESS;
}

#ifdef GMPLS
DEFUN (te_tna_addr_subtlv_tna_addr_ipv6,
       te_tna_addr_subtlv_tna_addr_ipv6_cmd,
       "te-link tna-address-ipv6 add NODE_ID <0-128> ADDRESS",
       "Configure TE link parameters\n"
       "TNA Address (IPv6)\n"
       "Add new IPv6 TNA Adress\n"
       "Node ID (IPv4)\n"
       "Address length\n"
       "IPv6 address\n"
       "<cr>\n")
{
  struct interface *ifp = (struct interface *) vty->index;
  struct te_link *lp;

  if ((lp = lookup_linkparams_by_ifp (ifp)) == NULL)
  {
    vty_out (vty, "te_link_tna_addr_ipv6: Something wrong!%s", VTY_NEWLINE);
    return CMD_WARNING;
  }

  u_int32_t length;
  if (sscanf (argv[1], "%d", &length) != 1)
  {
    vty_out (vty, "te_link_tna_addr_ipv6: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
    return CMD_WARNING;
  }

  struct in6_addr address;
  struct in_addr node_id;

  str2in6_addr (argv[2], &address);

  if (! inet_aton (argv[0], &node_id))
  {
    vty_out (vty, "Please specify Node ID by A.B.C.D%s", VTY_NEWLINE);
    return CMD_WARNING;
  }

  struct in_addr empty;
  empty.s_addr = 0;
  add_tna_addr(lp, TNA_IP6, node_id, empty, length, (void *) &address);

  if (OspfTE.status == enabled)
    if (lp->area != NULL)
    {
      if (lp->flags & LPFLG_LSA_TNA_ENGAGED)
        ospf_te_lsa_schedule (lp, REFRESH_THIS_LSA, TNA_ADDRESS);
      else
        ospf_te_lsa_schedule (lp, REORIGINATE_PER_AREA, TNA_ADDRESS);
    }
  return CMD_SUCCESS;
}
#endif /* GMPLS */

DEFUN (te_tna_addr_subtlv_tna_addr_nsap,
       te_tna_addr_subtlv_tna_addr_nsap_cmd,
       "te-link tna-address-nsap add NODE_ID <0-160> ADD_PART1 ADD_PART2 ADD_PART3 ADD_PART4 ADD_PART5",
       "Configure TE link parameters\n"
       "TNA Address (NSAP 160-bit)\n"
       "Add new NSAP TNA Address\n"
       "Node ID (IPv4)\n"
       "Address length\n"
       "(32-bit Hexadecimal value; ex. a1b2c3d4) First part of the address\n"
       "(32-bit Hexadecimal value; ex. a1b2c3d4) Second part of the address\n"
       "(32-bit Hexadecimal value; ex. a1b2c3d4) Third part of the address\n"
       "(32-bit Hexadecimal value; ex. a1b2c3d4) Fourth part of the address\n"
       "(32-bit Hexadecimal value; ex. a1b2c3d4) Fifth part of the address\n"
       "<cr>\n")
{
  struct interface *ifp = (struct interface *) vty->index;
  struct te_link *lp;

  if ((lp = lookup_linkparams_by_ifp (ifp)) == NULL)
  {
    vty_out (vty, "te_link_tna_addr_nsap: Something wrong!%s", VTY_NEWLINE);
    return CMD_WARNING;
  }

  u_int32_t length;
  if (sscanf (argv[1], "%d", &length) != 1)
  {
    vty_out (vty, "te_link_tna_addr_nsap: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
    return CMD_WARNING;
  }

  struct in_addr node_id;
  if (! inet_aton (argv[0], &node_id))
  {
    vty_out (vty, "Please specify Node ID by A.B.C.D%s", VTY_NEWLINE);
    return CMD_WARNING;
  }

  u_int32_t nsap_address[5];

  if (sscanf (argv[2], "%x", &nsap_address[4]) != 1)
  {
    vty_out (vty, "Please specify TNA Address%s", VTY_NEWLINE);
    return CMD_WARNING;
  }
  if (sscanf (argv[3], "%x", &nsap_address[3]) != 1)
  {
    vty_out (vty, "Please specify TNA Address%s", VTY_NEWLINE);
    return CMD_WARNING;
  }
  if (sscanf (argv[4], "%x", &nsap_address[2]) != 1)
  {
    vty_out (vty, "Please specify TNA Address%s", VTY_NEWLINE);
    return CMD_WARNING;
  }
  if (sscanf (argv[5], "%x", &nsap_address[1]) != 1)
  {
    vty_out (vty, "Please specify TNA Address%s", VTY_NEWLINE);
    return CMD_WARNING;
  }
  if (sscanf (argv[6], "%x", &nsap_address[0]) != 1)
  {
    vty_out (vty, "Please specify TNA Address%s", VTY_NEWLINE);
    return CMD_WARNING;
  }

  struct in_addr empty;
  empty.s_addr = 0;
  add_tna_addr(lp, TNA_NSAP, node_id, empty, length, (void *) nsap_address);

  if (OspfTE.status == enabled)
    if (lp->area != NULL)
    {
      if (lp->flags & LPFLG_LSA_TNA_ENGAGED)
        ospf_te_lsa_schedule (lp, REFRESH_THIS_LSA, TNA_ADDRESS);
      else
        ospf_te_lsa_schedule (lp, REORIGINATE_PER_AREA, TNA_ADDRESS);
    }
  return CMD_SUCCESS;
}

DEFUN (te_tna_addr_subtlv_node_id_add,
       te_tna_addr_subtlv_node_id_add_cmd,
       "te-link node-id add ID",
       "Configure TE link parameters\n"
       "Node ID\n"
       "Add new Node ID\n"
       "IPv4 address\n"
       "<cr>\n")
{
  struct interface *ifp = (struct interface *) vty->index;
  struct te_link *lp;

  if ((lp = lookup_linkparams_by_ifp (ifp)) == NULL)
  {
    vty_out (vty, "te_link_node_id: Something wrong!%s", VTY_NEWLINE);
    return CMD_WARNING;
  }
  struct in_addr value;

  if (! inet_aton (argv[0], &value))
  {
    vty_out (vty, "Please specify Remote Node ID by A.B.C.D%s", VTY_NEWLINE);
    return CMD_WARNING;
  }

  struct in_addr empty;
  empty.s_addr = 0;
  add_tna_addr (lp, TNA_NODE, value, empty, 0, NULL);

  if (OspfTE.status == enabled)
    if (lp->area != NULL)
    {
      if (lp->flags & LPFLG_LSA_TNA_ENGAGED)
        ospf_te_lsa_schedule (lp, REFRESH_THIS_LSA, TNA_ADDRESS);
      else
        ospf_te_lsa_schedule (lp, REORIGINATE_PER_AREA, TNA_ADDRESS);
    }
  return CMD_SUCCESS;
}

DEFUN (te_tna_addr_subtlv_node_id_clear,
       te_tna_addr_subtlv_node_id_clear_cmd,
       "te-link node-id clear",
       "Configure TE link parameters\n"
       "Node ID\n"
       "Clear Node ID list\n"
       "IPv4 address\n"
       "<cr>\n")
{
  struct interface *ifp = (struct interface *) vty->index;
  struct te_link *lp;

  if ((lp = lookup_linkparams_by_ifp (ifp)) == NULL)
  {
    vty_out (vty, "te_link_node_id: Something wrong!%s", VTY_NEWLINE);
    return CMD_WARNING;
  }

  clear_tna_addr (lp);

  if (OspfTE.status == enabled)
    if (lp->area != NULL)
    {
      if (lp->flags & LPFLG_LSA_TNA_ENGAGED)
        ospf_te_lsa_schedule (lp, REFRESH_THIS_LSA, TNA_ADDRESS);
      else
        ospf_te_lsa_schedule (lp, REORIGINATE_PER_AREA, TNA_ADDRESS);
    }
  return CMD_SUCCESS;
}

DEFUN (te_link_subtlv_general_cap_flag_s_set,
       te_link_subtlv_general_cap_flag_s_set_cmd,
       "te-link general-cap flag-s set (sonet|sdh|ssdh)",
       "Configure TE link parameters\n"
       "Configure General Capabilities\n"
       "Configure flag S\n"
       "Set flag S\n"
       "SONET switching-capable\n"
       "SDH switching-capable\n"
       "SONET and SDH switching-capable\n"
       "<cr>\n")
{
  struct interface *ifp = (struct interface *) vty->index;
  struct te_link *lp;

  if ((lp = lookup_linkparams_by_ifp (ifp)) == NULL)
    {
      vty_out (vty, "te_link_general_cap_flag_s: Something wrong!%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  u_int8_t value = str2val(&pair_val_str_flags_values, argv[0]);
  if (value == 0)
  {
      vty_out (vty, "Invalid signal type %s %s", argv[0], VTY_NEWLINE);
      return CMD_WARNING;
  }

  set_oif_general_cap_flag_s(lp, value);
 
      if (OspfTE.status == enabled)
        if (lp->area != NULL)
          {
            if (lp->flags & LPFLG_LSA_LI_ENGAGED)
              ospf_te_lsa_schedule (lp, REFRESH_THIS_LSA, LINK);
            else
              ospf_te_lsa_schedule (lp, REORIGINATE_PER_AREA, LINK);
          }

  return CMD_SUCCESS;
}

DEFUN (te_link_subtlv_general_cap_flag_t_enable,
       te_link_subtlv_general_cap_flag_t_enable_cmd,
       "te-link general-cap flag-t enable",
       "Configure TE link parameters\n"
       "Configure General Capabilities\n"
       "Configure flag T\n"
       "Enable transit control domain\n"
       "<cr>\n")
{
  struct interface *ifp = (struct interface *) vty->index;
  struct te_link *lp;

  if ((lp = lookup_linkparams_by_ifp (ifp)) == NULL)
    {
      vty_out (vty, "te_link_general_cap_flag_s: Something wrong!%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  set_oif_general_cap_flag_t(lp, GEN_CAP_T);

     if (OspfTE.status == enabled)
       if (lp->area != NULL)
          {
            if (lp->flags & LPFLG_LSA_LI_ENGAGED)
              ospf_te_lsa_schedule (lp, REFRESH_THIS_LSA, LINK);
            else
              ospf_te_lsa_schedule (lp, REORIGINATE_PER_AREA, LINK);
          }
  return CMD_SUCCESS;
}

DEFUN (te_link_subtlv_general_cap_flag_t_disable,
       te_link_subtlv_general_cap_flag_t_disable_cmd,
       "te-link general-cap flag-t disable",
       "Configure TE link parameters\n"
       "Configure General Capabilities\n"
       "Configure flag T\n"
       "Disable transit control domain\n"
       "<cr>\n")
{
  struct interface *ifp = (struct interface *) vty->index;
  struct te_link *lp;

  if ((lp = lookup_linkparams_by_ifp (ifp)) == NULL)
    {
      vty_out (vty, "te_link_general_cap_flag_s: Something wrong!%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  set_oif_general_cap_flag_t(lp, 0);

     if (OspfTE.status == enabled)
       if (lp->area != NULL)
          {
            if (lp->flags & LPFLG_LSA_LI_ENGAGED)
              ospf_te_lsa_schedule (lp, REFRESH_THIS_LSA, LINK);
            else
              ospf_te_lsa_schedule (lp, REORIGINATE_PER_AREA, LINK);
          }
  return CMD_SUCCESS;
}

DEFUN (te_link_subtlv_general_cap_flag_m_enable,
       te_link_subtlv_general_cap_flag_m_enable_cmd,
       "te-link general-cap flag-m enable",
       "Configure TE link parameters\n"
       "Configure General Capabilities\n"
       "Configure flag M\n"
       "Enable support branching for point-to-multipoint connections\n"
       "<cr>\n")
{
  struct interface *ifp = (struct interface *) vty->index;
  struct te_link *lp;

  if ((lp = lookup_linkparams_by_ifp (ifp)) == NULL)
    {
      vty_out (vty, "te_link_general_cap_flag_s: Something wrong!%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  set_oif_general_cap_flag_m(lp, GEN_CAP_M);

     if (OspfTE.status == enabled)
       if (lp->area != NULL)
          {
            if (lp->flags & LPFLG_LSA_LI_ENGAGED)
              ospf_te_lsa_schedule (lp, REFRESH_THIS_LSA, LINK);
            else
              ospf_te_lsa_schedule (lp, REORIGINATE_PER_AREA, LINK);
          }
  return CMD_SUCCESS;
}

DEFUN (te_link_subtlv_general_cap_flag_m_disable,
       te_link_subtlv_general_cap_flag_m_disable_cmd,
       "te-link general-cap flag-m disable",
       "Configure TE link parameters\n"
       "Configure General Capabilities\n"
       "Configure flag M\n"
       "Disable support branching for point-to-multipoint connections\n"
       "<cr>\n")
{
  struct interface *ifp = (struct interface *) vty->index;
  struct te_link *lp;

  if ((lp = lookup_linkparams_by_ifp (ifp)) == NULL)
    {
      vty_out (vty, "te_link_general_cap_flag_s: Something wrong!%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  set_oif_general_cap_flag_m(lp, 0);

     if (OspfTE.status == enabled)
       if (lp->area != NULL)
          {
            if (lp->flags & LPFLG_LSA_LI_ENGAGED)
              ospf_te_lsa_schedule (lp, REFRESH_THIS_LSA, LINK);
            else
              ospf_te_lsa_schedule (lp, REORIGINATE_PER_AREA, LINK);
          }
  return CMD_SUCCESS;
}

DEFUN (te_link_subtlv_hierarchy_list_add,
       te_link_subtlv_hierarchy_list_add_cmd,
       "te-link hierarchy-list add ID",
       "Configure TE link parameters\n"
       "Configure Hierarchy List\n"
       "Add Routing Controller ID\n"
       "IPv4 address\n"
       "<cr>\n")
{
  struct interface *ifp = (struct interface *) vty->index;
  struct te_link *lp;

  if ((lp = lookup_linkparams_by_ifp (ifp)) == NULL)
    {
      vty_out (vty, "te_link_hierarchy_list: Something wrong!%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  struct in_addr value;

  if (! inet_aton (argv[0], &value))
    {
      vty_out (vty, "Please specify RC ID by A.B.C.D%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  add_oif_hierarchy_list_id (lp, value);

  if (OspfTE.status == enabled)
  {
        if (lp->area != NULL)
          {
            if (lp->flags & LPFLG_LSA_LI_ENGAGED)
              ospf_te_lsa_schedule (lp, REFRESH_THIS_LSA, LINK);
            else
              ospf_te_lsa_schedule (lp, REORIGINATE_PER_AREA, LINK);
          }
  }
  return CMD_SUCCESS;
}

DEFUN (te_link_subtlv_hierarchy_list_clear,
       te_link_subtlv_hierarchy_list_clear_cmd,
       "te-link hierarchy-list clear",
       "Configure TE link parameters\n"
       "Configure Hierarchy List\n"
       "Clear Hierarchy List\n"
       "<cr>\n")
{
  struct interface *ifp = (struct interface *) vty->index;
  struct te_link *lp;

  if ((lp = lookup_linkparams_by_ifp (ifp)) == NULL)
    {
      vty_out (vty, "te_link_hierarchy_list: Something wrong!%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  int ret = clear_oif_hierarchy_list_id(lp);

  if (ret == -1)
    vty_out (vty, "  Hierarchy list: List is already empty!%s", VTY_NEWLINE);

  if ((ntohs(lp->hierarchy_list.header.type) == 0) || (ret == 0))
    {
      if (OspfTE.status == enabled)
        if (lp->area != NULL)
          {
            if (lp->flags & LPFLG_LSA_LI_ENGAGED)
              ospf_te_lsa_schedule (lp, REFRESH_THIS_LSA, LINK);
            else
              ospf_te_lsa_schedule (lp, REORIGINATE_PER_AREA, LINK);
          }
    }
  return CMD_SUCCESS;
}

DEFUN (te_link_subtlv_anc_rc_id,
       te_link_subtlv_anc_rc_id_cmd,
       "te-link ancestor-rc-id ID",
       "Configure TE link parameters\n"
       "Configure Ancestor RC (Routing Controller) ID\n"
       "IPv4 address\n"
       "<cr>\n")
{
  struct interface *ifp = (struct interface *) vty->index;
  struct te_link *lp;

  if ((lp = lookup_linkparams_by_ifp (ifp)) == NULL)
    {
      vty_out (vty, "te_link_anc_rc_id: Something wrong!%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  struct in_addr value;

  if (! inet_aton (argv[0], &value))
    {
      vty_out (vty, "Please specify Ancestor RC ID by A.B.C.D%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
    set_oif_anc_rc_id(lp, value); 
      if (OspfTE.status == enabled)
        if (lp->area != NULL)
          {
            if (lp->flags & LPFLG_LSA_LI_ENGAGED)
              ospf_te_lsa_schedule (lp, REFRESH_THIS_LSA, LINK);
            else
              ospf_te_lsa_schedule (lp, REORIGINATE_PER_AREA, LINK);
          }
  return CMD_SUCCESS;
}

/** ******************************************************************* */
/** *************** GMPLS ASON Routing ******************************** */

DEFUN (te_link_subtlv_band_account_add,
       te_link_subtlv_band_account_add_cmd,
       "te-link bandwidth-accounting add SIGNAL-TYPE TIME-SLOTS",
       "Configure TE link parameters\n"
       "Configure Technology Specific Bandwidth Accounting\n"
       "Add signal\n"
       "(8-bit Hexadecimal value; ex. 0xa1) Signal type\n"
       "(24-bit Hexadecimal value; ex. 0xa1a1a1) Unallocated time slots\n"
       "<cr>\n")
{
  struct interface *ifp = (struct interface *) vty->index;
  struct te_link *lp;

  if ((lp = lookup_linkparams_by_ifp (ifp)) == NULL)
    {
      vty_out (vty, "te_link_band_account: Something wrong!%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  u_int32_t signal;
  if (sscanf (argv[0], "0x%x", &signal) != 1)
  {
    vty_out (vty, "te_link_band_account: %s%s", safe_strerror (errno), VTY_NEWLINE);
    return CMD_WARNING;
  }
  u_int32_t value;
  if (sscanf (argv[1], "0x%x", &value) != 1)
    {
      vty_out (vty, "te_link_band_account fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
      return CMD_WARNING;
    }

  u_char utslots[3];
  utslots[0] = value;
  value = value>>8;
  utslots[1] = value;
  value = value>>8;
  utslots[2] = value;

  add_ason_band_account (lp, signal, utslots);

      if (OspfTE.status == enabled)
        if (lp->area != NULL)
          {
            if (lp->flags & LPFLG_LSA_LI_ENGAGED)
              ospf_te_lsa_schedule (lp, REFRESH_THIS_LSA, LINK);
            else
              ospf_te_lsa_schedule (lp, REORIGINATE_PER_AREA, LINK);
          }
  return CMD_SUCCESS;
}

DEFUN (te_link_subtlv_band_account_clear,
       te_link_subtlv_band_account_clear_cmd,
       "te-link bandwidth-accounting clear",
       "Configure TE link parameters\n"
       "Configure Technology Specific Bandwidth Accounting\n"
       "Clear signal list\n"
       "<cr>\n")
{
  struct interface *ifp = (struct interface *) vty->index;
  struct te_link *lp;

  if ((lp = lookup_linkparams_by_ifp (ifp)) == NULL)
    {
      vty_out (vty, "te_link_bandwidth-accounting: Something wrong!%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  int ret = clear_ason_band_account(lp);

  if (ret == -1)
    vty_out (vty, "  Bandwidth accounting: List is already empty!%s", VTY_NEWLINE);

  if ((ntohs(lp->band_account.header.type) == 0) || (ret == 0))
    {
      if (OspfTE.status == enabled)
        if (lp->area != NULL)
          {
            if (lp->flags & LPFLG_LSA_LI_ENGAGED)
              ospf_te_lsa_schedule (lp, REFRESH_THIS_LSA, LINK);
            else
              ospf_te_lsa_schedule (lp, REORIGINATE_PER_AREA, LINK);
          }
    }
  return CMD_SUCCESS;
}

DEFUN (te_link_subtlv_ospf_down_aa_id_add,
       te_link_subtlv_ospf_down_aa_id_add_cmd,
       "te-link ospf-down-aa-id add AREA-ID",
       "Configure TE link parameters\n"
       "Configure OSPF Downstream Associated Area ID\n"
       "Add area ID\n"
       "(32-bit Hexadecimal value; ex. 0xa1a1a1a1)\n"
       "<cr>\n")
{
  struct interface *ifp = (struct interface *) vty->index;
  struct te_link *lp;

  if ((lp = lookup_linkparams_by_ifp (ifp)) == NULL)
    {
      vty_out (vty, "te_link_ospf_down_aa_id: Something wrong!%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  u_int32_t value;
  if (sscanf (argv[0], "0x%x", &value) != 1)
  {
    vty_out (vty, "te_link_ospf_down_aa_id: %s%s", safe_strerror (errno), VTY_NEWLINE);
    return CMD_WARNING;
  }

  add_ason_ospf_down_aa_id (lp, value);

     if (OspfTE.status == enabled)
        if (lp->area != NULL)
          {
            if (lp->flags & LPFLG_LSA_LI_ENGAGED)
              ospf_te_lsa_schedule (lp, REFRESH_THIS_LSA, LINK);
            else
              ospf_te_lsa_schedule (lp, REORIGINATE_PER_AREA, LINK);
          }
  return CMD_SUCCESS;
}

DEFUN (te_link_subtlv_ospf_down_aa_id_clear,
       te_link_subtlv_ospf_down_aa_id_clear_cmd,
       "te-link ospf-down-aa-id clear",
       "Configure TE link parameters\n"
       "Configure OSPF Downstream Associated Area ID\n"
       "Clear area ID list\n"
       "<cr>\n")
{
  struct interface *ifp = (struct interface *) vty->index;
  struct te_link *lp;

  if ((lp = lookup_linkparams_by_ifp (ifp)) == NULL)
    {
      vty_out (vty, "te_link_ospf_down_aa_id: Something wrong!%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  int ret = clear_ason_ospf_down_aa_id(lp);

  if (ret == -1)
    vty_out (vty, "  Ospf downstream associated area ID: List is already empty!%s", VTY_NEWLINE);

  if ((ntohs(lp->band_account.header.type) == 0) || (ret == 0))
    {
      if (OspfTE.status == enabled)
        if (lp->area != NULL)
          {
            if (lp->flags & LPFLG_LSA_LI_ENGAGED)
              ospf_te_lsa_schedule (lp, REFRESH_THIS_LSA, LINK);
            else
              ospf_te_lsa_schedule (lp, REORIGINATE_PER_AREA, LINK);
          }
    }
  return CMD_SUCCESS;
}

DEFUN (te_link_subtlv_aa_id,
       te_link_subtlv_aa_id_cmd,
       "te-link aa-id AREA-ID",
       "Configure TE link parameters\n"
       "Configure Associated Area ID\n"
       "(32-bit Hexadecimal value; ex. 0xa1a1a1a1)\n"
       "<cr>\n")
{
  struct interface *ifp = (struct interface *) vty->index;
  struct te_link *lp;

  if ((lp = lookup_linkparams_by_ifp (ifp)) == NULL)
    {
      vty_out (vty, "te_link_aa_id: Something wrong!%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  u_int32_t value;
  if (sscanf (argv[0], "0x%x", &value) != 1)
  {
    vty_out (vty, "te_link_aa_id: %s%s", safe_strerror (errno), VTY_NEWLINE);
    return CMD_WARNING;
  }

  set_ason_aa_id (lp, value);

     if (OspfTE.status == enabled)
        if (lp->area != NULL)
          {
            if (lp->flags & LPFLG_LSA_LI_ENGAGED)
              ospf_te_lsa_schedule (lp, REFRESH_THIS_LSA, LINK);
            else
              ospf_te_lsa_schedule (lp, REORIGINATE_PER_AREA, LINK);
          }
  return CMD_SUCCESS;
}

/** *************** GMPLS All-optical Extensions ********************** */

DEFUN (te_link_subtlv_ber_estimate,
       te_link_subtlv_ber_estimate_cmd,
       "te-link ber-estimate BER",
       "Configure TE link parameters\n"
       "BER estimate\n"
       "(8-bit Hexadecimal value; ex. 0xa1) The exponent from the BER representation \n"
       "<cr>\n")
{
  struct interface *ifp = (struct interface *) vty->index;
  struct te_link *lp;

  if ((lp = lookup_linkparams_by_ifp (ifp)) == NULL)
    {
      vty_out (vty, "te_link_ber_estimate: Something wrong!%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  u_int32_t val;
  if (sscanf (argv[0], "0x%x", &val) != 1)
    {
      vty_out (vty, "te_link_ber_estimate: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
      return CMD_WARNING;
    }
  if (ntohs (lp->ber_estimate.header.type) == 0  ||  lp->ber_estimate.value != val)
    {
      set_all_opt_ext_ber_estimate (lp, val);

      if (OspfTE.status == enabled)
        if (lp->area != NULL)
          {
            if (lp->flags & LPFLG_LSA_LI_ENGAGED)
              ospf_te_lsa_schedule (lp, REFRESH_THIS_LSA, LINK);
            else
              ospf_te_lsa_schedule (lp, REORIGINATE_PER_AREA, LINK);
          }
    }
  return CMD_SUCCESS;
}

DEFUN (te_link_subtlv_span_length,
       te_link_subtlv_span_length_cmd,
       "te-link span-length <0-4294967295>",
       "Configure TE link parameters\n"
       "The total length of the WDM span in meters \n"
       "Span length in meters\n"
       "<cr>\n")
{
  struct interface *ifp = (struct interface *) vty->index;
  struct te_link *lp;
  u_int32_t value;

  if ((lp = lookup_linkparams_by_ifp (ifp)) == NULL)
    {
      vty_out (vty, "te_link_span_length: Something wrong!%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  value = strtoul (argv[0], NULL, 10);

  if (ntohs (lp->span_length.header.type) == 0
  ||  ntohl (lp->span_length.value) != value)
    {
      set_all_opt_ext_span_length (lp, value);

      if (OspfTE.status == enabled)
        if (lp->area != NULL)
          {
            if (lp->flags & LPFLG_LSA_LI_ENGAGED)
              ospf_te_lsa_schedule (lp, REFRESH_THIS_LSA, LINK);
            else
              ospf_te_lsa_schedule (lp, REORIGINATE_PER_AREA, LINK);
          }
    }
  return CMD_SUCCESS;
}

DEFUN (te_link_subtlv_osnr,
       te_link_subtlv_osnr_cmd,
       "te-link osnr <0-4294967295>",
       "Configure TE link parameters\n"
       "The value in dB of the signal to noise ratio \n"
       "OSNR\n"
       "<cr>\n")
{
  struct interface *ifp = (struct interface *) vty->index;
  struct te_link *lp;
  u_int32_t value;

  if ((lp = lookup_linkparams_by_ifp (ifp)) == NULL)
    {
      vty_out (vty, "te_link_osnr: Something wrong!%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  value = strtoul (argv[0], NULL, 10);

  if (ntohs (lp->osnr.header.type) == 0
  ||  ntohl (lp->osnr.value) != value)
    {
      set_all_opt_ext_osnr (lp, value);

      if (OspfTE.status == enabled)
        if (lp->area != NULL)
          {
            if (lp->flags & LPFLG_LSA_LI_ENGAGED)
              ospf_te_lsa_schedule (lp, REFRESH_THIS_LSA, LINK);
            else
              ospf_te_lsa_schedule (lp, REORIGINATE_PER_AREA, LINK);
          }
    }
  return CMD_SUCCESS;
}

DEFUN (te_link_subtlv_d_pdm,
       te_link_subtlv_d_pdm_cmd,
       "te-link d-pdm D-PDM",
       "Configure TE link parameters\n"
       "The fiber PDM parameter in ps per sqrt(km) of the k-th span in the circuit \n"
       "(IEEE floating point format)\n"
       "<cr>\n")
{
  struct interface *ifp = (struct interface *) vty->index;
  struct te_link *lp;
  float f1, f2;

  if ((lp = lookup_linkparams_by_ifp (ifp)) == NULL)
    {
      vty_out (vty, "te_link_d_pdm: Something wrong!%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  ntohf (&lp->max_rsv_bw.value, &f1);
  if (sscanf (argv[0], "%g", &f2) != 1)
    {
      vty_out (vty, "te_link_d_pdm: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (ntohs (lp->d_pdm.header.type) == 0 ||  f1 != f2)
    {
      set_all_opt_ext_d_pdm (lp, &f2);

      if (OspfTE.status == enabled)
        if (lp->area != NULL)
          {
            if (lp->flags & LPFLG_LSA_LI_ENGAGED)
              ospf_te_lsa_schedule (lp, REFRESH_THIS_LSA, LINK);
            else
              ospf_te_lsa_schedule (lp, REORIGINATE_PER_AREA, LINK);
          }
    }
  return CMD_SUCCESS;
}

DEFUN (te_link_subtlv_amp_list_add,
       te_link_subtlv_amp_list_add_cmd,
       "te-link amplifiers-list add GAIN NOISE",
       "Configure TE link parameters\n"
       "List of amplifiers traversed in the span (gain and noise)\n"
       "Add amplifier\n"
       "(32-bit value)\n"
       "(IEEE floating point format)\n"
       "<cr>\n")
{
  struct interface *ifp = (struct interface *) vty->index;
  struct te_link *lp;

  if ((lp = lookup_linkparams_by_ifp (ifp)) == NULL)
    {
      vty_out (vty, "te_link_amp_list: Something wrong!%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  u_int32_t value;
  if (sscanf (argv[0], "%d", &value) != 1)
    {
      vty_out (vty, "te_link_amp_list arg0 fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
      return CMD_WARNING;
    }

  float fval;
  if (sscanf (argv[1], "%g", &fval) != 1)
  {
      vty_out (vty, "te_link_amp_list: arg1 anf: %s%s", safe_strerror (errno), VTY_NEWLINE);
      return CMD_WARNING;
  }

  add_all_opt_ext_amp_list(lp, value, &fval);

  if (OspfTE.status == enabled)
  {
        if (lp->area != NULL)
          {
            if (lp->flags & LPFLG_LSA_LI_ENGAGED)
              ospf_te_lsa_schedule (lp, REFRESH_THIS_LSA, LINK);
            else
              ospf_te_lsa_schedule (lp, REORIGINATE_PER_AREA, LINK);
          }
  }
  return CMD_SUCCESS;
}

DEFUN (te_link_subtlv_amp_list_clear,
       te_link_subtlv_amp_list_clear_cmd,
       "te-link amplifiers-list clear",
       "Configure TE link parameters\n"
       "List of amplifiers traversed in the span (gain and noise)\n"
       "Clear amplifiers list\n"
       "<cr>\n")
{
  struct interface *ifp = (struct interface *) vty->index;
  struct te_link *lp;

  if ((lp = lookup_linkparams_by_ifp (ifp)) == NULL)
    {
      vty_out (vty, "te_link_amp_list: Something wrong!%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  int ret = clear_all_opt_ext_amp_list(lp); 

  if (ret == -1)
    vty_out (vty, "  Amplifiers list: List is already empty!%s", VTY_NEWLINE);

  if ((ntohs(lp->amp_list.header.type) == 0) || (ret == 0))
    {
      if (OspfTE.status == enabled)
        if (lp->area != NULL)
          {
            if (lp->flags & LPFLG_LSA_LI_ENGAGED)
              ospf_te_lsa_schedule (lp, REFRESH_THIS_LSA, LINK);
            else
              ospf_te_lsa_schedule (lp, REORIGINATE_PER_AREA, LINK);
          }
    }
  return CMD_SUCCESS;
}

DEFUN (te_link_subtlv_av_wave_mask_set,
       te_link_subtlv_av_wave_mask_set_cmd,
       "te-link available-wave-mask set NUMBER DESCRIPTION",
       "Configure TE link parameters\n"
       "Available wavelengths\n"
       "Set properties\n"
       "Number of wavelengths: 16-bit value (ex. 0xa1b2)\n"
       "Label set description field: 32-bit value (ex. 0xa1b2)\n"
       "<cr>\n")
{
  struct interface *ifp = (struct interface *) vty->index;
  struct te_link *lp;

  if ((lp = lookup_linkparams_by_ifp (ifp)) == NULL)
  {
    vty_out (vty, "te_link_av_wave_mask: Something wrong!%s", VTY_NEWLINE);
    return CMD_WARNING;
  }

  unsigned int value;
  if (sscanf (argv[0], "0x%x", &value) != 1)
  {
    vty_out (vty, "te_link_av_wave_mask arg0 fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
    return CMD_WARNING;
  }

  unsigned int value1;
  if (sscanf (argv[1], "0x%x", &value1) != 1)
  {
    vty_out (vty, "te_link_av_wave_mask arg1 fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
    return CMD_WARNING;
  }

  set_all_opt_ext_av_wave_mask(lp, (u_int16_t)value, value1);

  if (OspfTE.status == enabled)
  {
    if (lp->area != NULL)
    {
      if (lp->flags & LPFLG_LSA_LI_ENGAGED)
        ospf_te_lsa_schedule (lp, REFRESH_THIS_LSA, LINK);
      else
        ospf_te_lsa_schedule (lp, REORIGINATE_PER_AREA, LINK);
    }
  }
  return CMD_SUCCESS;
}

DEFUN (te_link_subtlv_av_wave_mask_add,
       te_link_subtlv_av_wave_mask_add_cmd,
       "te-link available-wave-mask add BITMAP",
       "Configure TE link parameters\n"
       "Available wavelengths\n"
       "Add wavelengths bitmap\n"
       "32-bit value (ex. 0xa1b2)\n"
       "<cr>\n")
{
  struct interface *ifp = (struct interface *) vty->index;
  struct te_link *lp;

  if ((lp = lookup_linkparams_by_ifp (ifp)) == NULL)
    {
      vty_out (vty, "te_link_av_wave_mask: Something wrong!%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  unsigned int value;
  if (sscanf (argv[0], "0x%x", &value) != 1)
    {
      vty_out (vty, "te_link_av_wave_mask arg0 fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
      return CMD_WARNING;
    }

  add_all_opt_ext_av_wave_mask_bitmap (lp, value);

  if (OspfTE.status == enabled)
  {
        if (lp->area != NULL)
          {
            if (lp->flags & LPFLG_LSA_LI_ENGAGED)
              ospf_te_lsa_schedule (lp, REFRESH_THIS_LSA, LINK);
            else
              ospf_te_lsa_schedule (lp, REORIGINATE_PER_AREA, LINK);
          }
  }
  return CMD_SUCCESS;
}

DEFUN (te_link_subtlv_av_wave_mask_clear,
       te_link_subtlv_av_wave_mask_clear_cmd,
       "te-link available-wave-mask clear",
       "Configure TE link parameters\n"
       "Available wavelengths\n"
       "Clear list\n"
       "<cr>\n")
{
  struct interface *ifp = (struct interface *) vty->index;
  struct te_link *lp;

  if ((lp = lookup_linkparams_by_ifp (ifp)) == NULL)
    {
      vty_out (vty, "te_link_av_wave_mask: Something wrong!%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  int ret = clear_all_opt_ext_av_wave_mask(lp);

  if (ret == -1)
    vty_out (vty, "  Available wavelength mask: List is already empty!%s", VTY_NEWLINE);

  if ((ntohs(lp->av_wave_mask.header.type) == 0)||(ret == 0))
    {
      if (OspfTE.status == enabled)
        if (lp->area != NULL)
          {
            if (lp->flags & LPFLG_LSA_LI_ENGAGED)
              ospf_te_lsa_schedule (lp, REFRESH_THIS_LSA, LINK);
            else
              ospf_te_lsa_schedule (lp, REORIGINATE_PER_AREA, LINK);
          }
    }
  return CMD_SUCCESS;
}


DEFUN (te_link_subtlv_te_link_calendar_add,
       te_link_subtlv_te_link_calendar_add_cmd,
       "te-link te-link-calendar add TIME BAND_0 BAND_1 BAND_2 BAND_3 BAND_4 BAND_5 BAND_6 BAND_7",
       "Configure TE link parameters\n"
        "TE-link calendar\n"
        "Add calendar\n"
        "Time\n"
        "Unreserved bandwidth (pri 0)\n"
        "Unreserved bandwidth (pri 1)\n"
        "Unreserved bandwidth (pri 2)\n"
        "Unreserved bandwidth (pri 3)\n"
        "Unreserved bandwidth (pri 4)\n"
        "Unreserved bandwidth (pri 5)\n"
        "Unreserved bandwidth (pri 6)\n"
        "Unreserved bandwidth (pri 7)\n"
        "<cr>\n")
{
  struct interface *ifp = (struct interface *) vty->index;
  struct te_link *lp;
  int i;

  if ((lp = lookup_linkparams_by_ifp (ifp)) == NULL)
  {
    vty_out (vty, "te_link_te_link_calendar: Something wrong!%s", VTY_NEWLINE);
    return CMD_WARNING;
  }

  u_int32_t value;
  if (sscanf (argv[0], "%d", &value) != 1)
  {
    vty_out (vty, "te_link_te_link_calendar arg0 fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
    return CMD_WARNING;
  }

  float fval[8];
  for (i=1; i<=8; i++)
  {
    if (sscanf (argv[i], "%g", &fval[i-1]) != 1)
    {
      vty_out (vty, "te_link_amp_list: arg1 anf: %s%s", safe_strerror (errno), VTY_NEWLINE);
      return CMD_WARNING;
    }
  }

  add_all_opt_ext_te_link_calendar(lp, value, fval);

  if (OspfTE.status == enabled)
  {
    if (lp->area != NULL)
    {
      if (lp->flags & LPFLG_LSA_LI_ENGAGED)
        ospf_te_lsa_schedule (lp, REFRESH_THIS_LSA, LINK);
      else
        ospf_te_lsa_schedule (lp, REORIGINATE_PER_AREA, LINK);
    }
  }
  return CMD_SUCCESS;
}

DEFUN (te_link_subtlv_te_link_calendar_clear,
       te_link_subtlv_te_link_calendar_clear_cmd,
       "te-link te-link-calendar clear",
       "Configure TE link parameters\n"
       "TE-link calendar\n"
       "Clear calendar\n"
       "<cr>\n")
{
  struct interface *ifp = (struct interface *) vty->index;
  struct te_link *lp;

  if ((lp = lookup_linkparams_by_ifp (ifp)) == NULL)
  {
    vty_out (vty, "te_link_te_link_calendar: Something wrong!%s", VTY_NEWLINE);
    return CMD_WARNING;
  }

  int ret = clear_all_opt_ext_te_link_calendar(lp); 

  if (ret == -1)
    vty_out (vty, "  TE-link calendar: List is already empty!%s", VTY_NEWLINE);

  if ((ntohs(lp->te_link_calendar.header.type) == 0) || (ret == 0))
  {
    if (OspfTE.status == enabled)
      if (lp->area != NULL)
      {
        if (lp->flags & LPFLG_LSA_LI_ENGAGED)
          ospf_te_lsa_schedule (lp, REFRESH_THIS_LSA, LINK);
        else
          ospf_te_lsa_schedule (lp, REORIGINATE_PER_AREA, LINK);
      }
  }
  return CMD_SUCCESS;
}

DEFUN (te_link_subtlv_power_consumption,
       te_link_subtlv_power_consumption_cmd,
       "te-link power-consumption POWER-CONSUMPTION",
       "Configure TE link parameters\n"
       "Energy consumption of the link\n"
       "(IEEE floating point format)\n"
       "<cr>\n")
{
  struct interface *ifp = (struct interface *) vty->index;
  struct te_link *lp;
  float f1;

  if ((lp = lookup_linkparams_by_ifp (ifp)) == NULL)
    {
      vty_out (vty, "te_link_power_consumption: Something wrong!%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  ntohf (&lp->power_consumption.power_consumption, &f1);

  if (ntohs (lp->power_consumption.header.type) == 0)
    {
      set_linkparams_power_consumption (lp, &f1);

      if (OspfTE.status == enabled)
        if (lp->area != NULL)
          {
            if (lp->flags & LPFLG_LSA_LI_ENGAGED)
              ospf_te_lsa_schedule (lp, REFRESH_THIS_LSA, LINK);
            else
              ospf_te_lsa_schedule (lp, REORIGINATE_PER_AREA, LINK);
          }
    }
  return CMD_SUCCESS;
}

DEFUN (te_link_subtlv_dynamic_replanning,
       te_link_subtlv_dynamic_replanning_cmd,
       "te-link dynamic-replanning DYNAMIC-REPLANNING",
       "Configure TE link parameters\n"
       "Maximum upgrade and downgrade of the link bandwidth\n"
       "(IEEE floating point format)\n"
       "<cr>\n")
{
  struct interface *ifp = (struct interface *) vty->index;
  struct te_link *lp;
  float f1, f2;

  if ((lp = lookup_linkparams_by_ifp (ifp)) == NULL)
    {
      vty_out (vty, "te_link_dynamic_replanning: Something wrong!%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  ntohf (&lp->dynamic_replanning.max_bandwidth_upgrade, &f1);
  ntohf (&lp->dynamic_replanning.max_bandwidth_downgrade, &f2);

  if (ntohs (lp->dynamic_replanning.header.type) == 0)
    {
      set_linkparams_dynanic_replanning (lp, &f1, &f2);

      if (OspfTE.status == enabled)
        if (lp->area != NULL)
          {
            if (lp->flags & LPFLG_LSA_LI_ENGAGED)
              ospf_te_lsa_schedule (lp, REFRESH_THIS_LSA, LINK);
            else
              ospf_te_lsa_schedule (lp, REORIGINATE_PER_AREA, LINK);
          }
    }
  return CMD_SUCCESS;
}

#endif /* GMPLS */


/*DEFUN (te_link_control,
       te_link_control_cmd,
       "te link control",
       "TE specific commands\n"
       "Configure TE link parameters\n"
       "Set Interface as control plane interface\n")
{
  struct interface *ifp = (struct interface *) vty->index;
  OspfTE.control_plane_interface = ifp;

  return CMD_SUCCESS;
} */

static void show_te_router_parameters(struct vty *vty, adj_type_t interface_type)
{
  vty_out (vty, "--- TE router %s parameters ---%s", (interface_type == INNI) ? "INNI" : (interface_type == ENNI) ? "ENNI" : "UNI", VTY_NEWLINE);
  if (ntohs (OspfTE.router_addr[(uint16_t)interface_type].router_addr.header.type) != 0)
    show_vty_router_addr_subtlv_router_addr (vty, &OspfTE.router_addr[(uint16_t)interface_type].router_addr.header);
  if (ntohs (OspfTE.router_addr[(uint16_t)interface_type].aa_id.header.type) != 0)
    show_vty_router_addr_subtlv_aa_id (vty, &OspfTE.router_addr[(uint16_t)interface_type].aa_id.header);
  if (ntohs (OspfTE.router_addr[(uint16_t)interface_type].power_consumption.header.type) != 0)
    show_vty_router_addr_subtlv_power_consumption (vty, &OspfTE.router_addr[(uint16_t)interface_type].power_consumption.header);

  if (ntohs (OspfTE.node_attr[(uint16_t)interface_type].node_ip4_lcl_prefix.header.type) != 0)
    show_vty_node_attr_subtlv_node_ip4_lcl_prefix_parsed (vty, &OspfTE.node_attr[(uint16_t)interface_type].node_ip4_lcl_prefix.header);
  if (ntohs (OspfTE.node_attr[(uint16_t)interface_type].node_ip6_lcl_prefix.header.type) != 0)
    show_vty_node_attr_subtlv_node_ip6_lcl_prefix_parsed (vty, &OspfTE.node_attr[(uint16_t)interface_type].node_ip6_lcl_prefix.header);
  if (ntohs (OspfTE.node_attr[(uint16_t)interface_type].lcl_te_router_id.header.type) != 0)
    show_vty_node_attr_subtlv_lcl_te_router_id (vty, &OspfTE.node_attr[(uint16_t)interface_type].lcl_te_router_id.header);
  if (ntohs (OspfTE.node_attr[(uint16_t)interface_type].aa_id.header.type) != 0)
    show_vty_node_attr_subtlv_aa_id (vty, &OspfTE.node_attr[(uint16_t)interface_type].aa_id.header);
}

DEFUN (show_te_router,
       show_te_router_cmd,
#ifndef GMPLS
       "show te router",
#else
       "show te (router|router-inni|router-enni|router-uni)",
#endif /* GMPLS */
       SHOW_STR
       "TE information\n"
       "Router information\n"
#ifdef GMPLS
       "Router INNI information\n"
       "Router ENNI information\n"
       "Router UNI information\n"
#endif /* GMPLS */
       )
{
  if (OspfTE.status == enabled)
  {
#ifndef GMPLS
    show_te_router_parameters(INNI)
#else
    if (strcmp(argv[0], "router") == 0)
    {
      if (ospf_inni_lookup() != NULL)
        show_te_router_parameters(vty, INNI);
      else
        vty_out(vty, "No ospf INNI instance%s", VTY_NEWLINE);

      if (ospf_enni_lookup() != NULL)
        show_te_router_parameters(vty, ENNI);
      else
        vty_out(vty, "No ospf ENNI instance%s", VTY_NEWLINE);
    }

    if (strcmp(argv[0], "router-inni") == 0)
    {
      if (ospf_inni_lookup() != NULL)
        show_te_router_parameters(vty, INNI);
      else
        vty_out(vty, "No ospf INNI instance%s", VTY_NEWLINE);
    }

    if (strcmp(argv[0], "router-enni") == 0)
    {
      if (ospf_enni_lookup() != NULL)
        show_te_router_parameters(vty, ENNI);
      else
        vty_out(vty, "No ospf ENNI instance%s", VTY_NEWLINE);
    }
    if (strcmp(argv[0], "router-uni") == 0)
    {
      if (ospf_uni_lookup() != NULL)
        show_te_router_parameters(vty, UNI);
      else
        vty_out(vty, "No ospf UNI instance%s", VTY_NEWLINE);
    }
#endif /* GMPLS */
  }
  return CMD_SUCCESS;
}

static void
show_te_link_sub (struct vty *vty, struct interface *ifp)
{
  struct te_link *lp = lookup_linkparams_by_ifp (ifp);
  struct te_tlv_header *tlvh;

  if ((OspfTE.status == enabled)
  &&  (! if_is_loopback (ifp) && if_is_up (ifp) && ospf_oi_count (ifp) > 0)
  &&  (lp != NULL))
  {
    vty_out (vty, "- TE link parameters for %s -- adj: %s, instance %s%s", ifp->name, SHOW_ADJTYPE(ifp->adj_type), SHOW_ADJTYPE(ifp->ospf_instance), VTY_NEWLINE);
/*    vty_out (vty, "- TE link parameters for %s -- adj: %s, instance %s  %s%s", ifp->name, SHOW_ADJTYPE(ifp->adj_type), SHOW_ADJTYPE(ifp->ospf_instance), (lp->flags & LPFLG_LSA_ORIGINATED) ? "lsa originated" : "lsa NOT originated", VTY_NEWLINE); */
    struct in_addr temp;
    temp.s_addr = htonl(lp->instance_li);
    vty_out(vty , "    TE-Link instance id %s%s", inet_ntoa(temp), VTY_NEWLINE);
    temp.s_addr = htonl(lp->instance_tna);
/*    vty_out (vty, "    TE-Link %s %s %s%s", (lp->flags & LPFLG_LI_LOOKUP_DONE) ? "LOOKUP DONE," : "NO LOOKUP DONE,", (lp->flags & LPFLG_LSA_LI_ENGAGED) ? "ENGAGED," : "NOT ENGAGED,", (lp->flags & LPFLG_LSA_LI_FORCED_REFRESH) ? "FORCED REFRESH" : "NO FORCED REFRESH ", VTY_NEWLINE); */
    vty_out(vty , "    TNA     instance id %s%s", inet_ntoa(temp), VTY_NEWLINE);
    vty_out (vty, "    TNA     %s %s %s%s", (lp->flags & LPFLG_TNA_LOOKUP_DONE) ? "LOOKUP DONE," : "NO LOOKUP DONE,", (lp->flags & LPFLG_LSA_TNA_ENGAGED) ? "ENGAGED," : "NOT ENGAGED,", (lp->flags & LPFLG_LSA_TNA_FORCED_REFRESH) ? "FORCED REFRESH" : "NO FORCED REFRESH ", VTY_NEWLINE);
/*    vty_out (vty, "    flags:         lookup done          engaged         forced_refresh%s", VTY_NEWLINE);
      vty_out (vty, "    ROUTE_ADDRESS       %s                %s              %s%s", (lp->flags & LPFLG_RA_LOOKUP_DONE) ? "YES" : "NO ", (lp->flags & LPFLG_LSA_RA_ENGAGED) ? "YES" : "NO ", (lp->flags & LPFLG_LSA_RA_FORCED_REFRESH) ? "YES" : "NO ", VTY_NEWLINE);
    vty_out (vty, "    NODE ATTRIBUTE      %s                %s              %s%s", (lp->flags & LPFLG_NA_LOOKUP_DONE) ? "YES" : "NO ", (lp->flags & LPFLG_LSA_NA_ENGAGED) ? "YES" : "NO ", (lp->flags & LPFLG_LSA_NA_FORCED_REFRESH) ? "YES" : "NO ", VTY_NEWLINE);
    vty_out (vty, "    TE LINK             %s                %s              %s%s", (lp->flags & LPFLG_LI_LOOKUP_DONE) ? "YES" : "NO ", (lp->flags & LPFLG_LSA_LI_ENGAGED) ? "YES" : "NO ", (lp->flags & LPFLG_LSA_LI_FORCED_REFRESH) ? "YES" : "NO ", VTY_NEWLINE);
    vty_out (vty, "    TNA_ADDRESS         %s                %s              %s%s", (lp->flags & LPFLG_TNA_LOOKUP_DONE) ? "YES" : "NO ", (lp->flags & LPFLG_LSA_TNA_ENGAGED) ? "YES" : "NO ", (lp->flags & LPFLG_LSA_TNA_FORCED_REFRESH) ? "YES" : "NO ", VTY_NEWLINE);
*/
    show_vty_link_subtlv_link_type (vty, &lp->link_type.header);
    show_vty_link_subtlv_link_id (vty, &lp->link_id.header);

    if ((tlvh = (struct te_tlv_header *) &lp->lclif_ipaddr) != NULL)
      show_vty_link_subtlv_lclif_ipaddr (vty, tlvh);
    if ((tlvh = (struct te_tlv_header *) &lp->rmtif_ipaddr) != NULL)
      show_vty_link_subtlv_rmtif_ipaddr (vty, tlvh);
    show_vty_link_subtlv_link_lcl_rmt_ids(vty, &lp->link_lcl_rmt_ids.header);
    show_vty_link_subtlv_lcl_rmt_te_router_id(vty, &lp->lcl_rmt_te_router_id.header);
    show_vty_link_subtlv_lcl_node_id (vty, &lp->lcl_node_id.header);
    show_vty_link_subtlv_rmt_node_id (vty, &lp->rmt_node_id.header);
    show_vty_tna_address_tlv (vty, &lp->tna_address.header);
      
    //show_vty_link_subtlv_te_metric (vty, &lp->te_metric.header);
    vty_out (vty, "  Traffic Engineering Metric: %d%s", ntohl(lp->te_metric.value), VTY_NEWLINE);
    show_vty_link_subtlv_rsc_clsclr (vty, &lp->rsc_clsclr.header);
    show_vty_link_subtlv_max_bw (vty, &lp->max_bw.header);
    show_vty_link_subtlv_max_rsv_bw (vty, &lp->max_rsv_bw.header);
    show_vty_link_subtlv_unrsv_bw (vty, &lp->unrsv_bw.header);

    show_vty_link_subtlv_link_protect_type(vty, &lp->link_protect_type.header);

    struct zlistnode *node, *nnode;
    struct te_link_subtlv_if_sw_cap_desc *ifswcap;
    for (ALL_LIST_ELEMENTS(&lp->if_sw_cap_descs, node, nnode, ifswcap))
      show_vty_link_subtlv_if_sw_cap_desc(vty, &ifswcap->header);

    show_vty_link_subtlv_shared_risk_link_grp_parsed(vty, &lp->shared_risk_link_grp.header);

    show_vty_link_subtlv_ssdh_if_sw_cap_desc_parsed (vty, &lp->ssdh_if_sw_cap_desc.header);
    show_vty_link_subtlv_general_cap (vty, &lp->general_cap.header);
    show_vty_link_subtlv_hierarchy_list_parsed (vty, &lp->hierarchy_list.header);
    show_vty_link_subtlv_anc_rc_id (vty, &lp->anc_rc_id.header);
    show_vty_link_subtlv_band_account_parsed (vty, &lp->band_account.header);
    show_vty_link_subtlv_ospf_down_aa_id_parsed (vty, &lp->ospf_down_aa_id.header);
    show_vty_link_subtlv_aa_id (vty, &lp->aa_id.header);
    show_vty_link_subtlv_ber_estimate (vty, &lp->ber_estimate.header);
    show_vty_link_subtlv_span_length (vty, &lp->span_length.header);
    show_vty_link_subtlv_osnr (vty, &lp->osnr.header);
    show_vty_link_subtlv_d_pdm (vty, &lp->d_pdm.header);
    show_vty_link_subtlv_amp_list_parsed (vty, &lp->amp_list.header);
    show_vty_link_subtlv_av_wave_mask_parsed (vty, &lp->av_wave_mask.header);
    show_vty_link_subtlv_te_link_calendar_parsed (vty, &lp->te_link_calendar.header);

    show_vty_link_subtlv_power_consumption (vty, &lp->power_consumption.header);
    show_vty_link_subtlv_dynamic_replanning (vty, &lp->dynamic_replanning.header);
  }
  else
  {
    vty_out (vty, "  %s: TE is disabled on this interface%s", ifp->name, VTY_NEWLINE);
    vty_out (vty, "    ospf status: %s%s%s%s%s%s",
      (OspfTE.status == enabled) ? "enabled" : "disabled",
      if_is_loopback (ifp) ? ", Loopback interface":"",
      if_is_up (ifp) ? "":", Interface is down", 
      ospf_oi_count (ifp) <= 0 ? ", Number of sopf intercace <= 0":"",
      lp == NULL ? ", Can't find TE-link for this interface":"",
      VTY_NEWLINE);
  }
  return;
}

DEFUN (show_te_link,
       show_te_link_cmd,
#ifndef GMPLS
       "show te interface [INTERFACE]",
#else
       "show te (interface|interface-inni|interface-enni|interface-uni) [INTERFACE]",
#endif /* GMPLS */
       SHOW_STR
       "TE information\n"
       "Interface information\n"
#ifndef GMPLS
#define CLI_ARG_GMPLS 0
#else
#define CLI_ARG_GMPLS 1
       "Interface INNI information\n"
       "Interface ENNI information\n"
       "Interface UNI information\n"
#endif /* GMPLS */
       "Interface name\n")
{

  struct te_link *lp;
  struct interface *ifp;
  struct zlistnode *node, *nnode;

  /* Show All Interfaces. */
#ifdef GMPLS
  if (strcmp(argv[0], "interface")==0)
  {
#endif /* GMPLS */
    if (argc == 0 + CLI_ARG_GMPLS)
    {
      for (ALL_LIST_ELEMENTS (OspfTE.iflist, node, nnode, lp))
        show_te_link_sub (vty, lp->ifp);
    }
    /* Interface name is specified. */
    else
    {
      if ((ifp = if_lookup_by_name (argv[0+CLI_ARG_GMPLS])) == NULL)
        vty_out (vty, "No such interface name%s", VTY_NEWLINE);
      else
        show_te_link_sub (vty, ifp);
    }
#ifdef GMPLS
  }
  else
  {
    adj_type_t interface_type = (strcmp(argv[0], "interface-enni")==0) ? ENNI : (strcmp(argv[0], "interface-uni")==0) ? UNI: INNI;
    if (argc == 0 + CLI_ARG_GMPLS)
    {
      for (ALL_LIST_ELEMENTS (OspfTE.iflist, node, nnode, lp))
        if ((lp->ifp->adj_type == interface_type) && (lp->ifp->ospf_instance != ENNI))
          show_te_link_sub (vty, lp->ifp);
    }
    else     /* Interface name is specified. */
    {
      if ((ifp = if_lookup_by_name (argv[0+CLI_ARG_GMPLS])) == NULL)
        vty_out (vty, "No such interface name%s", VTY_NEWLINE);
      else
        if (ifp->adj_type == interface_type)
          show_te_link_sub (vty, ifp);
    }
  }
#endif /* GMPLS */
  return CMD_SUCCESS;
}

static void
show_harmony_router_parameters (struct vty *vty, struct raHarmony *ra)
{
  vty_out(vty, "===================================================%s", VTY_NEWLINE);
  if (ntohs (ra->router_addr.router_addr.header.type) != 0)
    show_vty_router_addr_subtlv_router_addr (vty, &ra->router_addr.router_addr.header);
  if (ntohs (ra->router_addr.aa_id.header.type) != 0)
    show_vty_router_addr_subtlv_aa_id (vty, &ra->router_addr.aa_id.header);
  if (ntohs (ra->router_addr.power_consumption.header.type) != 0)
    show_vty_router_addr_subtlv_power_consumption (vty, &ra->router_addr.power_consumption.header);

  return;
}

DEFUN (show_harmony_info_routers,
       show_harmony_info_routers_cmd,
       "show harmony-info routers",
       SHOW_STR
       "Harmony information\n"
       "Routers information\n")
{
  struct raHarmony *ra;
  struct zlistnode *node, *nnode;

  if (!ospf_enni_lookup())
  {
    vty_out (vty, "%s Harmony is disabled!%s%s", VTY_NEWLINE, VTY_NEWLINE, VTY_NEWLINE);
    return CMD_WARNING;
  }

  if (listcount(OspfTE.harmonyRaList) == 0)
  {
    vty_out (vty, "%s There are no harmony routers!%s%s", VTY_NEWLINE, VTY_NEWLINE, VTY_NEWLINE);
    return CMD_SUCCESS;
  }

  for (ALL_LIST_ELEMENTS (OspfTE.harmonyRaList, node, nnode, ra))
    show_harmony_router_parameters (vty, ra);
  vty_out (vty, "%s", VTY_NEWLINE);

  return CMD_SUCCESS;
}

static void
show_harmony_link_sub (struct vty *vty, struct te_link *lp)
{
  struct te_tlv_header *tlvh;

  vty_out(vty, "===================================================%s", VTY_NEWLINE);

  show_vty_link_subtlv_link_type (vty, &lp->link_type.header);
  show_vty_link_subtlv_link_id (vty, &lp->link_id.header);

  if ((tlvh = (struct te_tlv_header *) &lp->lclif_ipaddr) != NULL)
    show_vty_link_subtlv_lclif_ipaddr (vty, tlvh);
  if ((tlvh = (struct te_tlv_header *) &lp->rmtif_ipaddr) != NULL)
    show_vty_link_subtlv_rmtif_ipaddr (vty, tlvh);
  show_vty_link_subtlv_link_lcl_rmt_ids(vty, &lp->link_lcl_rmt_ids.header);
  show_vty_link_subtlv_lcl_rmt_te_router_id(vty, &lp->lcl_rmt_te_router_id.header);
  show_vty_link_subtlv_lcl_node_id (vty, &lp->lcl_node_id.header);
  show_vty_link_subtlv_rmt_node_id (vty, &lp->rmt_node_id.header);
  show_vty_tna_address_tlv (vty, &lp->tna_address.header);

  show_vty_link_subtlv_te_metric (vty, &lp->te_metric.header);
  show_vty_link_subtlv_rsc_clsclr (vty, &lp->rsc_clsclr.header);
  show_vty_link_subtlv_max_bw (vty, &lp->max_bw.header);
  show_vty_link_subtlv_max_rsv_bw (vty, &lp->max_rsv_bw.header);
  show_vty_link_subtlv_unrsv_bw (vty, &lp->unrsv_bw.header);

  show_vty_link_subtlv_link_protect_type(vty, &lp->link_protect_type.header);

  struct zlistnode *node, *nnode;
  struct te_link_subtlv_if_sw_cap_desc *ifswcap;
  for (ALL_LIST_ELEMENTS(&lp->if_sw_cap_descs, node, nnode, ifswcap))
    show_vty_link_subtlv_if_sw_cap_desc(vty, &ifswcap->header);

  show_vty_link_subtlv_shared_risk_link_grp_parsed(vty, &lp->shared_risk_link_grp.header);

  show_vty_link_subtlv_ssdh_if_sw_cap_desc_parsed (vty, &lp->ssdh_if_sw_cap_desc.header);
  show_vty_link_subtlv_general_cap (vty, &lp->general_cap.header);
  show_vty_link_subtlv_hierarchy_list_parsed (vty, &lp->hierarchy_list.header);
  show_vty_link_subtlv_anc_rc_id (vty, &lp->anc_rc_id.header);
  show_vty_link_subtlv_band_account_parsed (vty, &lp->band_account.header);
  show_vty_link_subtlv_ospf_down_aa_id_parsed (vty, &lp->ospf_down_aa_id.header);
  show_vty_link_subtlv_aa_id (vty, &lp->aa_id.header);
  show_vty_link_subtlv_ber_estimate (vty, &lp->ber_estimate.header);
  show_vty_link_subtlv_span_length (vty, &lp->span_length.header);
  show_vty_link_subtlv_osnr (vty, &lp->osnr.header);
  show_vty_link_subtlv_d_pdm (vty, &lp->d_pdm.header);
  show_vty_link_subtlv_amp_list_parsed (vty, &lp->amp_list.header);
  show_vty_link_subtlv_av_wave_mask_parsed (vty, &lp->av_wave_mask.header);
  show_vty_link_subtlv_te_link_calendar_parsed (vty, &lp->te_link_calendar.header);

  show_vty_link_subtlv_power_consumption (vty, &lp->power_consumption.header);
  show_vty_link_subtlv_dynamic_replanning (vty, &lp->dynamic_replanning.header);

  return;
}

DEFUN (show_harmony_info_links,
       show_harmony_info_links_cmd,
       "show harmony-info te-links",
       SHOW_STR
       "Harmony information\n"
       "TE-Links information\n")
{
  struct te_link *lp;
  struct zlistnode *node, *nnode;

  if (!ospf_enni_lookup())
  {
    vty_out (vty, "%s Harmony is disabled!%s%s", VTY_NEWLINE, VTY_NEWLINE, VTY_NEWLINE);
    return CMD_WARNING;
  }

  if (listcount(OspfTE.harmonyIflist) == 0)
  {
    vty_out (vty, "%s There are no harmony TE-Links!%s%s", VTY_NEWLINE, VTY_NEWLINE, VTY_NEWLINE);
    return CMD_SUCCESS;
  }

  for (ALL_LIST_ELEMENTS (OspfTE.harmonyIflist, node, nnode, lp))
    show_harmony_link_sub (vty, lp);
  vty_out (vty, "%s", VTY_NEWLINE);

  return CMD_SUCCESS;
}


DEFUN (debug_ospf_te,
       debug_ospf_te_cmd,
       "debug ospf te (all|generate|originate|refresh|flush|"
       "feed-up|feed-down|uni-inni|inni-uni|"
       "new|delete|ism-change|nsm-change|"
       "initialization|read|corba-update|corba-set|user)",
       DEBUG_STR
       OSPF_STR
       "Traffic Engineering information\n"
       "all te events\n"

       "te generate events\n"
       "te originate events\n"
       "te opaque refresh events\n"
       "te opaque flush events\n"

       "te feed up\n"
       "te feed down\n"
       "te moving lsa from ospf uni to ospf inni instance\n"
       "te moving lsa from ospf inni to ospf uni instance\n"

       "te opaque new\n"
       "te opaque delete\n"
       "te ISM change\n"
       "te NSM change\n"

       "te parameter initialization\n"
       "te parameters reading from interface\n"
       "te corba update\n"
       "te corba set\n"
       "te info for user\n")
{
  if (strcmp (argv[0], "all") == 0)
    TE_DEBUG_ON (ALL);

  else if (strcmp (argv[0], "generate") == 0)
    TE_DEBUG_ON (GENERATE);
  else if (strcmp (argv[0], "originate") == 0)
    TE_DEBUG_ON (ORIGINATE);
  else if (strcmp (argv[0], "flush") == 0)
    TE_DEBUG_ON (FLUSH);
  else if (strcmp (argv[0], "refresh") == 0)
    TE_DEBUG_ON (REFRESH);

  else if (strcmp (argv[0], "feed-up") == 0)
    TE_DEBUG_ON (FEED_UP);
  else if (strcmp (argv[0], "feed-down") == 0)
    TE_DEBUG_ON (FEED_DOWN);
  else if (strcmp (argv[0], "uni-inni") == 0)
    TE_DEBUG_ON (UNI_TO_INNI);
  else if (strcmp (argv[0], "inni-uni") == 0)
    TE_DEBUG_ON (INNI_TO_UNI);

  else if (strcmp (argv[0], "ism-change") == 0)
    TE_DEBUG_ON (ISM_CHANGE);
  else if (strcmp (argv[0], "nsm-change") == 0)
    TE_DEBUG_ON (NSM_CHANGE);
  else if (strcmp (argv[0], "new") == 0)
    TE_DEBUG_ON (LSA_NEW);
  else if (strcmp (argv[0], "delete") == 0)
    TE_DEBUG_ON (LSA_DELETE);

  else if (strcmp (argv[0], "ism-change") == 0)
    TE_DEBUG_ON (ISM_CHANGE);
  else if (strcmp (argv[0], "nsm-change") == 0)
    TE_DEBUG_ON (NSM_CHANGE);
  else if (strcmp (argv[0], "corba-update") == 0)
    TE_DEBUG_ON (CORBA_UPDATE);
  else if (strcmp (argv[0], "corba-set") == 0)
    TE_DEBUG_ON (CORBA_SET);
  else if (strcmp (argv[0], "user") == 0)
    TE_DEBUG_ON (USER);

  return CMD_SUCCESS;
}

DEFUN (no_debug_ospf_te,
       no_debug_ospf_te_cmd,
       "no debug ospf te (all|generate|originate|refresh|flush|"
       "feed-up|feed-down|uni-inni|inni-uni|"
       "new|delete|ism-change|nsm-change|"
       "initialization|read|corba-update|corba-set|user)",
       NO_STR
       DEBUG_STR
       OSPF_STR
       "Traffic Engineering information\n"
       "all te events\n"

       "te generate events\n"
       "te originate events\n"
       "te opaque refresh events\n"
       "te opaque flush events\n"

       "te feed up\n"
       "te feed down\n"
       "te moving lsa from ospf uni to ospf inni instance\n"
       "te moving lsa from ospf inni to ospf uni instance\n"

       "te opaque new\n"
       "te opaque delete\n"
       "te ISM change\n"
       "te NSM change\n"

       "te parameter initialization\n"
       "te parameters reading from interface\n"
       "te corba update\n"
       "te corba set\n"
       "te information for user\n")

{
  if (strcmp (argv[0], "all") == 0)
    TE_DEBUG_OFF (ALL);
  else if (strcmp (argv[0], "generate") == 0)
    TE_DEBUG_OFF (GENERATE);
  else if (strcmp (argv[0], "originate") == 0)
    TE_DEBUG_OFF (ORIGINATE);
  else if (strcmp (argv[0], "flush") == 0)
    TE_DEBUG_OFF (FLUSH);
  else if (strcmp (argv[0], "refresh") == 0)
    TE_DEBUG_OFF (REFRESH);

  else if (strcmp (argv[0], "feed-up") == 0)
    TE_DEBUG_OFF (FEED_UP);
  else if (strcmp (argv[0], "feed-down") == 0)
    TE_DEBUG_OFF (FEED_DOWN);
  else if (strcmp (argv[0], "uni-inni") == 0)
    TE_DEBUG_OFF (UNI_TO_INNI);
  else if (strcmp (argv[0], "inni-uni") == 0)
    TE_DEBUG_OFF (INNI_TO_UNI);

  else if (strcmp (argv[0], "ism-change") == 0)
    TE_DEBUG_OFF (ISM_CHANGE);
  else if (strcmp (argv[0], "nsm-change") == 0)
    TE_DEBUG_OFF (NSM_CHANGE);
  else if (strcmp (argv[0], "new") == 0)
    TE_DEBUG_OFF (LSA_NEW);
  else if (strcmp (argv[0], "delete") == 0)
    TE_DEBUG_OFF (LSA_DELETE);

  else if (strcmp (argv[0], "ism-change") == 0)
    TE_DEBUG_OFF (ISM_CHANGE);
  else if (strcmp (argv[0], "nsm-change") == 0)
    TE_DEBUG_OFF (NSM_CHANGE);
  else if (strcmp (argv[0], "corba-update") == 0)
    TE_DEBUG_OFF (CORBA_UPDATE);
  else if (strcmp (argv[0], "corba-set") == 0)
    TE_DEBUG_OFF (CORBA_SET);
  else if (strcmp (argv[0], "user") == 0)
    TE_DEBUG_OFF (USER);

  return CMD_SUCCESS;
}

static void
ospf_te_register_vty (void)
{
//install_node (&ospf_te_link_node, te_link_node_write);

//install_element (CONFIG_NODE, &te_link_node_cmd);

  install_element (VIEW_NODE, &show_te_router_cmd);
  install_element (VIEW_NODE, &show_te_link_cmd);
  install_element (VIEW_NODE, &show_harmony_info_routers_cmd);
  install_element (VIEW_NODE, &show_harmony_info_links_cmd);
  install_element (ENABLE_NODE, &show_te_router_cmd);
  install_element (ENABLE_NODE, &show_te_link_cmd);
  install_element (ENABLE_NODE, &show_harmony_info_routers_cmd);
  install_element (ENABLE_NODE, &show_harmony_info_links_cmd);

  install_element (ENABLE_NODE, &debug_ospf_te_cmd);
  install_element (CONFIG_NODE, &debug_ospf_te_cmd);
  install_element (ENABLE_NODE, &no_debug_ospf_te_cmd);
  install_element (CONFIG_NODE, &no_debug_ospf_te_cmd);

//install_element (ENABLE_NODE, &show_te_data_link_cmd);
  install_element (OSPF_NODE, &te_force_originate_cmd);
  install_element (OSPF_NODE, &te_tna_force_cmd);
  install_element (OSPF_NODE, &te_cmd);
  install_element (OSPF_NODE, &no_te_cmd);
  install_element (OSPF_NODE, &te_on_cmd);
//install_element (OSPF_NODE, &te_router_addr_cmd);
  install_element (OSPF_NODE, &te_router_addr_subtlv_router_addr_cmd);
  install_element (OSPF_NODE, &te_router_addr_subtlv_aa_id_cmd);
  install_element (OSPF_NODE, &te_router_addr_subtlv_power_consumption_cmd);

  install_element (OSPF_NODE, &te_node_attr_subtlv_lcl_te_router_id_cmd);
  install_element (OSPF_NODE, &te_node_attr_subtlv_aa_id_cmd);
  install_element (OSPF_NODE, &te_node_attr_subtlv_node_ip4_lcl_prefix_add_cmd);
  install_element (OSPF_NODE, &te_node_attr_subtlv_node_ip4_lcl_prefix_clear_cmd);
  install_element (OSPF_NODE, &te_node_attr_subtlv_node_ip6_lcl_prefix_add_cmd);
  install_element (OSPF_NODE, &te_node_attr_subtlv_node_ip6_lcl_prefix_clear_cmd);


  install_element (OSPF_NODE, &mpls_te_cmd);
  install_element (OSPF_NODE, &gmpls_te_cmd);
  install_element (OSPF_NODE, &g2mpls_te_cmd);
  install_element (OSPF_NODE, &reoriginate_te_cmd);
//install_element (OSPF_NODE, &ospf_inni_cmd);
//install_element (OSPF_NODE, &ospf_enni_cmd);

  install_element (INTERFACE_NODE, &te_link_area_cmd);

  install_element (INTERFACE_NODE, &te_link_metric_cmd);
  install_element (INTERFACE_NODE, &te_link_maxbw_cmd);
  install_element (INTERFACE_NODE, &te_link_max_rsv_bw_cmd);
  install_element (INTERFACE_NODE, &te_link_unrsv_bw_cmd);
  install_element (INTERFACE_NODE, &te_link_rsc_clsclr_cmd);

//install_element (INTERFACE_NODE, &te_link_control_cmd);

  install_element (INTERFACE_NODE, &te_link_subtlv_link_lcl_rmt_ids_local_cmd);
  install_element (INTERFACE_NODE, &te_link_subtlv_link_lcl_rmt_ids_remote_cmd);
  install_element (INTERFACE_NODE, &te_link_subtlv_link_protect_type_cmd);
  install_element (INTERFACE_NODE, &te_link_subtlv_if_sw_cap_desc_psc_cmd);
  install_element (INTERFACE_NODE, &te_link_subtlv_if_sw_cap_desc_tdm_cmd);
  install_element (INTERFACE_NODE, &te_link_subtlv_if_sw_cap_desc_lsc_fsc_cmd);
  install_element (INTERFACE_NODE, &te_link_subtlv_if_sw_cap_maxLSPbw_cmd);
  install_element (INTERFACE_NODE, &te_link_subtlv_if_sw_cap_desc_clear_cmd);
  install_element (INTERFACE_NODE, &te_link_subtlv_shared_risk_link_grp_add_cmd);
  install_element (INTERFACE_NODE, &te_link_subtlv_shared_risk_link_grp_clear_cmd);

  install_element (INTERFACE_NODE, &te_link_subtlv_lcl_rmt_te_router_id_cmd);

#ifdef GMPLS
/** **************** OIF E-NNI Routing ************************************* */
  install_element (INTERFACE_NODE, &te_link_subtlv_lcl_node_id_cmd);
  install_element (INTERFACE_NODE, &te_link_subtlv_rmt_node_id_cmd);
  install_element (INTERFACE_NODE, &te_link_subtlv_ssdh_if_sw_cap_desc_add_cmd);
  install_element (INTERFACE_NODE, &te_link_subtlv_ssdh_if_sw_cap_desc_clear_cmd);
  install_element (INTERFACE_NODE, &te_link_subtlv_general_cap_flag_s_set_cmd);
  install_element (INTERFACE_NODE, &te_link_subtlv_general_cap_flag_t_enable_cmd);
  install_element (INTERFACE_NODE, &te_link_subtlv_general_cap_flag_t_disable_cmd);
  install_element (INTERFACE_NODE, &te_link_subtlv_general_cap_flag_m_enable_cmd);
  install_element (INTERFACE_NODE, &te_link_subtlv_general_cap_flag_m_disable_cmd);
  install_element (INTERFACE_NODE, &te_link_subtlv_hierarchy_list_add_cmd);
  install_element (INTERFACE_NODE, &te_link_subtlv_hierarchy_list_clear_cmd);
  install_element (INTERFACE_NODE, &te_link_subtlv_anc_rc_id_cmd);
/** **************** GMPLS ASON Routing ************************************ */
  install_element (INTERFACE_NODE, &te_link_subtlv_band_account_add_cmd);
  install_element (INTERFACE_NODE, &te_link_subtlv_band_account_clear_cmd);
  install_element (INTERFACE_NODE, &te_link_subtlv_ospf_down_aa_id_add_cmd);
  install_element (INTERFACE_NODE, &te_link_subtlv_ospf_down_aa_id_clear_cmd);
  install_element (INTERFACE_NODE, &te_link_subtlv_aa_id_cmd);
/** **************** GMPLS All-optical Extensions ************************** */
  install_element (INTERFACE_NODE, &te_link_subtlv_ber_estimate_cmd);
  install_element (INTERFACE_NODE, &te_link_subtlv_span_length_cmd);
  install_element (INTERFACE_NODE, &te_link_subtlv_osnr_cmd);
  install_element (INTERFACE_NODE, &te_link_subtlv_d_pdm_cmd);
  install_element (INTERFACE_NODE, &te_link_subtlv_amp_list_add_cmd);
  install_element (INTERFACE_NODE, &te_link_subtlv_amp_list_clear_cmd);
  install_element (INTERFACE_NODE, &te_link_subtlv_av_wave_mask_set_cmd);
  install_element (INTERFACE_NODE, &te_link_subtlv_av_wave_mask_add_cmd);
  install_element (INTERFACE_NODE, &te_link_subtlv_av_wave_mask_clear_cmd);
  install_element (INTERFACE_NODE, &te_link_subtlv_te_link_calendar_add_cmd);
  install_element (INTERFACE_NODE, &te_link_subtlv_te_link_calendar_clear_cmd);

/** **************** Geysers Extensions ************************** */
  install_element (INTERFACE_NODE, &te_link_subtlv_power_consumption_cmd);
  install_element (INTERFACE_NODE, &te_link_subtlv_dynamic_replanning_cmd);

  install_element (INTERFACE_NODE, &te_tna_addr_subtlv_tna_addr_ipv4_cmd);
  install_element (INTERFACE_NODE, &te_tna_addr_subtlv_tna_addr_ipv6_cmd);
  install_element (INTERFACE_NODE, &te_tna_addr_subtlv_tna_addr_nsap_cmd);
  install_element (INTERFACE_NODE, &te_tna_addr_subtlv_node_id_add_cmd);
  install_element (INTERFACE_NODE, &te_tna_addr_subtlv_node_id_clear_cmd);

#endif /* GMPLS */
/*
  install_default (OSPF_TE_LINK_NODE);
  install_element (OSPF_TE_LINK_NODE, &te_link_subtlv_link_lcl_rmt_ids_cmd);
  install_element (OSPF_TE_LINK_NODE, &te_link_subtlv_link_protect_type_cmd);
  install_element (OSPF_TE_LINK_NODE, &te_link_subtlv_if_sw_cap_desc_psc_cmd);
  install_element (OSPF_TE_LINK_NODE, &te_link_subtlv_if_sw_cap_desc_tdm_cmd);
  install_element (OSPF_TE_LINK_NODE, &te_link_subtlv_if_sw_cap_desc_lsc_fsc_cmd);
  install_element (OSPF_TE_LINK_NODE, &te_link_subtlv_if_sw_cap_maxLSPbw_cmd);
  install_element (OSPF_TE_LINK_NODE, &te_link_subtlv_shared_risk_link_grp_add_cmd);
  install_element (OSPF_TE_LINK_NODE, &te_link_subtlv_shared_risk_link_grp_clear_cmd); */
  return;
}

#endif /* HAVE_OSPF_TE */
