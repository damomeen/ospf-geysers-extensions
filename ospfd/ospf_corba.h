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


#ifndef _OSPF_CORBA_H_
#define _OSPF_CORBA_H_

#include <zebra.h>

#ifdef GMPLS_NXW
#include "ospfd/ospf_scngw.h"
#endif

#if HAVE_OMNIORB

typedef enum {
  NTYPE_UNKNOWN,
  NTYPE_NETWORK,
} node_type_t;

typedef enum {
  LINKT_UNKNOWN,
  LINKT_TE,
  LINKT_TE_SDHSONET,
  LINKT_TE_G709,
  LINKT_TE_WDM
} link_type_t;

typedef enum {
  LINKM_UNKNOWN         ,
  LINKM_P2P_UNNUMBERED  ,
  LINKM_P2P_NUMBERED    ,
  LINKM_MULTIACCESS     ,
  LINKM_ENNI_INTERDOMAIN,
  LINKM_ENNI_INTRADOMAIN
} link_mode_t;

typedef struct te_link_if_sw_cap
{
  u_char       switching_cap;     /** Switching Capability */
  u_char       encoding;          /** Encoding */
  float        maxLSPbw[8];       /** Max LSP Bandwidth */

  float        min_lsp_bw;        /** Minimul LSP Bandwidth (TDM & PSC) */
  u_char       indication;        /** Indication            (TDM)       */
  uint16_t     mtu;               /** Interface MTU         (PSC)       */
} te_link_if_sw_cap_t;

#ifdef __cplusplus
extern "C" {
#endif

int corba_g2pcera_client_setup(void);
int corba_gunigw_client_setup(void);
#ifdef GMPLS_NXW
int corba_scngw_client_setup(void);

/***** Corba SCNGW  *****/
int scngw_registration                           (client_type_t cl_type);
#endif

/***** Corba update NODES *****/
void node_add                                    (uint8_t server,
                                                  int id,
                                                  node_type_t type);
void node_del                                    (uint8_t server,
                                                  uint32_t id,
                                                  node_type_t type);
void update_net_node                             (int id,
                                                  uint8_t isDomain);

/***** Corba update TE LINK *****/
void init_link_tmp_values                        (void);
void init_link_ident                             (void);

typedef enum {
  INTERDOM_TEL,
  INTRADOM_TEL
} telink_type_t;

void set_link_ident                              (telink_type_t type);

uint8_t link_update                              (uint8_t option, telink_type_t type);
void link_update_com                             (void);
void link_update_tdm                             (void);
void link_update_lscG709                         (void);
void link_update_lscwdm                          (void);
void link_update_states                          (void);
void link_update_genbw                           (void);
void link_update_tdmbw                           (void);
void link_update_lscwdm_bw                       (void);
void link_update_power_consumption               (void);
void link_update_dynamic_replanning              (void);

void corba_update_advertising_router             (struct in_addr value);
void corba_update_te_link_type                   (uint8_t type);
void corba_update_te_link_id                     (struct in_addr id);
void corba_update_te_link_lclif_ipaddr           (struct in_addr value);
void corba_update_te_link_rmtif_ipaddr           (struct in_addr value);
void corba_update_te_link_metric                 (uint32_t teMetric);
void corba_update_te_link_max_bw                 (float teMaxBw);
void corba_update_te_link_max_res_bw             (float teMaxResvBw);
void corba_update_te_link_unrsv_bw               (float avBand[]);
void corba_update_te_link_rsc_clsclr             (uint32_t teColorMask);
void corba_update_te_link_lcl_rmt_ids            (uint32_t localId,
                                                  uint32_t remoteId);
void corba_update_te_link_protect_type           (uint8_t teProtectionTypeMask);
void corba_update_te_link_if_sw_cap_desc_pscisc  (uint8_t switching_cap,
                                                  uint8_t encoding,
                                                  float maxLSPbw[],
                                                  float minLSPbw,
                                                  uint16_t interfaceMTU);
void corba_update_te_link_if_sw_cap_desc_tdmisc  (uint8_t switching_cap,
                                                  uint8_t encoding,
                                                  float maxLSPbw[],
                                                  float minLSPbw,
                                                  uint8_t indication);
void corba_update_te_link_if_sw_cap_desc_genisc  (uint8_t switching_cap,
                                                  uint8_t encoding,
                                                  float maxLSPbw[]);
void corba_update_te_link_if_sw_cap_desc         (void);
void init_grid_TELink_Iscs                       (void);
void corba_update_te_link_shared_risk_link_grp   (uint32_t *srlg,
                                                  uint16_t len);
void corba_update_te_link_srlg                   (void);
void corba_update_te_link_lcl_node_id            (struct in_addr localNodeId);
void corba_update_te_link_rmt_node_id            (struct in_addr remoteNodeId);
void corba_update_te_link_ssdh_if_sw_cap_desc    (struct zlist* freeTS);
void corba_update_te_link_anc_rc_id              (struct in_addr value);
void corba_update_te_link_band_account           (uint32_t *band_account,
                                                  uint32_t list_len);
void corba_update_te_link_span_length            (uint32_t spanLength);
void corba_update_te_link_d_pdm                  (uint32_t dispersionPMD);
void corba_update_te_link_amp_list               (struct amp_par *amplist,
                                                  uint16_t len);
void corba_update_te_link_av_wave_mask           (u_int16_t num_wavelengths,
                                                  u_int32_t label_set_desc,
                                                  uint32_t *bitmap,
                                                  uint16_t bitmap_len);
void corba_update_te_link_callendar              (struct te_link_calendar *te_calendar,
                                                  uint16_t te_calendar_len);
void corba_update_te_link_tecal                  (void);

/* Geysers */
void corba_update_te_link_energy_consumption      (float energyConsumption);
void corba_update_te_link_bwReplanning            (float maxBwUpgrade, float maxBwDowngrade);
/* end of Geysers */

/***** Corba update TE TNA *****/
void init_tna_ident                              (void);
void corba_update_te_tna_addr                    (g2mpls_addr_t tna);
void corba_update_te_tna_node                    (struct in_addr node_id);
void corba_update_te_tna_id                      (int server,
                                                  uint8_t option,
                                                  g2mpls_addr_t tna_addr);
void corba_update_te_tna_anc_rc_id               (struct in_addr value);
void tna_ids_update                              (uint8_t option);

/***** Corba update TE NA *****/
void corba_update_te_na_router_id                (uint32_t router_id);
void corba_update_te_na_aa_id                    (uint32_t area_id);
void corba_update_te_na_ipv4_lcl_pref            (struct prefix_ip4 *pref_list,
                                                  uint16_t list_len);
void corba_update_te_na_ipv6_lcl_pref            (struct prefix_ip6 *pref_list,
                                                  uint16_t list_len);

/***** Corba update TE RA *****/
void corba_update_te_ra_router_addr              (struct in_addr address);
void corba_update_te_ra_aa_id                    (uint32_t area_id);
void corba_update_te_ra_router_energy_consumption(float energyConsum);

#ifdef __cplusplus
}
#endif

#endif // HAVE_OMNIORB

#endif // _OSPF_CORBA_H_
