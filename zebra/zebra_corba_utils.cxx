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
 *  Giacomo Bernini (Nextworks s.r.l.)   <g.bernini_at_nextworks.it>
 */

#include <string>
#include <exception>

#include "zebra.h"
#include "log.h"
#include "prefix.h"

#include "g2mpls_corba_utils.h"

#include "zebra/zebra_corba_utils.h"

void
fill_adv_rsrv_calendar(const gmplsTypes::teLinkCalendarSeq & src,
		       struct zlist *                         dst)
{
	size_t             size;
	calendar_event_t * event;

	list_delete_all_node(dst);

	for (size_t i = 0; i < src.length(); i++) {
		event = (calendar_event_t *) malloc(sizeof(*event));
		if (event == NULL) {
			throw std::runtime_error("Cannot allocate a "
						 "calendar event "
						 "data structure");
		}
		event->time_stamp  = src[i].unixTime;
		for (size_t j = 0; j < MAX_BW_PRIORITIES; j++) {
			event->avail_bw[j] = src[i].availBw[j];
		}
		listnode_add(dst, event);
	}
}

void
fill_lambdas_bitmap(const gmplsTypes::teLinkWdmLambdasBitmap & src,
		    wdm_link_lambdas_bitmap_t &                 dst)
{
	size_t    size;
	uint8_t * mask;

	if (dst.bitmap_word) {
		free(dst.bitmap_word);
	}

	memset(&dst, 0, sizeof(dst));

	dst.base_lambda_label = src.baseLambda;
	dst.num_wavelengths   = src.numLambdas;

	dst.bitmap_size = (src.numLambdas % 32 ?
			   (src.numLambdas / 32) + 1 :
			   src.numLambdas / 32);

	size = (size_t) (dst.bitmap_size * 4);
	dst.bitmap_word = (uint32_t *) malloc(size);
	memset(dst.bitmap_word, 0, size);

	mask = (uint8_t *) dst.bitmap_word;

	for (size_t i = 0; i < src.bitmap.length(); i++) {
		*mask = src.bitmap[i];
		mask++;
	}
}

void telinksdata2if(const gmplsTypes::TELinkData & tel,
		    struct interface *              ifp)
{
	struct zlistnode   *node;
	struct zlistnode   *nnode;
	u_int32_t          *data, *new_data;

	/* Preliminary checks */
	/* TE-link must be IPv4 --- FIX-ME */
	if (tel.localId._d() != gmplsTypes::LINKIDTYPE_IPV4) {
		throw std::runtime_error("TE-link local Id is not IPv4");
	}
	if (tel.remoteId._d() != gmplsTypes::LINKIDTYPE_IPV4) {
		throw std::runtime_error("TE-link remote Id is not IPv4");
	}
		
	ifp->ifindex = tel.parms.telkey;

	/*flags of the interface*/
	ifp->flags  = 4163; //IFF_UP and IFF_RUNNING should be enough
	/*
	 * We explicitly put MTU to maximum 2^16 to avoid pkts frag by ospfd
	 */
	ifp->mtu    = 65536;
	ifp->metric = 1;
	ifp->status = ZEBRA_INTERFACE_ACTIVE;
	struct connected    * ifc  = connected_new();
	struct prefix_ipv4  * p    = prefix_ipv4_new ();
	struct prefix_ipv4 * peer  = prefix_ipv4_new ();

	p->family        = AF_INET;
        zlog_debug("TELink local Id %x", (unsigned int)tel.localId.ipv4());
	p->prefix.s_addr = ntohl(tel.localId.ipv4());	/* local TE link id ipv4 */
	p->prefixlen     = 32;

	ifc->address = (struct prefix *) p;
	ifc->flags   = ZEBRA_IFA_PEER;
	ifc->conf    = ZEBRA_IFC_CONFIGURED;

	peer->family        = AF_INET;
	zlog_debug("TELink remote Id %x", (unsigned int)tel.remoteId.ipv4());
	peer->prefix.s_addr = ntohl(tel.remoteId.ipv4()); /* remote TE Link id ipv4 */
	peer->prefixlen     = 32;
	ifc->destination    = (struct prefix *) peer;
	ifc->ifp            = ifp;

	listnode_add (ifp->connected, ifc);

	/*now we send the te link TE params to ospf*/
    const gmplsTypes::linkHwParameters* linkParams = &tel.parms.hwParms[0];
	adj_type_t       adj;
	sw_cap_t         swcap;
	enc_type_t       enct;
	gmpls_prottype_t prot;
	g2mpls_addr_t    tna;

	zlog_debug("Begin Wrinting TE parameters into interface");
	adj << tel.parms.adj;
	ifp->adj_type = adj;
	//TODO FIXME add command that add interface (with no TE-link) to ospf enni instance
	if (ifp->adj_type == ENNI) {
		ifp->ospf_instance = INNI;
		ifp->rem_rc_id = tel.parms.remRcId;
	} else {
		ifp->ospf_instance = ifp->adj_type;
		ifp->rem_rc_id = 0;
	}
	ifp->te_local_id       = ntohl(tel.localId.ipv4());
	ifp->te_remote_id      = ntohl(tel.remoteId.ipv4());;
	ifp->te_remote_node_id = tel.neighbour;
	ifp->te_metric         = tel.parms.metric;
	ifp->te_link_color     = tel.parms.colorMask;
    swcap << linkParams->swCap;
	ifp->te_swcap          = swcap;
	ifp->te_swcap_options  = 0;;
	enct << linkParams->encType;
	ifp->te_enctype        = enct;

	ifp->te_max_bw         = linkParams->maxBw;
	ifp->te_max_res_bw     = linkParams->maxResBw;

	for (int i = 0; i < MAX_BW_PRIORITIES; i++) {
		ifp->te_avail_bw_per_prio[i] = linkParams->availBw[i];
		ifp->te_max_LSP_bw[i]        = linkParams->maxLspBw[i];
	}
	ifp->te_min_LSP_bw      = linkParams->minLspBw;
	prot << linkParams->prot;
	ifp->te_protection_type = (u_int8_t) prot;

	/*copy the advance reservation calendar of events*/
	fill_adv_rsrv_calendar(linkParams->calendar,
			       ifp->adv_rsrv_calendar);

	/*copy the lambdas bitmap*/
	if (ifp->te_swcap == SWCAP_LSC) {
		fill_lambdas_bitmap(linkParams->lambdasBit,
				    ifp->lambdas_bitmap);
	}
     /* Geysers types */
    ifp->te_energy_consumption = linkParams->powerConsumption;
    zlog_debug("TElink power consumption is %d", linkParams->powerConsumption);
    if (linkParams->vlinkBwReplanning.length() > 0) {
	zlog_debug("TElink Bandwidth replanning: upgrade=%d, downgrade=%d", 
	            (uint32_t)linkParams->vlinkBwReplanning[0].maxBwUpgrade,
	            (uint32_t)linkParams->vlinkBwReplanning[0].maxBwDowngrade);
        ifp->te_max_bw_upgrade = linkParams->vlinkBwReplanning[0].maxBwUpgrade;
        ifp->te_max_bw_downgrade = linkParams->vlinkBwReplanning[0].maxBwDowngrade;
    }
    else {
        ifp->te_max_bw_upgrade = 0;
        ifp->te_max_bw_downgrade = 0;
    }
    /* end of Geysers types */

	/*create the new srgl ids list*/
	if (ifp->te_SRLG_ids != NULL) {
		list_delete_all_node(ifp->te_SRLG_ids);
	} else {
		ifp->te_SRLG_ids = list_new();
		//ifp->te_SRLG_ids->del = del_te_SRLG_id;
	}

	for (int j = 0; j < tel.parms.srlg.length(); j++) {
		new_data = (uint32_t *)malloc(sizeof(uint32_t));
		*new_data = tel.parms.srlg[j];
		listnode_add(ifp->te_SRLG_ids, new_data);
	}

	/* zeroing */
	ifp->te_TNA_address_type  = IPv4;
	ifp->te_TNA_prefix_length = 0;
	ifp->te_TNA_address = (u_int32_t *) malloc(4);
	memset(ifp->te_TNA_address, 0, 4);

	gmplsTypes::tnaId_var tnaTmp;
	tnaTmp = tel.parms.tna;

	tna << tnaTmp;

	if ( ifp->adj_type == UNI  ||
	     (ifp->adj_type == ENNI && !is_addr_null(tna))) {
		ifp->te_TNA_address_type  = tna.type;
		ifp->te_TNA_prefix_length = 32;
		switch (ifp->te_TNA_address_type) {
			case IPv4:
				ifp->te_TNA_address = (u_int32_t *) malloc(4);
				memcpy(ifp->te_TNA_address , &tna.value.ipv4, 4);
				break;
			case IPv6:
				ifp->te_TNA_address = (u_int32_t *) malloc(16);
				memcpy(ifp->te_TNA_address , &tna.value.ipv6, 16);
				break;
			case NSAP:
				ifp->te_TNA_address = (u_int32_t *) malloc(20);
				memcpy(ifp->te_TNA_address , &tna.value.nsap, 20);
				break;
			default:
				throw std::runtime_error("Bad TNA type");
		}
	}
	zlog_debug("End Wrinting TE parameters into interface");
	/*END of TE-link parameters*/
}

