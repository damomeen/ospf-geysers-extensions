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
#include <stdexcept>

#include "zebra.h"
#include "log.h"
#include "if.h"
#include "prefix.h"
#include "memory.h"

#include "lib/corba.h"
#include "g2mpls_corba_utils.h"

#include "zebra/zserv.h"
#include "zebra/zebra_corba_servant.h"
#include "zebra/zebra_corba_utils.h"

extern struct zebra_t zebrad;

ZEBRA_i::ZEBRA_i()
{
}

ZEBRA_i::~ZEBRA_i()
{
}

void
ZEBRA_i::add(Types::uint32                  telKey,
	     const gmplsTypes::TELinkData& telData)
{
	try {
		struct interface *             ifp;
		struct zlistnode             * cnode, * clnode, *cnnode, *clnnode;
		struct connected             * c;
		struct zserv                 * client;
		void                         * data, * datal;
		uint32_t                       key;
		char                           t_name[7];

		zlog_debug("Received TE-link add from LRM");

		/* Check OSPF is registered */
		if (list_isempty(zebrad.client_list)) {
			zlog_err("OSPF not yet registered. Cannot add TE-link");
			throw std::runtime_error("OSPF not registered");
		}

		/* Create fake interface */
		key = telData.parms.telkey;
		sprintf(t_name, "tel%d", key);
		ifp = if_create(t_name, strlen(t_name));

		zlog_debug("\n\n\n LOC TEL %x \n\n\n", (uint32_t) telData.localId.ipv4());
		zlog_debug("\n\n\n REM TEL %x \n\n\n", (uint32_t) telData.remoteId.ipv4());
		
		telinksdata2if(telData, ifp);

		zlog_debug("Going to send TE-link to OSPF");

		/* Retrieve OSPF client structure */
		for (ALL_LIST_ELEMENTS(zebrad.client_list, clnode, clnnode, datal)) {
			client = (struct zserv*) datal;
			if (zsend_interface_add (client, ifp) < 0) {
				zlog_err("Cannot send ZEBRA_INTERFACE_ADD"
					 "to OSPF");
				throw std::runtime_error("zclient/zserv error");
			}
			for (ALL_LIST_ELEMENTS(ifp->connected, cnode,
					       cnnode, data)) {
				c = (struct connected *) data;
				zsend_interface_address(ZEBRA_INTERFACE_ADDRESS_ADD,
							client,
							ifp,
							c);
			}
		}

		/* Delete fake interface */
		list_delete (ifp->connected);
		XFREE (MTYPE_IF, ifp);
		ifp = 0;

	} catch (std::runtime_error & e) {
		zlog_err("Cannot add Te-link from LRM: %s", e.what());
		throw ZEBRA::TeLink::InternalProblems();
	} catch (std::out_of_range & e) {
		zlog_err("Cannot add Te-link from LRM: %s", e.what());
		throw ZEBRA::TeLink::InternalProblems();
	} catch (...) {
		zlog_err("Cannot add Te-link from LRM: unknwon reason");
		throw ZEBRA::TeLink::InternalProblems();
	}
}

void
ZEBRA_i::del(Types::uint32 telKey)
{
	try {
		struct interface *             ifp;
		struct zlistnode             * clnode, *clnnode;
		struct zserv                 * client;
		void                         * datal;
		uint32_t                       key;
		char                           t_name[7];

		zlog_debug("Received TE-link delete from LRM");

		/* Check OSPF is registered */
		if (list_isempty(zebrad.client_list)) {
			zlog_err("OSPF not yet registered. Cannot delete TE-link");
			throw std::runtime_error("OSPF not registered");
		}

		/* Create fake interface */
		key = telKey;
		sprintf(t_name, "tel%d", key);
		ifp = if_create(t_name, strlen(t_name));

		ifp->ifindex   = key;
		ifp->flags     = 4163; //IFF_UP and IFF_RUNNING should be enough
		ifp->mtu       = 65536;
		ifp->mtu6      = 65536;
		ifp->metric    = 1;
		ifp->status    = ZEBRA_INTERFACE_ACTIVE;
		ifp->bandwidth = 0;

		zlog_debug("Going to send TE-link delete to OSPF");

		/* Retrieve OSPF client structure */
		for (ALL_LIST_ELEMENTS(zebrad.client_list, clnode, clnnode, datal)) {
			client = (struct zserv*) datal;
			if (zsend_interface_delete(client, ifp) < 0) {
				zlog_err("Cannot send ZEBRA_INTERFACE_DELETE"
					 "to OSPF");
				throw std::runtime_error("zclient/zserv error");
			}
		}
		/* Delete fake interface */
		list_delete (ifp->connected);
		XFREE (MTYPE_IF, ifp);
		ifp = 0;

	} catch (std::runtime_error & e) {
		zlog_err("Cannot delete Te-link from LRM: %s", e.what());
		throw ZEBRA::TeLink::InternalProblems();
	} catch (std::out_of_range & e) {
		zlog_err("Cannot delete Te-link from LRM: %s", e.what());
		throw ZEBRA::TeLink::InternalProblems();
	} catch (...) {
		zlog_err("Cannot delete Te-link from LRM: unknwon reason");
		throw ZEBRA::TeLink::InternalProblems();
	}
}

void
ZEBRA_i::updateMetric(Types::uint32 telKey,
		      Types::uint32 metric)
{
	try {
		struct interface *             ifp;
		struct zlistnode             * clnode, *clnnode;
		struct zserv                 * client;
		void                         * datal;
		uint32_t                       key;
		uint32_t                       tem;
		char                           t_name[7];

		zlog_debug("Received TE-link updateMetric from LRM");

		/* Check OSPF is registered */
		if (list_isempty(zebrad.client_list)) {
			zlog_err("OSPF not yet registered. Cannot update TE-link");
			throw std::runtime_error("OSPF not registered");
		}

		/* Create fake interface */
		key = telKey;
		tem = metric;
		sprintf(t_name, "tel%d", key);
		ifp = if_create(t_name, strlen(t_name));

		ifp->te_metric = tem;

		zlog_debug("Going to send TE-link update to OSPF");

		/* Retrieve OSPF client structure */
		for (ALL_LIST_ELEMENTS(zebrad.client_list, clnode, clnnode, datal)) {
			client = (struct zserv*) datal;
			if (zsend_te_interface_update(client, ifp, METRIC_UPDATE) < 0) {
				zlog_err("Cannot send ZEBRA_INTERFACE_UPDATE"
					 "to OSPF");
				throw std::runtime_error("zclient/zserv error");
			}
		}
		/* Delete fake interface */
		list_delete (ifp->connected);
		XFREE (MTYPE_IF, ifp);
		ifp = 0;

	} catch (std::runtime_error & e) {
		zlog_err("Cannot update Te-link from LRM: %s", e.what());
		throw ZEBRA::TeLink::InternalProblems();
	} catch (std::out_of_range & e) {
		zlog_err("Cannot update Te-link from LRM: %s", e.what());
		throw ZEBRA::TeLink::InternalProblems();
	} catch (...) {
		zlog_err("Cannot update Te-link from LRM: unknwon reason");
		throw ZEBRA::TeLink::InternalProblems();
	}

}

void
ZEBRA_i::updateColor(Types::uint32 telKey,
		     Types::uint32 colorMask)
{
	try {
		struct interface *             ifp;
		struct zlistnode             * clnode, *clnnode;
		struct zserv                 * client;
		void                         * datal;
		uint32_t                       key;
		uint32_t                       color;
		char                           t_name[7];

		zlog_debug("Received TE-link updateColor from LRM");

		/* Check OSPF is registered */
		if (list_isempty(zebrad.client_list)) {
			zlog_err("OSPF not yet registered. Cannot update TE-link");
			throw std::runtime_error("OSPF not registered");
		}

		/* Create fake interface */
		key = telKey;
		color = colorMask;
		sprintf(t_name, "tel%d", key);
		ifp = if_create(t_name, strlen(t_name));

		ifp->te_link_color = color;

		zlog_debug("Going to send TE-link update to OSPF");

		/* Retrieve OSPF client structure */
		for (ALL_LIST_ELEMENTS(zebrad.client_list, clnode, clnnode, datal)) {
			client = (struct zserv*) datal;
			if (zsend_te_interface_update(client, ifp, LINK_CLR_UPDATE) < 0) {
				zlog_err("Cannot send ZEBRA_INTERFACE_UPDATE"
					 "to OSPF");
				throw std::runtime_error("zclient/zserv error");
			}
		}
		/* Delete fake interface */
		list_delete (ifp->connected);
		XFREE (MTYPE_IF, ifp);
		ifp = 0;

	} catch (std::runtime_error & e) {
		zlog_err("Cannot update Te-link from LRM: %s", e.what());
		throw ZEBRA::TeLink::InternalProblems();
	} catch (std::out_of_range & e) {
		zlog_err("Cannot update Te-link from LRM: %s", e.what());
		throw ZEBRA::TeLink::InternalProblems();
	} catch (...) {
		zlog_err("Cannot update Te-link from LRM: unknwon reason");
		throw ZEBRA::TeLink::InternalProblems();
	}

}

void
ZEBRA_i::updateBw(Types::uint32                              telKey,
		  const gmplsTypes::bwPerPrio                availBw,
		  const gmplsTypes::bwPerPrio                maxLspBw,
		  const gmplsTypes::teLinkCalendarSeq&       calendar,
		  const gmplsTypes::teLinkWdmLambdasBitmap&  lambdaBit)
{
	try {
		struct interface *             ifp;
		struct zlistnode             * clnode, *clnnode;
		struct zserv                 * client;
		void                         * datal;
		uint32_t                       key;
		sw_cap_t                       swcap;
		char                           t_name[7];

		zlog_debug("Received TE-link updateBw from LRM");

		/* Check OSPF is registered */
		if (list_isempty(zebrad.client_list)) {
			zlog_err("OSPF not yet registered. Cannot update TE-link");
			throw std::runtime_error("OSPF not registered");
		}

		/* Create fake interface */
		key = telKey;
		sprintf(t_name, "tel%d", key);
		ifp = if_create(t_name, strlen(t_name));

		for (int i = 0; i < MAX_BW_PRIORITIES; i++) {
			ifp->te_avail_bw_per_prio[i] = availBw[i];
			ifp->te_max_LSP_bw[i]        = maxLspBw[i];
		}

		/*copy the advance reservation calendar of events*/
		fill_adv_rsrv_calendar(calendar,
				       ifp->adv_rsrv_calendar);

		/*copy the lambdas bitmap*/
		if (lambdaBit.bitmap.length() > 0) {
			ifp->te_swcap = SWCAP_LSC; //hard-coded to let the bitmap be read by OSPF
			fill_lambdas_bitmap(lambdaBit,
					    ifp->lambdas_bitmap);
		}

		zlog_debug("Going to send TE-link update to OSPF");

		/* Retrieve OSPF client structure */
		for (ALL_LIST_ELEMENTS(zebrad.client_list, clnode, clnnode, datal)) {
			client = (struct zserv*) datal;
			if (zsend_te_interface_update(client, ifp, BW_UPDATE) < 0) {
				zlog_err("Cannot send ZEBRA_INTERFACE_UPDATE"
					 "to OSPF");
				throw std::runtime_error("zclient/zserv error");
			}
		}
		/* Delete fake interface */
		list_delete (ifp->connected);
		XFREE (MTYPE_IF, ifp);
		ifp = 0;

	} catch (std::runtime_error & e) {
		zlog_err("Cannot update Te-link from LRM: %s", e.what());
		throw ZEBRA::TeLink::InternalProblems();
	} catch (std::out_of_range & e) {
		zlog_err("Cannot update Te-link from LRM: %s", e.what());
		throw ZEBRA::TeLink::InternalProblems();
	} catch (...) {
		zlog_err("Cannot update Te-link from LRM: unknwon reason");
		throw ZEBRA::TeLink::InternalProblems();
	}

}

void
ZEBRA_i::updateDJPL(Types::uint32                   telKey,
			Types::uint32                           avgDelay,
			Types::uint32                           maxDelay,
			Types::uint32                           avgJitter,
			Types::uint32                           avgPktLoss,
			Types::uint32                           maxPktLoss)
{
}

void
ZEBRA_i::updateSrlg(Types::uint32               telKey,
		    const gmplsTypes::srlgSeq&  srlg)
{
	try {
		struct interface *             ifp;
		struct zlistnode             * clnode, *clnnode;
		struct zserv                 * client;
		void                         * datal;
		uint32_t                       key;
		uint32_t *                     new_data;
		char                           t_name[7];

		zlog_debug("Received TE-link updateSrlg from LRM");

		/* Check OSPF is registered */
		if (list_isempty(zebrad.client_list)) {
			zlog_err("OSPF not yet registered. Cannot update TE-link");
			throw std::runtime_error("OSPF not registered");
		}

		/* Create fake interface */
		key = telKey;
		sprintf(t_name, "tel%d", key);
		ifp = if_create(t_name, strlen(t_name));

		if (ifp->te_SRLG_ids != NULL) {
			list_delete_all_node(ifp->te_SRLG_ids);
		} else {
			ifp->te_SRLG_ids = list_new();
			//ifp->te_SRLG_ids->del = del_te_SRLG_id;
		}

		for (int j = 0; j < srlg.length(); j++) {
			new_data = (uint32_t *)malloc(sizeof(uint32_t));
			*new_data = srlg[j];
			listnode_add(ifp->te_SRLG_ids, new_data);
		}

		zlog_debug("Going to send TE-link update to OSPF");

		/* Retrieve OSPF client structure */
		for (ALL_LIST_ELEMENTS(zebrad.client_list, clnode, clnnode, datal)) {
			client = (struct zserv*) datal;
			if (zsend_te_interface_update(client, ifp, SRLGid_UPDATE) < 0) {
				zlog_err("Cannot send ZEBRA_INTERFACE_UPDATE"
					 "to OSPF");
				throw std::runtime_error("zclient/zserv error");
			}
		}
		/* Delete fake interface */
		list_delete (ifp->connected);
		XFREE (MTYPE_IF, ifp);
		ifp = 0;

	} catch (std::runtime_error & e) {
		zlog_err("Cannot update Te-link from LRM: %s", e.what());
		throw ZEBRA::TeLink::InternalProblems();
	} catch (std::out_of_range & e) {
		zlog_err("Cannot update Te-link from LRM: %s", e.what());
		throw ZEBRA::TeLink::InternalProblems();
	} catch (...) {
		zlog_err("Cannot update Te-link from LRM: unknwon reason");
		throw ZEBRA::TeLink::InternalProblems();
	}
}

void
ZEBRA_i::updateTna(Types::uint32             telKey,
		   const gmplsTypes::tnaId&  tnaId)
{
	try {
		struct interface *             ifp;
		struct zlistnode             * clnode, *clnnode;
		struct zserv                 * client;
		void                         * datal;
		uint32_t                       key;
		g2mpls_addr_t                  tna;
		gmplsTypes::tnaId_var         tnaTmp;
		char                           t_name[7];

		zlog_debug("Received TE-link updateMteric from LRM");

		/* Check OSPF is registered */
		if (list_isempty(zebrad.client_list)) {
			zlog_err("OSPF not yet registered. Cannot update TE-link");
			throw std::runtime_error("OSPF not registered");
		}

		/* Create fake interface */
		key = telKey;
		sprintf(t_name, "tel%d", key);
		ifp = if_create(t_name, strlen(t_name));

		/* zeroing */
		ifp->te_TNA_address_type  = IPv4;
		ifp->te_TNA_prefix_length = 0;
		ifp->te_TNA_address = (u_int32_t *) malloc(4);
		memset(ifp->te_TNA_address, 0, 4);

		tnaTmp = tnaId;
		tna << tnaTmp;

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

		zlog_debug("Going to send TE-link update to OSPF");

		/* Retrieve OSPF client structure */
		for (ALL_LIST_ELEMENTS(zebrad.client_list, clnode, clnnode, datal)) {
			client = (struct zserv*) datal;
			if (zsend_te_interface_update(client, ifp, TNA_UPDATE) < 0) {
				zlog_err("Cannot send ZEBRA_INTERFACE_UPDATE"
					 "to OSPF");
				throw std::runtime_error("zclient/zserv error");
			}
		}
		/* Delete fake interface */
		list_delete (ifp->connected);
		XFREE (MTYPE_IF, ifp);
		ifp = 0;

	} catch (std::runtime_error & e) {
		zlog_err("Cannot update Te-link from LRM: %s", e.what());
		throw ZEBRA::TeLink::InternalProblems();
	} catch (std::out_of_range & e) {
		zlog_err("Cannot update Te-link from LRM: %s", e.what());
		throw ZEBRA::TeLink::InternalProblems();
	} catch (...) {
		zlog_err("Cannot update Te-link from LRM: unknwon reason");
		throw ZEBRA::TeLink::InternalProblems();
	}

}

void
ZEBRA_i::updateProtection(Types::uint32         telKey,
			  gmplsTypes::protType  prot)
{
	try {
		struct interface *             ifp;
		struct zlistnode             * clnode, *clnnode;
		struct zserv                 * client;
		void                         * datal;
		uint32_t                       key;
		gmpls_prottype_t               protection;
		char                           t_name[7];

		zlog_debug("Received TE-link updateMteric from LRM");

		/* Check OSPF is registered */
		if (list_isempty(zebrad.client_list)) {
			zlog_err("OSPF not yet registered. Cannot update TE-link");
			throw std::runtime_error("OSPF not registered");
		}

		/* Create fake interface */
		key = telKey;
		sprintf(t_name, "tel%d", key);
		ifp = if_create(t_name, strlen(t_name));

		protection << prot;
		ifp->te_protection_type = (u_int8_t) protection;

		zlog_debug("Going to send TE-link update to OSPF");

		/* Retrieve OSPF client structure */
		for (ALL_LIST_ELEMENTS(zebrad.client_list, clnode, clnnode, datal)) {
			client = (struct zserv*) datal;
			if (zsend_te_interface_update(client, ifp, PROTECTION_UPDATE) < 0) {
				zlog_err("Cannot send ZEBRA_INTERFACE_UPDATE"
					 "to OSPF");
				throw std::runtime_error("zclient/zserv error");
			}
		}
		/* Delete fake interface */
		list_delete (ifp->connected);
		XFREE (MTYPE_IF, ifp);
		ifp = 0;

	} catch (std::runtime_error & e) {
		zlog_err("Cannot update Te-link from LRM: %s", e.what());
		throw ZEBRA::TeLink::InternalProblems();
	} catch (std::out_of_range & e) {
		zlog_err("Cannot update Te-link from LRM: %s", e.what());
		throw ZEBRA::TeLink::InternalProblems();
	} catch (...) {
		zlog_err("Cannot update Te-link from LRM: unknwon reason");
		throw ZEBRA::TeLink::InternalProblems();
	}
}

void
ZEBRA_i::updatePower(Types::uint32         telKey,
		     gmplsTypes::powerType  powerConsumption)
{
    try {
	    struct interface *             ifp;
	    struct zlistnode             * clnode, *clnnode;
	    struct zserv                 * client;
	    void                         * datal;
	    uint32_t                       key;
	    char                           t_name[7];

	    zlog_debug("Received TE-link updatePower from LRM");

	    /* Check OSPF is registered */
	    if (list_isempty(zebrad.client_list)) {
		    zlog_err("OSPF not yet registered. Cannot update TE-link");
		    throw std::runtime_error("OSPF not registered");
	    }

	    /* Create fake interface */
	    key = telKey;
	    sprintf(t_name, "tel%d", key);
	    ifp = if_create(t_name, strlen(t_name));

	    ifp->te_energy_consumption = powerConsumption;

	    zlog_debug("Going to send TE-link update to OSPF");

	    /* Retrieve OSPF client structure */
	    for (ALL_LIST_ELEMENTS(zebrad.client_list, clnode, clnnode, datal)) {
		    client = (struct zserv*) datal;
		    if (zsend_te_interface_update(client, ifp, ENERGY_UPDATE) < 0) {
			    zlog_err("Cannot send ZEBRA_INTERFACE_UPDATE"
				     "to OSPF");
			    throw std::runtime_error("zclient/zserv error");
		    }
	    }
	    /* Delete fake interface */
	    list_delete (ifp->connected);
	    XFREE (MTYPE_IF, ifp);
	    ifp = 0;

    } catch (std::runtime_error & e) {
	    zlog_err("Cannot update Te-link from LRM: %s", e.what());
	    throw ZEBRA::TeLink::InternalProblems();
    } catch (std::out_of_range & e) {
	    zlog_err("Cannot update Te-link from LRM: %s", e.what());
	    throw ZEBRA::TeLink::InternalProblems();
    } catch (...) {
	    zlog_err("Cannot update Te-link from LRM: unknwon reason");
	    throw ZEBRA::TeLink::InternalProblems();
    }
}

void
ZEBRA_i::updateReplanningInfo(Types::uint32         telKey,
			  const gmplsTypes::vlinkBwReplanInfo&       replanInfo)
{
    try {
		struct interface *             ifp;
		struct zlistnode             * clnode, *clnnode;
		struct zserv                 * client;
		void                         * datal;
		uint32_t                       key;
		char                           t_name[7];

		zlog_debug("Received TE-link updateReplanningInfo from LRM downgrade: %d, upgrade: %d", 
						replanInfo.maxBwDowngrade, replanInfo.maxBwUpgrade);

		/* Check OSPF is registered */
		if (list_isempty(zebrad.client_list)) {
			zlog_err("OSPF not yet registered. Cannot update TE-link");
			throw std::runtime_error("OSPF not registered");
		}

		/* Create fake interface */
		key = telKey;
		sprintf(t_name, "tel%d", key);
		ifp = if_create(t_name, strlen(t_name));

		ifp->te_max_bw_upgrade = replanInfo.maxBwUpgrade;
		ifp->te_max_bw_downgrade = replanInfo.maxBwDowngrade;

		zlog_debug("Going to send TE-link update to OSPF");

		/* Retrieve OSPF client structure */
		for (ALL_LIST_ELEMENTS(zebrad.client_list, clnode, clnnode, datal)) {
			client = (struct zserv*) datal;
			if (zsend_te_interface_update(client, ifp, BW_REPLANNING_UPDATE) < 0) {
				zlog_err("Cannot send ZEBRA_INTERFACE_UPDATE"
					 "to OSPF");
				throw std::runtime_error("zclient/zserv error");
			}
		}
		/* Delete fake interface */
		list_delete (ifp->connected);
		XFREE (MTYPE_IF, ifp);
		ifp = 0;

	} catch (std::runtime_error & e) {
		zlog_err("Cannot update Te-link from LRM: %s", e.what());
		throw ZEBRA::TeLink::InternalProblems();
	} catch (std::out_of_range & e) {
		zlog_err("Cannot update Te-link from LRM: %s", e.what());
		throw ZEBRA::TeLink::InternalProblems();
	} catch (...) {
		zlog_err("Cannot update Te-link from LRM: unknwon reason");
		throw ZEBRA::TeLink::InternalProblems();
	}
}


ZEBRA_Node_i::ZEBRA_Node_i()
{
}

ZEBRA_Node_i::~ZEBRA_Node_i()
{
}

void
ZEBRA_Node_i::update(Types::uint32        ridKey,
                     const gmplsTypes::nodeData& data)
{
	try {
        //TODO
	} catch (std::runtime_error & e) {
		zlog_err("Cannot update Node from LRM: %s", e.what());
		throw ZEBRA::Node::InternalProblems();
	} catch (std::out_of_range & e) {
		zlog_err("Cannot update Node from LRM: %s", e.what());
		throw ZEBRA::Node::InternalProblems();
	} catch (...) {
		zlog_err("Cannot update Node from LRM: unknwon reason");
		throw ZEBRA::Node::InternalProblems();
	}
}

