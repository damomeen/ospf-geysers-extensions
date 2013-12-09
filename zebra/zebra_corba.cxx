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
#include "if.h"
#include "memory.h"

#include "lib/corba.h"
#include "g2mpls_types.h"
#include "g2mpls_corba_utils.h"

#include "zebra/zserv.h"
#include "zebra/zebra_corba.h"
#include "zebra/zebra_corba_servant.h"
#include "zebra/zebra_corba_utils.h"

#include "lrm.hh"
#include "zebra.hh"

LRM::TeLink_var lrm_tel_proxy;
LRM::Global_var lrm_glob_proxy;

extern "C" {

	int corba_server_setup(void)
	{
		zlog_debug("Setting up ZEBRA_TELINK CORBA server side");

		try {
			ZEBRA_i * servant;

			servant = new ZEBRA_i();
			if (!servant) {
				zlog_err("Cannot create servant");
				return 0;
			}

			PortableServer::POA_var poa;
			poa = corba_poa();
			if (CORBA::is_nil(poa)) {
				zlog_err("Cannot get POA");
				return 0;
			}

			PortableServer::ObjectId_var servant_id;
			servant_id = poa->activate_object(servant);

			CORBA::Object_var obj;
			obj = servant->_this();
			if (CORBA::is_nil(obj)) {
				zlog_err("Cannot get object");
				return 0;
			}

			CORBA::ORB_var orb;
			orb = corba_orb();
			if (CORBA::is_nil(orb)) {
				zlog_err("Cannot get ORB");
				return 0;
			}

			CORBA::String_var sior(orb->object_to_string(obj));

			if (!corba_dump_ior(CORBA_SERVANT_ZEBRA_TELINK,
					    std::string(sior))) {
				zlog_err("Cannot dump IOR");
				return 0;
			}

			servant->_remove_ref();

			PortableServer::POAManager_var poa_manager;
			poa_manager = corba_poa_manager();
			if (CORBA::is_nil(poa_manager)) {
				zlog_err("Cannot get POA Manager");
				return 0;
			}

			poa_manager->activate();
		} catch (CORBA::SystemException & e) {
			zlog_err("Caught CORBA::SystemException");
			return 0;
		} catch (CORBA::Exception & e) {
			zlog_err("Caught CORBA::Exception");
			return 0;
		} catch (omniORB::fatalException & e) {
			zlog_err("Caught omniORB::fatalException:");
			zlog_err("  file: %s", e.file());
			zlog_err("  line: %d", e.line());
			zlog_err("  mesg: %s", e.errmsg());
			return 0;
		} catch (...) {
			zlog_err("Caught unknown exception");
			return 0;
		}

		return 1;
	}

	int corba_node_server_setup(void)
	{
		zlog_debug("Setting up ZEBRA_NODE CORBA server side");

		try {
			ZEBRA_Node_i * servant;

			servant = new ZEBRA_Node_i();
			if (!servant) {
				zlog_err("Cannot create servant");
				return 0;
			}

			PortableServer::POA_var poa;
			poa = corba_poa();
			if (CORBA::is_nil(poa)) {
				zlog_err("Cannot get POA");
				return 0;
			}

			PortableServer::ObjectId_var servant_id;
			servant_id = poa->activate_object(servant);

			CORBA::Object_var obj;
			obj = servant->_this();
			if (CORBA::is_nil(obj)) {
				zlog_err("Cannot get object");
				return 0;
			}

			CORBA::ORB_var orb;
			orb = corba_orb();
			if (CORBA::is_nil(orb)) {
				zlog_err("Cannot get ORB");
				return 0;
			}

			CORBA::String_var sior(orb->object_to_string(obj));

			if (!corba_dump_ior(CORBA_SERVANT_ZEBRA_NODE,
					    std::string(sior))) {
				zlog_err("Cannot dump IOR");
				return 0;
			}

			servant->_remove_ref();

			PortableServer::POAManager_var poa_manager;
			poa_manager = corba_poa_manager();
			if (CORBA::is_nil(poa_manager)) {
				zlog_err("Cannot get POA Manager");
				return 0;
			}

			poa_manager->activate();
		} catch (CORBA::SystemException & e) {
			zlog_err("Caught CORBA::SystemException");
			return 0;
		} catch (CORBA::Exception & e) {
			zlog_err("Caught CORBA::Exception");
			return 0;
		} catch (omniORB::fatalException & e) {
			zlog_err("Caught omniORB::fatalException:");
			zlog_err("  file: %s", e.file());
			zlog_err("  line: %d", e.line());
			zlog_err("  mesg: %s", e.errmsg());
			return 0;
		} catch (...) {
			zlog_err("Caught unknown exception");
			return 0;
		}

		return 1;
	}


	int corba_tel_client_setup()
	{
		zlog_debug("Setting up LRM_TELINK CORBA client side");

		CORBA::ORB_var orb;
		orb = corba_orb();
		if (CORBA::is_nil(orb)) {
			zlog_err("Cannot get ORB");
			return 0;
		}

		std::string ior;
		if (!corba_fetch_ior(CORBA_SERVANT_LRM_TELINK, ior)) {
			zlog_err("Cannot fetch IOR");
			return 0;
		}

		try {
			CORBA::Object_var obj;
			obj = orb->string_to_object(ior.c_str());
			if (CORBA::is_nil(obj)) {
				zlog_err("Cannot get object");
				return 0;
			}

			lrm_tel_proxy = LRM::TeLink::_narrow(obj);
			if (CORBA::is_nil(lrm_tel_proxy)) {
				zlog_err("cannot invoke on a nil object "
					 "reference");
				return 0;
			}
		} catch (CORBA::SystemException & e) {
			zlog_err("Caught CORBA::SystemException");
			return 0;
		} catch (CORBA::Exception & e) {
			zlog_err("Caught CORBA::Exception");
			return 0;
		} catch (...) {
			zlog_err("CLIENT_SETUP: caught unknown "
				 "exception");
			return 0;
		}

		return 1;
	}

	int corba_glob_client_setup()
	{
		zlog_debug("Setting up LRM_GLOBAL CORBA client side");

		CORBA::ORB_var orb;
		orb = corba_orb();
		if (CORBA::is_nil(orb)) {
			zlog_err("Cannot get ORB");
			return 0;
		}

		std::string ior;
		if (!corba_fetch_ior(CORBA_SERVANT_LRM_GLOBAL, ior)) {
			zlog_err("Cannot fetch IOR");
			return 0;
		}

		try {
			CORBA::Object_var obj;
			obj = orb->string_to_object(ior.c_str());
			if (CORBA::is_nil(obj)) {
				zlog_err("Cannot get object");
				return 0;
			}

			lrm_glob_proxy = LRM::Global::_narrow(obj);
			if (CORBA::is_nil(lrm_glob_proxy)) {
				zlog_err("cannot invoke on a nil object "
					 "reference");
				return 0;
			}
		} catch (CORBA::SystemException & e) {
			zlog_err("Caught CORBA::SystemException");
			return 0;
		} catch (CORBA::Exception & e) {
			zlog_err("Caught CORBA::Exception");
			return 0;
		} catch (...) {
			zlog_err("CLIENT_SETUP: caught unknown "
				 "exception");
			return 0;
		}

		return 1;
	}

	int zebra_retrieve_telinks_from_lrm(struct zserv * client,
					    uint32_t       type)
	{
		gmplsTypes::adjType adjacencyType;

		if (type & OSPF_UNI_CLIENT) {
			zlog_debug("Requesting for UNI TE-links to LRM..");
			adjacencyType = gmplsTypes::ADJTYPE_UNI;
		} else if (type & OSPF_INNI_CLIENT) {
			zlog_debug("Requesting for INNI TE-links to LRM..");
			adjacencyType = gmplsTypes::ADJTYPE_INNI;
		} else if (type & OSPF_ENNI_CLIENT) {
			zlog_debug("Requesting for ENNI TE-links to LRM..");
			adjacencyType = gmplsTypes::ADJTYPE_ENNI;
		} else {
			zlog_err("Unknown client type: %d", type);
			return -1;
		}

		try {
			gmplsTypes::TELinkDataSeq_var TELinks;
			struct interface *             ifp;
			struct zlistnode             * cnode, *cnnode;
			struct connected             * c;
			void                         * data;
			uint32_t                       key;
			char                           t_name[7];

			TELinks = lrm_tel_proxy->getFromAdjType(adjacencyType);

			zlog_debug("Number TE Links: %ld",
				   TELinks->length());

			for (size_t i = 0; i < TELinks->length(); i++) {
				/* Create fake interface */
				key = TELinks[i].parms.telkey;
				sprintf(t_name, "tel%d", key);
				ifp = if_create(t_name, strlen(t_name));

				telinksdata2if(TELinks[i], ifp);

				if (zsend_interface_add (client, ifp) < 0) {
					zlog_err("Cannot send ZEBRA_INTERFACE_ADD"
						 "to OSPF");
					return -1;
				}
				for (ALL_LIST_ELEMENTS (ifp->connected, cnode,
							cnnode, data)) {
					c = (struct connected *) data;
					zsend_interface_address(ZEBRA_INTERFACE_ADDRESS_ADD,
								client,
								ifp,
								c);
				}
				/* Delete fake interface */
				list_delete (ifp->connected);
				XFREE (MTYPE_IF, ifp);
				ifp = 0;
			}
		} catch (CORBA::SystemException & e) {
			zlog_err("Cannot get TE Links from LRM: "
				 "CORBA::SystemException");
			return -1;
		} catch (omniORB::fatalException & e) {
			zlog_err("Cannot get TE Links from LRM: "
				 "omniORB::fatalException:");
			zlog_err("  file: %s\n", e.file());
			zlog_err("  line: %d\n", e.line());
			zlog_err("  mesg: %s\n", e.errmsg());
			return -1;
		} catch (LRM::TeLink::NoTELinks & e) {
			zlog_err("Cannot get TE Links from LRM: "
				 "no TE Links found");
			return -1;
		} catch (std::out_of_range & e) {
			zlog_err("Cannot get TE Links from LRM: %s",
				 e.what());
			return -1;
		} catch (std::runtime_error & e) {
			zlog_err("Cannot get TE Links from LRM: %s",
				 e.what());
			return -1;
		} catch (...) {
			zlog_err("Cannot get TE Links from LRM");
			return -1;
		}

		return 1;
	}

	int zebra_retrieve_rid_from_lrm(adj_type_t type,
					uint32_t * addr, uint32_t* powerConsumption)
	{
		try {
			zlog_debug("Retriving Router id from LRM");
			gmplsTypes::nodeId  rid;
			gmplsTypes::adjType adjacencyType;
			gmplsTypes::nodeData node_data;

			adjacencyType << type;

			rid = lrm_glob_proxy->getNodeId();
			lrm_glob_proxy->getNodeData(node_data);

			zlog_debug("Retrived id is %x", (uint32_t)rid);
			*addr = ntohl(rid);
			zlog_debug("Retrived node power consumption is %d", (uint32_t)node_data.powerConsumption);
			*powerConsumption = node_data.powerConsumption;

		} catch (CORBA::SystemException & e) {
			zlog_err("Cannot get router id from LRM: "
				 "CORBA::SystemException");
			return -1;
		} catch (omniORB::fatalException & e) {
			zlog_err("Cannot get router id from LRM: "
				 "omniORB::fatalException:");
			zlog_err("  file: %s\n", e.file());
			zlog_err("  line: %d\n", e.line());
			zlog_err("  mesg: %s\n", e.errmsg());
			return -1;
		} catch (LRM::Global::InternalProblems & e) {
			zlog_err("Cannot get router id from LRM");
			return -1;
		} catch (std::out_of_range & e) {
			zlog_err("Cannot get router id from LRM: %s",
				 e.what());
			return -1;
		} catch (...) {
			zlog_err("Cannot get router id from LRM");
			return -1;
		}

		return 1;
	}
}
