//
//  This file is part of phosphorus-g2mpls.
//
//  Copyright (C) 2006, 2007, 2008, 2009 Nextworks s.r.l.
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
//  Giacomo Bernini       (Nextworks s.r.l.) <g.bernini_at_nextworks.it>
//  Gino Carrozzo         (Nextworks s.r.l.) <g.carrozzo_at_nextworks.it>
//  Nicola Ciulli         (Nextworks s.r.l.) <n.ciulli_at_nextworks.it>
//  Giodi Giorgi          (Nextworks s.r.l.) <g.giorgi_at_nextworks.it>
//  Francesco Salvestrini (Nextworks s.r.l.) <f.salvestrini_at_nextworks.it>
//



#include <zebra.h>
#if HAVE_OMNIORB

#include "thread.h"
#include "log.h"
#include "corba.h"

using namespace std;

#include <omniORB4/CORBA.h>

#include <iostream>
#include <fstream>

#include <stdlib.h>
#include <unistd.h>
#include <assert.h>

static omni_mutex                     stack_mutex;

CORBA::ORB_var                        orb;
static PortableServer::POA_var        poa;
static PortableServer::POAManager_var poa_manager;
static string                         iors_dir;

CORBA::ORB_var corba_orb(void)
{
	return orb;
}

PortableServer::POA_var corba_poa(void)
{
	return poa;
}

PortableServer::POAManager_var corba_poa_manager(void)
{
	return poa_manager;
}

static string servant_name_2_ior_file(corba_servant_t n)
{
	string filename;

	string i = string("!!! BUG !!!");
	switch (n) {
		case  CORBA_SERVANT_LRM:
			i = string("lrm");
			break;
		case  CORBA_SERVANT_LRM_TELINK:
			i = string("lrm_telink");
			break;
		case  CORBA_SERVANT_LRM_GLOBAL:
            i = std::string("lrm_global");
            break;
		case  CORBA_SERVANT_ZEBRA_TELINK:
			i = string("zebra_telink");
			break;	
		case  CORBA_SERVANT_ZEBRA_NODE:
			i = string("zebra_node");
			break;
		case  CORBA_SERVANT_TNRC:
			i = string("tnrc");
			break;
		case  CORBA_SERVANT_TNRCONTROLLER_G2RSVPTE:
			i = string("g2rsvpte_tnrc");
			break;
		case  CORBA_SERVANT_NORTHBOUND_G2RSVPTE:
			i = string("g2rsvpte_nb");
			break;
		case  CORBA_SERVANT_LSPSIGNORTH_UNIRSVP:
			i = string("unirsvp_lspsignorth");
			break;
		case  CORBA_SERVANT_LSPSIGNORTH_ENNIRSVP:
			i = string("ennirsvp_lspsignorth");
			break;
		case  CORBA_SERVANT_G2RSVPTE_UNIVTYCONF:
			i = string("g2rsvpte_univtyconf");
			break;
		case  CORBA_SERVANT_G2RSVPTE_INNIVTYCONF:
			i = string("g2rsvpte_innivtyconf");
			break;
		case  CORBA_SERVANT_G2RSVPTE_ENNIVTYCONF:
			i = string("g2rsvpte_ennivtyconf");
			break;
		case  CORBA_SERVANT_SCNGW:
			i = string("scngw");
			break;
		case  CORBA_SERVANT_SCNGW_NETSERVICES:
			i = string("scngw_netservices");
			break;
		case  CORBA_SERVANT_NETWORK_CALLCONTROLLER:
			i = string("ncc");
			break;
		case  CORBA_SERVANT_NETWORK_CALLCONTROLLER_EW:
			i = string("ncc-ew");
			break;
		case  CORBA_SERVANT_LSPSIGSOUTH_NETWORK_CALLCONTROLLER:
			i = string("ncc-ls");
			break;
		case  CORBA_SERVANT_CLIENT_CALLCONTROLLER:
			i = string("ccc");
			break;
		case  CORBA_SERVANT_CLIENT_CALLCONTROLLER_EW:
			i = string("ccc-ew");
			break;
		case  CORBA_SERVANT_LSPSIGSOUTH_CLIENT_CALLCONTROLLER:
			i = string("ccc-ls");
			break;
		case  CORBA_SERVANT_GUNIGW:
			i = string("gw_ew");
			break;
		case  CORBA_SERVANT_HG2GW:
			i = string("gw_ew");
			break;
		case  CORBA_SERVANT_RC_NBI:
			i = string("rc-nb");
			break;
		case  CORBA_SERVANT_RC_SBI:
			i = string("rc-sb");
			break;
		case  CORBA_SERVANT_G2PCERA:
			i = string("g2pcera");
			break;
		case  CORBA_SERVANT_G2PCERA_VTYCONF:
			i = string("g2pcera_vtyconf");
			break;
		case  CORBA_SERVANT_G2MPLS_TOPOLOGY:
			i = string("gmpls_topology");
			break;
		case  CORBA_SERVANT_G2TOPOLOGY:
			i = string("g2topology");
			break;
		case  CORBA_SERVANT_G2TOPOLOGY_UNI:
			i = string("g2topology_uni");
			break;
		case  CORBA_SERVANT_G2TOPOLOGY_ENNI:
			i = string("g2topology_enni");
			break;
		case  CORBA_SERVANT_MGMT_PERSISTENCYCONTROLLER:
			i = string("pc-mgmt");
			break;
		case  CORBA_SERVANT_INNIRSVPLSP_PERSISTENCYCONTROLLER:
			i = string("pc-innirsvplsp");
			break;
		case  CORBA_SERVANT_UNIRSVPLSP_PERSISTENCYCONTROLLER:
			i = string("pc-unirsvplsp");
			break;
		case  CORBA_SERVANT_ENNIRSVPLSP_PERSISTENCYCONTROLLER:
			i = string("pc-ennirsvplsp");
			break;
		default:
			assert(0);
			break;
	}

	filename = string(iors_dir) + string("/") + string(i) + string(".ior");

	fprintf(stderr, "filename:  %s\n", filename.c_str());

	return filename;
}

bool corba_fetch_ior(corba_servant_t name,
		     string &        ior)
{
	string file_name;

	file_name = servant_name_2_ior_file(name);
	try {
		ifstream file_stream;

		file_stream.open(file_name.c_str());
		file_stream >> ior;
		file_stream.close();
	} catch (...) {
		return false;
	}

	return true;
}

bool corba_dump_ior(corba_servant_t name,
		    const string &  ior)
{
	string file_name;

	file_name = servant_name_2_ior_file(name);
	try {
		ofstream file_stream;

		file_stream.open(file_name.c_str());
		file_stream << ior;
		file_stream.close();
	} catch (...) {
		return false;
	}

	return true;
}

bool corba_remove_ior(corba_servant_t name)
{
	string file_name;

	file_name = servant_name_2_ior_file(name);
	if (unlink(file_name.c_str())) {
		fprintf(stderr, "Cannot remove %s file\n", file_name.c_str());
		return false;
	}

	return true;
}

struct thread_master * corba_master = 0;

int corba_thread(struct thread * thread)
{
      if (!corba_step()) {
	      fprintf(stderr, "Cannot step CORBA subsystem\n");
      }

      thread_add_timer(corba_master, corba_thread, NULL, 1);
}

#ifdef __cplusplus
extern "C" {
#endif
	int corba_init(char *                 iors_dir,
		       corba_servant_t        servant,
		       struct thread_master * master)
	{
		if (master == 0) {
			fprintf(stderr, "Master thread is empty\n");
			return 0;
		}

		fprintf(stdout, "CORBA_init() start\n");

		int    argc = 0;
		char** argv = NULL;

		try {
			if (!iors_dir) {
				throw string("Bad parameters");
			}

			::iors_dir = string(iors_dir);

			fprintf(stderr, "IOR directory is %s\n", iors_dir);

			orb = CORBA::ORB_init(argc, argv, "omniORB4");
			if (!orb) {
				throw string("Cannot initialize ORB");
			}

			CORBA::Object_var obj;

			obj = orb->resolve_initial_references("RootPOA");
			if (!obj) {
				throw string("Cannot find RootPOA");
			}

			poa = PortableServer::POA::_narrow(obj);
			if (!poa) {
				throw string("Cannot narrow object");
			}

			poa_manager = poa->the_POAManager();
			if (!poa_manager) {
				throw string("Cannot get POA manager");
			}

		} catch (CORBA::SystemException & e) {
			fprintf(stderr, "Caught CORBA::SystemException\n");
			return 0;
		} catch (CORBA::Exception & e) {
			fprintf(stderr, "Caught CORBA::Exception\n");
			return 0;
		} catch (omniORB::fatalException & e) {
			fprintf(stderr, "Caught omniORB::fatalException:");
			fprintf(stderr, "  file: %s", e.file());
			fprintf(stderr, "  line: %d", e.line());
			fprintf(stderr, "  mesg: %s\n", e.errmsg());
			return 0;
		} catch (string & e) {
			fprintf(stderr,
				"Caught library exception: %s\n",
				e.c_str());
		} catch (...) {
			fprintf(stderr, "Caught unknown exception\n");
			return 0;
		}

		fprintf(stdout, "CORBA_init() stop\n");

		corba_master = master;
		thread_add_timer(master, corba_thread, NULL, 1);

		return 1;
	}

	void stack_lock(void)
	{
		stack_mutex.lock();
	}

	void stack_unlock(void)
	{
		stack_mutex.release();
	}

	int corba_step(void)
	{
		//fprintf(stdout, "CORBA_step() start\n");

		try {
			STACK_UNLOCK();

			if (orb->work_pending()) {
				orb->perform_work();
			}

			STACK_LOCK();
		} catch (...) {
			fprintf(stderr,
				"Caught exception while running ORB\n");
			return 0;
		}

		//fprintf(stdout, "CORBA_step() stop\n");

		return 1;
	}

	int corba_fini(void)
	{
		fprintf(stdout, "CORBA_fini() start\n");
		fprintf(stdout, "CORBA_fini() stop\n");

		return 1;
	}
#ifdef __cplusplus
}
#endif

#endif // HAVE_OMNIORB
