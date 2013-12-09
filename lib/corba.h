/*
 *  This file is part of phosphorus-g2mpls.
 *
 *  Copyright (C) 2006, 2007, 2008, 2009 Nextworks s.r.l.
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
 *  Giacomo Bernini       (Nextworks s.r.l.) <g.bernini_at_nextworks.it>
 *  Gino Carrozzo         (Nextworks s.r.l.) <g.carrozzo_at_nextworks.it>
 *  Nicola Ciulli         (Nextworks s.r.l.) <n.ciulli_at_nextworks.it>
 *  Giodi Giorgi          (Nextworks s.r.l.) <g.giorgi_at_nextworks.it>
 *  Francesco Salvestrini (Nextworks s.r.l.) <f.salvestrini_at_nextworks.it>
 */



#include <zebra.h>

//#define VERBOSE_MUTEX_ACTIONS

#ifndef _ZEBRA_CORBA_H
#define _ZEBRA_CORBA_H

typedef enum {
	CORBA_SERVANT_LRM = 1,
	CORBA_SERVANT_LRM_TELINK,
	CORBA_SERVANT_LRM_GLOBAL,
	CORBA_SERVANT_ZEBRA_TELINK,
    CORBA_SERVANT_ZEBRA_NODE,
	CORBA_SERVANT_TNRC,
	CORBA_SERVANT_TNRCONTROLLER_G2RSVPTE,
	CORBA_SERVANT_NORTHBOUND_G2RSVPTE,
	CORBA_SERVANT_LSPSIGNORTH_UNIRSVP,
	CORBA_SERVANT_LSPSIGNORTH_ENNIRSVP,
	CORBA_SERVANT_G2RSVPTE_UNIVTYCONF,
	CORBA_SERVANT_G2RSVPTE_INNIVTYCONF,
	CORBA_SERVANT_G2RSVPTE_ENNIVTYCONF,
	CORBA_SERVANT_SCNGW,
	CORBA_SERVANT_SCNGW_NETSERVICES,
	CORBA_SERVANT_NETWORK_CALLCONTROLLER,
	CORBA_SERVANT_NETWORK_CALLCONTROLLER_EW,
	CORBA_SERVANT_LSPSIGSOUTH_NETWORK_CALLCONTROLLER,
	CORBA_SERVANT_CLIENT_CALLCONTROLLER,
	CORBA_SERVANT_CLIENT_CALLCONTROLLER_EW,
	CORBA_SERVANT_LSPSIGSOUTH_CLIENT_CALLCONTROLLER,
	CORBA_SERVANT_GUNIGW,
	CORBA_SERVANT_HG2GW,
	CORBA_SERVANT_RC_NBI,
	CORBA_SERVANT_RC_SBI,
	CORBA_SERVANT_G2PCERA,
	CORBA_SERVANT_G2PCERA_VTYCONF,
	CORBA_SERVANT_G2MPLS_TOPOLOGY,
	CORBA_SERVANT_G2TOPOLOGY,
	CORBA_SERVANT_G2TOPOLOGY_UNI,
	CORBA_SERVANT_G2TOPOLOGY_ENNI,
	CORBA_SERVANT_MGMT_PERSISTENCYCONTROLLER,
	CORBA_SERVANT_INNIRSVPLSP_PERSISTENCYCONTROLLER,
	CORBA_SERVANT_UNIRSVPLSP_PERSISTENCYCONTROLLER,
	CORBA_SERVANT_ENNIRSVPLSP_PERSISTENCYCONTROLLER
} corba_servant_t;

#ifdef __cplusplus
extern "C" {
#endif
	int                     corba_init(char *                 iors_dir,
					   corba_servant_t        servant,
					   struct thread_master * master);

	int                     corba_step(void);
	int                     corba_fini(void);

	void                    stack_lock(void);
	void                    stack_unlock(void);

#ifdef VERBOSE_MUTEX_ACTIONS
#define STACK_LOCK(X)						\
{								\
	fprintf(stdout,						\
		"stack_lock(): LOCKING stack_mutex for %s\n",	\
		__PRETTY_FUNCTION__);				\
								\
	stack_lock();						\
}

#define STACK_UNLOCK(X)							\
{									\
	stack_unlock();							\
	fprintf(stdout,							\
		"stack_unlock(): UNLOCKING stack_mutex for %s\n",	\
		__PRETTY_FUNCTION__);					\
}
#else

#define STACK_LOCK(X)	{	stack_lock();	}
#define STACK_UNLOCK(X) {	stack_unlock();	}

#endif // VERBOSE_MUTEX_ACTIONS

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus

#if HAVE_OMNIORB

#include <iostream>
#include <omniORB4/CORBA.h>

CORBA::ORB_var                 corba_orb(void);
bool                           corba_remove_ior(corba_servant_t name);
bool                           corba_fetch_ior(corba_servant_t name,
					       std::string &   ior);
bool                           corba_dump_ior(corba_servant_t name,
					      const std::string & ior);
PortableServer::POA_var        corba_poa(void);
PortableServer::POAManager_var corba_poa_manager(void);

#endif // HAVE_OMNIORB

#endif // __cplusplus

#endif // _ZEBRA_CORBA_H
