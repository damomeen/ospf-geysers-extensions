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

#ifndef _ZEBRA_CORBA_SERVANT_H_
#define _ZEBRA_CORBA_SERVANT_H_

#include "lib/corba.h"

#include "zebra.hh"
#include "gmpls.hh"

class ZEBRA_i : public POA_ZEBRA::TeLink,
	public PortableServer::RefCountServantBase
{
 public:
	ZEBRA_i();
	virtual ~ZEBRA_i();

	void add(Types::uint32                  telKey,
		 const gmplsTypes::TELinkData& telData);

	void del(Types::uint32 telKey);

	void updateMetric(Types::uint32 telKey,
			  Types::uint32 metric);

	void updateColor(Types::uint32 telKey,
			 Types::uint32 colorMask);

	void updateBw(Types::uint32                         telKey,
		      const gmplsTypes::bwPerPrio               availBw,
		      const gmplsTypes::bwPerPrio               maxLspBw,
		      const gmplsTypes::teLinkCalendarSeq&      calendar,
		      const gmplsTypes::teLinkWdmLambdasBitmap& lambdaBit);

	void updateDJPL(Types::uint32                           telKey,
			Types::uint32                           avgDelay,
			Types::uint32                           maxDelay,
			Types::uint32                           avgJitter,
			Types::uint32                           avgPktLoss,
			Types::uint32                           maxPktLoss);

	void updateSrlg(Types::uint32               telKey,
			const gmplsTypes::srlgSeq&          srlg);

	void updateTna(Types::uint32                telKey,
		       const gmplsTypes::tnaId&         tnaId);

	void updateProtection(Types::uint32         telKey,
			      gmplsTypes::protType          prot);
			      
	void updatePower(Types::uint32              telKey,
			gmplsTypes::powerType               powerConsumption);

	void updateReplanningInfo(Types::uint32     telKey,
			const gmplsTypes::vlinkBwReplanInfo&       replanInfo);

};

class ZEBRA_Node_i : public POA_ZEBRA::Node,
	public PortableServer::RefCountServantBase
{
 public:
	ZEBRA_Node_i();
	virtual ~ZEBRA_Node_i();

    void update(Types::uint32        ridKey,
                const gmplsTypes::nodeData& data);

};

#endif
