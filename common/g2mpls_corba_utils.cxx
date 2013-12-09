//
//  This file is part of phosphorus-g2mpls.
//
//  Copyright (C) 2006, 2007, 2008, 2009 Nextworks s.r.l.
//
//  This program is free software; you can redistribute it and/or modify
//  it under the terms of the GNU Lesser General Public License as
//  published by the Free Software Foundation; either version 2.1
//  of the License, or (at your option) any later version.
//
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU Lesser General Public License for more details.
//
//  You should have received a copy of the GNU Lesser General Public
//  License along with this program; if not, write to the Free Software
//  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
//  MA 02110-1301 USA.
//
//  Authors:
//
//  Giacomo Bernini       (Nextworks s.r.l.) <g.bernini_at_nextworks.it>
//  Gino Carrozzo         (Nextworks s.r.l.) <g.carrozzo_at_nextworks.it>
//  Nicola Ciulli         (Nextworks s.r.l.) <n.ciulli_at_nextworks.it>
//  Giodi Giorgi          (Nextworks s.r.l.) <g.giorgi_at_nextworks.it>
//  Francesco Salvestrini (Nextworks s.r.l.) <f.salvestrini_at_nextworks.it>
//

#include <config.h>

#if HAVE_OMNIORB

#ifdef __cplusplus

#include "g2mpls_corba_utils.h"

using namespace std;

#include <omniORB4/CORBA.h>

#include <iostream>
#include <fstream>
#include <stdlib.h>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <arpa/inet.h>

//
// nodeId
//
g2mpls_addr_t &
operator << (g2mpls_addr_t &                 dst,
	     const gmplsTypes::nodeId     & src)
{
	memset(&dst, 0, sizeof(dst));

	dst.type              = IPv4;
	dst.preflen           = 32;
	dst.value.ipv4.s_addr = htonl(src);

	return dst;
}

gmplsTypes::nodeId &
operator << (gmplsTypes::nodeId &     dst,
	     const g2mpls_addr_t &     src)
{
	switch (src.type) {
		case IPv4: {
			dst = ntohl(src.value.ipv4.s_addr);
			break;
		}
		case IPv6:
		case UNNUMBERED:
		case NSAP:
		default:
			throw out_of_range("nodeId G2.ADDR type out-of-range");
			break;
	}

	return dst;
}

std::string &
operator << (std::string &                   dst,
	     const gmplsTypes::nodeId &     src)
{
	std::ostringstream id;

	ipv4_t addr;
	addr.s_addr = htonl(src);

	id << "0x" << std::hex << std::setw(8) << std::setfill('0') << src;
	id << std::hex << " (IPv4 " << inet_ntoa(addr) << ")";

	dst = id.str();

	return dst;
}

//
// linkId
//
g2mpls_addr_t &
operator << (g2mpls_addr_t &                 dst,
	     const gmplsTypes::linkId_var & src)
{
	memset(&dst, 0, sizeof(dst));

	switch (src->_d()) {
		case gmplsTypes::LINKIDTYPE_IPV4: {
			dst.type              = IPv4;
			dst.preflen           = 32;
			dst.value.ipv4.s_addr = htonl(src->ipv4());
			break;
		}
		case gmplsTypes::LINKIDTYPE_IPV6: {
			int    i;

			dst.type    = IPv6;
			dst.preflen = 128;

			for (i = 0; i < 4; i++) {
				dst.value.ipv6.s6_addr32[i] =
					htonl(src->ipv6()[i]);
			}
			break;
		}
		case gmplsTypes::LINKIDTYPE_UNNUM: {
			dst.type                = UNNUMBERED;
			dst.preflen             = 0;
			//dst.value.unnum.addr    = src.unnum().addr;
			//dst.value.unnum.node_id = src.unnum().node;
			//dst.value.unnum.addr    = src->unnum();
			//dst.value.unnum.node_id = 0; // meaningless
			dst.value.unnum         = src->unnum();
			break;
		}
		default:
			throw out_of_range("linkId type out-of-range");
			break;
	}

	return dst;
}

gmplsTypes::linkId_var &
operator << (gmplsTypes::linkId_var & dst,
	     const g2mpls_addr_t &     src)
{
	dst = new gmplsTypes::linkId;

	switch (src.type) {
		case IPv4:
			dst->ipv4(ntohl(src.value.ipv4.s_addr));
			break;
		case IPv6: {
			gmplsTypes::addrIPv6 parts;
			int i;

			for (i = 0; i < 4; i++) {
				parts[i] =
					ntohl(src.value.ipv6.s6_addr32[i]);
			}

			dst->ipv6(parts);
			break;
		}
		case UNNUMBERED: {
			//gmplsTypes::addrUnnum unnId;
			//
			//unnId.node = src.value.unnum.node_id;
			//unnId.addr = src.value.unnum.addr;
			//dst.unnum(unnId);
			//dst->unnum(src.value.unnum.addr);
			dst->unnum(src.value.unnum);
			break;
		}
		default:
			throw out_of_range("link G2.ADDR type out-of-range");
			break;
	}

	return dst;
}

std::string &
operator << (std::string &                   dst,
	     const gmplsTypes::linkId_var & src)
{
	std::ostringstream id;

	switch (src->_d()) {
		case gmplsTypes::LINKIDTYPE_IPV4: {
			id << "(LINK-IPv4) " << numb_htoa(src->ipv4());
			break;
		}
		case gmplsTypes::LINKIDTYPE_IPV6: {
			int    i;

			id << "(LINK-IPv6) " << std::hex;
			for (i = 0; i < 4; i++) {
				id << std::setw(8)
				   << std::setfill('0')
				   << src->ipv6()[i];
			}
			id << std::dec;
			break;
		}
		case gmplsTypes::LINKIDTYPE_UNNUM: {
			id << "(LINK-UNN) ";
			//  id << "Node:0x"
			//     << std::hex
			//     << std::setw(8)
			//     << std::setfill('0')
			//     << src.unnum().node
			//     << std::dec;
			//  id << " / Id:0x"
			//     << std::hex
			//     << std::setw(8)
			//     << std::setfill('0')
			//     << src.unnum().addr
			//     << std::dec;
			id << "Id:0x"
			   << std::hex
			   << std::setw(8)
			   << std::setfill('0')
			   << src->unnum()
			   << std::dec;
			break;
		}
		default:
			throw out_of_range("linkId type out-of-range");
			break;
	}

	dst = id.str();

	return dst;
}

bool
operator == (const g2mpls_addr_t &           src,
	     const gmplsTypes::linkId_var & dst)
{
	switch (dst->_d()) {
		case gmplsTypes::LINKIDTYPE_IPV4: {
			if (src.type != IPv4 ||
			    ntohl(src.value.ipv4.s_addr) != dst->ipv4()) {
				return false;
			}
			break;
		}
		case gmplsTypes::LINKIDTYPE_IPV6: {
			int i;

			if (src.type != IPv6) {
				return false;
			}

			for (i = 0; i < 4; i++) {
				if (htonl(src.value.ipv6.s6_addr32[i]) !=
				    dst->ipv6()[i]) {
					return false;
				}
			}
			break;
		}
		case gmplsTypes::LINKIDTYPE_UNNUM: {
			//  if (src.type                != UNNUMBERED       ||
			//      src.value.unnum.node_id != dst.unnum().node ||
			//      src.value.unnum.addr    != dst.unnum().addr) {
			//      return false;
			//  }
			// if (src.type                != UNNUMBERED ||
			//     src.value.unnum.addr    != dst->unnum()) {
			//     return false;
			// }
			if (src.type        != UNNUMBERED ||
			    src.value.unnum != dst->unnum()) {
				return false;
			}
			break;
		}
		default:
			return false;
	}
	return true;
}

//
// labelId
//
label_id_t &
operator<< (label_id_t &                     dst,
	    const gmplsTypes::labelId_var & src)
{
	memset(&dst, 0, sizeof(dst));

	switch (src->_d()) {
		case gmplsTypes:: LABELTYPE_L32: {
			dst.type = LABEL_32BIT;
			dst.value.label32.id = src->label32();
			break;
		}
		case gmplsTypes:: LABELTYPE_L60: {
			uint64_t l60v, l60m;
			int      i;

			l60v = src->label60() & 0x0FFFFFFFFFFFFFFFull;

			dst.type = LABEL_60BIT;
			for (i = 0; i < 6; i++) {
				int disp = ((5 - i) * 8 + 12);
				l60m = (0xFFull) << disp;
				dst.value.label60.mac[i] =
					(uint8_t) ((l60v & l60m) >> disp);
			}
			dst.value.label60.vlan_id =
				(l60v & 0x0000000000000FFFull);
			break;
		}
		default:
			throw out_of_range("LABEL ID type out-of-range");
			break;
	}

	return dst;
}

gmplsTypes::labelId_var &
operator<< (gmplsTypes::labelId_var & dst,
	    const label_id_t &         src)
{
	dst = new gmplsTypes::labelId;

	switch (src.type) {
		case LABEL_32BIT: {
			dst->label32(src.value.label32.id);
			break;
		}
		case LABEL_60BIT: {
			uint64_t l60v;
			int i;

			l60v = 0x0ull;
			for (i = 0; i < 6; i++) {
				int disp = ((5 - i) * 8 + 12);
				l60v |= src.value.label60.mac[i] << disp;
			}
			l60v |= src.value.label60.vlan_id;

			dst->label60(l60v);
			break;
		}
		default:
			throw out_of_range("G2.LABEL type out-of-range");
			break;
	}

	return dst;
}

std::string &
operator<< (std::string &                    dst,
	    const gmplsTypes::labelId_var & src)
{
	std::ostringstream id;

	switch (src->_d()) {
		case gmplsTypes:: LABELTYPE_L32: {
			id << "(LABEL-32bit) - 0x"
			   << std::hex
			   << std::setw(8)
			   << std::setfill('0')
			   << src->label32()
			   << std::dec;
			break;
		}
		case gmplsTypes:: LABELTYPE_L60: {
			id << "(LABEL-60bit) 0x"
			   << std::hex
			   << std::setw(16)
			   << std::setfill('0')
			   << src->label60()
			   << std::dec;
			break;
		}
		default:
			throw out_of_range("LABEL ID type out-of-range");
			break;
	}

	dst = id.str();

	return dst;
}

//
// xcDirection
//
xcdirection_t &
operator<< (xcdirection_t &                      dst,
	    const gmplsTypes::xcDirection &     src)
{
	switch (src) {
		case gmplsTypes::XCDIR_UNIDIRECTIONAL: {
			dst = XCDIRECTION_UNIDIR;
			break;
		}
		case gmplsTypes::XCDIR_BIDIRECTIONAL: {
			dst = XCDIRECTION_BIDIR;
			break;
		}
		case gmplsTypes::XCDIR_BCAST: {
			dst = XCDIRECTION_BCAST;
			break;
		}
		default:
			throw out_of_range("xcDirection type out-of-range");
			break;
	}

	return dst;
}

gmplsTypes::xcDirection &
operator<< (gmplsTypes::xcDirection &           dst,
	    const xcdirection_t &                src)
{
	switch (src) {
		case XCDIRECTION_UNIDIR: {
			dst = gmplsTypes::XCDIR_UNIDIRECTIONAL;
			break;
		}
		case XCDIRECTION_BIDIR: {
			dst = gmplsTypes::XCDIR_BIDIRECTIONAL;
			break;
		}
		case XCDIRECTION_BCAST: {
			dst = gmplsTypes::XCDIR_BCAST;
			break;
		}
		default:
			throw out_of_range("xcDirection type out-of-range");
			break;
	}

	return dst;
}

std::string &
operator << (std::string &                       dst,
	     const gmplsTypes::xcDirection &    src)
{
	std::ostringstream id;

	switch (src) {
		case gmplsTypes::XCDIR_UNIDIRECTIONAL: {
			id << "XCDIR_UNIDIRECTIONAL";
			break;
		}
		case gmplsTypes::XCDIR_BIDIRECTIONAL: {
			id << "XCDIR_BIDIRECTIONAL";
			break;
		}
		case gmplsTypes::XCDIR_BCAST: {
			id << "XCDIR_BCAST";
			break;
		}
		default:
			throw out_of_range("xcDirection type out-of-range");
			break;
	}

	dst = id.str();

	return dst;
}

//
// tnrcResult
//
std::string &
operator << (std::string &                       dst,
	     const gmplsTypes::tnrcResult &     src)
{
	std::ostringstream id;



	switch (src) {
		case gmplsTypes::TNRC_RESULT_MAKEXC_NOERROR: {
			id << "MAKE XC NO ERROR";
			break;
		}
		case gmplsTypes::TNRC_RESULT_MAKEXC_EQPTDOWN: {
			id << "MAKE XC EQPT DOWN";
			break;
		}
		case gmplsTypes::TNRC_RESULT_MAKEXC_PARAMERROR: {
			id << "MAKE XC PARAM ERROR";
			break;
		}
		case gmplsTypes::TNRC_RESULT_MAKEXC_NOTCAPABLE: {
			id << "MAKE XC NOT CAPABLE";
			break;
		}
		case gmplsTypes::TNRC_RESULT_MAKEXC_BUSYRESOURCES: {
			id << "MAKE XC BUSY RESOURCES";
			break;
		}
		case gmplsTypes::TNRC_RESULT_MAKEXC_INTERNALERROR: {
			id << "MAKE XC INTERNAL ERROR";
			break;
		}
		case gmplsTypes::TNRC_RESULT_MAKEXC_GENERICERROR: {
			id << "MAKE XC GENERIC ERROR";
			break;
		}

		case gmplsTypes::TNRC_RESULT_DESTROYXC_NOERROR: {
			id << "DESTROY XC NO ERROR";
			break;
		}
		case gmplsTypes::TNRC_RESULT_DESTROYXC_EQPTDOWN: {
			id << "DESTROY XC EQPT DOWN";
			break;
		}
		case gmplsTypes::TNRC_RESULT_DESTROYXC_PARAMERROR: {
			id << "DESTROY XC PARAM ERROR";
			break;
		}
		case gmplsTypes::TNRC_RESULT_DESTROYXC_NOTCAPABLE: {
			id << "DESTROY XC NOT CAPABLE";
			break;
		}
		case gmplsTypes::TNRC_RESULT_DESTROYXC_BUSYRESOURCES: {
			id << "DESTROY XC BUSY RESOURCES";
			break;
		}
		case gmplsTypes::TNRC_RESULT_DESTROYXC_INTERNALERROR: {
			id << "DESTROY XC INTERNAL ERROR";
			break;
		}
		case gmplsTypes::TNRC_RESULT_DESTROYXC_GENERICERROR: {
			id << "DESTROY XC GENERIC ERROR";
			break;
		}

		case gmplsTypes::TNRC_RESULT_RESERVEXC_NOERROR: {
			id << "RESERVE XC NO ERROR";
			break;
		}
		case gmplsTypes::TNRC_RESULT_RESERVEXC_EQPTDOWN: {
			id << "RESERVE XC EQPT DOWN";
			break;
		}
		case gmplsTypes::TNRC_RESULT_RESERVEXC_PARAMERROR: {
			id << "RESERVE XC PARAM ERROR";
			break;
		}
		case gmplsTypes::TNRC_RESULT_RESERVEXC_NOTCAPABLE: {
			id << "RESERVE XC NOT CAPABLE";
			break;
		}
		case gmplsTypes::TNRC_RESULT_RESERVEXC_BUSYRESOURCES: {
			id << "RESERVE XC BUSY RESOURCES";
			break;
		}
		case gmplsTypes::TNRC_RESULT_RESERVEXC_INTERNALERROR: {
			id << "RESERVE XC INTERNAL ERROR";
			break;
		}
		case gmplsTypes::TNRC_RESULT_RESERVEXC_GENERICERROR: {
			id << "RESERVE XC GENERIC ERROR";
			break;
		}

		case gmplsTypes::TNRC_RESULT_UNRESERVEXC_NOERROR: {
			id << "UNRESERVE XC NO ERROR";
			break;
		}
		case gmplsTypes::TNRC_RESULT_UNRESERVEXC_EQPTDOWN: {
			id << "UNRESERVE XC EQPT DOWN";
			break;
		}
		case gmplsTypes::TNRC_RESULT_UNRESERVEXC_PARAMERROR: {
			id << "UNRESERVE XC PARAM ERROR";
			break;
		}
		case gmplsTypes::TNRC_RESULT_UNRESERVEXC_NOTCAPABLE: {
			id << "UNRESERVE XC NOT CAPABLE";
			break;
		}
		case gmplsTypes::TNRC_RESULT_UNRESERVEXC_BUSYRESOURCES: {
			id << "UNRESERVE XC BUSY RESOURCES";
			break;
		}
		case gmplsTypes::TNRC_RESULT_UNRESERVEXC_INTERNALERROR: {
			id << "UNRESERVE XC INTERNAL ERROR";
			break;
		}
		case gmplsTypes::TNRC_RESULT_UNRESERVEXC_GENERICERROR: {
			id << "UNRESERVE XC GENERIC ERROR";
			break;
		}
		default:
			throw out_of_range("tnrcResult type out-of-range");
			break;
	}

	dst = id.str();

	return dst;
}

//
// adjType
//

adj_type_t &
operator << (adj_type_t &                        dst,
	     const gmplsTypes::adjType &        src)
{
	switch (src) {
		case gmplsTypes::ADJTYPE_UNI: {
			dst = UNI;
			break;
		}
		case gmplsTypes::ADJTYPE_INNI: {
			dst = INNI;
			break;
		}
		case gmplsTypes::ADJTYPE_ENNI: {
		        dst = ENNI;
			break;
		}
		default:
			throw out_of_range("adjType type out-of-range");
			break;
	}

	return dst;
}

gmplsTypes::adjType &
operator << (gmplsTypes::adjType &              dst,
	     const adj_type_t &                  src)
{
	switch (src) {
		case UNI: {
			dst = gmplsTypes::ADJTYPE_UNI;
			break;
		}
		case INNI: {
			dst = gmplsTypes::ADJTYPE_INNI;
			break;
		}
		case ENNI: {
		        dst = gmplsTypes::ADJTYPE_ENNI;
			break;
		}
		default:
			throw out_of_range("adj_type_t type out-of-range");
			break;
	}

	return dst;
}

bool
operator == (const adj_type_t &                  dst,
	     const gmplsTypes::adjType &        src)
{
	switch (src) {
		case gmplsTypes::ADJTYPE_UNI: {
			if (dst != UNI) {
				return false;
			}
			break;
		}
		case gmplsTypes::ADJTYPE_INNI: {
			if (dst != INNI) {
				return false;
			}
			break;
		}
		case gmplsTypes::ADJTYPE_ENNI: {
			if (dst != ENNI) {
				return false;
			}
			break;
		}
		default:
			return false;
	}
	return true;
}

std::string &
operator << (std::string &                      dst,
	     const gmplsTypes::adjType &       src)
{
	std::ostringstream id;

	switch (src) {
		case gmplsTypes::ADJTYPE_INNI: {
			id << "INNI";
			break;
		}
		case gmplsTypes::ADJTYPE_UNI: {
			id << "UNI";
			break;
		}
		case gmplsTypes::ADJTYPE_ENNI: {
			id << "ENNI";
			break;
		}
		default:
			throw out_of_range("adjType type out-of-range");
			break;
	}

	dst = id.str();

	return dst;
}

//
// operState
//
opstate_t &
operator << (opstate_t &                        dst,
	     const gmplsTypes::operState &     src)
{
	switch (src) {
		case gmplsTypes::OPERSTATE_UP: {
			dst = UP;
			break;
		}
		case gmplsTypes::OPERSTATE_DOWN: {
			dst = DOWN;
			break;
		}
		default:
			throw out_of_range("operState type out-of-range");
			break;
	}

	return dst;
}

gmplsTypes::operState &
operator << (gmplsTypes::operState &     dst,
	     const opstate_t &            src)
{
	switch (src) {
		case UP: {
			dst = gmplsTypes::OPERSTATE_UP;
			break;
		}
		case DOWN: {
			dst = gmplsTypes::OPERSTATE_DOWN;
			break;
		}
		default:
			throw out_of_range("opstate_t type out-of-range");
			break;
	}

	return dst;
}

std::string &
operator << (std::string &                      dst,
	     const gmplsTypes::operState &     src)
{
	std::ostringstream id;

	switch (src) {
		case gmplsTypes::OPERSTATE_UP: {
			id << "UP";
			break;
		}
		case gmplsTypes::OPERSTATE_DOWN: {
			id << "DOWN";
			break;
		}
		default:
			throw out_of_range("operState type out-of-range");
			break;
	}

	dst = id.str();

	return dst;
}

//
// adminState
//
admstate_t &
operator << (admstate_t &                        dst,
	     const gmplsTypes::adminState &     src)
{
	switch (src) {
		case gmplsTypes::ADMINSTATE_ENABLED: {
			dst = ENABLED;
			break;
		}
		case gmplsTypes::ADMINSTATE_DISABLED: {
			dst = DISABLED;
			break;
		}
		default:
			throw out_of_range("adminState type out-of-range");
			break;
	}

	return dst;
}

gmplsTypes::adminState &
operator << (gmplsTypes::adminState &     dst,
	     const admstate_t &            src)
{
	switch (src) {
		case ENABLED: {
			dst = gmplsTypes::ADMINSTATE_ENABLED;
			break;
		}
		case DISABLED: {
			dst = gmplsTypes::ADMINSTATE_DISABLED;
			break;
		}
		default:
			throw out_of_range("admstate_t type out-of-range");
			break;
	}

	return dst;
}

std::string &
operator << (std::string &                       dst,
	     const gmplsTypes::adminState &     src)
{
	std::ostringstream id;

	switch (src) {
		case gmplsTypes::ADMINSTATE_ENABLED: {
			id << "ENABLED";
			break;
		}
		case gmplsTypes::ADMINSTATE_DISABLED: {
			id << "DISABLED";
			break;
		}
		default:
			throw out_of_range("adminState type out-of-range");
			break;
	}

	dst = id.str();

	return dst;
}

//
// switchingCap
//

sw_cap_t &
operator << (sw_cap_t &                          dst,
	     const gmplsTypes::switchingCap &   src)
{
	switch (src) {
		case gmplsTypes::SWITCHINGCAP_UNKNOWN: {
			dst = SWCAP_UNKNOWN;
			break;
        }
		case gmplsTypes::SWITCHINGCAP_PSC_1: {
			dst = SWCAP_PSC_1;
			break;
		}
		case gmplsTypes::SWITCHINGCAP_PSC_2: {
			dst = SWCAP_PSC_2;
			break;
		}
		case gmplsTypes::SWITCHINGCAP_PSC_3: {
			dst = SWCAP_PSC_3;
			break;
		}
		case gmplsTypes::SWITCHINGCAP_PSC_4: {
			dst = SWCAP_PSC_4;
			break;
		}
		case gmplsTypes::SWITCHINGCAP_EVPL: {
			dst = SWCAP_EVPL;
			break;
		}
		case gmplsTypes::SWITCHINGCAP_8021_PBBTE: {
			dst = SWCAP_8021_PBBTE;
			break;
		}
		case gmplsTypes::SWITCHINGCAP_L2SC: {
			dst = SWCAP_L2SC;
			break;
		}
		case gmplsTypes::SWITCHINGCAP_TDM: {
			dst = SWCAP_TDM;
			break;
		}
		case gmplsTypes::SWITCHINGCAP_DCSC: {
			dst = SWCAP_DCSC;
			break;
		}
		case gmplsTypes::SWITCHINGCAP_OBSC: {
			dst = SWCAP_OBSC;
			break;
		}
		case gmplsTypes::SWITCHINGCAP_LSC: {
			dst = SWCAP_LSC;
			break;
		}
		case gmplsTypes::SWITCHINGCAP_FSC: {
			dst = SWCAP_FSC;
			break;
		}
		default:
			throw out_of_range("switchingCap type out-of-range");
			break;
	}

	return dst;
}

gmplsTypes::switchingCap &
operator << (gmplsTypes::switchingCap &         dst,
	     const sw_cap_t  &                   src)
{
	switch (src) {
		case SWCAP_PSC_1: {
			dst = gmplsTypes::SWITCHINGCAP_PSC_1;
			break;
		}
		case SWCAP_PSC_2: {
			dst = gmplsTypes::SWITCHINGCAP_PSC_2;
			break;
		}
		case SWCAP_PSC_3: {
			dst = gmplsTypes::SWITCHINGCAP_PSC_3;
			break;
		}
		case SWCAP_PSC_4: {
			dst =gmplsTypes::SWITCHINGCAP_PSC_4;
			break;
		}
		case SWCAP_L2SC: {
			dst = gmplsTypes::SWITCHINGCAP_L2SC;
			break;
		}
		case SWCAP_TDM: {
			dst = gmplsTypes::SWITCHINGCAP_TDM;
			break;
		}
		case SWCAP_LSC: {
			dst = gmplsTypes::SWITCHINGCAP_LSC;
			break;
		}
		case SWCAP_FSC: {
			dst = gmplsTypes::SWITCHINGCAP_FSC;
			break;
		}
		default:
			throw out_of_range("switchingCap type out-of-range");
			break;
	}

	return dst;
}

std::string &
operator << (std::string &                       dst,
	     const gmplsTypes::switchingCap &   src)
{
	std::ostringstream id;

	switch (src) {
		case gmplsTypes::SWITCHINGCAP_PSC_1: {
			id << "PSC_1";
			break;
		}
		case gmplsTypes::SWITCHINGCAP_PSC_2: {
			id << "PSC_2";
			break;
		}
		case gmplsTypes::SWITCHINGCAP_PSC_3: {
			id << "PSC_3";
			break;
		}
		case gmplsTypes::SWITCHINGCAP_PSC_4: {
			id << "PSC_4";
			break;
		}
		case gmplsTypes::SWITCHINGCAP_L2SC: {
			id << "L2SC";
			break;
		}
		case gmplsTypes::SWITCHINGCAP_TDM: {
			id << "TDM";
			break;
		}
		case gmplsTypes::SWITCHINGCAP_LSC: {
			id << "LSC";
			break;
		}
		case gmplsTypes::SWITCHINGCAP_FSC: {
			id << "FSC";
			break;
		}
		default:
			throw out_of_range("switchingCap type out-of-range");
			break;
	}

	dst = id.str();

	return dst;
}

//
// encodingType
//

enc_type_t &
operator << (enc_type_t &                        dst,
	     const gmplsTypes::encodingType &   src)
{
	switch (src) {
		case gmplsTypes::ENCODINGTYPE_PACKET: {
			dst = ENCT_PACKET;
			break;
		}
		case gmplsTypes::ENCODINGTYPE_ETHERNET: {
			dst = ENCT_ETHERNET;
			break;
		}
		case gmplsTypes::ENCODINGTYPE_ANSI_ETSI_PDH: {
			dst = ENCT_ANSI_ETSI_PDH;
			break;
		}
		case gmplsTypes::ENCODINGTYPE_RESERVED_1: {
			dst = ENCT_RESERVED_1;
			break;
		}
		case gmplsTypes::ENCODINGTYPE_SDH_SONET: {
			dst = ENCT_SDH_SONET;
			break;
		}
		case gmplsTypes::ENCODINGTYPE_RESERVED_2: {
			dst = ENCT_RESERVED_2;
			break;
		}
		case gmplsTypes::ENCODINGTYPE_DIGITAL_WRAPPER: {
			dst = ENCT_DIGITAL_WRAPPER;
			break;
		}
		case gmplsTypes::ENCODINGTYPE_LAMBDA: {
			dst = ENCT_LAMBDA;
			break;
		}
		case gmplsTypes::ENCODINGTYPE_FIBER: {
			dst = ENCT_FIBER;
			break;
		}
		case gmplsTypes::ENCODINGTYPE_RESERVED_3: {
			dst = ENCT_RESERVED_3;
			break;
		}
		case gmplsTypes::ENCODINGTYPE_FIBERCHANNEL: {
			dst = ENCT_FIBERCHANNEL;
			break;
		}
		case gmplsTypes::ENCODINGTYPE_G709_ODU: {
			dst = ENCT_G709_ODU;
			break;
		}
		case gmplsTypes::ENCODINGTYPE_G709_OC: {
			dst = ENCT_G709_OC;
			break;
		}
	}

	return dst;
}

gmplsTypes::encodingType &
operator << (gmplsTypes::encodingType &         dst,
	     const enc_type_t &                  src)
{
	switch (src) {
		case ENCT_PACKET: {
			dst = gmplsTypes::ENCODINGTYPE_PACKET;
			break;
		}
		case ENCT_ETHERNET: {
			dst = gmplsTypes::ENCODINGTYPE_ETHERNET;
			break;
		}
		case ENCT_ANSI_ETSI_PDH: {
			dst = gmplsTypes::ENCODINGTYPE_ANSI_ETSI_PDH;
			break;
		}
		case ENCT_RESERVED_1: {
			dst = gmplsTypes::ENCODINGTYPE_RESERVED_1;
			break;
		}
		case ENCT_SDH_SONET: {
			dst = gmplsTypes::ENCODINGTYPE_SDH_SONET;
			break;
		}
		case ENCT_RESERVED_2: {
			dst = gmplsTypes::ENCODINGTYPE_RESERVED_2;
			break;
		}
		case ENCT_DIGITAL_WRAPPER: {
			dst = gmplsTypes::ENCODINGTYPE_DIGITAL_WRAPPER;
			break;
		}
		case ENCT_LAMBDA: {
			dst = gmplsTypes::ENCODINGTYPE_LAMBDA;
			break;
		}
		case ENCT_FIBER: {
			dst = gmplsTypes::ENCODINGTYPE_FIBER;
			break;
		}
		case ENCT_RESERVED_3: {
			dst = gmplsTypes::ENCODINGTYPE_RESERVED_3;
			break;
		}
		case ENCT_FIBERCHANNEL: {
			dst = gmplsTypes::ENCODINGTYPE_FIBERCHANNEL;
			break;
		}
		case ENCT_G709_ODU: {
			dst = gmplsTypes::ENCODINGTYPE_G709_ODU;
			break;
		}
		case ENCT_G709_OC: {
			dst = gmplsTypes::ENCODINGTYPE_G709_OC;
			break;
		}
	}

	return dst;
}

std::string &
operator << (std::string &                       dst,
	     const gmplsTypes::encodingType &   src)
{
	std::ostringstream id;

	switch (src) {
		case gmplsTypes::ENCODINGTYPE_PACKET: {
			id << "PACKET";
			break;
		}
		case gmplsTypes::ENCODINGTYPE_ETHERNET: {
			id << "ETHERNET";
			break;
		}
		case gmplsTypes::ENCODINGTYPE_ANSI_ETSI_PDH: {
			id << "ANSI_ETSI_PDH";
			break;
		}
		case gmplsTypes::ENCODINGTYPE_RESERVED_1: {
			id << "RESERVED_1";
			break;
		}
		case gmplsTypes::ENCODINGTYPE_SDH_SONET: {
			id << "SDH_SONET";
			break;
		}
		case gmplsTypes::ENCODINGTYPE_RESERVED_2: {
			id << "RESERVED_2";
			break;
		}
		case gmplsTypes::ENCODINGTYPE_DIGITAL_WRAPPER: {
			id << "DIGITAL_WRAPPER";
			break;
		}
		case gmplsTypes::ENCODINGTYPE_LAMBDA: {
			id << "LAMBDA";
			break;
		}
		case gmplsTypes::ENCODINGTYPE_FIBER: {
			id << "FIBER";
			break;
		}
		case gmplsTypes::ENCODINGTYPE_RESERVED_3: {
			id << "RESERVED_3";
			break;
		}
		case gmplsTypes::ENCODINGTYPE_FIBERCHANNEL: {
			id << "FIBERCHANNEL";
			break;
		}
		case gmplsTypes::ENCODINGTYPE_G709_ODU: {
			id << "G709_ODU";
			break;
		}
		case gmplsTypes::ENCODINGTYPE_G709_OC: {
			id << "G709_OC";
			break;
		}
	}

	dst = id.str();

	return dst;
}

//
// labelState
//
label_state_t &
operator << (label_state_t &                     dst,
	     const gmplsTypes::labelState &     src)
{
	switch (src) {
		case gmplsTypes::LABELSTATE_FREE: {
			dst = LABEL_FREE;
			break;
		}
		case gmplsTypes::LABELSTATE_BOOKED: {
			dst = LABEL_BOOKED;
			break;
		}
		case gmplsTypes::LABELSTATE_XCONNECTED: {
			dst = LABEL_XCONNECTED;
			break;
		}
		case gmplsTypes::LABELSTATE_BUSY: {
			dst = LABEL_BUSY;
			break;
		}
		default:
			throw out_of_range("labelState type out-of-range");
			break;
	}

	return dst;
}

gmplsTypes::labelState &
operator << (gmplsTypes::labelState &     dst,
	     const label_state_t &         src)
{
	switch (src) {
		case LABEL_FREE: {
			dst = gmplsTypes::LABELSTATE_FREE;
			break;
		}
		case LABEL_BOOKED: {
			dst = gmplsTypes::LABELSTATE_BOOKED;
			break;
		}
		case LABEL_XCONNECTED: {
			dst = gmplsTypes::LABELSTATE_XCONNECTED;
			break;
		}
		case LABEL_BUSY: {
			dst = gmplsTypes::LABELSTATE_BUSY;
			break;
		}
		default:
			throw out_of_range("label_state_t type out-of-range");
			break;
	}

	return dst;
}

std::string &
operator << (std::string &                       dst,
	     const gmplsTypes::labelState &     src)
{
	std::ostringstream id;

	switch (src) {
		case gmplsTypes::LABELSTATE_FREE: {
			id << "LABEL_FREE";
			break;
		}
		case gmplsTypes::LABELSTATE_BOOKED: {
			id << "LABEL_BOOKED";
			break;
		}
		case gmplsTypes::LABELSTATE_XCONNECTED: {
			id << "LABEL_XCONNECTED";
			break;
		}
		case gmplsTypes::LABELSTATE_BUSY: {
			id << "LABEL_BUSY";
			break;
		}
		default:
			throw out_of_range("labelState type out-of-range");
			break;
	}

	dst = id.str();

	return dst;
}

//
// sourceId
//
g2mpls_addr_t &  operator<< (g2mpls_addr_t &                   dst,
			     const gmplsTypes::sourceId_var & src)
{
	memset(&dst, 0, sizeof(dst));

	switch (src->_d()) {
		case gmplsTypes::SOURCEIDTYPE_IPV4: {
			dst.type    = IPv4;
			dst.preflen = 32;
			dst.value.ipv4.s_addr = htonl(src->ipv4());
			break;
		}
		case gmplsTypes::SOURCEIDTYPE_IPV6: {
			int    i;

			dst.type    = IPv6;
			dst.preflen = 128;

			for (i = 0; i < 4; i++) {
				dst.value.ipv6.s6_addr32[i] =
					htonl(src->ipv6()[i]);
			}
			break;
		}
		case gmplsTypes::SOURCEIDTYPE_NSAP: {
			int    i;

			dst.type    = NSAP;
			dst.preflen = 160;

			for (i = 0; i < 20; i++) {
				dst.value.nsap.nsap_addr8[i] =
					src->nsap()[i];
			}
			break;
		}
		case gmplsTypes::SOURCEIDTYPE_MAC: {
			// not supported
			break;
		}
		default:
			throw out_of_range("SOURCE ID type out-of-range");
			break;
	}

	return dst;
}

gmplsTypes::sourceId_var & operator<< (gmplsTypes::sourceId_var &  dst,
					const g2mpls_addr_t &        src)
{
	dst = new gmplsTypes::sourceId;

	switch (src.type) {
		case IPv4:
			dst->ipv4(ntohl(src.value.ipv4.s_addr));
			break;
		case IPv6: {
			gmplsTypes::addrIPv6 parts;
			int i;

			for (i = 0; i < 4; i++) {
				parts[i] =
					ntohl(src.value.ipv6.s6_addr32[i]);
			}
			dst->ipv6(parts);
		}
			break;
		case NSAP: {
			gmplsTypes::addrNSAP parts;
			int i;

			for (i = 0; i < 20; i++) {
				parts[i] = src.value.nsap.nsap_addr8[i];
			}
			dst->nsap(parts);
		}
			break;
		default:
			throw out_of_range("sourceId G2.ADDR type "
					   "out-of-range");
			break;
	}

	return dst;
}

std::string & operator<< (std::string &                     dst,
			  const gmplsTypes::sourceId_var & src)
{
	std::ostringstream id;

	dst = std::string("");

	switch (src->_d()) {
		case gmplsTypes::SOURCEIDTYPE_IPV4: {
			ipv4_t addr;

			addr.s_addr = htonl(src->ipv4());
			id << "(IPv4) " << inet_ntoa(addr);
			break;
		}
		case gmplsTypes::SOURCEIDTYPE_IPV6: {
			int    i;

			id << "(IPv6) " ;
			for (i = 0; i < 4; i++) {
				id << std::hex
				   << std::setw(8)
				   << std::setfill('0')
				   << src->ipv6()[i];
			}
			break;
		}
		case gmplsTypes::SOURCEIDTYPE_NSAP: {
			int    i;

			id << "(NSAP) " ;
			for (i = 0; i < 20; i++) {

				id << std::hex
				   << std::setw(2)
				   << std::setfill('0')
				   << (uint32_t) src->nsap()[i];
				if ((i == 0)  | (i == 2)  | (i == 3)  |
				    (i == 6)  | (i == 8)  | (i == 10) |
				    (i == 12) | (i == 18)) {
					id << ".";
				}
			}
			break;
		}
		case gmplsTypes::SOURCEIDTYPE_MAC: {
			int    i;

			id << "(MAC) " ;
			for (i = 0; i < 6; i++) {

				id << std::hex
				   << std::setw(2)
				   << std::setfill('0')
				   << (uint32_t) src->mac()[i];
				if (i != 5) {
					id << ":";
				}
			}
			break;
		}
		default:
			throw out_of_range("SOURCE ID type out-of-range");
			break;
	}

	dst += id.str();

	return dst;
}

//
// tnaId
//
g2mpls_addr_t &  operator<< (g2mpls_addr_t &                dst,
			     const gmplsTypes::tnaId_var & src)
{
	memset(&dst, 0, sizeof(dst));

	switch (src->_d()) {
		case gmplsTypes::TNAIDTYPE_IPV4: {
			dst.type    = IPv4;
			dst.preflen = 32;
			dst.value.ipv4.s_addr = htonl(src->ipv4());
			break;
		}
		case gmplsTypes::TNAIDTYPE_IPV6: {
			int    i;

			dst.type    = IPv6;
			dst.preflen = 128;

			for (i = 0; i < 4; i++) {
				dst.value.ipv6.s6_addr32[i] =
					htonl(src->ipv6()[i]);
			}
			break;
		}
		case gmplsTypes::TNAIDTYPE_NSAP: {
			int    i;

			dst.type    = NSAP;
			dst.preflen = 160;

			for (i = 0; i < 20; i++) {
				dst.value.nsap.nsap_addr8[i] =
					src->nsap()[i];
			}
			break;
		}
		default:
			throw out_of_range("TNA ID type out-of-range");
	}

	return dst;
}

gmplsTypes::tnaId_var & operator<< (gmplsTypes::tnaId_var &   dst,
				     const g2mpls_addr_t &      src)
{
	dst = new gmplsTypes::tnaId;

	switch (src.type) {
		case IPv4:
			dst->ipv4(ntohl(src.value.ipv4.s_addr));
			break;
		case IPv6: {
			gmplsTypes::addrIPv6 parts;
			int i;

			for (i = 0; i < 4; i++) {
				parts[i] =
					ntohl(src.value.ipv6.s6_addr32[i]);
			}
			dst->ipv6(parts);
		}
			break;
		case NSAP: {
			gmplsTypes::addrNSAP parts;
			int i;

			for (i = 0; i < 20; i++) {
				parts[i] = src.value.nsap.nsap_addr8[i];
			}
			dst->nsap(parts);
		}
			break;
		default:
			throw out_of_range("tnaId G2.ADDR type out-of-range");
			break;
	}

	return dst;
}

std::string & operator<< (std::string &                  dst,
			  const gmplsTypes::tnaId_var & src)
{
	std::ostringstream id;

	dst = std::string("");

	switch (src->_d()) {
		case gmplsTypes::TNAIDTYPE_IPV4: {
			ipv4_t addr;

			addr.s_addr = htonl(src->ipv4());
			id << "(TNA-IPv4) " << inet_ntoa(addr);
			break;
		}
		case gmplsTypes::TNAIDTYPE_IPV6: {
			int    i;

			id << "(TNA-IPv6) " ;
			for (i = 0; i < 4; i++) {
				id << std::hex
				   << std::setw(8)
				   << std::setfill('0')
				   << src->ipv6()[i];
			}
			break;
		}
		case gmplsTypes::TNAIDTYPE_NSAP: {
			int    i;

			id << "(TNA-NSAP) " ;
			for (i = 0; i < 20; i++) {

				id << std::hex
				   << std::setw(2)
				   << std::setfill('0')
				   << (uint32_t) src->nsap()[i];
				if ((i == 0)  | (i == 2)  | (i == 3)  |
				    (i == 6)  | (i == 8)  | (i == 10) |
				    (i == 12) | (i == 18)) {
					id << ".";
				}
			}
			break;
		}
		default:
			throw out_of_range("TNA ID type out-of-range");
			break;
	}

	dst += id.str();

	return dst;
}


//
//
// Call attrs operators
//
//
call_ident_t & operator<< (call_ident_t &                     dst,
			   const gmplsTypes::callIdent_var & src)
{
	switch (src->idType) {
		case gmplsTypes::CALLIDTYPE_NULL:
			dst.type = CALLID_NULL;
			break;
		case gmplsTypes::CALLIDTYPE_OPSPEC:
			dst.type = CALLID_OPSPEC;
			break;
		case gmplsTypes::CALLIDTYPE_GLOBUNIQ:
			dst.type = CALLID_GLOBUNIQ;
			break;
		default:
			throw out_of_range("Call type out-of-range");
			break;
	}

	dst.local_id  = src->localId;

	gmplsTypes::sourceId_var lclAddr;
	lclAddr      = src->srcId;
	dst.src_addr << lclAddr;

#if 0
	if (dst.type == CALLID_GLOBUNIQ) {
		dst.itu_country_code |=
			(((uint32_t) src->segs.intlSeg[0]) << 16);
		dst.itu_country_code |=
			(((uint32_t) src->segs.intlSeg[1]) <<  8);
		dst.itu_country_code |=
			(((uint32_t) src->segs.intlSeg[2]) <<  0);
		dst.itu_country_code &= 0x00FFFFFF;

		dst.itu_carrier_code |=
			(((uint64_t) src->segs.natlSeg[0]) << 16);
		dst.itu_carrier_code |=
			(((uint64_t) ((src->segs.natlSeg[1] &
				       0xFFFF0000)) >> 16) << 0);
		dst.itu_carrier_code &= 0x0000FFFFFFFFFFFFull;

		dst.unique_ap |=
			(((uint64_t) ((src->segs.natlSeg[1] &
				       0x0000FFFF)) >> 0) << 32);
		dst.unique_ap |=
			(((uint64_t) src->segs.natlSeg[2]) <<  0);
		dst.unique_ap &= 0x0000FFFFFFFFFFFFull;
	}
#endif // 0

	return dst;
}

gmplsTypes::callIdent_var & operator<<(gmplsTypes::callIdent_var &   dst,
					const call_ident_t &           src)
{
	dst = new gmplsTypes::callIdent;

	switch (src.type) {
		case CALLID_NULL:
			dst->idType = gmplsTypes::CALLIDTYPE_NULL;
			break;
		case CALLID_OPSPEC:
			dst->idType = gmplsTypes::CALLIDTYPE_OPSPEC;
			break;
		case CALLID_GLOBUNIQ:
			dst->idType = gmplsTypes::CALLIDTYPE_GLOBUNIQ;
			break;
		default:
			throw out_of_range("G2.Call type out-of-range");
			break;
	}

	dst->localId  = src.local_id;

	gmplsTypes::sourceId_var lclAddr;
	lclAddr    << src.src_addr;
	dst->srcId  = lclAddr;

#if 0
	if (src.type == CALLID_GLOBUNIQ) {
		dst->segs.intlSeg[0] |=
			(uint8_t) ((src.itu_country_code & 0x00FF0000) >> 16);
		dst->segs.intlSeg[1] |=
			(uint8_t) ((src.itu_country_code & 0x0000FF00) >>  8);
		dst->segs.intlSeg[2] |=
			(uint8_t) ((src.itu_country_code & 0x000000FF) >>  0);

		dst->segs.natlSeg[0] |=
			(uint32_t) ((src.itu_carrier_code &
				     0x0000FFFFFFFF0000ull) >>  16);
		dst->segs.natlSeg[1] |=
			(uint32_t) (((src.itu_carrier_code &
				      0x000000000000FFFFull) >>   0) << 16);
		dst->segs.natlSeg[1] |=
			(uint32_t) (((src.unique_ap &
				      0x0000FFFF00000000ull) >>  32) <<  0);
		dst->segs.natlSeg[2] |=
			(uint32_t) (((src.unique_ap &
				      0x00000000FFFFFFFFull) >>   0) <<  0);
	}
#endif // 0

	return dst;
}

//
//
// Call attrs operators
//
//
call_info_t & operator<<(call_info_t &                        dst,
			 const gmplsTypes::callParams_var &  src)
{
	memset(&dst, 0, sizeof(dst));

	switch (src->typee) {
		case gmplsTypes::CALLTYPE_SPC:
			dst.call_type = CALL_TYPE_SPC;
			break;
		case gmplsTypes::CALLTYPE_PC:
			dst.call_type = CALL_TYPE_PC;
			break;
		case gmplsTypes::CALLTYPE_SC:
			dst.call_type = CALL_TYPE_SC;
			break;
		case gmplsTypes::CALLTYPE_AUTO:
			dst.call_type = CALL_TYPE_AUTO;
			break;
		case gmplsTypes::CALLTYPE_aUGWzUGW:
			dst.call_type = CALL_TYPE_aUGWzUGW;
			break;
		case gmplsTypes::CALLTYPE_aMGTzEGW:
			dst.call_type = CALL_TYPE_aMGTzEGW;
			break;
		case gmplsTypes::CALLTYPE_aUGWzEGW:
			dst.call_type = CALL_TYPE_aUGWzEGW;
			break;
		case gmplsTypes::CALLTYPE_aEGWzMGT:
			dst.call_type = CALL_TYPE_aEGWzMGT;
			break;
		case gmplsTypes::CALLTYPE_aEGWzUGW:
			dst.call_type = CALL_TYPE_aEGWzUGW;
			break;
		case gmplsTypes::CALLTYPE_aEGWzEGW:
			dst.call_type = CALL_TYPE_aEGWzEGW;
			break;
		default:
			throw out_of_range("CALL TYPE out-of-range");
			break;
	}

	dst.call_name    = new std::string(src->name);

	// GNS attributes
	dst.times.start_time = src->times.startTime;
	dst.times.end_time   = src->times.endTime;

	BITMASK_BITSET(dst.mask_,   call_type);
	BITMASK_BITSET(dst.mask_,   call_name);
	BITMASK_BITSET(dst.mask_,   times);

	BITMASK_BITRESET(dst.mask_, iTNA_res);
	BITMASK_BITRESET(dst.mask_, eTNA_res);

	return dst;
}

gmplsTypes::callParams_var & operator<<(gmplsTypes::callParams_var &  dst,
					 const call_info_t &            src)
{
	dst = new gmplsTypes::callParams;

	switch (src.call_type) {
		case CALL_TYPE_SPC:
			dst->typee = gmplsTypes::CALLTYPE_SPC;
			break;
		case CALL_TYPE_PC:
			dst->typee = gmplsTypes::CALLTYPE_PC;
			break;
		case CALL_TYPE_SC:
			dst->typee = gmplsTypes::CALLTYPE_SC;
			break;
		case CALL_TYPE_AUTO:
			dst->typee = gmplsTypes::CALLTYPE_AUTO;
			break;
		case CALL_TYPE_aUGWzUGW:
			dst->typee = gmplsTypes::CALLTYPE_aUGWzUGW;
			break;
		case CALL_TYPE_aMGTzEGW:
			dst->typee = gmplsTypes::CALLTYPE_aMGTzEGW;
			break;
		case CALL_TYPE_aUGWzEGW:
			dst->typee = gmplsTypes::CALLTYPE_aUGWzEGW;
			break;
		case CALL_TYPE_aEGWzMGT:
			dst->typee = gmplsTypes::CALLTYPE_aEGWzMGT;
			break;
		case CALL_TYPE_aEGWzUGW:
			dst->typee = gmplsTypes::CALLTYPE_aEGWzUGW;
			break;
		case CALL_TYPE_aEGWzEGW:
			dst->typee = gmplsTypes::CALLTYPE_aEGWzEGW;
			break;
		default:
			throw out_of_range("CALL TYPE out-of-range");
			break;
	}

	if (src.call_name) {
		dst->name = CORBA::string_dup(src.call_name->c_str());
	}

	// GNS Attributes
	dst->times.startTime = src.times.start_time;
	dst->times.endTime   = src.times.end_time;

	return dst;
}

recovery_info_t & operator<<(recovery_info_t &                        dst,
			     const gmplsTypes::recoveryParams_var &  src)
{
	memset(&dst, 0, sizeof(dst));

	switch (src->recType) {
		case gmplsTypes::RECOVERYTYPE_UNPROTECTED:
			dst.rec_type = RECOVERY_NONE;
			break;
		case gmplsTypes::RECOVERYTYPE_PROTECTION:
			dst.rec_type = RECOVERY_PROTECTION;
			break;
		case gmplsTypes::RECOVERYTYPE_PREPLANNED:
			dst.rec_type = RECOVERY_PREPLANNED;
			break;
		case gmplsTypes::RECOVERYTYPE_OTF:
			dst.rec_type = RECOVERY_ONTHEFLY;
			break;
		case gmplsTypes::RECOVERYTYPE_OTF_REVERTIVE:
			dst.rec_type = RECOVERY_REVERTIVEONTHEFLY;
			break;
		default:
			throw out_of_range("RECOVERY TYPE out-of-range");
			break;
	}

	switch (src->disjType) {
		case gmplsTypes::DISJOINTNESS_NONE:
			dst.disj_type = DISJOINTNESS_NONE;
			break;
		case gmplsTypes::DISJOINTNESS_LINK:
			dst.disj_type = DISJOINTNESS_LINK;
			break;
		case gmplsTypes::DISJOINTNESS_NODE:
			dst.disj_type = DISJOINTNESS_NODE;
			break;
		case gmplsTypes::DISJOINTNESS_SRLG:
			dst.disj_type = DISJOINTNESS_SRLG;
			break;
		default:
			throw out_of_range("DISJOINTNESS type out-of-range");
			break;
	}

	BITMASK_BITSET(dst.mask_, rec_type);
	BITMASK_BITSET(dst.mask_, disj_type);

	return dst;
}



gmplsTypes::recoveryParams_var &
operator<<(gmplsTypes::recoveryParams_var &  dst,
	   const recovery_info_t &            src)
{
	dst = new gmplsTypes::recoveryParams;

	switch (src.rec_type) {
		case RECOVERY_NONE:
			dst->recType = gmplsTypes::RECOVERYTYPE_UNPROTECTED;
			break;
		case RECOVERY_PROTECTION:
			dst->recType = gmplsTypes::RECOVERYTYPE_PROTECTION;
			break;
		case RECOVERY_PREPLANNED:
			dst->recType = gmplsTypes::RECOVERYTYPE_PREPLANNED;
			break;
		case RECOVERY_ONTHEFLY:
			dst->recType = gmplsTypes::RECOVERYTYPE_OTF;
			break;
		case RECOVERY_REVERTIVEONTHEFLY:
			dst->recType = gmplsTypes::RECOVERYTYPE_OTF_REVERTIVE;
			break;
		default:
			throw out_of_range("RECOVERY TYPE out-of-range");
			break;
	}

	switch (src.disj_type) {
		case DISJOINTNESS_NONE:
			dst->disjType = gmplsTypes::DISJOINTNESS_NONE;
			break;
		case DISJOINTNESS_LINK:
			dst->disjType = gmplsTypes::DISJOINTNESS_LINK;
			break;
		case DISJOINTNESS_NODE:
			dst->disjType = gmplsTypes::DISJOINTNESS_NODE;
			break;
		case DISJOINTNESS_SRLG:
			dst->disjType = gmplsTypes::DISJOINTNESS_SRLG;
			break;
		default:
			throw out_of_range("DISJOINTNESS type out-of-range");
			break;
	}

	return dst;
}

//
// lspIdent
//
lsp_ident_t & operator<<(lsp_ident_t &                     dst,
			 const gmplsTypes::lspIdent_var & src)
{
	memset(&dst, 0, sizeof(dst));

	dst.dst_nid    = src->dstNodeId;
	dst.src_nid    = src->srcNodeId;
	dst.tun_id     = src->tunId;
	dst.ext_tun_id = src->extTid;
	dst.lsp_id     = src->lspId;

	return dst;
}

gmplsTypes::lspIdent_var & operator<<(gmplsTypes::lspIdent_var & dst,
				       const lsp_ident_t &         src)
{
	dst = new gmplsTypes::lspIdent;

	dst->dstNodeId   = src.dst_nid;
	dst->srcNodeId   = src.src_nid;
	dst->tunId       = src.tun_id;
	dst->extTid      = src.ext_tun_id;
	dst->lspId       = src.lsp_id;

	return dst;
}

// tnResource
net_res_spec_t &
operator<<(net_res_spec_t &                        dst,
	   const gmplsTypes::tnResource_var &     src)
{
	memset(&dst, 0, sizeof(dst));

	gmplsTypes::TELinkId_var lclTel;
	lclTel   = src->teLink;
	dst.tna << lclTel;
	if (!is_addr_null(dst.tna)) {
		BITMASK_BITSET(dst.mask_, tna);
	}

	gmplsTypes::DLinkId_var lclDl;
	lclDl          = src->dataLink;
	dst.data_link << lclDl;
	if (!is_addr_null(dst.data_link)) {
		BITMASK_BITSET(dst.mask_, data_link);
	}

	gmplsTypes::labelId_var lclLbl;
	//lclLbl      = src->label;      # TODO Damian - find where operator is defined
	dst.label  << lclLbl;
	if (!is_label_null(dst.label)) {
		BITMASK_BITSET(dst.mask_, label);
	}

	return dst;
}

gmplsTypes::tnResource_var &
operator<<(gmplsTypes::tnResource_var &           dst,
	   const net_res_spec_t &                  src)
{
	dst = new gmplsTypes::tnResource;

	gmplsTypes::TELinkId_var  lclTel;
	lclTel << src.tna;
	dst->teLink = lclTel;

	gmplsTypes::DLinkId_var  lclDl;
	lclDl << src.data_link;
	dst->dataLink = lclDl;

	gmplsTypes::labelId_var  lclLbl;
	lclLbl << src.label;
	dst->label = lclLbl;

	return dst;
}


// tnaResource
net_res_spec_t &
operator<<(net_res_spec_t &                         dst,
	   const gmplsTypes::tnaResource_var &     src)
{
	memset(&dst, 0, sizeof(dst));

	gmplsTypes::tnaId_var lclTna;
	lclTna   = src->tna;
	dst.tna << lclTna;
	if (!is_addr_null(dst.tna)) {
		BITMASK_BITSET(dst.mask_, tna);
	}

	gmplsTypes::DLinkId_var lclDl;
	lclDl          = src->dataLink;
	dst.data_link << lclDl;
	if (!is_addr_null(dst.data_link)) {
		BITMASK_BITSET(dst.mask_, data_link);
	}

	gmplsTypes::labelId_var lclLbl;
	//lclLbl      = src->label;        # TODO Damian - find where operator is defined
	dst.label  << lclLbl;
	if (!is_label_null(dst.label)) {
		BITMASK_BITSET(dst.mask_, label);
	}

	return dst;
}

gmplsTypes::tnaResource_var &
operator<<(gmplsTypes::tnaResource_var &           dst,
	   const net_res_spec_t &                   src)
{
	dst = new gmplsTypes::tnaResource;

	gmplsTypes::tnaId_var  lclTna;
	lclTna << src.tna;
	dst->tna = lclTna;

	gmplsTypes::DLinkId_var  lclDl;
	lclDl << src.data_link;
	dst->dataLink = lclDl;

	gmplsTypes::labelId_var  lclLbl;
	lclLbl << src.label;
	dst->label = lclLbl;

	return dst;
}

//
// wdmLambdasBitmap
//
wdm_link_lambdas_bitmap_t &
operator<<(wdm_link_lambdas_bitmap_t &               dst,
	   const gmplsTypes::wdmLambdasBitmap_var & src)
{
	size_t    size;
	uint8_t * mask;

	memset(&dst, 0, sizeof(dst));

	dst.base_lambda_label = src->baseLambda;
	dst.num_wavelengths   = src->numLambdas;

	dst.bitmap_size = (src->numLambdas % 32 ? (src->numLambdas / 32) + 1 :
			   src->numLambdas / 32);

	size = (size_t) (dst.bitmap_size * 4);
	dst.bitmap_word = (uint32_t *) malloc(size);

	mask = (uint8_t *) dst.bitmap_word;

	for (size_t i = 0; i < src->bitmap.length(); i++) {
		*mask = src->bitmap[i];
		mask++;
	}

	return dst;
}

gmplsTypes::wdmLambdasBitmap_var &
operator<<(gmplsTypes::wdmLambdasBitmap_var & dst,
	   const wdm_link_lambdas_bitmap_t &   src)
{
	size_t    size;
	uint8_t * byte;

	dst = new gmplsTypes::wdmLambdasBitmap;

	dst->baseLambda = src.base_lambda_label;
	dst->numLambdas = src.num_wavelengths;

	size = src.bitmap_size * 4;

	gmplsTypes::bitmapSeq_var lambdaBitmap;
	{
		gmplsTypes::bitmapSeq * tmp;
		tmp = new gmplsTypes::bitmapSeq(size);
		if (!tmp) {
			throw out_of_range("Cannot allocate "
					   "gmplsTypes::bitmapSeq");
		}
		lambdaBitmap = tmp;
	}
	lambdaBitmap->length(size);

	byte = (uint8_t *) src.bitmap_word;
	if (byte == NULL) {
		dst->bitmap = lambdaBitmap;
		return dst;
	}

	for (size_t i = 0; i < size; i++) {
		lambdaBitmap[i] = *byte;
		byte++;
	}
	dst->bitmap = lambdaBitmap;

	return dst;
}

//
// errorInfo
//

error_info_t &
operator<<(error_info_t &                           dst,
	   const gmplsTypes::errorInfo_var &       src)
{
	memset(&dst, 0, sizeof(dst));

	dst.flags    = src->stateRemoved ? 0x04 : 0x00;
	dst.err_code = 24;
	dst.err_val  = 1;
	//dst.err_code = src->errorCode;
	//dst.err_val  = src->errorValue;
	dst.node_id  = src->erroredNode;
}

gmplsTypes::errorInfo_var &
operator<<(gmplsTypes::errorInfo_var &             dst,
	   const error_info_t &                     src)
{
	dst = new gmplsTypes::errorInfo;

	dst->errorCode  = gmplsTypes::GRSVPTEERRORCODE_X;
	dst->errorValue = gmplsTypes::GRSVPTEERRORVALUE_X;
	//
	dst->erroredNode  = src.node_id;
	dst->stateRemoved = src.flags & 0x04 ? true : false;
}


#endif // __cpluscplus

#endif // HAVE_OMNIORB
