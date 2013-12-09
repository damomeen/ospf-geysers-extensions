/*
 *  This file is part of phosphorus-g2mpls.
 *
 *  Copyright (C) 2006, 2007, 2008, 2009 Nextworks s.r.l.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as
 *  published by the Free Software Foundation; either version 2.1
 *  of the License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA 02110-1301 USA.
 *
 *  Authors:
 *
 *  Giacomo Bernini       (Nextworks s.r.l.) <g.bernini_at_nextworks.it>
 *  Gino Carrozzo         (Nextworks s.r.l.) <g.carrozzo_at_nextworks.it>
 *  Nicola Ciulli         (Nextworks s.r.l.) <n.ciulli_at_nextworks.it>
 *  Giodi Giorgi          (Nextworks s.r.l.) <g.giorgi_at_nextworks.it>
 *  Francesco Salvestrini (Nextworks s.r.l.) <f.salvestrini_at_nextworks.it>
 */



#include "g2mpls_addr.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>

#ifdef GMPLS

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/*
 * Check if 2 addresses are equal: returns 0 on false, 1 on true
 */
int
addr_equal(const g2mpls_addr_t saddr, g2mpls_addr_t daddr)
{
	if (saddr.type != daddr.type) {
		return 0;
	}

	switch (saddr.type) {

		case IPv4:
			if (saddr.value.ipv4.s_addr ==
			    daddr.value.ipv4.s_addr) {
				return 1;
			}
			break;

		case IPv6:
			if (!memcmp(&saddr.value.ipv6,
				    &daddr.value.ipv6,
				    sizeof(struct in6_addr))) {
				return 1;
			}
			break;

		case UNNUMBERED:
			/* if ((saddr.value.unnum.node_id == */
			/*      daddr.value.unnum.node_id) && */
			/*     (saddr.value.unnum.addr == */
			/*      daddr.value.unnum.addr)) { */
			/*      return 1; */
			/* } */
			if (saddr.value.unnum == daddr.value.unnum) {
				return 1;
			}
			break;

		case NSAP:
			if (!memcmp(&saddr.value.nsap,
				    &daddr.value.nsap,
				    sizeof(nsap__t))) {
				return 1;
			}
			break;
		default:
			break;
	}

	return 0;
}

/*
 * Check if the address is null: returns 0 on false, 1 on true
 */
int
is_addr_null(const g2mpls_addr_t addr)
{
	switch (addr.type) {

		case IPv4:
			if (addr.value.ipv4.s_addr != 0) {
				return 0;
			}
			break;

		case IPv6:
			for(int i = 0; i < 4; i++) {
				if (addr.value.ipv6.s6_addr32[i] != 0) {
					return 0;
				}
			}
			break;

		case UNNUMBERED:
			/* if (addr.value.unnum.addr != 0) { */
			/*	return 0;		     */
			/* }                                 */
			if (addr.value.unnum != 0) {
				return 0;
			}
			break;

		case NSAP:
			for(int i = 0; i < 5; i++) {
				if (addr.value.nsap.nsap_addr32[i] != 0) {
					return 0;
				}
			}
			break;

		default:
			break;
	}

	return 1;
}

const char *
addr_ntoa(const g2mpls_addr_t addr)
{
	int         tmp;
	static char lcl_buffer[512];

	lcl_buffer[0] = 0;

	switch (addr.type) {

		case IPv4:
			tmp = snprintf(lcl_buffer,
				       sizeof(lcl_buffer),
				       "(IPv4) %s/%d",
				       inet_ntoa(addr.value.ipv4),
				       addr.preflen);
			break;

		case IPv6:
			tmp = snprintf(lcl_buffer,
				       sizeof(lcl_buffer),
				       "(IPv6) "
				       "%02x%02x:%02x%02x:%02x%02x:%02x%02x:"
				       "%02x%02x:%02x%02x:%02x%02x:%02x%02x"
				       "/%d",
				       /* GG FIX 2008-11-14 */
				       addr.value.ipv6.s6_addr[0],
				       addr.value.ipv6.s6_addr[1],
				       addr.value.ipv6.s6_addr[2],
				       addr.value.ipv6.s6_addr[3],
				       addr.value.ipv6.s6_addr[4],
				       addr.value.ipv6.s6_addr[5],
				       addr.value.ipv6.s6_addr[6],
				       addr.value.ipv6.s6_addr[7],
				       addr.value.ipv6.s6_addr[8],
				       addr.value.ipv6.s6_addr[9],
				       addr.value.ipv6.s6_addr[10],
				       addr.value.ipv6.s6_addr[11],
				       addr.value.ipv6.s6_addr[12],
				       addr.value.ipv6.s6_addr[13],
				       addr.value.ipv6.s6_addr[14],
				       addr.value.ipv6.s6_addr[15],
				       addr.preflen);
			break;

		case UNNUMBERED: {
			/* ipv4_t nid;                                        */
			/* nid.s_addr = htonl(addr.value.unnum.node_id);      */
			/*						      */
			/* tmp = snprintf(lcl_buffer,			      */
			/*	       sizeof(lcl_buffer),		      */
			/*	       "(UNNUM) node %s / id 0x%08x",	      */
			/*	       inet_ntoa(nid), addr.value.unnum.addr);*/

			tmp = snprintf(lcl_buffer,
				       sizeof(lcl_buffer),
				       "(UNNUM) 0x%08x",
				       addr.value.unnum);
		}
			break;

		case NSAP:
			tmp = snprintf(lcl_buffer,
				       sizeof(lcl_buffer),
				       "(NSAP) "
				       "%02x.%02x%02x."
				       "%02x.%02x%02x%02x."
				       "%02x%02x.%02x%02x.%02x%02x."
				       "%02x%02x%02x%02x%02x%02x.%02x"
				       "/%d",
				       addr.value.nsap.nsap_addr8[0],
				       addr.value.nsap.nsap_addr8[1],
				       addr.value.nsap.nsap_addr8[2],
				       addr.value.nsap.nsap_addr8[3],
				       addr.value.nsap.nsap_addr8[4],
				       addr.value.nsap.nsap_addr8[5],
				       addr.value.nsap.nsap_addr8[6],
				       addr.value.nsap.nsap_addr8[7],
				       addr.value.nsap.nsap_addr8[8],
				       addr.value.nsap.nsap_addr8[9],
				       addr.value.nsap.nsap_addr8[10],
				       addr.value.nsap.nsap_addr8[11],
				       addr.value.nsap.nsap_addr8[12],
				       addr.value.nsap.nsap_addr8[13],
				       addr.value.nsap.nsap_addr8[14],
				       addr.value.nsap.nsap_addr8[15],
				       addr.value.nsap.nsap_addr8[16],
				       addr.value.nsap.nsap_addr8[17],
				       addr.value.nsap.nsap_addr8[18],
				       addr.value.nsap.nsap_addr8[19],
				       addr.preflen);
			break;

		default:
			tmp = snprintf(lcl_buffer,
				       sizeof(lcl_buffer),
				       "==UNKNOWN==");
			break;
	}

	assert(tmp >= 0);
	assert((size_t) tmp < sizeof(lcl_buffer));

	return lcl_buffer;
}


#define INRANGE(X, MIN, MAX)  (((X) >= (MIN)) && ((X) <= (MAX)))

int
addr_in_net(g2mpls_addr_t net, g2mpls_addr_t addr)
{
	if (net.type == addr.type) {
		switch(net.type) {

			case IPv4:
				if (INRANGE(net.preflen,  1, 32) &&
				    INRANGE(addr.preflen, 1, 32) &&
				    (net.preflen <= addr.preflen)) {

					uint32_t byte_mask, hnet, haddr;

					byte_mask =
						(0xFFFFFFFF <<
						 (32 - (net.preflen % 32)));

					hnet  = ntohl(net.value.ipv4.s_addr);
					haddr = ntohl(addr.value.ipv4.s_addr);

					if ((hnet & byte_mask) ==
					    (haddr & byte_mask)) {
						/* addr is in the network */
						return 1;
					}
				}
				break;

			case IPv6:
				if (INRANGE(net.preflen,  1, 128) &&
				    INRANGE(addr.preflen, 1, 128) &&
				    (net.preflen <= addr.preflen)) {
					uint32_t i;
					uint32_t bytes, byte_mask, hnet, haddr;

					bytes = net.preflen/32;
					byte_mask =
						(0xFFFFFFFF <<
						 (32 - net.preflen % 32));

					for (i = 0; i < bytes; i++) {
						if (net.value.
						    ipv6.s6_addr32[i] !=
						    addr.value.
						    ipv6.s6_addr32[i]) {
							break;
						}
					}

					hnet  = ntohl(net.value.ipv6.
						      s6_addr32[i]);
					haddr = ntohl(addr.value.ipv6.
						      s6_addr32[i]);

					if ((i == bytes) &&
					    ((i == 4) ||
					     ((hnet  & byte_mask) &
					      (haddr & byte_mask)))) {
						/* addr is in the network */
						return 1;
					}
				}
				break;

			case UNNUMBERED:
				break;

			case NSAP:
				if (INRANGE(net.preflen,  1, 160) &&
				    INRANGE(addr.preflen, 1, 160) &&
				    (net.preflen <= addr.preflen)) {
					uint32_t i;
					uint32_t bytes, byte_mask, hnet, haddr;

					bytes = net.preflen/32;
					byte_mask =
						(0xFFFFFFFF <<
						 (32 - net.preflen % 32));

					for (i = 0; i < bytes; i++) {
						if (net.value.
						    nsap.nsap_addr32[i] !=
						    addr.value.
						    nsap.nsap_addr32[i]) {
							break;
						}
					}

					hnet  = ntohl(net.value.nsap.
						      nsap_addr32[i]);
					haddr = ntohl(addr.value.nsap.
						      nsap_addr32[i]);

					if ((i == bytes) &&
					    ((i == 5) ||
					     (hnet  & byte_mask) &
					      (haddr & byte_mask))) {
						/* addr is in the network */
						return 1;
					}
				}
				break;

			default:
				return 0;
		}
	}

	return 0;
}

int
addr_gt(g2mpls_addr_t addr1, g2mpls_addr_t addr2)
{
	if (addr1.type == addr2.type) {
		switch(addr1.type) {

			case IPv4:
				if (addr1.value.ipv4.s_addr >
				    addr2.value.ipv4.s_addr) {
					return 1;
				}
				break;

			case IPv6: {
				int i;

				for (i = 0; i < 4; i++ ) {
					if (addr1.value.ipv6.s6_addr32[i] <=
					    addr2.value.ipv6.s6_addr32[i]) {
						return 0;
					}
				}
				return 1;
			}
				break;

			case UNNUMBERED:
				/* if ((addr1.value.unnum.node_id ==  */
				/*      addr2.value.unnum.node_id) && */
				/*     (addr1.value.unnum.addr >      */
				/*      addr2.value.unnum.addr)) {    */
				/*	return 1;		      */
				/* }                                  */
				if (addr1.value.unnum > addr2.value.unnum) {
					return 1;
				}
				break;

			case NSAP: {
				int i;

				for (i = 0; i < 5; i++ ) {
					if (addr1.value.nsap.nsap_addr32[i] <=
					    addr2.value.nsap.nsap_addr32[i]) {
						return 0;
					}
				}
				return 1;
			}
				break;

			default:
				return 0;
		}
	}

	return 0;
}

int
addr_copy(g2mpls_addr_t *daddr, g2mpls_addr_t *saddr)
{
	if (!daddr || !saddr) {
		return 0;
	}

	daddr->type    = saddr->type;
	daddr->preflen = saddr->preflen;

	switch(daddr->type) {

		case IPv4:
			daddr->value.ipv4.s_addr = saddr->value.ipv4.s_addr;
			break;

		case IPv6: {
			int i;

			for(i = 0; i < 4; i++) {
				daddr->value.ipv6.s6_addr32[i] =
					saddr->value.ipv6.s6_addr32[i];
			}
		}
			break;

		case UNNUMBERED:
			/*daddr->value.unnum.node_id =      */
			/*	saddr->value.unnum.node_id; */
			/*daddr->value.unnum.addr =	    */
			/*	saddr->value.unnum.addr;    */
			daddr->value.unnum = saddr->value.unnum;
			break;

		case NSAP: {
			int i;

			for(i = 0; i < 5; i++) {
				daddr->value.nsap.nsap_addr32[i] =
					saddr->value.nsap.nsap_addr32[i];
			}
		}
			break;

		default:
			return 0;
	}

	return 1;
}

int
make_addr(g2mpls_addr_t * dst,
	  addr_type_t     type,
	  void *          value)
{
	if (!value || !dst) {
		return 0;
	}

	dst->type = type;

	switch(dst->type) {

		case IPv4:
			dst->preflen = 32;
			dst->value.ipv4 = *((ipv4_t *)value);
			break;

		case IPv6:
			dst->preflen = 128;
			dst->value.ipv6 = *((ipv6_t *)value);
			break;

		case UNNUMBERED:
			dst->value.unnum = *((unn_t *)value);
			break;

		case NSAP:
			dst->preflen = 160;
			dst->value.nsap = *((nsap__t *)value);
			break;

		default:
			return 0;
	}

	return 1;
}

const char *
numb_htoa(uint32_t numb)
{
	struct in_addr tmp;

	tmp.s_addr = htonl(numb);

	return inet_ntoa(tmp);
}

#endif /* GMPLS */
