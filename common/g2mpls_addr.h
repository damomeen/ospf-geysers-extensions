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




#ifndef __G2MPLS_ADDR_H__
#define __G2MPLS_ADDR_H__

#include <config.h>
#include <netinet/in.h>

#ifdef GMPLS

typedef struct in_addr  ipv4_t;
/*   struct in_addr {                             */
/*     in_addr_t s_addr;                          */
/*   }                                            */

typedef struct in6_addr ipv6_t;
/*   struct in6_addr {                            */
/*     union {                                    */
/*       uint8_t  u6_addr8[16];                   */
/*       uint16_t u6_addr16[8];                   */
/*       uint32_t u6_addr32[4];                   */
/*     } in6_u;                                   */
/*     #define s6_addr                  in6_u.u6_addr8    */
/*     #define s6_addr16                in6_u.u6_addr16   */
/*     #define s6_addr32                in6_u.u6_addr32   */
/*   }                                            */

/* typedef struct unn_address { */
/*	uint32_t  node_id;      */
/*	uint32_t  addr;         */
/* } unn_t;                     */
typedef uint32_t unn_t;

typedef struct nsap_address {
	union {
		uint8_t  u_addr8[20];
		uint16_t u_addr16[10];
		uint32_t u_addr32[5];
	} nsap_u;
#define nsap_addr8                 nsap_u.u_addr8
#define nsap_addr16                nsap_u.u_addr16
#define nsap_addr32                nsap_u.u_addr32
} nsap__t;

typedef enum addr_type {
	IPv4            = 0x0,
	IPv6            = 0x1,
	UNNUMBERED      = 0x2,
	NSAP            = 0x3
} addr_type_t;

typedef struct address {
	addr_type_t type;

	/* max preflen: 32 if IPv4, 128 if IPv6, 0 if unn, 160 if NSAP*/
	u_int8_t    preflen;

	union {
		ipv4_t    ipv4;
		ipv6_t    ipv6;
		unn_t     unnum;
		nsap__t   nsap;
	} value;
} g2mpls_addr_t;


#ifdef __cplusplus
extern "C" {
#endif

/* Address related functions */
int          is_addr_null(const g2mpls_addr_t addr);
int          addr_equal(const g2mpls_addr_t saddr, g2mpls_addr_t daddr);
int          addr_in_net(g2mpls_addr_t net, g2mpls_addr_t addr);
int          addr_gt(g2mpls_addr_t addr1, g2mpls_addr_t addr2);
int          addr_copy(g2mpls_addr_t *daddr, g2mpls_addr_t *saddr);
const char * addr_ntoa(const g2mpls_addr_t addr);
int          make_addr(g2mpls_addr_t * dst, addr_type_t type, void * value);
const char * numb_htoa(uint32_t numb);

#ifdef __cplusplus
}
#endif

#endif /* GMPLS */

#endif /* __G2MPLS_ADDR_H__ */
