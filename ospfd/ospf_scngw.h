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


#ifndef _ZEBRA_OSPF_SCNGW_H
#define _ZEBRA_OSPF_SCNGW_H

#ifdef __cplusplus
extern "C" {
#endif

#include "stream.h"

#ifndef IPPROTO_OSPFIGP
#define IPPROTO_OSPFIGP         89
#endif // IPPROTO_OSPFIGP

#ifndef IPPROTO_RSVP
#define IPPROTO_RSVP            46
#endif // IPPROTO_RSVP

#define SCNGW_IP_TTL           100

#define SCNGW_HDR_SIZE         24U

#define SCNGW_PORT           50000

#define OSPF_INNI_PORT       (SCNGW_PORT + 8901)
#define OSPF_UNI_PORT        (SCNGW_PORT + 8902)
#define OSPF_ENNI_PORT       (SCNGW_PORT + 8903)


#define MAX_PACKET_SIZE      65535
#define MAX_RAW_PACKET_SIZE  65535

typedef enum client_type {
        OSPF_UNI  = 4,
        OSPF_INNI = 5,
        OSPF_ENNI = 6
} client_type_t;

#define PACKETS_ENCAPSULATED(X)			\
	(((X) == OSPF_UNI ) ? 1  :		\
	(((X) == OSPF_INNI) ? 1  :		\
	                      0))

/* structure containing the SCNGW header parameters */
struct scngw_hdr {
	client_type_t       cl_type;   /* Client type */
        u_int32_t           src_addr;  /* TE-link local address */
	u_int32_t           dst_addr;  /* TE-link remote address */
	u_int32_t           cc;        /* Control channel */
	u_int32_t           sdu_len;   /* SDU length (bytes) */
};

/* Protoypes */
extern int  scngw_init(client_type_t);
extern int  scngw_sendmsg(int, const void *, u_int16_t, struct in_addr, struct in_addr, client_type_t);
extern int  scngw_recvmsg(void *, int, struct ip **, size_t);
extern void scngw_close(int);


#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_OSPF_SCNGW_H */
