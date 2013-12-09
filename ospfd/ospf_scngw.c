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
a *
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

#include "stream.h"
#include "if.h"
#include "log.h"
#include "memory.h"
#include "sockopt.h"
#include "sockunion.h"
#include "hash.h"
#include "checksum.h"
#include "linklist.h"
#include "network.h"

#include "ospfd/ospf_scngw.h"
#include "ospfd/ospf_corba.h"


/* This function receives the SCNGW header in a message from SCNGW server */
static int
recv_hdr(int sock, struct stream *buf, u_int32_t size, int flags)
{
	int nbytes_hdr;

	nbytes_hdr = recv(sock, buf->data, size, flags);
	if (nbytes_hdr < 0) {
		zlog_debug("recv_hdr: error in executing recv: %s", safe_strerror(errno));
	}

	return nbytes_hdr;
}

/* This function receives the body of a message from SCNGW server */
static int
recv_sdu(int sock, struct stream *buf, u_int32_t size, int flags)
{
	int nbytes_msg;

	nbytes_msg = recv(sock, buf->data + SCNGW_HDR_SIZE, size, flags);
	if (nbytes_msg < 0) {
		zlog_debug("recv_msg: error in executing recv: %s", safe_strerror(errno));
	}

	return nbytes_msg;
}

/* This function sends the SCNGW header in a message to SCNGW server */
static int
send_msg(int sock, struct stream *buf, u_int32_t size, int flags)
{
	int nbytes_hdr;

	nbytes_hdr = send(sock, buf->data, size, flags);
	if (nbytes_hdr < 0) {
		zlog_warn("send_hdr: send failed, %s", safe_strerror(errno));
	}
	else if (nbytes_hdr != (int)size) {
		zlog_debug("send_hdr: sent wrong number of bytes, %d instead of %d", nbytes_hdr, (int)size);
	}
	return nbytes_hdr;
}

/* This function adds the IP header to the OSPF SDU */
static void
iphdr_add(struct stream *buff, struct in_addr src, struct in_addr dst, u_int16_t sdu_len)
{
	struct ip iph;

	memset (&iph, 0, sizeof(struct ip));
	iph.ip_hl = sizeof(struct ip) >> 2;
	iph.ip_v = IPVERSION;
	iph.ip_tos = IPTOS_PREC_INTERNETCONTROL;
	iph.ip_len = (iph.ip_hl << 2) + sdu_len;
	iph.ip_off = 0;
	iph.ip_ttl = SCNGW_IP_TTL;
	iph.ip_p = IPPROTO_OSPFIGP;
	iph.ip_src.s_addr = src.s_addr;
	iph.ip_dst.s_addr = dst.s_addr;
	sockopt_iphdrincl_swab_htosys (&iph);
	iph.ip_sum = in_cksum(&iph, iph.ip_hl*4);

	stream_write(buff, (u_char *)&iph, sizeof (struct ip));
}

/* This function extracts the IP header from a packet from SCNGW server */
static struct ip *
iphdr_extract(struct stream *buff)
{
	struct ip *hdr;
	struct ip *ptr;

	hdr = malloc(sizeof(struct ip));
	if (!hdr) {
		zlog_debug("iphdr_extract: malloc() cannot allocate memory");
		exit(1);
	}
	bzero(hdr, sizeof(struct ip));
	ptr = (struct ip *) STREAM_PNT (buff);
	sockopt_iphdrincl_swab_systoh (ptr);
	memcpy(hdr, ptr, sizeof(struct ip));

	buff->endp += (hdr->ip_hl << 2);

	return hdr;
}

/*This function is used to connect OSPF to SCNGW server*/
int
scngw_connect(int sock, client_type_t client, int s_port)
{
	int ret;
	struct sockaddr_in serv;
	struct sockaddr_in local_addr;

	/* Define server address */
	memset (&serv, 0, sizeof(struct sockaddr_in));
	serv.sin_family = AF_INET;
	serv.sin_port   = htons(s_port);

#ifdef HAVE_SIN_LEN
	serv.sin_len = sizeof (struct sockaddr_in);
#endif /* HAVE_SIN_LEN */

	serv.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	/* Bind local socket to a port number */
	local_addr.sin_family      = AF_INET;
	local_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	switch (client) {
		case OSPF_UNI:
			local_addr.sin_port = htons(OSPF_UNI_PORT);
			break;
		case OSPF_INNI:
			local_addr.sin_port = htons(OSPF_INNI_PORT);
			break;
		case OSPF_ENNI:
			local_addr.sin_port = htons(OSPF_ENNI_PORT);
			break;
		default:
			zlog_err("scngw_connect: client %d not supported by SCNGW",
				 client);
			return -1;
	}

	ret = bind(sock, (struct sockaddr *) &local_addr, sizeof(local_addr));
	if (ret < 0) {
		zlog_debug("scngw_connect: Can't bind to local address: %s",
			   safe_strerror(errno));
		return ret;
	}
        /* Connect to scngws*/
	ret = connect(sock, (struct sockaddr *) &serv, sizeof(serv));
	if (ret < 0) {
		zlog_debug("scngw_connect: Can't connect to SCNGWs with fd %d: %s",
			   sock, safe_strerror(errno));
		return ret;
	}

	return ret;
}

/*This function opens the client socket. It's a kind of wrap function of the original net socket opened by client */
static int
scngw_socket(int domain, int type, int sock_proto, client_type_t cl_type, int s_port)
{
	int sock, ret;
	int on = 1;
	int buf_size = MAX_PACKET_SIZE;
	size_t len = sizeof (int);

	sock = socket(domain, type, sock_proto);
	if (sock < 0) {
		zlog_err("scngw_socket: Can't open socket to scngws: %s", safe_strerror(errno));
		return -1;
	}

	ret = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (void *) &on, sizeof (on));
	if (ret < 0) {
		zlog_warn("scngw_socket: Can't set sockopt SO_REUSEADDR to socket %d", sock);
		return -1;
	}
	ret = setsockopt(sock, SOL_SOCKET, SO_SNDBUF, (char *)&buf_size, len);
	if (ret < 0) {
		zlog_debug("scngw_socket: cannot set SO_SNDBUF %s", strerror (errno));
		return -1;
	}
	ret = setsockopt(sock, SOL_SOCKET, SO_RCVBUF, (char *)&buf_size, len);
	if (ret < 0) {
		zlog_debug("scngw_socket: cannot set SO_RCVBUF %s", strerror (errno));
		return -1;
	}

	ret = scngw_connect(sock, cl_type, s_port);
	if (ret < 0) {
		return -1;
	}

	return sock;
}

/* This function is called by OSPF who wants to connect to SCNGW server */
int
scngw_init(client_type_t cl_type)
{
	int sock;
	int server_port;

	zlog_debug("Initializing connection with SCNGW server");

	/* Send registration to SCNGW server via CORBA */
	server_port = scngw_registration(cl_type);
	if (server_port < 0) {
		zlog_err("Cannot send registration to SCNGW server.");
	}

	/* Open socket with SCNGW server */
	sock = scngw_socket(AF_INET, SOCK_STREAM, 0, cl_type, server_port);
	if (sock < 0) {
		zlog_err("Problems in opening socket to SCNGW server.");
		return -1;
	}
	zlog_debug("Connection with SCNGW server done");

	return sock;
}

/* This function adds the SCNGW header to the packet that client sends*/
static int
scngw_hdr_add(struct stream *s, struct in_addr src_addr, struct in_addr dst_addr,
	      u_int32_t sdu_length, client_type_t cl_type)
{
        //zlog_debug("scngw_hrd_add: Value of cl_type is %d, src_addr %x, dst_addr %x",
	//		   cl_type, src_addr.s_addr, dst_addr.s_addr);

	u_int32_t cc = 0;           /* ctrl channel */
	u_int32_t check_assoc = 0;  /* check tel/cc association (must be 0 for OSPF) */

	stream_putl(s, htonl(cl_type));
	stream_put_ipv4(s, src_addr.s_addr);
	stream_put_ipv4(s, dst_addr.s_addr);
	stream_putl(s, htonl(cc));
	stream_putl(s, htonl(check_assoc));
	stream_putl(s, htonl(sdu_length));

	return SCNGW_HDR_SIZE;

}

/* This function reads the SCNGW header of the message received from SCNGWs*/
static int
scngw_hdr_read(struct stream *buf, struct scngw_hdr *hdr)
{
	u_int32_t check_assoc;

	hdr->cl_type  = ntohl(stream_getl(buf));
	hdr->src_addr = stream_get_ipv4(buf);
	hdr->dst_addr = stream_get_ipv4(buf);
	hdr->cc       = ntohl(stream_getl(buf));
	check_assoc   = ntohl(stream_getl(buf)); /* not used in OSPF */
	hdr->sdu_len  = ntohl(stream_getl(buf));

        //zlog_debug("scngw_hrd_read: Value of cl_type is %d, src_addr %x, dst_addr %x",
	//		   hdr->cl_type, hdr->src_addr, hdr->dst_addr);

	return 0;
}

/* This function sends the OSPF packet (with the SCNGW header added) to SCNGWs*/
int
scngw_sendmsg(int sock, const void *sdu, u_int16_t sdu_size,
	      struct in_addr src_addr, struct in_addr dst_addr, client_type_t cl_type)
{
	struct stream *buff;
	size_t size, pckt_size, msg_size, ret;

	pckt_size = sdu_size + sizeof (struct ip);
	msg_size = pckt_size + SCNGW_HDR_SIZE +1;
	buff = stream_new(msg_size);
	stream_reset (buff);
	memset (buff->data, 0, buff->size);

	if (PACKETS_ENCAPSULATED(cl_type)) {
		size = pckt_size;
		scngw_hdr_add(buff, src_addr, dst_addr, size, cl_type);
		iphdr_add(buff, src_addr, dst_addr, sdu_size);
	}
	else {
		size = sdu_size;
		scngw_hdr_add(buff, src_addr, dst_addr, size, cl_type);
	}

	memcpy(buff->data + buff->endp, sdu, sdu_size);
	buff->endp += sdu_size;

	ret = send_msg(sock, buff, SCNGW_HDR_SIZE + size, 0);
	if (ret < 0) {
		stream_free (buff);
		return ret;
	}

	stream_free(buff);

	return ret;
}


/* This function receives the message from SCNGWs containing a client packet (plus SCNGW header) */
int
scngw_recvmsg(void *sdu, int sock, struct ip **iph, size_t size)
{
	int              ret;
	size_t           newsize = size + SCNGW_HDR_SIZE;
	size_t           sdu_size;
	size_t           offset;
	struct stream *  buf;
	struct scngw_hdr scnhdr;

	buf = stream_new(newsize);
	stream_reset(buf);
        memset(buf->data, 0, buf->size);

	ret = recv_hdr(sock, buf, SCNGW_HDR_SIZE, MSG_WAITALL);
	if (ret == 0) {
		zlog_debug("scngw_recvmsg: server shutdown");
		stream_free(buf);
		return 0;
	} else if (ret < 0) {
		stream_free(buf);
		return -1;
	}
	buf->endp += ret;
	memset(&scnhdr, 0, sizeof (struct scngw_hdr));
	scngw_hdr_read(buf, &scnhdr);
	ret = recv_sdu(sock, buf, scnhdr.sdu_len, MSG_WAITALL);
	if (ret == 0) {
		zlog_debug("scngw_recvmsg: server shutdown");
		stream_free(buf);
		return 0;
	} else if (ret < 0) {
		stream_free(buf);
		return -1;
	}
	buf->endp += ret;
	/* reset get pointer */
	stream_set_getp(buf, 0);
	/* get IP header */
	stream_forward_getp(buf, SCNGW_HDR_SIZE);
	*iph = iphdr_extract(buf);
	offset = SCNGW_HDR_SIZE + ((*iph)->ip_hl << 2);
	sdu_size = (*iph)->ip_len - ((*iph)->ip_hl << 2);

	memcpy(sdu, buf->data + offset, sdu_size);
	//s->endp += sdu_size;

	stream_free(buf);

	return sdu_size;
}

/*Function for socket closing*/
void
scngw_close(int sock)
{
	close(sock);
	return;
}
