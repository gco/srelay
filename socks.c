/*
  socks.c:
  $Id$

Copyright (C) 2001 Tomo.M (author).
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.
3. Neither the name of the author nor the names of its contributors
   may be used to endorse or promote products derived from this software
   without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

#include "srelay.h"

#define S5REQ_CONN    1
#define S5REQ_BIND    2
#define S5REQ_UDPA    3

#define S5AGRANTED    0
#define S5EGENERAL    1
#define S5ENOTALOW    2
#define S5ENETURCH    3 
#define S5EHOSURCH    4
#define S5ECREFUSE    5
#define S5ETTLEXPR    6
#define S5EUNSUPRT    7
#define S5EUSATYPE    8
#define S5EINVADDR    9

#define S4REQ_CONN    1
#define S4REQ_BIND    2

#define S4AGRANTED    90
#define S4EGENERAL    91
#define S4ECNIDENT    92
#define S4EIVUSRID    93

#define TIMEOUTSEC    30

#define GEN_ERR_REP(s, v) \
    switch ((v)) { \
    case 0x04:\
      socks_rep((s), (v), S4EGENERAL, 0);\
      break;\
    case 0x05:\
      socks_rep((s), (v), S5EGENERAL, 0);\
      break;\
    default:\
      break;\
    }\
    close((s));

#define POSITIVE_REP(s, v, a) \
    switch ((v)) { \
    case 0x04:\
      error = socks_rep((s), (v), S4AGRANTED, (a));\
      break;\
    case 0x05:\
      error = socks_rep((s), (v), S5AGRANTED, (a));\
      break;\
    default:\
      error = -1;\
      break;\
    }\


struct host_info {
  char    host[NI_MAXHOST];
  char    port[NI_MAXSERV];
};

struct req_host_info {
  struct  host_info dest;
  struct  host_info proxy;
};

/* prototypes */
int addr_comp __P((struct bin_addr *, struct bin_addr *, int));
int lookup_tbl __P((struct socks_req *));
int resolv_host __P((struct bin_addr *, u_int16_t, struct host_info *));
int log_request __P((int, struct socks_req *, struct req_host_info *));
int do_bind __P((int, struct addrinfo *, u_int16_t));
int socks_rep __P((int , int , int , struct sockaddr *));
int socks_direct_conn __P((int, struct socks_req *));
int proto_socks4 __P((int));
int proto_socks5 __P((int));
int s5auth_s __P((int));
int s5auth_s_rep __P((int, int));
int s5auth_c __P((int, int));
int proxy_connect __P((int, struct socks_req *));
int connect_to_socks __P((int, struct socks_req *));
int proxy_reply __P((int, int, int, int));

/*
  wait_for_read:
          wait for readable status.
	  descriptor 's' must be in blocking i/o mode.
 */
int wait_for_read(int s, long sec)
{
  fd_set fds;
  int n, nfd;
  struct timeval tv;

  tv.tv_sec = sec;
  tv.tv_usec = 0;

  nfd = s;
  FD_ZERO(&fds); FD_SET(s, &fds);
  n = select(nfd+1, &fds, 0, 0, &tv);
  switch (n) {
  case -1:            /* error */
    return(-1);
  case 0:             /* timed out */
    return(0);
  default:            /* ok */
    if (FD_ISSET(s, &fds))
      return(s);
    else
      return(-1);
  }
}

ssize_t timerd_read(int s, char *buf, size_t len, int sec, int flags)
{
  ssize_t r = -1;
  settimer(sec);
  r = recvfrom(s, buf, len, flags, 0, 0);
  settimer(0);
  return(r);
}

ssize_t timerd_write(int s, char *buf, size_t len, int sec)
{
  ssize_t r = -1;
  settimer(sec);
  r = sendto(s, buf, len, 0, 0, 0);
  settimer(0);
  return(r);
}

int addr_comp(struct bin_addr *a1, struct bin_addr *a2, int mask)
{
  int    ret = -1;
  struct in6_addr in6addr_any = IN6ADDR_ANY_INIT;
  struct in_addr  inaddr_any;

  inaddr_any.s_addr = INADDR_ANY;

  if (a1->atype != a2->atype)
    return -1;             /* address type mismatched */

  /* if a2 entry is wildcard, every thing is matched */
  switch (a1->atype) {
  case S5ATIPV4:
    if (memcmp(a2->v4_addr,
	       &inaddr_any, sizeof inaddr_any) == 0)
      return 0;
    break;
  case S5ATIPV6:
    if (memcmp(a2->v6_addr,
	       &in6addr_any, sizeof in6addr_any) == 0)
      return 0;
    break;
  case S5ATFQDN:
    if (strncmp(a2->fqdn, "*", sizeof("*")) == 0)
      return 0;
    break;
  default:
    break;
  }
    
  if (mask == 0) {  /* no need to process mask */
    switch (a1->atype) {
    case S5ATIPV4:
      if (memcmp(a2->v4_addr, a1->v4_addr, sizeof(struct in_addr)) == 0)
	return 0;
      break;
    case S5ATIPV6:
      if (memcmp(a2->v6_addr, a1->v6_addr, sizeof(struct in6_addr)) == 0)
	if (a2->v6_scope == a1->v6_scope)
	  return 0;
      break;
    case S5ATFQDN:
      if ( a1->len_fqdn < a2->len_fqdn )
	break;
      if (strncasecmp(a2->fqdn,
		      &(a1->fqdn[a1->len_fqdn - a2->len_fqdn]),
		      a2->len_fqdn) == 0)
	return 0;
      break;
    default:
      break;
    }
    return -1;
  } else {
    /* process address mask */
    switch (a1->atype) {
    case S5ATIPV4:
      /* sanity check */
      if (mask < 1 || mask > 32) {
	ret = -1;
      } else {
	u_int32_t smask;
	struct in_addr sin1, sin2;
	smask = ( 0xffffffff << (32-mask) ) & 0xffffffff;
	memcpy(&sin1, a1->v4_addr, sizeof(struct in_addr));
	memcpy(&sin2, a2->v4_addr, sizeof(struct in_addr));
	sin1.s_addr &= htonl(smask);
	sin2.s_addr &= htonl(smask);
	ret = memcmp(&sin1, &sin2, sizeof(struct in_addr));
      }
      break;
      
    case S5ATIPV6:
      if (a2->v6_scope != a1->v6_scope) {
	ret = -1;
	break;
      }
      if (mask < 1 || mask > 128) {
	ret = -1;
      } else {
	u_int16_t  f, r, smask;
	int      i;
	struct in6_addr sin1, sin2;
	
	f = mask / 8;
	r = mask % 8;
	if ( f > 16 ) { /* ??? why ??? */
	  f = 16; r = 0;
	}
	memcpy(&sin1, a1->v6_addr, sizeof(struct in6_addr));
	memcpy(&sin2, a2->v6_addr, sizeof(struct in6_addr));
	ret = 0;
	for (i=0; i<f; i++) {
	  if (sin1.s6_addr[i] != sin2.s6_addr[i]) {
	    ret = -1;
	    break;
	  }
	}
	if (ret == 0) {
	  if (f < 16 && r > 0) {
	    smask = (0xff << (8-r)) & 0xff;
	    sin1.s6_addr[f] &= smask;
	    sin2.s6_addr[f] &= smask;
	    ret = memcmp(&sin1, &sin2, sizeof(struct in6_addr));
	  }
	}
      }
      break;

    default:
      ret = -1;
    }
    if (ret == 0)
      return 0;
  }
  return -1;
}

int lookup_tbl(struct socks_req *req)
{
  int    i, match, error;
  struct addrinfo hints, *res, *res0;
  char   name[NI_MAXHOST];
  struct bin_addr addr;
  struct sockaddr_in  *sa;
  struct sockaddr_in6 *sa6;

  match = 0;
  for (i=0; i < proxy_tbl_ind; i++) {
    /* check atype */
    if ( req->dest.atype != proxy_tbl[i].dest.atype )
      continue;
    /* check destination port */
    if ( req->port < proxy_tbl[i].port_l
	 || req->port > proxy_tbl[i].port_h)
      continue;

    if (addr_comp(&(req->dest), &(proxy_tbl[i].dest),
		  proxy_tbl[i].mask) == 0) {
      match++;
      break;
    }
  }

  if ( !match && req->dest.atype == S5ATFQDN ) {
    /* fqdn 2nd stage: try resolve and lookup */

    strncpy(name, req->dest.fqdn, req->dest.len_fqdn);
    name[req->dest.len_fqdn] = '\0';
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    error = getaddrinfo(name, NULL, &hints, &res0);

    if ( !error ) {
      for (res = res0; res; res = res->ai_next) {
	for (i = 0; i < proxy_tbl_ind; i++) {
	  /* check destination port */
	  if ( req->port < proxy_tbl[i].port_l
	       || req->port > proxy_tbl[i].port_h)
	    continue;

	  memset(&addr, 0, sizeof(addr));
	  switch (res->ai_family) {
	  case AF_INET:
	    addr.atype = S5ATIPV4;
	    sa = (struct sockaddr_in *)res->ai_addr;
	    memcpy(addr.v4_addr,
		   &sa->sin_addr, sizeof(struct in_addr));
	    break;
	  case AF_INET6:
	    addr.atype = S5ATIPV6;
	    sa6 = (struct sockaddr_in6 *)res->ai_addr;
	    memcpy(addr.v6_addr,
		   &sa6->sin6_addr, sizeof(struct in6_addr));
	    addr.v6_scope = sa6->sin6_scope_id;
	    break;
	  default:
	    addr.atype = -1;
	    break;
	  }
	  if ( addr.atype != proxy_tbl[i].dest.atype )
	    continue;
	  if (addr_comp(&addr, &(proxy_tbl[i].dest),
			proxy_tbl[i].mask) == 0)
	    match++;
	  break;
	}
	if ( match )
	  break;
      }
      freeaddrinfo(res0);
    }
  }
  if (match)
    return(i);
  else
    return(proxy_tbl_ind);
}

int resolv_host(struct bin_addr *addr, u_int16_t port, struct host_info *info)
{
  struct  sockaddr_storage ss;
  struct  sockaddr_in  *sa;
  struct  sockaddr_in6 *sa6;
  int     error = 0;
  int     len;

  len = sizeof(ss);
  memset(&ss, 0, len);
  switch (addr->atype) {
  case S5ATIPV4:
    len = sizeof(struct sockaddr_in);
    sa = (struct sockaddr_in *)&ss;
#ifdef HAVE_SOCKADDR_SA_LEN
    sa->sin_len = len;
#endif
    sa->sin_family = AF_INET;
    memcpy(&(sa->sin_addr), addr->v4_addr, sizeof(struct in_addr));
    sa->sin_port = htons(port);
    break;
  case S5ATIPV6:
    len = sizeof(struct sockaddr_in6);
    sa6 = (struct sockaddr_in6 *)&ss;
#ifdef HAVE_SOCKADDR_SA_LEN
    sa6->sin6_len = len;
#endif
    sa6->sin6_family = AF_INET6;
    memcpy(&(sa6->sin6_addr), addr->v6_addr, sizeof(struct in6_addr));
    sa6->sin6_scope_id = addr->v6_scope;
    sa6->sin6_port = htons(port);
    break;
  case S5ATFQDN:
    len = sizeof(struct sockaddr_in);
    sa = (struct sockaddr_in *)&ss;
#ifdef HAVE_SOCKADDR_SA_LEN
    sa->sin_len = len;
#endif
    sa->sin_family = AF_INET;
    sa->sin_port = htons(port);
    break;
  default:
    break;
  }
  if (addr->atype == S5ATIPV4 || addr->atype == S5ATIPV6) {
    error = getnameinfo((struct sockaddr *)&ss, len,
			info->host, sizeof(info->host),
			info->port, sizeof(info->port),
			NI_NUMERICHOST | NI_NUMERICSERV);
  } else if (addr->atype == S5ATFQDN) {
    error = getnameinfo((struct sockaddr *)&ss, len,
			NULL, 0,
			info->port, sizeof(info->port),
			NI_NUMERICSERV);
    strncpy(info->host, addr->fqdn, addr->len_fqdn);
    info->host[addr->len_fqdn] = '\0';
  } else {
    strcpy(info->host, "?");
    strcpy(info->port, "?");
    error++;
  }
  return(error);
}

/*
  log_request:
*/
int log_request(int v, struct socks_req *req, struct req_host_info *info)
{
  struct  sockaddr_storage ss;
  struct  host_info client;
  int     error = 0;
  char    user[256];
  char    *ats[] =  {"ipv4", "fqdn", "ipv6", "?"};
  char    *reqs[] = {"CON", "BND", "UDP", "?"};
  int     atmap[] = {3, 0, 3, 1, 2};
  int     reqmap[] = {3, 0, 1, 2};
  int     len;
  int     direct = 0;

  len = sizeof(ss);
  if (getpeername(req->s, (struct sockaddr *)&ss, &len) != 0) {
    strncpy(client.host, "?", sizeof(client.host));
    strncpy(client.port, "?", sizeof(client.port));
    error++;
  } else {
    error += getnameinfo((struct sockaddr *)&ss, len,
			client.host, sizeof(client.host),
			client.port, sizeof(client.port),
			NI_NUMERICHOST | NI_NUMERICSERV);
  }

  strncpy(user, req->user, req->u_len);
  user[req->u_len] = '\0';

  if (req->tbl_ind == proxy_tbl_ind ||
      proxy_tbl[req->tbl_ind].port == 0) {
    direct = 1;
  }

  msg_out(norm, "%s:%s %d-%s %s:%s(%s) %s %s%s:%s.",
		client.host, client.port,
		v, reqs[reqmap[req->req]],
	        info->dest.host, info->dest.port,
		ats[atmap[req->dest.atype]],
	        user,
		direct ? "direct" : "relay=",
	        info->proxy.host, info->proxy.port );
  return(error);
}

int bind_sock(int s, struct socks_req *req, struct addrinfo *ai)
{
  /*
    BIND port selection priority.
    1. requested port. (assuming dest->sin_port as requested port)
    2. clients src port.
    3. free port.
  */
  struct sockaddr_storage ss;
  struct sockaddr_in  *sa;
  struct sockaddr_in6 *sa6;
  u_int16_t  port;
  size_t     len;

  /* try requested port */
  if (do_bind(s, ai, req->port) == 0)
    return 0;

  /* try same port as client's */
  len = sizeof(ss);
  memset(&ss, 0, len);
  if (getpeername(req->s, (struct sockaddr *)&ss, &len) != 0)
    port = 0;
  else {
    switch (ss.ss_family) {
    case AF_INET:
      sa = (struct sockaddr_in *)&ss;
      port = ntohs(sa->sin_port);
      break;
    case AF_INET6:
      sa6 = (struct sockaddr_in6 *)&ss;
      port = ntohs(sa6->sin6_port);
      break;
    default:
      port = 0;
    }
  }
  if (do_bind(s, ai, port) == 0)
    return 0;

  /*  bind free port */
  return(do_bind(s, ai, 0));
}

int do_bind(int s, struct addrinfo *ai, u_int16_t p)
{
  u_int16_t port = p;  /* Host Byte Order */
  int       r;
  struct sockaddr_in  *sa;
  struct sockaddr_in6 *sa6;

  if ( bind_restrict && port < IPPORT_RESERVEDSTART)
    port = 0;

  switch (ai->ai_family) {
  case AF_INET:
    sa = (struct sockaddr_in *)ai->ai_addr;
    sa->sin_port = htons(port);
    break;
  case AF_INET6:
    sa6 = (struct sockaddr_in6 *)ai->ai_addr;
    sa6->sin6_port = htons(port);
    break;
  default:
    /* unsupported */
    return(-1);
  }

#ifdef IPV6_V6ONLY
  {
    int    on = 1;
    if (ai->ai_family == AF_INET6 &&
	setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY,
		   &on, sizeof(on)) < 0)
      return -1;
  }
#endif

  if (port > 0 && port < IPPORT_RESERVED)
    setreuid(PROCUID, 0);
  r = bind(s, ai->ai_addr, ai->ai_addrlen);
  setreuid(0, PROCUID);
  return(r);
}

int socks_rep(int s, int ver, int code, struct sockaddr *addr)
{
  struct sockaddr_in  *sa;
  struct sockaddr_in6 *sa6;
  u_char     buf[512];
  int        len, r, rcode = 0;

  switch (ver) {
  case 0x04:
    switch (code) {
    case S4AGRANTED:
      buf[0] = 0;
      buf[1] = code;   /* succeeded */
      sa = (struct sockaddr_in *)addr;
      memcpy(&buf[2], &(sa->sin_port), 2);
      memcpy(&buf[4], &(sa->sin_addr), 4);
      len = 8;
      break;

    default:  /* error cases */
      memset(buf, 0, sizeof(buf));
      buf[0] = ver;
      buf[1] = code;   /* error code */
      len = 8;
      break;
    }
    break;

  case 0x05:
    switch (code) {
    case S5AGRANTED:
      buf[0] = ver;
      buf[1] = code;   /* succeeded */
      buf[2] = 0;
      switch (addr->sa_family) {
      case AF_INET:
	buf[3] = S5ATIPV4;
	sa = (struct sockaddr_in *)addr;
	memcpy(&buf[4], &(sa->sin_addr), sizeof(struct in_addr));
	memcpy(&buf[8], &(sa->sin_port), 2);
	len = 4+4+2;
	break;
      case AF_INET6:
	buf[3] = S5ATIPV6;
	sa6 = (struct sockaddr_in6 *)addr;
	memcpy(&buf[4], &(sa6->sin6_addr), sizeof(struct in6_addr));
	memcpy(&buf[20], &(sa6->sin6_port), 2);
	len = 4+16+2;
	break;
      default:
	len = 0;
	break;
      }
      break;

    default:  /* error cases */
      memset(buf, 0, sizeof(buf));
      buf[0] = ver;
      buf[1] = code & 0xff;   /* error code */
      buf[2] = 0;
      buf[3] = 0x01;  /* addr type fixed to IPv4 */
      len = 10;
      break;
    }
    break;

  default:
    /* unsupported socks version */
    len = 0;
    break;
  }
  if (len > 0)
    r = timerd_write(s, buf, len, TIMEOUTSEC);
  else
    r = -1;
  if (r < len)
    rcode = -1;

  return (rcode);
}

/*
  proto_socks:
               handle socks protocol.
*/
int proto_socks(int s)
{
  u_char buf[128];
  int r;
  int on = 1;

  r = timerd_read(s, buf, sizeof(buf), TIMEOUTSEC, MSG_PEEK);
  if ( r <= 0 ) {
    close(s);
    return(-1);
  }

  switch (buf[0]) {
  case 4:
    if (method_num > 0) {
      /* this implies this server is working in V5 mode */
      socks_rep(s, 4, S4EGENERAL, 0);
      msg_out(warn, "V4 request is not accepted.");
      r = -1;
    } else {
      r = proto_socks4(s);
    }
    break;
  case 5:
    if ((r = s5auth_s(s)) == 0) {
      r = proto_socks5(s);
    }
    break;
  default:
    r = -1;
  }

  if (r > 0) {
    setsockopt(r, SOL_SOCKET, SO_REUSEADDR, (char *)&on, sizeof on);
#ifdef FREEBSD
    setsockopt(r, SOL_SOCKET, SO_REUSEPORT, (char *)&on, sizeof on);
#endif
    setsockopt(r, IPPROTO_TCP, TCP_NODELAY, (char *)&on, sizeof on);
  }
  return(r);   /* connected socket descriptor/err(-1) */
}

/*  socks4 protocol functions */
/*
  proto_socks4:
           handle socks v4/v4a protocol.
*/
int proto_socks4(int s)
{
  u_char  buf[512];
  int     r, len;
  struct  socks_req req;

  memset(&req, 0, sizeof(req));
  req.s = s;

  r = timerd_read(s, buf, 1+1+2+4, TIMEOUTSEC, 0);
  if (r < 1+1+2+4) {    /* cannot read request */
    GEN_ERR_REP(s, 4);
    return(-1);
  }
  if ( buf[0] != 0x04 ) {
    /* wrong version request (why ?) */
    GEN_ERR_REP(s, 4);
    return(-1);
  }
  req.req = buf[1];

  /* check if request has socks4-a domain name format */
  if ( buf[4] == 0 && buf[5] == 0 &&
       buf[6] == 0 && buf[7] != 0 ) {
    req.dest.atype = S4ATFQDN;
  } else {
    req.dest.atype = S4ATIPV4;
  }

  req.port = buf[2] * 0x100 + buf[3];

  if (req.dest.atype == S4ATIPV4) {
    memcpy(req.dest.v4_addr, &buf[4], 4);
  }
  
  /* read client user name in request */
  r = timerd_read(s, buf, sizeof(buf), TIMEOUTSEC, MSG_PEEK);
  if ( r < 1 ) {
    /* error or client sends EOF */
    GEN_ERR_REP(s, 4);
    return(-1);
  }
  /* buf could contains
          username '\0'
      or,
          username '\0' hostname '\0'
  */
  r = strlen(buf);        /* r should be 0 <= r <= 255 */
  if (r < 0 || r > 255) {
    /* invalid username length */
    GEN_ERR_REP(s, 4);
    return(-1);
  }

  r = timerd_read(s, buf, r+1, TIMEOUTSEC, 0);
  if ( r > 0 && r <= 255 ) {    /* r should be 1 <= r <= 255 */
    len = r - 1;
    req.u_len = len;
    memcpy(&(req.user), buf, len);
    req.user[len] = '\0';
  } else {
    /* read error or something */
    GEN_ERR_REP(s, 4);
    return(-1);
  }

  if ( req.dest.atype == S4ATFQDN ) {
    /* request is socks4-A specific */
    r = timerd_read(s, buf, sizeof buf, TIMEOUTSEC, 0);
    if ( r > 0 && r <= 256 ) {   /* r should be 1 <= r <= 256 */
      len = r - 1;
      req.dest.len_fqdn = len;
      memcpy(req.dest.fqdn, buf, len);
      req.dest.fqdn[len] = '\0';
    } else {
      /* read error or something */
      GEN_ERR_REP(s, 4);
      return(-1);
    }
  }

  req.tbl_ind = lookup_tbl(&req);
  if (req.tbl_ind == proxy_tbl_ind ||             /* do default */
      proxy_tbl[req.tbl_ind].port == 0) {
    return(socks_direct_conn(4, &req));
  }
  return(proxy_connect(4, &req));
}


/* socks5 protocol functions */
int proto_socks5(int s)
{
  u_char    buf[512];
  int     r, len;
  struct  socks_req req;

  memset(&req, 0, sizeof(req));
  req.s = s;

  /* peek first 5 bytes of request. */
  r = timerd_read(s, buf, sizeof(buf), TIMEOUTSEC, MSG_PEEK);
  if ( r < 5 ) {
    /* cannot read client request */
    close(s);
    return(-1);
  }

  if ( buf[0] != 0x05 ) {
    /* wrong version request */
    GEN_ERR_REP(s, 5);
    return(-1);
  }

  req.req = buf[1];
  req.dest.atype = buf[3];  /* address type field */

  switch(req.dest.atype) {
  case S5ATIPV4:  /* IPv4 address */
    r = timerd_read(s, buf, 4+4+2, TIMEOUTSEC, 0);
    if (r < 4+4+2) {     /* cannot read request (why?) */
      GEN_ERR_REP(s, 5);
      return(-1);
    }
    memcpy(req.dest.v4_addr, &buf[4], sizeof(struct in_addr));
    req.port = buf[8] * 0x100 + buf[9];
    break;

  case S5ATIPV6:
    r = timerd_read(s, buf, 4+16+2, TIMEOUTSEC, 0);
    if (r < 4+16+2) {     /* cannot read request (why?) */
      GEN_ERR_REP(s, 5);
      return(-1);
    }
    memcpy(req.dest.v6_addr, &buf[4], sizeof(struct in6_addr));
    req.port = buf[20] * 0x100 + buf[21];
    break;

  case S5ATFQDN:  /* string or FQDN */
    if ((len = buf[4]) < 0 || len > 255) {
      /* invalid length */
      socks_rep(s, 5, S5EINVADDR, 0);
      close(s);
      return(-1);
    }
    r = timerd_read(s, buf, 4+1+len+2, TIMEOUTSEC, 0);
    if ( r < 4+1+len+2 ) {  /* cannot read request (why?) */
      GEN_ERR_REP(s, 5);
      return(-1);
    }
    memcpy(req.dest.fqdn, &buf[5], len);
    req.dest.len_fqdn = len;
    req.port = buf[4+1+len] * 0x100 + buf[4+1+len+1];
    break;

  default:
    /* unsupported address */
    socks_rep(s, 5, S5EUSATYPE, 0);
    close(s);
    return(-1);
  }

  req.tbl_ind = lookup_tbl(&req);
  if (req.tbl_ind == proxy_tbl_ind ||                 /* do default */
      proxy_tbl[req.tbl_ind].port == 0) {
    return(socks_direct_conn(5, &req));
  }
  return(proxy_connect(5, &req));
}

/*
  socks5 auth negotiation as server.
*/
int s5auth_s(int s)
{
  u_char buf[512];
  int r, i, j, len;
  int method=0, done=0;

  /* auth method negotiation */
  r = timerd_read(s, buf, 2, TIMEOUTSEC, 0);
  if ( r < 2 ) {
    /* cannot read */
    s5auth_s_rep(s, S5ANOTACC);
    return(-1);
  }

  len = buf[1];
  if ( len < 0 || len > 255 ) {
    /* invalid number of methods */
    s5auth_s_rep(s, S5ANOTACC);
    return(-1);
  }

  r = timerd_read(s, buf, len, TIMEOUTSEC, 0);
  if (method_num == 0) {
    for (i = 0; i < r; i++) {
      if (buf[i] == S5ANOAUTH) {
	method = S5ANOAUTH;
	done = 1;
	break;
      }
    }
  } else {
    for (i = 0; i < method_num; i++) {
      for (j = 0; j < r; j++) {
	if (buf[j] == method_tab[i]){
	  method = method_tab[i];
	  done = 1;
	  break;
	}
      }
      if (done)
	break;
    }
  }
  if (!done) {
    /* no suitable method found */
    method = S5ANOTACC;
  }

  if (s5auth_s_rep(s, method) < 0)
    return(-1);

  switch (method) {
  case S5ANOAUTH:
    /* heh, do nothing */
    break;
  case S5AUSRPAS:
    if (auth_pwd_server(s) == 0) {
      break;
    } else {
      close(s);
      return(-1);
    }
  default:
    /* other methods are unknown or not implemented */
    close(s);
    return(-1);
  }
  return(0);
}

/*
  Auth method negotiation reply
*/
int s5auth_s_rep(int s, int method)
{
  u_char buf[2];
  int r;

  /* reply to client */
  buf[0] = 0x05;   /* socks version */
  buf[1] = method & 0xff;   /* authentication method */
  r = timerd_write(s, buf, 2, TIMEOUTSEC);
  if (r < 2) {
    /* write error */
    close(s);
    return(-1);
  }
  return(0);
}

/*
  socks5 auth negotiation as client.
*/
int s5auth_c(int s, int ind)
{
  u_char buf[512];
  int r;

  /* auth method negotiation */
  buf[0] = 0x05;
  buf[1] = 2;           /* number of methods.*/
  buf[2] = S5ANOAUTH;   /* no authentication */
  buf[3] = S5AUSRPAS;   /* username/passwd authentication */
  r = timerd_write(s, buf, 4, TIMEOUTSEC);
  if ( r < 4 ) {
    /* cannot write */
    close(s);
    return(-1);
  }

  r = timerd_read(s, buf, 2, TIMEOUTSEC, 0);
  if ( r < 2 ) {
    /* cannot read */
    close(s);
    return(-1);
  }
  if (buf[0] == 0x05 && buf[1] == 0) {
    /* no auth method is accepted */
    return(0);
  }
  if (buf[0] == 0x05 && buf[1] == 2) {
    /* do username/passwd authentication */
    return(auth_pwd_client(s, ind));
  }
  /* auth negotiation failed */
  return(-1);
}

int socks_direct_conn(int ver, struct socks_req *req)
{
  int    cs, acs = 0;
  int    len;
  struct addrinfo hints, *res, *res0;
  struct addrinfo ba;
  struct sockaddr_storage ss;
  struct req_host_info info;
  int    error = 0;
  int    save_errno = 0;

  /* proxy_XX is N/A */
  strcpy(info.proxy.host, "-");
  strcpy(info.proxy.port, "-");
  /* resolve addresses in request and log it */
  error = resolv_host(&req->dest, req->port, &info.dest);
  error += log_request(ver, req, &info);

  if (error) {   /* error in name resolve */
    GEN_ERR_REP(req->s, ver);
    return(-1);
  }

  /* process direct connect/bind to destination */

  /* process by_command request */
  switch (req->req) {   /* request */
  case S5REQ_CONN:
    /* string addr => addrinfo */
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    error = getaddrinfo(info.dest.host, info.dest.port, &hints, &res0);
    if (error) {
      /* getaddrinfo error */
      GEN_ERR_REP(req->s, ver);
      return(-1);
    }
    cs = -1;
    for (res = res0; res; res = res->ai_next) {
      save_errno = 0;
      cs = socket(res->ai_family,
                  res->ai_socktype, res->ai_protocol);
      if ( cs < 0 ) {
        /* socket error */
        continue;
      }

      if (connect(cs, res->ai_addr, res->ai_addrlen) < 0) {
        /* connect fail */
	save_errno = errno;
        close(cs);
        continue;
      }
      len = sizeof(ss);
      if (getsockname(cs, (struct sockaddr *)&ss, &len) < 0) {
	save_errno = errno;
	close(cs);
	continue;
      }
      break;
    }
    freeaddrinfo(res0);
    if (cs < 0 || save_errno != 0) {
      /* any socket error */
      switch (ver) {
      case 0x04:
	socks_rep(req->s, 4, S4EGENERAL, 0);
	break;
      case 0x05:
	switch(save_errno) {
	case ENETUNREACH:  socks_rep(req->s, 5, S5ENETURCH, 0); break;
	case ECONNREFUSED: socks_rep(req->s, 5, S5ECREFUSE, 0); break;
#ifndef _POSIX_SOURCE
	case EHOSTUNREACH: socks_rep(req->s, 5, S5EHOSURCH, 0); break;
#endif
	case ETIMEDOUT:    socks_rep(req->s, 5, S5ETTLEXPR, 0); break; /* ??? */
	default:           socks_rep(req->s, 5, S5EGENERAL, 0); break;
	}
	break;
      default:
	break;
      }
      close(req->s);
      return(-1);
    }
    break;

  case S5REQ_BIND:
    memset(&ba, 0, sizeof(ba));
    memset(&ss, 0, sizeof(ss));
    ba.ai_addr = (struct sockaddr *)&ss;
    ba.ai_addrlen = sizeof(ss);
    /* just one address can be stored */
    error = get_bind_addr(req, &ba);
    if (error) {
      GEN_ERR_REP(req->s, ver);
      return(-1);
    }
    acs = -1;
    acs = socket(ba.ai_family, ba.ai_socktype, ba.ai_protocol);
    if (acs < 0) {
      /* socket error */
      GEN_ERR_REP(req->s, ver);
      return(-1);
    }

    if (bind_sock(acs, req, &ba) != 0) {
      GEN_ERR_REP(req->s, ver);
      return(-1);
    }

    listen(acs, 64);
    /* get my socket name again to acquire an
       actual listen port number */
    len = sizeof(ss);
    if (getsockname(acs, (struct sockaddr *)&ss, &len) == -1) {
      /* getsockname failed */
      GEN_ERR_REP(req->s, ver);
      close(acs);
      return(-1);
    }

    /* first reply for bind request */
    POSITIVE_REP(req->s, ver, (struct sockaddr *)&ss);
    if ( error < 0 ) {
      /* could not reply */
      close(req->s);
      close(acs);
      return(-1);
    }
    if (wait_for_read(acs, TIMEOUTSEC) <= 0) {
      GEN_ERR_REP(req->s, ver);
      close(acs);
      return(-1);
    }
      
    len = sizeof(ss);
    if ((cs = accept(acs, (struct sockaddr *)&ss, &len)) < 0) {
      GEN_ERR_REP(req->s, ver);
      close(acs);
      return(-1);
    }
    close(acs); /* accept socket is not needed
		   any more, for current socks spec. */
    /* sock name is in ss */
    /* TODO:
     *  we must check ss against req->dest here for security reason
     */
    /* XXXXX */
    break;

  default:
    /* unsupported request */
    switch (ver) {
    case 0x04:
      socks_rep(req->s, 4, S4EGENERAL, 0);
      break;
    case 0x05:
      socks_rep(req->s, 5, S5EUNSUPRT, 0);
      break;
    default:
      break;
    }
    close(req->s);
    return(-1);
  }

  POSITIVE_REP(req->s, ver, (struct sockaddr *)&ss);
  if ( error < 0 ) {
    /* could not reply */
    close(req->s);
    close(cs);
    return(-1);
  }
  return(cs);   /* return forwarding socket */
}

/*   proxy socks functions  */
/*
  proxy_connect:
	   connect to next hop socks server.
           used in indirect connect to destination.
*/
int proxy_connect(int ver, struct socks_req *req)
{
  int s;

  /* first try socks5 server */
  s = connect_to_socks(5, req);
  if ( s >= 0 ) {
    /* succeeded */
    switch (ver) {
    case 0x04:
      /* client version differs.
	 need v5 to v4 converted reply */
      if (proxy_reply(5, req->s, s, req->req) != 0) {
	close(s);
	GEN_ERR_REP(req->s, 4);
	return(-1);
      }
      break;
    case 0x05:
      /* same version
	 further processing not needed. */
      break;
    default:
      /* i don't know what to do */
      break;
    }
  } else {      
    /* if an error, second try socks4 server */
    s = connect_to_socks(4, req);
    /* succeeded */
    if ( s >= 0 ) { 
      switch (ver) {
      case 0x04:
	/* same version client.
	   further processing not needed. */
	break;
      case 0x05:
	/* client version differs.
	   need v4 to v5 converted reply */
	if (proxy_reply(4, req->s, s, req->req) != 0) {
	  close(s);
	  GEN_ERR_REP(req->s, 5);
	  return(-1);
	}
	break;
      default:
	/* i don't know what to do */
	break;
      }
    } else {  /* still be an error, give it up. */
      GEN_ERR_REP(req->s, ver);
      return(-1);
    }
  }
  return(s);
}

int connect_to_socks(int ver, struct socks_req *req)
{
  int     cs;
  int     r, len = 0;
  struct  addrinfo hints, *res, *res0;
  struct  req_host_info info;
  int     error = 0;
  char    *user;
  u_char  buf[640];
  int     save_errno = 0;

  /* sanity check */
  if (req->tbl_ind == proxy_tbl_ind ||
      proxy_tbl[req->tbl_ind].port == 0) {
    /* shoud not be here */
    return -1;
  }

  /* process proxy request to next hop socks */

  switch (ver) {   /* next hop socks server version */
  case 0x04:
    /* build v4 request */
    buf[0] = 0x04;
    buf[1] = req->req;
    if ( req->u_len == 0 ) {
      user = S4DEFUSR;
      r = strlen(user);
    } else {
      user = req->user;
      r = req->u_len;
    }
    if (r < 0 || r > 255) {
      return(-1);
    }
    buf[2] = (req->port / 256);
    buf[3] = (req->port % 256);
    memcpy(&buf[8], user, r);
    len = 8+r;
    buf[len++] = 0x00;
    switch (req->dest.atype) {
    case S4ATIPV4:
      memcpy(&buf[4], req->dest.v4_addr, sizeof(struct in_addr));
      break;
    case S4ATFQDN:
      buf[4] = buf[5] = buf[6] = 0; buf[7] = 1;
      r = req->dest.len_fqdn;
      if (r <= 0 || r > 255) {
	return(-1);
      }
      memcpy(&buf[len++], req->dest.fqdn, r);
      len += r;
      buf[len++] = 0x00;
      break;
    default:
      return(-1);
    }
    break;

  case 0x05:
    /* build v5 request */
    buf[0] = 0x05;
    buf[1] = req->req;
    buf[2] = 0;
    buf[3] = req->dest.atype;
    switch (req->dest.atype) {
    case S5ATIPV4:
      memcpy(&buf[4], req->dest.v4_addr, 4);
      buf[8] = (req->port / 256);
      buf[9] = (req->port % 256);
      len = 10;
      break;
    case S5ATIPV6:
      memcpy(&buf[4], req->dest.v6_addr, 16);
      buf[20] = (req->port / 256);
      buf[21] = (req->port % 256);
      len = 22;
      break;
    case S5ATFQDN:
      buf[4] = req->dest.len_fqdn;
      memcpy(&buf[5], req->dest.fqdn, len);
      buf[5+len]   = (req->port / 256);
      buf[5+len+1] = (req->port % 256);
      len = 5+len+2;
      break;
    default:
      return(-1);
    }
    break;
  default:
    return(-1);   /* unknown version */
  }

  /* resolve addresses in request and log it */
  error = resolv_host(&req->dest, req->port, &info.dest);
  error = resolv_host(&proxy_tbl[req->tbl_ind].proxy,
			proxy_tbl[req->tbl_ind].port,
			&info.proxy);
  error = log_request(ver, req, &info);
  if (error) {
    return (-1);
  }

  /* string addr => addrinfo */
  memset(&hints, 0, sizeof(hints));
  hints.ai_socktype = SOCK_STREAM;
  
  error = getaddrinfo(info.proxy.host, info.proxy.port, &hints, &res0);
  if (error) {
    /* getaddrinfo error */
    return(-1);
  }
  cs = 0;
  for (res = res0; res; res = res->ai_next) {
    save_errno = 0;
    cs = socket(res->ai_family,
		res->ai_socktype, res->ai_protocol);
    if ( cs < 0 ) {
      continue;
    }

    if (connect(cs, res->ai_addr, res->ai_addrlen) < 0) {
      /* connect fail */
      save_errno = errno;
      close(cs);
      continue;
    }
    break;
  }
  freeaddrinfo(res0);
  if (cs < 0 || save_errno != 0) {
    return -1;
  }

  if (ver == 0x05) {
    if (s5auth_c(cs, req->tbl_ind) != 0) {
      /* socks5 auth nego to next hop failed */
      close(cs);
      return(-1);
    }
  }

  r = timerd_write(cs, buf, len, TIMEOUTSEC);
  if ( r < len ) {
    /* could not send request */
    close(cs);
    return(-1);
  }
  return(cs);   /* return forwarding socket */
}

int proxy_reply(int v, int cs, int ss, int req)
{
  int     r, c, len;
  u_char  buf[512];
  u_char  rep[512];
  struct  addrinfo hints, *res, *res0;
  int     error;
  struct  sockaddr_in *sa = 0;
  int found = 0;

  /* v:
        4: 4 to 5,  5: 5 to 4
  */

  switch (req) {
  case S5REQ_CONN:
    c = 1;
    break;

  case S5REQ_BIND:
    c = 2;
    break;

  default:   /* i don't know what to do */
    c = 1;
    break;
  }

  switch (v) {
  case 4:
    while (c-- > 0) {
      /* read ver 4 reply */
      r = timerd_read(ss, buf, sizeof buf, TIMEOUTSEC, 0);
      if ( r < 8 ) {   /* should be 8 is ver 4 specific. */
	/* cannot read server reply */
	return(-1);
      }
      if ( buf[1] != S4AGRANTED ) {
	return(-1);
      }
      /* translate reply */
      rep[0] = 0x05;
      rep[1] = 0x00;
      rep[2] = 0x00;
      rep[3] = S5ATIPV4;
      memcpy(&rep[4], &buf[4], 4);
      memcpy(&rep[8], &buf[2], 2);
      timerd_write(cs, rep, 10, TIMEOUTSEC);
      if ( r < 10 ) {
	/* could not reply */
	return(-1);
      }
    }
    break;

  case 5:
    while (c-- > 0) {
      /* read ver 5 reply */
      r = timerd_read(ss, buf, sizeof buf, TIMEOUTSEC, 0);
      if ( r < 7 ) {   /* should be 10 or more */
	/* cannot read server reply */
	return(-1);
      }
      if ( buf[1] != 0 ) {  /* not positive reply */
	return(-1);
      }
      /* translate reply */
      rep[0] = 0x04;
      rep[1] = S4AGRANTED; /* granted */
      switch (buf[3]) {   /* address type */
      case S5ATIPV4:
	memcpy(&rep[4], &buf[4], 4);
	memcpy(&rep[2], &buf[8], 2);
	break;
      case S5ATFQDN:
      default:
	len = buf[4] & 0xff;
	memcpy(&rep[2], &buf[5+len], 2);
	buf[5+len] = '\0';
	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_family = AF_INET;
	error = getaddrinfo(&buf[5], NULL, &hints, &res0);
	if (error) {
	  /* getaddrinfo error */
	  return -1;
	}
	for (res = res0; res; res = res->ai_next) {
	  if (res->ai_socktype != AF_INET)
	    continue;
	  sa = (struct sockaddr_in *)res->ai_addr;
	  found++; break;
	}
	freeaddrinfo(res0);
	if (!found) {
	  return -1;
	}
	memcpy(&res[4], &(sa->sin_addr), sizeof(struct in_addr));
	break;
      }
      timerd_write(cs, rep, 8, TIMEOUTSEC);
      if ( r < 8 ) {
	/* could not reply */
	return(-1);
      }
    }
    break;
  default:
    /* parameter error */
    return(-1);
  }
  return(0);
}
