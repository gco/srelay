/*
  socks.c:

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

#define TIMEOUTSEC   30

struct socks_req {
  int    s;                 /* client socket */
  int    atype;             /* address type */
  struct sockaddr_in *dest; /* destination sockaddr */
  char   *hostname;         /* destination hostname */
  char   *username;         /* user name used for socks v4 */ 
  int    req;               /* request CONN/BIND */
  int    tbl_ind;           /* proxy table indicator */
};

/* prototypes */
int lookup_tbl __P((int, struct sockaddr_in *, char *));
int log_request __P((int, struct socks_req *, int));
int proto_socks4 __P((int));
int s4direct_conn __P((struct socks_req *));
void s4err_rep __P((int, int));
int proto_socks5 __P((int));
int s5direct_conn __P((struct socks_req *));
int s5auth_s __P((int));
int s5auth_s_rep __P((int, int));
int s5auth_c __P((int, int));
void s5err_rep __P((int, int));
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
    return(s);
  }
}

ssize_t timerd_read(int s, char *buf, size_t len, int sec)
{
  ssize_t r = -1;
  settimer(sec);
  r = recvfrom(s, buf, len, 0, 0, 0);
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

int lookup_tbl(int atype, struct sockaddr_in *sa, char *domain)
{
  int i, match, len;
  struct in_addr net;
  u_short port;

  port = ntohs(sa->sin_port);
  match = 0;
  for (i=0; i < proxy_tbl_ind; i++) {
    if ( atype != proxy_tbl[i].atype ) {
      continue;
    }
    switch (atype) {
    case S5ATFQDN:
      len = strlen(domain);
      if (len <= 0 || len >= 256)
	break;
      if ( len < proxy_tbl[i].len || *domain == '\0' ) {
	break;
      }
      if (strncasecmp(proxy_tbl[i].domain,
		      &(domain[len - proxy_tbl[i].len]),
		      proxy_tbl[i].len) == 0) {
	match++;
      }
      break;
    case S5ATIPV4:
      memset(&net, 0, sizeof(net));
      memcpy(&net, &(sa->sin_addr), sizeof(net));
      net.s_addr &= proxy_tbl[i].mask.s_addr;
      if ( memcmp(&net, &(proxy_tbl[i].dest),
		  sizeof(struct in_addr)) == 0) {
	match++;
      }
      break;
    default:
      break;
    }
    if (!match) {
      continue;
    }
    if (port >= proxy_tbl[i].port_l && port <= proxy_tbl[i].port_h) {
      break;
    } else {
      match = 0;
    }
  }
  if (match)
    return(i);
  else
    return(proxy_tbl_ind);
}

/*
  log_request:
*/
int log_request(int v, struct socks_req *sr, int dp)
{
  struct sockaddr_in client;
  char  client_ip[16];
  char  dest_ip[16];
  char  proxy_ip[16];
  u_short client_port, dest_port;
  char  *host = "(?)";
  char  *user = "-";
  char  *ats[] =  {"ipv4", "fqdn:", "ipv6", "?"};
  char  *reqs[] = {"CON", "BND", "UDP", "?"};
  int   atmap[] = {3, 0, 3, 1, 2};
  int   reqmap[] = {3, 0, 1, 2};
  int   len;

  client_ip[0] = '\0'; dest_ip[0] = '\0'; proxy_ip[0] = '\0';

  len = sizeof(struct sockaddr_in);
  if (getpeername(sr->s, (struct sockaddr *)&client, &len) != 0) {
    client_port = 0;
  } else {
    inet_ntop(AF_INET, &(client.sin_addr), client_ip, sizeof client_ip);
    client_port = ntohs(client.sin_port);
  }

  inet_ntop(AF_INET, &(sr->dest->sin_addr), dest_ip, sizeof dest_ip);
  dest_port = ntohs(sr->dest->sin_port);

  if (sr->hostname != 0)
    host = sr->hostname;
  if (sr->username != 0)
    user = sr->username;

  if ( dp != 0 ) {    /* if not direct, i.e. proxy */
    if (sr->tbl_ind >= 0 && sr->tbl_ind <= proxy_tbl_ind) {
      if (proxy_tbl[sr->tbl_ind].proxy.s_addr != 0) {
	inet_ntop(AF_INET, &(proxy_tbl[sr->tbl_ind].proxy),
		  proxy_ip, sizeof proxy_ip);
      }
    }
  }

  msg_out(norm, "%s:%d %d-%s %s:%d(%s%s) %s %s%s.",
		client_ip, client_port,
		v, reqs[reqmap[sr->req]],
	         dest_ip, dest_port,
		ats[atmap[sr->atype]],
	        sr->atype == 3 ? host : "",
	        user,
		dp == 0 ? "direct" : "relay=",
	        proxy_ip );
  return(0);
}

int bind_sock(int s, struct sockaddr_in *sa)
{
  int len = sizeof(struct sockaddr_in);
  u_short port;
  int r;

  port = ntohs(sa->sin_port);
  if ( bind_restrict ) {
    if (port < IPPORT_RESERVEDSTART) {
      sa->sin_port = 0;
    }
  }
  if (port > 0 && port < IPPORT_RESERVED)
    seteuid(0);
  r = bind(s, (struct sockaddr *)sa, len);
  seteuid(PROCUID);
  return(r);
}

/*
  proto_socks:
               handle socks protocol.
*/
int proto_socks(int s)
{
  char buf[128];
  int r;
  int on = 1;

  if (wait_for_read(s, TIMEOUTSEC) <= 0) {
    close(s);
    return(-1);
  }
  r = recvfrom(s, buf, sizeof(buf), MSG_PEEK, 0, 0);
  if ( r <= 0 ) {
    close(s);
    return(-1);
  }

  switch (buf[0]) {
  case 4:
    if (method_num > 0) {
      /* this implies this server is working in V5 mode */
      s4err_rep(s, S4EGENERAL);
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
#ifdef __FreeBSD__
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
  char buf[512];
  char username[256], hostname[256];
  int r, len;
  struct hostent *h;
#if HAVE_GETHOSTBYNAME_R
  struct hostent he;
  char   ghwork[1024];
  int    gherrno;
#endif
  struct sockaddr_in dest;
  struct socks_req sr;

  memset(&sr, 0, sizeof sr);
  sr.s = s;
  sr.dest = &dest;
  sr.hostname = hostname;
  sr.username = username;

  r = timerd_read(s, buf, 1+1+2+4, TIMEOUTSEC);
  if (r < 1+1+2+4) {    /* cannt read request */
    s4err_rep(s, S4EGENERAL);
    return(-1);
  }
  if ( buf[0] != 0x04 ) {
    /* wrong version request (why ?) */
    s4err_rep(s, S4EGENERAL);
    return(-1);
  }
  sr.req = buf[1];
  memset(&dest, 0, sizeof dest);
  dest.sin_family = AF_INET;
  memcpy(&(dest.sin_port), &buf[2], 2);
  memcpy(&(dest.sin_addr), &buf[4], 4);

  /* check if request has socks4-a domain name format */
  if ( buf[4] == 0 && buf[5] == 0 &&
       buf[6] == 0 && buf[7] != 0 ) {
    sr.atype = S4ATFQDN;
  } else {
    sr.atype = S4ATIPV4;
  }

  /* read client user name in request */
  r = recvfrom(s, buf, sizeof(buf), MSG_PEEK, 0, 0);
  if ( r < 1 ) {
    /* error or client sends EOF */
    s4err_rep(s, S4EGENERAL);
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
    s4err_rep(s, S4EGENERAL);
    return(-1);
  }

  r = timerd_read(s, buf, r+1, TIMEOUTSEC);
  if ( r > 0 && r <= 255 ) {    /* r should be 1 <= r <= 255 */
    len = r - 1;
    strncpy(username, buf, len);
    username[len] = '\0';
  } else {
    /* read error or something */
    s4err_rep(s, S4EGENERAL);
    return(-1);
  }

  memset(hostname, 0, sizeof hostname);
  len = 0;
  if ( sr.atype == S4ATFQDN ) {
    /* request is socks4-A specific */
    r = timerd_read(s, buf, sizeof buf, TIMEOUTSEC);
    if ( r > 0 && r <= 256 ) {   /* r should be 1 <= r <= 256 */
      len = r - 1;
      strncpy(hostname, buf, len);
      hostname[len] = '\0';
    } else {
      /* read error or something */
      s4err_rep(s, S4EGENERAL);
      return(-1);
    }
  }

  sr.tbl_ind = lookup_tbl(sr.atype, &dest, hostname);
  if (sr.atype == S4ATFQDN && sr.tbl_ind == proxy_tbl_ind) {
    /* fqdn request but, not particular routing */
#if HAVE_GETHOSTBYNAME_R
    h = gethostbyname_r(hostname, &he,
			ghwork, sizeof ghwork, &gherrno);
#else
    MUTEX_LOCK(mutex_gh0);
    h = gethostbyname(hostname);
#endif
    if (h != NULL) {       /* resolvable */
      sr.atype = S4ATIPV4; /* revert atype */
      memcpy(&(dest.sin_addr), h->h_addr_list[0], 4);
      /* re-search table */
      sr.tbl_ind = lookup_tbl(sr.atype, &dest, hostname);
    }
#ifndef HAVE_GETHOSTBYNAME_R
    MUTEX_UNLOCK(mutex_gh0);
#endif
  }

  if (sr.tbl_ind == proxy_tbl_ind ||             /* do default */
      proxy_tbl[sr.tbl_ind].proxy.s_addr == 0) {
    if ( sr.atype == S4ATFQDN ) {
#if HAVE_GETHOSTBYNAME_R
      h = gethostbyname_r(hostname, &he,
			ghwork, sizeof ghwork, &gherrno);
#else
      MUTEX_LOCK(mutex_gh0);
      h = gethostbyname(hostname);
#endif
      if (h == NULL) {
	/* cannot resolve ?? */
#ifndef HAVE_GETHOSTBYNAME_R
	MUTEX_UNLOCK(mutex_gh0);
#endif
	s4err_rep(s, S4EGENERAL);
	return(-1);
      }
      memcpy(&(dest.sin_addr), h->h_addr_list[0], 4);
#ifndef HAVE_GETHOSTBYNAME_R
      MUTEX_UNLOCK(mutex_gh0);
#endif
    }
    return(s4direct_conn(&sr));
  }
  return(proxy_connect(4, &sr));
}

int s4direct_conn(struct socks_req *sr)
{
  int cs=0, acs;
  int r, len;
  struct sockaddr_in my, cl;
  struct in_addr bindaddr;
  char   buf[512];

  /* log the request */
  log_request(4, sr, 0);

  /* process direct connect/bind to destination */

  /* process by_command request */
  switch (sr->req) {   /* request */
  case S4REQ_CONN:
    if ((cs = socket(PF_INET, SOCK_STREAM, IPPROTO_IP)) == -1) {
      /* socket error */
      s4err_rep(sr->s, S4EGENERAL);
      return(-1);
    }
    if (connect(cs, (struct sockaddr *)(sr->dest),
		sizeof(struct sockaddr_in)) == -1) {
      /* connect fail */
      s4err_rep(sr->s, S4EGENERAL);
      close(cs);
      return(-1);
    }
    len = sizeof(my);
    getsockname(cs, (struct sockaddr *)&my, &len);
    /* socks v4 doesn't care about my socket name,
       so that error handling is ommited here. */
    break;

  case S4REQ_BIND:
    if (get_bind_addr(&(sr->dest->sin_addr), &bindaddr) < 0 ||
	bindaddr.s_addr == 0) {
      s4err_rep(sr->s, S4EGENERAL);
      return(-1);
    }
    len = sizeof(struct sockaddr_in);
    memset(&my, 0, len);
    my.sin_family = PF_INET;
    my.sin_addr.s_addr = bindaddr.s_addr;

    if ((acs = socket(PF_INET, SOCK_STREAM, IPPROTO_IP)) == -1) {
      /* socket error */
      s4err_rep(sr->s, S4EGENERAL);
      return(-1);
    }

    /*
      BIND port selection priority.
      1. requested port. (assuming dest->sin_port as requested port)
      2. clients src port.
      3. free port.
    */
    my.sin_port = sr->dest->sin_port;   /* set requested bind port */
    if (bind_sock(acs, &my) != -1)
      goto s4bind_ok;

    /* bind failed for requested port */
    len = sizeof(cl);
    if (getpeername(sr->s, (struct sockaddr *)&cl, &len) == 0) {
      my.sin_port = cl.sin_port;
      if (bind_sock(acs, &my) != -1)
	goto s4bind_ok;
    }

    /* try bind to free-port */
    my.sin_port = 0;
    if (bind_sock(acs, &my) == -1) {
      /* bind failed either */
      s4err_rep(sr->s, S4EGENERAL);
      close(acs);
      return(-1);
    }

  s4bind_ok:
    listen(acs, 64);
    /* get my socket name again to acquire an
       actual listen port number */
    len = sizeof(my);
    memset(&my, 0, sizeof(my));
    if (getsockname(acs, (struct sockaddr *)&my, &len) == -1) {
      /* getsockname failed */
      s4err_rep(sr->s, S4EGENERAL);
      close(acs);
      return(-1);
    }
    /* first reply for bind request */
    buf[0] = 0x00;
    buf[1] = S4AGRANTED & 0xff;   /* succeeded */
    memcpy(&buf[2], &(my.sin_port), 2);
    memcpy(&buf[4], &(my.sin_addr), 4);
    r = timerd_write(sr->s, buf, 8, TIMEOUTSEC);
    if ( r < 8 ) {
      /* could not reply */
      close(sr->s);
      close(acs);
      return(-1);
    }
    if ((cs = wait_for_read(acs, TIMEOUTSEC)) <= 0 ||
	cs != acs) {
      /* cs == 0:   time out
	 cs == -1:  some error
	 cs != acs:  why ???
      */
      s4err_rep(sr->s, S4EGENERAL);
      close(acs);
      return(-1);
    }
      
    len = sizeof(struct sockaddr_in);
    if ((cs = accept(acs, (struct sockaddr *)&my, &len)) < 0) {
      s4err_rep(sr->s, S4EGENERAL);
      close(acs);
      return(-1);
    }
    close(acs); /* accept socket is not needed
		   any more, for current socks spec. */
    /* sock name is in my */
    break;

  default:
    /* unsupported request */
    s4err_rep(sr->s, S4EGENERAL);
    close(cs);
    return(-1);
  }
  buf[0] = 0;
  buf[1] = S4AGRANTED & 0xff;   /* succeeded */
  memcpy(&buf[2], &(my.sin_port), 2);
  memcpy(&buf[4], &(my.sin_addr), 4);
  r = timerd_write(sr->s, buf, 8, TIMEOUTSEC);
  if ( r < 8 ) {
    /* could not reply */
    close(sr->s);
    close(cs);
    return(-1);
  }
  return(cs);   /* return forwarding socket */
}
void s4err_rep(int s, int code)
{
  char buf[8];
  int r;

  memset(buf, 0, sizeof(buf));
  buf[0] = 0x04;
  buf[1] = code & 0xff;   /* error code */
  r = timerd_write(s, buf, 8, TIMEOUTSEC);
  /* close client side socket here */
  close(s);
}

/* socks5 protocol functions */
int proto_socks5(int s)
{
  char buf[512];
  char hostname[512];
  int r, len;
  struct hostent *h;
#ifdef HAVE_GETHOSTBYNAME_R
  struct hostent he;
  char   ghwork[1024];
  int    gherrno;
#endif
  struct sockaddr_in dest;
  struct socks_req sr;

  memset(&sr, 0, sizeof sr);
  sr.s = s;
  sr.dest = &dest;
  sr.hostname = hostname;

  /* peek first 5 bytes of request. */
  if (wait_for_read(s, TIMEOUTSEC) <= 0) {
    /* timeout or error occuerd during reading client */
    close(s);
    return(-1);
  }
  r = recvfrom(s, buf, sizeof(buf), MSG_PEEK, 0, 0);
  if ( r < 5 ) {
    /* cannot read client request */
    close(s);
    return(-1);
  }

  if ( buf[0] != 0x05 ) {
    /* wrong version request */
    s5err_rep(s, S5EGENERAL);
    return(-1);
  }

  sr.req = buf[1];
  memset(&dest, 0, sizeof dest);
  dest.sin_family = PF_INET;
  memset(hostname, 0, sizeof hostname);
  len = 0;

  sr.atype = buf[3];  /* address type field */
  switch(sr.atype) {
  case S5ATIPV4:  /* IPv4 address */
    r = timerd_read(s, buf, 4+4+2, TIMEOUTSEC);
    if (r < 4+4+2) {     /* cannot read request (why?) */
      s5err_rep(s, S5EGENERAL);
      return(-1);
    }
    memcpy(&(dest.sin_addr), &buf[4], 4);
    memcpy(&(dest.sin_port), &buf[8], 2);
    break;
  case S5ATFQDN:  /* string or FQDN */
    if ((len = buf[4]) < 0 || len > 255) {
      /* invalid length */
      s5err_rep(s, S5EINVADDR);
      return(-1);
    }
    r = timerd_read(s, buf, 4+1+len+2, TIMEOUTSEC);
    if ( r < 4+1+len+2 ) {  /* cannot read request (why?) */
      s5err_rep(s, S5EGENERAL);
      return(-1);
    }
    memcpy(hostname, &buf[5], len);
    hostname[len] = '\0';
    memcpy(&(dest.sin_port), &buf[4+1+len], 2);
    break;

  default:
    /* unsupported address */
    s5err_rep(s, S5EUSATYPE);
    return(-1);
  }

  sr.tbl_ind = lookup_tbl(sr.atype, &dest, hostname);
  if (sr.atype == S5ATFQDN && sr.tbl_ind == proxy_tbl_ind) {
    /* fqdn request but, not particular routing */
#if HAVE_GETHOSTBYNAME_R
    h = gethostbyname_r(hostname, &he,
			ghwork, sizeof ghwork, &gherrno);
#else
    MUTEX_LOCK(mutex_gh0);
    h = gethostbyname(hostname);
#endif
    if (h != NULL) {       /* resolvable */
      sr.atype = S5ATIPV4; /* revert atype */
      memcpy(&(dest.sin_addr), h->h_addr_list[0], 4);
      /* re-search table */
      sr.tbl_ind = lookup_tbl(sr.atype, &dest, hostname);
    }
#ifndef HAVE_GETHOSTBYNAME_R
    MUTEX_UNLOCK(mutex_gh0);
#endif
  }

  if (sr.tbl_ind == proxy_tbl_ind ||                 /* do default */
      proxy_tbl[sr.tbl_ind].proxy.s_addr == 0) {
    if ( sr.atype == S5ATFQDN ) {
#if HAVE_GETHOSTBYNAME_R
      h = gethostbyname_r(hostname, &he,
			ghwork, sizeof ghwork, &gherrno);
#else
      MUTEX_LOCK(mutex_gh0);
      h = gethostbyname(hostname);
#endif
      if (h == NULL) {
	/* cannot resolve ?? */
#ifndef HAVE_GETHOSTBYNAME_R
	MUTEX_UNLOCK(mutex_gh0);
#endif
	s5err_rep(s, S5EINVADDR);
	return(-1);
      }
      memcpy(&(dest.sin_addr), h->h_addr_list[0], 4);
#ifndef HAVE_GETHOSTBYNAME_R
      MUTEX_UNLOCK(mutex_gh0);
#endif
    }
    return(s5direct_conn(&sr));
  }
  return(proxy_connect(5, &sr));
}

int s5direct_conn(struct socks_req *sr)
{
  int cs=0, acs;
  int r, len;
  struct sockaddr_in my, cl;
  struct in_addr bindaddr;
  char buf[512];

  /* log the request */
  log_request(5, sr, 0);

  /* process direct connect/bind to destination */

  /* process by_command request */
  switch (sr->req) {   /* request */
  case S5REQ_CONN:
    if ((cs = socket(PF_INET, SOCK_STREAM, IPPROTO_IP)) == -1) {
      /* socket error */
      s5err_rep(sr->s, S5EGENERAL);
      return(-1);
    }
    if (connect(cs, (struct sockaddr *)(sr->dest),
		sizeof(struct sockaddr_in)) == -1) {
      /* connect fail */
      switch(errno) {
      case ENETUNREACH:  s5err_rep(sr->s, S5ENETURCH); break;
      case ECONNREFUSED: s5err_rep(sr->s, S5ECREFUSE); break;
#ifndef _POSIX_SOURCE
      case EHOSTUNREACH: s5err_rep(sr->s, S5EHOSURCH); break;
#endif
      case ETIMEDOUT:    s5err_rep(sr->s, S5ETTLEXPR); break; /* ??? */
      default:           s5err_rep(sr->s, S5EGENERAL); break;
      }
      close(cs);
      return(-1);
    }
    len = sizeof(my);
    if (getsockname(cs, (struct sockaddr *)&my, &len) == -1) {
      /* cannot get my socket name */
      s5err_rep(sr->s, S5EGENERAL);
      close(cs);
      return(-1);
    }
    break;

  case S5REQ_BIND:
    if (get_bind_addr(&(sr->dest->sin_addr), &bindaddr) < 0 ||
	bindaddr.s_addr == 0) {
      s5err_rep(sr->s, S5EGENERAL);
      return(-1);
    }
    len = sizeof(struct sockaddr_in);
    memset(&my, 0, len);
    my.sin_family = PF_INET;
    my.sin_addr.s_addr = bindaddr.s_addr;

    if ((acs = socket(PF_INET, SOCK_STREAM, IPPROTO_IP)) == -1) {
      /* socket error */
      s5err_rep(sr->s, S5EGENERAL);
      return(-1);
    }
    my.sin_port = sr->dest->sin_port;   /* set requested bind port */
    if (bind_sock(acs, &my) != -1)
      goto s5bind_ok;

    /* bind failed for requested port */
    len = sizeof(cl);
    if (getpeername(sr->s, (struct sockaddr *)&cl, &len) == 0) {
      my.sin_port = cl.sin_port;
      if (bind_sock(acs, &my) != -1)
	goto s5bind_ok;
    }

    /* try bind to free-port */
    my.sin_port = 0;
    if (bind_sock(acs, &my) == -1) {
      /* bind failed either */
      s5err_rep(sr->s, S5EGENERAL);
      close(acs);
      return(-1);
    }

  s5bind_ok:
    listen(acs, 64);
    /* get my socket name again to acquire an
       actual listen port number */
    len = sizeof(my);
    memset(&my, 0, sizeof(my));
    if (getsockname(acs, (struct sockaddr *)&my, &len) == -1) {
      /* getsockname failed */
      s5err_rep(sr->s, S5EGENERAL);
      close(acs);
      return(-1);
    }
    /* first reply for bind request */
    buf[0] = 0x05;
    buf[1] = 0;   /* succeeded */
    buf[2] = 0;
    buf[3] = 0x01;  /* addr type fixed to IPv4 */
    memcpy(&buf[4], &(my.sin_addr), 4);
    memcpy(&buf[8], &(my.sin_port), 2);
    r = timerd_write(sr->s, buf, 10, TIMEOUTSEC);
    if ( r < 10 ) {
      /* could not reply */
      close(sr->s);
      close(acs);
      return(-1);
    }
    if ((cs = wait_for_read(acs, TIMEOUTSEC)) <= 0 ||
	cs != acs) {
      /* cs == 0:   time out
	 cs == -1:  some error
	 cs != acs:  why ???
      */
      s5err_rep(sr->s, S5EGENERAL);
      close(acs);
      return(-1);
    }
      
    len = sizeof(struct sockaddr_in);
    if ((cs = accept(acs, (struct sockaddr *)&my, &len)) < 0) {
      s5err_rep(sr->s, S5EGENERAL);
      close(acs);
      return(-1);
    }
    close(acs); /* accept socket is not needed
		   any more, for current socks spec. */
    /* sock name is in my */
    break;

  default:
    /* unsupported request */
    s5err_rep(sr->s, S5EUNSUPRT);
    close(cs);
    return(-1);
  }
  buf[0] = 0x05;
  buf[1] = 0;     /* succeeded */
  buf[2] = 0;
  buf[3] = 0x01;  /* addr type fixed to IPv4 */
  memcpy(&buf[4], &(my.sin_addr), 4);
  memcpy(&buf[8], &(my.sin_port), 2);
  r = timerd_write(sr->s, buf, 10, TIMEOUTSEC);
  if ( r < 10 ) {
    /* could not reply */
    close(sr->s);
    close(cs);
    return(-1);
  }
  return(cs);   /* return forwarding socket */
}

/*
  socks5 auth negotiation as server.
*/
int s5auth_s(int s)
{
  char buf[512];
  int r, i, j, len;
  int method=0, done=0;

  /* auth method negotiation */
  r = timerd_read(s, buf, 2, TIMEOUTSEC);
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

  r = timerd_read(s, buf, len, TIMEOUTSEC);
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
  char buf[2];
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
  char buf[512];
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

  r = timerd_read(s, buf, 2, TIMEOUTSEC);
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

void s5err_rep(int s, int code)
{
  char buf[10];
  int r;

  memset(buf, 0, sizeof(buf));
  buf[0] = 0x05;
  buf[1] = code & 0xff;   /* error code */
  buf[2] = 0;
  buf[3] = 0x01;  /* addr type fixed to IPv4 */
  r = timerd_write(s, buf, 10, TIMEOUTSEC);
  /* close client side socket here */
  close(s);
}

/*   proxy socks functions  */
/*
  proxy_connect:
	   connect to next hop socks server.
           used in indirect connect to destination.
*/
int proxy_connect(int ver, struct socks_req *sr)
{
  int s;

  /* log the request */
  log_request(ver, sr, 1);

  /* first try socks5 server */
  s = connect_to_socks(5, sr);
  if ( s >= 0 ) {
    /* succeeded */
    switch (ver) {
    case 0x04:
      /* client version differs.
	 need v5 to v4 converted reply */
      if (proxy_reply(5, sr->s, s, sr->req) != 0) {
	close(s);
	s4err_rep(sr->s, S4EGENERAL);
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
    s = connect_to_socks(4, sr);
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
	if (proxy_reply(4, sr->s, s, sr->req) != 0) {
	  close(s);
	  s5err_rep(sr->s, S5EGENERAL);
	  return(-1);
	}
	break;
      default:
	/* i don't know what to do */
	break;
      }
    } else {  /* still be an error, give it up. */
      switch (ver) {   /* client socks version */
      case 0x04:
	s4err_rep(sr->s, S4EGENERAL);
	return(-1);
      case 0x05:
	s5err_rep(sr->s, S5EGENERAL);
	return(-1);
      default:
	close(sr->s);
	return(-1);
      }
    }
  }
  return(s);
}

int connect_to_socks(int ver, struct socks_req *sr)
{
  int cs;
  int r, len;
  struct sockaddr_in proxy;
  char *username;
  char buf[640];

  /* process proxy request to next hop socks */

  switch (ver) {   /* next hop socks server version */
  case 0x04:
    /* build v4 request */
    buf[0] = 0x04;
    buf[1] = sr->req & 0xff;
    if ( sr->username == NULL ) {
      username = S4DEFUSR;
    } else {
      username = sr->username;
    }
    r = strlen(username);
    if (r < 0 || r > 255) {
      return(-1);
    }
    memcpy(&buf[2], &(sr->dest->sin_port), 2);
    memcpy(&buf[8], username, r);
    len = 8+r;
    buf[len++] = 0x00;
    switch (sr->atype) {
    case S4ATIPV4:
      memcpy(&buf[4], &(sr->dest->sin_addr), 4);
      break;
    case S4ATFQDN:
      buf[4] = buf[5] = buf[6] = 0; buf[7] = 1;
      r = strlen(sr->hostname);
      if (r <= 0 || r > 255) {
	return(-1);
      }
      memcpy(&buf[len++], sr->hostname, r);
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
    buf[1] = sr->req & 0xff;
    buf[2] = 0;
    buf[3] = sr->atype & 0xff;
    switch (sr->atype) {
    case S5ATIPV4:
      memcpy(&buf[4], &(sr->dest->sin_addr), 4);
      memcpy(&buf[8], &(sr->dest->sin_port), 2);
      len = 10;
      break;
    case S5ATFQDN:
      len = strlen(sr->hostname);
      if (len <= 0 || len > 255) {
	return(-1);
      }
      buf[4] = len & 0xff;
      memcpy(&buf[5], sr->hostname, len);
      memcpy(&buf[5+len], &(sr->dest->sin_port), 2);
      len = 5+len+2;
      break;
    default:
      return(-1);
    }
    break;
  default:
    return(-1);   /* unknown version */
  }

  if ((cs = socket(PF_INET, SOCK_STREAM, IPPROTO_IP)) == -1) {
    /* socket error */
    return(-1);
  }

  memset(&proxy, 0, sizeof proxy);
  proxy.sin_family = PF_INET;
  memcpy(&(proxy.sin_addr), &(proxy_tbl[sr->tbl_ind].proxy), 4);
  proxy.sin_port = htons(proxy_tbl[sr->tbl_ind].port);

  if (connect(cs, (struct sockaddr *)&proxy, sizeof proxy) == -1) {
    close(cs);
    return(-1);
  }

  if (ver == 0x05) {
    if (s5auth_c(cs, sr->tbl_ind) != 0) {
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
  int  r, c=0, len=0;
  char buf[512];
  char rep[512];
  struct hostent *h;
#ifdef HAVE_GETHOSTBYNAME_R
  struct hostent he;
  char   ghwork[1024];
  int    gherrno;
#endif

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
      r = timerd_read(ss, buf, sizeof buf, TIMEOUTSEC);
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
      r = timerd_read(ss, buf, sizeof buf, TIMEOUTSEC);
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
#if HAVE_GETHOSTBYNAME_R
	h = gethostbyname_r(&buf[5], &he,
			ghwork, sizeof ghwork, &gherrno);
#else
	MUTEX_LOCK(mutex_gh0);
	h = gethostbyname(&buf[5]);
#endif
	if (h == NULL) {
	  /* cannot resolve ?? */
	  rep[4] = rep[5] = rep[6] = 0; rep[7]=1;
	} else {
	  memcpy(&rep[4], h->h_addr_list[0], 4);
	}
#ifndef HAVE_GETHOSTBYNAME_R
	MUTEX_UNLOCK(mutex_gh0);
#endif
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
