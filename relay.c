/*
  relay.c:

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

#if HAVE_LIBWRAP
# include <tcpd.h>
extern int hosts_ctl __P((char *, char *, char *, char *));
#endif

#define TIMEOUTSEC   30

typedef struct {
  int from, to;
  size_t nr, nw;
  ssize_t nread, nwritten;
  int oob;     /* flag OOB */
  char buf[BUFSIZE];
} rlyinfo;

int resolv_client;

/* proto types */
void readn __P((rlyinfo *));
void writen __P((rlyinfo *));
ssize_t forward __P((rlyinfo *));
int validate_access __P((char *, char *));
void relay __P((int, int));
int log_transfer __P((int, int, u_long, u_long, struct timeval *));

void readn(rlyinfo *ri)
{
  ri->nread = 0;
  settimer(TIMEOUTSEC);
  if (ri->oob == 0) {
    ri->nread = read(ri->from, ri->buf, ri->nr);
  } else {
    ri->nread = recvfrom(ri->from, ri->buf, ri->nr, MSG_OOB, NULL, NULL);
  }
  settimer(0);
  if (ri->nread < 0) {
    msg_out(warn, "read: %m");
  }
}

void writen(rlyinfo *ri)
{
  ri->nwritten = 0;
  settimer(TIMEOUTSEC);
  if (ri->oob == 0) {
    ri->nwritten = write(ri->to, ri->buf, ri->nw);
  } else {
    ri->nwritten = sendto(ri->to, ri->buf, ri->nw, MSG_OOB, NULL, NULL);
  }
  settimer(0);
  if (ri->nwritten <= 0) {
    msg_out(warn, "write: %m");
  }
}

ssize_t forward(rlyinfo *ri)
{
  readn(ri);
  if (ri->nread > 0) {
    ri->nw = ri->nread;
    writen(ri);
  }
  if (ri->nread == 0)
    return(0);           /* EOF */
  if (ri->nread < 0)
    return(-1);
  return(ri->nwritten);
}

int validate_access(char *client_addr, char *client_name)
{
  int stat = 1; /* valid access */

#ifdef HAVE_LIBWRAP
  stat = hosts_ctl(ident, client_name, client_addr, STRING_UNKNOWN);
#endif
  if (stat != 1) {
    msg_out(warn, "%s[%s] access denied.", client_name, client_addr);
  }

  return stat;
}

u_long idle_timeout = IDLE_TIMEOUT;

void relay(int cs, int ss)
{
  fd_set rfds, xfds;
  int    nfds, sfd;
  struct timeval tv, ts, ots, elp;
  struct timezone tz;
  ssize_t wc;
  u_long  upl, dnl, bc;
  rlyinfo ri;
  int done;
  u_long max_count = idle_timeout;
  u_long timeout_count;

  /* idle timeout related setting. */
  tv.tv_sec = 60; tv.tv_usec = 0;   /* unit = 1 minute. */

  ri.nr = BUFSIZE;
  tz.tz_minuteswest = 0; tz.tz_dsttime = 0;

  nfds = (ss > cs ? ss : cs);
  setsignal(SIGALRM, timeout);
  gettimeofday(&ots, &tz);
  bc = upl = dnl = 0; ri.oob = 0; timeout_count = 0;
  for (;;) {
    FD_SET(cs, &rfds); FD_SET(ss, &rfds);
    if (ri.oob == 0) {
      FD_SET(cs, &xfds); FD_SET(ss, &xfds);
    }
    done = 0;
    sfd = select(nfds+1, &rfds, 0, &xfds, &tv);
    if (sfd > 0) {
      if (FD_ISSET(ss, &rfds)) {
	ri.from = ss; ri.to = cs; ri.oob = 0;
	if ((wc = forward(&ri)) <= 0)
	  done++;
	else
	  bc += wc; dnl += wc;

	FD_CLR(ss, &rfds);
      }
      if (FD_ISSET(ss, &xfds)) {
	ri.from = ss; ri.to = cs; ri.oob = 1;
	if ((wc = forward(&ri)) <= 0)
	  done++;
	else
	  bc += wc; dnl += wc;
	FD_CLR(ss, &xfds);
      }
      if (FD_ISSET(cs, &rfds)) {
	ri.from = cs; ri.to = ss; ri.oob = 0;
	if ((wc = forward(&ri)) <= 0)
	  done++;
	else
	  bc += wc; upl += wc;
	FD_CLR(cs, &rfds);
      }
      if (FD_ISSET(cs, &xfds)) {
	ri.from = cs; ri.to = ss; ri.oob = 1;
	if ((wc = forward(&ri)) <= 0)
	  done++;
	else
	  bc += wc; upl += wc;
	FD_CLR(cs, &xfds);
      }
      if (done > 0)
	break;
    } else if (sfd < 0) {
      if (errno != EINTR)
	break;
    } else { /* sfd == 0 */
      if (max_count != 0) {
	timeout_count++;
	if (timeout_count > max_count)
	  break;
      }
    }
  }
  gettimeofday(&ts, &tz);
  if (ts.tv_usec < ots.tv_usec) {
    ts.tv_sec--; ts.tv_usec += 1000000;
  }
  elp.tv_sec = ts.tv_sec - ots.tv_sec;
  elp.tv_usec = ts.tv_usec - ots.tv_usec;

  log_transfer(cs, ss, upl, dnl, &elp);

  close(ss);
  close(cs);
}

#ifdef USE_THREAD
pthread_mutex_t mutex_select;
pthread_mutex_t mutex_gh0;
#endif

int serv_loop(void *id)
{
  int    cs, ss=0;
  struct sockaddr_in client;
  fd_set readable;
  int    i, n, len;
  struct hostent *h;
  char   cl_addr[16];
  char   cl_name[256];
  pid_t  pid;

#ifdef USE_THREAD
  if (threading) {
    blocksignal(SIGHUP);
    blocksignal(SIGINT);
    blocksignal(SIGUSR1);
  }
#endif

  for (;;) {
    readable = allsock;

#ifdef USE_THREAD
    if (threading) {
      t_t[(int)id].count++;
    }
#endif
    MUTEX_LOCK(mutex_select);
    n = select(maxsock+1, &readable, 0, 0, 0);
    if (n <= 0) {
      if (n < 0 && errno != EINTR) {
        msg_out(warn, "select: %m");
      }
      MUTEX_UNLOCK(mutex_select);
      continue;
    }

    for ( i = 0; i < serv_sock_ind; i++ ) {
      if (FD_ISSET(serv_sock[i], &readable)) {
	n--;
	break;
      }
    }
    if ( n < 0 || i >= serv_sock_ind ) {
      MUTEX_UNLOCK(mutex_select);
      continue;
    }

    len = sizeof(struct sockaddr_in);
    cs = accept(serv_sock[i], (struct sockaddr *)&client, &len);
    if (cs < 0) {
      if (errno == EINTR
#ifdef SOLARIS
	  || errno == EPROTO
#endif
	  || errno == EWOULDBLOCK
	  || errno == ECONNABORTED) {
	; /* ignore */
      } else {
	/* real accept error */
	msg_out(warn, "accept: %m");
      }
      MUTEX_UNLOCK(mutex_select);
      continue;
    }
    MUTEX_UNLOCK(mutex_select);

#ifdef USE_THREAD
    if ( !threading ) {
#endif
      if (max_child > 0 && cur_child >= max_child) {
	msg_out(warn, "child: cur %d; exeedeing max(%d)",
		          cur_child, max_child);
	close(cs);
	continue;
      }
#ifdef USE_THREAD
    }
#endif

    memset(cl_addr, 0, sizeof cl_addr);
    memset(cl_name, 0, sizeof cl_name);
    if(inet_ntop(AF_INET, &(client.sin_addr),
		 cl_addr, sizeof cl_addr) == NULL) {
      cl_addr[0] = '\0';
    } else {
      cl_addr[(sizeof cl_addr) - 1] = '\0';
    }
    MUTEX_LOCK(mutex_gh0);
    if (resolv_client) {
      h = gethostbyaddr((char *)&(client.sin_addr),
			sizeof client.sin_addr, AF_INET);
      if (h == NULL) {
	strncpy(cl_name, cl_addr, sizeof cl_addr);
      } else {
	strncpy(cl_name, h->h_name, sizeof cl_name);
      }
      msg_out(norm, "%s[%s] connected", cl_name, cl_addr);
    } else {
      strncpy(cl_name, cl_addr, sizeof cl_addr);
      msg_out(norm, "%s connected", cl_addr);
    }
    MUTEX_UNLOCK(mutex_gh0);

    i = validate_access(cl_addr, cl_name);
    if ( i != 1) {
      /* access denied */
      close(cs);
      continue;
    }

    set_blocking(cs);

#ifdef USE_THREAD
    if (!threading ) {
#endif
      blocksignal(SIGHUP);
      blocksignal(SIGCHLD);
      pid = fork();
      switch (pid) {
      case -1:  /* fork child failed */
	break;
      case 0:   /* i am child */
	for ( i = 0; i < serv_sock_ind; i++ ) {
	  close(serv_sock[i]);
	}
	setsignal(SIGCHLD, SIG_DFL);
        setsignal(SIGHUP, SIG_DFL);
        releasesignal(SIGCHLD);
        releasesignal(SIGHUP);
	ss = proto_socks(cs);
	if ( ss == -1 ) {
	  close(cs);  /* may already be closed */
	  exit(1);
	}
	relay(cs, ss);
	exit(0);
      default: /* may be parent */
	cur_child++;
	break;
      }
      close(cs);
      releasesignal(SIGHUP);
      releasesignal(SIGCHLD);
#ifdef USE_THREAD
    } else {
      ss = proto_socks(cs);
      if ( ss == -1 ) {
	close(cs);  /* may already be closed */
	continue;
      }
      relay(cs, ss);
    }
#endif
  }
}

int log_transfer(int cs, int ss,
		 u_long upl, u_long dnl, struct timeval *elapsed)
{
  struct sockaddr_in sa;
  char cs_ip[16], ss_ip[16];
  u_short cs_port, ss_port;
  int len;

  /* get socket cs peer name */
  len = sizeof(struct sockaddr_in);
  if (getpeername(cs, (struct sockaddr *)&sa, &len) != 0) {
    cs_ip[0] = '\0';
    cs_port = 0;
  } else {
    if (inet_ntop(AF_INET, &(sa.sin_addr),
		  cs_ip, sizeof cs_ip) == NULL) {
      cs_ip[0] = '\0';
    }
    cs_port = ntohs(sa.sin_port);
  }
  /* get socket ss peer name */
  len = sizeof(struct sockaddr_in);
  if (getpeername(ss, (struct sockaddr *)&sa, &len) != 0) {
    ss_ip[0] = '\0';
    ss_port = 0;
  } else {
    if (inet_ntop(AF_INET, &(sa.sin_addr),
		  ss_ip, sizeof ss_ip) == NULL) {
      ss_ip[0] = '\0';
    }
    ss_port = ntohs(sa.sin_port);
  }
  msg_out(norm, "== %s:%u %s:%u up: %u, down: %u,"
		" elapsed: %u.%06u(sec.)",
		cs_ip, cs_port, ss_ip, ss_port, upl, dnl,
		elapsed->tv_sec, elapsed->tv_usec);
  return(0);
}
