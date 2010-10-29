/*
  relay.c:
  $Id$

Copyright (C) 2001-2010 Tomo.M (author).
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

#define TIMEOUTSEC   30

typedef struct {
  int		from, to;
  size_t	nr, nw;
  ssize_t	nread, nwritten;
  int		flags;		/* flag OOB, ... */
  struct sockaddr *ss;		/* sockaddr used for recv / sendto */
  socklen_t	len;		/* sockaddr len used for recv / sendto */
  char		buf[BUFSIZE];	/* data */
  int		top;		/* top position of udp data */
  int		dir;		/* udp relay direction */
} rlyinfo;

enum { UP, DOWN };		/* udp relay direction */

int resolv_client;

/* proto types */
void readn	 __P((rlyinfo *));
void writen	 __P((rlyinfo *));
ssize_t forward	 __P((rlyinfo *));
ssize_t forward_udp __P((SOCKS_STATE *, rlyinfo *));
int log_transfer __P((loginfo *));

void readn(rlyinfo *ri)
{
  ri->nread = 0;
  ri->nread = recvfrom(ri->from, ri->buf+ri->top, ri->nr, ri->flags,
		       ri->ss, &ri->len);
  if (ri->nread < 0) {
    msg_out(warn, "read: %m");
  }
}

void writen(rlyinfo *ri)
{
  ri->nwritten = 0;
  ri->nwritten = sendto(ri->to, ri->buf+ri->top, ri->nw, ri->flags,
			ri->ss, ri->len);
  if (ri->nwritten <= 0) {
    msg_out(warn, "write: %m");
  }
}

ssize_t forward(rlyinfo *ri)
{
  settimer(TIMEOUTSEC);
  readn(ri);
  if (ri->nread > 0) {
    ri->nw = ri->nread;
    writen(ri);
  }
  settimer(0);
  if (ri->nread == 0)
    return(0);           /* EOF */
  if (ri->nread < 0)
    return(-1);
  return(ri->nwritten);
}

ssize_t forward_udp(SOCKS_STATE *state, rlyinfo *ri)
{
  settimer(TIMEOUTSEC);
  if (state->rtbl.rl_meth == DIRECT) {
    switch (ri->dir) {
    case UP:
      ri->top = 0;
      readn(ri);
      if (ri->nread > 0) {
	/* (check and) save down-side sockaddr */
	memcpy(&state->udp.adn.addr, ri->ss, ri->len);
	state->udp.adn.len = ri->len;
	/* decode socks udp header and set it to up-side sockaddr */
	if (decode_socks_udp(state, (u_char *)ri->buf) < 0)
	  return(-1);
	/* shift buf top pointer by udp header length */
	ri->top = state->udp.sv.len;
	/* open upward socket unless opened yet */
	/* XXXX little bit ambiguous ?? */
	if (state->udp.u < 0) {
	  if ((state->udp.u = socket(state->udp.aup.addr.ss_family,
				     SOCK_DGRAM, IPPROTO_IP)) < 0)
	    return(-1);
	  ri->to = state->udp.u;
	}
	/* set destination(up-ward) sockaddr */
	memcpy(ri->ss, &state->udp.aup.addr, state->udp.aup.len);
	ri->len = state->udp.aup.len;
	/* set write data len */
	if (ri->nread - state->udp.sv.len < 0)
	  return(-1);
	ri->nw = ri->nread - state->udp.sv.len;
      }
      break;
    case DOWN:
      if (state->udp.sv.len <= 0)
	return(-1);
      /* shift buf top pointer by udp header length */
      ri->top = state->udp.sv.len;
      readn(ri);
      if(ri->nread > 0) {
	/* (check and) save up-ward sockaddr */
	memcpy(&state->udp.aup.addr, ri->ss, ri->len);
	state->udp.aup.len = ri->len;
	/* prepend socks udp header to buffer */
	memcpy(ri->buf, state->udp.sv.data, state->udp.sv.len);
	/* set destination(down-ward) sockaddr */
	memcpy(ri->ss, &state->udp.adn.addr, state->udp.adn.len);
	ri->len = state->udp.adn.len;
	/* reset buf top */
	ri->top = 0;
	/* set write data len */
	ri->nw = ri->nread + state->udp.sv.len;
      }
      break;
    }
    writen(ri);
  } else {
    /* PROXY just relay */
    /* XXXXX  not yet */
  }
  settimer(0);
  if (ri->nread == 0)
    /* none the EOF case of UDP but assume innormal */
    return(0);
  if (ri->nread < 0)
    return(-1);
  return(ri->nwritten);
}

#ifndef MAX
# define MAX(a,b)  (((a)>(b))?(a):(b))
#endif

u_long idle_timeout = IDLE_TIMEOUT;

void relay(SOCKS_STATE *state)
{
  fd_set   rfds, xfds;
  int      nfds, sfd;
  struct   timeval tv;
  struct   timezone tz;
  ssize_t  wc;
  rlyinfo  ri;
  int      done;
  u_long   max_count = idle_timeout;
  u_long   timeout_count;

  memset(&ri, 0, sizeof(ri));
  ri.ss = (struct sockaddr *)NULL;
  ri.len = 0;
  ri.nr = BUFSIZE;

  nfds = MAX(state->r, state->s);
  setsignal(SIGALRM, timeout);
  gettimeofday(&state->li->start, &tz);
  state->li->bc = state->li->upl = state->li->dnl = 0;
  ri.flags = 0; timeout_count = 0;
  for (;;) {
    FD_ZERO(&rfds);
    FD_SET(state->s, &rfds); FD_SET(state->r, &rfds);
    if (ri.flags == 0) {
      FD_ZERO(&xfds);
      FD_SET(state->s, &xfds); FD_SET(state->r, &xfds);
    }
    done = 0;
    /* idle timeout related setting. */
    tv.tv_sec = 60; tv.tv_usec = 0;   /* unit = 1 minute. */
    tz.tz_minuteswest = 0; tz.tz_dsttime = 0;
    sfd = select(nfds+1, &rfds, 0, &xfds, &tv);
    if (sfd > 0) {
      if (FD_ISSET(state->r, &rfds)) {
	ri.from = state->r; ri.to = state->s; ri.flags = 0;
	if ((wc = forward(&ri)) <= 0)
	  done++;
	else
	  state->li->bc += wc; state->li->dnl += wc;

	FD_CLR(state->r, &rfds);
      }
      if (FD_ISSET(state->r, &xfds)) {
	ri.from = state->r; ri.to = state->s; ri.flags = MSG_OOB;
	if ((wc = forward(&ri)) <= 0)
	  done++;
	else
	  state->li->bc += wc; state->li->dnl += wc;
	FD_CLR(state->r, &xfds);
      }
      if (FD_ISSET(state->s, &rfds)) {
	ri.from = state->s; ri.to = state->r; ri.flags = 0;
	if ((wc = forward(&ri)) <= 0)
	  done++;
	else
	  state->li->bc += wc; state->li->upl += wc;
	FD_CLR(state->s, &rfds);
      }
      if (FD_ISSET(state->s, &xfds)) {
	ri.from = state->s; ri.to = state->r; ri.flags = MSG_OOB;
	if ((wc = forward(&ri)) <= 0)
	  done++;
	else
	  state->li->bc += wc; state->li->upl += wc;
	FD_CLR(state->s, &xfds);
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
  gettimeofday(&state->li->end, &tz);
  log_transfer(state->li);

  close(state->r);
  close(state->s);
}

void relay_udp(SOCKS_STATE *state)
{
  fd_set   rfds;
  int      nfds, sfd;
  struct   timeval tv;
  struct   timezone tz;
  ssize_t  wc;
  rlyinfo  ri;
  int      done;
  u_long   max_count = idle_timeout;
  u_long   timeout_count;
  struct sockaddr_storage ss;

  memset(&ri, 0, sizeof(ri));
  ri.ss = (struct sockaddr *)&ss;
  ri.flags = 0;
  ri.nr = BUFSIZE-sizeof(UDPH);

  setsignal(SIGALRM, timeout);
  gettimeofday(&state->li->start, &tz);
  state->li->bc = state->li->upl = state->li->dnl = 0;
  timeout_count = 0;
  for (;;) {
    FD_ZERO(&rfds);
    FD_SET(state->s, &rfds); FD_SET(state->udp.d, &rfds);
    nfds = MAX(state->s, state->udp.d);
    if (state->r >= 0) {
      FD_SET(state->r, &rfds);
      nfds = MAX(nfds, state->r);
    }
    if (state->udp.u >= 0) {
      FD_SET(state->udp.u, &rfds);
      nfds = MAX(nfds, state->udp.u);
    }

    done = 0;
    /* idle timeout related setting. */
    tv.tv_sec = 60; tv.tv_usec = 0;   /* unit = 1 minute. */
    tz.tz_minuteswest = 0; tz.tz_dsttime = 0;
    sfd = select(nfds+1, &rfds, 0, 0, &tv);
    if (sfd > 0) {
      /* UDP channels */
      if (FD_ISSET(state->udp.d, &rfds)) {
	ri.from = state->udp.d; ri.to = state->udp.u;
	ri.dir = UP;
	if ((wc = forward_udp(state, &ri)) <= 0)
	  done++;
	else
	  state->li->bc += wc; state->li->upl += wc;
	FD_CLR(state->udp.d, &rfds);
      }
      if (FD_ISSET(state->udp.u, &rfds)) {
	ri.from = state->udp.u; ri.to = state->udp.d;
	ri.dir = DOWN;
	if ((wc = forward_udp(state, &ri)) <= 0)
	  done++;
	else
	  state->li->bc += wc; state->li->dnl += wc;
	FD_CLR(state->udp.d, &rfds);
      }
      /* packets on TCP channel may indicate
	 termination of UDP assoc.
      */
      if (FD_ISSET(state->s, &rfds)) {
	ri.from = state->s; ri.to = state->r; ri.flags = 0;
	if ((wc = forward(&ri)) <= 0)
	  done++;
	/*
	else
	  state->li->bc += wc; state->li->upl += wc;
	*/
	FD_CLR(state->s, &rfds);
      }
      if (FD_ISSET(state->r, &rfds)) {
	ri.from = state->r; ri.to = state->s; ri.flags = 0;
	if ((wc = forward(&ri)) <= 0)
	  done++;
	/*
	else
	  state->li->bc += wc; state->li->dnl += wc;
	*/
	FD_CLR(state->r, &rfds);
      }

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

  gettimeofday(&state->li->end, &tz);
  log_transfer(state->li);

  close(state->s);
  close(state->r);
  close(state->udp.d);
  close(state->udp.u);
}

int log_transfer(loginfo *li)
{

  char    prc_ip[NI_MAXHOST], prs_ip[NI_MAXHOST];
  char    myc_port[NI_MAXSERV], mys_port[NI_MAXSERV];
  char    prc_port[NI_MAXSERV], prs_port[NI_MAXSERV];
  struct timeval elp;
  int     error = 0;

  memcpy(&elp, &li->end, sizeof(struct timeval));
  if (elp.tv_usec < li->start.tv_usec) {
    elp.tv_sec--; elp.tv_usec += 1000000;
  }
  elp.tv_sec  -= li->start.tv_sec;
  elp.tv_usec -= li->start.tv_usec;

  error = getnameinfo((struct sockaddr *)&li->myc.addr, li->myc.len,
		      NULL, 0,
		      myc_port, sizeof(myc_port),
		      NI_NUMERICHOST|NI_NUMERICSERV);
  error = getnameinfo((struct sockaddr *)&li->mys.addr, li->mys.len,
		      NULL, 0,
		      mys_port, sizeof(mys_port),
		      NI_NUMERICHOST|NI_NUMERICSERV);
  error = getnameinfo((struct sockaddr *)&li->prc.addr, li->prc.len,
		      prc_ip, sizeof(prc_ip),
		      prc_port, sizeof(prc_port),
		      NI_NUMERICHOST|NI_NUMERICSERV);
  error = getnameinfo((struct sockaddr *)&li->prs.addr, li->prs.len,
		      prs_ip, sizeof(prs_ip),
		      prs_port, sizeof(prs_port),
		      NI_NUMERICHOST|NI_NUMERICSERV);

  msg_out(norm, "%s:%s-%s/%s-%s:%s %u(%u/%u) %u.%06u",
	  prc_ip, prc_port, myc_port,
	  mys_port, prs_ip, prs_port,
	  li->bc, li->upl, li->dnl,
	  elp.tv_sec, elp.tv_usec);

  return(0);
}
