/*
  init.c

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

#include <sys/param.h>
#include "srelay.h"

/* prototypes */
int sock_init __P((struct sockaddr_in *));

int *serv_sock;       /* must be NULLed at startup */
int serv_sock_ind;

fd_set allsock;
int    maxsock;

int sock_init(struct sockaddr_in *sa)
{
  int s;
  int on = 1;

  if ( (s = socket(AF_INET, SOCK_STREAM, IPPROTO_IP)) == -1 ) {
    perror("socket");
    return(-1);
  }
  if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char *)&on, sizeof on) < 0) {
    perror("setsockopt: SO_REUSEADDR");
    return(-1);
  }

  if (bind(s, (struct sockaddr *)sa, sizeof(struct sockaddr_in)) < 0) {
    perror("bind");
    return(-1);
  }
  listen(s, 64);
  set_blocking(s);
  return(s);
}

int serv_init(char *ifs)
{
  int s, i, len, dup;
  char *p, *q, *r, *hobj;
  u_short port;
  struct sockaddr_in sa;
  struct hostent *h;
  struct {
    int       fd;
    struct in_addr in;
    u_short port;
  } tmp_tbl[MAX_SOCKS];

  if (ifs == NULL || *ifs == NULL) {  /* init table */
    if (serv_sock != NULL) {
      free(serv_sock);
    }
    serv_sock = NULL;
    serv_sock_ind = 0;
    FD_ZERO(&allsock);
    maxsock = 0;
    return(0);
  }

  for ( p = q = ifs; q != NULL; p=q+1) {
    if (p == NULL || *p == NULL)
      break;

    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;

    q = strchr(p, ',');
    if (q != NULL) {    /* may be more entry */
      len = q - p;
    } else {            /* last one */
      len = strlen(p);
    }
    if ((hobj = malloc(len+1)) == NULL) {
      /* malloc error, fatal */
      return(-1);
    }
    memcpy(hobj, p, len);
    *(hobj+len) = NULL;

    r = strchr(hobj, '/');
    if (r != NULL) {         /* there may be port assignment */
      *r++ = NULL;
      if (*r != NULL) {
	port = atoi(r);
	if ( port != 0 ) {
	  sa.sin_port = htons(port);
	} else {
	  /* invalid port, ignore this entry */
	  free(hobj);
	  continue;
	}
      } else {   /* special case; null port */
	sa.sin_port = htons(SOCKS_PORT);
      }
    } else {     /* no port asignment (defaults to SOCKS_PORT)*/
      sa.sin_port = htons(SOCKS_PORT);
    }
    if (*hobj == NULL) {  /* special case; null host */
      sa.sin_addr.s_addr = INADDR_ANY;
    } else {
      if ((h = gethostbyname(hobj)) == NULL) {
	/* cannot determin serv ip */
	herror("gethostbyname");
	free(hobj);
	continue;
      }
      memcpy(&(sa.sin_addr), h->h_addr_list[0], 4);
    }
    free(hobj);

    /* check duplication */
    for ( i=0, dup=0; i < serv_sock_ind; i++ ) {
      if (tmp_tbl[i].in.s_addr == sa.sin_addr.s_addr &&
	  tmp_tbl[i].port == sa.sin_port) { /* it's duplicates */
	dup++;
	break;
      }
    }
    if (!dup) {
      if ((s = sock_init(&sa)) < 0) {
	/* cannot open socket */
	continue;
      }
      tmp_tbl[serv_sock_ind].in.s_addr = sa.sin_addr.s_addr;
      tmp_tbl[serv_sock_ind].port = sa.sin_port;
      tmp_tbl[serv_sock_ind].fd = s;
      FD_SET(s, &allsock);
      maxsock = MAX(s, maxsock);
      serv_sock_ind++;
      if (serv_sock_ind >= MAX_SOCKS)
	break;
    }
  }

  if (serv_sock_ind == 0) {
    msg_out(warn, "no server socket prepared, exitting...\n");
    return(-1);
  }

  if ((serv_sock = (int *)malloc(sizeof(int) * serv_sock_ind)) != NULL) {
    for ( i=0; i < serv_sock_ind; i++ ) {
      serv_sock[i] = tmp_tbl[i].fd;
    }
    return(0);
  }
  /* malloc failed */
  return(-1);
}

#if 0

int main(int argc, char **argv) {

  if (argc > 1) {
    serv_init(NULL);
    serv_init(argv[1]);
  } else {
    fprintf(stderr,"need args\n");
  }
  return(0);
}

#endif
