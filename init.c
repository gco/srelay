/*
  init.c
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

#include <sys/param.h>
#include "srelay.h"

/* prototypes */
int sock_init __P((struct sockaddr_in *));

char **str_serv_sock; /* to use tcp_wrappers validation */
int *serv_sock;       /* must be NULLed at startup */
int serv_sock_ind;

fd_set allsock;
int    maxsock;
int    sig_queue[2];

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
    close(s);
    return(-1);
  }

  if (bind(s, (struct sockaddr *)sa, sizeof(struct sockaddr_in)) < 0) {
    perror("bind");
    close(s);
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
    char    str_addr[15+1+5+1]; /* aaa.bbb.ccc.ddd.ppppp\0 */
  } tmp_tbl[MAX_SOCKS];
  char str_ip[16], str_port[6];


  if (ifs == NULL || *ifs == '\0') {
    /* init table is initiated. */
    if (serv_sock != NULL) {
      free(serv_sock);
    }
    if (str_serv_sock != NULL) {
      for (i = 0; i < serv_sock_ind; i++) {
	if (str_serv_sock[i] != NULL) {
	  free(str_serv_sock[i]);
	}
      }
      free(str_serv_sock);
    }
    serv_sock = NULL;
    str_serv_sock = NULL;
    serv_sock_ind = 0;
    FD_ZERO(&allsock);
    maxsock = 0;
    return(0);
  }

  for (p = q = ifs; q != NULL; p=q+1) {
    if (p == NULL || *p == '\0')
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
    *(hobj+len) = '\0';

    r = strchr(hobj, '/');
    if (r != NULL) {         /* there may be port assignment */
      *r++ = '\0';
      if (*r != '\0') {
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
    if (*hobj == '\0') {  /* special case; null host */
      sa.sin_addr.s_addr = INADDR_ANY;
    } else {
      if ((h = gethostbyname(hobj)) == NULL) {
	/* cannot determin serv ip */
#if (! SOLARIS )
	/* solaris defines hstrerror as non-global */
	msg_out(warn, "gethostbyname: %s - %s\n",
		hobj, hstrerror(h_errno));
#endif
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
      if (inet_ntop(AF_INET, &sa.sin_addr, str_ip, sizeof(str_ip)) == NULL
	  || (len = strlen(str_ip) + 1) < sizeof("0.0.0.0")
	  || len > sizeof("123.123.123.123")) {
	/* string conversion failed */
	str_ip[0] = '\0';
      }
      if (snprintf(str_port, sizeof(str_port),
		   "%d", ntohs(sa.sin_port)) >= sizeof(str_port)) {
	/* string conversion failed */
	str_port[0] = '\0';
      }
      strncpy(tmp_tbl[serv_sock_ind].str_addr, str_ip, sizeof(str_ip));
      tmp_tbl[serv_sock_ind].str_addr[strlen(str_ip)] = '.';
      tmp_tbl[serv_sock_ind].str_addr[strlen(str_ip)+1] = '\0';
      strncat(tmp_tbl[serv_sock_ind].str_addr,
	      str_port, sizeof(tmp_tbl[serv_sock_ind].str_addr));

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
    for (i = 0; i < serv_sock_ind; i++ ) {
      serv_sock[i] = tmp_tbl[i].fd;
    }
  } else {
    /* malloc failed */
    return(-1);
  }

  if ((str_serv_sock =
       (char **)malloc(sizeof(char *) * serv_sock_ind)) != NULL) {
    for (i = 0; i < serv_sock_ind; i++) {
      str_serv_sock[i] = strdup(tmp_tbl[i].str_addr);
    }
  } else {
    /* malloc failed */
    return(-1);
  }

#ifdef USE_THREAD
  if ( ! threading ) {
#endif
    if (sig_queue[0] > 0) {
      FD_SET(sig_queue[0], &allsock);
      maxsock = MAX(sig_queue[0], maxsock);
    } else {
      return(-1);
    }
#ifdef USE_THREAD
  }
#endif
  return(0);
}

int queue_init()
{
  if (pipe(sig_queue) != 0) {
    return(-1);
  }
  return(0);
}

#if 0
/*
  to test ...
  ./configure
  make init.o
  make util.o
  cc -o test-ini init.o util.o
  ./test-ini 123.123.123.123/1111,localhost
*/
int cur_child;
char *pidfile;

int main(int argc, char **argv) {

  int i;

  if (argc > 1) {
    serv_init(NULL);
    serv_init(argv[1]);
  } else {
    fprintf(stderr,"need args\n");
  }
  for (i = 0; i < serv_sock_ind; i++) {
    fprintf(stdout, "%d: %s\n", serv_sock[i], str_serv_sock[i]);
  }
  return(0);
}

#endif
