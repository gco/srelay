/*
  readconf.c:
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

/* prototypes */
char *skip   __P((char *));
char *spell  __P((char *));
void add_entry __P((struct rtbl *, struct rtbl *, int));
void parse_err __P((int, int, char *));

#define MAXLINE  1024
#define SP        040
#define HT        011
#define NL        012
#define VT        013
#define NP        014
#define CR        015

#define SPACES(c) (c == SP || c == HT || c == VT || c == NP)
#define DELIMS(c) (c == '\0' || c == '#' || c == ';' || c == NL || c == CR)

#define PORT_MIN  0
#define PORT_MAX  65535

struct rtbl *proxy_tbl;    /* proxy routing table */
int proxy_tbl_ind;         /* next entry indicator */

/*
  config format:
        #   comment line
	# dest_ip[/mask]          port-low-port-hi  next-proxy  [porxy-port]
	192.168.1.2/255.255.255.0   1-100           172.16.5.1  1080
	172.17.5.0/24               901             102.100.2.1 11080
	172.17.8.0/16               any
	0.0.0.0/0.0.0.0             0-32767         10.1.1.2    1080
        
  note:
        port-low, port-hi includes specified ports.
	port numbers must be port-low <= port-hi.
	separator of port-low and port-hi is '-'. no space chars.
	port-low = NULL (-port-hi) means 0 to port-hi.
	port-hi=NULL (port-low-) means port-low to 65535.
	           ... so, single '-' means 0 to 65535 (?).
	special port 'any' means 0-65535
	no next-proxy means "direct" connect to destination.
*/

int readconf(FILE *fp)
{
  char *p, *q, *r, *tok;
  int i, len, err, c;
  struct in_addr zero;
  int n = 0;
  char *any = "any";
  struct rtbl tmp;
  struct rtbl tmp_tbl[MAX_ROUTE];
  char buf[MAXLINE];
  struct hostent *h;
  struct rtbl *new_proxy_tbl;
  int new_proxy_tbl_ind = 0;

  while (fp && fgets(buf, MAXLINE-1, fp) != NULL) {
    memset(&tmp, 0, sizeof(struct rtbl));
    p = buf;
    n++;
    err = 0;

    if ((p = skip(p)) == NULL) { /* comment line or something */
      continue;
    }

    /* destination */
    tok = p; p = spell(p);
    /* check whether dest is numeric IP or FQDN */
    len = strlen(tok);
    tmp.atype = S5ATIPV4;
    for (i=0; i<len; i++) {
      c = *(tok+i);
      if ( c != '.' && c != '/' && (c < '0' || c > '9')) {
	/* dest contains non-numeric character */
	tmp.atype = S5ATFQDN;
	break;
      }
    }

    switch (tmp.atype) {
    case S5ATFQDN:
      /* destination may be domain name */
      tmp.len = strlen(tok);
      tmp.domain = strdup(tok);  /* strdup dynamically allocates mem */
      if ( tmp.domain == NULL ) {
	/* can't allocate memory. it's fatal, but ... */
	parse_err(warn, n, "memory allocation error(domain).");
	err++;
      }
      break;
    case S5ATIPV4:
      /* dest ip and mask */
      q = strchr(tok, '/');  /* check dest mask sep. */
      if (q != NULL) {       /* there is a mask expression */
	*q++ = '\0';
	r = strchr(q, '.');  /* check mask format */
	if (r != NULL) {     /* may be dotted notation */
	  if ( inet_pton(AF_INET, q, &(tmp.mask)) != 1 ) {
	    parse_err(warn, n, "parse dest addr mask.");
	    err++; break;
	  }
	} else {             /* may be numeric notation */
	  if ( *q < '0' || *q > '9' ) { /* check slightly */
	    parse_err(warn, n, "parse dest addr mask.");
	    err++; break;
	  }
	  i = atoi(q);
	  if ( i < 0 || i > 32) {     /* more check */
	    parse_err(warn, n, "parse dest addr mask.");
	    err++; break;
	  }
	  tmp.mask.s_addr = htonl(0xffffffff<<(32-i));
	}
      } else {             /* there isn't mask exp. */
	tmp.mask.s_addr = htonl(0xffffffff);
      }
      if ( inet_pton(AF_INET, tok, &(tmp.dest)) != 1 ) {
	parse_err(warn, n, "parse dest addr.");
	err++; break;
      }
      memset(&zero, 0, sizeof zero);
      if (memcmp(&(tmp.dest), &zero, sizeof zero) == 0) {
	/* dest is 0.0.0.0, so mask forcibly be zeroed */
	memset(&(tmp.mask), 0, sizeof tmp.mask);
      }
      break;
    default:
      parse_err(warn, n, "unsupported address type.");
      err++; break;
    }
    if ( err > 0 ) { /* there is an error in one of cases */
      continue;
    }

    if ((p = skip(p)) == NULL) {
      parse_err(warn, n, "dest port missing or invalid, ignore this line.");
      continue;
    }

    /* dest port */
    tok = p; p = spell(p);
    if ((q = strchr(tok, '-')) != NULL ) {
      if (tok == q) {           /* special case '-port-hi' */
	tmp.port_l = PORT_MIN;
      } else {
	*q = '\0';
	tmp.port_l = atoi(tok);
      }
      if (*++q == '\0') {       /* special case 'port-low-' */
	tmp.port_h = PORT_MAX;
      } else {
	tmp.port_h = atoi(q);
      }
    } else if ((strncasecmp(tok, any, strlen(any))) == 0) {
      tmp.port_l = PORT_MIN;
      tmp.port_h = PORT_MAX;
    } else {     /* may be single port */
      tmp.port_l = tmp.port_h = atoi(tok);
      if ( errno == ERANGE ) {
	parse_err(warn, n, "parse dest port number.");
	continue;
      }
    }
    if ((tmp.port_l > tmp.port_h) || (tmp.port_h == 0)) {
      parse_err(warn, n, "dest port range is invalid.");
      continue;
    }

    if ((p = skip(p)) == NULL) {        /* no proxy entry */
      add_entry(&tmp, tmp_tbl, new_proxy_tbl_ind++);
      continue;
    }

    /* proxy */
    tok = p; p = spell(p);
    if ((h = gethostbyname(tok)) != NULL) {
      memcpy(&(tmp.proxy), h->h_addr_list[0], 4);
    } else {
      parse_err(warn, n, "parse proxy address.");
      continue;
    }

    /* proxy port */
    if ((p = skip(p)) == NULL) { /* proxy-port is ommited */
      tmp.port = SOCKS_PORT;     /* defaults to socks port */
      add_entry(&tmp, tmp_tbl, new_proxy_tbl_ind++);
      /* remaining data is ignored */
      continue;
    } else {
      tok = p; p = spell(p);
      tmp.port = atoi(tok);
      if ( errno == ERANGE ) {
	parse_err(warn, n, "parse proxy port number.");
	continue;
      }
      add_entry(&tmp, tmp_tbl, new_proxy_tbl_ind++);
    }
  }

  if ( new_proxy_tbl_ind <= 0 ) { /* no valid entries */
    parse_err(warn, n, "no valid entries found. using default.");
    new_proxy_tbl_ind = 1;
    memset(tmp_tbl, 0, sizeof(struct rtbl));
    tmp_tbl[0].port_l = PORT_MIN; tmp_tbl[0].port_h = PORT_MAX;
  }

  /* allocate suitable memory space to proxy_tbl */
  new_proxy_tbl = (struct rtbl *)malloc(sizeof(struct rtbl)
					* new_proxy_tbl_ind);
  if ( new_proxy_tbl == (struct rtbl *)0 ) {
    /* malloc error */
    return(-1);
  }
  memcpy(new_proxy_tbl, tmp_tbl,
	 sizeof(struct rtbl) * new_proxy_tbl_ind);
  if (proxy_tbl != NULL) { /* may holds previous table */
    free(proxy_tbl);
  }
  proxy_tbl     = new_proxy_tbl;
  proxy_tbl_ind = new_proxy_tbl_ind;
  return(0);
}

/*
 *  skip spaces.
 *  return:  0  if delimited.
 *  return: ptr to next token.
 */
char *skip(char *s)
{
  while (SPACES(*s))
    s++;
  if (DELIMS(*s))
    return(NULL);
  else
    return(s);
}

char *spell(char *s) {
  while (!SPACES(*s) && !DELIMS(*s))
    s++;
  *s++ = '\0';
  return(s);
}

void add_entry(struct rtbl *r, struct rtbl *t, int ind)
{
  if (ind >= MAX_ROUTE) {
    /* error in add_entry */
    return;
  }
  /* convert dest addr to dest network address */
  r->dest.s_addr &= r->mask.s_addr;
  memcpy(&t[ind], r, sizeof(struct rtbl));
}

void parse_err(int sev, int line, char *msg)
{
  msg_out(sev, "%s: line %d: %s\n", CONFIG, line, msg);
}

/*
  readpasswd:
	read from fp, search user and set pass.
	it is little bit dangerous, that this routine will
	over-writes arguemts 'user' and 'pass' contents.
    File format:
    # comment
    # proxy-host-ip/name   user    passwd
    10.1.1.117             tomo    hogerata
    dtmp163.kddi.com       bob     foobar

*/
int readpasswd(FILE *fp, int ind, 
	       char *user, int ulen, char *pass, int plen)
{
  char buf[MAXLINE];
  char *p, *tok;
  int  r, len;
  struct in_addr proxy;
  struct hostent *h;
#ifdef HAVE_GETHOSTBYNAME_R
  struct hostent he;
  char   ghwork[1024];
  int    gherrno;
#endif

  proxy.s_addr = proxy_tbl[ind].proxy.s_addr;
  if (proxy.s_addr == 0) {
    /* it must be no-proxy. how did you fetch up here ?
       any way, you shouldn't be hanging aroud.
    */
    return(0);
  }
  while (fgets(buf, MAXLINE-1, fp) != NULL) {
    p = buf; tok = 0;
    if ((p = skip(p)) == NULL) { /* comment line or something */
      continue;
    }
    /* proxy host ip/name entry */
    tok = p; p = spell(p);
#ifdef HAVE_GETHOSTBYNAME_R
# ifdef SOLARIS
    if ((h = gethostbyname_r(tok, &he,
		ghwork, sizeof ghwork, &gherrno)) == NULL) {
      /* name resolv failed */
      continue;
    }
# elif LINUX
    if (gethostbyname_r(tok, &he,
		ghwork, sizeof ghwork, &h, &gherrno) != 0) {
      /* name resolv failed */
      continue;
    }
# endif
    r = memcmp(&proxy, h->h_addr_list[0], 4);
#else
    MUTEX_LOCK(mutex_gh0);
    if ((h = gethostbyname(tok)) == NULL) {
      /* name resolv failed */
      MUTEX_UNLOCK(mutex_gh0);
      continue;
    }
    r = memcmp(&proxy, h->h_addr_list[0], 4);
    MUTEX_UNLOCK(mutex_gh0);
#endif
    if (r != 0) {
	/* proxy address not matched */
	continue;
    }

    if ((p = skip(p)) == NULL) {
      /* insufficient fields, ignore this line */
      continue;
    }

    tok = p; p = spell(p); len = strlen(tok); 
    if (len <= ulen) {
      strncpy(user, tok, len);
      user[len] = '\0';
    } else {
      /* invalid length, ignore this line */
      continue;
    }

    if ((p = skip(p)) == NULL) {
      /* insufficient fields, ignore this line */
      continue;
    }

    tok = p; p = spell(p); len = strlen(tok);
    if (len <= plen) {
      strncpy(pass, tok, len);
      pass[len] = '\0';
      /* OK, this is enough, */
      return(0);
    } else {
      /* invalid length, ignore this line */
      continue;
    }
  }
  /* matching entry not found or error */
  return(-1);
}

#if 0

/* dummy */
char *pidfile;
int cur_child;

void dump_entry()
{
  int i;
  char ip[16];

  for (i=0; i < proxy_tbl_ind; i++) {
    fprintf(stdout, "--- %d ---\n", i);
    fprintf(stdout, "atype: %d\n", proxy_tbl[i].atype);
    inet_ntop(AF_INET, &(proxy_tbl[i].dest), ip, sizeof ip);
    ip[(sizeof ip) - 1] = '\0'; 
    fprintf(stdout, "dest: %s\n", ip);
    inet_ntop(AF_INET, &(proxy_tbl[i].mask), ip, sizeof ip);
    ip[(sizeof ip) - 1] = '\0'; 
    fprintf(stdout, "mask: %s\n", ip);
    if ( proxy_tbl[i].atype == S5ATFQDN ) {
      fprintf(stdout, "len: %d\n", proxy_tbl[i].len);
      fprintf(stdout, "domain: %s\n", proxy_tbl[i].domain);
    }
    fprintf(stdout, "port_l: %u\n", proxy_tbl[i].port_l);
    fprintf(stdout, "port_h: %u\n", proxy_tbl[i].port_h);
    inet_ntop(AF_INET, &(proxy_tbl[i].proxy), ip, sizeof ip);
    ip[(sizeof ip) - 1] = '\0'; 
    fprintf(stdout, "proxy: %s\n", ip);
    fprintf(stdout, "port: %u\n", proxy_tbl[i].port);
  }
}

void checkpwd(char *user)
{
  FILE *fp;
  char pass[256];

  if ( (fp = fopen(PWDFILE, "r")) == NULL ) {
    fprintf(stderr, "cannot open %s\n", PWDFILE);
    return;
  }
  if (readpasswd(fp, user, pass, 255) == 0) {
    fprintf(stdout, "%s\n", pass);
  }

}

int main(int argc, char **argv) {

  /*
  FILE *fp;
  if ( (fp = fopen(CONFIG, "r")) == NULL ) {
    return(1);
  }
  */

  if (argc < 2) {
    fprintf(stderr, "need args\n");
    return(1);
  }

  checkpwd(argv[1]);

  /*
  readconf(fp);
  fclose(fp);

  dump_entry();
  return(0);
  */
}
#endif
