/*
  get-bind.c:

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
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/sockio.h>
#include <net/if.h>
#include <net/route.h>
#ifdef	HAVE_SOCKADDR_DL_STRUCT
# include <net/if_dl.h>
#endif

#ifndef RTAX_DST
#define RTAX_DST         0
#define RTAX_GATEWAY     1
#define RTAX_NETMASK     2
#define RTAX_GENMASK     3
#define RTAX_IFP         4
#define RTAX_IFA         5
#define RTAX_AUTHOR      6
#define RTAX_BRD         7
#define RTAX_MAX        RTA_NUMBITS /* Number of bits used in RTA_* */
#endif

#ifndef HAVE_SOCKLEN_T
typedef unsigned int socklen_t;
#endif

struct if_list {
  char if_name[IFNAMSIZ];
  struct in_addr if_addr;
};

/*
 * Round up 'a' to next multiple of 'size'
 */
#define ROUNDUP(a, size) (((a) & ((size)-1)) ? (1 + ((a) | ((size)-1))) : (a))

/*
 * Step to next socket address structure;
 * if sa_len is 0, assume it is sizeof(u_long).
 */
#ifdef HAVE_SOCKADDR_SA_LEN
#define NEXT_SA(ap)	ap = (struct sockaddr *) \
	((caddr_t) ap + (ap->sa_len ? ROUNDUP(ap->sa_len, sizeof (u_long)) : \
				sizeof(u_long)))
#endif

void
get_rtaddrs(int addrs, struct sockaddr *sa, struct sockaddr **rti_info)
{
  int	i;
#ifndef HAVE_SOCKADDR_SA_LEN
  char  *p = (char *)sa;
  size_t len;
#endif

  for (i = 0; i < RTAX_MAX; i++) {
    if (addrs & (1 << i)) {
      rti_info[i] = sa;
#ifdef HAVE_SOCKADDR_SA_LEN
      NEXT_SA(sa);
#else
      switch(sa->sa_family) {
      case AF_INET:
	len = sizeof(struct sockaddr_in);
	break;
      case AF_LINK:
	len = sizeof(struct sockaddr_dl);
	break;
      default:
	len = 0;
      }
      sa = (struct sockaddr *) (p + len);
      p = (char *)sa;
#endif
    } else
      rti_info[i] = NULL;
  }
}

#define	SEQ		9999	/* packet sequence dummy */
#define MAXNUM_IF	256	/* max number of interfaces */

int get_bind_addr(struct in_addr *dest, struct in_addr *binda)
{

  /* list interface name/address
   *   fixed size buffer limits number of recognizable interfaces.
   *   buf size = sizeof(struct ifreq) * 256 interface = 8192
   */
  int			i, ent, sockfd, len;
  char			*ptr, buf[sizeof(struct ifreq) * MAXNUM_IF];
  struct ifconf		ifc;
  struct ifreq		*ifr;
  struct sockaddr_in	*sinptr;
  struct if_list        ifl[MAXNUM_IF];

  pid_t			pid;
  ssize_t		n;
  struct rt_msghdr	*rtm;
  struct sockaddr	*sa, *rti_info[RTAX_MAX];
  struct sockaddr_in	*sin;
  struct sockaddr_dl    *sdl;


  sockfd = socket(AF_INET, SOCK_DGRAM, 0);

  ifc.ifc_len = sizeof(buf);
  ifc.ifc_req = (struct ifreq *) buf;
  ioctl(sockfd, SIOCGIFCONF, &ifc);

  close(sockfd);

  i = ent = 0;
  for (ptr = buf; ptr < buf + ifc.ifc_len; ) {
    ifr = (struct ifreq *) ptr;
    len = sizeof(struct sockaddr);
#ifdef	HAVE_SOCKADDR_SA_LEN
    if (ifr->ifr_addr.sa_len > len)
      len = ifr->ifr_addr.sa_len;		/* length > 16 */
#endif
    ptr += sizeof(ifr->ifr_name) + len;	/* for next one in buffer */

    switch (ifr->ifr_addr.sa_family) {
    case AF_INET:
      strncpy(ifl[i].if_name, ifr->ifr_name, IFNAMSIZ);
      sinptr = (struct sockaddr_in *) &ifr->ifr_addr;
      memcpy(&ifl[i].if_addr, &sinptr->sin_addr, sizeof(struct in_addr));
      i++;
      break;

    default:
      break;
    }
  }
  ent = i; /* number of interfaces */

  /* get routing */
  seteuid(0);
  sockfd = socket(AF_ROUTE, SOCK_RAW, 0);	/* need superuser privileges */
  seteuid(PROCUID);
  if (sockfd < 0) {
    /* socket error */
    return(-1);
  }

  memset(buf, 0, sizeof buf);

  rtm = (struct rt_msghdr *) buf;
  rtm->rtm_msglen = sizeof(struct rt_msghdr)
                  + sizeof(struct sockaddr_in)
                  + sizeof(struct sockaddr_dl);
  rtm->rtm_version = RTM_VERSION;
  rtm->rtm_type = RTM_GET;
  rtm->rtm_addrs = RTA_DST|RTA_IFP;
  rtm->rtm_pid = pid = getpid();
  rtm->rtm_seq = SEQ;

  sin = (struct sockaddr_in *) (buf + sizeof(struct rt_msghdr));
  sin->sin_family = AF_INET;
#ifdef HAVE_SOCKADDR_SA_LEN
  sin->sin_len = sizeof(struct sockaddr_in);
#endif

  sin->sin_addr.s_addr = dest->s_addr;

#ifdef HAVE_SOCKADDR_SA_LEN
  sa = (struct sockaddr *)sin;
  NEXT_SA(sa);
  sdl = (struct sockaddr_dl *)sa;
  sdl->sdl_len = sizeof(struct sockaddr_dl);
#else
  sdl = (struct sockaddr_dl *) (buf
		+ ROUNDUP(sizeof(struct rt_msghdr), sizeof(u_long))
		+ ROUNDUP(sizeof(struct sockaddr_in), sizeof(u_long)));
#endif
  sdl->sdl_family = AF_LINK;

  write(sockfd, rtm, rtm->rtm_msglen);

  do {
    n = read(sockfd, rtm, sizeof buf);
  } while (rtm->rtm_type != RTM_GET || rtm->rtm_seq != SEQ ||
	   rtm->rtm_pid != pid);

  close(sockfd);

  rtm = (struct rt_msghdr *) buf;
  sa = (struct sockaddr *) (rtm + 1);
  get_rtaddrs(rtm->rtm_addrs, sa, rti_info);

  if ( (sa = rti_info[RTAX_IFP]) != NULL) {
    sdl = (struct sockaddr_dl *)sa;
    if (sdl->sdl_nlen > 0) {
      for (i=0; i<ent; i++) {
	if (memcmp(ifl[i].if_name, sdl->sdl_data, sdl->sdl_nlen) == 0) {
	  binda->s_addr = ifl[i].if_addr.s_addr;
	  return(0);
	}
      }
    }
  }
  return(-1);
}
