/*
  auth-pwd.c

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
#ifdef __FreeBSD__
#include <pwd.h>
#elif  SOLARIS
#include <shadow.h>
#include <crypt.h>
#endif

#define TIMEOUTSEC    30

char *pwdfile = PWDFILE;

/* proto types */
int checkpasswd(char *, char *);

int auth_pwd_server(int s)
{
  char buf[512];
  int  r, len, i;
  char user[256];
  char pass[256];
  struct sockaddr_in client;
  char client_ip[16];
  int  code = 0;

  if (wait_for_read(s, TIMEOUTSEC) <= 0) {
    return(-1);
  }
  r = recvfrom(s, buf, sizeof(buf), MSG_PEEK, 0, 0);
  if ( r < 2 ) {
    return(-1);
  }
  if (buf[0] != 0x01) { /* current username/password auth version */
    /* error in version */
    return(-1);
  }
  len = buf[1];
  if (len < 1 || len > 255) {
    /* invalid username len */
    return(-1);
  }
  /* read username */
  r = timerd_read(s, buf, 2+len, TIMEOUTSEC);
  if (r < 2+len) {
    /* read error */
    return(-1);
  }
  strncpy(user, &buf[2], len);
  user[len] = '\0';

  /* get passwd */
  r = recvfrom(s, buf, sizeof(buf), MSG_PEEK, 0, 0);
  if ( r < 1 ) {
    return(-1);
  }
  len = buf[0];
  if (len < 1 || len > 255) {
    /* invalid password len */
    return(-1);
  }
  /* read passwd */
  r = timerd_read(s, buf, 1+len, TIMEOUTSEC);
  if (r < 1+len) {
    /* read error */
    return(-1);
  }
  strncpy(pass, &buf[1], len);
  pass[len] = '\0';

  /* do authentication */
  r = checkpasswd(user, pass);

  /* logging */
  len = sizeof(struct sockaddr_in);
  if (getpeername(s, (struct sockaddr *)&client, &len) != 0) {
    client_ip[0] = '\0';
  } else {
    if (inet_ntop(AF_INET, &(client.sin_addr),
                  client_ip, sizeof client_ip) == NULL) {
      client_ip[0] = '\0';
    }
  }
  msg_out(norm, "v5 %s u/p auth user %s %s.", client_ip,
	  user, r == 0 ? "accepted" : "denied");

  /* erace uname and passwd storage */
  for (i=0; i < strlen(user); i++) {
    user[i] = '\0';
  }
  for (i=0; i < strlen(pass); i++) {
    pass[i] = '\0';
  }
  if (r == 0) {
    code = 0;
  } else {
    code = -1;
  }
  /* reply to client */
  buf[0] = 0x01;  /* sub negotiation version */
  buf[1] = code & 0xff;  /* grant or not */
  r = timerd_write(s, buf, 2, TIMEOUTSEC);
  if (r < 2) {
    /* write error */
    return(-1);
  }
  return(code);   /* access granted or not */
}

int auth_pwd_client(int s, int ind)
{
  char buf[640];
  int  r, ulen, plen;
  FILE *fp;
  char user[256];
  char pass[256];

  /* get username/password */
  seteuid(0);
  fp = fopen(pwdfile, "r");
  seteuid(PROCUID);
  if ( fp == NULL ) {
    /* cannot open pwdfile */
    return(-1);
  }

  r = readpasswd(fp, ind,
		 user, sizeof(user)-1, pass, sizeof(pass)-1);
  fclose(fp);

  if ( r != 0) {
    /* no matching entry found or error */
    return(-1);
  }
  ulen = strlen(user);
  if ( ulen < 1 || ulen > 255) {
    /* invalid user name length */
    return(-1);
  }
  plen = strlen(pass);
  if ( plen < 1 || plen > 255 ) {
    /* invalid password length */
    return(-1);
  }
  /* build auth data */
  buf[0] = 0x01;
  buf[1] = ulen & 0xff;
  memcpy(&buf[2], user, ulen);
  buf[2+ulen] = plen & 0xff;
  memcpy(&buf[2+ulen+1], pass, plen);

  r = timerd_write(s, buf, 3+ulen+plen, TIMEOUTSEC);
  if (r < 3+ulen+plen) {
    /* cannot write */
    return(-1);
  }

  /* get server reply */
  r = timerd_read(s, buf, 2, TIMEOUTSEC);
  if (r < 2) {
    /* cannot read */
    return(-1);
  }
  if (buf[0] == 0x01 && buf[1] == 0) {
    /* username/passwd auth succeded */
    return(0);
  }
  return(-1);
}

int checkpasswd(char *user, char *pass)
{
#ifdef __FreeBSD__
  struct passwd *pwd;
#elif SOLARIS
  struct spwd *spwd, sp;
  char   buf[512];
#endif
  int matched = 0;

  if (user == NULL) {
    /* user must be specified */
    return(-1);
  }

#ifdef __FreeBSD__
  seteuid(0);
  pwd = getpwnam(user);
  seteuid(PROCUID);
  if (pwd == NULL) {
    /* error in getpwnam */
    return(-1);
  }
  if (pwd->pw_passwd == NULL && pass == NULL) {
    /* null password matched */
    return(0);
  }
  if (*pwd->pw_passwd) {
    if (strcmp(pwd->pw_passwd, crypt(pass, pwd->pw_passwd)) == 0) {
      matched = 1;
    }
  }
  memset(pwd->pw_passwd, 0, strlen(pwd->pw_passwd));

#elif  SOLARIS
  seteuid(0);
  spwd = getspnam_r(user, &sp, buf, sizeof buf);
  seteuid(PROCUID);
  if (spwd == NULL) {
    /* error in getspnam */
    return(-1);
  }
  if (spwd->sp_pwdp == NULL && pass == NULL) {
    /* null password matched */
    return(0);
  }
  if (*spwd->sp_pwdp) {
    if (strcmp(spwd->sp_pwdp, crypt(pass, spwd->sp_pwdp)) == 0) {
      matched = 1;
    }
  }
  memset(spwd->sp_pwdp, 0, strlen(spwd->sp_pwdp));
#endif

#if defined(__FreeBSD__) || defined(SOLARIS)
  if (matched) {
    return(0);
  } else {
    return(-1);
  }
#endif
  return(0);
}
