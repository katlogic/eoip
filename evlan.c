/*
 * 802.1q vlan -> eoip tagging gateway
 * (c) 2008-2011 Karel Tuma <karel.tuma@pilsfree.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 * 
 * You should have received a copy of the GNU General Public License
 * (for example /usr/src/linux/COPYING); if not, write to the Free
 * Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <linux/if.h>
#include <linux/if_tun.h>
#include <string.h>
#include <stdarg.h>
#include <assert.h>
#include <time.h>

#include <netinet/ip.h>
#include <arpa/inet.h>

#define max(a,b) ((a)>(b) ? (a):(b))

#if 0
#define DEBUG printf
#else
#define DEBUG(x...)
#endif
#define LOG(msg...) {printf(msg); printf("\n");}

/* gre header */
#define GREHDR "\x20\x01\x64\x00"
#define GREHDRSZ 4

struct gre_packet {
	uint8_t magic[4];
	uint16_t len;
	uint16_t tid;
	char data[0];
};

static	int opentun(int flags, char *name)
{
	struct ifreq ifr;
	int fd = open("/dev/net/tun", O_RDWR);
	assert(fd>=0);
	memset(&ifr,0,sizeof(ifr));
	ifr.ifr_flags = flags;
	strncpy(ifr.ifr_name, name, IFNAMSIZ);
//	write(2, &ifr, sizeof(ifr));
	ioctl(fd, TUNSETIFF, (void *) &ifr);
//	ioctl(fd, TUNSETPERSIST, 1);
	return fd;
}

void usage(char *a0)
{
	fprintf(stderr,
		"%s <intf> <localip> <remoteip - eoip target> [ignored vlan ids]\n",a0);
	exit(254);
}


int main(int argc, char *argv[])
{
	int	fdtap, fdraw, i;
	unsigned char ignore[4096];

	if (argc < 4)
		usage(argv[0]);
	memset(ignore,0,sizeof(ignore));
	for (i = 3; i < argc; i++)
		ignore[atoi(argv[i])]=1;

	fd_set fds;
	struct	sockaddr_in sin;
	in_addr_t locip;
	in_addr_t remip;

	union {
		uint8_t buf[65536];
		struct iphdr ip;
	} pkt;

	fdtap = opentun(IFF_TAP|IFF_NO_PI, argv[1]);
	locip = inet_addr(argv[2]);
	remip = inet_addr(argv[3]);

	/* eoip socket */
	fdraw = socket(AF_INET, SOCK_RAW, 47);
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = locip;
	sin.sin_port = htons(47);
	assert(bind(fdraw, (struct sockaddr*)&sin, sizeof(sin))==0);

	/* sending socket */
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = remip;


	FD_ZERO(&fds);
	ioctl(fdtap, TUNSETNOCSUM, 1);

	/* ad nausea */
	while (1) {
		int len;
		uint8_t *p;
		struct timeval tv;
		uint32_t tid;

		FD_SET(fdtap, &fds);
		FD_SET(fdraw, &fds);

		tv.tv_sec = 1;
		tv.tv_usec = 0;

		select(max(fdtap,fdraw)+1,&fds,NULL,NULL,&tv);

		/* got mtk GRE packet */
		if (FD_ISSET(fdraw, &fds)) {
			len = recv(fdraw, pkt.buf, sizeof(pkt), 0);

			/* but not for us */
			if (pkt.ip.daddr != locip) continue;
			if (pkt.ip.saddr != remip) continue;

			/* move past ip header */
			p = pkt.buf + pkt.ip.ihl*4; len -= pkt.ip.ihl*4;
			DEBUG("len is=%d\n", len);

			/* check its really eoip */
			if (memcmp(p, GREHDR, GREHDRSZ)) continue;

			/* move past header */
			p += GREHDRSZ + 4;
			len -= GREHDRSZ + 4;
			if (len < 0) continue;

			tid = ((uint16_t *) p)[-1]; /* tunnel id, actually 802.1q tag number */
			if (tid > 4095) continue;
			if (ignore[tid]) continue;

			/* IP hdr/eoip length mismatch */
			if (len != ntohs(((uint16_t*)p)[-2])) {
				DEBUG("%d %d\n",len,ntohs(((uint16_t*)p)[-2]));
				continue;
			}
#if DUMPING
			int i;
			DEBUG("len=%d\n",len);
			for (i = 0; i < len; i++) DEBUG("%02hhx ", p[i]);
			DEBUG("\n\n");
#endif
			/* shift src/dst mac by 4 bytes */
			memmove(p-4,p,12);
			p[12-4] = 0x81; p[13-4] = 0x00;
			p[14-4] = /*0x40 | */(tid>>8);
			p[15-4] = tid & 0xff;
			write(fdtap, p-4, len+4);
		}


		/* local tap */
		if (FD_ISSET(fdtap, &fds)) {
			union {
				struct gre_packet gre;
				uint8_t mybuf[65536];
			} sbuf;

			p = pkt.buf;
			len = read(fdtap, p, sizeof(pkt));
			/* some sanity */
			if (len <= 16) continue;
			/* only tagged packets please */
			if (p[12] != 0x81 || p[13] != 0x00) continue;
			tid = ((p[14] << 8)&0xf00) | p[15];
			if (ignore[tid]) continue;
			memcpy(sbuf.gre.data, p, 12); /* src & dst mac */
			memcpy(sbuf.gre.data + 12, p + 16, len-16); /* skip the tag */

			sin.sin_port = htons(47);
			memcpy(sbuf.gre.magic, GREHDR, GREHDRSZ);
			sbuf.gre.len = htons(len - 4);
			sbuf.gre.tid = tid; /* little endian! */
			sendto(fdraw, sbuf.mybuf, len+8-4, 0, (struct sockaddr*) &sin, sizeof(sin));
		}
	}
}
