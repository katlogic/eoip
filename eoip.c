/*
 * eoip, etherip tunnel daemon & virtual switch
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
#include <sys/stat.h>

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

/* Hardcoded consts */
#define GCTIME 10

#define ETHERIP 65535

#define max(a,b) ((a)>(b) ? (a):(b))
#define HASHSZ 8192

#define MACF "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx"
#define MACA(x) x[0],x[1],x[2],x[3],x[4],x[5]

#define PORTF "%s:%d"
#define PORTA(x) ip2s(x->ip), x->tid

#define DUMPING 1


#if 0
#define DEBUG printf
#else
#define DEBUG(x...)
#endif
#define LOG(msg...) {printf(msg); printf("\n");}

/* gre header */
#define GREHDR "\x20\x01\x64\x00"
#define GREHDRSZ 4

#define EHDR "\x00\x00"
#define EHDRSZ 2

/* virtual switch port */
struct	peer {
	struct peer *next;
	uint32_t ip;
	uint32_t tid;
	int count;
};

/* tunnel<->mac association */
struct macpair {
	int rx, tx; /* TBD used for bandwith usage reporting */
	struct macpair *next; /* next in bucket hash */
	struct peer *port;
	time_t last;
	uint8_t mac[6];
};
struct gre_packet {
	uint8_t magic[4];
	uint16_t len;
	uint16_t tid;
	char data[0];
};
struct eip_packet {
	uint16_t stuff;
	char data[0];
};



/* virtual switch CAM */
static struct macpair *mactab[HASHSZ];
static struct peer *peertab[HASHSZ];

/* tunables */
static int mactimeout = 1800;
static int filtering = 0;
static int fixedmode = 0;
static int ethermode = 0; /* promiscuously create etherip tunnels */
/* list of currently connected tunnels */

/* data sockets */
static int	fdtap, fdraw, fdraw2;
static time_t	now;

/* ip to string */
static	char *ip2s(uint32_t ip)
{
	struct in_addr addr;
	addr.s_addr = ip;
	return inet_ntoa(addr);
}

/* register new tunnel (optionally increment usage count) */
static	struct peer *port_get(uint32_t ip, uint32_t tid, int inc)
{
	struct peer *curr;
	uint32_t key = (ip^tid) % HASHSZ;
	DEBUG("port add %d\n", tid);

	for (curr = peertab[key]; curr; curr = curr->next) {
		if ((curr->ip == ip) && (curr->tid == tid)) {
			curr->count+=inc;
			DEBUG(" -> count %d\n", curr->count);
			return curr;
		}
	}
	if (fixedmode==2 && (tid != ETHERIP || !ethermode)) return NULL;
	curr = malloc(sizeof(*curr));
	curr->ip = ip;
	curr->count = inc;
	curr->next = peertab[key];
	curr->tid = tid;
	peertab[key] = curr;
	LOG("REG/Discovered peer/" PORTF, PORTA(curr));
	return curr;
}

/* remove port */
static	void port_put(uint32_t ip, uint32_t tid)
{
	struct peer *curr, *prev = NULL;
	uint32_t key = (ip^tid) % HASHSZ;
	DEBUG("port del %d\n", tid);
	for (curr = peertab[key]; curr; prev = curr, curr = curr->next) {
		if (curr->tid == tid && curr->ip == ip) {
			if (--curr->count <= 0) {
				LOG("UNREG/Removed peer/" PORTF, PORTA(curr));
				DEBUG("  -> count 0, freeing, %p\n", curr->next);
				if (!prev) {
					peertab[key] = curr->next;
				} else {
					prev->next = curr->next;
				}
				free(curr);
			}
			return;
		}
	}
}

/* get mac addr hash */
static	uint32_t machash(uint8_t *x)
{
	uint16_t *mm = (void *) x;
	uint32_t r = mm[0] + (mm[1] ^ mm[2]);
	r %= HASHSZ;
	//DEBUG("hash " MACF "= %08x\n", MACA(x), r);
	return r;
}

static	int opentun(int flags, char *name)
{
	printf("Opening %s\n",name);
	struct ifreq ifr;
	int fd = open("/dev/net/tun", O_RDWR);
	assert(fd>=0);
	memset(&ifr,0,sizeof(ifr));
	ifr.ifr_flags = flags;
	strncpy(ifr.ifr_name, name, IFNAMSIZ);
//	write(2, &ifr, sizeof(ifr));
	assert(ioctl(fd, TUNSETIFF, (void *) &ifr)==0);
//	ioctl(fd, TUNSETPERSIST, 1);
	return fd;
}

/* find target port according to mac */
static struct peer *dstfind(uint8_t *mac)
{
	uint32_t key = machash(mac);
	struct macpair *mp;

	/* flood broadcast */
	if (mac[0] & 0x1) return NULL;

	for (mp = mactab[key]; mp; mp = mp->next)
		if (!memcmp(mp->mac, mac, 6)) return mp->port;
	/* unknown unicast as well */
	return NULL;
}

/* learn a mac addr. returns pair if known */
static	int srcadd(uint8_t *mac, uint32_t portip, uint32_t porttid, int len)
{
	uint32_t key = machash(mac);
	struct macpair *mp;

	/* but not multicasts */
	if (mac[0] & 0x1) return 1;

	/* already got it? */
	for (mp = mactab[key]; mp; mp = mp->next)
		if (!memcmp(mp->mac, mac, 6)) break;

	/* nope. */
	if (!mp) {
		struct peer *np = port_get(portip, porttid, 1);
		if (!np) return 0;
		DEBUG("new mac " MACF "\n", MACA(mac));
		mp = malloc(sizeof(*mp));
		mp->rx = mp->tx = 0;
		mp->next = mactab[key];
		mp->port = np;
		memcpy(mp->mac, mac, 6);
		mactab[key] = mp;
		LOG("NEWMAC/New mac on port/" MACF "/" PORTF, MACA(mac), PORTA(mp->port));
	}
	/* refresh learning timer */
	mp->last = now;
	/* mac moved */
	if ((mp->port->ip != portip) || (mp->port->tid != porttid)) {
		struct peer *newport = port_get(portip, porttid, 1);
		if (!newport) return 0;
		LOG("MOVEMAC: Moved mac between ports/" MACF "/" PORTF "/" PORTF "", MACA(mac), PORTA(mp->port), PORTA(newport));
		port_put(mp->port->ip, mp->port->tid);
		mp->port = newport;
	}
	if (fixedmode!=2 || mp->port->ip==0)
		mp->port->ip = portip;
	return 1;
}

/* send a packet to the destination port */
void	packet_send(struct peer *dst, uint32_t src, uint8_t *p, int len)
{
	union {
		struct gre_packet gre;
		struct eip_packet eip;
		uint8_t mybuf[65536];
	} sbuf;
	struct sockaddr_in sin;

	/* unknown destination, flood everyone */
	if (!dst) {
		int i;
		for (i = 0; i < HASHSZ; i++) {
			for (dst = peertab[i]; dst; dst = dst->next)
				/* in case of broadcast filter, flood only
				   the tap iface, or everyone if source is tap */
				if (!filtering || ((!dst->tid) || (!src)))
					packet_send(dst, src, p, len);
		}
		return;
	}

	/* dont echo back to sender */
	if (src == dst->tid)
		return;

	/* tap interface? */
	if (!dst->tid) {
		(void)write(fdtap, p, len);
		return;
	}

	/* regular peer */
	if (!dst->ip) return; /* not associated yet */

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = dst->ip;

	if (dst->tid == 65535) {
		/* etherip */
		sin.sin_port = htons(97);
		sbuf.eip.stuff = htons(768);
		memcpy(sbuf.eip.data,p,len);
		sendto(fdraw2, sbuf.mybuf, len+2, 0, (struct sockaddr*) &sin, sizeof(sin));
	} else {
		/* mtk eoip */
		sin.sin_port = htons(47);
		memcpy(sbuf.gre.magic, GREHDR, GREHDRSZ);
		sbuf.gre.len = htons(len);
		sbuf.gre.tid = dst->tid; /* little endian! */
		memcpy(sbuf.gre.data, p, len);
		sendto(fdraw, sbuf.mybuf, len+8, 0, (struct sockaddr*) &sin, sizeof(sin));
	}

}

/* receive one packet */
void	receive_packet(uint8_t *p, int len, uint32_t srcip, uint32_t srctid)
{
	if (!srcadd(p+6, srcip, srctid, len)) return;
	packet_send(dstfind(p), srctid, p, len);
}

void	collect_garbage()
{
	uint32_t key;
	struct macpair *mp, *prev, *next;
	for (key = 0; key < HASHSZ; key++) {
		prev = NULL;
		for (mp = mactab[key]; mp; mp = next) {
			next = mp->next;
			if (mp->last + mactimeout < now) {
				LOG("EXPIREMAC/Mac address expired/" MACF "/" PORTF, MACA(mp->mac), PORTA(mp->port));
				port_put(mp->port->ip, mp->port->tid);
				if (prev) {
					prev->next = next;
				} else mactab[key] = next;
				free(mp);
				continue;
			}
			prev = mp;
		}
	}
}

void	write_status(char *fn, char *tmp)
{
	struct peer *peer;
	struct macpair *mac;
	int i;
	FILE *f = fopen(tmp, "w");

	for (i = 0; i < HASHSZ; i++) {
		for (peer = peertab[i]; peer; peer = peer->next) {
			fprintf(f, "%s %d %d\n", ip2s(peer->ip), peer->tid, peer->count);
		}
	}
	fprintf(f, "\n");
	for (i = 0; i < HASHSZ; i++) {
		for (mac = mactab[i]; mac; mac = mac->next) {
			fprintf(f, "%s:%d " MACF "\n", ip2s(mac->port->ip), mac->port->tid, MACA(mac->mac));
		}
	}
	fclose(f);
	/* this is atomic */
	rename(tmp, fn);
}

void usage(char *a0)
{
	fprintf(stderr,
		"%s [-f] [-s /tmp/statusfile] <intf> <local> [<remote>:<tunnelid> <remote:tunnelid...>]\n"
		"Flags:\n"
		"\t-f\tfilter switch ports\n"
		"\t-t N\tmac address timeout (seconds, 1800 by default)\n"
		"\t-s path\tstore connected status and mac learning reports in here\n",a0);
	exit(254);
}


int main(int argc, char *argv[])
{
	fd_set fds;
	int	lastgc = 0;
	struct	sockaddr_in sin;
	in_addr_t myip;
	int c;
	char *statusfile = NULL;
	char statustmp[1024];


	union {
		uint8_t buf[65536];
		struct iphdr ip;
	} pkt;

	while ((c = getopt(argc, argv, "fr:t:s:"))!=-1) switch (c) {
		case 'f':
			filtering=1;
			break;
		case 't':
			mactimeout=atoi(optarg);
			break;
		case 's':
			statusfile=optarg;
			sprintf(statustmp, "%s.tmp", statusfile);
			break;
		default:
			usage(argv[0]);
	}

	setbuf(stdout, NULL);
	DEBUG("%d %d\n",argc,optind);
	if (argc-optind < 2) usage(argv[0]);
	fdtap = opentun(IFF_TAP|IFF_NO_PI, argv[optind++]);
	myip = inet_addr(argv[optind++]);

	port_get(0,0,1);

	/* create static ports */
	for (;optind < argc; optind++) {
		in_addr_t peer = inet_addr(strtok(argv[optind],":"));
		char *eoipidstr = strtok(NULL, ":");
		int eoipid = eoipidstr?atoi(eoipidstr):ETHERIP;
		/* tunnel ip addresses will be locked in case of eoip */
		if (eoipid == ETHERIP && !peer) {
			ethermode=1;
			continue;
		}
		fixedmode=1;
		assert(port_get(peer, eoipid,1));
	}
	fixedmode=fixedmode*2;
	if (fixedmode==2)
		LOG("FIXED/Running in fixed mode");

	fdraw = socket(AF_INET, SOCK_RAW, 47);

	/* eoip socket */
	fdraw2 = socket(AF_INET, SOCK_RAW, 97);
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = myip;
	sin.sin_port = htons(47);
	assert(bind(fdraw, (struct sockaddr*)&sin, sizeof(sin))==0);

	/* etherip socket */
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = myip;
	sin.sin_port = htons(97);
	assert(bind(fdraw2, (struct sockaddr*)&sin, sizeof(sin))==0);


	FD_ZERO(&fds);
	ioctl(fdtap, TUNSETNOCSUM, 1);

		
	/* ad nausea */
	while (1) {
		int len;
		uint8_t *p;
		struct timeval tv;

		FD_SET(fdtap, &fds);
		FD_SET(fdraw, &fds);
		FD_SET(fdraw2, &fds);

		tv.tv_sec = 0;
		tv.tv_usec = 1000;

		select(max(max(fdtap,fdraw),fdraw2)+1,&fds,NULL,NULL,&tv);
		now=time(NULL);

		/* time for gc? */
		if (now-lastgc > GCTIME) {
			lastgc = now;
			collect_garbage();
			if (statusfile)
				write_status(statusfile, statustmp);
		}

		/* got mtk GRE packet */
		if (FD_ISSET(fdraw, &fds)) {
			uint32_t tid;
			len = recv(fdraw, pkt.buf, sizeof(pkt), 0);

			/* but not for us */
			if (pkt.ip.daddr != myip) continue;

			/* move past ip header */
			p = pkt.buf + pkt.ip.ihl*4; len -= pkt.ip.ihl*4;
			DEBUG("len is=%d\n", len);

			/* check its really eoip */
			if (memcmp(p, GREHDR, GREHDRSZ)) continue;

			/* move past header */
			p += GREHDRSZ + 4;
			len -= GREHDRSZ + 4;
			if (len < 0) continue;

			tid = ((uint16_t *) p)[-1]; /* klic */

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
			if (len >= 12)
				receive_packet(p, len,pkt.ip.saddr, tid);
		}

		/* got etherip packet */
		if (FD_ISSET(fdraw2, &fds)) {
			len = recv(fdraw2, pkt.buf, sizeof(pkt), 0);

			/* but not for us */
			if (pkt.ip.daddr != myip) continue;

			/* move past ip header */
			p = pkt.buf + pkt.ip.ihl*4; len -= pkt.ip.ihl*4;

			if ((ntohs(((uint16_t*)p)[0]))!=768) continue;
			p += 2;
			len -= 2;
#if DUMPING
			int i;
			DEBUG("len=%d\n",len);
			for (i = 0; i < len; i++) DEBUG("%02hhx ", p[i]);
			DEBUG("\n\n");
#endif
			if (len >= 12)
				receive_packet(p, len,pkt.ip.saddr, 65535);
		}

		/* local tap */
		if (FD_ISSET(fdtap, &fds)) {
			p = pkt.buf;
			len = read(fdtap, p, sizeof(pkt));
			/* some sanity */
			if (len <= 12) continue;
#if DUMPING
			int i;
			DEBUG("len=%d\n",len);
			for (i = 0; i < len; i++) DEBUG("%02hhx ", p[i]);
			DEBUG("\n\n");
			fflush(stdout);
#endif
			/* tid 0 = tap */
			receive_packet((void *)&pkt, len, 0, 0);
		}
	}
}
