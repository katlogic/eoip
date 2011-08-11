/*
 * sd@pilsfree.net
 * gpl2 licensed, send mods pls.
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
#define HASHSZ 8192

#define MACF "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx"
#define MACA(x) x[0],x[1],x[2],x[3],x[4],x[5]

#define PORTF "%s:%d"
#define PORTA(x) ip2s(x->ip), x->key

#define DUMPING 1


#if 0
#define DEBUG printf
#else
#define DEBUG(x...)
#endif

#define LOG(msg...) {printf(msg); printf("\n");}
#define OURMAC "\x00\x10\x01\xde\xb1\x13"

#define GCTIME 10
#define BCLIMIT (64000/8)*GCTIME

struct	port {
	struct port *next;
	uint32_t ip; /* ip */
	uint32_t key; /* id tunelu */
	int count; /* pocet mac adres */
};

struct macpair {
	int bytes;
	struct macpair *next;
	struct port *port;
	time_t last;
	uint8_t mac[6];
};

struct macpair *mactab[HASHSZ];

int mactimeout = 1800;
struct	port *ports = NULL;
#define MAGIC "\x20\x01\x64\x00"
#define MAGICSZ 4
int	fdtap,fdraw;
time_t	now;
uint32_t mysrc;

static	char *ip2s(uint32_t ip)
{
	struct in_addr addr;
	addr.s_addr = ip;
	return inet_ntoa(addr);
}

static	struct port *port_add(uint32_t port, uint16_t key, int inc)
{
	struct port *curr;
	DEBUG("port add %08x\n", ntohl(port));
	for (curr = ports; curr; curr = curr->next) {
		if (curr->ip == port && curr->key == key) {
			curr->count+=inc;
			DEBUG(" -> count %d\n", curr->count);
			return curr;
		}
	}
	curr = malloc(sizeof(*curr));
	curr->ip = port;
	curr->count = inc;
	curr->next = ports;
	curr->key = key;
	ports = curr;
	LOG("ENDPOINT REGISTER " PORTF, PORTA(curr));
	return curr;
}
static	void port_del(struct port *port)
{
	struct port *curr, *prev = NULL;
	DEBUG("port del %08x\n", ntohl(port->ip));
	for (curr = ports; curr; prev = curr, curr = curr->next) {
		if (curr == port) {
			if (--curr->count <= 0) {
				LOG("ENDPOINT UNREGISTER " PORTF, PORTA(curr));
				DEBUG("  -> count 0, freeing\n");
				if (!prev) {
					ports = curr->next;
				} else {
					prev->next = curr->next;
				}
				free(curr);
			}
			return;
		}
	}
}

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
	struct ifreq ifr;
	int fd = open("/dev/net/tun", O_RDWR);
	assert(fd>=0);
	memset(&ifr,0,sizeof(ifr));
	ifr.ifr_flags = flags;
	strncpy(ifr.ifr_name, name, IFNAMSIZ);
//	write(2, &ifr, sizeof(ifr));
	ioctl(fd, TUNSETIFF, (void *) &ifr);
	ioctl(fd, TUNSETPERSIST, 1);
	return fd;
}
struct port *dstfind(uint8_t *mac)
{
	uint32_t key = machash(mac);
	struct macpair *mp;
	for (mp = mactab[key]; mp; mp = mp->next)
		if (!memcmp(mp->mac, mac, 6)) return mp->port;
	return 0;
}

/* mac adresa se objevila na nejakem portu tak ji tam pridej, pripadne
 * prehod na jinej port pokud probehl handover */
static	int srcadd(uint8_t *mac, uint32_t port, uint16_t portkey, int len)
{
	uint32_t key = machash(mac);
	struct macpair *mp;

	if (mac[0] & 0x1) return;

	for (mp = mactab[key]; mp; mp = mp->next)
		if (!memcmp(mp->mac, mac, 6)) break;
	if (!mp) {
		DEBUG("new mac " MACF "\n", MACA(mac));
		mp = malloc(sizeof(*mp));
		mp->bytes = 0;
		mp->next = mactab[key];
		mp->port = port_add(port, portkey,1);
		memcpy(mp->mac, mac, 6);
		mactab[key] = mp;
		LOG("MAC NEW " MACF " " PORTF, MACA(mac), PORTA(mp->port));
	}
	mp->last = now;
	/* probehl handover */
	if (mp->port->ip != port || mp->port->key != portkey) {
		struct port *newport = port_add(port, portkey,1);
		LOG("MAC HANDOVER " MACF " " PORTF " " PORTF "", MACA(mac), PORTA(mp->port), PORTA(newport));
		port_del(mp->port);
		mp->port = newport;
	}
	if (mac[-6] & 0x1)
	{
		mp->bytes += len;
		if (mp->bytes > BCLIMIT) return 0;
	}
	return 1;
}
void	packet_send(struct port *dst, uint8_t *p, int len)
{
	union {
		struct {
			uint8_t magic[4];
			uint16_t len;
			uint16_t key;
			char data[0];
		} gre;
		uint8_t mybuf[65536];
	} sbuf;
	struct sockaddr_in sin;

	/* neznamy cil, floodujem tap */
	if (!dst || dst->ip == 0) {
		write(fdtap, p, len);
		return;
	}
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = dst->ip;
	sin.sin_port = htons(47);

	memcpy(sbuf.gre.magic, MAGIC, MAGICSZ);
	sbuf.gre.len = htons(len);
	sbuf.gre.key = dst->key;
	memcpy(sbuf.gre.data, p, len);

	sendto(fdraw, sbuf.mybuf, len+8, 0, (struct sockaddr*) &sin, sizeof(sin));
}
/* prijmem jeden paket */
void	receive_packet(uint8_t *p, int len, uint32_t srcport, uint16_t srckey, int bcall)
{
	struct port *port, *dst;

	/* broadcast */
	if (p[0] & 0x1) {
		if (bcall)
			for (port = ports; port; port = port->next)
				if ((srcport != port->ip || srckey != port->key) && (port->ip))
					packet_send(port, p, len);
		if (srcport != -1)
			packet_send(NULL, p, len);
		return;
	}

	/* mame kam poslat? */
	if (!(dst=dstfind(p))) {
		/* neznamy cil, budem floodovat jenom tap ... */
		if (srcport) 
			packet_send(NULL, p, len);
		return;
	}
	packet_send(dst, p, len);
}

void	collect()
{
	uint32_t key;
	struct macpair *mp, *prev, *next;
	for (key = 0; key < HASHSZ; key++) {
		prev = NULL;
		for (mp = mactab[key]; mp; mp = next) {
			next = mp->next;
			mp->bytes = 0;
			if ((mp->last + mactimeout < now) && (memcmp(mp->mac, OURMAC, 6))) {
				LOG("MAC TIMEOUT " MACF " " PORTF, MACA(mp->mac), PORTA(mp->port));
				port_del(mp->port);
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

int main(int argc, char *argv[])
{
	fd_set fds;
	int	lastgc = 0;
	struct	sockaddr_in sin;
	union {
		uint8_t buf[65536];
		struct iphdr ip;
	} pkt;

	setbuf( stdout , NULL );
	assert(argc>=5);

	fdtap = opentun(IFF_TAP|IFF_NO_PI, argv[1]);
	mactimeout = atol(argv[3]);
	if (argc == 4)
		system(argv[4]);

	fdraw = socket(AF_INET, SOCK_RAW, 47);
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = inet_addr(argv[2]);
	sin.sin_port = htons(47);
	assert(bind(fdraw, (struct sockaddr*)&sin, sizeof(sin))==0);
	FD_ZERO(&fds);
	ioctl(fdtap, TUNSETNOCSUM, 1);
	while (1) {
		int len;
		uint8_t *p;
		struct timeval tv;
		FD_SET(fdtap, &fds);
		FD_SET(fdraw, &fds);
		tv.tv_sec = 1;
		tv.tv_usec = 0;
		select(max(fdtap,fdraw)+1,&fds,NULL,NULL,&tv);
		now=time(NULL);

		if (now-lastgc > GCTIME) {
			lastgc = now;
			collect();
		}
		if (FD_ISSET(fdraw, &fds)) {
			uint16_t key;
			socklen_t sinlen = sizeof(sin);
			len = recvfrom(fdraw, pkt.buf, sizeof(pkt), 0, (struct sockaddr *) &sin, &sinlen);
			p = pkt.buf + pkt.ip.ihl*4;
			len -= pkt.ip.ihl*4;
			DEBUG("len is=%d\n", len);
			if (memcmp(p, MAGIC, MAGICSZ)) continue;

			p += MAGICSZ + 4;
			len -= MAGICSZ + 4;
			if (len < 0) continue;
			key = ((uint16_t *) p)[-1]; /* klic */
#if DUMPING
			int i;
			DEBUG("len=%d\n",len);
			for (i = 0; i < len; i++) DEBUG("%02hhx ", p[i]);
			DEBUG("\n\n");
#endif
			//fflush(stdout);
			//stdout=TriggerSnippet()
			//TriggerSnippe
			if (len > 0)
			{
				receive_packet(p, len,sin.sin_addr.s_addr, key, srcadd(p+6,sin.sin_addr.s_addr, key, len));
			} else {
				port_add(sin.sin_addr.s_addr, key, 0);
			}
		}
		if (FD_ISSET(fdtap, &fds)) {
			p = pkt.buf;
			len = read(fdtap, p, sizeof(pkt));
			if (len <= 12) continue;
#if DUMPING
			int i;
			DEBUG("len=%d\n",len);
			for (i = 0; i < len; i++) DEBUG("%02hhx ", p[i]);
			DEBUG("\n\n");
#endif
			//fflush(stdout);
			srcadd(p+6,0,0,0);
			receive_packet((void *)&pkt, len, -1, -1, 1);
		}
	}
}
