#include <time.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <assert.h>
#include <stdarg.h>
#include <stdlib.h>

#include <txall.h>

#include <utx/utxpl.h>
#include <utx/socket.h>
#include <utx/dns_fwd.h>

#include <tcpup/tcp_debug.h>

struct dns_query_packet {
	unsigned short q_ident;
	unsigned short q_flags;
	unsigned short q_qdcount;
	unsigned short q_ancount;
	unsigned short q_nscount;
	unsigned short q_arcount;
};

static struct cached_client {
	int flags;
	unsigned short r_ident;
	unsigned short l_ident;

	int netif;
	struct tcpup_addr from;

	int hdrlen;
	char header[64];
} __cached_client[512];

#define RCVPKT_MAXSIZ 1500
static int __last_index = 0;

int resolved_dns_packet(void *buf, const void *packet, size_t length, int *pnetif, struct tcpup_addr *from, rgn_iovec *vec)
{
	int flags;
	int index, ident;
	struct dns_query_packet *dnsp;
	struct dns_query_packet *dnsout;

	dnsp = (struct dns_query_packet *)packet;
	flags = ntohs(dnsp->q_flags);

	if (flags & 0x8000) {
		/* from dns server */;
		ident = htons(dnsp->q_ident);
		index = (ident & 0x1FF);

		struct cached_client *client = &__cached_client[index];
		if (client->flags == 1 &&
				client->r_ident == ident) {
			client->flags = 0;
			dnsout = (struct dns_query_packet *)buf;
			memcpy(buf, packet, length);
			dnsout->q_ident = htons(client->l_ident);

			*pnetif = client->netif;
			memcpy(from, &client->from, sizeof(*from));
			vec->iov_base = client->header;
			vec->iov_len  = client->hdrlen;
			return length;
		}
	}

	return 0;
}

int record_dns_packet(void *packet, size_t length, int netif, const tcpup_addr *from, void *hdr, size_t hdrlen)
{
	int flags;
	struct dns_query_packet *dnsp;

	dnsp = (struct dns_query_packet *)packet;
	flags = ntohs(dnsp->q_flags);

	if (flags & 0x8000) {
		return 0;
	}

	/* from dns client */;
	int index = (__last_index++ & 0x1FF);
	struct cached_client *client = &__cached_client[index];

	memcpy(&client->from, from, sizeof(*from));
	client->flags = 1;
	client->l_ident = htons(dnsp->q_ident);
	client->r_ident = (rand() & 0xFE00) | index;

	client->hdrlen = hdrlen;
	assert(hdrlen <= sizeof(client->header));
	memcpy(client->header, hdr, hdrlen);

	dnsp->q_ident = htons(client->r_ident);
	return 1;
}

#define DNS_MAGIC_LEN 8
static int _fwd_handle = 0;
static int _force_override = 0;
static struct sockaddr_in _fwd_target = {0};

unsigned char magic[DNS_MAGIC_LEN] = {
	0xfe, 0x80, 0x00, 0x00
};

unsigned char magic1[DNS_MAGIC_LEN] = {
	0xfe, 0x80, 0x00, 0x01
};

struct udpuphdr {
    int u_conv;

    u_char  u_flag;
    u_char  u_magic;

    u_char  u_frag;
    u_char  u_doff;

    u_char  u_tag;
    u_char  u_len;

    u_short u_port;
};

struct udpuphdr4 {
    struct udpuphdr uh;
    u_int addr[1];
};

struct udpuphdr6 {
    struct udpuphdr uh;
    u_int addr[4];
};

struct udp_forward_context {
	int do_nat;
	int uf_conv;
	int uf_handle;
	long uf_rcvtime;

	tx_task_t uf_ready;
	tx_aiocb  uf_aiocb;
	tcpup_addr uf_from;

	tx_task_t uf_kill;
	tx_timer_t uf_timer;
	LIST_ENTRY(udp_forward_context) entries;

	struct sockaddr *(*get_dest)(struct udp_forward_context *ctx, struct udpuphdr *hdr, socklen_t *len);
};

typedef LIST_HEAD(udp_forward_context_q, udp_forward_context) udp_forward_context_q;
static udp_forward_context_q _forward_header;

static void on_udp_idle(void *upp)
{
	struct udp_forward_context *ctx = (struct udp_forward_context *)upp;

	LIST_REMOVE(ctx, entries);

	tx_timer_stop(&ctx->uf_timer);
	tx_aiocb_fini(&ctx->uf_aiocb);
	closesocket(ctx->uf_handle);

	tx_task_drop(&ctx->uf_kill);
	tx_task_drop(&ctx->uf_ready);

	delete ctx;
}

static void on_udp6_receive(void *upp)
{
	int len;
	socklen_t salen;
	struct sockaddr_in6 saaddr;
	char packet[RCVPKT_MAXSIZ];
	char udp_packet[RCVPKT_MAXSIZ];
	struct udp_forward_context *ctx = (struct udp_forward_context *)upp;

	while (tx_readable(&ctx->uf_aiocb)) {
		salen = sizeof(saaddr);
		len = recvfrom(ctx->uf_handle, packet, RCVPKT_MAXSIZ, MSG_DONTWAIT, (struct sockaddr *)&saaddr, &salen);
		tx_aincb_update(&ctx->uf_aiocb, len);
		if (len > 0) {
			rgn_iovec dns_pkt[2];
			dns_pkt[0].iov_base = magic1;
			dns_pkt[0].iov_len  = DNS_MAGIC_LEN;
			if (len > 1420) {
				TCP_DEBUG(len > 1420, "packet is trim from %d to 1420\n", len);
				len = 1420;
			}

			struct udpuphdr6 *up = (struct udpuphdr6 *)udp_packet;

			up->uh.u_conv = ctx->uf_conv;
			up->uh.u_magic = 0xcc;
			up->uh.u_doff = (sizeof(*up) >> 2);
			up->uh.u_frag = 0;
			up->uh.u_flag = 0;
			up->uh.u_tag = 0x86;
			up->uh.u_len = 20;
			up->uh.u_port = saaddr.sin6_port;
			memcpy(up->addr, &saaddr.sin6_addr, sizeof(up->addr));
			assert(len + sizeof(*up) < sizeof(udp_packet));
			memcpy(up + 1, packet, len);

			dns_pkt[1].iov_base = udp_packet;
			dns_pkt[1].iov_len  = len + sizeof(*up);

			utxpl_output(0, dns_pkt, 2, &ctx->uf_from);
		}
	}

	tx_aincb_active(&ctx->uf_aiocb, &ctx->uf_ready);
	return;
}


static void on_udp_receive(void *upp)
{
	int len;
	socklen_t salen;
	struct sockaddr_in saaddr;
	char packet[RCVPKT_MAXSIZ];
	char udp_packet[RCVPKT_MAXSIZ];
	struct udp_forward_context *ctx = (struct udp_forward_context *)upp;

	while (tx_readable(&ctx->uf_aiocb)) {
		salen = sizeof(saaddr);
		len = recvfrom(ctx->uf_handle, packet, RCVPKT_MAXSIZ, MSG_DONTWAIT, (struct sockaddr *)&saaddr, &salen);
		tx_aincb_update(&ctx->uf_aiocb, len);
		if (len > 0) {
			rgn_iovec dns_pkt[2];
			dns_pkt[0].iov_base = magic1;
			dns_pkt[0].iov_len  = DNS_MAGIC_LEN;
			if (len > 1420) {
				TCP_DEBUG(len > 1420, "packet is trim from %d to 1420\n", len);
				len = 1420;
			}

			if (ctx->do_nat && 
					saaddr.sin_port == _fwd_target.sin_port &&
					saaddr.sin_addr.s_addr == _fwd_target.sin_addr.s_addr) {
				saaddr.sin_port = htons(53);
				saaddr.sin_addr.s_addr = 0x08080808;
			}

			struct udpuphdr4 *up4 = (struct udpuphdr4 *)udp_packet;

			up4->uh.u_conv = ctx->uf_conv;
			up4->uh.u_magic = 0xcc;
			up4->uh.u_doff = (sizeof(*up4) >> 2);
			up4->uh.u_frag = 0;
			up4->uh.u_flag = 0;
			up4->uh.u_tag = 0x84;
			up4->uh.u_len = 0x8;
			up4->uh.u_port = saaddr.sin_port;
			up4->addr[0] = saaddr.sin_addr.s_addr;
			assert(len + sizeof(*up4) < sizeof(udp_packet));
			memcpy(up4 + 1, packet, len);

			dns_pkt[1].iov_base = udp_packet;
			dns_pkt[1].iov_len  = len + sizeof(*up4);

			utxpl_output(0, dns_pkt, 2, &ctx->uf_from);
		}
	}

	tx_aincb_active(&ctx->uf_aiocb, &ctx->uf_ready);
	return;
}

static int get_port(struct sockaddr *in)
{
	struct sockaddr_in *sin = (struct sockaddr_in *)in;
	return htons(sin->sin_port);
}

static struct sockaddr *udp4_get_dest(struct udp_forward_context *ctx, struct udpuphdr *up, socklen_t *plen)
{
	static struct sockaddr_in sin = {};
	struct udpuphdr4 *uphdr4 = (struct udpuphdr4 *)up;

	sin.sin_family = AF_INET;
	sin.sin_port   = (up->u_port);
	if ((uphdr4->addr[0] == 0x08080808) && (up->u_port == htons(53))) {
		sin.sin_addr = _fwd_target.sin_addr;
		sin.sin_port = _fwd_target.sin_port;
		ctx->do_nat = 1;
	} else {
		sin.sin_addr.s_addr   = (uphdr4->addr[0]);
		ctx->do_nat = 0;
	}

	if (plen != NULL) *plen = sizeof(sin);
	return (struct sockaddr *)&sin;
}

static void udp4_forward_init(struct udp_forward_context *ctx)
{
	int err;
	struct sockaddr_in sa = {0};
	struct sockaddr * sap = (struct sockaddr *)&sa;

	ctx->uf_handle = socket(AF_INET, SOCK_DGRAM, 0);
	assert(ctx->uf_handle != -1);

	sa.sin_family = AF_INET;
	err = bind(ctx->uf_handle, sap, sizeof(sa));
	assert(err == 0);

	ctx->get_dest  = udp4_get_dest;
}

static struct sockaddr *udp6_get_dest(struct udp_forward_context *ignore, struct udpuphdr *up, socklen_t *plen)
{
	static struct sockaddr_in6 sin = {0};
	struct udpuphdr6 *uphdr = (struct udpuphdr6 *)up;

	sin.sin6_family = AF_INET6;
	sin.sin6_port   = (up->u_port);
	memcpy(&sin.sin6_addr,  uphdr->addr, sizeof(sin.sin6_addr));

	if (plen != NULL) *plen = sizeof(sin);
	return (struct sockaddr *)&sin;
}

static void udp6_forward_init(struct udp_forward_context *ctx)
{
	int err;
	struct sockaddr_in6 sa = {0};
	struct sockaddr * sap = (struct sockaddr *)&sa;

	ctx->uf_handle = socket(AF_INET6, SOCK_DGRAM, 0);
	assert(ctx->uf_handle != -1);

	sa.sin6_family = AF_INET6;
	err = bind(ctx->uf_handle, sap, sizeof(sa));
	assert(err == 0);

	ctx->get_dest  = udp6_get_dest;
}

struct udp_forward_context * udp_forward_create(int conv, int type)
{
	struct udp_forward_context *ctx;
	struct udp_forward_context_q *ctxq = &_forward_header;

	LIST_FOREACH(ctx, ctxq, entries)
		if (ctx->uf_conv == conv)
			return ctx;

	ctx = new udp_forward_context;
	/* start udp process forward request */
	if (ctx != NULL) {
		ctx->do_nat    = 0;
		ctx->uf_conv   = conv;
		tx_loop_t *loop = tx_loop_default();

		if (type == 0x84) {
			udp4_forward_init(ctx);
			tx_task_init(&ctx->uf_ready, loop, on_udp_receive, (void *)ctx);
		} else {
			udp6_forward_init(ctx);
			tx_task_init(&ctx->uf_ready, loop, on_udp6_receive, (void *)ctx);
		}

#ifdef WIN32
		int bufsize = 8192;
		setsockopt(ctx->uf_handle, SOL_SOCKET, SO_RCVBUF, (char *)&bufsize, sizeof(bufsize));
		tx_setblockopt(ctx->uf_handle, 0);
#endif

		tx_aiocb_init(&ctx->uf_aiocb, loop, ctx->uf_handle);

		tx_task_init(&ctx->uf_kill, loop, on_udp_idle, (void *)ctx);
		tx_timer_init(&ctx->uf_timer, loop, &ctx->uf_kill);
		tx_timer_reset(&ctx->uf_timer, 10 * 1000);

		tx_aincb_active(&ctx->uf_aiocb, &ctx->uf_ready);
		LIST_INSERT_HEAD(ctxq, ctx, entries);
	}

	return ctx;
}

int filter_hook_dns_forward(int netif, void *buf, size_t len, const struct tcpup_addr *from)
{
	int err = -1;
	int magic = -1;
	struct udpuphdr *udphdr = NULL;

	unsigned char *payload = (unsigned char *)buf;
	unsigned char *payload_limit = (payload + len);

	payload += DNS_MAGIC_LEN;
	memcpy(&magic, buf, sizeof(magic));

	if (magic == htonl(0xfe800001)) {

		udphdr = (struct udpuphdr *)payload;
		if (payload_limit - payload >= sizeof(*udphdr) && 
				udphdr->u_flag == 0 && udphdr->u_magic == 0xcc) {
			int doff = (udphdr->u_doff << 2);
			struct sockaddr *target;

			struct udp_forward_context *c = udp_forward_create(udphdr->u_conv, udphdr->u_tag);
			if (c != NULL) {
				socklen_t target_len = 0;
				target = c->get_dest(c, udphdr, &target_len);

				err = sendto(c->uf_handle, (const char *)payload + doff,
						payload_limit - payload - doff, 0, target, target_len);
				assert (err > 0);
				int timeout = 25;
				if (get_port(target) != 53) timeout = 300;
				tx_timer_reset(&c->uf_timer, timeout * 1000);
				c->uf_rcvtime = tx_getticks();
				c->uf_from = *from;
			}

			return 1;
		}
	}

	if (magic == htonl(0xfe800000)) {

		udphdr = (struct udpuphdr *)payload;
		if (payload_limit - payload >= sizeof(*udphdr) && 
				udphdr->u_flag == 0 && udphdr->u_magic == 0xcc) {
			int doff = (udphdr->u_doff << 2);
			struct sockaddr_in target = {0};
			struct udpuphdr4 *udphdr4 = (struct udpuphdr4 *)udphdr;

			memcpy(&target, &_fwd_target, sizeof(target));
			if (udphdr->u_tag == 0x84 && !_force_override && udphdr4->addr[0] != 0x08080808) {
				target.sin_family = AF_INET;
				target.sin_port   = (udphdr->u_port);
				target.sin_addr.s_addr   = (udphdr4->addr[0]);
			}

			if (record_dns_packet(payload + doff, payload_limit - payload - doff, netif, from, payload, doff)) {
				err = sendto(_fwd_handle, (const char *)payload + doff,
						payload_limit - payload - doff, 0, (struct sockaddr *)&target, sizeof(target));
				TCP_DEBUG(err <= 0, "sendto error %s\n", strerror(errno));
			}

			TCP_DEBUG(udphdr->u_tag != 0x84, "found dns packet forward request\n");
			return 1;
		}
	}

	return 0;
}

static tx_task_t _dns_ready = {0};
static tx_aiocb  _dns_aiocb = {0};
static void on_dns_receive(void *upp)
{
	int len;
	socklen_t salen;
	struct sockaddr saaddr;
	char packet[RCVPKT_MAXSIZ];

	int netif;
	int length;
	char dns_packet[RCVPKT_MAXSIZ];
	struct tcpup_addr from = {0};

	while (tx_readable(&_dns_aiocb)) {
		salen = sizeof(saaddr);
		len = recvfrom(_fwd_handle, packet, RCVPKT_MAXSIZ, MSG_DONTWAIT, &saaddr, &salen);
		tx_aincb_update(&_dns_aiocb, len);

		if (len > 12) {
			rgn_iovec dns_pkt[3];
			length = resolved_dns_packet(dns_packet, packet, len, &netif, &from, &dns_pkt[1]);
			if (length > 12) {
				dns_pkt[0].iov_base = magic;
				dns_pkt[0].iov_len  = DNS_MAGIC_LEN;

				dns_pkt[2].iov_base = dns_packet;
				dns_pkt[2].iov_len  = length;
				utxpl_output(netif, dns_pkt, 3, &from);
			}
		}
	}

	tx_aincb_active(&_dns_aiocb, &_dns_ready);
	return;
}

static void module_init(void)
{
	int err;
	struct sockaddr sa = {0};

	_fwd_handle = socket(AF_INET, SOCK_DGRAM, 0);

	sa.sa_family = AF_INET;
	err = bind(_fwd_handle, &sa, sizeof(sa));
	assert(err == 0);

#ifdef WIN32
	int bufsize = 1024 * 1024;
	setsockopt(_fwd_handle, SOL_SOCKET, SO_RCVBUF, (char *)&bufsize, sizeof(bufsize));
	tx_setblockopt(_fwd_handle, 0);
#endif

	tx_loop_t *loop = tx_loop_default();
	tx_aiocb_init(&_dns_aiocb, loop, _fwd_handle);

	tx_task_init(&_dns_ready, loop, on_dns_receive, (void *)(long)_fwd_handle);
	tx_aincb_active(&_dns_aiocb, &_dns_ready);

	_fwd_target.sin_family = AF_INET;
	_fwd_target.sin_port   = htons(53);

	char tmp[256] = "", *p;
	char *nameserver = getenv("NAMESERVER");
	_fwd_target.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (nameserver != NULL) {
		strcpy(tmp, nameserver);
		_force_override = 0;
	}

	nameserver = getenv("NAMESERVER_OVERRIDE");
	if (nameserver != NULL) {
		strcpy(tmp, nameserver);
		_force_override = 1;
	}

	if (tmp[0] != 0) {
		p = strchr(tmp, ':');
		p && (*p++ = 0);
		p && (_fwd_target.sin_port = htons(atoi(p)));
		_fwd_target.sin_addr.s_addr = inet_addr(tmp);
	}
}

static void module_clean(void)
{
	tx_aiocb_fini(&_dns_aiocb);
	tx_task_drop(&_dns_ready);
	closesocket(_fwd_handle);
}

struct module_stub  dns_forward_mod = {
	module_init, module_clean
};
