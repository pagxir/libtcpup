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
} __cached_client[512];

#define RCVPKT_MAXSIZ 1500
static int __last_index = 0;

int resolved_dns_packet(void *buf, const void *packet, size_t length, int *pnetif, struct tcpup_addr *from)
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
			return length;
		}
	}

	return 0;
}

int record_dns_packet(void *packet, size_t length, int netif, const tcpup_addr *from)
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
	dnsp->q_ident = htons(client->r_ident);
	return 1;
}

#define DNS_MAGIC_LEN 4
static int _fwd_handle = 0;
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
};

struct udpuphdr4 {
    struct udpuphdr uh;
    u_char tag;
    u_char len;
    u_short port;
    u_int addr[1];
};

struct udpuphdr6 {
    struct udpuphdr uh;
    u_char tag;
    u_char len;
    u_short port;
    u_int addr[4];
};

struct udp_forward_context {
	int uf_conv;
	int uf_handle;
	long uf_rcvtime;

	tx_task_t uf_ready;
	tx_aiocb  uf_aiocb;
	tcpup_addr uf_from;

	tx_task_t uf_kill;
	tx_timer_t uf_timer;
    LIST_ENTRY(udp_forward_context) entries;
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
				fprintf(stderr, "packet is trim from %d to 1420\n", len);
				len = 1420;
			}

			struct udpuphdr4 *up4 = (struct udpuphdr4 *)udp_packet;

			up4->uh.u_conv = ctx->uf_conv;
			up4->uh.u_magic = 0xcc;
			up4->uh.u_doff = (sizeof(*up4) >> 2);
			up4->uh.u_frag = 0;
			up4->uh.u_flag = 0;
			up4->tag = 0x84;
			up4->len = 0x8;
			up4->port = saaddr.sin_port;
			up4->addr[0] = saaddr.sin_addr.s_addr;
			memcpy(up4 + 1, packet, len);
			dns_pkt[1].iov_base = udp_packet;
			dns_pkt[1].iov_len  = len + sizeof(*up4);

			utxpl_output(0, dns_pkt, 2, &ctx->uf_from);
		}
	}

	tx_aincb_active(&ctx->uf_aiocb, &ctx->uf_ready);
	return;
}

struct udp_forward_context * udp_forward_create(int conv, int type)
{
	int err;
	int bufsize = 8192;
	struct sockaddr sa = {0};
	struct udp_forward_context *ctx;
	struct udp_forward_context_q *ctxq = &_forward_header;

	LIST_FOREACH(ctx, ctxq, entries)
		if (ctx->uf_conv == conv)
			return ctx;

	ctx = new udp_forward_context;
	/* start udp process forward request */
	if (ctx != NULL) {
		ctx->uf_handle = socket(AF_INET, SOCK_DGRAM, 0);
		ctx->uf_conv   = conv;

		sa.sa_family = AF_INET;
		err = bind(ctx->uf_handle, &sa, sizeof(sa));
		assert(err == 0);

#ifdef WIN32
		setsockopt(ctx->uf_handle, SOL_SOCKET, SO_RCVBUF, (char *)&bufsize, sizeof(bufsize));
		tx_setblockopt(ctx->uf_handle, 0);
#endif

		tx_loop_t *loop = tx_loop_default();
		tx_aiocb_init(&ctx->uf_aiocb, loop, ctx->uf_handle);

		tx_task_init(&ctx->uf_ready, loop, on_udp_receive, (void *)ctx);
		tx_aincb_active(&ctx->uf_aiocb, &ctx->uf_ready);

		tx_task_init(&ctx->uf_kill, loop, on_udp_idle, (void *)ctx);
		tx_timer_init(&ctx->uf_timer, loop, &ctx->uf_kill);
		tx_timer_reset(&ctx->uf_timer, 120 * 1000);

		LIST_INSERT_HEAD(ctxq, ctx, entries);
	}

	return ctx;
}

int filter_hook_dns_forward(int netif, void *buf, size_t len, const struct tcpup_addr *from)
{
	int err = -1;
	int magic = htonl(0xfe800001);
	unsigned char *pdns = 0;

	memcpy(&magic, buf, sizeof(magic));
	if (magic == htonl(0xfe800001)) {
		struct udpuphdr *up = (struct udpuphdr *)((char *)buf + DNS_MAGIC_LEN);
		if (len >= DNS_MAGIC_LEN + sizeof(*up) && 
				up->u_flag == 0 && up->u_magic == 0xcc && up->u_flag == 0) {
			int doff = (up->u_doff << 2);
			struct sockaddr_in target = {0};
			struct udpuphdr4 *up4 = (struct udpuphdr4 *)up;

			struct udp_forward_context *c = udp_forward_create(up->u_conv, up4->tag != 0x84);
			if (up4->tag == 0x84 && c != NULL) {
				target.sin_family = AF_INET;
				target.sin_port   = (up4->port);
				target.sin_addr.s_addr   = (up4->addr[0]);
				err = sendto(c->uf_handle, (const char *)((char *)buf + DNS_MAGIC_LEN + doff),
						len - DNS_MAGIC_LEN - doff, 0, (struct sockaddr *)&target, sizeof(target));
				tx_timer_reset(&c->uf_timer, 120 * 1000);
				c->uf_rcvtime = tx_getticks();
				c->uf_from = *from;
			} else {
				fprintf(stderr, "found udp packet forward request\n");
			}

			return 1;
		}
	}

	if (magic == htonl(0xfe800000)) {
		pdns = (unsigned char *)buf;
		if (record_dns_packet(pdns + DNS_MAGIC_LEN, len - DNS_MAGIC_LEN, netif, from)) {
			err = sendto(_fwd_handle, (const char *)(pdns + DNS_MAGIC_LEN),
					len - DNS_MAGIC_LEN, 0, (struct sockaddr *)&_fwd_target, sizeof(_fwd_target));
			if (err == -1) {
				fprintf(stderr, "sendto error %s\n", strerror(errno));
				return 0;
			}
		}

		return 1;
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
			length = resolved_dns_packet(dns_packet, packet, len, &netif, &from);
			if (length > 12) {
				rgn_iovec dns_pkt[2];
				dns_pkt[0].iov_base = magic;
				dns_pkt[0].iov_len  = DNS_MAGIC_LEN;

				dns_pkt[1].iov_base = dns_packet;
				dns_pkt[1].iov_len  = length;
				utxpl_output(netif, dns_pkt, 2, &from);
			}
		}
	}

	tx_aincb_active(&_dns_aiocb, &_dns_ready);
	return;
}

static void module_init(void)
{
	int err;
	int bufsize = 1024 * 1024;
	struct sockaddr sa = {0};

	_fwd_handle = socket(AF_INET, SOCK_DGRAM, 0);

	sa.sa_family = AF_INET;
	err = bind(_fwd_handle, &sa, sizeof(sa));
	assert(err == 0);

#ifdef WIN32
	setsockopt(_fwd_handle, SOL_SOCKET, SO_RCVBUF, (char *)&bufsize, sizeof(bufsize));
	tx_setblockopt(_fwd_handle, 0);
#endif

	tx_loop_t *loop = tx_loop_default();
	tx_aiocb_init(&_dns_aiocb, loop, _fwd_handle);

	tx_task_init(&_dns_ready, loop, on_dns_receive, (void *)_fwd_handle);
	tx_aincb_active(&_dns_aiocb, &_dns_ready);

	_fwd_target.sin_family = AF_INET;
	_fwd_target.sin_port   = htons(53);

	char *nameserver = getenv("NAMESERVER");
	if (nameserver == NULL) {
		_fwd_target.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	} else {
		_fwd_target.sin_addr.s_addr = inet_addr(nameserver);
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
