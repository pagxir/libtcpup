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

#define DNS_MAGIC_LEN 24
static int _fwd_handle = 0;
static struct sockaddr_in _fwd_target = {0};

unsigned char magic[DNS_MAGIC_LEN] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
};

int filter_hook_dns_forward(int netif, void *buf, size_t len, const struct tcpup_addr *from)
{
	int err = -1;
	unsigned char *pdns = 0;

	if (memcmp(magic, buf, sizeof(magic))) {
		/* this packet is not dns query */
		return 0;
	}

	pdns = (unsigned char *)buf;
	if (record_dns_packet(pdns + DNS_MAGIC_LEN, len - DNS_MAGIC_LEN, netif, from)) {
		err = sendto(_fwd_handle, pdns + DNS_MAGIC_LEN,
			len - DNS_MAGIC_LEN, 0, (struct sockaddr *)&_fwd_target, sizeof(_fwd_target));
		if (err == -1) {
			fprintf(stderr, "sendto error %s\n", strerror(errno));
			return 0;
		}
	}

	return 1;
}

static tx_task_t _dns_ready = {0};
static tx_aiocb  _dns_aiocb = {0};
#define RCVPKT_MAXSIZ 1500

static void on_udp_receive(void *upp)
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
	setsockopt(_file, SOL_SOCKET, SO_RCVBUF, (char *)&bufsize, sizeof(bufsize));
	tx_setblockopt(_file, 0);
#endif

	tx_loop_t *loop = tx_loop_default();
	tx_aiocb_init(&_dns_aiocb, loop, _fwd_handle);

	tx_task_init(&_dns_ready, loop, on_udp_receive, (void *)_fwd_handle);
	tx_aincb_active(&_dns_aiocb, &_dns_ready);

	_fwd_target.sin_family = AF_INET;
	_fwd_target.sin_port   = htons(53);
	_fwd_target.sin_addr.s_addr   = htonl(0x08080808);
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
