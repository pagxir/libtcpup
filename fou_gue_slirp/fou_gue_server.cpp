#include <ctype.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/types.h>

#include <netinet/in.h>
#include <netinet/icmp6.h>
#include <arpa/nameser.h>
#include <resolv.h>

#ifdef WIN32
#include <windows.h>
#else
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <netdb.h>
#define closesocket close
#endif

#include "txall.h"

#include <txall.h>

#define __packed  __attribute__((__packed__))
#define ip6_vfc         ip6_ctlun.ip6_un2_vfc
#define ip6_flow        ip6_ctlun.ip6_un1.ip6_un1_flow
#define ip6_plen        ip6_ctlun.ip6_un1.ip6_un1_plen
#define ip6_nxt         ip6_ctlun.ip6_un1.ip6_un1_nxt
#define ip6_hlim        ip6_ctlun.ip6_un1.ip6_un1_hlim
#define ip6_hops        ip6_ctlun.ip6_un1.ip6_un1_hlim
struct ip6_hdr {
	union {
		struct ip6_hdrctl {
			uint32_t ip6_un1_flow;	/* 20 bits of flow-ID */
			uint16_t ip6_un1_plen;	/* payload length */
			uint8_t  ip6_un1_nxt;	/* next header */
			uint8_t  ip6_un1_hlim;	/* hop limit */
		} ip6_un1;
		uint8_t ip6_un2_vfc;	/* 4 bits version, top 4 bits class */
	} ip6_ctlun;
	struct in6_addr ip6_src;	/* source address */
	struct in6_addr ip6_dst;	/* destination address */
} __packed;

struct tcp_hdr {
	uint16_t sport;
	uint16_t dport;
	uint32_t th_seq;
	uint32_t th_ack;
    uint8_t  th_hlen;
    uint8_t  th_flags;
    uint16_t th_win;
    uint16_t th_sum;
    uint16_t th_urp;
} __packed;

static const uint8_t nat64_prefix[16] = {0, 0x64, 0xff, 0x9b, 0};
static const uint16_t v4map_prefix[8] = {0, 0, 0, 0, 0, 0xffff, 0x00, 0x00};

void * tcp_lookup_create_session(int fd, struct sockaddr_in6 *link, struct in6_addr *src, struct in6_addr *dst, void *head);
void   tcp_session_forward(void *session, struct in6_addr *src, struct in6_addr *dst, void *head, size_t len);

void * udp_lookup_create_session(int fd, struct sockaddr_in6 *link, struct in6_addr *src, struct in6_addr *dst, void *head);
void   udp_session_forward(void *session, struct in6_addr *src, struct in6_addr *dst, void *head, size_t len);

typedef void f_tcp_packet_receive(void *frame, size_t len, void *buf);
f_tcp_packet_receive tcp_packet_receive;

void   slirp_init(tx_loop_t *loop, f_tcp_packet_receive *func);
void   tcpup_init(tx_loop_t *loop, f_tcp_packet_receive *func);
void   tcptun_init(tx_loop_t *loop, f_tcp_packet_receive *func);

struct timer_task {
	tx_task_t task;
	tx_timer_t timer;
};

struct udp_exchange_context {
	int sockfd;
	int port;
	int dport;
	tx_aiocb file;
	tx_task_t task;
};

#define PUT_UINT32(ptr, off, val) *(uint32_t*)(((char *)ptr) + off) = val

static void update_timer(void *up)
{
	struct timer_task *ttp;
	ttp = (struct timer_task*)up;

	tx_timer_reset(&ttp->timer, 50000);
	LOG_INFO("update_timer %d\n", tx_ticks);

	// udp_conngc_session(time(NULL), NULL);
	return;
}

static uint16_t csum_fold(uint32_t sum)
{
	sum = (sum >> 16) + (uint16_t)sum;
	sum = (sum >> 16) + (uint16_t)sum;
	return sum;
}

static uint8_t nd_router_advert[] = {
	0x86, 0x00, 0xa3, 0x37, 0x40, 0x00, 0x07, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x01, 0x01, 0x94, 0x83, 0xc4, 0x52, 0xde, 0x75, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x05, 0x90,
	0x03, 0x04, 0x40, 0xc0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
	0x34, 0x02, 0x52, 0xe2, 0x76, 0xb5, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x19, 0x03, 0x00, 0x00, 0x00, 0x00, 0x17, 0x70, 0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64, 0x64, 0x1f, 0x04, 0x00, 0x00, 0x00, 0x00, 0x17, 0x70,
	0x08, 0x74, 0x32, 0x6d, 0x6f, 0x62, 0x69, 0x6c, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x01, 0x00, 0x00, 0x00, 0x09, 0x27, 0xc0
};

static uint16_t update_cksum_icmp6(const void *buf, size_t len, const void *addr, size_t alen)
{
	uint32_t sum = htons(len + IPPROTO_ICMPV6);
	uint16_t *ptr = (uint16_t *)buf;

	while (len > 1) {
		sum += *ptr ++;
		len -= 2;
	}

	if (len > 0) {
		sum += (*ptr & htons(0xff00));
	}

	ptr = (uint16_t *)addr;
	while (alen > 1) {
		sum += *ptr ++;
		alen -= 2;
	}
	assert(alen == 0);

	return (uint16_t)~csum_fold(sum);
}

#define HTTP_GET    0x47455420
#define HTTP_PUT    0x50555420
#define HTTP_POST   0x504f5354
#define HTTP_HTTP   0x48545450
#define HTTP_HEAD   0x48454144
#define HTTP_OPTION 0x4f505449
#define HTTP_DELETE 0x44454c45

static inline int is_http_head(void *head)
{
	struct tcp_hdr *tcp = (struct tcp_hdr *)head;
	uint32_t *data = (uint32_t *)head;
#if 0
	uint32_t magic = htonl(data[tcp->th_hlen]);
	return magic == HTTP_DELETE ||
		magic == HTTP_GET ||
		magic == HTTP_PUT ||
		magic == HTTP_OPTION ||
		magic == HTTP_HEAD ||
		magic == HTTP_POST ||
		magic == HTTP_HTTP;
#else
	uint32_t magic = data[tcp->th_hlen];
	return (magic & 0x80808080) == 0;
#endif
}

static inline int is_https_head(void *head)
{
	struct tcp_hdr *tcp = (struct tcp_hdr *)head;
	uint8_t *data = (uint8_t *)head;
	data += (tcp->th_hlen << 2);
	return (*data == 22) && (data[1] < 4) && (data[2] < 4);
}

size_t send_via_link(int fd, struct sockaddr *via, size_t vialen, struct in6_addr *src, struct in6_addr *dst,  void *payload, size_t len, void *buf, int proto)
{
	uint16_t flags[2];
	char * packet = (char *)buf;
	char * header = (char *)payload;

	struct in6_addr src0;
	assert(packet + 8 < header);
	if (memcmp(v4map_prefix, src, 12) == 0) {
		src0 = src[0];
		src = &src0;
		memcpy(src, nat64_prefix, 12);
	}

	uint32_t *identp = (uint32_t*)dst;
	PUT_UINT32((header - 4), 0, identp[3]);
	memcpy(header + len, src, 16);

	int pad = 0;
	uint16_t *ports = (uint16_t *)payload;

	flags[1] = htons(len);
	if (proto == IPPROTO_UDP && ports[0] == htons(53)) {
		flags[0] = htons(0x9700 | proto);
	} else if (proto == IPPROTO_TCP && ports[0] == htons(443) && is_https_head(ports)) {
		flags[0] = htons(0x9700 | proto);
	} else if (proto == IPPROTO_TCP && ports[0] == htons(80) && is_http_head(ports)) {
		flags[0] = htons(0x9700 | proto);
	} else if (proto == IPPROTO_ICMPV6) {
		flags[0] = htons(0x9700 | proto); pad = 0;
	} else {
		flags[0] = htons(0x6800 | proto);
	}

	memcpy(header + len + 16, flags, sizeof(flags));
	if ((flags[0] & htons(0xff00)) == htons(0x9700)) {
		uint8_t *data = (uint8_t *)payload;
		for (int i = 0; i < len; i++) *data++ ^= 0xf;
	}

	assert (len > 0);
	int error = sendto(fd, header - 4 - pad, len + 24, 0, via, vialen);

#if 0
	char abuf[56];
	struct sockaddr_in6 *via0 = (struct sockaddr_in6 *)via;
	inet_ntop(AF_INET6, &via0->sin6_addr, abuf, sizeof(abuf));
	LOG_VERBOSE("send_via_link: %s:%d %d %d\n", abuf, htons(via0->sin6_port), len + 24, error);
#endif

	return error;
}

static void do_udp_exchange_recv(void *upp)
{
	int count;
	int HEADROOM = 40;
	socklen_t in_len;
	char buf[2048];
	static time_t next_ping_time = 0;

	struct sockaddr_in6 in6addr;
	struct sockaddr * inaddr = (struct sockaddr *)&in6addr;
	udp_exchange_context *up = (udp_exchange_context *)upp;

	void *last_tcp_session = NULL;
	uint8_t tcp_fragments[81920];
	uint8_t *tcp_data = tcp_fragments;
	struct in6_addr tcp_src, tcp_dst;
	int tcp_plen[41];
	int tcp_count = 0;

	while (tx_readable(&up->file)) {
		in_len = sizeof(in6addr);
		count = recvfrom(up->sockfd, buf + HEADROOM, sizeof(buf) - HEADROOM, MSG_DONTWAIT, inaddr, &in_len);
		tx_aincb_update(&up->file, count);

		if (count <= 0) {
			LOG_VERBOSE("recvfrom len %d, %d, strerr %s", count, errno, strerror(errno));
			break;
		}

		if (count < 12) {
			LOG_VERBOSE("recvfrom len %d, %d, strerr %s", count, errno, strerror(errno));
			continue;
		}

		size_t plen = 0;
		uint32_t packet_ident = 0;
		struct ip6_hdr *ip6 = NULL;

		char *last = &buf[HEADROOM + count];
		uint16_t *packet_flags = (uint16_t *)(last - 4);

		if ((*packet_flags & htons(0xff00)) == htons(0x6000)) {
			plen = htons(packet_flags[1]);
			assert(plen < count);

			memcpy(&packet_ident, last - plen - 24, sizeof(packet_ident));
			ip6  = (struct ip6_hdr *)(last - plen - 20 - sizeof(*ip6));

			memcpy(&ip6->ip6_dst, last - 20, 16);
			inet_pton(AF_INET6, "3402:52e2:76b5::5efe:0:0", &ip6->ip6_src);
			PUT_UINT32(&ip6->ip6_src, 12, packet_ident);

			ip6->ip6_flow = htonl(0x60000000);
			ip6->ip6_nxt  = htons(packet_flags[0]);
			ip6->ip6_plen = packet_flags[1];
			ip6->ip6_hlim = 0xff;
		} else if ((*packet_flags & htons(0xff00)) == htons(0x9f00)) {
			plen = htons(packet_flags[1]);
			assert(plen < count);

			memcpy(&packet_ident, last - plen - 24, sizeof(packet_ident));
			ip6  = (struct ip6_hdr *)(last - plen - 20 - sizeof(*ip6));

			memcpy(&ip6->ip6_dst, last - 20, 16);
			inet_pton(AF_INET6, "3402:52e2:76b5::5efe:0:0", &ip6->ip6_src);
			PUT_UINT32(&ip6->ip6_src, 12, packet_ident);

			ip6->ip6_flow = htonl(0x60000000);
			ip6->ip6_nxt  = htons(packet_flags[0]);
			ip6->ip6_plen = packet_flags[1];
			ip6->ip6_hlim = 0xff;

			uint8_t *data = (uint8_t *)(ip6 + 1);
			for (int i = 0; i < plen; i++) *data++ ^= 0xf;
			
		} else if ((*packet_flags & htons(0xff00)) == htons(0x4000)) {
			// struct ip4_hdr *ip6 = (struct ip4_hdr *)(buf + HEADROOM - 40 + 4);

			continue;
		} else {
			continue;
		}

#define ICMP6_TYPE_CODE_PING (ICMP6_ECHO_REQUEST << 8)
#define ICMP6_TYPE_CODE_PONG (ICMP6_ECHO_REPLY << 8)

		struct in6_addr src = ip6->ip6_src;
		struct in6_addr dst = ip6->ip6_dst;
		uint16_t * typecode = (uint16_t *)(ip6 + 1);

		LOG_VERBOSE("proto: 0x%x len %d %x\n", ip6->ip6_nxt, htons(ip6->ip6_plen), htons(typecode[0]));

		if (ip6->ip6_nxt == IPPROTO_ICMPV6 &&
				htons(typecode[0]) == ICMP6_TYPE_CODE_PING) {
			uint32_t check = typecode[1] + htons(ICMP6_TYPE_CODE_PING) + (uint16_t)~htons(ICMP6_TYPE_CODE_PONG);
			typecode[1] = csum_fold(check);
			typecode[0] = htons(ICMP6_TYPE_CODE_PONG);

			send_via_link(up->sockfd, inaddr, in_len, &dst, &src, ip6 + 1, plen, buf, IPPROTO_ICMPV6);
			LOG_VERBOSE("ICMPv6 echo request\n");
		} else if (ip6->ip6_nxt == IPPROTO_ICMPV6 &&
				htons(typecode[0]) ==  (ND_ROUTER_SOLICIT << 8)) {

			memcpy(typecode, nd_router_advert, sizeof(nd_router_advert));
			typecode[1] = 0;
			typecode[1] = update_cksum_icmp6(typecode, sizeof(nd_router_advert), &ip6->ip6_src, 32);

			send_via_link(up->sockfd, inaddr, in_len, &dst, &src, ip6 + 1, sizeof(nd_router_advert), buf, IPPROTO_ICMPV6);
			LOG_VERBOSE("ICMPv6 router advise request\n");
		} else if (ip6->ip6_nxt == IPPROTO_TCP) {
			if (memcmp(nat64_prefix, &dst, 12) == 0) memcpy(&dst, v4map_prefix, 12);
			void * session = tcp_lookup_create_session(up->sockfd, &in6addr, &src, &dst, (ip6 + 1));

			if (last_tcp_session != session || tcp_count >= 40 || plen > 64) {
				ticks = tx_getticks();
				tcp_data = tcp_fragments;
				for (int i = 0; i < tcp_count; i++) {
					int len = tcp_plen[i];
					tcp_session_forward(last_tcp_session, &tcp_src, &tcp_dst, tcp_data, len);
					tcp_data += len;
				}
				last_tcp_session = NULL;
				tcp_data = tcp_fragments;
				tcp_count = 0;
			}

			if (plen > 64) {
				ticks = tx_getticks();
				tcp_session_forward(session, &src, &dst, ip6 + 1, plen);
				last_tcp_session = session;
				tcp_src = src;
				tcp_dst = dst;
				assert (tcp_count == 0);
				continue;
			} else if (last_tcp_session == NULL) {
				last_tcp_session = session;
				tcp_src = src;
				tcp_dst = dst;
				assert (tcp_count == 0);
			}

			int index = tcp_count++;
			assert(index < 40);
			tcp_plen[index] = plen;
			memcpy(tcp_data, ip6 + 1, plen);
			tcp_data += plen;
		} else if (ip6->ip6_nxt == IPPROTO_UDP) {
			if (memcmp(nat64_prefix, &dst, 12) == 0) memcpy(&dst, v4map_prefix, 12);
			void * session = udp_lookup_create_session(up->sockfd, &in6addr, &src, &dst, (ip6 + 1));
			udp_session_forward(session, &src, &dst, ip6 + 1, plen);
		}
	}

	ticks = tx_getticks();
	tcp_data = tcp_fragments;
	for (int i = 0; i < tcp_count; i++) {
		int len = tcp_plen[i];
		tcp_session_forward(last_tcp_session, &tcp_src, &tcp_dst, tcp_data, len);
		tcp_data += len;
	}
	last_tcp_session = NULL;
	tcp_count = 0;

	tx_aincb_active(&up->file, &up->task);
	return;
}

static void * udp_exchange_create(int port, int dport)
{
	int sockfd;
	int error = -1;
	struct sockaddr_in6 in6addr;

	fprintf(stderr, "udp_exchange_create %d\n", port);
	sockfd = socket(AF_INET6, SOCK_DGRAM, 0);
	TX_CHECK(sockfd != -1, "create udp socket failure");

	// tx_setblockopt(sockfd, 0);
#if 1
	int rcvbufsiz = 655360 * 1;
	setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, (char *)&rcvbufsiz, sizeof(rcvbufsiz));

	int sndbufsiz = 655360 * 2;
	setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &sndbufsiz, sizeof(sndbufsiz));
#endif

	int optval = 0;
	setsockopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&optval, sizeof(optval));

	in6addr.sin6_family = AF_INET6;
	in6addr.sin6_port = htons(port);
	in6addr.sin6_addr = in6addr_loopback;
	in6addr.sin6_addr = in6addr_any;

	if (getenv("BINDADDR") != NULL)
		inet_pton(AF_INET6, getenv("BINDADDR"), &in6addr.sin6_addr);

	error = bind(sockfd, (struct sockaddr *)&in6addr, sizeof(in6addr));
	TX_CHECK(error == 0, "bind udp socket failure");

	struct udp_exchange_context *up = NULL;

	up = new udp_exchange_context();
	tx_loop_t *loop = tx_loop_default();

	up->port  = port;
	up->dport  = dport;
	up->sockfd = sockfd;
	tx_aiocb_init(&up->file, loop, sockfd);
	tx_task_init(&up->task, loop, do_udp_exchange_recv, up);

	tx_aincb_active(&up->file, &up->task);

#if 0
	struct sockaddr_in6 dest;
	dest.sin6_family = AF_INET6;
	dest.sin6_port = htons(53);
	inet_pton(AF_INET6, "::ffff:101:101", &dest.sin6_addr);
	sendto(sockfd, "HELO", 4, 0, (struct sockaddr *)&dest, sizeof(dest));
#endif

	return 0;
}

int main(int argc, char *argv[])
{
	int err;
	unsigned int last_tick = 0;
	struct timer_task tmtask;

#ifndef WIN32
	signal(SIGPIPE, SIG_IGN);
#endif

	tx_loop_t *loop = tx_loop_default();
	tx_poll_t *poll = tx_epoll_init(loop);
	tx_timer_ring *provider = tx_timer_ring_get(loop);
	tx_timer_init(&tmtask.timer, loop, &tmtask.task);

	tx_task_init(&tmtask.task, loop, update_timer, &tmtask);
	tx_timer_reset(&tmtask.timer, 500);

	for (int i = 1; i < argc; i++) {
		int port, dport, match;
		if (0 == strcmp(argv[i], "-slirp"))  {
			slirp_init(loop, tcp_packet_receive);
		} else if (0 == strcmp(argv[i], "-tcpup"))  {
			tcpup_init(loop, tcp_packet_receive);
		} else if (0 == strcmp(argv[i], "-tcptun"))  {
			tcptun_init(loop, tcp_packet_receive);
		} else if (0 == strcmp(argv[i], "-cc.algo"))  {
			void set_cc_algo(const char *name);
			if (i < argc) set_cc_algo(argv[++i]);
			continue;
		} else if ((match = sscanf(argv[i], "%d", &port)) == 1) {
			assert (port >  0 && port < 65536);
			udp_exchange_create(port, port);
		}
	}

	tx_loop_main(loop);

	tx_timer_stop(&tmtask.timer);
	tx_loop_delete(loop);

	TX_UNUSED(last_tick);

	return 0;
}
