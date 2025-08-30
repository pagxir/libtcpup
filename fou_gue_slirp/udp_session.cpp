
#include <ctype.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <sys/ioctl.h>

#include <netinet/in.h>
#include <netinet/icmp6.h>
#include <arpa/nameser.h>
#include <resolv.h>

#include <linux/if.h>
#include <linux/if_tun.h>

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

struct udp_hdr {
	uint16_t sport;
	uint16_t dport;
	uint16_t len;
	uint16_t check;
} __packed;

#define HASH_MASK 0xFFFF

typedef struct _nat_conntrack_t {
	int sockfd;
	int mainfd;
	int hash_idx;
	time_t last_alive;
	struct sockaddr_in6 source;
	struct sockaddr_in6 target;

	int port;
	tx_aiocb file;
	tx_task_t task;
	LIST_ENTRY(_nat_conntrack_t) entry;
} nat_conntrack_t;

static nat_conntrack_t *_session_last[HASH_MASK + 1] = {};
static LIST_HEAD(nat_conntrack_q, _nat_conntrack_t) _session_header = LIST_HEAD_INITIALIZER(_session_header);

static inline unsigned int get_connection_match_hash(const void *src, const void *dst, uint16_t sport, uint16_t dport)
{
	uint32_t hash = 0, hashs[4];
	uint32_t *srcp = (uint32_t *)src;
	uint32_t *dstp = (uint32_t *)dst;

	hashs[0] = srcp[0] ^ dstp[0];
	hashs[1] = srcp[1] ^ dstp[1];
	hashs[2] = srcp[2] ^ dstp[2];
	hashs[3] = srcp[3] ^ dstp[3];

	hashs[0] = (hashs[0] ^ hashs[1]);
	hashs[2] = (hashs[2] ^ hashs[3]);

	hash = (hashs[0] ^ hashs[2]) ^ sport ^ dport;
	return ((hash >> 16)^ hash) & HASH_MASK;
}

static time_t _session_gc_time = 0;
static int conngc_session(time_t now, nat_conntrack_t *skip)
{
	int timeout = 30;
	if (now < _session_gc_time || now > _session_gc_time + 30) {
		nat_conntrack_t *item, *next;

		_session_gc_time = now;
		LIST_FOREACH_SAFE(item, &_session_header, entry, next) {
			if (item == skip) {
				continue;
			}

			if ((item->last_alive > now) ||
					(item->last_alive + timeout < now)) {
				LOG_INFO("free datagram connection: %p, %d\n", skip, 0);
				int hash_idx = item->hash_idx;

				if (item == _session_last[hash_idx]) {
					_session_last[hash_idx] = NULL;
				}

				tx_aiocb_fini(&item->file);
				tx_task_drop(&item->task);
				close(item->sockfd);

				LIST_REMOVE(item, entry);
				free(item);
			}
		}
	}

	return 0;
}

static nat_conntrack_t * lookup_session(int fd, struct sockaddr_in6 *from, struct in6_addr *inner, uint16_t port)
{
	nat_conntrack_t *item;
	static uint32_t ZEROS[4] = {};

	int hash_idx0 = get_connection_match_hash(&from->sin6_addr, ZEROS, port, from->sin6_port);

	item = _session_last[hash_idx0];
	if (item != NULL) {
		if ((item->source.sin6_port == from->sin6_port) && port == item->port &&
				item->mainfd == fd &&
				IN6_ARE_ADDR_EQUAL(inner, &item->target.sin6_addr) &&
				IN6_ARE_ADDR_EQUAL(&item->source.sin6_addr, &from->sin6_addr)) {
			item->last_alive = time(NULL);
			return item;
		}
	}

	LIST_FOREACH(item, &_session_header, entry) {
		if ((item->source.sin6_port == from->sin6_port) && port == item->port &&
				item->mainfd == fd &&
				IN6_ARE_ADDR_EQUAL(inner, &item->target.sin6_addr) &&
				IN6_ARE_ADDR_EQUAL(&item->source.sin6_addr, &from->sin6_addr)) {
			item->last_alive = time(NULL);
			assert(hash_idx0 == item->hash_idx);
			_session_last[hash_idx0] = item;
			return item;
		}
	}

	return NULL;
}

static uint16_t csum_fold(uint32_t sum)
{
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);

	return sum;
}

static uint32_t udp_checksum(const void *buf, size_t len, struct in6_addr *src, struct in6_addr *dst)
{
	int i;
	uint32_t sum = 0;

	uint16_t *d1 = (uint16_t *)src;
	uint16_t *d2 = (uint16_t *)dst;

	for (i = 0; i < 8; i++) {
		sum += *d1++;
		sum += *d2++;
	}

	uint16_t *d = (uint16_t *)buf;
	for (i = 0; i < (len/2); i++) {
		sum += *d++;
	}

	if (len & 1) {
		sum += *d & htons(0xff00);
	}

	sum += htons(len + IPPROTO_UDP);
	return sum;
}

#define ALLOC_NEW(type)  (type *)calloc(1, sizeof(type))
size_t send_via_link(int fd, struct sockaddr *via, size_t vialen, struct in6_addr *src, struct in6_addr *dst,  void *payload, size_t len, void *buf, int proto);

static void do_udp_exchange_back(void *upp)
{
	int count;
	socklen_t in_len;
	char buf[2048];
	int restlen = 12 + 40 + 8;

	struct sockaddr_in6 in6addr;
	struct sockaddr * inaddr = (struct sockaddr *)&in6addr;
	nat_conntrack_t *up = (nat_conntrack_t *)upp;

	while (tx_readable(&up->file)) {
		in_len = sizeof(in6addr);
		count = recvfrom(up->sockfd, buf + restlen, sizeof(buf) - restlen, MSG_DONTWAIT, inaddr, &in_len);
		tx_aincb_update(&up->file, count);

		if (count <= 0) {
			LOG_VERBOSE("back recvfrom len %d, %d, strerr %s", count, errno, strerror(errno));
			break;
		}

		struct udp_hdr *udp = (struct udp_hdr *)(buf + restlen - 8);
		udp->sport = in6addr.sin6_port;
		udp->dport = up->target.sin6_port;
		udp->len   = htons(count + 8);

		uint32_t check = udp_checksum(udp, count + 8, &in6addr.sin6_addr, &up->target.sin6_addr);
		udp->check = csum_fold(udp->check + (uint16_t)~csum_fold(check));

		send_via_link(up->mainfd, (struct sockaddr *)&up->source, sizeof(up->source), &in6addr.sin6_addr, &up->target.sin6_addr, udp, count + 8, buf, IPPROTO_UDP);
	}

	tx_aincb_active(&up->file, &up->task);
	return;
}

static nat_conntrack_t * newconn_session(int mainfd, struct sockaddr_in6 *from, struct in6_addr *addr, int port)
{
	int sockfd;

	time_t now;
	nat_conntrack_t *conn;

	now = time(NULL);

	conn = ALLOC_NEW(nat_conntrack_t);
	if (conn != NULL) {
		conn->last_alive = now;
		conn->source = *from;
		conn->target.sin6_addr = *addr;
		conn->target.sin6_port = port;
		conn->mainfd = mainfd;
		conn->port   = port;

		sockfd = socket(AF_INET6, SOCK_DGRAM, 0);
		TX_CHECK(sockfd != -1, "create udp socket failure");

		// tx_setblockopt(sockfd, 0);

		int rcvbufsiz = 655360;
		setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, (char *)&rcvbufsiz, sizeof(rcvbufsiz));


		int sndbufsiz = 1638400;
		setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &sndbufsiz, sizeof(sndbufsiz));

		conn->sockfd = sockfd;

		tx_loop_t *loop = tx_loop_default();
		tx_aiocb_init(&conn->file, loop, sockfd);
		tx_task_init(&conn->task, loop, do_udp_exchange_back, conn);

		tx_aincb_active(&conn->file, &conn->task);

		static uint32_t ZEROS[4] = {};
		conn->hash_idx = get_connection_match_hash(&from->sin6_addr, ZEROS, port, from->sin6_port);
		LIST_INSERT_HEAD(&_session_header, conn, entry);
		_session_last[conn->hash_idx] = conn;
	}

	conngc_session(now, conn);
	return conn;
}

void * udp_lookup_create_session(int fd, struct sockaddr_in6 *link, struct in6_addr *src, struct in6_addr *dst, void *head)
{
	nat_conntrack_t * session = NULL;
	struct udp_hdr *udp = (struct udp_hdr *)head;

	if (!!(session = lookup_session(fd, link, src, udp->sport))) {
		return session;
	}

	return newconn_session(fd, link, src, udp->sport); 
}

void udp_session_forward(void *context, struct in6_addr *src, struct in6_addr *dst, void *head, size_t len)
{
	struct udp_hdr *udp = (struct udp_hdr *)head;
	nat_conntrack_t * up = (nat_conntrack_t *)context;
	struct sockaddr_in6 v6addr;
	struct sockaddr * target = (struct sockaddr *)&v6addr;

	size_t targetlen = sizeof(v6addr);
	v6addr.sin6_addr = *dst;
	v6addr.sin6_port = udp->dport;
	v6addr.sin6_family = AF_INET6;
		
	sendto(up->sockfd, udp + 1, len - sizeof(*udp), 0, target, targetlen);
}

