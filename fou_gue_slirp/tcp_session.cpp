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
struct tcp_hdr {
	uint16_t sport;
	uint16_t dport;
} __packed;

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


#define HASH_MASK 0xFFFF

typedef struct _nat_conntrack_t {
	int sockfd;
	int mainfd;
	int hash_idx;
	time_t last_alive;
	struct sockaddr_in6 link;
	struct sockaddr_in6 name;
	struct sockaddr_in6 peer;

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

static nat_conntrack_t * lookup_session_by_id(int id)
{
	nat_conntrack_t *item;

	LIST_FOREACH(item, &_session_header, entry) {
		if (item->sockfd == id) {
			item->last_alive = time(NULL);
			return item;
		}
	}

	return NULL;
}

static nat_conntrack_t * lookup_session(int fd, struct sockaddr_in6 *link, struct in6_addr *src, struct in6_addr *dst, uint16_t sport, uint16_t dport)
{
	nat_conntrack_t *item;
	static uint32_t ZEROS[4] = {};

	int hash_idx0 = get_connection_match_hash(&link->sin6_addr, ZEROS, sport, link->sin6_port);

	item = _session_last[hash_idx0];
	if (item != NULL) {
		if ((item->link.sin6_port == link->sin6_port) &&
				sport == item->name.sin6_port &&
				dport == item->peer.sin6_port &&
				item->mainfd == fd &&
				IN6_ARE_ADDR_EQUAL(dst, &item->peer.sin6_addr) &&
				IN6_ARE_ADDR_EQUAL(src, &item->name.sin6_addr) &&
				IN6_ARE_ADDR_EQUAL(&item->link.sin6_addr, &link->sin6_addr)) {
			item->last_alive = time(NULL);
			return item;
		}
	}

	LIST_FOREACH(item, &_session_header, entry) {
		if ((item->link.sin6_port == link->sin6_port) &&
				sport == item->name.sin6_port &&
				dport == item->peer.sin6_port &&
				item->mainfd == fd &&
				IN6_ARE_ADDR_EQUAL(dst, &item->peer.sin6_addr) &&
				IN6_ARE_ADDR_EQUAL(src, &item->name.sin6_addr) &&
				IN6_ARE_ADDR_EQUAL(&item->link.sin6_addr, &link->sin6_addr)) {
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

static uint32_t tcp_checksum(const void *buf, size_t len, struct in6_addr *src, struct in6_addr *dst)
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

	sum += htons(len + IPPROTO_TCP);
	return sum;
}

#define ALLOC_NEW(type)  (type *)calloc(1, sizeof(type))

static void do_tcp_exchange_back(void *upp)
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

		// 02 29 00 01 80 00 00 00 00 28 00 2e
	}

	tx_aincb_active(&up->file, &up->task);
	return;
}

static nat_conntrack_t * newconn_session(int mainfd, struct sockaddr_in6 *link, struct in6_addr *src, struct in6_addr *dst, int sport, int dport)
{
	int sockfd;

	time_t now;
	nat_conntrack_t *conn;

	now = time(NULL);

	conn = ALLOC_NEW(nat_conntrack_t);
	if (conn != NULL) {
		conn->last_alive = now;
		conn->link = *link;
		conn->name.sin6_addr = *src;
		conn->name.sin6_port = sport;
		conn->peer.sin6_addr = *dst;
		conn->peer.sin6_port = dport;
		conn->mainfd = mainfd;
		conn->port   = sport;

		sockfd = socket(AF_INET6, SOCK_STREAM, 0);
		TX_CHECK(sockfd != -1, "create tcp socket failure");

		tx_setblockopt(sockfd, 0);

		conn->sockfd = sockfd;

		tx_loop_t *loop = tx_loop_default();
		tx_aiocb_init(&conn->file, loop, sockfd);
		tx_task_init(&conn->task, loop, do_tcp_exchange_back, conn);

		static uint32_t ZEROS[4] = {};
		conn->hash_idx = get_connection_match_hash(&link->sin6_addr, ZEROS, sport, link->sin6_port);
		LIST_INSERT_HEAD(&_session_header, conn, entry);
		_session_last[conn->hash_idx] = conn;
	}

	conngc_session(now, conn);
	return conn;
}

void * tcp_lookup_create_session(int fd, struct sockaddr_in6 *link, struct in6_addr *src, struct in6_addr *dst, void *head)
{
	nat_conntrack_t * session = NULL;
	struct tcp_hdr *tcp = (struct tcp_hdr *)head;

	if (!!(session = lookup_session(fd, link, src, dst, tcp->sport, tcp->dport))) {
		return session;
	}

	return newconn_session(fd, link, src, dst, tcp->sport, tcp->dport); 
}

struct ip_hdr {
	uint8_t verhdr;
	uint8_t tos;
	uint16_t totollen;
	uint16_t id;
	uint16_t flag_frag_off;
	uint8_t ttl;
	uint8_t proto;
	uint16_t head_check;
	uint32_t src;
	uint32_t dst;
};

static uint32_t checksum(void *head, size_t len)
{
	uint32_t sum = 0;
	uint16_t *shortp = (uint16_t *)head;

	while (len > 1) {
		sum += *shortp++;
		len -= 2;
	}

	if (len > 0) {
		sum += (*shortp & htons(0xff00));
	}

	return csum_fold(sum);
}

typedef int f_tcp_write(void *head, size_t hlen, void *payload, size_t len);

f_tcp_write slip_write;
f_tcp_write * tcp_engine_write = slip_write;

void set_tcp_send_handler(f_tcp_write *handler)
{
	tcp_engine_write = handler;
	return;
}

#define PICK_UINT32(ptr, off)  (*(uint32_t *)(((char *)ptr) + off))
#define PICK_UINT16(ptr, off)  (*(uint16_t *)(((char *)ptr) + off))
#define PUT_UINT16(ptr, off, val) *(uint16_t*)(((char *)ptr) + off) = val

void tcp_session_forward(void *session, struct in6_addr *src, struct in6_addr *dst, void *head, size_t len)
{
	struct tcp_hdr *tcp = (struct tcp_hdr *)head;
	nat_conntrack_t * up = (nat_conntrack_t *)session;

	if (!IN6_IS_ADDR_V4MAPPED(dst)) {
		struct ip6_hdr ip6;
		ip6.ip6_flow = htonl(0x60000000);
		ip6.ip6_nxt  = IPPROTO_TCP;
		ip6.ip6_plen = htons(len);
		ip6.ip6_hlim = 255;
		ip6.ip6_src  = *src;
		ip6.ip6_dst  = *dst;

		uint16_t *potp = (uint16_t*)&ip6.ip6_src;
		uint32_t check = potp[7] + tcp->sport + (uint16_t)~up->sockfd;
		potp[7] = csum_fold(check);
		tcp->sport = up->sockfd;
		
#if 0
		uint32_t check = PICK_UINT16(head, 0) + csum_fold(sum) + (uint16_t)~csum_fold(ip.src);
		PUT_UINT16(head, 0, csum_fold(check));

		LOG_VERBOSE("TCP check=%x\n", 
				csum_fold(checksum(head, len) + htons(IPPROTO_TCP) + htons(len) + csum_fold(ip.src) + csum_fold(ip.dst)));
#endif
		tcp_engine_write(&ip6, sizeof(ip6), head, len);
		return;
	}

	struct ip_hdr ip;
	ip.verhdr = 0x45;
	ip.tos    = 0;
	ip.totollen = htons(len + 20);
	ip.id = (random() & 0xffff);
	ip.flag_frag_off = 0;
	ip.ttl = 0x80;
	ip.proto = IPPROTO_TCP;
	ip.head_check = 0;
	ip.src = PICK_UINT32(src, 12);
	ip.dst = PICK_UINT32(dst, 12);

	inet_pton(AF_INET, "10.0.0.0", &ip.src);
	assert (up->sockfd < 63336);

	uint32_t sum = 0;
	uint16_t *shortp = (uint16_t*)src;
	for (int i = 0; i < 8; i++) sum  += shortp[i];

	uint32_t check = tcp->sport + csum_fold(sum) + (uint16_t)~csum_fold(ip.src) + (uint16_t)~up->sockfd;
	PUT_UINT16(&ip.src, 2, csum_fold(check));
	tcp->sport = up->sockfd;

#if 0
	uint16_t *pv4a = (uint16_t *)&ip.src;
	pv4a[0] = (psrc[6]);
	pv4a[1] = csum_fold(psrc[7] + csum_fold(sum));
#endif

	sum = 0;
	shortp = (uint16_t *)&ip;
	for (int i = 0; i < 10; i++) sum += shortp[i];
	ip.head_check = (uint16_t)~csum_fold(sum);

	LOG_VERBOSE("TCP check=%x %d\n", 
			csum_fold(checksum(head, len) + htons(IPPROTO_TCP) + htons(len) + csum_fold(ip.src) + csum_fold(ip.dst)), up->sockfd);
	tcp_engine_write(&ip, sizeof(ip), head, len);
}

char *xxdump(const void *buf, size_t len);
size_t send_via_link(int fd, struct sockaddr *via, size_t vialen,
		struct in6_addr *src, struct in6_addr *dst, void *payload, size_t len, void *buf, int proto);

void tcp_packet_receive(void *frame, size_t len, void *buf)
{
	uint8_t * packet = (uint8_t *)frame;
	struct ip_hdr * ip = (struct ip_hdr *)packet;
	struct tcp_hdr * tcp = (struct tcp_hdr *)(ip + 1);
	LOG_VERBOSE("mainfd = %x\n", htonl(ip->dst));
	nat_conntrack_t * up = lookup_session_by_id(tcp->sport);

	LOG_VERBOSE("TCP receive check=%x %d\n", 
			csum_fold(checksum(tcp, len - 20) + htons(IPPROTO_TCP) + htons(len - 20) + csum_fold(ip->src) + csum_fold(ip->dst)), len);

	if (up != NULL) {
		tcp->dport = up->name.sin6_port;
		// LOG_VERBOSE("tcp ipv4 data: \n%s\n", xxdump(frame, len));
		send_via_link(up->mainfd, (struct sockaddr *)&up->link, sizeof(up->link),
			&up->peer.sin6_addr, &up->name.sin6_addr, tcp, len - 20, buf, IPPROTO_TCP); 
	}

	return;
}

int tcp_packet_receive_by_stream(int id, void *frame, size_t len, void *buf)
{
	struct tcp_hdr * tcp = (struct tcp_hdr *)frame;
	nat_conntrack_t * up = lookup_session_by_id(id);

	if (up != NULL) {
		tcp->dport = up->name.sin6_port;
		// LOG_VERBOSE("tcp ipv4 data: \n%s\n", xxdump(frame, len));
		return send_via_link(up->mainfd, (struct sockaddr *)&up->link, sizeof(up->link),
			&up->peer.sin6_addr, &up->name.sin6_addr, tcp, len, buf, IPPROTO_TCP); 
	}

	return -1;
}
