#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>

#include <txall.h>
#include <utx/utxpl.h>
#include <utx/socket.h>
#include <utx/router.h>

#include "dns_txasync.h"
#include "tcp_channel.h"
#include "pstcp_channel.h"


#define STACK2TASK(s) (&(s)->tx_sched)
#define EXTRA_FLAGS_INTERACTIVE (1 << 24)

#define TF_RESOLVED   0x10
#define TF_RESOLVING  0x20

#define TF_CONNECTED  0x40
#define TF_CONNECTING 0x80

#define TF_EOF0       0x1
#define TF_SHUT0      0x2

#define TF_EOF1       0x4
#define TF_SHUT1      0x8

#ifndef WIN32
#include <errno.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#define SD_BOTH SHUT_RDWR
#define WSAEINPROGRESS EINPROGRESS
#else
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

struct relay_data {
	int off;
	int len;
#define RDF_EOF 0x01
#define RDF_FIN 0x02
#define RDF_BROKEN 0x04
	int flag;
	char buf[1 << 16];
};

class pstcp_channel {
	public:
		pstcp_channel(sockcb_t so);
		~pstcp_channel();

	public:
		int run(void);
		int reset_keepalive();
		static void tc_callback(void *context, tx_task_stack_t *sta);

	private:
		int m_file;
		int m_dns_handle;
		static int total_instance;

		int m_skip_count;
		int use_socks_backend;

	public:
		int m_flags;
		int m_extraflags;
		struct relay_data r2s;
		struct relay_data s2r;

		sockcb_t m_peer;
		tx_aiocb m_sockcbp;
		tx_task_stack_t m_tasklet;

	private:
		tx_task_t xidle;
		tx_timer_t tidle;
		static void tc_idleclose(void *context);
		int expend_relay(struct sockaddr_storage *, sockcb_t , u_long , u_short , struct tx_task_t *);
};

int pstcp_channel::total_instance = 0;

u_short _forward_port = 1080;
u_long  _forward_addr = INADDR_LOOPBACK;
static int get_backend(const char relay[], size_t len);

static void anybind(int fd, int family)
{
	struct sockaddr_in6 si6addr = {0};
	const char *bind_addr = getenv("BIND_ADDR");

	si6addr.sin6_family = AF_INET6;
	si6addr.sin6_port   = 0;

	if (bind_addr) {
		inet_pton(AF_INET6, bind_addr, &si6addr);
	}

	bind(fd, (struct sockaddr *)&si6addr, sizeof(si6addr));
	return;
}

	pstcp_channel::pstcp_channel(sockcb_t so)
:m_flags(0), m_extraflags(0)
{
	int len;
	char relay[128];

	s2r.flag = 0;
	s2r.off = s2r.len = 0;

	r2s.flag = 0;
	r2s.off = r2s.len = 0;

	m_peer = so;
	m_dns_handle = -1;

	tx_loop_t *loop = tx_loop_default();
	tx_task_init(&xidle, loop, tc_idleclose, this);
	tx_timer_init(&tidle, loop, &xidle);

	tx_task_stack_init(&m_tasklet, loop);
	tx_task_stack_push(&m_tasklet, tc_callback, this);

	len = sooptget_target(so, relay, sizeof(relay));

	m_file = socket(AF_INET6, SOCK_STREAM, 0);

	assert(m_file != -1);
	disable_ipv6_only(m_file);
	tx_setblockopt(m_file, 0);
	anybind(m_file, AF_INET6);
	tx_aiocb_init(&m_sockcbp, loop, m_file);
	total_instance++;
}

pstcp_channel::~pstcp_channel()
{
	if (m_dns_handle != -1) {
		dns_query_close(m_dns_handle);
		m_dns_handle = -1;
	}

#if 1
    const char *info = "";
    int port = 0;

    int sfd = m_sockcbp.tx_fd;
    if (sfd != -1) {
        struct sockaddr_in6 inaddr;
        socklen_t inlen = sizeof(inaddr);
        if (0 == getpeername(sfd, (struct sockaddr*)&inaddr, &inlen)) {
			info = ntop6(inaddr.sin6_addr);
			port = htons(inaddr.sin6_port);
        }
    }

    LOG_DEBUG("link is close: %s:%d, %x", info, port, m_extraflags);
#endif
	LOG_DEBUG("pstcp_channel::~pstcp_channel: %d\n", total_instance);

	tx_aiocb_fini(&m_sockcbp);
	soclose(m_peer);

	tx_timer_stop(&tidle);
	tx_task_drop(&xidle);

	tx_task_stack_drop(&m_tasklet);

	closesocket(m_file);
	total_instance--;
}

#if 0
int pstcp_channel::expend_relay(struct sockaddr_storage *destination, sockcb_t tp, u_long defdest, u_short port, struct tx_task_t *task)
{
	int len, typ;
	struct addrinfo hints;
	char *p, relay[64], serv[10];

	struct sockaddr_in6 *dst4 =
		(struct sockaddr_in6 *)destination;

	struct sockaddr_in6 *dst6 =
		(struct sockaddr_in6 *)destination;

	p = relay;
	len = sooptget_target(tp, relay, sizeof(relay));

	if (use_socks_backend) {
		dst4->sin_family = AF_INET;
		dst4->sin_addr.s_addr = inet_addr("127.0.0.1");
		dst4->sin_port = htons(1080);
		return 0;
	}

	while (len > 4 && len < sizeof(relay)) {
		int err = 0;
		unsigned short p0;
		const struct route_item *fib;
		typ = *p++;
		if (*p++ != 0) break;

		memcpy(&p0, p, sizeof(p0));
		p += 2;

		switch (typ) {
			case 0x01:
				/* IPv4 (8 byte): atyp=0x01 + 0x0 + port[2]+ addr[4]. */
				if (len == 8) {
					int hport = ntohs(p0);
					dst4->sin_family = AF_INET;
					dst4->sin_port   = p0;
					memcpy(&dst4->sin_addr, p, 4);
					fib = route_get(dst4->sin_addr);
					if (fib != NULL && fib->nexthop == INADDR_LOOPBACK) {
						dst4->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
					}

					if (hport == 14000) m_extraflags |= EXTRA_FLAGS_INTERACTIVE;
					if (hport == 5228) m_extraflags |= EXTRA_FLAGS_INTERACTIVE;
					return 0;
				}

				break;

			case 0x03:
				/* FQDN (4 + x byte): atyp=0x01 + 0x0 + port[2] + fqdn[4]. */
				memset(&hints, 0, sizeof(struct addrinfo));
				hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
				hints.ai_socktype = SOCK_STREAM; /* Datagram socket */
				hints.ai_flags = 0;
				hints.ai_protocol = 0;          /* Any protocol */

				err = snprintf(serv, sizeof(serv), "%d", ntohs(p0));
				assert(err < sizeof(serv));
				relay[len] = 0;

				m_dns_handle = dns_query_open(relay + 4, serv, &hints, task);
				if (m_dns_handle >= 0) {
					LOG_DEBUG("dns query is pending: %s\n", relay + 4);
					return 1;
				}

				break;

			case 0x04:
				/* IPv6 (8 byte): atyp=0x04 + 0x0 + port[2] + addr6[16]. */
				if (len == 20) {
					dst6->sin6_family = AF_INET6;
					dst6->sin6_port   = p0;
					memcpy(&dst6->sin6_addr, p, 16);
					return 0;
				}

				break;
		}

		break;
	}

	dst4->sin_family = AF_INET;
	dst4->sin_port   = htons(port);
	dst4->sin_addr.s_addr = htonl(defdest);
	LOG_DEBUG("relay: len %d\n", len);
	return 0;
}
#endif

int socksv5_connect(sockcb_t cb, void *buf, size_t size)
{
	char relay[128];
	char *p = relay;

	int len = sooptget_target(cb, relay, sizeof(relay));

	while (len > 4 && len < sizeof(relay)) {
		int typ = *p++;
		unsigned short p0;

		if (*p++ != 0) break;

		memcpy(&p0, p, 2);
		p += 2;

		switch(typ) {
			case 0x01:
				if (len == 8) {
					char *cmdp = (char *)buf;
					*cmdp++ = 0x05;
					*cmdp++ = 0x01;
					*cmdp++ = 0x00;

					*cmdp++ = 0x05;
					*cmdp++ = 0x01;
					*cmdp++ = 0x00;
					*cmdp++ = typ;
					memcpy(cmdp, p, 4);
					cmdp += 4;
					memcpy(cmdp, &p0, 2);
					cmdp += 2;
					return cmdp - (char *)buf;
				}
				break;

			case 0x04:
				if (len == 20) {
					char *cmdp = (char *)buf;
					*cmdp++ = 0x05;
					*cmdp++ = 0x01;
					*cmdp++ = 0x00;

					*cmdp++ = 0x05;
					*cmdp++ = 0x01;
					*cmdp++ = 0x00;
					*cmdp++ = typ;
					memcpy(cmdp, p, 16);
					cmdp += 16;
					memcpy(cmdp, &p0, 2);
					cmdp += 2;
					return cmdp - (char *)buf;
				}
				break;
		}
	}

	return 0;
}

static int get_keepalive(int count)
{
	int keepalive = 16 * 60 / count;
	if (keepalive < 1) keepalive = 1;
	if (keepalive > 60) keepalive = 60;
	return 100 * keepalive;
}

#define MAX(a, b) ((a) < (b)? (b): (a))
#define MIN(a, b) ((a) < (b)? (a): (b))

#if 0
int pstcp_channel::run0(void)
{
	int len = 0;
	int error = -1;
	int change = 0;

	socklen_t namelen;
	struct sockaddr_storage name;

	int timeout = 1000 * get_keepalive(total_instance);
	if ((s2r.flag & RDF_FIN) || (RDF_FIN & r2s.flag)) {
		timeout = MIN(timeout, 1000 * 120);
	} else if (m_extraflags & EXTRA_FLAGS_INTERACTIVE) {
		timeout = MAX(timeout, 1000 * 1800);
	}
	tx_timer_reset(&tidle, timeout); // close after 3 min idle time

#define TF_RESOLVABLE(flags) (0x0 == (flags&(TF_RESOLVING|TF_RESOLVED)))
	if (TF_RESOLVABLE(m_flags)) {
		error = expend_relay(&name, m_peer, _forward_addr, _forward_port, STACK2TASK(&m_tasklet));
		if (error == -1) {
			LOG_DEBUG("do dns resolv error\n");
			return 0;
		}

		if (error) {
			m_flags |= TF_RESOLVING;
			return 1;
		}

		m_flags |= TF_RESOLVED;
	} else {
		int error;
		int rsoket;
		struct tx_loop_t *loop;
		struct addrinfo *rp, *result = 0;

		if (m_dns_handle != -1 && (m_flags & TF_RESOLVING)) {
			error = dns_query_result(m_dns_handle, &result);
			if (error) {
				LOG_DEBUG("do dns async resolv failure\n");
				return 0;
			}

			if (result != NULL) {
				m_flags &= ~TF_RESOLVING;
				m_flags |= TF_RESOLVED;

				tx_aiocb_fini(&m_sockcbp);
				closesocket(m_file);

				loop = tx_loop_default();
				for (rp = result; rp != NULL; rp = rp->ai_next) {
					rsoket = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
					if (rsoket == -1) continue;
					tx_setblockopt(rsoket, 0);
					anybind(rsoket, rp->ai_family);

					tx_aiocb_init(&m_sockcbp, loop, rsoket);
					error = tx_aiocb_connect(&m_sockcbp, (struct sockaddr *)rp->ai_addr, rp->ai_addrlen, STACK2TASK(&m_tasklet));

					if (error == 0 || error == -WSAEINPROGRESS) {
						m_file = rsoket;
						if (error) {
							m_flags |= TF_CONNECTING;
							LOG_DEBUG("connect is pending: error = %d\n", errno);
							dns_query_close(m_dns_handle);
							m_dns_handle = -1;
							return 1;
						}

						m_flags |= TF_CONNECTED;
						LOG_DEBUG("connect all pending\n");
						dns_query_close(m_dns_handle);
						m_dns_handle = -1;
						return 1;
					}

					LOG_DEBUG("connect error code: %d\n", errno);
					tx_aiocb_fini(&m_sockcbp);
					closesocket(rsoket);
				}

				LOG_DEBUG("connect all failure\n");
				return 0;
			}

			LOG_DEBUG("query is pending\n");
			return 1;
		}
	}

#define TF_CONNECTABLE(f) (0x0 == (f&(TF_CONNECTING|TF_CONNECTED)))
	if (TF_CONNECTABLE(m_flags) && (m_flags & TF_RESOLVED)) {
		namelen = sizeof(struct sockaddr_in);
		if (name.ss_family == AF_INET6) {
			namelen = sizeof(struct sockaddr_in6);
		}

		error = tx_aiocb_connect(&m_sockcbp, (struct sockaddr *)&name, namelen, STACK2TASK(&m_tasklet));
		if (error == 0 || error == -WSAEINPROGRESS) {
			if (error) {
				LOG_DEBUG("connect is pending\n");
				m_flags |= TF_CONNECTING;
				return 1;
			} else if (use_socks_backend) {
				r2s.len = socksv5_connect(m_peer, r2s.buf, sizeof(r2s.buf));
				if (r2s.len > 0) m_skip_count = 12;
			}

			LOG_DEBUG("connect all pending\n");
			m_flags |= TF_CONNECTED;
			return 1;
		}

		LOG_DEBUG("tcp connect error: %s\n", strerror(errno));
#ifndef WIN32
		v4_only = (errno == EINVAL? 1: v4_only);
#endif
		return 0;
	} else {
		if (tx_writable(&m_sockcbp)
				&& (m_flags & TF_CONNECTING)) {
			LOG_DEBUG("connect is finish...\n");
			m_skip_count = 0;
			if (use_socks_backend) {
				r2s.len = socksv5_connect(m_peer, r2s.buf, sizeof(r2s.buf));
				if (r2s.len > 0) m_skip_count = 12;
			}
			m_flags &= ~TF_CONNECTING;
			m_flags |= TF_CONNECTED;
		}

		if ((m_flags & TF_CONNECTED) == 0) {
			LOG_DEBUG("%p connect is inprogress...\n", this);
			return 1;
		}
	}


	return error;
}
#endif

int pstcp_channel::reset_keepalive()
{
	int timeout = 1000 * get_keepalive(total_instance);

	if ((s2r.flag & RDF_FIN) || (RDF_FIN & r2s.flag)) {
		timeout = MIN(timeout, 1000 * 120);
	} else if (m_extraflags & EXTRA_FLAGS_INTERACTIVE) {
		timeout = MAX(timeout, 1000 * 1800);
	}

	tx_timer_reset(&tidle, timeout); // close after 3 min idle time
	return 0;
}

enum {
	INDEX_BASE = 1,
	INDEX_BROKEN,
	INDEX_RESOLVED,
	INDEX_CONNECTED,
	INDEX_TRANSFERED,

	INDEX_CONNECTING,
};

#define FLAG_ZERO        (0)
#define FLAG_BASE        (1 << INDEX_BASE)
#define FLAG_BROKEN      (1 << INDEX_BROKEN)
#define FLAG_RESOLVED    (1 << INDEX_RESOLVED)
#define FLAG_CONNECTED   (1 << INDEX_CONNECTED)
#define FLAG_TRANSFERED  (1 << INDEX_TRANSFERED)
#define FLAG_CONNECTING  (1 << INDEX_CONNECTING)

#define FLAG_GET(flags, mask) ((flags) & (mask))

void do_name_resovled(void *upp, tx_task_stack_t *sta)
{
	return;
}

static void bug_check(int cond)
{
	if (cond) return;
	abort();
	return;
}

#define AFTYP_INET   1
#define AFTYP_DOMAIN 3
#define AFTYP_INET6  4

static int peer_info_expend(const char *relay, size_t len, char *domain, size_t size, struct sockaddr_storage *ss, int *isinteractive)
{
	int type, val_port;
	const char *p = relay;
	unsigned short val_short;
	struct sockaddr_in6 *in6p;
	const struct route_item *fib;
	char _source[256];

	type = *p++;
	bug_check(*p++ == 0);

	memcpy(&val_short, p, sizeof(val_short));
	p += sizeof(val_short);

	switch (type) {
		case AFTYP_INET:
			/* IPv4 (8 byte): atyp=0x01 + 0x0 + port[2]+ addr[4]. */
			bug_check(len == 8);
			in6p = (struct sockaddr_in6 *)ss;
			in6p->sin6_family = AF_INET6;
			in6p->sin6_port   = val_short;
			inet_4to6(&in6p->sin6_addr, p);
			NAT64_UPDATE(&in6p->sin6_addr, isinteractive);
			LOG_DEBUG("TARGET4: %s %d %p", inet_ntop(AF_INET6, &in6p->sin6_addr, _source, sizeof(_source)), htons(val_short), isinteractive);

			val_port = htons(val_short);
			if (val_port == 5228) *isinteractive |= EXTRA_FLAGS_INTERACTIVE;
			break;

		case AFTYP_INET6:
			/* IPv6 (8 byte): atyp=0x04 + 0x0 + port[2] + addr6[16]. */
			bug_check(len == 20);
			in6p = (struct sockaddr_in6 *)ss;
			in6p->sin6_family = AF_INET6;
			in6p->sin6_port   = val_short;
			in6p->sin6_addr   = *(struct in6_addr *)p;
			NAT64_UPDATE(&in6p->sin6_addr, isinteractive);
			LOG_DEBUG("TARGET: %s", inet_ntop(AF_INET6, &in6p->sin6_addr, _source, sizeof(_source)));
			if (val_short == htons(5228)) *isinteractive |= EXTRA_FLAGS_INTERACTIVE;
			break;

		case AFTYP_DOMAIN:
			/* FQDN (4 + x byte): atyp=0x01 + 0x0 + port[2] + fqdn[4]. */
			strncpy(domain, p, size);
			break;

		default:
			abort();
			break;
	}

	return type;
}

static const char *P(struct in_addr *ip)
{
    static int _si = 0;
    static char sbuf[4][16] = {};
    char *_sbuf = sbuf[_si++ % 4];
	snprintf(_sbuf, sizeof(sbuf[0]), "%s", inet_ntoa(*ip));
	return _sbuf;
}

static void do_peer_connect(void *upp, tx_task_stack_t *sta)
{
	int len;
	int type;
	char relay[64], domain[64];
	pstcp_channel *up = (pstcp_channel *)upp;
	struct sockaddr_storage sa_store = {};

	len = sooptget_target(up->m_peer, relay, sizeof(relay));
	assert (len > 4 && len < sizeof(relay));

	up->reset_keepalive();
	up->m_flags |= FLAG_CONNECTED;

	relay[len] = 0;
	type = peer_info_expend(relay, len, domain, sizeof(domain), &sa_store, &up->m_extraflags);
	if (type == AFTYP_DOMAIN) {
		tx_task_stack_raise(sta, "do_peer_connect");
		return;
	}

	if (FLAG_ZERO == FLAG_GET(up->m_flags, FLAG_CONNECTING| FLAG_ZERO| FLAG_BROKEN)) {
		tx_aiocb_connect(&up->m_sockcbp, (struct sockaddr *)&sa_store, sizeof(sa_store), STACK2TASK(sta));
		up->m_flags |= FLAG_CONNECTING;
		return;
	}

	if (tx_writable(&up->m_sockcbp)) {
		tx_task_stack_pop0(sta);
		tx_task_stack_active(sta, "do_peer_connect");
	}

	return;
}

static int fill_data(struct relay_data *d, tx_aiocb *f)
{
	int len;
	int change = 0;

	if (d->off >= d->len) {
		d->off = d->len = 0;
	}

	if (tx_readable(f) && d->len < sizeof(d->buf) && !d->flag) {
		len = recv(f->tx_fd, d->buf + d->len, sizeof(d->buf) - d->len, 0);
		tx_aincb_update(f, len);

		change |= (len > 0);
		if (len > 0)
			d->len += len;
		else if (len == 0) {
			fprintf(stderr, "read eof stream of aiocb TODO:XXX\n");
			assert(d->len < sizeof(d->buf));
			d->flag |= RDF_EOF;
		} else if (tx_readable(f)) // socket meet error condiction
			d->flag |= RDF_BROKEN;
	}

	return (d->flag & RDF_BROKEN)? (2|change): change;
}

static int fill_data(struct relay_data *d, sockcb_t f)
{
	int len;
	int change = 0;

	if (d->off >= d->len) {
		d->off = d->len = 0;
	}

	if (soreadable(f) && d->len < sizeof(d->buf) && !d->flag) {
		len = soread(f, d->buf + d->len, sizeof(d->buf) - d->len);

		change |= (len > 0);
		if (len > 0)
			d->len += len;
		else if (len == 0) {
			assert(d->len < sizeof(d->buf));
			fprintf(stderr, "read eof stream of sockcb TODO:XXX\n");
			d->flag |= RDF_EOF;
		} else if (soreadable(f)) // socket meet error condiction
			d->flag |= RDF_BROKEN;
	}

	return (d->flag & RDF_BROKEN)? (2|change): change;
}

static int flush_data(struct relay_data *d, tx_aiocb *f)
{
	int len;
	int change = 0;

	if (tx_writable(f) && d->off < d->len) {
		len = tx_outcb_write(f, d->buf + d->off, d->len - d->off);
		if (len > 0) {
			d->off += len;
			change |= (len > 0);
		} else if (tx_writable(f)) {
			d->flag |= RDF_BROKEN;
			return 0;
		}
	}

	return change;
}

static int flush_data(struct relay_data *d, sockcb_t f)
{
	int len;
	int change = 0;

	if (sowritable(f) && d->off < d->len) {
		len = sowrite(f, d->buf + d->off, d->len - d->off);

		if (len > 0) {
			d->off += len;
			change |= (len > 0);
		} else if (sowritable(f)) {
			d->flag |= RDF_BROKEN;
			return 0;
		}
	}

	return change;
}

#define FLAG_OUTGOING 1
#define FLAG_INCOMING 2

static int try_shutdown(struct relay_data *d, tx_aiocb *f)
{
	int change = FLAG_INCOMING| FLAG_OUTGOING;

	if (d->off == d->len) {
		change &= ~FLAG_OUTGOING;
		d->off = d->len = 0;
	}

	if (d->len == sizeof(d->buf)) {
		change &= ~FLAG_INCOMING;
	}

	if (d->flag & RDF_EOF) {
		change &= ~FLAG_INCOMING;
	}

	if (d->flag & RDF_FIN) {
		assert (change == 0);
		return change;
	}

	if (change == 0) {
		shutdown(f->tx_fd, SD_BOTH);
		d->flag |= RDF_FIN;
	}

	return change;
}

static int try_shutdown(struct relay_data *d, sockcb_t f)
{
	int change = FLAG_INCOMING| FLAG_OUTGOING;

	if (d->off == d->len) {
		change &= ~FLAG_OUTGOING;
		d->off = d->len = 0;
	}

	if (d->len == sizeof(d->buf)) {
		change &= ~FLAG_INCOMING;
	}

	if (d->flag & RDF_EOF) {
		change &= ~FLAG_INCOMING;
	}

	if (d->flag & RDF_FIN) {
		assert (change == 0);
		return change;
	}

	if (change == 0) {
		fprintf(stderr, "START shutdown now: %x %d %d\n", d->flag, d->off, d->len);
		d->flag |= RDF_FIN;
		soshutdown(f);
	}

	return change;
}

void do_data_transfer(void *upp, tx_task_stack_t *sta)
{
	int change;
	int forward = 1, backward = 1;
	pstcp_channel *up = (pstcp_channel *)upp;

	up->reset_keepalive();
	up->m_flags |= FLAG_TRANSFERED;

	do {
		if (forward) {
			change  = fill_data(&up->s2r, &up->m_sockcbp);
			change |= flush_data(&up->s2r, up->m_peer);
			forward = (change == 1);
		}

		if (backward) {
			change  = fill_data(&up->r2s, up->m_peer);
			change |= flush_data(&up->r2s, &up->m_sockcbp);
			backward = (change == 1);
		}

	} while (forward || backward);

	if ((up->s2r.flag | up->r2s.flag) & RDF_BROKEN) {
		tx_task_stack_raise(sta, "do_data_transfer");
		return;
	}

	if ((up->s2r.flag & RDF_FIN) && (up->r2s.flag & RDF_FIN)) {
		tx_task_stack_pop0(sta);
		tx_task_stack_active(sta, "do_data_transfer");
		return;
	}

	forward = try_shutdown(&up->s2r, up->m_peer);
	if (tx_readable(&up->m_sockcbp)) forward &= ~FLAG_INCOMING;
	if (sowritable(up->m_peer)) forward &= ~FLAG_OUTGOING;

	if (forward & FLAG_OUTGOING)
		sopoll(up->m_peer, SO_SEND, STACK2TASK(sta));

	if (forward & FLAG_INCOMING)
		tx_aincb_active(&up->m_sockcbp, STACK2TASK(sta));

	backward = try_shutdown(&up->r2s, &up->m_sockcbp);
	if (soreadable(up->m_peer)) backward &= ~FLAG_INCOMING;
	if (tx_writable(&up->m_sockcbp)) backward &= ~FLAG_OUTGOING;

	if (backward & FLAG_OUTGOING)
		tx_outcb_prepare(&up->m_sockcbp, STACK2TASK(sta), 0);

	if (backward & FLAG_INCOMING)
		sopoll(up->m_peer, SO_RECEIVE, STACK2TASK(sta));

	if ((up->s2r.flag & RDF_FIN) && (up->r2s.flag & RDF_FIN)) {
		tx_task_stack_pop0(sta);
		tx_task_stack_active(sta, "do_data_transfer");
		return;
	}

	assert (backward || forward);
	return;
}

int pstcp_channel::run(void)
{
	reset_keepalive();

	if (FLAG_ZERO == FLAG_GET(m_flags, FLAG_CONNECTED| FLAG_ZERO| FLAG_BROKEN)) {
		tx_task_stack_push(&m_tasklet, do_peer_connect, this);
		tx_task_stack_active(&m_tasklet, "::run");
		return 1;
	}

	if (FLAG_CONNECTED == FLAG_GET(m_flags, FLAG_TRANSFERED| FLAG_CONNECTED| FLAG_BROKEN)) {
		tx_task_stack_push(&m_tasklet, do_data_transfer, this);
		tx_task_stack_active(&m_tasklet, "::run");
		return 1;
	}

	return 0;
}

void pstcp_channel::tc_idleclose(void *context)
{
	pstcp_channel *chan;
	chan = (pstcp_channel *)context;
	const char *info = "";
	int port = 0;

	int sfd = chan->m_sockcbp.tx_fd;
	if (sfd != -1) {
		struct sockaddr_in6 inaddr;
		socklen_t inlen = sizeof(inaddr);
		if (0 == getpeername(sfd, (struct sockaddr*)&inaddr, &inlen)) {
			info = ntop6(inaddr.sin6_addr);
			port = htons(inaddr.sin6_port);
		}
	}

	LOG_DEBUG("timeout close: %s:%d, %x", info, port, chan->m_extraflags);

	delete chan;
	return;
}

void pstcp_channel::tc_callback(void *context, tx_task_stack_t *sta)
{
	pstcp_channel *chan;
	chan = (pstcp_channel *)context;

	if (chan->run() == 0) {
		delete chan;
		return;
	}

	return;
}

void new_pstcp_channel(sockcb_t tp)
{
	pstcp_channel *chan;
	chan = new pstcp_channel(tp);

	if (chan == NULL) {
		soclose(tp);
		return;
	}

	pstcp_channel::tc_callback(chan, NULL);
	return;
}

extern "C" void pstcp_channel_forward(struct tcpip_info *info)
{
	_forward_addr = ntohl(info->tii_address);
	_forward_port = ntohs(info->port);
	return;
}

struct ipv6_npt_pair {
	int pfx_len;
	uint8_t src_pfx[16];
	uint8_t dst_pfx[16];
};

static int _ipv6_npt_count = 0;
static struct ipv6_npt_pair _ipv6_npt_tbl[10];

int ipv6_npt_add(const char *src_pfx, const char *dst_pfx, size_t pfx_len)
{
	struct ipv6_npt_pair *pair;

	if (_ipv6_npt_count < 10) {
		int index = _ipv6_npt_count++;

		pair = &_ipv6_npt_tbl[index];
		assert(pfx_len <= 128);
		LOG_DEBUG("ipv6_npt_add: %s %s %d", src_pfx, dst_pfx, pfx_len);
		inet_pton(AF_INET6, src_pfx, pair->src_pfx);
		inet_pton(AF_INET6, dst_pfx, pair->dst_pfx);
		pair->pfx_len = pfx_len;
	}

	return 0;
}

static int ipv6_prefix_match(const void *ipv6, const uint8_t *pfx, size_t pfxlen)
{
	const uint8_t *pfx_src = (const uint8_t *)ipv6;

	assert(pfxlen <= 128);

	while (pfxlen >= 8) {
		if (*pfx_src != *pfx)
			return *pfx_src ^ *pfx;
		pfx_src++, pfx++;
		pfxlen -= 8;
	}

	if (pfxlen > 0) {
		uint8_t mask = (0xff00 >> pfxlen);
		return (*pfx_src & mask) ^ (*pfx & mask);
	}

	return 0;
}

static int ipv6_prefix_set(void *ipv6, const uint8_t *pfx, size_t pfxlen)
{
	uint8_t *pfx_dst = (uint8_t *)ipv6;

	assert(pfxlen <= 128);
	while (pfxlen >= 8) {
		*pfx_dst++ = *pfx++;
		pfxlen -= 8;
	}

	if (pfxlen > 0) {
		uint8_t mask = (0xff00 >> pfxlen);
		*pfx_dst &= ~mask;
		*pfx_dst |= (mask & *pfx);
	}

	return 0;
}

void NAT64_UPDATE(void *addr, int *stat)
{
	for (int i = 0; i < _ipv6_npt_count; i++) {
		struct ipv6_npt_pair *pair = _ipv6_npt_tbl + i;
		if (ipv6_prefix_match(addr, pair->src_pfx, pair->pfx_len) == 0) {
			// char buf[128];
			// LOG_DEBUG("NAT64_UPDATE: %s\n", inet_ntop(AF_INET6, addr, buf, sizeof(buf)));
			ipv6_prefix_set(addr, pair->dst_pfx, pair->pfx_len);
			*stat = i;
			break;
		}
	}
}

void NAT64_REVERT(void *addr, int stat)
{
	for (int i = 0; i < _ipv6_npt_count; i++) {
		struct ipv6_npt_pair *pair = _ipv6_npt_tbl + i;
		if (ipv6_prefix_match(addr, pair->dst_pfx, pair->pfx_len) == 0 && (stat & 0xffff) == i) {
			// char buf[128];
			// LOG_DEBUG("NAT64_REVERT: %s\n", inet_ntop(AF_INET6, addr, buf, sizeof(buf)));
			ipv6_prefix_set(addr, pair->src_pfx, pair->pfx_len);
			break;
		}
	}
}
