#include <stdio.h>
#include <assert.h>

#include <txall.h>
#include <utx/utxpl.h>
#include <utx/socket.h>

#include "dns_txasync.h"
#include "tcp_channel.h"
#include "pstcp_channel.h"

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
    int flag;
    char buf[4096];
};

class pstcp_channel {
   	public:
		pstcp_channel(struct tcpcb *tp);
		~pstcp_channel();

	public:
		int run(void);
		static void tc_callback(void *context);

	private:
		int m_file;
		int m_flags;
		int m_dns_handle;
		static int v4_only;

	private:
		struct tx_task_t m_rwait;
		struct tx_task_t m_wwait;
		struct tx_aiocb m_sockcbp;

	private:
		struct relay_data r2s;
		struct relay_data s2r;

	private:
		struct tcpcb *m_peer;
		struct tx_task_t r_evt_peer;
		struct tx_task_t w_evt_peer;

	private:
		struct tx_task_t xidle;
		struct tx_timer_t tidle;
		static void tc_idleclose(void *context);
		int expend_relay(struct sockaddr_storage *, struct tcpcb *, u_long , u_short , struct tx_task_t *);
};

int pstcp_channel::v4_only = 0;
u_short _forward_port = 1080;
u_long  _forward_addr = INADDR_LOOPBACK;

static void anybind(int fd, int family)
{
	struct sockaddr_in siaddr = {0};
	struct sockaddr_in6 si6addr = {0};

	switch(family) {
		case AF_INET:
			siaddr.sin_family = AF_INET;
			bind(fd, (struct sockaddr *)&siaddr, sizeof(siaddr));
			break;

		case AF_INET6:
			si6addr.sin6_family = AF_INET6;
			bind(fd, (struct sockaddr *)&si6addr, sizeof(si6addr));
			break;

		default:
			break;
	}

	return;
}

pstcp_channel::pstcp_channel(struct tcpcb *tp)
	:m_flags(0)
{
	int len;
	int is_v4only;
	char relay[128];

	s2r.flag = 0;
	s2r.off = s2r.len = 0;

	r2s.flag = 0;
	r2s.off = r2s.len = 0;

	m_peer = tp;
	m_dns_handle = -1;

	tx_loop_t *loop = tx_loop_default();
	tx_task_init(&xidle, loop, tc_idleclose, this);
	tx_timer_init(&tidle, loop, &xidle);

	tx_task_init(&m_rwait, loop, tc_callback, this);
	tx_task_init(&m_wwait, loop, tc_callback, this);
	tx_task_init(&r_evt_peer, loop, tc_callback, this);
	tx_task_init(&w_evt_peer, loop, tc_callback, this);

	is_v4only = v4_only;
	len = tcp_relayget(tp, relay, sizeof(relay));
	if (len > 4) is_v4only = (relay[0] == 0x01);

	m_file = socket(is_v4only? AF_INET: AF_INET6, SOCK_STREAM, 0);
	if (m_file == -1 && EAFNOSUPPORT == errno) {
		m_file = socket(AF_INET, SOCK_STREAM, 0);
		v4_only = 1;
	}

	assert(m_file != -1);
	tx_setblockopt(m_file, 0);
	anybind(m_file, AF_INET);
	tx_aiocb_init(&m_sockcbp, loop, m_file);
}

pstcp_channel::~pstcp_channel()
{
	if (m_dns_handle != -1) {
		dns_query_close(m_dns_handle);
		m_dns_handle = -1;
	}

	tx_aiocb_fini(&m_sockcbp);
	tcp_soclose(m_peer);

	tx_timer_stop(&tidle);
	tx_task_drop(&xidle);

	tx_task_drop(&w_evt_peer);
	tx_task_drop(&r_evt_peer);
	tx_task_drop(&m_wwait);
	tx_task_drop(&m_rwait);

	fprintf(stderr, "pstcp_channel::~pstcp_channel\n");
	closesocket(m_file);
}

int pstcp_channel::expend_relay(struct sockaddr_storage *destination, struct tcpcb *tp, u_long defdest, u_short port, struct tx_task_t *task)
{
	int len, typ;
	struct addrinfo hints;
    char *p, relay[64], serv[10];

    struct sockaddr_in *dst4 =
        (struct sockaddr_in *)destination;

    struct sockaddr_in6 *dst6 =
        (struct sockaddr_in6 *)destination;

    p = relay;
    len = tcp_relayget(tp, relay, sizeof(relay));

    while (len > 4 && len < sizeof(relay)) {
        int p0;
        typ = *p++;
        if (*p++ != 0) break;

        memcpy(&p0, p, 2);
        p += 2;

        switch (typ) {
            case 0x01:
                /* IPv4 (8 byte): atyp=0x01 + 0x0 + port[2]+ addr[4]. */
                if (len == 8) {
                    dst4->sin_family = AF_INET;
                    dst4->sin_port   = p0;
                    memcpy(&dst4->sin_addr, p, 4);
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

				sprintf(serv, "%d", ntohs(p0));
				relay[len] = 0;

				m_dns_handle = dns_query_open(relay + 4, serv, &hints, task);
				if (m_dns_handle >= 0) {
					fprintf(stderr, "dns query is pending: %s\n", relay + 4);
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
	fprintf(stderr, "relay: len %d\n", len);
    return 0;
}

int pstcp_channel::run(void)
{
	int len = 0;
	int error = -1;
	int change = 0;

	socklen_t namelen;
	struct sockaddr_storage name;

	tx_timer_reset(&tidle, 1000 * 180); // close after 3 min idle time

#define TF_RESOLVABLE(flags) (0x0 == (flags&(TF_RESOLVING|TF_RESOLVED)))
	if (TF_RESOLVABLE(m_flags)) {
		error = expend_relay(&name, m_peer, _forward_addr, _forward_port, &m_wwait);
		if (error == -1) {
			fprintf(stderr, "do dns resolv error\n");
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
				fprintf(stderr, "do dns async resolv failure\n");
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
					error = tx_aiocb_connect(&m_sockcbp, (struct sockaddr *)rp->ai_addr, rp->ai_addrlen, &m_wwait);

					if (error == 0 || error == -WSAEINPROGRESS) {
						m_file = rsoket;
						if (error) {
							m_flags |= TF_CONNECTING;
							fprintf(stderr, "connect is pending: error = %d\n", errno);
							dns_query_close(m_dns_handle);
							m_dns_handle = -1;
							return 1;
						}

						m_flags |= TF_CONNECTED;
						fprintf(stderr, "connect all pending\n");
						dns_query_close(m_dns_handle);
						m_dns_handle = -1;
						return 1;
					}

					fprintf(stderr, "connect error code: %d\n", errno);
					tx_aiocb_fini(&m_sockcbp);
					closesocket(rsoket);
				}

				fprintf(stderr, "connect all failure\n");
				return 0;
			}

			fprintf(stderr, "query is pending\n");
			return 1;
		}
	}

#define TF_CONNECTABLE(f) (0x0 == (f&(TF_CONNECTING|TF_CONNECTED)))
	if (TF_CONNECTABLE(m_flags) && (m_flags & TF_RESOLVED)) {
		namelen = sizeof(struct sockaddr_in);
		if (name.ss_family == AF_INET6) {
			namelen = sizeof(struct sockaddr_in6);
		}

		error = tx_aiocb_connect(&m_sockcbp, (struct sockaddr *)&name, namelen, &m_wwait);
		if (error == 0 || error == -WSAEINPROGRESS) {
			if (error) {
				fprintf(stderr, "connect is pending\n");
				m_flags |= TF_CONNECTING;
				return 1;
			}

			fprintf(stderr, "connect all pending\n");
			m_flags |= TF_CONNECTED;
			return 1;
		}

		fprintf(stderr, "tcp connect error: %s\n", strerror(errno));
		v4_only = (errno == EINVAL? 1: v4_only);
		return 0;
	} else {
		if (tx_writable(&m_sockcbp)
				&& (m_flags & TF_CONNECTING)) {
			fprintf(stderr, "connect is finish...\n", this);
			m_flags &= ~TF_CONNECTING;
			m_flags |= TF_CONNECTED;
		}

		if ((m_flags & TF_CONNECTED) == 0) {
			fprintf(stderr, "%p connect is inprogress...\n", this);
			return 1;
		}
	}

	do {
		change = 0;
		if (s2r.off >= s2r.len) s2r.off = s2r.len = 0;

		if (tx_readable(&m_sockcbp) && s2r.len < (int)sizeof(s2r.buf) && !s2r.flag) {
			len = recv(m_file, s2r.buf + s2r.len, sizeof(s2r.buf) - s2r.len, 0);
			tx_aincb_update(&m_sockcbp, len);

			change |= (len > 0);
			if (len > 0)
				s2r.len += len;
			else if (len == 0)
				s2r.flag |= RDF_EOF;
			else if (tx_readable(&m_sockcbp)) // socket meet error condiction
				return 0;
		}

		if (tcp_writable(m_peer) && s2r.off < s2r.len) {
			len = tcp_write(m_peer, s2r.buf + s2r.off, s2r.len - s2r.off);
			if (len == -1) return 0;
			change |= (len > 0);
			s2r.off += len;
		}
	} while (change);

	do {
		change = 0;
		if (r2s.off >= r2s.len)  r2s.off = r2s.len = 0;
		if (tcp_readable(m_peer) && r2s.len < (int)sizeof(r2s.buf) && !r2s.flag) {
			len = tcp_read(m_peer, r2s.buf + r2s.len, sizeof(r2s.buf) - r2s.len);
			if (len == -1 || len == 0) {
				r2s.flag |= RDF_EOF;
				len = 0;
			}

			change |= (len > 0);
			r2s.len += len;
		}

		if (tx_writable(&m_sockcbp) && r2s.off < r2s.len) {
			do {
				len = tx_outcb_write(&m_sockcbp, r2s.buf + r2s.off, r2s.len - r2s.off);
				if (len > 0) {
					r2s.off += len;
					change |= (len > 0);
				} else if (tx_writable(&m_sockcbp)) {
					return 0;
				}
			} while (len > 0 && r2s.off < r2s.len);
		}

	} while (change);


	error = 0;

	if (s2r.off >= s2r.len) {
        s2r.off = s2r.len = 0;

		if (s2r.flag == RDF_EOF) {
			tcp_shutdown(m_peer);
            s2r.flag |= RDF_FIN;
        }
	}

	if (r2s.off >= r2s.len) {
        r2s.off = r2s.len = 0;

		if (r2s.flag == RDF_EOF) {
			shutdown(m_file, SD_BOTH);
            r2s.flag |= RDF_FIN;
		}
	}

    if (s2r.off < s2r.len && !tcp_writable(m_peer)) {
		tcp_poll(m_peer, TCP_WRITE, &w_evt_peer);
		error = 1;
	}

	if (r2s.off < r2s.len && !tx_writable(&m_sockcbp)) {
		tx_outcb_prepare(&m_sockcbp, &m_wwait, 0);
		error = 1;
	}

    if ((s2r.flag == 0) && !tx_readable(&m_sockcbp) &&
            s2r.len < (int)sizeof(s2r.buf)) {
        tx_aincb_active(&m_sockcbp, &m_rwait);
        error = 1;
    }

    if ((r2s.flag == 0) && !tcp_readable(m_peer) &&
            r2s.len < (int)sizeof(r2s.buf)) {
        tcp_poll(m_peer, TCP_READ, &r_evt_peer);
        error = 1;
    }

	return error;
}

void pstcp_channel::tc_idleclose(void *context)
{
	pstcp_channel *chan;
	chan = (pstcp_channel *)context;
	delete chan;
	return;
}

void pstcp_channel::tc_callback(void *context)
{
	pstcp_channel *chan;
	chan = (pstcp_channel *)context;

	if (chan->run() == 0) {
		delete chan;
		return;
	}
   
	return;
}

void new_pstcp_channel(struct tcpcb *tp)
{
	pstcp_channel *chan;
   	chan = new pstcp_channel(tp);

	if (chan == NULL) {
		tcp_soclose(tp);
		return;
	}

	pstcp_channel::tc_callback(chan);
	return;
}

extern "C" void pstcp_channel_forward(struct tcpip_info *info)
{
	_forward_addr = ntohl(info->address);
	_forward_port = ntohs(info->port);
	return;
}

