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

	private:
		struct tx_task_t m_rwait;
		struct tx_task_t m_wwait;
		struct tx_aiocb m_sockcbp;

	private:
		int m_woff;
		int m_wlen;
		char m_wbuf[4096];

	private:
		int m_roff;
		int m_rlen;
		char m_rbuf[4096];

	private:
		struct tcpcb *m_peer;
		struct tx_task_t r_evt_peer;
		struct tx_task_t w_evt_peer;

	private:
		int expend_relay(struct sockaddr *, struct tcpcb *, u_long , u_short , struct tx_task_t *);
};

u_short _forward_port = 1080;
u_long  _forward_addr = INADDR_LOOPBACK;

pstcp_channel::pstcp_channel(struct tcpcb *tp)
	:m_flags(0)
{
	m_peer = tp;
	m_file = socket(AF_INET, SOCK_STREAM, 0);
	assert(m_file != -1);
	tx_loop_t *loop = tx_loop_default();
	tx_setblockopt(m_file, 0);
	tx_aiocb_init(&m_sockcbp, loop, m_file);

	m_roff = m_rlen = 0;
	m_woff = m_wlen = 0;
	m_dns_handle = -1;

	tx_task_init(&m_rwait, loop, tc_callback, this);
	tx_task_init(&m_wwait, loop, tc_callback, this);
	tx_task_init(&r_evt_peer, loop, tc_callback, this);
	tx_task_init(&w_evt_peer, loop, tc_callback, this);
}

pstcp_channel::~pstcp_channel()
{
	if (m_dns_handle != -1) {
		dns_query_close(m_dns_handle);
		m_dns_handle = -1;
	}

	tx_aiocb_fini(&m_sockcbp);
	tcp_soclose(m_peer);

	tx_task_drop(&w_evt_peer);
	tx_task_drop(&r_evt_peer);
	tx_task_drop(&m_wwait);
	tx_task_drop(&m_rwait);

	fprintf(stderr, "pstcp_channel::~pstcp_channel\n");
	closesocket(m_file);
}

int pstcp_channel::expend_relay(struct sockaddr *destination, struct tcpcb *tp, u_long defdest, u_short port, struct tx_task_t *task)
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
	struct sockaddr name;


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

					tx_aiocb_init(&m_sockcbp, loop, rsoket);
					error = tx_aiocb_connect(&m_sockcbp, (struct sockaddr *)rp->ai_addr, rp->ai_addrlen, &m_wwait);

					if (error == 0 || error == -WSAEINPROGRESS) {
						m_file = rsoket;
						if (error) {
							fprintf(stderr, "connect all pending\n");
							m_flags |= TF_CONNECTING;
							return 1;
						}

						m_flags |= TF_CONNECTED;
						dns_query_close(m_dns_handle);
						m_dns_handle = -1;
						goto process;
					}

					fprintf(stderr, "connect error colde: %d\n", errno);
					tx_aiocb_fini(&m_sockcbp);
					closesocket(rsoket);
				}

				fprintf(stderr, "connect all failure\n");
				return 0;
			}
		}
	}

#define TF_CONNECTABLE(f) (0x0 == (f&(TF_CONNECTING|TF_CONNECTED)))
	if (TF_CONNECTABLE(m_flags) && (m_flags & TF_RESOLVED)) {
		if (name.sa_family == AF_INET6) {
			struct tx_loop_t *loop = tx_loop_default();
			tx_aiocb_fini(&m_sockcbp);
			closesocket(m_file);

			m_file = socket(AF_INET6, SOCK_STREAM, 0);
			assert(m_file != -1);

			tx_setblockopt(m_file, 0);
			tx_aiocb_init(&m_sockcbp, loop, m_file);
		}

		error = tx_aiocb_connect(&m_sockcbp, (struct sockaddr *)&name, sizeof(name), &m_wwait);
		if (error == -1) {
			fprintf(stderr, "tcp connect error\n");
			return 0;
		}

		if (error) {
			m_flags |= TF_CONNECTING;
			return 1;
		}

		m_flags |= TF_CONNECTED;
	} else {
		if (tx_writable(&m_sockcbp)
				&& (m_flags & TF_CONNECTING)) {
			m_flags &= ~TF_CONNECTING;
			m_flags |= TF_CONNECTED;
		}

		if ((m_flags & TF_CONNECTED) == 0) {
			fprintf(stderr, "connect is inprogress...");
			return 1;
		}
	}

process:
reread:
	if (tx_readable(&m_sockcbp) && m_rlen < (int)sizeof(m_rbuf) && (m_flags & TF_EOF1) == 0) {
		len = recv(m_file, m_rbuf + m_rlen, sizeof(m_rbuf) - m_rlen, 0);
		tx_aincb_update(&m_sockcbp, len);
		if (len > 0)
		   	m_rlen += len;
		else if (len == 0)
			m_flags |= TF_EOF1;
		else if (tx_readable(&m_sockcbp))
			return 0;
	}

	if (tcp_readable(m_peer) && m_wlen < (int)sizeof(m_wbuf) && (m_flags & TF_EOF0) == 0) {
		len = tcp_read(m_peer, m_wbuf + m_wlen, sizeof(m_wbuf) - m_wlen);
		if (len == -1 || len == 0) {
			m_flags |= TF_EOF0;
			len = 0;
		}
		m_wlen += len;
	}

	if (tx_writable(&m_sockcbp) && m_woff < m_wlen) {
		do {
			len = tx_outcb_write(&m_sockcbp, m_wbuf + m_woff, m_wlen - m_woff);
			if (len > 0) {
				m_woff += len;
			} else if (tx_writable(&m_sockcbp)) {
				return 0;
			}
		} while (len > 0 && m_woff < m_wlen);
	}

	if (tcp_writable(m_peer) && m_roff < m_rlen) {
		len = tcp_write(m_peer, m_rbuf + m_roff, m_rlen - m_roff);
		if (len == -1) return 0;
		m_roff += len;
	}

	error = 0;

	if (m_roff >= m_rlen) {
		int test_flags = (TF_EOF1 | TF_SHUT1);
	   
		m_roff = m_rlen = 0;
        if ((m_flags & test_flags) == TF_EOF1) {
            test_flags |= TF_SHUT1;
            tcp_shutdown(m_peer);
        } else if ((m_flags & TF_EOF1) == 0) {
            /* XXX */
            if (tx_readable(&m_sockcbp)) { goto reread; }
        }
	}

	if (m_woff >= m_wlen) {
		int test_flags = (TF_EOF0 | TF_SHUT0);
		if ((m_flags & test_flags) == TF_EOF0) {
			shutdown(m_file, SD_BOTH);
			test_flags |= TF_SHUT0;
		}
		m_woff = m_wlen = 0;
	}

	if (m_roff < m_rlen) {
		tcp_poll(m_peer, TCP_WRITE, &w_evt_peer);
		error = 1;
	}

	if (m_woff < m_wlen) {
	   	tx_outcb_prepare(&m_sockcbp, &m_wwait, 0);
		error = 1;
	}

	if (m_rlen < (int)sizeof(m_rbuf) &&
			(m_flags & TF_EOF1) == 0) {
		tx_aincb_active(&m_sockcbp, &m_rwait);
		error = 1;
	}

	if (m_wlen < (int)sizeof(m_wbuf) &&
			(m_flags & TF_EOF0) == 0) {
		tcp_poll(m_peer, TCP_READ, &r_evt_peer);
		error = 1;
	}

	return error;
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

