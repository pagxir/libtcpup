#include <stdio.h>
#include <assert.h>

#include <txall.h>
#include <utx/utxpl.h>
#include <utx/socket.h>

#include "tcp_channel.h"
#include "pstcp_channel.h"

#define TF_CONNECT    1
#define TF_CONNECTING 2
#define TF_EOF0       4
#define TF_EOF1       8
#define TF_SHUT0      16 
#define TF_SHUT1      32

#ifndef WIN32
#include <errno.h>
#include <unistd.h>
#define closesocket close
#define SD_BOTH SHUT_RDWR
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

	tx_task_init(&m_rwait, loop, tc_callback, this);
	tx_task_init(&m_wwait, loop, tc_callback, this);
	tx_task_init(&r_evt_peer, loop, tc_callback, this);
	tx_task_init(&w_evt_peer, loop, tc_callback, this);
}

pstcp_channel::~pstcp_channel()
{
	tx_task_drop(&m_wwait);
	tx_task_drop(&m_rwait);
	tx_task_drop(&r_evt_peer);
	tx_task_drop(&r_evt_peer);

	fprintf(stderr, "pstcp_channel::~pstcp_channel\n");
	tx_aiocb_fini(&m_sockcbp);
	closesocket(m_file);
	tcp_soclose(m_peer);
}

int pstcp_channel::run(void)
{
	int len = 0;
	int error = -1;
	struct sockaddr_in name;

	if ((m_flags & TF_CONNECT) == 0) {
		name.sin_family = AF_INET;
		name.sin_port   = htons(_forward_port);
		name.sin_addr.s_addr = htonl(_forward_addr);
		error = tx_aiocb_connect(&m_sockcbp, (struct sockaddr *)&name, &m_wwait);
		m_flags |= TF_CONNECT;

		if (error == -1) {
			fprintf(stderr, "tcp connect error\n");
			return 0;
		} else if (error) {
			m_flags |= TF_CONNECTING;
			return 1;
		}
	}

	if (tx_writable(&m_sockcbp)) {
		m_flags &= ~TF_CONNECTING;
	} else if (m_flags & TF_CONNECTING) {
		return 1;
	}

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

