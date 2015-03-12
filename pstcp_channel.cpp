#include <stdio.h>
#include <assert.h>

#include <txall.h>
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
#define tx_get_error() errno
#else
#define tx_get_error WSAGetLastError
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

#if 0
	if ((m_flags & TF_CONNECT) == 0) {
		name.sin_family = AF_INET;
		name.sin_port   = htons(_forward_port);
		name.sin_addr.s_addr = htonl(_forward_addr);
	   	error = connect(m_file, (struct sockaddr *)&name, sizeof(name));
		m_flags |= TF_CONNECT;
		if (error == -1 && tx_get_error() == EINPROGRESS) {
			sock_write_wait(m_sockcbp, &m_wwait);
			m_flags |= TF_CONNECTING;
			return 1;
		}

		if (error != 0) {
			fprintf(stderr, "tcp connect error\n");
			return 0;
		}
	}

	if (waitcb_completed(&m_wwait)) {
		m_flags &= ~TF_CONNECTING;
	}

	if (m_flags & TF_CONNECTING) {
		return 1;
	}

reread:
	if (waitcb_completed(&m_rwait) && m_rlen < (int)sizeof(m_rbuf)) {
		len = recv(m_file, m_rbuf + m_rlen, sizeof(m_rbuf) - m_rlen, 0);
		if (len > 0)
		   	m_rlen += len;
		else if (len == 0)
			m_flags |= TF_EOF1;
		else if (tx_get_error() != WSAEWOULDBLOCK)
			return 0;
		waitcb_clear(&m_rwait);
	}

	if (waitcb_completed(&r_evt_peer) && m_wlen < (int)sizeof(m_wbuf)) {
		len = tcp_read(m_peer, m_wbuf + m_wlen, sizeof(m_wbuf) - m_wlen);
		if (len == -1 || len == 0) {
			m_flags |= TF_EOF0;
			len = 0;
		}
		waitcb_clear(&r_evt_peer);
		m_wlen += len;
	}

	if (waitcb_completed(&m_wwait) && m_woff < m_wlen) {
		do {
			len = send(m_file, m_wbuf + m_woff, m_wlen - m_woff, 0);
			if (len > 0)
				m_woff += len;
			else if (tx_get_error() == WSAEWOULDBLOCK)
				waitcb_clear(&m_wwait);
			else
				return 0;
		} while (len > 0 && m_woff < m_wlen);
	}

	if (waitcb_completed(&w_evt_peer) && m_roff < m_rlen) {
		len = tcp_write(m_peer, m_rbuf + m_roff, m_rlen - m_roff);
		if (len == -1)
			return 0;
		waitcb_clear(&w_evt_peer);
		m_roff += len;
	}

	error = 0;

	if (m_roff >= m_rlen) {
		int test_flags = (TF_EOF1 | TF_SHUT1);
	   
		m_roff = m_rlen = 0;
		if ((m_flags & test_flags) == TF_EOF1) {
			test_flags |= TF_SHUT1;
			tcp_shutdown(m_peer);
		} else {
			if (waitcb_completed(&m_rwait))
				goto reread;
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
	   	sock_write_wait(m_sockcbp, &m_wwait);
		error = 1;
	}

	if (m_rlen < (int)sizeof(m_rbuf) &&
			(m_flags & TF_EOF1) == 0) {
		sock_read_wait(m_sockcbp, &m_rwait);
		error = 1;
	}

	if (m_wlen < (int)sizeof(m_wbuf) &&
			(m_flags & TF_EOF0) == 0) {
		tcp_poll(m_peer, TCP_READ, &r_evt_peer);
		error = 1;
	}

	return error;
#endif
	return 0;
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

