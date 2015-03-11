#include <stdio.h>
#include <time.h>
#include <assert.h>
#include <stdlib.h>

#include <wait/module.h>
#include <wait/platform.h>
#include <wait/slotwait.h>
#include <wait/slotsock.h>

#include <utx/socket.h>
#include "tcp_channel.h"

#define TF_CONNECT    1
#define TF_CONNECTING 2
#define TF_EOF0       4
#define TF_EOF1       8
#define TF_SHUT0     16
#define TF_SHUT1     32

class tcp_channel {
   	public:
		tcp_channel(int fd);
		~tcp_channel();

	public:
		int run(void);
		static void tc_callback(void *context);

	private:
		int m_file;
		int m_flags;

	private:
		struct waitcb m_wwait;
		struct waitcb m_rwait;
		struct sockcb *m_sockcbp;

	private:
		int m_woff;
		int m_wlen;
		char m_wbuf[4096];

	private:
		int m_roff;
		int m_rlen;
		char m_rbuf[4096];

	private:
		struct waitcb r_evt_peer;
		struct waitcb w_evt_peer;
		struct tcpcb *m_peer;
};

static u_short _forward_port = 0; // 1080
static u_long  _forward_addr = INADDR_ANY;

tcp_channel::tcp_channel(int file)
	:m_file(file), m_flags(0)
{
	static u_long conv = time(NULL);
	m_peer = tcp_create(conv++);
	assert(m_peer != NULL);
	m_roff = m_rlen = 0;
	m_woff = m_wlen = 0;

	m_sockcbp = sock_attach(file);
	waitcb_init(&m_wwait, tc_callback, this);
	waitcb_init(&m_rwait, tc_callback, this);
	waitcb_init(&r_evt_peer, tc_callback, this);
	waitcb_init(&w_evt_peer, tc_callback, this);
}

tcp_channel::~tcp_channel()
{
	waitcb_clean(&m_rwait);
	waitcb_clean(&m_wwait);
	waitcb_clean(&r_evt_peer);
	waitcb_clean(&w_evt_peer);

	fprintf(stderr, "tcp_channel::~tcp_channel\n");
	sock_detach(m_sockcbp);
	closesocket(m_file);
	tcp_soclose(m_peer);
}

int tcp_channel::run(void)
{
	int len = 0;
	int error = 0;
	struct sockaddr_in name;

	if ((m_flags & TF_CONNECT) == 0) {
		name.sin_family = AF_INET;
		name.sin_port   = (_forward_port);
		name.sin_addr.s_addr = (_forward_addr);
	   	error = tcp_connect(m_peer, &name, sizeof(name));
		m_flags |= TF_CONNECT;
		if (error == 1) {
			tcp_poll(m_peer, TCP_WRITE, &w_evt_peer);
			m_flags |= TF_CONNECTING;
			return 1;
		}

		if (error != 0) {
			fprintf(stderr, "udp connect error\n");
			return 0;
		}
	}

	if ( waitcb_completed(&w_evt_peer) ) {
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
		else if (WSAGetLastError() != WSAEWOULDBLOCK)
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
			if (len > 0) {
				m_woff += len;
			} else if (WSAGetLastError() == WSAEWOULDBLOCK) {
				waitcb_clear(&m_wwait);
			} else {
				return 0;
			}
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
			tcp_shutdown(m_peer);
			m_flags |= TF_SHUT1;
		} else {
			if (waitcb_completed(&m_rwait))
				goto reread;
		}
	}

	if (m_woff >= m_wlen) {
		int test_flags = (TF_EOF0 | TF_SHUT0);
		if ((m_flags & test_flags) == TF_EOF0) {
			shutdown(m_file, SD_BOTH);
			m_flags |= TF_SHUT0;
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
		(TF_EOF1 & m_flags) == 0) {
	   	sock_read_wait(m_sockcbp, &m_rwait);
		error = 1;
	}

	if (m_wlen < (int)sizeof(m_wbuf) && 
			(TF_EOF0 & m_flags) == 0) {
		tcp_poll(m_peer, TCP_READ, &r_evt_peer);
		error = 1;
	}

	return error;
}

void tcp_channel::tc_callback(void *context)
{
	tcp_channel *chan;
	chan = (tcp_channel *)context;

	if (chan->run() == 0) {
		delete chan;
		return;
	}
   
	return;
}

void new_tcp_channel(int fd)
{
	tcp_channel *chan;
   	chan = new tcp_channel(fd);

	if (chan == NULL) {
		closesocket(fd);
		return;
	}

	tcp_channel::tc_callback(chan);
	return;
}

extern "C" void tcp_channel_forward(struct tcpip_info *info)
{
	_forward_addr = info->address;
	_forward_port = info->port;
	return;
}

