#include <stdio.h>
#include <assert.h>
#include <stdlib.h>

#include <unistd.h>
#include <fcntl.h>

#include <wait/module.h>
#include <wait/platform.h>
#include <wait/slotwait.h>
#include <wait/slotsock.h>

#include <utx/socket.h>

#include "pstcp_channel.h"

#define TF_CONNECT    1
#define TF_CONNECTING 2
#define TF_EOF0       4
#define TF_EOF1       8
#define TF_SHUT0      16 
#define TF_SHUT1      32

#ifndef WIN32
#define ENABLE_WRITE_STDOUT 1
#endif

class pstcp_channel {
   	public:
		pstcp_channel(struct tcpcb *tp);
		~pstcp_channel();

	public:
		int run(void);
		static void tc_callback(void *context);

	private:
		int m_flags;

	private:
		struct waitcb m_rwait;
		struct waitcb m_wwait;
		struct sockcb *m_stdincbp;
		struct sockcb *m_stdoutcbp;

	private:
		int m_woff;
		int m_wlen;
		char m_wbuf[8192];

	private:
		int m_roff;
		int m_rlen;
		char m_rbuf[8192];

	private:
		struct tcpcb *m_peer;
		struct waitcb r_evt_peer;
		struct waitcb w_evt_peer;
};

pstcp_channel::pstcp_channel(struct tcpcb *tp)
	:m_flags(0)
{
	m_peer = tp;
	m_stdincbp = sock_attach(0);
#if defined(ENABLE_WRITE_STDOUT)
	m_stdoutcbp = sock_attach(1);
#endif

	m_roff = m_rlen = 0;
	m_woff = m_wlen = 0;
	waitcb_init(&m_rwait, tc_callback, this);
	waitcb_init(&m_wwait, tc_callback, this);
	waitcb_init(&r_evt_peer, tc_callback, this);
	waitcb_init(&w_evt_peer, tc_callback, this);
}

pstcp_channel::~pstcp_channel()
{
	waitcb_clean(&m_wwait);
	waitcb_clean(&m_rwait);
	waitcb_clean(&r_evt_peer);
	waitcb_clean(&w_evt_peer);

	fprintf(stderr, "pstcp_channel::~pstcp_channel\n");
#if defined(ENABLE_WRITE_STDOUT)
	sock_detach(m_stdoutcbp);
#endif
	sock_detach(m_stdincbp);
	tcp_soclose(m_peer);
}

int pstcp_channel::run(void)
{
	int len = 0;
	int error = -1;

    if ((m_flags & TF_CONNECT) == 0) {
        m_flags |= TF_CONNECT;
        m_flags |= TF_CONNECTING;
        tcp_poll(m_peer, TCP_WRITE, &w_evt_peer);
    }   

    if ( waitcb_completed(&w_evt_peer) ) { 
        m_flags &= ~TF_CONNECTING;
    }   

    if (m_flags & TF_CONNECTING) {
        return 1;
    }   

reread:
	while (waitcb_completed(&m_rwait) && m_rlen < (int)sizeof(m_rbuf)) {
		len = read(0, m_rbuf + m_rlen, sizeof(m_rbuf) - m_rlen);
		if (len > 0)
		   	m_rlen += len;
		else if (len == 0)
			m_flags |= TF_EOF1;
		else if (WSAGetLastError() != WSAEWOULDBLOCK)
			return 0;
		if (len <= 0)
			waitcb_clear(&m_rwait);
	}

	if (waitcb_completed(&r_evt_peer) && m_wlen < (int)sizeof(m_wbuf)) {
		len = tcp_read(m_peer, m_wbuf + m_wlen, sizeof(m_wbuf) - m_wlen);
		if (len == -1 || len == 0) {
			fprintf(stderr, "reach end of tcp stream\n");
			m_flags |= TF_EOF0;
			len = 0;
		}
		waitcb_clear(&r_evt_peer);
		m_wlen += len;
	}

#if defined(ENABLE_WRITE_STDOUT) 
	if (waitcb_completed(&m_wwait) && m_woff < m_wlen) {
		do {
			len = write(1, m_wbuf + m_woff, m_wlen - m_woff);
			len = m_wlen - m_woff;
			if (len > 0)
				m_woff += len;
			else if (WSAGetLastError() == WSAEWOULDBLOCK)
				waitcb_clear(&m_wwait);
			else
				return 0;
		} while (len > 0 && m_woff < m_wlen);
	}
#else
	m_woff = m_wlen = 0;
#endif

	if (waitcb_completed(&w_evt_peer) && m_roff < m_rlen) {
		len = tcp_write(m_peer, m_rbuf + m_roff, m_rlen - m_roff);
		if (len == -1)
			return 0;
		waitcb_clear(&w_evt_peer);
		m_roff += len;
	}


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

	error = 0;
	if (m_woff >= m_wlen) {
		int test_flags = (TF_EOF0 | TF_SHUT0);
		if ((m_flags & test_flags) == TF_EOF0) {
			test_flags |= TF_SHUT0;
		}
		m_woff = m_wlen = 0;
	}

	if (m_roff < m_rlen) {
		tcp_poll(m_peer, TCP_WRITE, &w_evt_peer);
		error = 1;
	}

#if defined(ENABLE_WRITE_STDOUT)
	if (m_woff < m_wlen) {
	   	sock_write_wait(m_stdoutcbp, &m_wwait);
		error = 1;
	}
#endif

	int tf_eof = TF_EOF0| TF_EOF1;
	if (m_rlen < (int)sizeof(m_rbuf) &&
			(m_flags & tf_eof) == 0) {
		sock_read_wait(m_stdincbp, &m_rwait);
		error = 1;
	}

	if (m_wlen < (int)sizeof(m_wbuf) &&
			(m_flags & tf_eof) == 0) {
		tcp_poll(m_peer, TCP_READ, &r_evt_peer);
		error = 1;
	}

	return error;
}

void pstcp_channel::tc_callback(void *context)
{
	u_long mode = 1;
	pstcp_channel *chan;
	chan = (pstcp_channel *)context;

	if (chan->run() == 0) {
		delete chan;
#ifndef WIN32
		mode = fcntl(0, F_GETFL);
		fcntl(0, F_SETFL, mode & ~O_NONBLOCK);
#endif
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

