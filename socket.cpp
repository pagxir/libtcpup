#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

#define TCPUP_LAYER 1
#include <utx/utxpl.h>
#include <utx/queue.h>
#include <utx/sobuf.h>
#include <utx/socket.h>

#include <tcpup/tcp.h>
#include <tcpup/tcp_seq.h>
#include <tcpup/tcp_var.h>
#include <tcpup/tcp_debug.h>

static int _total_socket = 0;
static int _accept_evt_init = 0;
static sockcb_q so_list_head = {0};
static tx_task_q _accept_evt_list = {0};

sockcb_t mksockcb()
{
	sockcb_t so;
	so = (sockcb_t )calloc(1, sizeof(*so));

	so->so_tag = 0xBEAF;
	so->so_count = 1;
	so->so_state = 0;
	so->so_link = (random() & 0xffff);

	LIST_INSERT_HEAD(&so_list_head, so, entries);
	_total_socket++;
	TCP_DEBUG(_total_socket > 10, "total socket count: %d\n", _total_socket);
	return so;
}

void sofree(sockcb_t so)
{
	if (!(so->so_state & SS_NOFDREF) ||
			so->so_count != 0 || (so->so_state & SS_PROTOREF)) {
		return;
	}

	TCP_DEBUG(1, "sofree conv=%x\n", so->so_conv);
	(*so->usrreqs->so_detach)(so);
	so->so_tag = 0xDEAD;
	LIST_REMOVE(so, entries);
	free(so);
	_total_socket--;
}

sockcb_t solookup(so_conv_t conv)
{
	sockcb_t so = NULL, cur, next;

	LIST_FOREACH_SAFE(cur, &so_list_head, entries, next) {
		if (cur->so_conv == conv) {
			so = cur;
			break;
		}
	}

	return so;
}

sockcb_t sonewconn(int iface, so_conv_t conv,  unsigned link)
{
	sockcb_t so = mksockcb();
	so->so_conv = conv;
	so->so_link = link;
	so->so_iface = iface;
	so->usrreqs = &tcp_usrreqs;
	so->so_state |= SS_NOFDREF;
	so->so_state |= SS_ACCEPTABLE;
	so->so_count = 0;

	(*so->usrreqs->so_attach)(so);
		TCP_DEBUG(1, "sonewconn conv %x\n", so->so_conv);
	return so;
}

void soisconnected(sockcb_t so)
{
	struct tcpcb *tp;
	struct rgnbuf *sndbuf;

	if (_accept_evt_init == 0) {
		LIST_INIT(&_accept_evt_list);
		_accept_evt_init = 1;
	}

	tp = so->so_pcb;
	int oldstat = so->so_state;
	if (oldstat & SS_ISDISCONNECTED) {
		assert(0);
		return;
	}

	so->so_state &= ~(SS_ISCONNECTING| SS_ISDISCONNECTING);
	so->so_state |= SS_ISCONNECTED;

	if ((so->so_state & SS_NOFDREF) && !(oldstat & SS_ISCONNECTED)) {
		tx_task_wakeup(&_accept_evt_list, "accept");
	}

	sndbuf = tp->rgn_snd;
	if (sndbuf->rb_flags & SBS_CANTSENDMORE) {
		tcp_shutdown(tp);
	}

	return;
}

static void sorelease(sockcb_t so)
{
	assert(so->so_count > 0);

	if (--so->so_count == 0) {
		sofree(so);
	}

	return;
}

sockcb_t socreate(int file, so_conv_t conv)
{
	sockcb_t so = mksockcb();
	so->so_conv = conv;
	so->so_iface = file;
	so->usrreqs = &tcp_usrreqs;

	(*so->usrreqs->so_attach)(so);
	return so;
}

sockcb_t soaccept(sockcb_t lso, struct sockaddr *address, size_t *address_len)
{
	sockcb_t soacc = NULL, cur, next;

	LIST_FOREACH_SAFE(cur, &so_list_head, entries, next) {
		int sostat = cur->so_state;

		if ((sostat & SS_ISDISCONNECTED) || !(sostat & SS_ACCEPTABLE)) {
			continue;
		}

		if ((sostat & SS_ISCONNECTED) && (sostat & SS_NOFDREF)) {
			soacc = cur;
			break;
		}
	}

	if (soacc != NULL) {
		struct sockaddr *addr = NULL;
		soacc->so_state &= ~(SS_NOFDREF| SS_ACCEPTABLE);
		soacc->so_count++;

		(*soacc->usrreqs->so_accept)(soacc, &addr);
		if (addr != NULL && address != NULL) {
			if (address_len && *address_len >= sizeof(struct sockaddr_in)) {
				memcpy(address, addr, sizeof(struct sockaddr_in));
				*address_len = sizeof(struct sockaddr_in);
			}
		}
	}

	return soacc;
}

int soreadable(sockcb_t so)
{
	return tcp_readable(so->priv.tcp);
}

int sowritable(sockcb_t so)
{
	return tcp_writable(so->priv.tcp);
}

int soshutdown(sockcb_t so)
{
	return tcp_shutdown(so->priv.tcp);
}

int sopoll(sockcb_t so, SocketOps ops, tx_task_t *cb)
{
	sockcb_t cur, next;

	if (ops == SO_ACCEPT) {
		LIST_FOREACH_SAFE(cur, &so_list_head, entries, next) {
			int sostat = cur->so_state;

			if ((sostat & SS_ISDISCONNECTED) || !(sostat & SS_ACCEPTABLE)) {
				continue;
			}

			if ((sostat & SS_ISCONNECTED) && (sostat & SS_NOFDREF)) {
				tx_task_active(cb, "sopoll");
				return 0;
			}
		}

		if (_accept_evt_init == 0) {
			LIST_INIT(&_accept_evt_list);
			_accept_evt_init = 1;
		}

		tx_task_record(&_accept_evt_list, cb);
		return 0;
	}

	return tcp_poll(so->priv.tcp, ops, cb);
}

int sooptset_target(sockcb_t so, void *buf, size_t len)
{
	return tcp_relayto(so->priv.tcp, buf, len);
}

int sooptget_target(sockcb_t so, void *buf, size_t len)
{
	return tcp_relayget(so->priv.tcp, buf, len);
}

int sowrite(sockcb_t so, const void *buf, size_t len)
{
	return tcp_write(so->priv.tcp, buf, len);
}

int soread(sockcb_t so, void *buf, size_t len)
{
	return tcp_read(so->priv.tcp, buf, len);
}

int soconnected(sockcb_t so)
{
	return tcp_connected(so->priv.tcp);
}

int soconnect(sockcb_t so, const struct sockaddr *address, size_t address_len)
{
	int err = 0;

	err = (*so->usrreqs->so_connect)(so, address, address_len);

	return err;
}

#if 0
int soerrno(sockcb_t so)
{
	abort();
	return 0;
}
#endif

int soclose(sockcb_t so)
{
	int err = 0;
	(*so->usrreqs->so_close)(so);
	so->so_state |= SS_NOFDREF;
	sorelease(so);
	return err;
}
