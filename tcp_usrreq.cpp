#include <stdlib.h>
#include <errno.h>

#define TCPUP_LAYER 1
#include <utx/queue.h>
#include <utx/utxpl.h>
#include <utx/sobuf.h>
#include <utx/socket.h>

#include <tcpup/cc.h>
#include <tcpup/tcp.h>
#include <tcpup/h_ertt.h>
#include <tcpup/tcp_seq.h>
#include <tcpup/tcp_var.h>
#include <tcpup/tcp_fsm.h>
#include <tcpup/tcp_timer.h>
#include <tcpup/tcp_debug.h>

#include "tcp_filter.h"

#define LF_QUEUED 1
#ifndef ECONNABORTED
#define ECONNABORTED WSAECONNABORTED
#endif

extern int tcp_iss;
int tcp_rexmit_min = TCPTV_MIN;

void sorwakeup(struct tcpcb *tp)
{
   	tx_task_active(tp->r_event, "sor");
	return;
}

void sowwakeup(struct tcpcb *tp)
{
	switch (tp->t_state) {
		case TCPS_SYN_SENT:
		case TCPS_SYN_RECEIVED:
			if (rgn_len(tp->rgn_snd) < tp->t_maxseg) {
				tx_task_active(tp->w_event, "sow");
			}
			break;

		default:
			if (rgn_rest(tp->rgn_snd) * 4 >= rgn_size(tp->rgn_snd)) {
				tx_task_active(tp->w_event, "sow");
			} else if (rgn_rest(tp->rgn_snd) >= 4096) {
				tx_task_active(tp->w_event, "sow");
			}
			break;
	}

	return;
}

static int tcp_stat(void)
{
#if 0
#define XX(field) fprintf(stderr, "%s: %ld\n", #field, tcpstat.field)
	XX(tcps_sndprobe);
	XX(tcps_sndrexmitpack);
	XX(tcps_sndrexmitbyte);
	XX(tcps_sndpack);
	XX(tcps_sndbyte);
	XX(tcps_sndacks);
	XX(tcps_sndctrl);
	XX(tcps_sndwinup);
	XX(tcps_segstimed);
	XX(tcps_sndtotal);
	XX(tcps_accepts);
	XX(tcps_connects);
	XX(tcps_pawsdrop);
	XX(tcps_predack);
	XX(tcps_preddat);
	XX(tcps_rcvackbyte);
	XX(tcps_rcvackpack);
	XX(tcps_rcvacktoomuch);
	XX(tcps_rcvafterclose);
	XX(tcps_rcvbyte);
	XX(tcps_rcvbyteafterwin);
	XX(tcps_rcvdupbyte);
	XX(tcps_rcvduppack);
	XX(tcps_rcvpack);
	XX(tcps_rcvpackafterwin);
	XX(tcps_rcvpartdupbyte);
	XX(tcps_rcvpartduppack);
	XX(tcps_rcvtotal);
	XX(tcps_rcvwinprobe);
	XX(tcps_rcvwinupd);
	XX(tcps_delack);
	XX(tcps_timeoutdrop);
	XX(tcps_rexmttimeo);
	XX(tcps_persisttimeo);
	XX(tcps_keeptimeo);
	XX(tcps_keepprobe);
	XX(tcps_keepdrops);
	XX(tcps_rttupdated);
	XX(tcps_sndrexmitbad);
	XX(tcps_sack_rexmits);
	XX(tcps_sack_rexmit_bytes);
	XX(tcps_ecn_rcwnd);
	XX(tcps_sack_recovery_episode);
#undef XX
#endif
	return 0;
}

int get_device_mtu();
void ertt_uma_ctor(void *mem, int size, void *arg, int flags);
void ertt_uma_dtor(void *mem, int size, void *arg);

int tcp_usr_accept(sockcb_t so, struct sockaddr **nam)
{
	struct tcpcb *tp;

	if (so->so_state & SS_ISDISCONNECTED)
		return (ECONNABORTED);

	if (nam != NULL) {
		size_t cplen;
		static struct sockaddr_in6 so_addr;
		*nam = (struct sockaddr *)&so_addr;

		tp = so->so_pcb;
		cplen =  tp->dst_addr.namlen;
		cplen = (cplen > sizeof(so_addr)? sizeof(so_addr): cplen);
		memcpy(&so_addr, tp->dst_addr.name, cplen);
	}

	return 0;
}

static int tcp_attach(sockcb_t so)
{
	struct tcpcb *tp;
	int error = 0;

	tp = tcp_newtcpcb(so);
	assert(tp != NULL);

	tp->t_state = TCPS_CLOSED;
	return error;
}

/*
 * TCP attaches to socket via pru_attach(), reserving space,
 * and an internet control block.
 */
static int tcp_usr_attach(sockcb_t so)
{
	struct tcpcb *tp = NULL;
	int error;

	error = tcp_attach(so);
	if (error)
		goto out;

out:
	return error;
}

/*
 * tcp_detach is called when the socket layer loses its final reference
 * to the socket, be it a file descriptor reference, a reference from TCP,
 * etc.  At this point, there is only one case in which we will keep around
 * inpcb state: time wait.
 *
 * This function can probably be re-absorbed back into tcp_usr_detach() now
 * that there is a single detach path.
 */
static void tcp_detach(sockcb_t so, struct tcpcb *tp)
{
	assert(tp == so->so_pcb);
	assert(tp->tp_socket == so);

	if (tp->t_state < TCPS_SYN_SENT) {
		tcp_discardcb(tp);
	} else {
		abort();
	}

	return;
}

/*
 * pru_detach() detaches the TCP protocol from the socket.
 * If the protocol state is non-embryonic, then can't
 * do this directly: have to initiate a pru_disconnect(),
 * which may finish later; embryonic TCB's can just
 * be discarded here.
 */
static int tcp_usr_detach(sockcb_t so)
{
	tcp_detach(so, so->so_pcb);
	return 0;
}

struct tcpcb *tcp_drop(struct tcpcb *tp, int why)
{
	sockcb_t so = tp->tp_socket;

	if (TCPS_HAVERCVDSYN(tp->t_state)) {
		TCP_TRACE_AWAYS(tp, "%p %d -> TCPS_CLOSED\n", tp->t_state, tp);
		tcp_state_change(tp, TCPS_CLOSED);
		(void) tcp_output(tp);
	}

	return (tcp_close(tp));
}

void tcp_discardcb(struct tcpcb *tp)
{
	sockcb_t so = tp->tp_socket;

 	TCP_TRACE_END(tp, "tcp_free %p %x\n", tp, tp->t_flags & SS_NOFDREF);
	UTXPL_ASSERT(tp->r_event == NULL);
	UTXPL_ASSERT(tp->w_event == NULL);
	
	tcp_cleantimers(tp);
	rgn_destroy(tp->rgn_snd);
	rgn_destroy(tp->rgn_rcv);
	tcp_free_sackholes(tp);
	if (CC_ALGO(tp)->cb_destroy != NULL)
		CC_ALGO(tp)->cb_destroy(tp->ccv);
	// ertt_uma_dtor(tp->osd, 0, 0);
	tcp_filter_free(tp);
	free(tp->osd);

	// CC_ALGO(tp) = NULL;
	tp->tp_tag = 0xDEAD;
	tp->tp_socket = NULL;
	so->so_pcb = NULL;
	free(tp);

	tcp_stat();
	run_tcp_free_hook();
	return;
}

void soisdisconnecting(sockcb_t so)
{
	struct tcpcb *tp;
	so->so_state &= ~SS_ISCONNECTING;
	so->so_state |= SS_ISDISCONNECTING;

	tp = so->so_pcb;
	tp->rgn_rcv->rb_flags |= SBS_CANTRCVMORE;
	sorwakeup(tp);

	tp->rgn_snd->rb_flags |= SBS_CANTSENDMORE;
	tx_task_active(tp->w_event, "sow");
	return;
}

void soisdisconnected(sockcb_t so)
{
	struct tcpcb *tp;
	so->so_state &= ~(SS_ISCONNECTING| SS_ISCONNECTED| SS_ISDISCONNECTING);
	so->so_state |= SS_ISDISCONNECTED;

	tp = so->so_pcb;
	tp->rgn_rcv->rb_flags |= SBS_CANTRCVMORE;
	sorwakeup(tp);

	tp->rgn_snd->rb_flags |= SBS_CANTSENDMORE;
	tx_task_active(tp->w_event, "sow");
	return;
}

int tcp_read(struct tcpcb *tp, void *buf, size_t count)
{
	int min_len = min((int)count, rgn_len(tp->rgn_rcv));

	TCP_TRACE_CHECK(tp, tp->t_state != TCPS_ESTABLISHED,
			"min_len = %d\n", min_len);

	if (rgn_len(tp->rgn_rcv) == 0) {
		if (!iscantrcvmore(tp->rgn_rcv)) {
			tp->t_error = UTXEWOULDBLOCK;
			return -1;
		}

		TCP_TRACE_AWAYS(tp, "tcp_read return zero\n", tp);
		return 0;
	}


	rgn_get(tp->rgn_rcv, buf, min_len);
	tcp_output(tp);
	return min_len;
}

int sorlock(struct tcpcb *tp, rgn_iovec iov[2])
{
	int space;

	/* accqure tp->rgn_rcv */
	space = rgn_rlock(tp->rgn_rcv, iov);
	/* release tp->rgn_rcv */
	return space;
}

int sorunlock(struct tcpcb *tp, size_t len)
{
	/* accqure tp->rgn_rcv */
	rgn_runlock(tp->rgn_rcv, len);
	/* release tp->rgn_rcv */

#if 0
	tcp_update(tp);
#endif
	return 0;
}

int sowwait(struct tcpcb *tp)
{
	return 0;
}

int sowlock(struct tcpcb *tp, rgn_iovec iov[2])
{
	int space;

	/* accqure tp->rgn_snd */
	space = rgn_wlock(tp->rgn_snd, iov);
	/* release tp->rgn_snd */
	return space;
}

int sowunlock(struct tcpcb *tp, size_t len)
{
	/* accqure tp->rgn_snd */
	rgn_wunlock(tp->rgn_snd, len);
	/* release tp->rgn_snd */

#if 0
	tcp_update(tp);
#endif
	return 0;
}

int tcp_write(struct tcpcb *tp, const void *buf, size_t count)
{
	int min_len = min((int)count, rgn_rest(tp->rgn_snd));

	switch (tp->t_state) {
		case TCPS_SYN_SENT:
		case TCPS_SYN_RECEIVED:
			TCP_DEBUG(1, "tcp_write in incorrect state: %d\n", tp->t_state);

		case TCPS_ESTABLISHED:
		case TCPS_CLOSE_WAIT:
			rgn_put(tp->rgn_snd, buf, min_len);
			if (min_len < count)
				tp->t_flags |= TF_MORETOCOME;
			else if (rgn_rest(tp->rgn_snd))
				tp->t_flags &= ~TF_MORETOCOME;
			tcp_output(tp);
			break;

		default:
			tp->t_error = UTXEINVAL;
			return -1;
	}

	if (min_len == 0) {
		tp->t_error = UTXEWOULDBLOCK;
		return -1;
	}

	return min_len;
}

int tcp_connected(struct tcpcb *tp)
{
	return (tp->t_state >= TCPS_ESTABLISHED);
}

int tcp_writable(struct tcpcb *tp)
{
	if (tp->t_state == TCPS_ESTABLISHED ||
			tp->t_state == TCPS_CLOSE_WAIT) {
		return rgn_rest(tp->rgn_snd) > 0;
	}

	if (tp->t_state == TCPS_SYN_SENT ||
			tp->t_state == TCPS_SYN_RECEIVED) {
		return rgn_len(tp->rgn_snd) == 0;
	}

	return 1;
}

int tcp_readable(struct tcpcb *tp)
{
	if (rgn_len(tp->rgn_rcv) > 0 || 
			iscantrcvmore(tp->rgn_rcv)) {
		return 1;
	}

	return 0;
}

int tcp_relayto(struct tcpcb *tp, void *buf, size_t len)
{
	if (len < sizeof(tp->relay_target)) {
		memcpy(tp->relay_target, buf, len);
		tp->relay_len = len;
		return 0;
	}

	return -1;
}

#define AFTYP_INET   1
int tcp_relayget(struct tcpcb *tp, void *buf, int len)
{
	int cplen;
	uint8_t builtin_target[] = {AFTYP_INET, 0, 0, 22, 127, 0, 0, 1};

	if (tp->relay_len == 0 && len > sizeof(builtin_target)) {
		len = sizeof(builtin_target);
		memcpy(buf, builtin_target, len);
		return len;
	} else if (len >= tp->relay_len) {
		cplen = tp->relay_len;
		memcpy(buf, tp->relay_target, cplen);
		return cplen;
	}

	return -1;
}

void tcp_usrclosed(struct tcpcb *tp);
int tcp_shutdown(struct tcpcb *tp)
{
#if 0
	switch (tp->t_state) {
		case TCPS_ESTABLISHED:
			tp->t_state = TCPS_FIN_WAIT_1;
			TCP_TRACE_AWAYS(tp, "TCPS_ESTABLISHED -> TCPS_FIN_WAIT_1\n");
			(void)tcp_output(tp);
			break;

		case TCPS_CLOSE_WAIT:
			TCP_TRACE_AWAYS(tp, "TCPS_CLOSE_WAIT -> TCPS_LAST_ACK\n");
			tp->t_state = TCPS_LAST_ACK;
			(void)tcp_output(tp);
			break;

		default:
			tp->rgn_snd->rb_flags |= SBS_CANTSENDMORE;
			break;
	}
#endif

	tp->rgn_snd->rb_flags |= SBS_CANTSENDMORE;
	tcp_usrclosed(tp);

	if (tp->t_state != TCPS_CLOSED) {
		(void)tcp_output(tp);
		UTXPL_ASSERT(tp->rgn_snd);
		tp->rgn_snd = rgn_trim(tp->rgn_snd);
	}

	return 0;
}

int tcp_poll(struct tcpcb *tp, int typ, struct tx_task_t *task)
{
	int error = -1;
	int limit = 0;

	tx_task_drop(task);


   	switch (typ) {
		case TCP_READ:
			if (rgn_len(tp->rgn_rcv) > 0) {
			   	tx_task_active(task, "sor");
				error = 0;
				break;
		   	}

			if (iscantrcvmore(tp->rgn_rcv)) {
			   	tx_task_active(task, "sor");
				error = 0;
				break;
			}

			TCP_TRACE_CHECK(tp, tp->t_state != TCPS_ESTABLISHED, "%p not TCPS_ESTABLISHED %d state %d\n", tp, tp->tp_socket->so_conv, tp->t_state);
			assert(task == tp->r_event || tp->r_event == NULL);
		   	tp->r_event = task;
			error = 1;
			break;

		case TCP_CONNECT:
			if (tp->t_state == TCPS_SYN_SENT ||
					tp->t_state == TCPS_SYN_RECEIVED) {
				assert(task == tp->w_event || tp->w_event == NULL);
				tp->w_event = task;
				error = 0;
				break;
			} 

			tx_task_active(task, "soc");
			error = 1;
			break;

		case TCP_WRITE:
			if (rgn_rest(tp->rgn_snd) == 0 && rgn_len(tp->rgn_snd) > 0) {
				assert(task == tp->w_event || tp->w_event == NULL);
				tp->t_flags |= TF_MORETOCOME;
				tp->w_event = task;
				error = 0;
				break;
			}

#if 1
			limit = (tp->snd_max - tp->snd_una);
			if (tp->snd_wnd < (rgn_len(tp->rgn_snd) - limit) &&
					rgn_len(tp->rgn_snd) >= limit + 8192) {
				assert(task == tp->w_event || tp->w_event == NULL);
				tp->t_flags |= TF_MORETOCOME;
				tp->w_event = task;
				error = 0;
				break;
		   	} 
#endif

			if (rgn_len(tp->rgn_snd) > 0 &&
					(tp->t_state == TCPS_SYN_SENT ||
					 tp->t_state == TCPS_SYN_RECEIVED)) {
				assert(task == tp->w_event || tp->w_event == NULL);
				tp->w_event = task;
				error = 0;
				break;
			} 

			tx_task_active(task, "sow");
			error = 1;
			break;

		default:
			TCP_DEBUG(1, "tcp poll error\n");
			break;
	}

	return error;
}

int tcp_connect(struct tcpcb *tp,
		const struct sockaddr *name, socklen_t len)
{
	if (tp->t_state == TCPS_CLOSED) {
		tp->iss = tcp_iss;
		tcp_iss += TCP_ISSINCR / 2;
		tcp_sendseqinit(tp);
		tp->t_state = TCPS_SYN_SENT;
		memcpy(tp->dst_addr.name, name, len);
		tp->dst_addr.namlen = len;
		tp->dst_addr.xdat = tp->tp_socket->so_conv;
		TCP_TRACE_AWAYS(tp, "%p TCPS_CLOSED -> TCPS_SYN_SENT\n", tp);
		return 0;
	}

	tp->t_error = UTXEINVAL;
	return -1;
}

int tcp_listen(struct tcpcb *tp)
{
	if (tp->t_state == TCPS_CLOSED) {
		tp->t_state = TCPS_LISTEN;
		TCP_TRACE_AWAYS(tp, "%p TCPS_CLOSED -> TCPS_LISTEN\n", tp);
		return 1;
	}

	tp->t_error = UTXEINVAL;
	return -1;
}

void tcp_usrclosed(struct tcpcb *tp)
{
	TCP_TRACE_AWAYS(tp, "%p tcp_usrclosed: %x\n", tp, tp->tp_socket->so_conv);
	switch (tp->t_state) {
		case TCPS_LISTEN:
			/* FALLTHROUGH */
		case TCPS_CLOSED:
			tp = tcp_close(tp);
			/*
			 * tcp_close() should never return NULL here as the socket is
			 * still open.
			 */
			break;

		case TCPS_SYN_SENT:
		case TCPS_SYN_RECEIVED:
			tp->t_flags |= TF_NEEDFIN;
			break;

		case TCPS_ESTABLISHED:
		    TCP_TRACE_AWAYS(tp, "%p TCPS_ESTABLISHED -> TCPS_FIN_WAIT_1: %x\n", tp, tp->tp_socket->so_conv);
			tcp_state_change(tp, TCPS_FIN_WAIT_1);
			break;

		case TCPS_CLOSE_WAIT:
		    TCP_TRACE_AWAYS(tp, "%p TCPS_CLOSE_WAIT -> TCPS_LAST_ACK\n", tp);
			tcp_state_change(tp, TCPS_LAST_ACK);
			break;
	}

	if (tp->t_state >= TCPS_FIN_WAIT_2) {
		soisdisconnected(tp->tp_socket);
		/* Prevent the connection hanging in FIN_WAIT_2 forever. */
		if (tp->t_state == TCPS_FIN_WAIT_2) {
			int timeout;

#if 0
			timeout = (tcp_fast_finwait2_recycle) ? 
				tcp_finwait2_timeout : TP_MAXIDLE(tp);
#endif
			timeout = TP_MAXIDLE(tp);
			tcp_timer_activate(tp, TT_2MSL, timeout);
		}
	}
}

u_short update_checksum(const void *buf, size_t count, uint32_t link);

int tcpup_do_packet(int dst, const char *buf, size_t len, const struct tcpup_addr *from, unsigned link)
{
	int handled = 0;
	struct tcpcb *tp;
	struct tcphdr *th;

	th = (struct tcphdr *)buf;
	if (len < sizeof(*th) ||
			(th->th_x2 != 0) || (th->th_urp != 0)) {
		TCP_DEBUG(len >= sizeof(*th), "BAD TCPUP MAGIC: %x %x\n", th->th_x2, th->th_urp);
		TCP_DEBUG(1, "BAD TCPUP MAGIC: %x %x\n", th->th_x2, th->th_urp);
		return -1;
	}

	u_short cksum = update_checksum(buf, len, link);
	if (cksum != 0) {
		TCP_DEBUG(1, "BAD TCPUP CHECKSUM: %x %x\n", cksum, link);
		assert(cksum != 0xffff);
		assert(0);
		return -1;
	}

	sockcb_t so = solookup(th->th_conv);
	if (so != NULL) {
		tcp_input(so, so->so_pcb, dst, buf, len, from);
		handled = 1;
	}

#define TH_CONNECT (TH_SYN | TH_ACK | TH_RST)
	if (handled == 0 && (th->th_flags & TH_CONNECT) == TH_SYN) {
		sockcb_t sonew = sonewconn(dst, th->th_conv, link);
		if (sonew != NULL) {
			tp = sonew->so_pcb;
			tp->t_state = TCPS_LISTEN;
			tp->dst_addr = *from;
			tp->sav_addr = *from;
			tcp_input(sonew, tp, dst, buf, len, from);
			handled = 1;
		}
	} else if (handled == 0 && (th->th_flags & TH_CONNECT) == TH_ACK) {
		if (th->th_x2 == 0 && th->th_urp == 0) {
			struct tcpcb tcb = {0};
			struct sockcb sob = {0};
			tcb.dst_addr = *from;
			tcb.tp_socket = &sob;

			sob.so_pcb = &tcb;
			sob.so_iface = dst;
			sob.so_conv  = th->th_conv;
			tcp_respond(&tcb, th, 0, ntohl(th->th_ack), TH_RST);
			handled = 1;
		}
	}

	return handled;
}

static void (*_tcp_free_hook)(void) = NULL;

void run_tcp_free_hook(void)
{
	if (_tcp_free_hook != NULL) {
		_tcp_free_hook();
	}
	return;
}

void set_tcp_free_hook(void (*func)(void))
{
	_tcp_free_hook = func;
	return;
}

/*
 * Initiate connection to peer.
 * Create a template for use in transmissions on this connection.
 * Enter SYN_SENT state, and mark socket as connecting.
 * Start keep-alive timer, and seed output sequence space.
 * Send initial segment on connection.
 */
static int tcp_usr_connect(sockcb_t so, const struct sockaddr *nam, size_t len)
{
	int error = 0;
	struct tcpcb *tp = NULL;
	struct sockaddr_in *sinp;
	struct sockaddr_in6 *sin6p;

	sinp = (struct sockaddr_in *)nam;
	if (len != sizeof (*sinp) && len != sizeof(*sin6p)) {
		TCP_DEBUG(1, "tcp_usr_connect failure: %d\n", len);
		return (EINVAL);
	}

	tp = so->so_pcb;
	if ((error = tcp_connect(tp, nam, len)) != 0)
		goto out;

	tcp_timer_activate(tp, TT_KEEP, TP_KEEPINIT(tp));
	error = tcp_output(tp);
out:
	return (error);
}

/*
 * Initiate (or continue) disconnect.
 * If embryonic state, just send reset (once).
 * If in ``let data drain'' option and linger null, just drop.
 * Otherwise (hard), mark socket disconnecting and drop
 * current input data; switch states based on user close, and
 * send segment to peer (with FIN).
 */
static void tcp_disconnect(struct tcpcb *tp)
{
	sockcb_t so = tp->tp_socket;

	/*
	 * Neither tcp_close() nor tcp_drop() should return NULL, as the
	 * socket is still open.
	 */
	if (tp->t_state < TCPS_ESTABLISHED) {
		tp = tcp_close(tp);
	} else {
		soisdisconnecting(so);
		tcp_usrclosed(tp);
		if (tp->t_state != TCPS_CLOSED) {
			tcp_output(tp);
		}
	}
}


static int tcp_usr_close(sockcb_t so)
{
	struct tcpcb *tp = NULL;

	tp = so->so_pcb;
	tcp_disconnect(tp);

	if (tp->t_state != TCPS_CLOSED) {
		so->so_state |= SS_PROTOREF;
		tp->t_flags |= TF_SOCKREF;
	}

	if (tp->rgn_rcv) {
		int ignore = rgn_len(tp->rgn_rcv);
		rgn_drop(tp->rgn_rcv, ignore);
		tp->rgn_rcv = rgn_trim(tp->rgn_rcv);
	}

	if (tp->rgn_snd) {
		tp->rgn_snd = rgn_trim(tp->rgn_snd);
	}

	tp->w_event = NULL;
	tp->r_event = NULL;
	return 0;
}


struct so_usrreqs tcp_usrreqs = {
#ifndef WIN32
	.so_attach = tcp_usr_attach,
	.so_detach = tcp_usr_detach,
	.so_connect = tcp_usr_connect,
	.so_accept = tcp_usr_accept,
	.so_close = tcp_usr_close
#else
	tcp_usr_attach,
	tcp_usr_detach,
	tcp_usr_connect,
	tcp_usr_accept,
	tcp_usr_close
#endif
};
