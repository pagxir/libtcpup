#include <stdlib.h>

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

#define LF_QUEUED 1

extern int tcp_iss;
int tcp_rexmit_min = TCPTV_MIN;
struct tcpcb *tcp_last_tcpcb = 0;

static int _accept_evt_init = 0;
static tx_task_q _accept_evt_list;
static int tcp_free(struct tcpcb *tp);

void soisconnected(struct tcpcb *tp)
{
	struct rgnbuf *sndbuf;

	if (_accept_evt_init == 0) {
		LIST_INIT(&_accept_evt_list);
		_accept_evt_init = 1;
	}

	if ((tp->t_flags & SS_NOFDREF)) {
		tx_task_wakeup(&_accept_evt_list);
	}

	sndbuf = tp->rgn_snd;
	if (sndbuf->rb_flags & SBS_CANTSENDMORE) {
		tcp_shutdown(tp);
	}

	return;
}

void sorwakeup(struct tcpcb *tp)
{
   	tx_task_wakeup(&tp->r_event);
	return;
}

void sowwakeup(struct tcpcb *tp)
{
	switch (tp->t_state) {
		case TCPS_SYN_SENT:
		case TCPS_SYN_RECEIVED:
			break;

		default:
		   	if (rgn_rest(tp->rgn_snd) * 2 >=
				   	rgn_size(tp->rgn_snd)) {
				int limit = (tp->snd_max - tp->snd_una);
				if (rgn_len(tp->rgn_snd) < limit + 4096) {
					tx_task_wakeup(&tp->w_event);
				}
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

void ertt_uma_ctor(void *mem, int size, void *arg, int flags);
void ertt_uma_dtor(void *mem, int size, void *arg);

struct tcpcb * tcp_newtcpcb(int if_fd, tcp_seq conv)
{
	struct tcpcb *tp;
	tp = (struct tcpcb *) malloc(sizeof(*tp));
	memset(tp, 0, sizeof(*tp));

	tp->t_conv = conv;
	tp->if_dev = if_fd;
	tp->t_state = TCPS_CLOSED;
	tp->t_srtt  = TCPTV_SRTTBASE;
	tp->t_rxtcur = TCPTV_RTOBASE;
	tp->t_rttvar = ((TCPTV_RTOBASE - TCPTV_SRTTBASE) << TCP_RTTVAR_SHIFT) / 4;
	tp->t_flags = SS_NOFDREF;
	tp->t_maxseg = TCP_MSS;

	tp->snd_max_space = (1024 * 1024);
	tp->rgn_snd = rgn_create(64 * 1024);
	tp->rcv_max_space = (1024 * 1024);
	tp->rgn_rcv = rgn_create(128 * 1024);

	tp->snd_cwnd = rgn_size(tp->rgn_snd);
	tp->snd_ssthresh = rgn_size(tp->rgn_snd);
	tp->t_rcvtime = ticks;
	tp->t_rttmin  = tcp_rexmit_min;
	tp->ts_recent = 0;
	tp->ts_offset = 0;
	tp->ts_recent_age = 0;

	tx_taskq_init(&tp->w_event);
	tx_taskq_init(&tp->r_event);

	tp->t_rttupdated = 0;
	tp->t_keepidle  = 600 * hz;
	tp->t_keepintvl = 6 * hz;

	tp->relay_len = 0;

	tp->osd = (struct osd *)malloc(sizeof(*tp->osd));
	ertt_uma_ctor(tp->osd, 0, NULL, 0);
	tcp_setuptimers(tp);

	tp->ccv = (struct cc_var *)tp->cc_mem;
	memset(tp->ccv, 0, sizeof(struct cc_var));
	tp->ccv->tcp = tp;
    if (CC_ALGO(tp)->cb_init != NULL)
        CC_ALGO(tp)->cb_init(tp->ccv);

	tp->tle_flags = 0;
	tp->tle_next = NULL;
	tp->tle_prev = &tp->tle_next;
	TAILQ_INIT(&tp->snd_holes);

	return tp;
}

struct tcpcb *tcp_accept(struct sockaddr_in *name, size_t *namlen)
{
	struct tcpcb *tp;
	struct tcpcb *newtp;

	newtp = NULL;
	for (tp = tcp_last_tcpcb; tp != NULL; tp = tp->tle_next) {
		if ((tp->t_flags & SS_NOFDREF) &&
			   	(tp->t_state == TCPS_ESTABLISHED ||
				 tp->t_state == TCPS_CLOSE_WAIT)) {
			tp->t_flags &= ~SS_NOFDREF;
			if (name != NULL && namlen != NULL
					&& *namlen >= tp->dst_addr.namlen) {
				size_t cplen =  tp->dst_addr.namlen;
				memcpy(name, tp->dst_addr.name, cplen);
				*namlen = cplen;
			}
			newtp = tp;
			break;
		}
	}

	return newtp;
}

int tcp_attach(struct tcpcb *tp)
{
	UTXPL_ASSERT((tp->tle_flags & LF_QUEUED) == 0);
	tp->tle_flags |= LF_QUEUED;
	tp->tle_next = tcp_last_tcpcb;
	tp->tle_prev = &tcp_last_tcpcb;
	if (tcp_last_tcpcb != NULL)
		tcp_last_tcpcb->tle_prev = &tp->tle_next;
	tcp_last_tcpcb = tp;

	return 0;
}

static int tcp_detach(struct tcpcb *tp)
{
	UTXPL_ASSERT(tp->tle_flags & LF_QUEUED);
	*tp->tle_prev = tp->tle_next;
	if (tp->tle_next != NULL)
		tp->tle_next->tle_prev = tp->tle_prev;
	tp->tle_prev = &tp->tle_next;
	tp->tle_flags &= ~LF_QUEUED;

	return 0;
}

struct tcpcb *tcp_drop(struct tcpcb *tp, int why)
{
	tp->t_state = TCPS_CLOSED;
	soisdisconnected(tp);

	if (tp->t_flags & TF_PROTOREF) {
		tp->t_flags &= ~TF_PROTOREF;
		TCP_TRACE_AWAYS(tp, "T1 drop %x\n", tp->t_flags & SS_NOFDREF);
		tcp_free(tp);
		return NULL;
	}

	return tp;
}

int tcp_free(struct tcpcb *tp)
{
	UTXPL_ASSERT(tp->tle_flags & LF_QUEUED);
	if ((tp->t_flags & SS_NOFDREF) == 0 ||
			(tp->t_flags & TF_PROTOREF) == TF_PROTOREF)
		return -1;

 	TCP_TRACE_END(tp, "tcp_free %p %x\n", tp, tp->t_flags & SS_NOFDREF);
	UTXPL_ASSERT(tx_taskq_empty(&tp->r_event));
	UTXPL_ASSERT(tx_taskq_empty(&tp->w_event));
	
	rgn_destroy(tp->rgn_snd);
	rgn_destroy(tp->rgn_rcv);
    if (CC_ALGO(tp)->cb_destroy != NULL)
        CC_ALGO(tp)->cb_destroy(tp->ccv);
	ertt_uma_dtor(tp->osd, 0, 0);
	free(tp->osd);
	tcp_free_sackholes(tp);
	tcp_cleantimers(tp);
	tcp_detach(tp);
	tcp_stat();
	free(tp);

	run_tcp_free_hook();
	return 0;
}

void soisdisconnected(struct tcpcb *tp)
{
	tp->rgn_rcv->rb_flags |= SBS_CANTRCVMORE;
	sorwakeup(tp);

	tp->rgn_snd->rb_flags |= SBS_CANTSENDMORE;
	tx_task_wakeup(&tp->w_event);
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
		case TCPS_ESTABLISHED:
		case TCPS_CLOSE_WAIT:
			rgn_put(tp->rgn_snd, buf, min_len);
			if (min_len < count)
				tp->t_flags |= TF_MORETOCOME;
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

int tcp_relayget(struct tcpcb *tp, void *buf, int len)
{
	int cplen;

	if (len >= tp->relay_len) {
		cplen = tp->relay_len;
		memcpy(buf, tp->relay_target, cplen);
		return cplen;
	}

	return -1;
}

int tcp_shutdown(struct tcpcb *tp)
{
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

	return 0;
}

int tcp_poll(struct tcpcb *tp, int typ, struct tx_task_t *task)
{
	int error = -1;
	int limit = 0;

	tx_task_drop(task);

	if (_accept_evt_init == 0) {
		LIST_INIT(&_accept_evt_list);
		_accept_evt_init = 1;
	}

   	switch (typ) {
		case TCP_READ:
			if (rgn_len(tp->rgn_rcv) > 0) {
			   	tx_task_active(task);
				error = 0;
				break;
		   	}

			if (iscantrcvmore(tp->rgn_rcv)) {
			   	tx_task_active(task);
				error = 0;
				break;
			}

			TCP_TRACE_CHECK(tp, tp->t_state != TCPS_ESTABLISHED, "not TCPS_ESTABLISHED %d\n");
		   	tx_task_record(&tp->r_event, task);
			error = 1;
			break;

		case TCP_WRITE:
			limit = (tp->snd_max - tp->snd_una);
		   	if (rgn_len(tp->rgn_snd) >= limit + 4096 ||
				   	tp->t_state == TCPS_SYN_SENT ||
				   	tp->t_state == TCPS_SYN_RECEIVED) {
			   	tx_task_record(&tp->w_event, task);
				error = 0;
				break;
		   	} 

			tx_task_active(task);
			error = 1;
			break;

		case TCP_ACCEPT:
		   	for (tp = tcp_last_tcpcb; tp != NULL; tp = tp->tle_next) {
			   	if ((tp->t_flags & SS_NOFDREF) &&
					   	(tp->t_state == TCPS_ESTABLISHED ||
						 tp->t_state == TCPS_CLOSE_WAIT)) {
				   	tx_task_active(task);
					return 1;
			   	}
		   	}

			tx_task_record(&_accept_evt_list, task);
			break;

		default:
			TCP_DEBUG(1, "tcp poll error\n");
			break;
	}

	return error;
}

int tcp_connect(struct tcpcb *tp,
		const struct sockaddr_in *name, size_t namlen)
{
	if (tp->t_state == TCPS_CLOSED) {
		tp->iss = tcp_iss;
		tcp_sendseqinit(tp);
		tp->t_state = TCPS_SYN_SENT;
		UTXPL_ASSERT(namlen <= sizeof(tp->dst_addr.name));
		memcpy(tp->dst_addr.name, name, namlen);
		tp->dst_addr.namlen = namlen;
		tp->dst_addr.xdat = tp->t_conv;
		TCP_TRACE_AWAYS(tp, "TCPS_CLOSED -> TCPS_SYN_SENT\n");
		(void)tcp_output(tp);
		return 1;
	}

	tp->t_error = UTXEINVAL;
	return -1;
}

int tcp_listen(struct tcpcb *tp)
{
	if (tp->t_state == TCPS_CLOSED) {
		tp->t_state = TCPS_LISTEN;
		TCP_TRACE_AWAYS(tp, "TCPS_CLOSED -> TCPS_LISTEN\n");
		return 1;
	}

	tp->t_error = UTXEINVAL;
	return -1;
}

struct tcpcb *tcp_close(struct tcpcb *tp)
{
	soisdisconnected(tp);

	if (tp->t_flags & TF_PROTOREF) {
		tp->t_flags &= ~TF_PROTOREF;
		TCP_TRACE_AWAYS(tp, "T1 close %p %x\n", tp, tp->t_flags & SS_NOFDREF);
		tcp_free(tp);
		return NULL;
	}

	return tp;
}

int tcp_soclose(struct tcpcb *tp)
{
	tcp_shutdown(tp);
	soisdisconnected(tp);

	if (tp->t_state != TCPS_CLOSED)
		tp->t_flags |= TF_PROTOREF;

	TCP_TRACE_AWAYS(tp, "tcp_soclose %p\n", tp);
	tp->t_flags |= SS_NOFDREF;
	tcp_free(tp);
	return 0;
}

int tcpup_do_packet(int dst, const char *buf, size_t len, const struct tcpup_addr *from)
{
	int handled = 0;
	tcp_seq conv = 0;
	struct tcpcb *tp;
	struct tcphdr *th;

	th = (struct tcphdr *)buf;
	if (len < sizeof(*th) ||
			(th->th_magic != MAGIC_UDP_TCP)) {
		TCP_DEBUG(len >= sizeof(*th), "BAD TCPUP MAGIC\n");
		return -1;
	}

	conv = (th->th_conv);
	for (tp = tcp_last_tcpcb; tp != NULL; tp = tp->tle_next) {
		if (conv == tp->t_conv) {
			tcp_input(tp, dst, buf, len, from);
			handled = 1;
			break;
		}
	}

#define TH_CONNECT (TH_SYN | TH_ACK | TH_RST)
	if (handled == 0 && (th->th_flags & TH_CONNECT) == TH_SYN) {
		tp = tcp_newtcpcb(dst, conv);
		if (tp != NULL) {
			tcp_attach(tp);
			tp->t_state = TCPS_LISTEN;
			tp->dst_addr = *from;
			tcp_input(tp, dst, buf, len, from);
			handled = 1;
		}
	} else if (handled == 0 && (th->th_flags & TH_CONNECT) == TH_ACK) {
		if (th->th_magic == MAGIC_UDP_TCP) {
			struct tcpcb tcb = {0};
			tcb.if_dev = dst;
			tcb.t_conv = conv;
			tcb.dst_addr = *from;
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
