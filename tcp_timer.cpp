#include <stdio.h>
#include <time.h>
#include <assert.h>

#include <txall.h>

#define TCPUP_LAYER 1
#include <utx/queue.h>
#include <utx/utxpl.h>
#include <utx/socket.h>

#include <tcpup/cc.h>
#include <tcpup/tcp.h>
#include <tcpup/tcp_fsm.h>
#include <tcpup/tcp_var.h>
#include <tcpup/tcp_seq.h>
#include <tcpup/tcp_timer.h>
#include <tcpup/tcp_debug.h>

#include "tcp_filter.h"
#include "client_track.h"

extern int tcp_iss;

int tcp_keepinit = TCPTV_KEEP_INIT;
int tcp_keepidle = TCPTV_KEEP_IDLE;
int tcp_keepintvl = TCPTV_KEEPINTVL;
int tcp_rexmit_slop = TCPTV_CPU_VAR;

int tcp_keepcnt = TCPTV_KEEPCNT;
int tcp_maxidle = TCPTV_KEEPINTVL * TCPTV_KEEPCNT;
int tcp_delacktime = TCPTV_DELACK;

static int tcp_totbackoff = 2559; 

void tcp_canceltimers(struct tcpcb *tp)
{
	tx_timer_stop(&tp->t_timer_persist);
	tx_task_drop(&tp->t_timer_persist_t);

	tx_timer_stop(&tp->t_timer_rexmt);
	tx_task_drop(&tp->t_timer_rexmt_t);

	tx_timer_stop(&tp->t_timer_keep);
	tx_task_drop(&tp->t_timer_keep_t);

	tx_timer_stop(&tp->t_timer_2msl);
	tx_task_drop(&tp->t_timer_2msl_t);
}

static void tcp_2msl_timo(void *up)
{ 
   	struct tcpcb *tp;

	tp = (struct tcpcb *)up;
	ticks = tcp_ts_getticks();
   	if (tp->t_state != TCPS_TIME_WAIT &&
		   	(int)ticks - (int)tp->t_rcvtime <= (int)tcp_maxidle) {
		tx_timer_reset(&tp->t_timer_2msl, tcp_keepintvl);
   	} else {
	   	// tp->t_state = TCPS_CLOSED;
		tcp_close(tp);
   	}

	return;
}

static void tcp_persist_timo(void *up)
{
   	struct tcpcb *tp;

	tp = (struct tcpcb *)up;
   	TCPSTAT_INC(tcps_persisttimeo);
	
	ticks = tcp_ts_getticks();
	tcp_timer_activate(tp, TT_PERSIST, 0);

	/*
	 * Hack: if the peer is dead/unreachable, we do not
	 * time out if the window is closed.  After a full
	 * backoff, drop the connection if the idle time
	 * (no responses to probes) reaches the maximum
	 * backoff that we would use if retransmitting.
	 */
	if (tp->t_rxtshift == TCP_MAXRXTSHIFT &&
			(ticks - tp->t_rcvtime >= tcp_maxpersistidle ||
			 ticks - tp->t_rcvtime >= TCP_REXMTVAL(tp) * tcp_totbackoff)) {
		TCPSTAT_INC(tcps_persistdrop);
		tp = tcp_drop(tp, UTXTIMEDOUT);
		goto out;
	}
	/*
	 * If the user has closed the socket then drop a persisting
	 * connection after a much reduced timeout.
	 */
	if (tp->t_state > TCPS_CLOSE_WAIT &&
			(ticks - tp->t_rcvtime) >= TCPTV_PERSMAX) {
		TCPSTAT_INC(tcps_persistdrop);
		tp = tcp_drop(tp, UTXTIMEDOUT);
		goto out;
	}

	tcp_setpersist(tp);
   	tp->t_flags |= TF_FORCEDATA;
   	(void)tcp_output(tp);
   	tp->t_flags &= ~TF_FORCEDATA;
out:

	return;
}

int tcp_filter_lost(struct tcpcb *tp, int *retp);

extern int total;
static void tcp_rexmt_timo(void *up)
{
	int trans = total, lost;
	u_long rexmt;
   	struct tcpcb *tp;

	tp = (struct tcpcb *)up;
	ticks = tcp_ts_getticks();
	tcp_free_sackholes(tp);
	tcp_filter_free(tp);

	lost = tcp_filter_lost(tp, &trans);
	TCP_DEBUG(1, "tcp rexmt time out %x una %x rec %x rec %x dup %d %d tx %x/%d\n",
		tp->tp_socket->so_conv, tp->snd_una, tp->snd_recover, IN_FASTRECOVERY(tp->t_flags), tp->t_dupacks, tp->t_rxtcur, tp->snd_nxt, trans);

   	if (++tp->t_rxtshift > TCP_MAXRXTSHIFT) {
	   	tp->t_rxtshift = TCP_MAXRXTSHIFT;
	   	// tp->t_state = TCPS_CLOSED;
	   	TCPSTAT_INC(tcps_timeoutdrop);
	   	sorwakeup(tp);
	   	sowwakeup(tp);
		tcp_close(tp);
		return;
   	}

	int stat = client_track_fetch(tp->tp_socket->so_conv, &tp->dst_addr, sizeof(tp->dst_addr), tp->t_rcvtime);
	if (tp->t_rxtshift == 1) {
	   	tp->snd_cwnd_prev = tp->snd_cwnd;
	   	tp->snd_recover_prev = tp->snd_recover;
	   	tp->snd_ssthresh_prev = tp->snd_ssthresh;
	   	if (IN_FASTRECOVERY(tp->t_flags))
		   	tp->t_flags |= TF_WASFRECOVERY;
	   	else
		   	tp->t_flags &= ~TF_WASFRECOVERY;

		if (IN_CONGRECOVERY(tp->t_flags))
			tp->t_flags |= TF_WASCRECOVERY;
		else
			tp->t_flags &= ~TF_WASCRECOVERY;

	   	tp->t_badrxtwin = ticks + (tp->t_srtt >> (TCP_RTT_SHIFT + 1));
		tp->t_flags |= TF_PREVVALID;
   	} else
		tp->t_flags &= ~TF_PREVVALID;
   
	TCPSTAT_INC(tcps_rexmttimeo);
   	rexmt = TCP_REXMTVAL(tp) * tcp_backoff[tp->t_rxtshift];
   	TCPT_RANGESET(tp->t_rxtcur, rexmt, 
			(u_long)tp->t_rttmin, TCPTV_REXMTMAX);
	tx_timer_reset(&tp->t_timer_rexmt, tp->t_rxtcur);

	if (tp->t_rxtshift > TCP_MAXRXTSHIFT / 4) {
	   	tp->t_rttvar += (tp->t_srtt >> TCP_RTT_SHIFT);
	   	tp->t_srtt = 0;
   	}

   	tp->snd_nxt = tp->snd_una;
   	tp->snd_recover = tp->snd_max;
	tp->ts_recover = ticks;
   	tp->t_flags |= TF_ACKNOW;
   	tp->t_rtttime = 0;

	cc_cong_signal(tp, NULL, CC_RTO);
	tp->snd_cwnd = tp->t_maxseg;
   	(void)tcp_output(tp);

	return;
}

#include <stdlib.h>

static void tcp_keep_timo(void *up)
{
	int stat = 0;
   	struct tcpcb *tp;

	tp = (struct tcpcb *)up;
	ticks = tcp_ts_getticks();
   	TCPSTAT_INC(tcps_keeptimeo);
   	if (tp->t_state < TCPS_ESTABLISHED)
	   	goto dropit;
   	if (tp->t_state <= TCPS_CLOSING) {
		if (ticks - tp->t_rcvtime >= TP_KEEPIDLE(tp) + TP_MAXIDLE(tp))
			goto dropit;
		TCPSTAT_INC(tcps_keepprobe);
	   	/* tcp_respond */

		if ((tp->t_flags & TF_REC_ADDR) == 0) {
#if 0
			tp->dst_addr.xdat = rand();
			TCP_TRACE_AWAYS(tp, "%x re assign xdat %x\n", tp->tp_socket->t_conv, tp->dst_addr.xdat);
#endif
		}

		if (ticks - tp->t_rcvtime >= TP_KEEPIDLE(tp) + TP_KEEPINTVL(tp))
			stat = client_track_fetch(tp->tp_socket->so_conv, &tp->dst_addr, sizeof(tp->dst_addr), tp->t_rcvtime);
		tcp_respond(tp, NULL, tp->rcv_nxt, tp->snd_una - 1, TH_ACK, tp->tp_socket->so_link);
		tx_timer_reset(&tp->t_timer_keep, TP_KEEPINTVL(tp));
   	} else
		tx_timer_reset(&tp->t_timer_keep, TP_KEEPIDLE(tp));
	return;

dropit:
	TCPSTAT_INC(tcps_keepdrops);
	tp = tcp_drop(tp, UTXTIMEDOUT);

	return;
}

static void tcp_do_delack(void *uup)
{
	struct tcpcb *tp;

	tp = (struct tcpcb *)uup;

	tp->t_flags |= TF_ACKNOW;
	TCPSTAT_INC(tcps_delack);
	(void)tcp_output(tp);

	return;
}

int tcp_filter_xmit(struct tcpcb *);

static void tcp_output_wrap(void *uup)
{
	struct tcpcb *tp;
	tp = (struct tcpcb *)uup;

	tcp_cancel_devbusy(tp);

	ticks = tcp_ts_getticks();
	(void)tcp_filter_xmit(tp);
	return;
}

void
tcp_timer_activate(struct tcpcb *tp, int timer_type, u_int delta)
{
	struct tx_task_t *t_task;
	struct tx_timer_t *t_callout;

	switch (timer_type) {
		case TT_DELACK:
			t_callout = &tp->t_timer_delack;
			t_task = &tp->t_timer_delack_t;
			break;
		case TT_REXMT:
			t_callout = &tp->t_timer_rexmt;
			t_task = &tp->t_timer_rexmt_t;
			break;
		case TT_PERSIST:
			t_callout = &tp->t_timer_persist;
			t_task = &tp->t_timer_persist_t;
			break;
		case TT_KEEP:
			t_callout = &tp->t_timer_keep;
			t_task = &tp->t_timer_keep_t;
			break;
		case TT_2MSL:
			t_callout = &tp->t_timer_2msl;
			t_task = &tp->t_timer_2msl_t;
			break;
		default:
			/* static char _type[] = "bad timer_type"; */
			UTXPL_ASSERT(0);
			return;
	}

	if (delta == 0) {
		tx_timer_stop(t_callout);
		tx_task_drop(t_task);
	} else {
		tx_task_drop(t_task);
		tx_timer_reset(t_callout, delta);
	}

	return;
}

int
tcp_timer_active(struct tcpcb *tp, int timer_type)
{
	struct tx_task_t *t_task;
	struct tx_timer_t *t_callout;

	switch (timer_type) {
		case TT_DELACK:
			t_callout = &tp->t_timer_delack;
			t_task = &tp->t_timer_delack_t;
			break;
		case TT_REXMT:
			t_callout = &tp->t_timer_rexmt;
			t_task = &tp->t_timer_rexmt_t;
			break;
		case TT_PERSIST:
			t_callout = &tp->t_timer_persist;
			t_task = &tp->t_timer_persist_t;
			break;
		case TT_KEEP:
			t_callout = &tp->t_timer_keep;
			t_task = &tp->t_timer_keep_t;
			break;
		case TT_2MSL:
			t_callout = &tp->t_timer_2msl;
			t_task = &tp->t_timer_2msl_t;
			break;
		default:
			/* static char _type[] = "bad timer_type"; */
			TCP_DEBUG(1, "bad timer_type");
			UTXPL_ASSERT(0);
			return -1;
	}

	return !(tx_timer_idle(t_callout) && tx_task_idle(t_task));
}



void tcp_setuptimers(struct tcpcb *tp)
{
	tx_loop_t *loop = tx_loop_default();

#define TCP_TIMER_INIT(tp, timer, func) do { \
		tx_task_init(&tp->timer##_t, loop, func, tp); \
		tx_timer_init(&tp->timer, loop, &tp->timer##_t); \
	} while ( 0 )

	TCP_TIMER_INIT(tp, t_timer_2msl, tcp_2msl_timo);
	TCP_TIMER_INIT(tp, t_timer_keep, tcp_keep_timo);
	TCP_TIMER_INIT(tp, t_timer_rexmt, tcp_rexmt_timo);
	TCP_TIMER_INIT(tp, t_timer_delack, tcp_do_delack);
	TCP_TIMER_INIT(tp, t_timer_persist, tcp_persist_timo);
#undef TCP_TIMER_INIT

	tp->t_pacing = tx_getticks();
        tp->t_pacing <<= PACING_SHIFT;
	tx_task_init(&tp->t_event_devbusy, loop, tcp_output_wrap, tp);
}

void tcp_cleantimers(struct tcpcb *tp)
{

#define TCP_TIMER_CLEAN(tp, timer) do { \
		tx_task_drop(&tp->timer##_t); \
		tx_timer_stop(&tp->timer); \
	} while ( 0 )

	TCP_TIMER_CLEAN(tp, t_timer_2msl);
	TCP_TIMER_CLEAN(tp, t_timer_keep);
	TCP_TIMER_CLEAN(tp, t_timer_rexmt);
	TCP_TIMER_CLEAN(tp, t_timer_delack);
	TCP_TIMER_CLEAN(tp, t_timer_persist);
#undef TCP_TIMER_CLEAN

	tcp_cancel_devbusy(tp);

}

static tx_task_q _delack_queue;
static struct tx_task_t _iss_task;
static struct tx_timer_t _iss_timer;

static struct tx_task_t _delack_task;
static struct tx_timer_t _delack_timer;

void tcp_cancel_devbusy(struct tcpcb *tp)
{
	tp->t_flags &= ~TF_DEVBUSY;
	tx_task_drop(&tp->t_event_devbusy);
	return;
}

static void inc_iss(void *up)
{
	int *p_iss;

	p_iss = (int *)up;
	(*p_iss)++;

	tx_timer_reset(&_iss_timer, 500);
}

static void flush_delack(void *up)
{
	tx_task_wakeup(&_delack_queue, "flush_delay");
	tx_timer_reset(&_delack_timer, 200);
}

static void module_init(void)
{
	tx_loop_t *loop = tx_loop_default();

	tx_task_init(&_iss_task, loop, inc_iss, &tcp_iss);
	tx_timer_init(&_iss_timer, loop, &_iss_task);

	tx_task_init(&_delack_task, loop, flush_delack, &_delack_queue);
	tx_timer_init(&_delack_timer, loop, &_delack_task);

	tx_timer_reset(&_delack_timer, 1);
	tx_timer_reset(&_iss_timer, 1);
}

static void module_clean(void)
{
	tx_timer_stop(&_delack_timer);
	tx_timer_stop(&_iss_timer);
}

struct module_stub tcp_timer_mod = {
	module_init, module_clean
};
