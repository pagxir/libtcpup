#include <stdio.h>
#include <assert.h>

#include <txall.h>

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

extern int tcp_iss;

int tcp_keepidle = TCPTV_KEEP_IDLE;
int tcp_keepintvl = TCPTV_KEEPINTVL;
int tcp_rexmit_slop = TCPTV_CPU_VAR;

int tcp_keepcnt = TCPTV_KEEPCNT;
int tcp_maxidle = TCPTV_KEEPINTVL * TCPTV_KEEPCNT;
int tcp_delacktime = TCPTV_DELACK;

void tcp_canceltimers(struct tcpcb *tp)
{
	tx_timer_stop(&tp->t_timer_persist);
	tx_timer_stop(&tp->t_timer_rexmt);
	tx_timer_stop(&tp->t_timer_keep);
	tx_timer_stop(&tp->t_timer_2msl);
}

static void tcp_2msl_timo(void *up)
{ 
   	struct tcpcb *tp;

	tp = (struct tcpcb *)up;
   	if (tp->t_state != TCPS_TIME_WAIT &&
		   	(int)ticks - (int)tp->t_rcvtime <= (int)tcp_maxidle) {
		tx_timer_reset(&tp->t_timer_2msl, tcp_keepintvl);
   	} else {
	   	tp->t_state = TCPS_CLOSED;
	   	soisdisconnected(tp);
		tcp_close(tp);
   	}

	return;
}

static void tcp_persist_timo(void *up)
{
   	struct tcpcb *tp;

	tp = (struct tcpcb *)up;
   	tcpstat.tcps_persisttimeo++;
   	tcp_setpersist(tp);
   	tp->t_flags |= TF_FORCEDATA;
   	(void)tcp_output(tp);
   	tp->t_flags &= ~TF_FORCEDATA;

	return;
}

static void tcp_rexmt_timo(void *up)
{
	u_long rexmt;
   	struct tcpcb *tp;

	tp = (struct tcpcb *)up;
	tcp_free_sackholes(tp);

	TCP_DEBUG_TRACE(1, "tcp rexmt time out %x\n", tp->t_conv);
   	if (++tp->t_rxtshift > TCP_MAXRXTSHIFT) {
	   	tp->t_rxtshift = TCP_MAXRXTSHIFT;
	   	tp->t_state = TCPS_CLOSED;
	   	TCPSTAT_INC(tcps_timeoutdrop);
	   	sorwakeup(tp);
	   	sowwakeup(tp);
	   	soisdisconnected(tp);
		tcp_close(tp);
		return;
   	}

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
   	tp->t_flags |= TF_ACKNOW;
   	tp->t_rtttime = 0;

	cc_cong_signal(tp, NULL, CC_RTO);
   	(void)tcp_output(tp);

	return;
}

static void tcp_keep_timo(void *up)
{
   	struct tcpcb *tp;

	tp = (struct tcpcb *)up;
   	tcpstat.tcps_keeptimeo++;
   	if (tp->t_state < TCPS_ESTABLISHED)
	   	goto dropit;
   	if (tp->t_state <= TCPS_CLOSING) {
		if (ticks - tp->t_rcvtime >= TP_KEEPIDLE(tp) + TP_MAXIDLE(tp))
			goto dropit;
		TCPSTAT_INC(tcps_keepprobe);
	   	/* tcp_respond */

		struct tcphdr th = {0};
		th.th_ack = htonl(tp->rcv_nxt);
		th.th_seq = htonl(tp->snd_una);
		th.th_tsval = htonl(tcp_snd_getticks);
		th.th_tsecr = htonl(tp->ts_recent);

		tcp_respond(tp, &th, 0, 0);
		tx_timer_reset(&tp->t_timer_keep, TP_KEEPINTVL(tp));
   	} else
		tx_timer_reset(&tp->t_timer_keep, TP_KEEPIDLE(tp));
	return;

dropit:
   	tcpstat.tcps_keepdrops++;
   	tp->t_state = TCPS_CLOSED;
	soisdisconnected(tp);

	return;
}

static void tcp_do_delack(void *uup)
{
	struct tcpcb *tp;

	tp = (struct tcpcb *)uup;

	tp->t_flags |= TF_ACKNOW;
	tcpstat.tcps_delack++;
	(void)tcp_output(tp);

	return;
}

static void tcp_output_wrap(void *uup)
{
	struct tcpcb *tp;
	tp = (struct tcpcb *)uup;
	(void)tcp_output(tp);
	return;
}

void
tcp_timer_activate(struct tcpcb *tp, int timer_type, u_int delta)
{
	struct tx_timer_t *t_callout;

	switch (timer_type) {
		case TT_DELACK:
			t_callout = &tp->t_timer_delack;
			break;
		case TT_REXMT:
			t_callout = &tp->t_timer_rexmt;
			break;
		case TT_PERSIST:
			t_callout = &tp->t_timer_persist;
			break;
		case TT_KEEP:
			t_callout = &tp->t_timer_keep;
			break;
		case TT_2MSL:
			t_callout = &tp->t_timer_2msl;
			break;
		default:
			/* static char _type[] = "bad timer_type"; */
			UTXPL_ASSERT(0);
			return;
	}

	if (delta == 0) {
		tx_timer_stop(t_callout);
	} else {
		tx_timer_reset(t_callout, delta);
	}

	return;
}

int
tcp_timer_active(struct tcpcb *tp, int timer_type)
{
	struct tx_timer_t *t_callout;

	switch (timer_type) {
		case TT_DELACK:
			t_callout = &tp->t_timer_delack;
			break;
		case TT_REXMT:
			t_callout = &tp->t_timer_rexmt;
			break;
		case TT_PERSIST:
			t_callout = &tp->t_timer_persist;
			break;
		case TT_KEEP:
			t_callout = &tp->t_timer_keep;
			break;
		case TT_2MSL:
			t_callout = &tp->t_timer_2msl;
			break;
		default:
			TCP_DEBUG_TRACE(1, "bad timer_type");
			return -1;
	}

	return !tx_timer_idle(t_callout);
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

}

static tx_task_q _delack_queue;
static struct tx_task_t _iss_task;
static struct tx_timer_t _iss_timer;

static struct tx_task_t _delack_task;
static struct tx_timer_t _delack_timer;

void tcp_cancel_devbusy(struct tcpcb *tp)
{
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
	tx_task_wakeup(&_delack_queue);
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
