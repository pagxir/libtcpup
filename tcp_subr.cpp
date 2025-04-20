#include <stdlib.h>

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

int tcp_maxpersistidle = TCPTV_KEEP_IDLE;

u_short utx_ntohs(u_short v)
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
	return (v << 8) | (v >> 8);
#else
	return v;
#endif
}

u_long utx_ntohl(u_long v)
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
	u_short vl = v;
	u_short vh = (v >> 16);

	u_short vh1 = (vh << 8) | (vh >> 8);
	u_short vl1 = (vl << 8) | (vl >> 8);

	return vh1 | (vl1 << 16);
#else
	return v;
#endif
}

int get_device_mtu();

struct tcpcb * tcp_newtcpcb(sockcb_t so)
{
	struct tcpcb *tp;
	tp = (struct tcpcb *) calloc(1, sizeof(*tp));
	so->priv.tcp = tp;
	tp->tp_socket = so;
	tp->tp_tag    = 0xEFED;

	tp->t_state = TCPS_CLOSED;
	tp->t_srtt  = TCPTV_SRTTBASE;
	tp->t_rxtcur = TCPTV_RTOBASE;
	tp->t_rttvar = ((TCPTV_RTOBASE - TCPTV_SRTTBASE) << TCP_RTTVAR_SHIFT) / 4;
	tp->t_flags = 0;
	tp->t_maxseg = TCP_MSS;
	tp->t_maxseg = get_device_mtu() - sizeof(struct tcphdr);
	tp->t_max_payload = tp->t_maxseg + 10;

	TCP_DEBUG(1, "tp->t_maxseg = %u\n", tp->t_maxseg);
	tp->snd_max_space = (8 * 1024 * 1024);
	tp->rgn_snd = rgn_create(1024 * 1024);
	tp->rcv_max_space = (2 * 1024 * 1024);
	tp->rgn_rcv = rgn_create(256 * 1024);
	tp->snd_wnd = tp->t_maxseg;

	tp->snd_cwnd = rgn_size(tp->rgn_snd);
	tp->snd_ssthresh = tp->snd_max_space;
	tp->t_rcvtime = ticks;

	tp->lost = 0;
	tp->delivered = 0;
	tp->delivered_mstamp = ticks;
	tp->pacing_rate = 0; // (1 << 20) * 3;

	tp->t_rttmin  = tcp_rexmit_min;
	tp->ts_recent = 0;
	tp->ts_offset = 0;
	tp->ts_recent_age = 0;

	tp->w_event = NULL;
	tp->r_event = NULL;

	tp->t_rttupdated = 0;
	tp->t_keepidle  = 1200 * hz;
	tp->t_keepintvl = 0;

	tp->relay_len = 0;

	tp->osd = (struct osd *)malloc(sizeof(*tp->osd));
	tcp_setuptimers(tp);

	tp->ccv = (struct cc_var *)tp->cc_mem;
	memset(tp->ccv, 0, sizeof(struct cc_var));
	tp->ccv->tcp = tp;
	TAILQ_INIT(&tp->snd_holes);
	TAILQ_INIT(&tp->txsegi_xmt_q);
	TAILQ_INIT(&tp->txsegi_rexmt_q);
	if (CC_ALGO(tp)->cb_init != NULL)
		CC_ALGO(tp)->cb_init(tp->ccv);

	return tp;
}

/*
 * Attempt to close a TCP control block, marking it as dropped, and freeing
 * the socket if we hold the only reference.
 */
struct tcpcb *
tcp_close(struct tcpcb *tp)
{
	sockcb_t so;

	so = tp->tp_socket;
	soisdisconnected(so);

	/* in_pcbdrop(inp); */
	tp->t_state = TCPS_CLOSED;
	if (tp->t_flags & TF_SOCKREF) {
		tp->t_flags &= ~TF_SOCKREF;
		so->so_state &= ~SS_PROTOREF;
		sofree(so);
		return (NULL);
	}

	return (tp);
}

/*
 * A subroutine which makes it easy to track TCP state changes with DTrace.
 * This function shouldn't be called for t_state initializations that don't
 * correspond to actual TCP state transitions.
 */
void
tcp_state_change(struct tcpcb *tp, int newstate)
{
	tp->t_state = newstate;
}
