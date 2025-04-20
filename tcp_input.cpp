#include <unistd.h>

#define TCPUP_LAYER 1
#include <utx/utxpl.h>
#include <utx/queue.h>
#include <utx/sobuf.h>
#include <utx/socket.h>

#include <tcpup/cc.h>
#include <tcpup/tcp.h>
#include <tcpup/tcp_seq.h>
#include <tcpup/tcp_var.h>
#include <tcpup/tcp_fsm.h>
#include <tcpup/tcp_timer.h>
#include <tcpup/tcp_debug.h>

#include "tcp_filter.h"
#include "client_track.h"

#define DELAY_ACK(tp) (!tcp_timer_active(tp, TT_DELACK))

int tcp_iss = 0;
struct tcpcb *tcp_drop(struct tcpcb *tp, int resean);
struct tcpcb *tcp_close(struct tcpcb *tp);

VNET_DEFINE(int, tcp_abc_l_var) = 2;
VNET_DEFINE(int, tcp_do_rfc3390) = 1;
const int tcprexmtthresh = 3;

static void tcp_xmit_timer(struct tcpcb *tp, int rtt);

#if 0
static void tcp_newreno_partial_ack(struct tcpcb *tp, struct tcphdr *th);
#endif
/*
 *  * Wrapper for the TCP established input helper hook.
 *   */
static void inline
hhook_run_tcp_est_in(struct tcpcb *tp, struct tcphdr *th, struct tcpopt *to)
{
    struct tcp_hhook_data hhook_data;

    hhook_data.tp = tp;
    hhook_data.th = th;
    hhook_data.to = to;

    tcp_filter_in(&hhook_data);
}

static void inline
cc_ack_received(struct tcpcb *tp, struct tcphdr *th, uint16_t type)
{
	tp->ccv->bytes_this_ack = BYTES_THIS_ACK(tp, th);
	if (tp->snd_cwnd == min(tp->snd_cwnd, tp->snd_wnd))
		tp->ccv->flags |= CCF_CWND_LIMITED;
	else {
		tp->ccv->flags &= ~CCF_CWND_LIMITED;
	}
	
	if (type == CC_ACK) {
		if (tp->snd_cwnd > tp->snd_ssthresh) {
			tp->t_bytes_acked += min(tp->ccv->bytes_this_ack,
				V_tcp_abc_l_var * (int)tp->t_maxseg);
			if (tp->t_bytes_acked >= (int)tp->snd_cwnd) {
				tp->t_bytes_acked -= tp->snd_cwnd;
				tp->ccv->flags |= CCF_ABC_SENTAWND;
			}
		} else {
			tp->ccv->flags &= ~CCF_ABC_SENTAWND;
			tp->t_bytes_acked = 0;
		}
	}

	tp->ccv->curack = th->th_ack;
    if (CC_ALGO(tp)->ack_received != NULL)
        CC_ALGO(tp)->ack_received(tp->ccv, type);

}

static void inline
cc_conn_init(struct tcpcb *tp)
{
#if 0
	struct hc_metrics_lite metrics;
	struct inpcb *inp = tp->t_inpcb;
	int rtt;

	INP_WLOCK_ASSERT(tp->t_inpcb);

	tcp_hc_get(&inp->inp_inc, &metrics);

	if (tp->t_srtt == 0 && (rtt = metrics.rmx_rtt)) {
		tp->t_srtt = rtt;
		tp->t_rttbest = tp->t_srtt + TCP_RTT_SCALE;
		TCPSTAT_INC(tcps_usedrtt);
		if (metrics.rmx_rttvar) {
			tp->t_rttvar = metrics.rmx_rttvar;
			TCPSTAT_INC(tcps_usedrttvar);
		} else {
			/* default variation is +- 1 rtt */
			tp->t_rttvar =
			    tp->t_srtt * TCP_RTTVAR_SCALE / TCP_RTT_SCALE;
		}
		TCPT_RANGESET(tp->t_rxtcur,
		    ((tp->t_srtt >> 2) + tp->t_rttvar) >> 1,
		    tp->t_rttmin, TCPTV_REXMTMAX);
	}
	if (metrics.rmx_ssthresh) {
		/*
		 * There's some sort of gateway or interface
		 * buffer limit on the path.  Use this to set
		 * the slow start threshhold, but set the
		 * threshold to no less than 2*mss.
		 */
		tp->snd_ssthresh = max(2 * tp->t_maxseg, metrics.rmx_ssthresh);
		TCPSTAT_INC(tcps_usedssthresh);
	}
#endif

	/*
	 * Set the initial slow-start flight size.
	 *
	 * RFC3390 says only do this if SYN or SYN/ACK didn't got lost.
	 * XXX: We currently check only in syncache_socket for that.
	 */
	if (V_tcp_do_rfc3390)
		tp->snd_cwnd = min(4 * tp->t_maxseg,
		    max(2 * tp->t_maxseg, 4380));
	else
		tp->snd_cwnd = tp->t_maxseg;

    if (CC_ALGO(tp)->conn_init != NULL)
        CC_ALGO(tp)->conn_init(tp->ccv);
}

void 
cc_cong_signal(struct tcpcb *tp, struct tcphdr *th, uint32_t type)
{
	switch (type) {
		case CC_NDUPACK:
			if (!IN_FASTRECOVERY(tp->t_flags)) {
				tp->snd_recover = tp->snd_max;
				tp->ts_recover = ticks;
				tp->t_flags |= TF_ECN_SND_CWR;
			}
			break;

		case CC_ECN:
			if (!IN_CONGRECOVERY(tp->t_flags)) {
				TCPSTAT_INC(tcps_ecn_rcwnd);
				tp->snd_recover = tp->snd_max;
				tp->ts_recover = ticks;
				tp->t_flags |= TF_ECN_SND_CWR;
			}
			break;

		case CC_RTO:
			tp->t_dupacks = 0;
			tp->t_bytes_acked = 0;
			EXIT_RECOVERY(tp->t_flags);
			tp->snd_ssthresh = max(2, min(tp->snd_wnd, tp->snd_cwnd) / 2 /
					tp->t_maxseg) * tp->t_maxseg;
			tp->snd_cwnd = tp->t_maxseg;
			break;

		case CC_RTO_ERR:
			TCPSTAT_INC(tcps_sndrexmitbad);
			/* RTO was unnecessary, so reset everything. */
			tp->snd_cwnd = tp->snd_cwnd_prev;
			tp->snd_ssthresh = tp->snd_ssthresh_prev;
			tp->snd_recover = tp->snd_recover_prev;
			tp->ts_recover = ticks;
			if (tp->t_flags & TF_WASFRECOVERY)
				ENTER_FASTRECOVERY(tp->t_flags);
			if (tp->t_flags & TF_WASCRECOVERY)
				ENTER_CONGRECOVERY(tp->t_flags);
			tp->snd_nxt = tp->snd_max;
			tp->t_flags &= ~TF_PREVVALID;
			tp->t_badrxtwin = 0;
			break;
	}

    if (CC_ALGO(tp)->cong_signal != NULL) {
		if (th != NULL)
			tp->ccv->curack = th->th_ack;
        CC_ALGO(tp)->cong_signal(tp->ccv, type);
	}
}

static void inline
cc_post_recovery(struct tcpcb *tp, struct tcphdr *th)
{
	tp->t_flags &= ~TF_SIGNATURE;
    if (CC_ALGO(tp)->post_recovery != NULL) {
		tp->ccv->curack = th->th_ack;
        CC_ALGO(tp)->post_recovery(tp->ccv);
	}
	/* XXXLAS: EXIT_RECOVERY ? */
	tp->t_bytes_acked = 0;
}

/*
 * Parse TCP options and place in tcpopt.
 */
static int
tcp_dooptions(struct tcpopt *to, u_char *cp, int cnt, int flags)
{
	static char _null_[] = {0};
	int opt, optlen, oldcnt = cnt;
	to->to_flags = 0;

	for (; cnt > 0; cnt -= optlen, cp += optlen) {
		opt = cp[0];
		if (opt == TCPOPT_EOL)
			break;
		if (opt == TCPOPT_NOP)
			optlen = 1;
		else {
			if (cnt < 2)
				break;
			optlen = cp[1];
			if (optlen < 2 || optlen > cnt)
				break;
		}
		switch (opt) {
			case TCPOPT_MAXSEG:
				if (optlen != TCPOLEN_MAXSEG)
					continue;
				if (!(flags & TO_SYN))
					continue;
				to->to_flags |= TOF_MSS;
				bcopy((char *)cp + 2,
						(char *)&to->to_mss, sizeof(to->to_mss));
				to->to_mss = ntohs(to->to_mss);
				break;
#if 0
			case TCPOPT_WINDOW:
				if (optlen != TCPOLEN_WINDOW)
					continue;
				if (!(flags & TO_SYN))
					continue;
				to->to_flags |= TOF_SCALE;
				to->to_wscale = min(cp[2], TCP_MAX_WINSHIFT);
				break;
#endif
			case TCPOPT_TIMESTAMP:
				if (optlen != TCPOLEN_TIMESTAMP)
					continue;
				to->to_flags |= TOF_TS;
				bcopy((char *)cp + 2,
						(char *)&to->to_tsval, sizeof(to->to_tsval));
				to->to_tsval = ntohl(to->to_tsval);
				bcopy((char *)cp + 6,
						(char *)&to->to_tsecr, sizeof(to->to_tsecr));
				to->to_tsecr = ntohl(to->to_tsecr);
				break;
#if 1
			case TCPOPT_SACK_PERMITTED:
				if (optlen != TCPOLEN_SACK_PERMITTED)
					continue;
				if (!(flags & TO_SYN))
					continue;
				to->to_flags |= TOF_SACKPERM;
				break;
#endif
            case TCPOPT_DESTINATION:
                if (optlen <= 2 || (optlen - 2) < 4)
                    continue;
                if (!(flags & TO_SYN))
                    continue;
                to->to_flags |= TOF_DESTINATION;
                to->to_dslen = (optlen - 2);
                to->to_dsaddr = cp + 2;
                break;
			case TCPOPT_SACK:
				if (optlen <= 2 || (optlen - 2) % TCPOLEN_SACK != 0)
					continue;
				if (flags & TO_SYN)
					continue;
				to->to_flags |= TOF_SACK;
				to->to_nsacks = (optlen - 2) / TCPOLEN_SACK;
				to->to_sacks = cp + 2;
				TCPSTAT_INC(tcps_sack_rcv_blocks);
				break;
			default:
				continue;
		}
	}

	return sizeof(tcphdr) + oldcnt;
}

void tcp_input(sockcb_t so, struct tcpcb *tp, int dst,
		const char *buf, size_t len, const struct tcpup_addr *from)
{
	int tlen;
	int thflags;
	int orig_len;
	int todrop, acked;
	int needoutput = 0;
	int ourfinisacked = 0;
	struct tcphdr *th, mth;
	const char *dat = NULL;
	u_long tiwin;
	struct tcpopt to;
	struct tcpcb tcb = {0};

	th = (struct tcphdr *)&mth;
	TCPSTAT_INC(tcps_rcvtotal);
	if (len < sizeof(*th)) {
		TCP_DEBUG(len < sizeof(*th), "incorrect paket %d\n", len);
		return;
	}

	memcpy(&mth, buf, sizeof(mth));
	th->th_seq = ntohl(th->th_seq);
	th->th_ack = ntohl(th->th_ack);
	th->th_win = ntohs(th->th_win);


	/* STAR HERE */
	thflags = th->th_flags;
	tp->sackhint.last_sack_ack = 0;
	TCP_TRACE_CHECK(tp, thflags & TH_FIN, "receive FIN: %x\n", so->so_conv);

	/*
	 * Segment received on connection.
	 * Reset idle time and keep-alive timer.
	 * XXX: This should be done after segment
	 * validation to ignore broken/spoofed segs.
	 */
	tp->t_rcvtime = ticks;
	if (TCPS_HAVEESTABLISHED(tp->t_state)) {
		if (tp->t_flags & TF_REC_ADDR) {
			tcp_timer_activate(tp, TT_KEEP, TP_KEEPIDLE(tp));
		} else if (tp->snd_max == tp->snd_una &&
				(len > sizeof(*th) + (th->th_opten << 2))) {
			tcp_timer_activate(tp, TT_KEEP, TP_KEEPINTVL(tp));
		} else {
			tcp_timer_activate(tp, TT_KEEP, TP_KEEPIDLE(tp));
		}
	}

	/*
	 * Unscale the window into a 32-bit value.
	 * For the SYN_SENT state the scale is zero.
	 */
	tiwin = th->th_win << WINDOW_SCALE; /* tp->snd_scale; */
	TCP_TRACE_CHECK(tp, tiwin < 2 * tp->t_maxseg, "small window  %ld\n", tiwin);
	TCP_TRACE_CHECK(tp, (tp->t_state > TCPS_ESTABLISHED), "after fin: %x %x %x\n", th->th_seq, th->th_ack, tp->snd_max);

	/*
	 * Parse options on any incoming segment.
	 */
	int hdrlen = tcp_dooptions(&to, (u_char *)(buf + sizeof(mth)),
			th->th_opten << 2, (thflags & TH_SYN) ? TO_SYN : 0);
	if (len < hdrlen) {
		TCP_DEBUG(len < hdrlen, "incorrect paket %d %d\n", len, hdrlen);
		return;
	}
	tlen = len - hdrlen;
	dat  = buf + hdrlen;

	orig_len = tlen;
	/*
	 * If echoed timestamp is later than the current time,
	 * fall back to non RFC1323 RTT calculation.  Normalize
	 * timestamp if syncookies were used when this connection
	 * was established.
	 */
	if (to.to_tsecr != 0) {
		to.to_tsecr -= tp->ts_offset;
		if (TSTMP_GT(to.to_tsecr, tcp_ts_getticks()))
			to.to_tsecr = 0;
	}

	if (tp->t_state == TCPS_SYN_SENT && (thflags & TH_SYN)) {
		tp->snd_wnd = tiwin;

		if (to.to_flags & TOF_TS) {
			tp->ts_recent = to.to_tsval;
			tp->ts_recent_age = tcp_ts_getticks();
		}

		if ((to.to_flags & TOF_MSS) &&
				to.to_mss >= 512 && to.to_mss < tp->t_maxseg) {
			TCP_TRACE_AWAYS(tp, "%x update mss from peer\n", so->so_conv);
			tp->t_max_payload = to.to_mss;
			tp->t_maxseg = to.to_mss - 10;
		}
	}

	if ((tp->t_flags & TF_REC_ADDR) &&
			(!(to.to_flags & TOF_TS) || TSTMP_GEQ(to.to_tsval, tp->ts_recent))
			&& memcmp(&tp->dst_addr, from, sizeof(*from))) {
		TCP_TRACE_AWAYS(tp, "update dst_addr\n");
		if (memcmp(&tp->sav_addr, from, sizeof(*from))) {
			client_track_update(th->th_conv, from, sizeof(*from), ticks);
			needoutput = 1;
		}
		tp->sav_addr = tp->dst_addr;
		tp->dst_addr = *from;
	}

	if (tp->t_state == TCPS_ESTABLISHED &&
			th->th_seq == tp->rcv_nxt &&
            ((tp->t_flags & (TF_NEEDSYN|TF_NEEDFIN)) == 0) &&
			(thflags & (TH_SYN | TH_FIN | TH_RST | TH_ACK)) == TH_ACK &&
			tp->snd_nxt == tp->snd_max &&
			tiwin && tiwin == tp->snd_wnd &&
			rgn_frgcnt(tp->rgn_rcv) == 0 &&
			(!(to.to_flags & TOF_TS) || TSTMP_GEQ(to.to_tsval, tp->ts_recent))) {

		/*
		 * If last ACK falls within this segment's sequence numbers,
		 * record the timestamp.
		 * NOTE that the test is modified according to the latest
		 * proposal of the tcplw@cray.com list (Braden 1993/04/26).
		 */
		if (SEQ_LEQ(th->th_seq, tp->last_ack_sent) && (to.to_flags & TOF_TS)) {
			tp->ts_recent_age = tcp_ts_getticks();
			tp->ts_recent = to.to_tsval;
		}

		if (tlen == 0) {
			if (SEQ_GT(th->th_ack, tp->snd_una) &&
					SEQ_LEQ(th->th_ack, tp->snd_max) &&
					!IN_RECOVERY(tp->t_flags) &&
					(to.to_flags & TOF_SACK) == 0 &&
					TAILQ_EMPTY(&tp->snd_holes)) {
				TCPSTAT_INC(tcps_predack);

				if (tp->t_rxtshift == 1 &&
						tp->t_flags & TF_PREVVALID &&
						(int)(ticks - tp->t_badrxtwin) < 0) {
					cc_cong_signal(tp, th, CC_RTO_ERR);
				}

				/*
				 * Recalculate the transmit timer / rtt.
				 *
				 * Some boxes send broken timestamp replies
				 * during the SYN+ACK phase, ignore
				 * timestamps of 0 or we could calculate a
				 * huge RTT and blow up the retransmit timer.
				 */
				if (to.to_tsecr != 0 && acked > 0) {
					u_int t;
					t = tcp_ts_getticks() - to.to_tsecr;
					tcp_xmit_timer(tp, TCP_TS_TO_TICKS(t) + 1);
				} else if (tp->t_rtttime &&
						SEQ_GT(th->th_ack, tp->t_rtseq)) {
					tcp_xmit_timer(tp, ticks - tp->t_rtttime);
				}

				acked = BYTES_THIS_ACK(tp, th);

				/* Run HHOOK_TCP_ESTABLISHED_IN helper hooks. */
				hhook_run_tcp_est_in(tp, th, &to);

				TCPSTAT_INC(tcps_rcvackpack);
				TCPSTAT_ADD(tcps_rcvackbyte, acked);
				rgn_drop(tp->rgn_snd, acked);
				if (SEQ_GT(tp->snd_una, tp->snd_recover) &&
						SEQ_LEQ(th->th_ack, tp->snd_recover)) {
					tp->snd_recover = th->th_ack - 1;
				        tp->ts_recover = ticks;
				}

				/*
				 * Let the congestion control algorithm update
				 * congestion control related information. This
				 * typically means increasing the congestion
				 * window.
				 */
				cc_ack_received(tp, th, CC_ACK);

				tp->snd_una = th->th_ack;

				/*
				 * Pull snd_wl2 up to prevent seq wrap relative
				 * to th_ack.
				 */
				tp->snd_wl2 = th->th_ack;
				tp->t_dupacks = 0;

				/*
				 * If all outstanding data are acked, stop
				 * retransmit timer, otherwise restart timer
				 * using current (possibly backed-off) value.
				 * If process is waiting for space,
				 * wakeup/selwakeup/signal.  If data
				 * are ready to send, let tcp_output
				 * decide between more output or persist.
				 */
				if (tp->snd_una == tp->snd_max)
					tcp_timer_activate(tp, TT_REXMT, 0);
				else if (!tcp_timer_active(tp, TT_PERSIST))
					tcp_timer_activate(tp, TT_REXMT,
							tp->t_rxtcur);

				sowwakeup(tp);
				if (rgn_len(tp->rgn_snd))
					(void) tcp_output(tp);
				goto check_delack;
			}
		} else if (th->th_ack == tp->snd_una &&
				tlen <= rgn_rest(tp->rgn_rcv)) {
			if (tp->rcv_numsacks)
				tcp_clean_sackreport(tp);
			TCPSTAT_INC(tcps_preddat);
			tp->rcv_nxt += tlen;

			/*
			 * Pull snd_wl1 up to prevent seq wrap relative to
			 * th_seq.
			 */
			tp->snd_wl1 = th->th_seq;

			TCPSTAT_INC(tcps_rcvpack);
			TCPSTAT_ADD(tcps_rcvbyte, tlen);
			rgn_put(tp->rgn_rcv, dat, tlen);

                        if (to.to_tsecr) {
				const int oldsz = rgn_size(tp->rgn_rcv);
				if (TSTMP_GT(to.to_tsecr, tp->rfbuf_ts) &&
						to.to_tsecr - tp->rfbuf_ts < hz) {
					if (tp->rfbuf_cnt > (oldsz / 8 * 6)
							&& oldsz * 2 < tp->rcv_max_space) {
						TCP_TRACE_AWAYS(tp, "expand connection receive space from %d to %d\n", oldsz, oldsz * 2);
						tp->rgn_rcv = rgn_resize(tp->rgn_rcv, oldsz * 2);
					}
					/* Start over with next RTT. */
					tp->rfbuf_ts = 0;
					tp->rfbuf_cnt = 0;
				} else
					tp->rfbuf_cnt += tlen;  /* add up */
                        }

			sorwakeup(tp);
			if (DELAY_ACK(tp) && tp->t_maxseg/2 <= len) {
				tp->t_flags |= TF_DELACK;
			} else {
				tp->t_flags |= TF_ACKNOW;
				tcp_output(tp);
			}
			goto check_delack;
		}
	}

	/*
	 * Calculate amount of space in receive window,
	 * and then do TCP input processing.
	 * Receive window is amount of space in rcv queue,
	 * but not less than advertised window.
	 */
	do {
		int win = rgn_rest(tp->rgn_rcv);
		if (win < 0) win = 0;
		tp->rcv_wnd = max(win, (int) (tp->rcv_adv - tp->rcv_nxt));
	} while ( 0 );

        /* Reset receive buffer auto scaling when not in bulk receive mode. */
        tp->rfbuf_ts = 0;
        tp->rfbuf_cnt = 0;

	/* Reset receive buffer auto scaling when not in bulk receive mode. */
	switch (tp->t_state) {
		case TCPS_LISTEN:
			if (thflags & TH_RST) {
				TCP_TRACE_AWAYS(tp, "drop %x\n", so->so_conv);
				goto drop;
			}

			if (thflags & TH_ACK) {
				TCP_TRACE_AWAYS(tp, "send reset\n");
				goto dropwithreset;
			}

			if ((thflags & TH_SYN) == 0) {
				TCP_TRACE_AWAYS(tp, "drop %x\n", so->so_conv);
				goto drop;
			}

			tp->iss = tcp_iss;
			tcp_iss += TCP_ISSINCR / 2;
			tp->irs = th->th_seq;
			tp->t_flags |= TF_ACKNOW;
			tp->t_state = TCPS_SYN_RECEIVED;
			TCP_TRACE_START(tp, "TCPS_LISTEN -> TCPS_SYN_RECEIVED\n");
			soisconnected(so); // tcp fast open feature

			if ((to.to_flags & TOF_MSS) &&
					to.to_mss >= 512 && to.to_mss < tp->t_maxseg) {
				TCP_TRACE_AWAYS(tp, "%x update mss from peer\n", so->so_conv);
				tp->t_maxseg = to.to_mss - 10;
				tp->t_max_payload = to.to_mss;
			}

			if (to.to_flags & TOF_TS) {
				tp->ts_recent = to.to_tsval;
				tp->ts_recent_age = tcp_ts_getticks();
			}

			if ((to.to_flags & TOF_DESTINATION) &&
					to.to_dslen >= 4 && to.to_dslen < 60) {
				TCP_TRACE_AWAYS(tp, "%x update relay from peer\n", so->so_conv);
				memcpy(tp->relay_target, to.to_dsaddr, to.to_dslen);
				tp->relay_len = to.to_dslen;
			}

			tcp_timer_activate(tp, TT_KEEP, TCPTV_KEEP_INIT);
			tcp_rcvseqinit(tp);
			tcp_sendseqinit(tp);
			client_track_update(th->th_conv, from, sizeof(*from), ticks);
			tp->dst_addr = *from;
			tp->t_flags |= TF_REC_ADDR;
			TCPSTAT_INC(tcps_accepts);
			goto trimthenstep6;


        /*
         * If the state is SYN_RECEIVED:
         *      if seg contains an ACK, but not for our SYN/ACK, send a RST.
         */
        case TCPS_SYN_RECEIVED:
			if ((thflags & TH_ACK) &&
					(SEQ_LEQ(th->th_ack, tp->snd_una) ||
					 SEQ_GT(th->th_ack, tp->snd_max))) {
				/* rstreason = BANDLIM_RST_OPENPORT; */
				TCP_TRACE_AWAYS(tp, "send reset on syn receive\n");
				goto dropwithreset;
			}
			soisconnected(so); // tcp fast open feature
			break;

        /*
         * If the state is SYN_SENT:
         *      if seg contains an ACK, but not for our SYN, drop the input.
         *      if seg contains a RST, then drop the connection.
         *      if seg does not contain SYN, then drop it.
         * Otherwise this is an acceptable SYN segment
         *      initialize tp->rcv_nxt and tp->irs
         *      if seg contains ack then advance tp->snd_una
         *      if seg contains an ECE and ECN support is enabled, the stream
         *          is ECN capable.
         *      if SYN has been acked change to ESTABLISHED else SYN_RCVD state
         *      arrange for segment to be acked (eventually)
         *      continue processing rest of data/controls, beginning with URG
         */
		case TCPS_SYN_SENT:
			if ((thflags & TH_ACK) &&
					(SEQ_LEQ(th->th_ack, tp->iss) ||
					 SEQ_GT(th->th_ack, tp->snd_max))) {
				TCP_TRACE_AWAYS(tp, "error iss %x ack %x L4 max %x\n",
						tp->iss, th->th_ack, tp->snd_max);
				goto dropwithreset;
			}

			if ((thflags & (TH_RST| TH_ACK)) == (TH_RST| TH_ACK)) {
				TCP_TRACE_AWAYS(tp, "error iss %x ack %x L3 max %x\n",
						tp->iss, th->th_ack, tp->snd_max);
				tp = tcp_drop(tp, UTXECONNREFUSED);
			}

			if (thflags & TH_RST) {
				TCP_TRACE_AWAYS(tp, "error iss %x ack %x L2 max %x drop\n",
						tp->iss, th->th_ack, tp->snd_max);
				goto drop;
			}
			
			if ((thflags & TH_SYN) == 0) {
				TCP_TRACE_AWAYS(tp, "error iss %x ack %x L1 max %x drop\n",
						tp->iss, th->th_ack, tp->snd_max);
				goto drop;
			}

			tp->irs = th->th_seq;
			tcp_rcvseqinit(tp);

			if (thflags & TH_ACK) {
				TCPSTAT_INC(tcps_connects);
				soisconnected(so);

				/* Do window scaling on this connection? */
				tp->rcv_adv += min(tp->rcv_wnd,
						TCP_MAXWIN << WINDOW_SCALE);
				tp->snd_una++;          /* SYN is acked */
				if (tp->snd_una == tp->snd_max)
					tcp_timer_activate(tp, TT_REXMT, 0);

				/*
				 * If there's data, delay ACK; if there's also a FIN
				 * ACKNOW will be turned on later.
				 */
				if (DELAY_ACK(tp) && tlen != 0)
					tcp_timer_activate(tp, TT_DELACK, tcp_delacktime);
				else
					tp->t_flags |= TF_ACKNOW;

				/*
				 * Received <SYN,ACK> in SYN_SENT[*] state.
				 * Transitions:
				 *      SYN_SENT  --> ESTABLISHED
				 *      SYN_SENT* --> FIN_WAIT_1
				 */

				tp->t_starttime = ticks;
				if (to.to_tsecr != 0) {
					u_int t = tcp_ts_getticks() - to.to_tsecr;
					tcp_xmit_timer(tp, TCP_TS_TO_TICKS(t) + 1);
				} else if (tp->t_rtttime &&
						SEQ_GT(th->th_ack, tp->t_rtseq)) {
					tcp_xmit_timer(tp, ticks - tp->t_rtttime);
				}

				if (tp->t_flags & TF_NEEDFIN) {
					TCP_TRACE_START(tp, "TCPS_SYN_SENT -> TCPS_FIN_WAIT_1\n");
					tcp_state_change(tp, TCPS_FIN_WAIT_1);
					tp->t_flags &= ~TF_NEEDFIN;
					thflags &= ~TH_SYN;
				} else {
					TCP_TRACE_START(tp, "TCPS_SYN_SENT -> TCPS_ESTABLISHED\n");
					tcp_state_change(tp, TCPS_ESTABLISHED);

					cc_conn_init(tp);
					tcp_timer_activate(tp, TT_KEEP,
							TP_KEEPIDLE(tp));
				}

				sowwakeup(tp);
			} else {
				/*
				 * Received initial SYN in SYN-SENT[*] state =>
				 * simultaneous open.  If segment contains CC option
				 * and there is a cached CC, apply TAO test.
				 * If it succeeds, connection is * half-synchronized.
				 * Otherwise, do 3-way handshake:
				 *        SYN-SENT -> SYN-RECEIVED
				 *        SYN-SENT* -> SYN-RECEIVED*
				 * If there was no CC option, clear cached CC value.
				 */
				tp->t_flags |= TF_ACKNOW;
				tcp_timer_activate(tp, TT_REXMT, 0);
				tp->t_state = TCPS_SYN_RECEIVED;
			}

trimthenstep6:
			th->th_seq++;
			if ((size_t)tlen > tp->rcv_wnd) {
				todrop = tlen - tp->rcv_wnd;
				tlen = (short)tp->rcv_wnd;
				TCP_TRACE_CHECK(tp, thflags & TH_FIN, "drop TH_FIN packet\n");
				thflags &= ~TH_FIN;
				TCPSTAT_INC(tcps_rcvpackafterwin);
				TCPSTAT_ADD(tcps_rcvbyteafterwin, todrop);
			}
			tp->snd_wl1 = th->th_seq  - 1;

			/*
			 * Client side of transaction: already sent SYN and data.
			 * If the remote host used T/TCP to validate the SYN,
			 * our data will be ACK'd; if so, enter normal data segment
			 * processing in the middle of step 5, ack processing.
			 * Otherwise, goto step 6.
			 */
			if (thflags & TH_ACK)
				goto process_ACK;

			goto step6;
			/*
			 * If the state is LAST_ACK or CLOSING or TIME_WAIT:
			 *      do normal processing.
			 *
			 * NB: Leftover from RFC1644 T/TCP.  Cases to be reused later.
			 */
		case TCPS_LAST_ACK:
		case TCPS_CLOSING:
			break;  /* continue normal processing */
        }

        /*
         * States other than LISTEN or SYN_SENT.
         * First check the RST flag and sequence number since reset segments
         * are exempt from the timestamp and connection count tests.  This
         * fixes a bug introduced by the Stevens, vol. 2, p. 960 bugfix
         * below which allowed reset segments in half the sequence space
         * to fall though and be processed (which gives forged reset
         * segments with a random sequence number a 50 percent chance of
         * killing a connection).
         * Then check timestamp, if present.
         * Then check the connection count, if present.
         * Then check that at least some bytes of segment are within
         * receive window.  If segment begins before rcv_nxt,
         * drop leading data (and SYN); if nothing left, just ack.
         *
         *
         * If the RST bit is set, check the sequence number to see
         * if this is a valid reset segment.
         * RFC 793 page 37:
         *   In all states except SYN-SENT, all reset (RST) segments
         *   are validated by checking their SEQ-fields.  A reset is
         *   valid if its sequence number is in the window.
         * Note: this does not take into account delayed ACKs, so
         *   we should test against last_ack_sent instead of rcv_nxt.
         *   The sequence number in the reset segment is normally an
         *   echo of our outgoing acknowlegement numbers, but some hosts
         *   send a reset with the sequence number at the rightmost edge
         *   of our receive window, and we have to handle this case.
         * Note 2: Paul Watson's paper "Slipping in the Window" has shown
         *   that brute force RST attacks are possible.  To combat this,
         *   we use a much stricter check while in the ESTABLISHED state,
         *   only accepting RSTs where the sequence number is equal to
         *   last_ack_sent.  In all other states (the states in which a
         *   RST is more likely), the more permissive check is used.
         * If we have multiple segments in flight, the initial reset
         * segment sequence numbers will be to the left of last_ack_sent,
         * but they will eventually catch up.
         * In any case, it never made sense to trim reset segments to
         * fit the receive window since RFC 1122 says:
         *   4.2.2.12  RST Segment: RFC-793 Section 3.4
         *
         *    A TCP SHOULD allow a received RST segment to include data.
         *
         *    DISCUSSION
         *         It has been suggested that a RST segment could contain
         *         ASCII text that encoded and explained the cause of the
         *         RST.  No standard has yet been established for such
         *         data.
         *
         * If the reset segment passes the sequence number test examine
         * the state:
         *    SYN_RECEIVED STATE:
         *      If passive open, return to LISTEN state.
         *      If active open, inform user that connection was refused.
         *    ESTABLISHED, FIN_WAIT_1, FIN_WAIT_2, CLOSE_WAIT STATES:
         *      Inform user that connection was reset, and close tcb.
         *    CLOSING, LAST_ACK STATES:
         *      Close the tcb.
         *    TIME_WAIT STATE:
         *      Drop the segment - see Stevens, vol. 2, p. 964 and
         *      RFC 1337.
         */

        if (thflags & TH_RST) {
				TCP_TRACE_AWAYS(tp, "drop since RST %x\n", so->so_conv);
                if (SEQ_GEQ(th->th_seq, tp->last_ack_sent - 1) &&
                    SEQ_LEQ(th->th_seq, tp->last_ack_sent + tp->rcv_wnd)) {
                        switch (tp->t_state) {

							case TCPS_SYN_RECEIVED:
								/* so->so_error = UTXECONNREFUSED; */
								goto close;

							case TCPS_ESTABLISHED:
								if (!(SEQ_GEQ(th->th_seq, tp->rcv_nxt - 1) &&
											SEQ_LEQ(th->th_seq, tp->rcv_nxt + 1)) &&
										!(SEQ_GEQ(th->th_seq, tp->last_ack_sent - 1) &&
											SEQ_LEQ(th->th_seq, tp->last_ack_sent + 1))) {
									/* TCPSTAT_INC(tcps_badrst); */
									TCP_TRACE_AWAYS(tp, "drop %x\n", so->so_conv);
									goto drop;
								}
								/* FALLTHROUGH */
							case TCPS_FIN_WAIT_1:
							case TCPS_FIN_WAIT_2:
							case TCPS_CLOSE_WAIT:
								/* so->so_error = UTXECONNRESET; */
close:
								tp->t_state = TCPS_CLOSED;
								TCPSTAT_INC(tcps_drops);
								TCP_TRACE_AWAYS(tp, "tp = NULL return1\n");
								tcp_close(tp);
								tp = NULL;
								break;

							case TCPS_CLOSING:
							case TCPS_LAST_ACK:
								TCP_TRACE_AWAYS(tp, "tp = NULL return2 \n");
								tcp_close(tp);
								tp = NULL;
								break;
						}
                }
                goto drop;
        }


	/*
	 * RFC 1323 PAWS: If we have a timestamp reply on this segment
	 * and it's less than ts_recent, drop it.
	 */
	if (tp->ts_recent && (to.to_flags & TOF_TS) && TSTMP_LT(to.to_tsval, tp->ts_recent)) {
		/* Check to see if ts_recent is over 24 days old.  */
		if (tcp_ts_getticks() - tp->ts_recent_age > TCP_PAWS_IDLE) {
			/*
			 * Invalidate ts_recent.  If this segment updates
			 * ts_recent, the age will be reset later and ts_recent
			 * will get a valid value.  If it does not, setting
			 * ts_recent to zero will at least satisfy the
			 * requirement that zero be placed in the timestamp
			 * echo reply when ts_recent isn't valid.  The
			 * age isn't reset until we get a valid ts_recent
			 * because we don't want out-of-order segments to be
			 * dropped when ts_recent is old.
			 */
			tp->ts_recent = 0;
		} else {
			TCPSTAT_INC(tcps_rcvduppack);
			TCPSTAT_ADD(tcps_rcvdupbyte, tlen);
			TCPSTAT_INC(tcps_pawsdrop);
			// TCP_TRACE_AWAYS(tp, "drop for time stamp, seq %x %x %x\n", th->th_seq, th->th_ack, tp->rcv_nxt, tp->snd_una);
			if (tlen > 0)
				goto dropafterack;

			if (orig_len == 0 &&
				th->th_seq == tp->rcv_nxt &&
				th->th_ack == tp->snd_una &&
				TSTMP_LT(tp->ts_recent, to.to_tsval + tp->t_rttmin)) {
				// TCP_TRACE_AWAYS(tp, "handle reorder %x\n", so->so_conv);
			} else {
				// TCP_TRACE_AWAYS(tp, "drop %x\n", so->so_conv);
				goto drop;
			}
		}
	}

	/*
	 * In the SYN-RECEIVED state, validate that the packet belongs to
	 * this connection before trimming the data to fit the receive
	 * window.  Check the sequence number versus IRS since we know
	 * the sequence numbers haven't wrapped.  This is a partial fix
	 * for the "LAND" DoS attack.
	 */
	if (tp->t_state == TCPS_SYN_RECEIVED && SEQ_LT(th->th_seq, tp->irs)) {
		/* rstreason = BANDLIM_RST_OPENPORT; */
		TCP_TRACE_AWAYS(tp, "send syn 1\n");
		goto dropwithreset;
	}

	todrop = tp->rcv_nxt - th->th_seq;
	if (todrop > 0) {
		/*
		 * If this is a duplicate SYN for our current connection,
		 * advance over it and pretend and it's not a SYN.
		 */
		if ((thflags & TH_SYN) && th->th_seq == tp->irs) {
			thflags &= ~TH_SYN;
			th->th_seq++;
			todrop--;
		}

		/*
		 * Following if statement from Stevens, vol. 2, p. 960.
		 */
		if (todrop > tlen ||
				(todrop == tlen && (thflags & TH_FIN) == 0)) {
			/*
			 * Any valid FIN must be to the left of the window.
			 * At this point the FIN must be a duplicate or out
			 * of sequence; drop it.
			 */
			TCP_TRACE_CHECK(tp, TH_FIN & thflags, "drop TH_FIN 2 packet\n");
			thflags &= ~TH_FIN;

			/*
			 * Send an ACK to resynchronize and drop any data.
			 * But keep on processing for RST or ACK.
			 */
			tp->t_flags |= TF_ACKNOW;
			todrop = tlen;
			TCPSTAT_INC(tcps_rcvduppack);
			TCPSTAT_ADD(tcps_rcvdupbyte, todrop);
		} else {
			TCPSTAT_INC(tcps_rcvpartduppack);
			TCPSTAT_ADD(tcps_rcvpartdupbyte, todrop);
		}

		th->th_seq += todrop;
		tlen -= todrop;
		dat += todrop;
	}

	/*
	 * If new data are received on a connection after the
	 * user processes are gone, then RST the other end.
	 */
	/* Do not support half open connect. */
	if ((so->so_state & SS_NOFDREF) &&
			tp->t_state > TCPS_CLOSE_WAIT && tlen) {
		size_t namlen = tp->dst_addr.namlen;
		TCP_TRACE_AWAYS(tp, "send syn wait %d %d %x %x\n", tp->t_state, tlen, th->th_seq, tp->rcv_nxt);

		UTXPL_ASSERT(namlen <= sizeof(tcb.dst_addr.name));
		memcpy(tcb.dst_addr.name, tp->dst_addr.name, namlen);
		tcb.dst_addr.namlen = namlen;

		tp = tcp_close(tp);
		TCPSTAT_INC(tcps_rcvafterclose);
		/* rstreason = BANDLIM_UNLIMITED; */
		goto dropwithreset;
	}

	/*
	 * If segment ends after window, drop trailing data
	 * (and PUSH and FIN); if nothing left, just ACK.
	 */
	todrop = (th->th_seq + tlen) - (tp->rcv_nxt + tp->rcv_wnd);
	if (todrop > 0) {
		TCPSTAT_INC(tcps_rcvpackafterwin);
		if (todrop >= tlen) {
			TCPSTAT_ADD(tcps_rcvbyteafterwin, tlen);
			/*
			 * If window is closed can only take segments at
			 * window edge, and have to drop data and PUSH from
			 * incoming segments.  Continue processing, but
			 * remember to ack.  Otherwise, drop segment
			 * and ack.
			 */
			if (tp->rcv_wnd == 0 && th->th_seq == tp->rcv_nxt) {
				tp->t_flags |= TF_ACKNOW;
				TCPSTAT_INC(tcps_rcvwinprobe);
			} else {
				TCP_TRACE_AWAYS(tp, "drop for out of win\n");
				goto dropafterack;
			}
		} else
			TCPSTAT_ADD(tcps_rcvbyteafterwin, todrop);
		tlen -= todrop;
		TCP_TRACE_CHECK(tp, thflags & TH_FIN, "drop TH_FIN for win\n");
		thflags &= ~TH_FIN;
	}

	/*
	 * If last ACK falls within this segment's sequence numbers,
	 * record its timestamp.
	 * NOTE: 
	 * 1) That the test incorporates suggestions from the latest
	 *    proposal of the tcplw@cray.com list (Braden 1993/04/26).
	 * 2) That updating only on newer timestamps interferes with
	 *    our earlier PAWS tests, so this check should be solely
	 *    predicated on the sequence space of this segment.
	 * 3) That we modify the segment boundary check to be 
	 *        Last.ACK.Sent <= SEG.SEQ + SEG.Len  
	 *    instead of RFC1323's
	 *        Last.ACK.Sent < SEG.SEQ + SEG.Len,
	 *    This modified check allows us to overcome RFC1323's
	 *    limitations as described in Stevens TCP/IP Illustrated
	 *    Vol. 2 p.869. In such cases, we can still calculate the
	 *    RTT correctly when RCV.NXT == Last.ACK.Sent.
	 */
	if ((to.to_flags & TOF_TS) && 
			SEQ_LEQ(th->th_seq, tp->last_ack_sent) &&
			SEQ_LEQ(tp->last_ack_sent, th->th_seq + tlen +
				((thflags & (TH_SYN|TH_FIN)) != 0))) {
		tp->ts_recent_age = tcp_ts_getticks();
		tp->ts_recent = to.to_tsval;
	}

	/*
	 * If a SYN is in the window, then this is an
	 * error and we send an RST and drop the connection.
	 */
	if (thflags & TH_SYN) {
		TCP_TRACE_AWAYS(tp, "drop %x\n", so->so_conv);
		tp = tcp_drop(tp, UTXECONNRESET);
		/* rstreason = BANDLIM_UNLIMITED; */
		goto drop;
	}

	/*
	 * If the ACK bit is off:  if in SYN-RECEIVED state or SENDSYN
	 * flag is on (half-synchronized state), then queue data for
	 * later processing; else drop segment and return.
	 */
	if ((thflags & TH_ACK) == 0) {
		if (tp->t_state == TCPS_SYN_RECEIVED)
			goto step6;
		else if (tp->t_flags & TF_ACKNOW)
			goto dropafterack;
		else {
			TCP_TRACE_AWAYS(tp, "drop %x\n", so->so_conv);
			goto drop;
		}
	}

	/*
	 * Ack processing.
	 */

	switch(tp->t_state) {
        /*
         * In SYN_RECEIVED state, the ack ACKs our SYN, so enter
         * ESTABLISHED state and continue processing.
         * The ACK was checked above.
         */
		case TCPS_SYN_RECEIVED:
			TCPSTAT_INC(tcps_connects);
			soisconnected(so);
			tp->snd_wnd = tiwin;

			/*
			 * Make transitions:
			 *      SYN-RECEIVED  -> ESTABLISHED
			 *      SYN-RECEIVED* -> FIN-WAIT-1
			 */
			tp->t_starttime = ticks;
			if (tp->t_flags & TF_NEEDFIN) {
				tcp_state_change(tp, TCPS_FIN_WAIT_1);
				tp->t_flags &= ~TF_NEEDFIN;
			} else {
				tcp_state_change(tp, TCPS_ESTABLISHED);
				cc_conn_init(tp);
				tcp_timer_activate(tp, TT_KEEP, TP_KEEPIDLE(tp));
			}

			if (to.to_tsecr != 0) {
				u_int t = tcp_ts_getticks() - to.to_tsecr;
				tcp_xmit_timer(tp, TCP_TS_TO_TICKS(t) + 1);
			} else if (tp->t_rtttime &&
					SEQ_GT(th->th_ack, tp->t_rtseq)) {
				tcp_xmit_timer(tp, ticks - tp->t_rtttime);
			}

			/*
			 * If segment contains data or ACK, will call tcp_reass()
			 * later; if not, do so now to pass queued data to user.
			 */
			if (tlen == 0 && (thflags & TH_FIN) == 0) {
				/* TODO */
			}
			tp->snd_wl1 = th->th_seq - 1;
			tp->snd_una++; /* Our SYN is Acked T/TCP not suppport yet. */
			if (tp->snd_una == tp->snd_max)
				tcp_timer_activate(tp, TT_REXMT, 0);
			sowwakeup(tp);
			/* FALLTHROUGH */
			TCP_TRACE_START(tp, "TCPS_SYN_RECEIVED -> TCPS_ESTABLISHED\n");
		case TCPS_ESTABLISHED:
		case TCPS_FIN_WAIT_1:
		case TCPS_FIN_WAIT_2:
		case TCPS_CLOSE_WAIT:
		case TCPS_CLOSING:
		case TCPS_LAST_ACK:
		case TCPS_TIME_WAIT:
			if (SEQ_GT(th->th_ack, tp->snd_max)) {
				TCPSTAT_INC(tcps_rcvacktoomuch);
				goto dropafterack;
			}

			if ((to.to_flags & TOF_SACK) ||
				!TAILQ_EMPTY(&tp->snd_holes))
				tcp_sack_doack(tp, &to, th->th_ack);

			/* Run HHOOK_TCP_ESTABLISHED_IN helper hooks. */
			hhook_run_tcp_est_in(tp, th, &to);

			if (SEQ_LEQ(th->th_ack, tp->snd_una)) {
				if (tlen == 0 && tiwin == tp->snd_wnd) {
					TCPSTAT_INC(tcps_rcvduppack);
					if (!tcp_timer_active(tp, TT_REXMT) ||
							th->th_ack != tp->snd_una)
						tp->t_dupacks = 0;
					else if (++tp->t_dupacks > tcprexmtthresh ||
							IN_FASTRECOVERY(tp->t_flags)) {
						cc_ack_received(tp, th, CC_DUPACK);
						if (IN_FASTRECOVERY(tp->t_flags)) {
							int awnd;

							awnd = (tp->snd_nxt - tp->snd_fack) +
								tp->sackhint.sack_bytes_rexmit;
							if (awnd < (int)tp->snd_ssthresh) {
								tp->snd_cwnd += tp->t_maxseg;
								if (tp->snd_cwnd > tp->snd_ssthresh &&
										tp->snd_ssthresh > tp->t_maxseg)
									tp->snd_cwnd = tp->snd_ssthresh;
							}
						} else
							tp->snd_cwnd += tp->t_maxseg;
						if ((thflags & TH_FIN) &&
								(TCPS_HAVERCVDFIN(tp->t_state) == 0)) {
							TCP_TRACE_AWAYS(tp, "drop TH_FIN2 for state");
							(void)tcp_output(tp);
							break;
						}
						(void)tcp_output(tp);
						goto drop;
					} else if (tp->t_dupacks == tcprexmtthresh) {
						tcp_seq onxt = tp->snd_nxt;

						if (IN_FASTRECOVERY(tp->t_flags)) {
							tp->t_dupacks = 0;
							break;
						}

						cc_cong_signal(tp, th, CC_NDUPACK);
						cc_ack_received(tp, th, CC_NDUPACK);
						tcp_timer_activate(tp, TT_REXMT, 0);
						tp->t_rtttime = 0;
						VAR_UNUSED(onxt);

						TCPSTAT_INC(tcps_sack_recovery_episode);

						if (tp->filter_nboard == 0) TCP_DEBUG(1, "filter_nboard not 0");
						tp->sack_newdata = tp->snd_nxt;
						tp->snd_cwnd = tp->t_maxseg;
						(void)tcp_output(tp);

						goto drop;
					} else {
						cc_ack_received(tp, th, CC_DUPACK);

						u_long oldcwnd = tp->snd_cwnd;
						tcp_seq oldsndmax = tp->snd_max;

						u_int sent;
						int avail;

						KASSERT(tp->t_dupacks == 1 ||
							   	tp->t_dupacks == 2,
								("%s: dupacks not 1 or 2", __func__));
						if (tp->t_dupacks == 1)
							tp->snd_limited = 0;

						tp->snd_cwnd = 
							(tp->snd_nxt - tp->snd_una) +
							(tp->t_dupacks - tp->snd_limited) * tp->t_maxseg;

						avail = rgn_len(tp->rgn_snd) - 
							(tp->snd_nxt - tp->snd_una);
						if (avail > 0)
							(void)tcp_output(tp);
						sent = tp->snd_max - oldsndmax;
						if (sent > tp->t_maxseg) {
							tp->snd_limited = 2;
						} else if (sent > 0)
							++tp->snd_limited;
						tp->snd_cwnd = oldcwnd;
						goto drop;
					}
				} else 
					tp->t_dupacks = 0;
				break;
			}

			if (IN_FASTRECOVERY(tp->t_flags)) {
				if (SEQ_LT(th->th_ack, tp->snd_recover)) {
				    tcp_sack_partialack(tp, th, TSTMP_GEQ(to.to_tsecr, tp->ts_recover));
				    if (TSTMP_GEQ(to.to_tsecr, tp->ts_recover)) {
					TCP_TRACE_AWAYS(tp, "slow recovery %x isnew %d\n", so->so_conv, TSTMP_GEQ(to.to_tsecr, tp->ts_recover));
					tp->ts_recover = ticks;
				    }
				} else {
					cc_post_recovery(tp, th);
				}
			}

			tp->t_dupacks = 0;
#if 0
			/*
			 * If we reach this point, ACK is not a duplicate,
			 *     i.e., it ACKs something we sent.
			 */
			if (tp->t_flags & TF_NEEDSYN) {
					/*
					 * T/TCP: Connection was half-synchronized, and our
					 * SYN has been ACK'd (so connection is now fully
					 * synchronized).  Go to non-starred state,
					 * increment snd_una for ACK of SYN, and check if
					 * we can do window scaling.
					 */
					tp->t_flags &= ~TF_NEEDSYN;
					tp->snd_una++;
					assert (tp->snd_una != tp->snd_max);
					/* Do window scaling? */
			}
#endif

process_ACK:
			acked = BYTES_THIS_ACK(tp, th);
			TCPSTAT_INC(tcps_rcvackpack);
			TCPSTAT_ADD(tcps_rcvackbyte, acked);

			if (TSTMP_GT(to.to_tsecr, tp->delivered_mstamp))
				tp->delivered_mstamp = to.to_tsecr;

			if (tp->t_rxtshift == 1 && tp->t_flags & TF_PREVVALID &&
					(int)(ticks - tp->t_badrxtwin) < 0)
				cc_cong_signal(tp, th, CC_RTO_ERR);

			if (to.to_tsecr != 0) {
				u_int t;
				t = tcp_ts_getticks() - to.to_tsecr;
				tcp_xmit_timer(tp, TCP_TS_TO_TICKS(t) + 1);
			} else if (tp->t_rtttime && SEQ_GT(th->th_ack, tp->t_rtseq)) {
				tcp_xmit_timer(tp, ticks - tp->t_rtttime);
			}

			if (th->th_ack == tp->snd_max) {
				tcp_timer_activate(tp, TT_REXMT, 0);
				needoutput = 1;
			} else if (!tcp_timer_active(tp, TT_PERSIST)) {
				tcp_timer_activate(tp, TT_REXMT, tp->t_rxtcur);
				tp->snd_rto = tp->snd_una;
			}

			if (acked == 0)
				goto step6;

			cc_ack_received(tp, th, CC_ACK);

			if (acked > rgn_len(tp->rgn_snd)) {
				tp->snd_wnd -= rgn_len(tp->rgn_snd);
				rgn_clear(tp->rgn_snd);
				ourfinisacked = 1;
			} else {
				rgn_drop(tp->rgn_snd, acked);
				tp->snd_wnd -= acked;
				ourfinisacked = 0;
				/* needoutput = 1; */
			}
			sowwakeup(tp);

			if (!IN_RECOVERY(tp->t_flags) &&
					SEQ_GT(tp->snd_una, tp->snd_recover) &&
					SEQ_LEQ(th->th_ack, tp->snd_recover)) {
				tp->snd_recover = th->th_ack - 1;
				tp->ts_recover = ticks;
			}

			if (IN_RECOVERY(tp->t_flags) &&
				SEQ_GEQ(th->th_ack, tp->snd_recover)) {
			    TCP_DEBUG(1, "leaving recovery %d \n", TAILQ_EMPTY(&tp->snd_holes));
			    EXIT_RECOVERY(tp->t_flags);
			}

			tp->snd_una = th->th_ack;
			if (SEQ_GT(tp->snd_una, tp->snd_recover)) {
				tp->snd_recover = tp->snd_una;
				tp->ts_recover = ticks;
			}

			if (SEQ_LT(tp->snd_nxt, tp->snd_una))
				tp->snd_nxt = tp->snd_una;

			switch (tp->t_state) {
				case TCPS_FIN_WAIT_1:
					if (ourfinisacked) {
						tcp_timer_activate(tp, TT_2MSL, TP_KEEPCNT(tp) * TP_KEEPINTVL(tp));
						tp->t_state = TCPS_FIN_WAIT_2;
						TCP_TRACE_AWAYS(tp, "TCPS_FIN_WAIT_1 -> TCPS_FIN_WAIT_2\n");
						soisdisconnected(so);
					}
					break;

				case TCPS_CLOSING:
					if (ourfinisacked) {
						tp->t_state = TCPS_TIME_WAIT;
						TCP_TRACE_AWAYS(tp, "TCPS_CLOSING -> TCPS_TIME_WAIT\n");
						tcp_canceltimers(tp);
						tcp_timer_activate(tp, TT_2MSL, 2 * TCPTV_MSL);
					}
					break;

				case TCPS_LAST_ACK:
					if (ourfinisacked) {
						TCP_TRACE_AWAYS(tp, "TCPS_LAST_ACK -> TCPS_CLOSED\n");
						tp->t_state = TCPS_CLOSED;
						tcp_close(tp);
						tp = NULL;
						goto drop;
					}
					break;

				case TCPS_TIME_WAIT:
					tcp_timer_activate(tp, TT_2MSL, 2 * TCPTV_MSL);
					tp->rgn_snd = rgn_trim(tp->rgn_snd);
					tp->rgn_rcv = rgn_trim(tp->rgn_rcv);
					goto dropafterack;
					break;
			}
	}

step6:
	if ((thflags & TH_ACK) &&
			(SEQ_LT(tp->snd_wl1, th->th_seq) ||
			 (tp->snd_wl1 == th->th_seq && (SEQ_LT(tp->snd_wl2, th->th_ack) || 
			  (tp->snd_wl2 == th->th_ack && tiwin > tp->snd_wnd))))) {

		if (tlen == 0 &&
				tp->snd_wl2 == th->th_ack && tiwin > tp->snd_wnd)
			TCPSTAT_INC(tcps_rcvwinupd);

		tp->snd_wnd = tiwin;
		tp->snd_wl1 = th->th_seq;
		tp->snd_wl2 = th->th_ack;
		if (tp->snd_wnd > tp->max_sndwnd)
			tp->max_sndwnd = tp->snd_wnd;
		needoutput = 1;
	}

	goto dodata;

dodata:
	if ((tlen || (thflags & TH_FIN)) &&
			TCPS_HAVERCVDFIN(tp->t_state) == 0) {
		tcp_seq	save_start = th->th_seq;

		if (th->th_seq == tp->rcv_nxt &&
				rgn_frgcnt(tp->rgn_rcv) == 0 &&
				TCPS_HAVEESTABLISHED(tp->t_state)) {
			tp->t_flags |= (DELAY_ACK(tp)? TF_DELACK: TF_ACKNOW);
			tp->rcv_nxt += tlen;
			thflags = (th->th_flags & TH_FIN);
			TCPSTAT_INC(tcps_rcvpack);
			TCPSTAT_ADD(tcps_rcvbyte, tlen);
			rgn_put(tp->rgn_rcv, dat, tlen);
			sorwakeup(tp);
		} else {
			if (thflags & TH_FIN) {
				tp->rcv_frs = (th->th_seq + tlen);
				tp->t_flags |= TF_GOTFIN;
			}

			if (tlen > 0) {
				if (SEQ_GT(th->th_seq, tp->rcv_nxt)) {
					int off = (th->th_seq - tp->rcv_nxt);
					rgn_fragment(tp->rgn_rcv, dat, tlen, off);
					thflags = 0;
				} else {
					rgn_put(tp->rgn_rcv, dat, tlen);
					tp->rcv_nxt += rgn_reass(tp->rgn_rcv);
					tp->rcv_nxt += tlen;

					if ((tp->t_flags & TF_GOTFIN)  && 
							(tp->rcv_frs == tp->rcv_nxt)) {
						assert(rgn_frgcnt(tp->rgn_rcv) == 0);
						thflags |= TH_FIN;
					}

					sorwakeup(tp);
				}
			}

			/* thflags = rgn_frgcnt(tp->rgn_rcv)? 0: (thflags & TH_FIN); */

			tp->t_flags |= TF_ACKNOW;
		}

		if (tlen > 0) {
			tcp_update_sack_list(tp, save_start, save_start + tlen);
		}
	} else {
		TCP_TRACE_CHECK(tp, thflags & TH_FIN, "FIN received but drop\n");
		thflags &= ~TH_FIN;
	}

	if (thflags & TH_FIN) {
		TCP_TRACE_AWAYS(tp, "FIN received %x\n", so->so_conv);
		if (TCPS_HAVERCVDFIN(tp->t_state) == 0) {
			TCP_TRACE_AWAYS(tp, "do FIN acked %x\n", so->so_conv);
			socantrcvmore(tp->rgn_rcv);
			tp->t_flags |= TF_ACKNOW;
			tp->rcv_nxt++;
		}

		switch(tp->t_state) {
			case TCPS_SYN_RECEIVED:
				tp->t_starttime = ticks;
			case TCPS_ESTABLISHED:
				TCP_TRACE_AWAYS(tp, "TCPS_ESTABLISHED -> TCPS_CLOSE_WAIT\n");
				tp->t_state = TCPS_CLOSE_WAIT;
				sorwakeup(tp);
				break;

			case TCPS_FIN_WAIT_1:
				TCP_TRACE_AWAYS(tp, "TCPS_FIN_WAIT_1 -> TCPS_CLOSING\n");
				tp->t_state = TCPS_CLOSING;
				sorwakeup(tp);
				break;

			case TCPS_FIN_WAIT_2:
				TCP_TRACE_AWAYS(tp, "TCPS_FIN_WAIT_2 -> TCPS_TIME_WAIT\n");
				tp->t_state = TCPS_TIME_WAIT;
				tcp_canceltimers(tp);
				tcp_timer_activate(tp, TT_2MSL, 2 * TCPTV_MSL);
				sorwakeup(tp);
				break;

			case TCPS_TIME_WAIT:
				tcp_timer_activate(tp, TT_2MSL, 2 * TCPTV_MSL);
				break;
		}
	}

	if (needoutput || (tp->t_flags & TF_ACKNOW))
		(void)tcp_output(tp);

check_delack:
	if (tp->t_flags & TF_DELACK) {
		tcp_timer_activate(tp, TT_DELACK, tcp_delacktime);
		tp->t_flags &= ~TF_DELACK;
	}
	return;

dropafterack:
	if (tp->t_state == TCPS_SYN_RECEIVED && (thflags & TH_ACK) &&
			(SEQ_GT(tp->snd_una, th->th_ack) ||
			 SEQ_GT(th->th_ack, tp->snd_max)) ) {
		/* rstreason = BANDLIM_RST_OPENPORT; */
		TCP_TRACE_AWAYS(tp, "send syn thack\n");
		goto dropwithreset;
	}

	tp->t_flags |= TF_ACKNOW;
	(void) tcp_output(tp);
	return;

dropwithreset:
	if (thflags & TH_RST)
		goto drop;

	if (tp == NULL) {
		static struct sockcb sob = {0};
		tcb.dst_addr = *from;
		tcb.tp_socket = &sob;

		sob.so_pcb = &tcb;
		sob.so_iface = dst;
		sob.so_conv  = th->th_conv;
		tp = &tcb;
	}

	if (thflags & TH_ACK) {
		TCP_TRACE_AWAYS(tp, "sentout RST without ACK\n");
		tcp_respond(tp, th, (tcp_seq)0, th->th_ack, TH_RST);
	} else {
		if (thflags & TH_SYN) tlen++;
		tcp_respond(tp, th, th->th_seq + tlen, (tcp_seq)0, TH_RST| TH_ACK);
		TCP_TRACE_AWAYS(tp, "sentout RST within ACK\n");
	}
	return;

drop:
	return;
}

static void tcp_xmit_timer(struct tcpcb *tp, int rtt)
{
	int delta;

	TCPSTAT_INC(tcps_rttupdated);
	tp->t_rttupdated++;
	if (tp->t_srtt != 0) {
		delta = ((rtt - 1) << TCP_DELTA_SHIFT) 
			- (tp->t_srtt >> (TCP_RTT_SHIFT - TCP_DELTA_SHIFT));

		if ((tp->t_srtt += delta) <= 0)
			tp->t_srtt = 1;

		if (delta < 0)
			delta = -delta;

		delta -= tp->t_rttvar >> (TCP_RTTVAR_SHIFT - TCP_DELTA_SHIFT);
		if ((tp->t_rttvar += delta) <= 0)
			tp->t_rttvar = 1;

	} else {
		tp->t_srtt = rtt << TCP_RTT_SHIFT;
		tp->t_rttvar = rtt << (TCP_RTTVAR_SHIFT - 1);
	}

	tp->t_rtttime = 0;
	tp->t_rxtshift = 0;
	TCPT_RANGESET(tp->t_rxtcur, TCP_REXMTVAL(tp),
			max(tp->t_rttmin, rtt + 2), TCPTV_REXMTMAX);

	return;
}

/*
 * On a partial ack arrives, force the retransmission of the
 * next unacknowledged segment.  Do not clear tp->t_dupacks.
 * By setting snd_nxt to th_ack, this forces retransmission timer to
 * be started again.
 */
#if 0
static void
tcp_newreno_partial_ack(struct tcpcb *tp, struct tcphdr *th)
{
        tcp_seq onxt = tp->snd_nxt;
        u_long  ocwnd = tp->snd_cwnd;

        INP_WLOCK_ASSERT(tp->t_inpcb);

        tcp_timer_activate(tp, TT_REXMT, 0);
        tp->t_rtttime = 0;
        tp->snd_nxt = th->th_ack;
        /*
         * Set snd_cwnd to one segment beyond acknowledged offset.
         * (tp->snd_una has not yet been updated when this function is called.)
         */
        tp->snd_cwnd = tp->t_maxseg + BYTES_THIS_ACK(tp, th);
        tp->t_flags |= TF_ACKNOW;
        (void) tcp_output(tp);
        tp->snd_cwnd = ocwnd;
        if (SEQ_GT(onxt, tp->snd_nxt))
                tp->snd_nxt = onxt;
        /*
         * Partial window deflation.  Relies on fact that tp->snd_una
         * not updated yet.
         */
        if (tp->snd_cwnd > BYTES_THIS_ACK(tp, th))
                tp->snd_cwnd -= BYTES_THIS_ACK(tp, th);
        else
                tp->snd_cwnd = 0;
        tp->snd_cwnd += tp->t_maxseg;
}
#endif


