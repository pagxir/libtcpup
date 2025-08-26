#include <stdlib.h>
#include <time.h>

#define TCPUP_LAYER 1
#include <utx/utxpl.h>
#include <utx/sobuf.h>
#include <utx/queue.h>
#include <utx/socket.h>

#define TCPOUTFLAGS
#include <tcpup/cc.h>
#include <tcpup/tcp.h>
#include <tcpup/tcp_seq.h>
#include <tcpup/tcp_var.h>
#include <tcpup/tcp_fsm.h>
#include <tcpup/tcp_timer.h>
#include <tcpup/tcp_debug.h>

#include "tcp_filter.h"

struct tcpstat tcpstat;
size_t set_tcp_link_target(const void *optval, size_t count);

int tcp_backoff[TCP_MAXRXTSHIFT + 1] = {
	1, 2, 4, 8, 16, 32, 64, 64, 64, 64, 64, 64, 64
};

void tcp_setpersist(struct tcpcb *tp)
{
	int persist_time = 0;
	int t = ((tp->t_srtt >> 2) + tp->t_rttvar) >> 1;
	UTXPL_ASSERT( !tcp_timer_active(tp, TT_REXMT) );

	tp->t_flags &= ~TF_PREVVALID;
	TCPT_RANGESET(persist_time,
			t * tcp_backoff[tp->t_rxtshift],
			TCPTV_PERSMIN, TCPTV_PERSMAX);
	tcp_timer_activate(tp, TT_PERSIST, persist_time);

	if (tp->t_rxtshift < TCP_MAXRXTSHIFT)
		tp->t_rxtshift++;

	return;
}

u_short update_checksum(const void *buf, size_t count, uint32_t link)
{
	uint32_t cksum = htons(count + IPPROTO_TCP);
	const uint16_t *base = (const uint16_t *)buf;
	size_t len = count;

	while (len >= 2) {
		cksum += *base++;
		len -= 2;
	}

	if (len > 0)
		cksum += *base & htons(0xff00);

	cksum += (link >> 16);
	cksum += (link & 0xffff);
	while (cksum >> 16)
		cksum = (cksum >> 16) + (uint16_t)cksum;

	return (uint16_t)~cksum;
}

uint16_t update_ckpass(const rgn_iovec iov[], size_t num, unsigned pseudo)
{
	int i, j;
	size_t total = 0;
	uint32_t cksum = (pseudo >> 16) + (0xffff & pseudo);

	for (i = 0; i < num; i++) {
		size_t len = iov[i].iov_len;
		const uint8_t *buf = (const uint8_t *)iov[i].iov_base;

		const uint16_t *base = (const uint16_t *)buf;
		if ((total & 0x1) && len > 0) {
			base = (const uint16_t *)(buf - 1);
			cksum += *base++  & htons(0xff);
			total++;
			len--;
		}

		total += len;
		while (len >= 2) {
			cksum += *base++;
			len -= 2;
		}

		if (len > 0) {
			cksum += *base & htons(0xff00);
			len--;
		}
	}

	cksum += htons(IPPROTO_TCP + total);

	while (cksum >> 16)
		cksum = (cksum >> 16) + (uint16_t)cksum;

	return (uint16_t)~cksum;
}

static int inline      hhook_run_tcp_est_out(struct tcpcb *tp,
                            struct tcphdr *th, struct tcpopt *to,
                            long len, int tso);
static void inline      cc_after_idle(struct tcpcb *tp);

/*
 * Wrapper for the TCP established output helper hook.
 */
static int inline
hhook_run_tcp_est_out(struct tcpcb *tp, struct tcphdr *th,
		struct tcpopt *to, long len, int tso)
{
    struct tcp_hhook_data hhook_data;

    hhook_data.tp = tp;
    hhook_data.th = th;
    hhook_data.to = to;
    hhook_data.len = len;
    hhook_data.tso = tso;

    return tcp_filter_out(&hhook_data);
}

static void inline
cc_after_idle(struct tcpcb *tp)
{
    if (CC_ALGO(tp)->after_idle != NULL)
        CC_ALGO(tp)->after_idle(tp->ccv);

    TCP_DEBUG(1, "cc_after_idle\n");

    if ((tp->t_flags & TF_REC_ADDR) == 0) {
        tp->dst_addr.xdat ^= 0x5a5a;
    }
}

#if 0
static int verify_checksum(rgn_iovec iov[], size_t count, uint32_t link)
{
	uint32_t check = 0;
	uint32_t total = 0;

	for (int i = 0; i < count; i++) {
		size_t len = iov[i].iov_len;
		const uint16_t *base = (const uint16_t *)iov[i].iov_base;

		TCP_DEBUG(1, "%d %x", i, len);
		assert(~len & 1);
		total += len;
		while (len > 0) {
			check += *base++;
			len -= 2;
		}
	}

	check += htons(IPPROTO_TCP + total);
	check += (link & 0xffff) + (link >> 16);
	while (check >> 16) check = (check & 0xffff) + (check >> 16);

	TCP_DEBUG(1, "check=%x %x %x", check, ~check, link);
	return check;
}
#endif

int tcp_output(struct tcpcb *tp)
{
	int error;
	long len, recwin, sendwin, cwnd;
	int off, flags;
	struct tcphdr *th;
	unsigned optlen;

	int idle, sendalot;
	int sack_rxmit, sack_bytes_rxmt;
	struct sackhole *p;
	struct tcpopt to = {0};

	rgn_iovec iobuf[4] = {{0, 0}};
	char th0_buf[sizeof(tcphdr) + 80];

	iobuf[0].iov_base = th0_buf;
	iobuf[0].iov_len  = sizeof(*th);
	th = (struct tcphdr *)th0_buf;
	ticks = tx_getticks();

	idle = (tp->t_flags & TF_LASTIDLE) || (tp->snd_max == tp->snd_una);
	if (idle && ticks - tp->t_rcvtime >= tp->t_rxtcur)
		cc_after_idle(tp);

	tp->t_flags &= ~TF_LASTIDLE;
	if (idle) {
		if (tp->t_flags & TF_MORETOCOME) {
			tp->t_flags |= TF_LASTIDLE;
			idle = 0;
		}
	}

	cwnd = tp->snd_cwnd + get_filter_win(tp);
	if (cwnd < tp->t_maxseg) {
		TCP_DEBUG(1, "incorrent cwnd size: %d", tp->snd_cwnd);
		cwnd = tp->t_maxseg;
	}
again:

	if (SEQ_LT(tp->snd_nxt, tp->snd_max))
		tcp_sack_adjust(tp);

	sendalot = 0;
	/* this_snd_nxt = tp->snd_nxt; */
	off = tp->snd_nxt - tp->snd_una;
	sendwin = min(tp->snd_wnd, cwnd);

	flags = tcp_outflags[tp->t_state];

	sack_rxmit = 0;
	sack_bytes_rxmt = 0;
	len = 0;
	p = NULL;
	if (IN_FASTRECOVERY(tp->t_flags) &&
		(p = tcp_sack_output(tp, &sack_bytes_rxmt))) {
		long cwin;

		cwin = sendwin - sack_bytes_rxmt;
		if (cwin < 0)
			cwin = 0;

		/* Do not retransmit SACK segments beyond snd_recover */
		if (SEQ_GT(p->end, tp->snd_recover)) {
			/*
			 * (At least) part of sack hole extends beyond
			 * snd_recover. Check to see if we can rexmit data
			 * for this hole.
			 */
			if (SEQ_GEQ(p->rxmit, tp->snd_recover)) {
				/*
				 * Can't rexmit any more data for this hole. 
				 * That data will be rexmitted in the next
				 * sack recovery episode, when snd_recover
				 * moves past p->rxmit.
				 */
				p = NULL;
				goto after_sack_rexmit;
			} else {
				/* Can rexmit part of the current hole */
				len = ((long)ulmin(cwin, tp->snd_recover - p->rxmit));
			}
		} else {
			len = ((long)ulmin(cwin, p->end - p->rxmit));
		}

		if (len > 0) {
		        off = p->rxmit - tp->snd_una;
			sack_rxmit = 1;
			sendalot = 1;
			TCPSTAT_INC(tcps_sack_rexmits);
			TCPSTAT_ADD(tcps_sack_rexmit_bytes, umin(len, tp->t_maxseg));
		}
	}

after_sack_rexmit:
	if (tp->t_flags & TF_NEEDFIN)
		flags |= TH_FIN;
	if (tp->t_flags & TF_NEEDSYN)
		flags |= TH_SYN;

	if (tp->t_flags & TF_FORCEDATA) {
		if (sendwin == 0) {
			if (off < rgn_len(tp->rgn_snd))
				flags &= ~TH_FIN;
			sendwin = 1;
		} else {
			tcp_timer_activate(tp, TT_PERSIST, 0);
			tp->t_rxtshift = 0;
		}
	}

	/*
	 * If snd_nxt == snd_max and we have transmitted a FIN, the
	 * offset will be > 0 even if so_snd.sb_cc is 0, resulting in
	 * a negative length.  This can also occur when TCP opens up
	 * its congestion window while receiving additional duplicate
	 * acks after fast-retransmit because TCP will reset snd_nxt
	 * to snd_max after the fast-retransmit.
	 *
	 * In the normal retransmit-FIN-only case, however, snd_nxt will
	 * be set to snd_una, the offset will be 0, and the length may
	 * wind up 0.
	 *
	 * If sack_rxmit is true we are retransmitting from the scoreboard
	 * in which case len is already set.
 	 */
	if (sack_rxmit == 0) {
		if (sack_bytes_rxmt == 0) {
			len = 0;
			if (sendwin >= off + tp->t_maxseg || (tp->t_flags & TF_FORCEDATA) ||
					rgn_len(tp->rgn_snd) < off + tp->t_maxseg) {
				len = ((long)ulmin(rgn_len(tp->rgn_snd), sendwin) - off);
			}
		} else {
			long cwin; 

			/*
			 * We are inside of a SACK recovery episode and are
			 * sending new data, having retransmitted all the
			 * data possible in the scoreboard.
			 */
			 len = ((long)ulmin(rgn_len(tp->rgn_snd), tp->snd_wnd) - off); 
			 /*
			  * Don't remove this (len > 0) check !
			  * We explicitly check for len > 0 here (although it 
			  * isn't really necessary), to work around a gcc 
			  * optimization issue - to force gcc to compute
			  * len above. Without this check, the computation
			  * of len is bungled by the optimizer.
			  */
			  if (len > 0) {
					cwin = cwnd -
				 		 (tp->snd_nxt - tp->sack_newdata) -
						 sack_bytes_rxmt;
					if (cwin < 0)
						cwin = 0;
					assert(~tp->t_flags & TF_FORCEDATA);
					len = lmin(len, cwin);
			  }
		}
	}

	/*
	 * Lop off SYN bit if it has already been sent.  However, if this
	 * is SYN-SENT state and if segment contains data and if we don't
	 * know that foreign host supports TAO, suppress sending segment.
	 */
	if ((flags & TH_SYN) && SEQ_GT(tp->snd_nxt, tp->snd_una)) {
		if (tp->t_state != TCPS_SYN_RECEIVED)
			flags &= ~TH_SYN;
		off--, len++;
	}

	if (flags & TH_SYN) {
		len = 0;
		flags &= ~TH_FIN;
	}

	if (len < 0) {
		len = 0;
		if (sendwin == 0) {
			tcp_timer_activate(tp, TT_REXMT, 0);
			tp->t_rxtshift = 0;
			tp->snd_nxt = tp->snd_una;
			if (!tcp_timer_active(tp, TT_PERSIST))
				tcp_setpersist(tp);
		}
	}

	/* len will be >= 0 after this point. */

	if (sack_rxmit) {
		if (SEQ_LT(p->rxmit + len, tp->snd_una + rgn_len(tp->rgn_snd)))
			flags &= ~TH_FIN;
	} else {
		if (SEQ_LT(tp->snd_nxt + len, tp->snd_una + rgn_len(tp->rgn_snd)))
			flags &= ~TH_FIN;
	}

	size_t old = rgn_size(tp->rgn_snd);
	if (!(tp->t_flags & TF_NEEDFIN)
			&& TCPS_HAVEESTABLISHED(tp->t_state) && 
			tp->t_state < TCPS_FIN_WAIT_1 &&
			(tp->snd_wnd / 4 * 5) >= rgn_size(tp->rgn_snd) &&
			rgn_len(tp->rgn_snd) >= (rgn_size(tp->rgn_snd) / 8 * 7) &&
			rgn_size(tp->rgn_snd) < tp->snd_max_space &&
			sendwin >= (rgn_len(tp->rgn_snd) - (tp->snd_nxt - tp->snd_una))) {
		TCP_DEBUG(1, "expand connection send space from %x@%d to %d -> %d\n", (tp->tp_socket->so_conv), tp->t_state, old, old << 1);
		UTXPL_ASSERT(old > tp->t_maxseg);
		tp->rgn_snd = rgn_resize(tp->rgn_snd, old << 1);
		sowwakeup(tp);
	}

	recwin = rgn_rest(tp->rgn_rcv);

	if (len) {
		if (len >= tp->t_maxseg)
			goto send_label;

		if (!(tp->t_flags & TF_MORETOCOME) &&
				(idle || (tp->t_flags & TF_NODELAY)) &&
				len + off >= rgn_len(tp->rgn_snd)) {
			goto send_label;
		}

		if (tp->t_flags & TF_FORCEDATA)
			goto send_label;

		if ((u_long)len >= tp->max_sndwnd / 2 &&
				tp->max_sndwnd > 0)
			goto send_label;

		if (SEQ_LT(tp->snd_nxt, tp->snd_max))
			goto send_label;

		if (sack_rxmit)
			goto send_label;

	}
	
	/*
	 * Compare available window to amount of window
	 * known to peer (as advertised window less
	 * next expected input).  If the difference is at least two
	 * max size segments, or at least 50% of the maximum possible
	 * window, then want to send a window update to peer.
	 * Skip this if the connection is in T/TCP half-open state.
	 * Don't send pure window updates when the peer has closed
	 * the connection and won't ever send more data.
	 */
	if (recwin > 0 && !(tp->t_flags & TF_NEEDSYN) &&
			!(tp->t_flags & TF_DELACK) &&
			!TCPS_HAVERCVDFIN(tp->t_state)) {
		long adv;
		int oldwin;

		adv = min(recwin, (long)(TCP_MAXWIN << WINDOW_SCALE));
		
		if (SEQ_GT(tp->rcv_adv, tp->rcv_nxt)) {
			oldwin = (tp->rcv_adv - tp->rcv_nxt);
			adv -= oldwin;
		} else
			oldwin = 0;

		/*
		 * If the new window size ends up being the same as the old
		 * size when it is scaled, then don't force a window update.
		 */
		if (oldwin >> WINDOW_SCALE == (adv + oldwin) >> WINDOW_SCALE)
			goto dontupdate;


		if (adv >= (long) (2 * tp->t_maxseg) &&
			(adv >= (long)(rgn_size(tp->rgn_rcv) / 4) ||
			 recwin <= (long)(rgn_size(tp->rgn_rcv) / 8) ||
			 rgn_size(tp->rgn_rcv) <= 8 * tp->t_maxseg))
		    goto send_label;
	}


dontupdate:
	/*
	 * Send if we own the peer an ACK, RST, SYN, or urgent data. ACKNOW
	 * is also a catch-all for the retransmit timer timeout case.
	 */
	if (tp->t_flags & TF_ACKNOW)
		goto send_label;

	if ((flags & TH_RST) || 
			((flags & TH_SYN) && (tp->t_flags & TF_NEEDSYN) == 0))
		goto send_label;

	if (flags & TH_FIN &&
			((tp->t_flags & TF_SENTFIN) == 0 || tp->snd_nxt == tp->snd_una))
		goto send_label;

	if (SEQ_GT(tp->snd_max, tp->snd_una) &&
		!tcp_timer_active(tp, TT_REXMT) &&
		!tcp_timer_active(tp, TT_PERSIST)) {
		tcp_timer_activate(tp, TT_REXMT, tp->t_rxtcur);
		TCP_DEBUG(1, "dupack %d %x %d\n", tp->t_dupacks, IN_FASTRECOVERY(tp->t_flags), tp->filter_nboard);
		goto just_return;
	}

	if (rgn_len(tp->rgn_snd) &&
		!tcp_timer_active(tp, TT_REXMT) &&
		!tcp_timer_active(tp, TT_PERSIST)) {
		tp->t_rxtshift = 0;
		tcp_setpersist(tp);
	}

just_return:
	return 0;

send_label:
	to.to_flags = 0;
	/* Maximum segment size. */
	if (flags & TH_SYN) {
		tp->snd_nxt = tp->iss;
		to.to_mss = tp->t_max_payload;
		to.to_flags |= TOF_MSS;
	}

	if ((flags & TH_SYN) && tp->relay_len > 0) {
		to.to_flags |= TOF_DESTINATION;
		to.to_dsaddr = tp->relay_target;
		to.to_dslen = tp->relay_len;
	}

	/* Window scaling. */
	assert(tp->t_flags & TF_REQ_SCALE);
	if ((flags & TH_SYN) && (tp->t_flags & TF_REQ_SCALE)) {
		to.to_wscale = WINDOW_SCALE;
		to.to_flags |= TOF_SCALE;
	}

	if (tp->t_flags & TF_SACK_PERMIT) {
		if (flags & TH_SYN)
			to.to_flags |= TOF_SACKPERM;
		else if (TCPS_HAVEESTABLISHED(tp->t_state) &&
				(tp->t_flags & TF_SACK_PERMIT) &&
				tp->rcv_numsacks > 0) {
			to.to_flags |= TOF_SACK;
			to.to_nsacks = tp->rcv_numsacks;
			to.to_sacks = (u_char *)tp->sackblks;
		}
	}

	if (tp->rfbuf_ts == 0)
		tp->rfbuf_ts = tcp_snd_getticks;

	to.to_flags |= TOF_TS;
	to.to_tsval = (tcp_snd_getticks);
	to.to_tsecr = (tp->ts_recent);

	optlen = tcp_addoptions(&to, (u_char *)(th + 1));

	iobuf[0].iov_base = (char *)th;
	iobuf[0].iov_len  = sizeof(*th) + optlen;

	if (len + optlen > tp->t_max_payload) {
		sendalot = 1;
		flags &= ~TH_FIN;
		len = tp->t_max_payload - optlen;
	}

	if (len) {
		if ((tp->t_flags & TF_FORCEDATA) && len == 1) {
			TCPSTAT_INC(tcps_sndprobe);
		} else if (SEQ_LT(tp->snd_nxt, tp->snd_max) || sack_rxmit) {
			/* tp->t_sndrexmitpack++; */
			TCPSTAT_INC(tcps_sndrexmitpack);
			TCPSTAT_ADD(tcps_sndrexmitbyte, len);
		} else {
			TCPSTAT_INC(tcps_sndpack);
			TCPSTAT_ADD(tcps_sndbyte, len);
		}
		// TCP_TRACE_CHECK(tp, off && p, "%x len %d, off %d, optlen %d, %x\n", tp->tp_socket->so_conv, len, off, optlen, to.to_flags);
		rgn_peek(tp->rgn_snd, iobuf + 1, len, off);
		if (off + len == rgn_len(tp->rgn_snd))
			flags |= TH_PUSH;
	} else {
		if (tp->t_flags & TF_ACKNOW) {
			TCPSTAT_INC(tcps_sndacks);
		} else if (flags & (TH_SYN | TH_FIN | TH_RST))
			TCPSTAT_INC(tcps_sndctrl);
		else
			TCPSTAT_INC(tcps_sndwinup);
	}

	if ((flags & TH_FIN) && (tp->t_flags & TF_SENTFIN) &&
			(tp->snd_nxt == tp->snd_max))
		tp->snd_nxt--;

	if (sack_rxmit == 0) {
		if (len || (flags & (TH_SYN | TH_FIN)) || 
			tcp_timer_active(tp, TT_PERSIST)) {
			th->th_seq = htonl(tp->snd_nxt);
		} else {
			th->th_seq = htonl(tp->snd_max_out);
		}
	} else {
		th->th_seq = htonl(p->rxmit);
		p->rxmit += len;
		tp->sackhint.sack_bytes_rexmit += len;
	}

	th->th_x2 = 0;
	th->th_opten = (optlen >> 2) + 5;
	th->th_ack = htonl(tp->rcv_nxt);
	th->th_flags = flags;
	th->th_conv  = (tp->tp_socket->so_conv);
	th->th_sum	 = 0;
	th->th_urp	 = 0;

	if (recwin < (long) rgn_size(tp->rgn_rcv) / 4 &&
		recwin < (long) tp->t_maxseg)
		recwin = 0;
	if (SEQ_GT(tp->rcv_adv, tp->rcv_nxt) &&
		recwin < (long)(tp->rcv_adv - tp->rcv_nxt))
		recwin = (long)(tp->rcv_adv - tp->rcv_nxt);
	if (recwin > (long)(TCP_MAXWIN << WINDOW_SCALE))
		recwin = (long)(TCP_MAXWIN << WINDOW_SCALE);
	th->th_win = htons((u_short)(recwin >> WINDOW_SCALE));


	th->th_sum = update_ckpass(iobuf, 3, tp->tp_socket->so_link);
    // verify_checksum(iobuf, 3, tp->tp_socket->so_link);
	/* Run HHOOK_TCP_ESTABLISHED_OUT helper hooks. */

	if (len == 0)
	    error = utxpl_output(tp->tp_socket->so_iface, iobuf, 3, &tp->dst_addr, tp->tp_socket->so_link);
	else
	    error = hhook_run_tcp_est_out(tp, th, &to, len, sack_rxmit);

	if ((tp->t_flags & TF_FORCEDATA) == 0 || !tcp_timer_active(tp, TT_PERSIST)) {
		tcp_seq startseq = tp->snd_nxt;

		if (flags & (TH_SYN | TH_FIN)) {
			if (flags & TH_SYN)
				tp->snd_nxt++;
			if (flags & TH_FIN) {
				tp->snd_nxt++;
				tp->t_flags |= TF_SENTFIN;
			}
		}

		if (sack_rxmit)
			goto timer;
		tp->snd_nxt += len;
		if (SEQ_GT(tp->snd_nxt, tp->snd_max)) {
			tp->snd_max = tp->snd_nxt;

			if (flags & (TH_SYN| TH_FIN)) {
				tp->snd_max_out = tp->snd_nxt;
			}

			TCP_DEBUG(error == -1, "error on sent rttime %d", tp->t_rtttime);
			if (tp->t_rtttime == 0 && error > 0) {
				assert(error > 0);
				tp->t_rtttime = ticks; // NEED TO FIXME
				tp->t_rtseq = startseq;
				TCPSTAT_INC(tcps_segstimed);
			}
		}

timer:
		if (!tcp_timer_active(tp, TT_REXMT) && error > 0 &&
			((sack_rxmit && tp->snd_nxt != tp->snd_max) ||
				(tp->snd_nxt != tp->snd_una))) {
			if ( tcp_timer_active(tp, TT_PERSIST) ) {
				tcp_timer_activate(tp, TT_PERSIST, 0);
				tp->t_rxtshift = 0;
			}

			assert (tp->snd_max != tp->snd_una);
			if (error > 0) {
				assert(error > 0);
				tp->snd_rto = htonl(th->th_seq);
			}
			TCP_DEBUG(error == -1, "error on sent");
			tcp_timer_activate(tp, TT_REXMT, tp->t_rxtcur * 2);
		}
	} else {
		int xlen = len;
		if (flags & TH_SYN)
			++xlen;
		if (flags & TH_FIN) {
			tp->t_flags |= TF_SENTFIN;
			++xlen;
		}
		if (SEQ_GT(tp->snd_nxt + xlen, tp->snd_max)) {
			tp->snd_max = tp->snd_nxt + len;
			assert (tp->snd_max != tp->snd_una);
		}
	}

	if (error == -1) {
		if (((tp->t_flags & TF_FORCEDATA) == 0 ||
					!tcp_timer_active(tp, TT_PERSIST)) &&
				((flags & TH_SYN) == 0)) {
			if (sack_rxmit) {
				p->rxmit -= len;
				tp->sackhint.sack_bytes_rexmit -= len;
				KASSERT(tp->sackhint.sack_bytes_rexmit >= 0,
						("sackhint bytes rtx >= 0"));
			} else
				tp->snd_nxt -= len;
		}

		if (!tcp_timer_active(tp, TT_REXMT) &&
				!tcp_timer_active(tp, TT_PERSIST))
			tcp_timer_activate(tp, TT_REXMT, tp->t_rxtcur);
		// tp->snd_cwnd = tp->t_maxseg;

		tcp_devbusy(tp, &tp->t_event_devbusy);
		return (0);
	}

	TCPSTAT_INC(tcps_sndtotal);
	if (recwin > 0 && SEQ_GT(tp->rcv_nxt + recwin, tp->rcv_adv))
		tp->rcv_adv = tp->rcv_nxt + recwin;
	tp->last_ack_sent = tp->rcv_nxt;
	tp->t_flags &= ~(TF_ACKNOW | TF_DELACK);
	tcp_timer_activate(tp, TT_DELACK, 0);

	if (error == 0 && len > 0) {
	    // TCP_DEBUG(1, "filter");
#if 0
	    if (sack_rxmit)
		tp->sackhint.sack_bytes_rexmit -= len;
#endif
	    sendalot = 1;
	}

	if (sendalot)
		goto again;

	return 0;
}

void tcp_respond(struct tcpcb *tp, struct tcphdr *orig, tcp_seq ack, tcp_seq seq, int flags)
{
	int error;
	struct rgn_iovec iov0;
	struct tcphdr tcpup_th0 = {};
	struct tcphdr *th = &tcpup_th0;

	th->th_x2 = 0;
	th->th_opten = 5;
	th->th_ack = htonl(ack);
	th->th_seq = htonl(seq);
	th->th_flags = flags;
	th->th_win   = 0;
	th->th_urp   = 0;

	if (orig != NULL) {
		th->th_conv = (orig->th_conv);
		// th->th_tsecr = htonl(orig->th_tsval);
	} else {
		th->th_conv = (tp->tp_socket->so_conv);
		th->th_flags = TH_ACK | ((rgn_len(tp->rgn_snd) || (tp->t_flags & TF_MORETOCOME))? 0: TH_PUSH);
		// th->th_tsecr = htonl(tp->ts_recent);
	}

	// th->th_tsval = htonl(tcp_ts_getticks());

	th->th_sum	= 0;
	if (tp != NULL && tp->rgn_rcv) {
		long recwin = rgn_rest(tp->rgn_rcv);
		if (recwin > (long)(TCP_MAXWIN << WINDOW_SCALE))
			recwin = (long)(TCP_MAXWIN << WINDOW_SCALE);
		th->th_win = htons((u_short)(recwin >> WINDOW_SCALE));
	}

	iov0.iov_len = sizeof(tcpup_th0);
	iov0.iov_base = &tcpup_th0;

	TCP_TRACE_AWAYS(tp, "tcp_respond: %x flags %x seq %x  ack %x ts %x %x\n",
			th->th_conv, flags, seq, ack, 0, 0);

	th->th_sum = update_ckpass(&iov0, 1, tp->tp_socket->so_link);
	error = utxpl_output(tp->tp_socket->so_iface, &iov0, 1, &tp->dst_addr, tp->tp_socket->so_link);
	VAR_UNUSED(error);
	return;
}

/*
 * Insert TCP options according to the supplied parameters to the place
 * optp in a consistent way. Can handle unaligned destinations.
 *
 * The order of the option processing is crucial for optimal packing and
 * alignment for the scarce option space.
 *
 * The optimal order for a SYN/SYN-ACK segment is:
 * MSS (4) + NOP (1) + Window scale (3) + SACK permitted (2) +
 * Timestamp (10) + Signature (18) = 38 bytes out of a maximum of 40.
 *
 * The SACK options should be last. SACK blocks consume 8*n+2 bytes.
 * So a full size SACK blocks option is 34 bytes (with 4 SACK blocks).
 * At minimum we need 10 bytes (to generate 1 SACK block). If both
 * TCP Timestamps (12 bytes) and TCP Signatures (18 bytes) are present,
 * we only have 10 bytes for SACK options (40 - (12 + 18)).
 */
int tcp_addoptions(struct tcpopt *to, u_char *optp)
{
	u_int mask, optlen = 0;
	u_int tsval, tsecr;

	for (mask = 1; mask < TOF_MAXOPT; mask <<= 1) {
		if ((to->to_flags & mask) != mask)
			continue;
		if (optlen == TCP_MAXOLEN)
			break;
		switch (to->to_flags & mask) {
			case TOF_MSS:
				while (optlen % 4) {
					optlen += TCPOLEN_NOP;
					*optp++ = TCPOPT_NOP;
				}
				if (TCP_MAXOLEN - optlen < TCPOLEN_MAXSEG)
					continue;
				optlen += TCPOLEN_MAXSEG;
				*optp++ = TCPOPT_MAXSEG;
				*optp++ = TCPOLEN_MAXSEG;
				to->to_mss = htons(to->to_mss);
				bcopy((u_char *)&to->to_mss, optp, sizeof(to->to_mss));
				optp += sizeof(to->to_mss);
				break;
			case TOF_SCALE:
				while (!optlen || optlen % 2 != 1) {
					optlen += TCPOLEN_NOP;
					*optp++ = TCPOPT_NOP;
				}
				if (TCP_MAXOLEN - optlen < TCPOLEN_WINDOW)
					continue;
				optlen += TCPOLEN_WINDOW;
				*optp++ = TCPOPT_WINDOW;
				*optp++ = TCPOLEN_WINDOW;
				*optp++ = to->to_wscale;
				break;
			case TOF_SACK:
				{
					int sackblks = 0;
					struct sackblk *sack = (struct sackblk *)to->to_sacks;
					tcp_seq sack_seq;

					while (!optlen || optlen % 4 != 2) {
						optlen += TCPOLEN_NOP;
						*optp++ = TCPOPT_NOP;
					}
					if (TCP_MAXOLEN - optlen < TCPOLEN_SACKHDR + TCPOLEN_SACK)
						continue;
					optlen += TCPOLEN_SACKHDR;
					*optp++ = TCPOPT_SACK;
					sackblks = min(to->to_nsacks,
							(TCP_MAXOLEN - optlen) / TCPOLEN_SACK);
					*optp++ = TCPOLEN_SACKHDR + sackblks * TCPOLEN_SACK;
					while (sackblks--) {
						sack_seq = htonl(sack->start);
						bcopy((u_char *)&sack_seq, optp, sizeof(sack_seq));
						optp += sizeof(sack_seq);
						sack_seq = htonl(sack->end);
						bcopy((u_char *)&sack_seq, optp, sizeof(sack_seq));
						optp += sizeof(sack_seq);
						optlen += TCPOLEN_SACK;
						sack++;
					}
					TCPSTAT_INC(tcps_sack_send_blocks);
					break;
				}
#if 0
			case TOF_DESTINATION:
				while (!optlen || optlen % 2 != 1) {
					optlen += TCPOLEN_NOP;
					*optp++ = TCPOPT_NOP;
				}
				if (TCP_MAXOLEN - optlen < TCPOLEN_DESTINATION + to->to_dslen)
					continue;
				optlen += (to->to_dslen + TCPOLEN_DESTINATION);
				*optp++ = TCPOPT_DESTINATION;
				*optp++ = (to->to_dslen + TCPOLEN_DESTINATION);
				memcpy(optp, to->to_dsaddr, to->to_dslen);
				optp += to->to_dslen;
				break;
#endif
			case TOF_TS:
				while (!optlen || optlen % 4 != 2) {
					optlen += TCPOLEN_NOP;
					*optp++ = TCPOPT_NOP;
				}
				if (TCP_MAXOLEN - optlen < TCPOLEN_TIMESTAMP)
					continue;
				optlen += TCPOLEN_TIMESTAMP;
				*optp++ = TCPOPT_TIMESTAMP;
				*optp++ = TCPOLEN_TIMESTAMP;
				tsval = htonl(to->to_tsval);
				tsecr = htonl(to->to_tsecr);
				bcopy((u_char *)&tsval, optp, sizeof(tsval));
				optp += sizeof(tsval);
				bcopy((u_char *)&tsecr, optp, sizeof(tsecr));
				optp += sizeof(tsecr);
				break;

			case TOF_SACKPERM:
				while (optlen % 2) {
					optlen += TCPOLEN_NOP;
					*optp++ = TCPOPT_NOP;
				}
				if (TCP_MAXOLEN - optlen < TCPOLEN_SACK_PERMITTED)
					continue;
				optlen += TCPOLEN_SACK_PERMITTED;
				*optp++ = TCPOPT_SACK_PERMITTED;
				*optp++ = TCPOLEN_SACK_PERMITTED;
				break;

			case TOF_DESTINATION:
				set_tcp_link_target(to->to_dsaddr, to->to_dslen);
				break;

			default:
				TX_PANIC(0, "unknown TCP option type");
				break;
		}
	}

	/* Terminate and pad TCP options to a 4 byte boundary. */
	if (optlen % 4) {
		optlen += TCPOLEN_EOL;
		*optp++ = TCPOPT_EOL;
	}
	/*
	 * According to RFC 793 (STD0007):
	 * "The content of the header beyond the End-of-Option option
	 * must be header padding (i.e., zero)."
	 * and later: "The padding is composed of zeros."
	 */
	while (optlen % 4) {
		optlen += TCPOLEN_PAD;
		*optp++ = TCPOPT_PAD;
	}

	KASSERT(optlen <= TCP_MAXOLEN, ("%s: TCP options too long", __func__));
	return (optlen);
}

