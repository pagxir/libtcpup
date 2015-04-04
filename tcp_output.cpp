#if 0
#include <stdio.h>
#include <UTXPL_ASSERT.h>
#include <unistd.h>
#include <fcntl.h>

#include <wait/platform.h>
#include <wait/callout.h>
#include <wait/slotwait.h>
#include <wait/slotsock.h>
#endif

#include <utx/utxpl.h>
#include <utx/sobuf.h>
#include <utx/queue.h>
#include <utx/socket.h>

#define TCPOUTFLAGS
#include <tcpup/cc.h>
#include <tcpup/tcp.h>
#include <tcpup/h_ertt.h>
#include <tcpup/tcp_seq.h>
#include <tcpup/tcp_var.h>
#include <tcpup/tcp_fsm.h>
#include <tcpup/tcp_timer.h>
#include <tcpup/tcp_debug.h>

struct tcpstat tcpstat;
int tcp_backoff[TCP_MAXRXTSHIFT + 1] = {
	1, 2, 4, 8, 16, 32, 64, 64, 64, 64, 64, 64, 64
};

void tcp_setpersist(struct tcpcb *tp)
{
	int persist_time = 0;
	register int t = ((tp->t_srtt >> 2) + tp->t_rttvar) >> 1;
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

int ertt_add_tx_segment_info_hook(int hhook_type, int hhook_id,
		void *udata, void *ctx_data, void *hdata, struct osd *hosd);

static void inline      hhook_run_tcp_est_out(struct tcpcb *tp,
                            struct tcphdr *th, struct tcpopt *to,
                            long len, int tso);
static void inline      cc_after_idle(struct tcpcb *tp);

/*
 * Wrapper for the TCP established output helper hook.
 */
static void inline
hhook_run_tcp_est_out(struct tcpcb *tp, struct tcphdr *th,
		struct tcpopt *to, long len, int tso)
{
	struct tcp_hhook_data hhook_data;

#if 0
	if (V_tcp_hhh[HHOOK_TCP_EST_OUT]->hhh_nhooks > 0) {
#endif
		hhook_data.tp = tp;
		hhook_data.th = th;
		hhook_data.to = to;
		hhook_data.len = len;
		hhook_data.tso = tso;
		ertt_add_tx_segment_info_hook(0, 0, 0, &hhook_data, &tp->osd->ertt, tp->osd);

#if 0
		hhook_run_hooks(V_tcp_hhh[HHOOK_TCP_EST_OUT], &hhook_data,
				tp->osd);
	}
#endif
}

static void inline
cc_after_idle(struct tcpcb *tp)
{
    if (CC_ALGO(tp)->after_idle != NULL)
        CC_ALGO(tp)->after_idle(tp->ccv);
}

int tcp_output(struct tcpcb *tp)
{
	int error;
	int tilen = 0;
	int rcv_numsacks;
	long len, sendwin, recwin;
	int off, flags;
	int idle, sendalot;
	int optlen = 0;
	int this_sent = 0;
	int sack_rxmit, sack_bytes_rxmt;
	struct sackhole *p;
	/* tcp_seq this_snd_nxt = 0; */
	rgn_iovec iobuf[4] = {{0, 0}};
	char th0_buf[sizeof(tcphdr) + 80];
	struct tcpopt to = {0};
	struct tcphdr *th = (struct tcphdr *)th0_buf;

	iobuf[0].iov_base = th0_buf;
	iobuf[0].iov_len  = sizeof(*th);

#if 0
	if ( tcp_busying() ) {
		tcp_devbusy(tp);
		return -1;
	}
#endif

	idle = (tp->t_flags & TF_LASTIDLE) || (tp->snd_max == tp->snd_una);
	if (idle && TSTMP_GEQ(ticks, tp->t_rcvtime + tp->t_rxtcur))
		cc_after_idle(tp);

	tp->t_flags &= ~TF_LASTIDLE;
	if (idle) {
		if (tp->t_flags & TF_MORETOCOME) {
			tp->t_flags |= TF_LASTIDLE;
			idle = 0;
		}
	}

again:
	if (SEQ_LT(tp->snd_nxt, tp->snd_max))
		tcp_sack_adjust(tp);

	optlen = 0;
	sendalot = 0;
	/* this_snd_nxt = tp->snd_nxt; */
	off = tp->snd_nxt - tp->snd_una;
	sendwin = min(tp->snd_wnd, tp->snd_cwnd);
	flags = tcp_outflags[tp->t_state];

	sack_rxmit = 0;
	sack_bytes_rxmt = 0;
	len = 0;
	p = NULL;
	if (IN_FASTRECOVERY(tp->t_flags) &&
		(p = tcp_sack_output(tp, &sack_bytes_rxmt))) {
		long cwin;

		cwin = min(tp->snd_wnd, tp->snd_cwnd) - sack_bytes_rxmt;
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
		off = p->rxmit - tp->snd_una;
		KASSERT(off >= 0, ("%s: sack block to the left of una : %d", __func__, off));
		if (len > 0) {
			sack_rxmit = 1;
			sendalot = 1;
			TCPSTAT_INC(tcps_sack_rexmits);
			TCPSTAT_ADD(tcps_sack_rexmit_bytes, umin(len, tp->t_maxseg));
		}
	}

after_sack_rexmit:
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
		if (sack_bytes_rxmt == 0)
			len = ((long)ulmin(rgn_len(tp->rgn_snd), sendwin) - off);
		else {
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
					cwin = tp->snd_cwnd -
				 		 (tp->snd_nxt - tp->sack_newdata) -
						 sack_bytes_rxmt;
					if (cwin < 0)
						cwin = 0;
					len = lmin(len, cwin);
			  }
		}
	}

	if (len < 0) {
		len = 0;
		if (sendwin == 0) {
			tcp_timer_activate(tp, TT_REXMT, 0);
			tp->snd_nxt = tp->snd_una;
			tp->t_rxtshift = 0;
			if ( !tcp_timer_active(tp, TT_PERSIST) )
				tcp_setpersist(tp);
		}
	}

	/* len will be >= 0 after this point. */
	KASSERT(len >= 0, ("[%s:%d]: len < 0", __func__, __LINE__));

	if (sack_rxmit) {
		if (SEQ_LT(p->rxmit + len, tp->snd_una + rgn_len(tp->rgn_snd)))
			flags &= ~TH_FIN;
	} else {
		if (SEQ_LT(tp->snd_nxt + len, tp->snd_una + rgn_len(tp->rgn_snd)))
			flags &= ~TH_FIN;
	}

	recwin = rgn_rest(tp->rgn_rcv);

	if (len > tp->t_maxseg) {
		len = tp->t_maxseg;
		flags &= ~TH_FIN;
		sendalot = 1;
	}


	if (len) {
		if (len >= tp->t_maxseg)
			goto sendit;

		if (idle && len + off >= rgn_len(tp->rgn_snd))
			goto sendit;

		if (tp->t_flags & TF_FORCEDATA)
			goto sendit;

		if ((u_long)len >= tp->max_sndwnd / 2 &&
				tp->max_sndwnd > 0)
			goto sendit;

		if (SEQ_LT(tp->snd_nxt, tp->snd_max))
			goto sendit;

		if (sack_rxmit)
			goto sendit;
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
	if (recwin > 0 && !(tp->t_flags & TF_DELACK) 
		&& !TCPS_HAVERCVDFIN(tp->t_state)) {
		long adv;
		int oldwin;

		adv = min(recwin, (long)TCP_MAXWIN);
		
		if (SEQ_GT(tp->rcv_adv, tp->rcv_nxt)) {
			oldwin = (tp->rcv_adv - tp->rcv_nxt);
			adv -= oldwin;
		} else
			oldwin = 0;

		/*
		 * If the new window size ends up being the same as the old
		 * size when it is scaled, then don't force a window update.
		 */
		if (oldwin == (adv + oldwin))
			goto dontupdate;

		if (adv >= (long) (2 * tp->t_maxseg))
			goto sendit;

		if (2 * adv >= (long) rgn_size(tp->rgn_rcv))
			goto sendit;
	}

dontupdate:
	/*
	 * Send if we own the peer an ACK, RST, SYN, or urgent data. ACKNOW
	 * is also a catch-all for the retransmit timer timeout case.
	 */
	if (tp->t_flags & TF_ACKNOW)
		goto sendit;

	if (flags & (TH_SYN | TH_RST))
		goto sendit;

	if (flags & TH_FIN &&
			((tp->t_flags & TF_SENTFIN) == 0 || tp->snd_nxt == tp->snd_una))
		goto sendit;

	if (SEQ_GT(tp->snd_max, tp->snd_una) &&
		!tcp_timer_active(tp, TT_REXMT) &&
		!tcp_timer_active(tp, TT_PERSIST)) {
		tcp_timer_activate(tp, TT_REXMT, tp->t_rxtcur);
		goto just_return;
	}

	if (rgn_len(tp->rgn_snd) &&
		!tcp_timer_active(tp, TT_REXMT) &&
		!tcp_timer_active(tp, TT_PERSIST)) {
		tp->t_rxtshift = 0;
		tcp_setpersist(tp);
	}

just_return:
	tcp_cancel_devbusy(tp);
	tp->t_flags &= ~TF_DEVBUSY;
	return 0;

sendit:
	if (flags & TH_SYN) {
		tp->snd_nxt = tp->iss;
	}

	if (tp->rcv_numsacks > 0) {
		to.to_flags |= TOF_SACK;
		to.to_nsacks = tp->rcv_numsacks;
		to.to_sacks = (u_char *)tp->sackblks;
	}

	optlen = tcp_addoptions(&to, (u_char *)(th + 1));
	rcv_numsacks = (optlen >> 2);
#if 0
	optlen = TCPOLEN_SACK * rcv_numsacks;
#endif

	iobuf[0].iov_base = (char *)th;
	iobuf[0].iov_len  = sizeof(*th) + optlen;

	if (len + optlen > tp->t_maxseg) {
		sendalot = 1;
		flags &= ~TH_FIN;
		len = tp->t_maxseg - optlen;
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
		TCP_DEBUG_TRACE(off && p, "len %d, off %d\n", len, off);
		rgn_peek(tp->rgn_snd, iobuf + 1, len, off);
#if 0
		if (off + len == rgn_len(tp->rgn_snd))
			flags |= TH_PUSH;
#endif
	} else {
		if (tp->t_flags & TF_ACKNOW) {
			TCPSTAT_INC(tcps_sndacks);
		} else if (flags & (TH_SYN | TH_FIN | TH_RST))
			TCPSTAT_INC(tcps_sndctrl);
		else
			TCPSTAT_INC(tcps_sndwinup);
	}

	if (flags & TH_FIN && tp->t_flags & TF_SENTFIN &&
			tp->snd_nxt == tp->snd_max)
		tp->snd_nxt--;

	if (sack_rxmit == 0) {
		if (len || (flags & (TH_SYN | TH_FIN)) || 
			tcp_timer_active(tp, TT_PERSIST)) {
			th->th_seq = htonl(tp->snd_nxt);
		} else {
			th->th_seq = htonl(tp->snd_max);
		}
	} else {
		th->th_seq = htonl(p->rxmit);
		p->rxmit += len;
		tp->sackhint.sack_bytes_rexmit += len;
	}

	to.to_flags = TOF_TS;
	to.to_tsval = htonl(tcp_snd_getticks);
	to.to_tsecr = htonl(tp->ts_recent);

	th->th_magic = MAGIC_UDP_TCP;
	th->th_opten = rcv_numsacks;
	th->th_ack = htonl(tp->rcv_nxt);
	th->th_tsval = (to.to_tsval);
	th->th_tsecr = (to.to_tsecr);
	th->th_flags = flags;
	th->th_conv  = htonl(tp->t_conv);
	tilen   = (u_short)len;

	if (recwin < (long) rgn_size(tp->rgn_rcv) / 4 &&
		recwin < (long) tp->t_maxseg)
		recwin = 0;
	if (SEQ_GT(tp->rcv_adv, tp->rcv_nxt) &&
		recwin < (long)(tp->rcv_adv - tp->rcv_nxt))
		recwin = (long)(tp->rcv_adv - tp->rcv_nxt);
	if (recwin > (long)TCP_MAXWIN)
		recwin = (long)TCP_MAXWIN;
	th->th_win = htons((u_short)(recwin >> WINDOW_SCALE));

	/* Run HHOOK_TCP_ESTABLISHED_OUT helper hooks. */
	hhook_run_tcp_est_out(tp, th, &to, tilen, 0);


	int prev_snd_nxt = tp->snd_nxt;
	int prev_snd_max = tp->snd_max;
	int prev_t_flags = tp->t_flags;
	int prev_t_rtseq = tp->t_rtseq;
	int prev_t_rtttime = tp->t_rtttime;

	if (th->th_flags & TH_FIN) {
		TCP_DEBUG_TRACE(th->th_flags & TH_FIN, "%x FIN sent\n", tp->t_conv);
		TCP_DEBUG_TRACE(tilen == 0 && tp->t_state > TCPS_ESTABLISHED, "%x finish ack\n", tp->t_conv);
	}

	error = utxpl_output(tp->if_dev, iobuf, 3, &tp->dst_addr);

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
			if (tp->t_rtttime == 0) {
				tp->t_rtttime = ticks;
				tp->t_rtseq = startseq;
				TCPSTAT_INC(tcps_segstimed);
			}
		}

timer:
		if (!tcp_timer_active(tp, TT_REXMT) &&
			((sack_rxmit && tp->snd_nxt != tp->snd_max) ||
				(tp->snd_nxt != tp->snd_una))) {
			if ( tcp_timer_active(tp, TT_PERSIST) ) {
				tcp_timer_activate(tp, TT_PERSIST, 0);
				tp->t_rxtshift = 0;
			}

			tcp_timer_activate(tp, TT_REXMT, tp->t_rxtcur);
		}
	} else {
		int xlen = len;
		if (flags & TH_SYN)
			++xlen;
		if (flags & TH_FIN) {
			tp->t_flags |= TF_SENTFIN;
			++xlen;
		}
		if (SEQ_GT(tp->snd_nxt + xlen, tp->snd_max))
			tp->snd_max = tp->snd_nxt + len;
	}

   	if (error == -1) {

		if ((!(tp->t_flags & TF_FORCEDATA) ||
					!tcp_timer_active(tp, TT_PERSIST)) &&
				((flags & TH_SYN) == 0)) {
			if (sack_rxmit) {
				p->rxmit -= len;
				tp->sackhint.sack_bytes_rexmit -= len;
			} else
				tp->snd_nxt -= len;

		}

		tp->snd_nxt = prev_snd_nxt;
		tp->snd_max = prev_snd_max;
		tp->t_rtseq = prev_t_rtseq;
		tp->t_flags = prev_t_flags;
		tp->t_rtttime = prev_t_rtttime;

		if (!tcp_timer_active(tp, TT_REXMT) &&
				!tcp_timer_active(tp, TT_PERSIST))
			tcp_timer_activate(tp, TT_REXMT, tp->t_rxtcur);
		tp->snd_cwnd = tp->t_maxseg;

		/* tp->t_dupacks++; */
		TCP_DEBUG_TRACE(1, "utxpl_output %d\n", utxpl_error());
		UTXPL_ASSERT(tp->snd_nxt >= tp->snd_una);

		tcp_devbusy(tp);
	   	return -1;
   	}


	this_sent += tilen;
	TCPSTAT_INC(tcps_sndtotal);
	if (recwin > 0 && SEQ_GT(tp->rcv_nxt + recwin, tp->rcv_adv))
		tp->rcv_adv = tp->rcv_nxt + recwin;
	tp->last_ack_sent = tp->rcv_nxt;
	tp->t_flags &= ~(TF_ACKNOW | TF_DELACK);
	tcp_timer_activate(tp, TT_DELACK, 0);

	if (sendalot)
		goto again;

#if 0
	if (sendalot) {
		tcp_devbusy(tp);
		return -1;
	}
#endif

	tcp_cancel_devbusy(tp);
	tp->t_flags &= ~TF_DEVBUSY;
	return 0;
}

void tcp_respond(struct tcpcb *tp, struct tcphdr *orig, int tlen, int flags)
{
	int error;
    struct rgn_iovec iov0;
    struct tcphdr tcpup_th0;
	struct tcphdr *th = &tcpup_th0;

	th->th_magic = MAGIC_UDP_TCP;
	th->th_opten = 0;
	th->th_ack = htonl(orig->th_seq + tlen);
	th->th_seq = htonl(orig->th_ack);
	th->th_conv = htonl(tp->t_conv);
	th->th_flags = flags;
	th->th_win   = 0;

	if (tp != NULL) {
		long recwin = rgn_rest(tp->rgn_rcv);
		if (recwin > (long)TCP_MAXWIN) recwin = (long)TCP_MAXWIN;
		th->th_win = htons((u_short)(recwin >> WINDOW_SCALE));
	}

	th->th_tsecr = htonl(orig->th_tsval);
	th->th_tsval = htonl(orig->th_tsecr);

    iov0.iov_len = sizeof(tcpup_th0);
    iov0.iov_base = &tcpup_th0;
	TCP_DEBUG_TRACE(th->th_flags & TH_FIN, "%x RST %x ACK %x\n", tp->t_conv, flags & TH_ACK, flags & TH_RST);

	error = utxpl_output(tp->if_dev, &iov0, 1, &tp->dst_addr);
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
			case TOF_TS:
			case TOF_SACKPERM:
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

