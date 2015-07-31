#include <utx/queue.h>
#include <utx/utxpl.h>

#include <tcpup/cc.h>
#include <tcpup/tcp.h>
#include <tcpup/tcp_var.h>
#include <tcpup/tcp_seq.h>

void newreno_ack_received(struct cc_var *ccv, uint16_t type);
void newreno_after_idle(struct cc_var *ccv);
void newreno_cong_signal(struct cc_var *ccv, uint32_t type);
void newreno_post_recovery(struct cc_var *ccv);

struct cc_algo newreno_cc_algo = {
	"newreno",
	mod_init: NULL,
    mod_destroy: NULL,
	cb_init: NULL,
	cb_destroy: NULL,
	conn_init: NULL,
	ack_received: newreno_ack_received,
	cong_signal: newreno_cong_signal,
	post_recovery: newreno_post_recovery,
	after_idle: newreno_after_idle,
};

void
newreno_ack_received(struct cc_var *ccv, uint16_t type)
{
	if (type == CC_ACK && !IN_RECOVERY(CCV(ccv, t_flags)) &&
			(ccv->flags & CCF_CWND_LIMITED)) {
		u_int cw = CCV(ccv, snd_cwnd);
		u_int incr = CCV(ccv, t_maxseg);

		/*
		 * Regular in-order ACK, open the congestion window.
		 * Method depends on which congestion control state we're
		 * in (slow start or cong avoid) and if ABC (RFC 3465) is
		 * enabled.
		 *
		 * slow start: cwnd <= ssthresh
		 * cong avoid: cwnd > ssthresh
		 *
		 * slow start and ABC (RFC 3465):
		 *   Grow cwnd exponentially by the amount of data
		 *   ACKed capping the max increment per ACK to
		 *   (abc_l_var * maxseg) bytes.
		 *
		 * slow start without ABC (RFC 5681):
		 *   Grow cwnd exponentially by maxseg per ACK.
		 *
		 * cong avoid and ABC (RFC 3465):
		 *   Grow cwnd linearly by maxseg per RTT for each
		 *   cwnd worth of ACKed data.
		 *
		 * cong avoid without ABC (RFC 5681):
		 *   Grow cwnd linearly by approximately maxseg per RTT using
		 *   maxseg^2 / cwnd per ACK as the increment.
		 *   If cwnd > maxseg^2, fix the cwnd increment at 1 byte to
		 *   avoid capping cwnd.
		 */
		if (cw > CCV(ccv, snd_ssthresh)) {
			if (V_tcp_do_rfc3465) {
				if (ccv->flags & CCF_ABC_SENTAWND)
					ccv->flags &= ~CCF_ABC_SENTAWND;
				else
					incr = 0;
			} else
				incr = max((incr * incr / cw), 1);
		} else if (V_tcp_do_rfc3465) {
			/*
			 * In slow-start with ABC enabled and no RTO in sight?
			 * (Must not use abc_l_var > 1 if slow starting after
			 * an RTO. On RTO, snd_nxt = snd_una, so the
			 * snd_nxt == snd_max check is sufficient to
			 * handle this).
			 *
			 * XXXLAS: Find a way to signal SS after RTO that
			 * doesn't rely on tcpcb vars.
			 */
			if (CCV(ccv, snd_nxt) == CCV(ccv, snd_max))
				incr = min(ccv->bytes_this_ack,
						V_tcp_abc_l_var * CCV(ccv, t_maxseg));
			else
				incr = min(ccv->bytes_this_ack, CCV(ccv, t_maxseg));
		}
		/* ABC is on by default, so incr equals 0 frequently. */
		if (incr > 0)
			CCV(ccv, snd_cwnd) = min(cw + incr, TCP_MAXWIN << WINDOW_SCALE);
	}
}

void
newreno_after_idle(struct cc_var *ccv)
{
	int rw;

	/*
	 * If we've been idle for more than one retransmit timeout the old
	 * congestion window is no longer current and we have to reduce it to
	 * the restart window before we can transmit again.
	 *
	 * The restart window is the initial window or the last CWND, whichever
	 * is smaller.
	 *
	 * This is done to prevent us from flooding the path with a full CWND at
	 * wirespeed, overloading router and switch buffers along the way.
	 *
	 * See RFC5681 Section 4.1. "Restarting Idle Connections".
	 */
	if (V_tcp_do_rfc3390)
		rw = min(4 * CCV(ccv, t_maxseg),
				max(2 * CCV(ccv, t_maxseg), 4380));
	else
		rw = CCV(ccv, t_maxseg) * 2;

	CCV(ccv, snd_cwnd) = min(rw, CCV(ccv, snd_cwnd));
}

/*
 * Perform any necessary tasks before we enter congestion recovery.
 */
void
newreno_cong_signal(struct cc_var *ccv, uint32_t type)
{
	u_int win;

	/* Catch algos which mistakenly leak private signal types. */
	KASSERT((type & CC_SIGPRIVMASK) == 0,
			("%s: congestion signal type 0x%08x is private\n", __func__, type));

	win = max(CCV(ccv, snd_cwnd) / 2 / CCV(ccv, t_maxseg), 2) *
		CCV(ccv, t_maxseg);

	switch (type) {
		case CC_NDUPACK:
			if (!IN_FASTRECOVERY(CCV(ccv, t_flags))) {
				if (!IN_CONGRECOVERY(CCV(ccv, t_flags)))
					CCV(ccv, snd_ssthresh) = win;
				ENTER_RECOVERY(CCV(ccv, t_flags));
			}
			break;
		case CC_ECN:
			if (!IN_CONGRECOVERY(CCV(ccv, t_flags))) {
				CCV(ccv, snd_ssthresh) = win;
				CCV(ccv, snd_cwnd) = win;
				ENTER_CONGRECOVERY(CCV(ccv, t_flags));
			}
			break;
	}
}

/*
 * Perform any necessary tasks before we exit congestion recovery.
 */
void
newreno_post_recovery(struct cc_var *ccv)
{
	if (IN_FASTRECOVERY(CCV(ccv, t_flags))) {
		/*
		 * Fast recovery will conclude after returning from this
		 * function. Window inflation should have left us with
		 * approximately snd_ssthresh outstanding data. But in case we
		 * would be inclined to send a burst, better to do it via the
		 * slow start mechanism.
		 *
		 * XXXLAS: Find a way to do this without needing curack
		 */
		if (SEQ_GT(ccv->curack + CCV(ccv, snd_ssthresh),
					CCV(ccv, snd_max)))
			CCV(ccv, snd_cwnd) = CCV(ccv, snd_max) -
				ccv->curack + CCV(ccv, t_maxseg);
		else
			CCV(ccv, snd_cwnd) = CCV(ccv, snd_ssthresh);
	}
}

