#include <utx/queue.h>
#include <utx/utxpl.h>

#include <tcpup/cc.h>
#include <tcpup/tcp.h>
#include <tcpup/tcp_var.h>
#include <tcpup/tcp_seq.h>

void hybla0_ack_received(struct cc_var *ccv, uint16_t type);
void hybla0_after_idle(struct cc_var *ccv);
void hybla0_cong_signal(struct cc_var *ccv, uint32_t type);
void hybla0_post_recovery(struct cc_var *ccv);

static int P = 8; //200
static int PxP = 64; //200
static int _2P_1 = 127; //200

struct cc_algo hybla0_cc_algo = {
	"hybla0",
	mod_init: NULL,
    	mod_destroy: NULL,
	cb_init: NULL,
	cb_destroy: NULL,
	conn_init: NULL,
	ack_received: hybla0_ack_received,
	cong_signal: hybla0_cong_signal,
	post_recovery: hybla0_post_recovery,
	after_idle: hybla0_after_idle,
};

void
hybla0_ack_received(struct cc_var *ccv, uint16_t type)
{
	if (type == CC_ACK && !IN_RECOVERY(CCV(ccv, t_flags)) &&
			(ccv->flags & CCF_CWND_LIMITED)) {
		u_int cw = CCV(ccv, snd_cwnd);
		u_int incr = CCV(ccv, t_maxseg);

		if (cw > CCV(ccv, snd_ssthresh)) {
			incr = max((PxP * incr * incr / cw), 1);
		} else {
			incr = min(ccv->bytes_this_ack * _2P_1, incr * _2P_1);
			if (incr + cw > CCV(ccv, snd_ssthresh))
				incr = min(ccv->bytes_this_ack, incr);
		}
		/* ABC is on by default, so incr equals 0 frequently. */
		if (incr > 0)
			CCV(ccv, snd_cwnd) = min(cw + incr, TCP_MAXWIN << WINDOW_SCALE);
	}
}

void
hybla0_after_idle(struct cc_var *ccv)
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
hybla0_cong_signal(struct cc_var *ccv, uint32_t type)
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
hybla0_post_recovery(struct cc_var *ccv)
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

