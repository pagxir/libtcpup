/*-
 * Copyright (c) 2009-2010
 *      Swinburne University of Technology, Melbourne, Australia
 * Copyright (c) 2010 Lawrence Stewart <lstewart@freebsd.org>
 * Copyright (c) 2010-2011 The FreeBSD Foundation
 * All rights reserved.
 *
 * This software was developed at the Centre for Advanced Internet
 * Architectures, Swinburne University of Technology, by David Hayes and
 * Lawrence Stewart, made possible in part by a grant from the Cisco University
 * Research Program Fund at Community Foundation Silicon Valley.
 *
 * Portions of this software were developed at the Centre for Advanced Internet
 * Architectures, Swinburne University of Technology, Melbourne, Australia by
 * David Hayes under sponsorship from the FreeBSD Foundation.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * An implementation of the Vegas congestion control algorithm for FreeBSD,
 * based on L. S. Brakmo and L. L. Peterson, "TCP Vegas: end to end congestion
 * avoidance on a global internet", IEEE J. Sel. Areas Commun., vol. 13, no. 8,
 * pp. 1465-1480, Oct. 1995. The original Vegas duplicate ack policy has not
 * been implemented, since clock ticks are not as coarse as they were (i.e.
 * 500ms) when Vegas was designed. Also, packets are timed once per RTT as in
 * the original paper.
 *
 * Originally released as part of the NewTCP research project at Swinburne
 * University of Technology's Centre for Advanced Internet Architectures,
 * Melbourne, Australia, which was made possible in part by a grant from the
 * Cisco University Research Program Fund at Community Foundation Silicon
 * Valley. More details are available at:
 *   http://caia.swin.edu.au/urp/newtcp/
 */

#include <stdio.h>
#include <stdint.h>
#include <math.h>
#include <time.h>
#include <stdlib.h>

#include <utx/utxpl.h>
#include <utx/queue.h>

#include <tcpup/cc.h>

#include <tcpup/tcp.h>
#include <tcpup/tcp_var.h>
#include <tcpup/tcp_debug.h>

#define CAST_PTR_INT(X) (*((int*)(X)))

/*
 * Private signal type for rate based congestion signal.
 * See <netinet/cc.h> for appropriate bit-range to use for private signals.
 */

static void     rateq_ack_received(struct cc_var *ccv, uint16_t ack_type);
static void     rateq_cb_destroy(struct cc_var *ccv);
static int      rateq_cb_init(struct cc_var *ccv);
static void     rateq_cong_signal(struct cc_var *ccv, uint32_t signal_type);
static void     rateq_conn_init(struct cc_var *ccv);
static int      rateq_mod_init(void);
static void 	rateq_after_idle(struct cc_var *ccv);
static void	rateq_post_recovery(struct cc_var *ccv);

struct rateq {
    int slow_start_toggle;
    int snd_cwnd_save;
};

static int TCPUP_PACING_RATE = 750000;

struct cc_algo rateq_cc_algo = {
    "rateq",
    mod_init: rateq_mod_init,
    mod_destroy: NULL,
    cb_init: rateq_cb_init,
    cb_destroy: rateq_cb_destroy,
    conn_init: rateq_conn_init,
    ack_received: rateq_ack_received,
    cong_signal: rateq_cong_signal,
    post_recovery: rateq_post_recovery,
    after_idle: rateq_after_idle
};

/*
 * The rateq window adjustment is done once every RTT, as indicated by the
 * ERTT_NEW_MEASUREMENT flag. This flag is reset once the new measurment data
 * has been used.
 */
static void
rateq_ack_received(struct cc_var *ccv, uint16_t ack_type)
{
    long rto;
    struct tcpcb *tp = ccv->tcp;

    rto = TCP_REXMTVAL(tp);

#if 0
    if (rto > 0 && !IN_FASTRECOVERY(CCV(ccv, t_flags)) &&
	    ccv->bytes_this_ack + tp->last_sacked > 0 &&
	    ack_type == CC_ACK && (ccv->flags & CCF_CWND_LIMITED)) {
	u_int snd_cwnd = CCV(ccv, snd_cwnd);
	u_int this_acked = ccv->bytes_this_ack + tp->last_sacked;
	u_int pacing_cwnd = rto * CCV(ccv, pacing_rate) / 1000;

	CCV(ccv, snd_cwnd) = min(snd_cwnd + this_acked, pacing_cwnd + 3 * tp->t_maxseg);
	return;
    }
#endif

    newreno_cc_algo.ack_received(ccv, ack_type);
}

void
rateq_after_idle(struct cc_var *ccv)
{
    return;
}

static void
rateq_cb_destroy(struct cc_var *ccv)
{
    if (ccv->cc_data != NULL)
	free(ccv->cc_data);
}

static int
rateq_cb_init(struct cc_var *ccv)
{
    struct rateq *rateq_data;
    rateq_data = (struct rateq *)calloc(1, sizeof(struct rateq));

    if (rateq_data == NULL)
	return (UTXENOMEM);

    CCV(ccv, pacing_rate) = TCPUP_PACING_RATE;
    TCP_DEBUG(1, "pacing rate: %d\n", CCV(ccv, pacing_rate));
    rateq_data->slow_start_toggle = 1;
    ccv->cc_data = rateq_data;
    return (0);
}

/*
 * If congestion has been triggered triggered by the Vegas measured rates, it is
 * handled here, otherwise it falls back to newreno's congestion handling.
 */
static void
rateq_cong_signal(struct cc_var *ccv, uint32_t signal_type)
{
    u_int win = CCV(ccv, snd_cwnd);
    u_int snd_ssthresh = CCV(ccv, snd_ssthresh);
    u_int fastrecovery = IN_FASTRECOVERY(CCV(ccv, t_flags));

    if (newreno_cc_algo.cong_signal)
	newreno_cc_algo.cong_signal(ccv, signal_type);

    long rto;
    struct tcpcb *tp = ccv->tcp;

    rto = TCP_REXMTVAL(tp);
#if 0
    if (signal_type == CC_NDUPACK && !fastrecovery) {
	TCP_DEBUG(1, "enter fast recovery: %d %p %d\n",
		tp->t_dupacks, TAILQ_FIRST(&tp->snd_holes), tp->filter_nboard);
	CCV(ccv, snd_ssthresh) = snd_ssthresh;
    }

    if (signal_type == CC_RTO_ERR) {
	TCP_DEBUG(1, "enter rto err recovery");
    }

    if (rto > 0 && signal_type == CC_RTO) {
	u_int pacing_cwnd = rto * CCV(ccv, pacing_rate) / 1000;

	CCV(ccv, snd_ssthresh) = pacing_cwnd;
	return;
    }
#endif

    return;
}

void
rateq_post_recovery(struct cc_var *ccv)
{
    long rto;
    struct tcpcb *tp = ccv->tcp;

    rto = TCP_REXMTVAL(tp);

#if 0
    if (IN_FASTRECOVERY(CCV(ccv, t_flags)) &&
	    rto > 0 && (ccv->flags & CCF_CWND_LIMITED)) {
	u_int pacing_cwnd = rto * CCV(ccv, pacing_rate) / 1000;

	CCV(ccv, snd_cwnd) = pacing_cwnd + tp->t_maxseg * 3;
	assert(pacing_cwnd  >= 0);
	return;
    }
#endif
    newreno_cc_algo.post_recovery(ccv);
}

static void
rateq_conn_init(struct cc_var *ccv)
{
    struct rateq *rateq_data;

    rateq_data = (struct rateq *)ccv->cc_data;
    rateq_data->slow_start_toggle = 1;

    long rto = TCP_REXMTVAL(ccv->tcp);
    if (rto > 0) {
	long snd_cwnd = rto * CCV(ccv, pacing_rate) / 1000;
	CCV(ccv, snd_cwnd) = max(snd_cwnd/CCV(ccv, t_maxseg), 2) * CCV(ccv, t_maxseg);
    }
}

static int
rateq_mod_init(void)
{
    int rate = TCPUP_PACING_RATE;
    const char *env_pacing_rate = getenv("PACING_RATE");

    if (env_pacing_rate)
	rate = atol(env_pacing_rate);

    if (rate > 8000)
	TCPUP_PACING_RATE = rate;

    return (0);
}
