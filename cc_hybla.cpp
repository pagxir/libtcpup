#include <stdio.h>
#include <stdint.h>
#include <limits.h>
#include <math.h>
#include <stdlib.h>

#include <utx/utxpl.h>
#include <utx/queue.h>

#include <tcpup/cc.h>
#include <tcpup/cc_cubic.h>
#include <tcpup/tcp.h>
#include <tcpup/tcp_seq.h>
#include <tcpup/tcp_var.h>
#include <tcpup/tcp_timer.h>

static int hybla_mod_init(void);
static int hybla_cb_init(struct cc_var *ccv);
static void hybla_cb_destroy(struct cc_var *ccv);
static void hybla_conn_init(struct cc_var *ccv);
static void hybla_post_recovery(struct cc_var *ccv);
static void hybla_cong_signal(struct cc_var *ccv, uint32_t type);
static void hybla_ack_received(struct cc_var *ccv, uint16_t type);

struct cc_algo hybla_cc_algo = {
	"hybla",
	mod_init: hybla_mod_init,
    	mod_destroy: NULL,
	cb_init: hybla_cb_init,
	cb_destroy: hybla_cb_destroy,
	conn_init: hybla_conn_init,
	ack_received: hybla_ack_received,
	cong_signal: hybla_cong_signal,
	post_recovery: hybla_post_recovery,
	after_idle: NULL,
};

struct hybla {
	uint8_t hybla_en;
	uint32_t snd_cwnd_cents; /* Keeps increment values when it is <1, <<7 */
	uint32_t rho;
	uint32_t rho2;
	uint32_t rho_31s;
	uint32_t rho2_71s;
	uint32_t minrtt_us;
	uint32_t snd_cwnd_cnt;
};

static int rtt0 = 37;
static inline void hybla_recalc_param(struct cc_var *ccv)
{
        struct hybla *ca;

	ca = (struct hybla *)ccv->cc_data;
	ca->rho_31s = max((CCV(ccv, t_srtt) >> TCP_DELTA_SHIFT)/rtt0, 8);
	ca->rho = ca->rho_31s >> 3;
	ca->rho2_71s = (ca->rho_31s * ca->rho_31s) << 1;
	ca->rho2 = ca->rho2_71s >> 7;
}

static void hybla_post_recovery(struct cc_var *ccv)
{
	if (newreno_cc_algo.post_recovery)
		newreno_cc_algo.post_recovery(ccv);
}

static void hybla_cong_signal(struct cc_var *ccv, uint32_t type)
{
        struct hybla *ca;

	if (newreno_cc_algo.cong_signal)
		newreno_cc_algo.cong_signal(ccv, type);
	ca = (struct hybla *)ccv->cc_data;
	ca->snd_cwnd_cnt = 0;
}

static void hybla_conn_init(struct cc_var *ccv)
{
        struct hybla *ca;
	ca = (struct hybla *)ccv->cc_data;

	ca->rho = 0;
	ca->rho2 = 0;
	ca->rho_31s = 0;
	ca->rho2_71s = 0;
	ca->snd_cwnd_cents = 0;
	ca->hybla_en = 1;
	CCV(ccv, snd_cwnd) = 2 * CCV(ccv, t_maxseg);

	hybla_recalc_param(ccv);

	ca->minrtt_us = CCV(ccv, t_srtt);
	CCV(ccv, snd_cwnd) = ca->rho * CCV(ccv, t_maxseg);
}

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof(*arr))

static inline uint32_t hybla_fraction(uint32_t odds)
{
	static const uint32_t fractions[] = {
		128, 139, 152, 165, 181, 197, 215, 234,
	};

	return (odds < ARRAY_SIZE(fractions))? fractions[odds]: 128;
}

static void hybla_ack_received(struct cc_var *ccv, uint16_t type)
{
        struct hybla *ca = (struct hybla *)ccv->cc_data;
	uint32_t increment, odd, rho_fractions;

	int is_slow_start = 0;
	u_int cw = CCV(ccv, snd_cwnd);
	u_int seg = CCV(ccv, t_maxseg);
	u_int incr = CCV(ccv, t_maxseg);

	if (CCV(ccv, t_srtt) < ca->minrtt_us) {
		hybla_recalc_param(ccv);
		ca->minrtt_us = CCV(ccv, t_srtt);
	}

	if (!(ccv->flags & CCF_CWND_LIMITED)) {
		return;
	}

	if (IN_RECOVERY(CCV(ccv, t_flags))) {
		return;
	}

	if (ca->rho == 0)
		hybla_recalc_param(ccv);


	rho_fractions = ca->rho_31s - (ca->rho << 3);

	if (cw <= CCV(ccv, snd_ssthresh)) {
		increment = ((1 << min(ca->rho, 16U)) *
			hybla_fraction(rho_fractions)) - 128;
		incr = (increment * seg) >> 7;
		is_slow_start = 1;
	} else {
		increment = (ca->rho2_71s * seg)/ cw;
		if (increment < 128) ca->snd_cwnd_cnt++;
	}

	odd = increment % 128;
	cw += (increment >> 7) * CCV(ccv, t_maxseg);
	ca->snd_cwnd_cents += odd;

	while (ca->snd_cwnd_cents >= 128) {
		cw += seg;
		ca->snd_cwnd_cents -= 128;
		ca->snd_cwnd_cnt = 0;
	}

	if (increment == 0 && odd == 0 &&
		ca->snd_cwnd_cnt * CCV(ccv, t_maxseg) >= cw) {
		cw += CCV(ccv, t_maxseg);
		ca->snd_cwnd_cnt = 0;
	}

	if (is_slow_start)
		cw = min(cw, CCV(ccv, snd_ssthresh) + 1);

	CCV(ccv, snd_cwnd) = min(cw, TCP_MAXWIN << WINDOW_SCALE);
	return;
}

static void hybla_cb_destroy(struct cc_var *ccv)
{

        if (ccv->cc_data != NULL)
                free(ccv->cc_data);
}

static int hybla_cb_init(struct cc_var *ccv)
{
        struct hybla *ca;

        ca = (struct hybla*)malloc(sizeof(struct hybla));//, M_HTCP, M_NOWAIT;

        if (ca == NULL)
                return (UTXENOMEM);
	memset(ca, 0, sizeof(*ca));
        ccv->cc_data = ca;

        return (0);
}

static int hybla_mod_init(void)
{

        // newreno_cc_algo.post_recovery;
	hybla_cc_algo.after_idle = newreno_cc_algo.after_idle;
        return (0);
}
