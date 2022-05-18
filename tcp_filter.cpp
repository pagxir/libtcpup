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

#define TXSI_SACKED 1

void tcp_sack_mark_loss(struct tcpcb *tp, tcp_seq seq, size_t len);

int is_sacked(struct tcpcb *tp, tcp_seq seq, size_t len)
{
    int j;
    struct sackblk sack1;

    for (j = 0; j < tp->filter_nboard; j++) {
	sack1 = tp->filter_board[j];
	if (SEQ_GEQ(seq, sack1.start) &&
		SEQ_GEQ(sack1.end, seq + len)) {
	    return 1;
	}
    }
	
    return 0;
}

int tcp_filter_out(struct tcp_hhook_data *ctx_data)
{
    struct tcpcb *tp;
    struct tcphdr *th;
    struct tcpopt *to;
    struct txseginfo *txsi;
    struct tcp_hhook_data *thdp;
    long len;
    int tso;

    thdp = ctx_data;
    tp = thdp->tp;
    th = thdp->th;
    to = thdp->to;
    len = thdp->len;
    tso = thdp->tso;

    if (len == 0) {
	return 0;
    }

    if (is_sacked(tp, ntohl(th->th_seq), len)) {
	assert(tso || SEQ_LT(ntohl(th->th_seq), tp->snd_recover));
	return 0;
    }

    txsi = (struct txseginfo *)malloc(sizeof(*txsi));
    if (txsi == NULL) {
	assert(0);
	return 0;
    }

    /* Construct txsi setting the necessary flags. */
    txsi->flags = 0; /* Needs to be initialised. */
    txsi->seq = ntohl(th->th_seq);
    txsi->len = len;
    txsi->tsloss = 0;
    txsi->sacked = th->th_win;

    txsi->tx_ts = (to->to_tsval) - tp->ts_offset;
    txsi->rx_ts = (to->to_tsecr);

    if (tso || SEQ_LT(txsi->seq, tp->snd_recover)) 
	TAILQ_INSERT_TAIL(&tp->txsegi_rexmt_q, txsi, txsegi_lnk);
    else
	TAILQ_INSERT_TAIL(&tp->txsegi_xmt_q, txsi, txsegi_lnk);

    tcp_filter_xmit(tp);
    return 1;
}

int tcp_filter_in(struct tcp_hhook_data *ctx_data)
{
    struct tcpcb *tp;
    struct tcphdr *th;
    struct tcpopt *to;
    struct txseginfo *txsi, *n_txsi;
    struct tcp_hhook_data *thdp;
    struct sackblk sack;
    long len;
    int tso;
    int i, j;

    thdp = ctx_data;
    tp = thdp->tp;
    th = thdp->th;
    to = thdp->to;
    len = thdp->len;
    tso = thdp->tso;

    tp->last_sacked = 0;
    if (tp->snd_max == th->th_ack) {
	tp->filter_nboard = 0;
	tcp_filter_free(tp);
	return 0;
    }

    if (to->to_flags & TOF_SACK) {
	int old_sacked = 0, new_sacked = 0;
	struct sackblk sack0, sack1;

	for (j = 0; j < tp->filter_nboard; j++) {
	    sack1 = tp->filter_board[j];
	    old_sacked += (sack1.end - sack1.start);
	}

	for (i = 0; i < to->to_nsacks; i++) {
	    bcopy((to->to_sacks + i * TCPOLEN_SACK),
		    &sack, sizeof(sack));
	    sack.start = ntohl(sack.start);
	    sack.end = ntohl(sack.end);

	    txsi = TAILQ_FIRST(&tp->txsegi_rexmt_q);
	    while (txsi != NULL) {
		if (SEQ_GEQ(txsi->seq, sack.start) &&
			SEQ_GEQ(sack.end, txsi->seq + txsi->len) && !(txsi->flags & TXSI_SACKED)) {
		    if (tp->sackhint.sack_bytes_rexmit > txsi->len)
			tp->sackhint.sack_bytes_rexmit -= txsi->len;
		    txsi->flags |= TXSI_SACKED;
		}
		txsi = TAILQ_NEXT(txsi, txsegi_lnk);
	    }

	    int num = 0;
	    sack0 = sack;

	    for (j = 0; j < tp->filter_nboard; j++) {
		sack1 = tp->filter_board[j];
		if (SEQ_GEQ(th->th_ack, sack1.start)) {
		    continue;
		}

		if (SEQ_LT(sack0.end, sack1.start)) {
		    tp->filter_board[num++] = sack1;
		    continue;
		}

		if (SEQ_LT(sack1.end, sack0.start)) {
		    tp->filter_board[num++] = sack1;
		    continue;
		}

		if (SEQ_LT(sack1.start, sack0.start)) {
		    sack0.start = sack1.start;
		}

		if (SEQ_LT(sack0.end, sack1.end)) {
		    sack0.end = sack1.start;
		}
	    }

	    tp->filter_nboard = num;
	    if (SEQ_LT(th->th_ack, sack0.start)) {
		assert(num < 1024);
		tp->filter_board[num++] = sack0;
		tp->filter_nboard = num;
	    }
	}

	for (j = 0; j < tp->filter_nboard; j++) {
	    sack1 = tp->filter_board[j];
	    new_sacked += (sack1.end - sack1.start);
	}

	if (new_sacked > old_sacked) {
	    tp->last_sacked = (new_sacked - old_sacked);
	}
    }

    return 0;
}

static int total = 0;

int pacing_check(struct tcpcb *tp, u_int64_t pacing)
{
    if (tp->pacing_rate == 0) {
	return 0;
    }

    unsigned ticks = tx_getticks();
    unsigned mypace = (pacing >> PACING_SHIFT);

    return TSTMP_GT(mypace, ticks);
}

int pacing_adjust(struct tcpcb *tp, u_int64_t *pacing, size_t datalen)
{
    if (tp->pacing_rate == 0) {
	return 0;
    }

    tx_loop_t *loop = tx_loop_default();
    static unsigned _last_mstamp = 0;
    static unsigned _next_mstamp = 0;
    static unsigned _last_upcount = 0;

    *pacing += (((datalen * 1000ull) << PACING_SHIFT) / tp->pacing_rate);
    if (_last_mstamp != 0 && TSTMP_GT(_last_mstamp - 1, (unsigned)(*pacing >> PACING_SHIFT))) {
	*pacing = _last_mstamp;
	*pacing <<= PACING_SHIFT;
    }

    if (loop->tx_upcount != _last_upcount) {
	_last_upcount = loop->tx_upcount;
	_last_mstamp = _next_mstamp;
	_next_mstamp = ticks;
    }

    return 0;
}

tcp_seq update_ckpass(const rgn_iovec iov[], size_t count);

static void tcp_filter_output(struct tcpcb *tp, struct txseginfo *txsi)
{
	tcp_seq seq;
	long len, off, optlen;
	struct tcphdr *th;
	struct tcpopt to = {0};
	rgn_iovec iobuf[4] = {};
	char th0_buf[sizeof(tcphdr) + 80];

	iobuf[0].iov_base = th0_buf;
	iobuf[0].iov_len  = sizeof(*th);
	th = (struct tcphdr *)th0_buf;

	len = txsi->len;
	seq = txsi->seq;
	off = txsi->seq - tp->snd_una;

	if ((txsi->flags & TXSI_SACKED)
		|| SEQ_GEQ(tp->snd_una, seq + len)) {
	
	    return;
	}

	if (SEQ_LT(seq, tp->snd_una)) {
	    len = (txsi->seq + txsi->len - tp->snd_una);
	    seq = tp->snd_una;
	    off = 0;
	}

	int flags = tcp_outflags[tp->t_state];

	to.to_flags = 0;
	/* Maximum segment size. */
	if (flags & TH_SYN) {
	    to.to_mss = tp->t_maxseg;
	    to.to_flags |= TOF_MSS;
	}

	if ((flags & TH_SYN) && tp->relay_len > 0) {
	    to.to_flags |= TOF_DESTINATION;
	    to.to_dsaddr = tp->relay_target;
	    to.to_dslen = tp->relay_len;
	}

	if (tp->rcv_numsacks > 0) {
	    to.to_flags |= TOF_SACK;
	    to.to_nsacks = tp->rcv_numsacks;
	    to.to_sacks = (u_char *)tp->sackblks;
	}

	if (tp->t_rtttime == txsi->tx_ts &&
		tp->t_rtseq == txsi->seq) {
	    tp->t_rtttime = ticks;
	}

	if (SEQ_LT(seq + len,
		    tp->snd_una + rgn_len(tp->rgn_snd))) {
	    flags &= ~TH_FIN;
	}

	if (txsi->seq == tp->snd_rto &&
		tcp_timer_active(tp, TT_REXMT)) {
	    tcp_timer_activate(tp, TT_REXMT, tp->t_rxtcur);
	}

	to.to_flags |= TOF_TS;
	to.to_tsval = (tcp_snd_getticks);
	to.to_tsecr = (tp->ts_recent);

	optlen = tcp_addoptions(&to, (u_char *)(th + 1));
	if (len + optlen > tp->t_maxseg) {
	    assert(to.to_nsacks > 0);
	    to.to_flags &= ~TOF_SACK; 
	    to.to_tsval = (tcp_snd_getticks);
	    to.to_tsecr = (tp->ts_recent);
	    optlen = tcp_addoptions(&to, (u_char *)(th + 1));
	}

	iobuf[0].iov_base = (char *)th;
	iobuf[0].iov_len  = sizeof(*th) + optlen;
	rgn_peek(tp->rgn_snd, iobuf + 1, len, off);

	th->th_magic = MAGIC_UDP_TCP;
	th->th_opten = (optlen >> 2);
	th->th_seq = htonl(seq);
	th->th_ack = htonl(tp->rcv_nxt);
	th->th_flags = flags;
	th->th_conv  = (tp->tp_socket->so_conv);
	th->th_win   = htons((tp->rcv_adv - tp->rcv_nxt) >> WINDOW_SCALE);
	th->th_ckpass	= 0;
	th->th_ckpass = update_ckpass(iobuf, 3);

	assert(len + optlen <= tp->t_maxseg);
	utxpl_output(tp->tp_socket->so_iface, iobuf, 3, &tp->dst_addr);
	pacing_adjust(tp, &tp->t_pacing, len + optlen);
	total++;

	return;
}

int tcp_filter_xmit(struct tcpcb *tp)
{
    struct txseginfo *txsi;

    do {

	if (pacing_check(tp, tp->t_pacing)) {
	    tcp_devbusy(tp, &tp->t_event_devbusy);
	    return 0;
	}

	txsi = TAILQ_FIRST(&tp->txsegi_rexmt_q);
	if (txsi != NULL) {
            TAILQ_REMOVE(&tp->txsegi_rexmt_q, txsi, txsegi_lnk);
	    tcp_filter_output(tp, txsi);
	    free(txsi);
	    continue;
	}

	txsi = TAILQ_FIRST(&tp->txsegi_xmt_q);
	if (txsi != NULL) {
            TAILQ_REMOVE(&tp->txsegi_xmt_q, txsi, txsegi_lnk);
	    tcp_filter_output(tp, txsi);
	    free(txsi);
	    continue;
	}

	tcp_cancel_devbusy(tp);
	break;
    } while (1);

    return 0;
}

int tcp_filter_free(struct tcpcb *tp)
{
    struct txseginfo *txsi;

    txsi = TAILQ_FIRST(&tp->txsegi_rexmt_q);
    while (txsi != NULL) {
	TAILQ_REMOVE(&tp->txsegi_rexmt_q, txsi, txsegi_lnk);
	free(txsi);
	txsi = TAILQ_FIRST(&tp->txsegi_rexmt_q);
    }

    txsi = TAILQ_FIRST(&tp->txsegi_xmt_q);
    while (txsi != NULL) {
	TAILQ_REMOVE(&tp->txsegi_xmt_q, txsi, txsegi_lnk);
	free(txsi);
	txsi = TAILQ_FIRST(&tp->txsegi_xmt_q);
    }

    return 0;
}

int tcp_filter_lost(struct tcpcb *tp, int *retp)
{
    int count = 0, retrans = 0;
    struct txseginfo *txsi, *n_txsi;

#if 0
    txsi = TAILQ_FIRST(&tp->txsegi_q);
    while (txsi != NULL) {
	n_txsi = TAILQ_NEXT(txsi, txsegi_lnk);
	if (SEQ_GEQ(tp->snd_una, txsi->seq + txsi->len)) {
	    TAILQ_REMOVE(&tp->txsegi_q, txsi, txsegi_lnk);
	    free(txsi);
	    txsi = n_txsi;
	    continue;
	}

	if (txsi->sacked & TCPCB_LOST) {
	    count++;
	}

	txsi = n_txsi;
	retrans++;
    }

    if (retp) *retp = retrans;
#endif

    return 0;
}
