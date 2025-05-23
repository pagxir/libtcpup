/*-
 * Copyright (c) 1982, 1986, 1993, 1995
 *      The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *      @(#)tcp_seq.h   8.3 (Berkeley) 6/21/95
 * $FreeBSD: head/sys/netinet/tcp_seq.h 231767 2012-02-15 16:09:56Z bz $
 */

#ifndef _TCPUP_TCP_SEQ_H_
#define _TCPUP_TCP_SEQ_H_
/*
 * TCP sequence numbers are 32 bit integers operated
 * on with modular arithmetic.  These macros can be
 * used to compare such integers.
 */
#define SEQ_LT(a,b)     ((int)((a)-(b)) < 0)
#define SEQ_LEQ(a,b)    ((int)((a)-(b)) <= 0)
#define SEQ_GT(a,b)     ((int)((a)-(b)) > 0)
#define SEQ_GEQ(a,b)    ((int)((a)-(b)) >= 0)

#define SEQ_MIN(a, b)   ((SEQ_LT(a, b)) ? (a) : (b))
#define SEQ_MAX(a, b)   ((SEQ_GT(a, b)) ? (a) : (b))

/* for modulo comparisons of timestamps */
#define TSTMP_LT(a,b)   ((int)((a)-(b)) < 0)
#define TSTMP_GT(a,b)   ((int)((a)-(b)) > 0)
#define TSTMP_GEQ(a,b)  ((int)((a)-(b)) >= 0)

/*
 * Macros to initialize tcp sequence numbers for
 * send and receive from initial send and receive
 * sequence numbers.
 */
#define tcp_rcvseqinit(tp) \
        (tp)->rcv_adv = (tp)->rcv_nxt = (tp)->irs + 1

#define tcp_sendseqinit(tp) \
        (tp)->snd_una = (tp)->snd_nxt = (tp)->snd_max = (tp)->snd_up = \
            (tp)->snd_max_out = (tp)->snd_recover = (tp)->iss

/*
 * Clock macros for RFC 1323 timestamps.
 */
#define TCP_TS_TO_TICKS(_t)     ((_t) * hz / 1000)

/* Timestamp wrap-around time, 24 days. */
#define TCP_PAWS_IDLE   (24 * 24 * 60 * 60 * 1000)

#define tcp_ts_getticks tx_getticks
#define tcp_snd_getticks  tx_getticks()

#endif /* _TCPUP_TCP_SEQ_H_ */

