#include <utx/utxpl.h>
#include <utx/queue.h>

#include <tcpup/tcp_var.h>
#include <tcpup/tcp_var.h>
#include <tcpup/tcp_timer.h>

int tcp_maxpersistidle = TCPTV_KEEP_IDLE;

struct tcpcb *tcp_create(int file, uint32_t conv)
{
	struct tcpcb *tp;

	tp = tcp_newtcpcb(file, conv);
	UTXPL_ASSERT(tp != NULL);

	tp->t_flags &= ~SS_NOFDREF;
	tcp_attach(tp);

	return tp;
}

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

