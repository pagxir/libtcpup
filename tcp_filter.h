#ifndef _TCP_FILTER_H
#define _TCP_FILTER_H

struct tcp_hhook_data;
int get_filter_win(struct tcpcb *tp);
int tcp_filter_xmit(struct tcpcb *tp);
int tcp_filter_free(struct tcpcb *tp);
int tcp_filter_in(struct tcp_hhook_data *hhook_data);
int tcp_filter_out(struct tcp_hhook_data *hhook_data);

#endif
