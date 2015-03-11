#ifndef _PSTCP_CHANNEL_H_
#define _PSTCP_CHANNEL_H_
struct tcpcb;
struct tcpip_info;
void new_pstcp_channel(struct tcpcb *tp);
extern "C" void pstcp_channel_forward(struct tcpip_info *info);
#endif

