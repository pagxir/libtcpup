#ifndef _PSTCP_CHANNEL_H_
#define _PSTCP_CHANNEL_H_
struct sockcb;
struct tcpip_info;
void new_pstcp_channel(sockcb_t tp);
extern "C" void pstcp_channel_forward(struct tcpip_info *info);
#endif

