#ifndef _PSTCP_CHANNEL_H_
#define _PSTCP_CHANNEL_H_
struct sockcb;
struct tcpip_info;
void new_pstcp_channel(sockcb_t tp);
extern "C" void pstcp_channel_forward(struct tcpip_info *info);

void NAT64_UPDATE(void *p, int *stat);
void NAT64_REVERT(void *p, int stat);
#endif

