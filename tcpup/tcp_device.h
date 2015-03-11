#ifndef _TCPUP_TCP_DEVICE_H_
#define _TCPUP_TCP_DEVICE_H_
struct tcpip_info;
extern "C" void tcp_backwork(struct tcpip_info *info);
extern "C" void tcp_set_device_address(struct tcpip_info *info);
#endif

