#ifndef _TCPUP_TCP_DEVICE_H_
#define _TCPUP_TCP_DEVICE_H_

#ifdef __cplusplus
extern "C" {
#endif

struct tcpip_info;
void tcp_backwork(struct tcpip_info *info);
void tcp_set_outter_address(struct tcpip_info *info);
void tcp_set_device_address(struct tcpip_info *info);
void tcp_set_keepalive_address(struct tcpip_info *info);

#ifdef __cplusplus
}
#endif

#endif

