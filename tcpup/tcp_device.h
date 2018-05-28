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

#if IF_DEV 
struct if_dev_cb {
    int head_size;
    int (* output)(int offset, rgn_iovec *iov, size_t count, struct tcpup_addr const *name);
    int (* set_filter)(FILTER_HOOK *hook);
    sockcb_t (* socreate)(so_conv_t conv);
    void (* dev_busy)(struct tcpcb *tp);
    void (* reply_mode)(int mode);
    void (* device_address)(struct tcpip_info *info);
    void (* outter_address)(struct tcpip_info *info);
    void (* keepalive_address)(struct tcpip_info *info);
};
#endif

#endif

