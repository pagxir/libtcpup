#ifndef _TCP_CHANNEL_H_
#define _TCP_CHANNEL_H_

#ifdef __cplusplus
extern "C" {
#endif

void new_tcp_channel(int fd);
void tcp_channel_forward(struct sockaddr *in, socklen_t len);
void set_tcp_listen_address(struct tcpip_info *info);

#ifdef __cplusplus
}
#endif

#endif

