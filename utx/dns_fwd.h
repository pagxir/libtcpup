#ifndef _DNS_FWD_H_
#define _DNS_FWD_H_
struct tcpup_addr;
int filter_hook_dns_forward(int netif, void *buf, size_t len, const struct tcpup_addr *from);

int record_dns_packet(void *p, size_t l, int netif, const tcpup_addr *from);
int resolved_dns_packet(void *buf, const void *packet, size_t length, int *pnetif, struct tcpup_addr *from);
#endif
