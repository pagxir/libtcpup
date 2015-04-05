#ifndef _DNS_TXASYNC_H_
#define _DNS_TXASYNC_H_

int dns_query_open(const char *, const char *, struct addrinfo *, tx_task_t *);
int dns_query_result(int dns_handle, struct addrinfo **result);
int dns_query_close(int dns_handle);

#endif
