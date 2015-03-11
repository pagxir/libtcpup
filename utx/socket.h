#ifndef _UTX_SOCKET_H_
#define _UTX_SOCKET_H_

struct tcpcb;
void tcp_devbusy(struct tcpcb *tp);

void sorwakeup(struct tcpcb *socb);
void sowwakeup(struct tcpcb *socb);
void soisconnected(struct tcpcb *socb);
void soisdisconnected(struct tcpcb *socb);
void soisdisconnecting(struct tcpcb *socb);

enum {
    TCP_READ,
#define TCP_READ TCP_READ
    TCP_WRITE,
#define TCP_WRITE TCP_WRITE
    TCP_ACCEPT,
#define TCP_ACCEPT TCP_ACCEPT
};

struct tcpcb;
struct tcpcb *tcp_create(uint32_t conv);
struct tcpcb *tcp_create(int file, uint32_t conv);
struct tcpcb *tcp_accept(struct sockaddr_in *name, size_t *namlen);

int tcp_shutdown(struct tcpcb *tp);
int tcp_error(struct tcpcb *tp);
int tcp_soclose(struct tcpcb *tp);

/* symmetry open */
int tcp_listen(struct tcpcb *tp, u_long addr, u_short port);
int tcp_soname(struct tcpcb *tp, u_long *addr, u_short *port);

/* traditional socket function */
int tcp_connect(struct tcpcb *tp,
	   	const struct sockaddr_in *name, size_t namlen);
int tcp_write(struct tcpcb *tp, const void *buf, size_t len);
int tcp_read(struct tcpcb *tp, void *buf, size_t len);
int tcp_poll(struct tcpcb *tp, int typ, struct tx_task_t *task);

void run_tcp_free_hook(void);
void set_tcp_free_hook(void (*func)(void));

#endif

