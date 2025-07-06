#ifndef _UTX_SOCKET_H_
#define _UTX_SOCKET_H_

enum SocketOps {
    SO_RECEIVE, SO_SEND, SO_ACCEPT, SO_CONNECT
};

typedef unsigned so_conv_t;
typedef struct sockcb *sockcb_t;
typedef struct tx_task_t tx_task_t;

sockcb_t solookup(so_conv_t conv);
sockcb_t sonewconn(int iface, so_conv_t conv, unsigned short link);

sockcb_t socreate(so_conv_t conv);
sockcb_t socreate(int file, so_conv_t conv);
sockcb_t soaccept(sockcb_t so, struct sockaddr *address, size_t *address_len);

int soconnected(sockcb_t so);
int soreadable(sockcb_t so);
int sowritable(sockcb_t so);
int soshutdown(sockcb_t so);

int soconnect(sockcb_t so, const struct sockaddr *address, size_t address_len);
int sooptset_target(sockcb_t so, void *buf, size_t len);
int sooptget_target(sockcb_t so, void *buf, size_t len);
int sopoll(sockcb_t so, SocketOps ops, tx_task_t *cb);

int sowrite(sockcb_t so, const void *buf, size_t len);
int soread(sockcb_t so, void *buf, size_t len);

int soerrno(sockcb_t so);
int soclose(sockcb_t so);

struct so_usrreqs {
    int (*so_attach)(sockcb_t so);
    int (*so_detach)(sockcb_t so);
    int (*so_connect)(sockcb_t so, const struct sockaddr *addr, size_t len);
    int (*so_accept)(sockcb_t so, struct sockaddr **addr);
    int (*so_close)(sockcb_t so);
};

extern struct so_usrreqs tcp_usrreqs;
#define SS_NOFDREF              0x0001
#define SS_ISCONNECTED          0x0002
#define SS_ISCONNECTING         0x0004
#define SS_ISDISCONNECTING      0x0008
#define SS_PROTOREF             0x4000  /* strong protocol reference */
#define SS_ISDISCONNECTED       0x2000
#define SS_ACCEPTABLE           0x1000

struct sockcb {
	int so_tag;
	union {
		void *data;
		struct tcpcb *tcp;
	} priv;
#define so_pcb priv.tcp

	int so_state;
	int so_count;
	int so_iface;
	unsigned short so_link;
	so_conv_t so_conv;
	struct so_usrreqs *usrreqs;
	LIST_ENTRY(sockcb) entries;
};

LIST_HEAD(sockcb_q, sockcb);

void sofree(sockcb_t so);

#ifdef TCPUP_LAYER
void tcp_devbusy(struct tcpcb *tp, tx_task_t *task);

void sorwakeup(struct tcpcb *socb);
void sowwakeup(struct tcpcb *socb);
void soisconnected(sockcb_t so);
void soisdisconnected(sockcb_t so);
void soisdisconnecting(sockcb_t so);

#define TCP_READ    SO_RECEIVE
#define TCP_WRITE   SO_SEND
#define TCP_ACCEPT  SO_ACCEPT
#define TCP_CONNECT SO_CONNECT

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

int tcp_relayget(struct tcpcb *tp, void *buf, int len);
int tcp_relayto(struct tcpcb *tp, void *buf, size_t len);

/* traditional socket function */
int tcp_connect(struct tcpcb *tp, const struct sockaddr_in *name);

int tcp_connected(struct tcpcb *tp);
int tcp_readable(struct tcpcb *tp);
int tcp_writable(struct tcpcb *tp);

int tcp_write(struct tcpcb *tp, const void *buf, size_t len);
int tcp_read(struct tcpcb *tp, void *buf, size_t len);
int tcp_poll(struct tcpcb *tp, int typ, struct tx_task_t *task);
#endif

void run_tcp_free_hook(void);
void set_tcp_free_hook(void (*func)(void));

#endif

