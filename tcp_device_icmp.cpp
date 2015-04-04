#include <time.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>
#include <stdarg.h>
#include <stdlib.h>
#include <strings.h>
#include <netinet/ip.h>

#include <wait/module.h>
#include <wait/platform.h>
#include <wait/slotwait.h>
#include <wait/slotsock.h>

#include <utx/utxpl.h>
#include <utx/socket.h>

#include <tcpup/tcp_subr.h>
#include <tcpup/tcp_debug.h>

#include <pstcp_stun.h>
#include "tcp_channel.h"

#define ICMPCODE_MAGIC 0
#define ICMP_MAGIC_CLIENT 0xBEEFDEAD
#define ICMP_MAGIC_SERVER 0xDEADDEAD

static int _file = -1;
static struct sockcb *_sockcbp;

static struct waitcb _stop;
static struct waitcb _event;
static struct waitcb _start;
static struct waitcb _dev_idle;
static struct waitcb *_dev_busy = 0;
static int _tcp_dev_busy = 0;
static struct sockaddr_in _addr_in;
static void listen_statecb(void *context);
static void listen_callback(void *context);

int tcp_busying(void)
{
	return _tcp_dev_busy;
}

#define ICMP_MODE_SERVER 0
#define ICMP_MODE_CLIENT 1
#define ICMP_SIZE_WHEEL  78

static int _icmp_mode = 0;
static int _icmp_left = 0;
static int _icmp_cached = 0;
static int _icmp_valecr = 0;
static int _icmp_polling = 0;
static int _icmp_last_rcv = 0;

static int _icmp_last_id = 0;
static int _icmp_last_idup = 0;
static int _icmp_last_seq = 0;
static int _icmp_last_sdup = 0;

static int _icmp_ticks[ICMP_SIZE_WHEEL] = {0};
static unsigned int _icmp_pair[ICMP_SIZE_WHEEL] = {0};

struct icmphdr {
	unsigned char type;
	unsigned char code;
	unsigned short checksum;
	union {
		unsigned int pair;
		struct {
			unsigned short ident;
			unsigned short seqno;
		};
	} u0;
	unsigned int   valecr;
	unsigned int   magic;
};

int set_icmp_mode(int mode, int polling)
{
	_icmp_mode = mode;
	_icmp_polling = polling;
	return 0;
}

struct tcpcb;
struct tcpcb *tcp_create(uint32_t conv)
{
	int fildes = _file;
	return tcp_create(fildes, conv);
}

static void dev_idle_callback(void *uup)
{
	struct waitcb *evt;

	_tcp_dev_busy = 0;
	while (_dev_busy != NULL &&
			_tcp_dev_busy == 0) {
		evt = _dev_busy;
		evt->wt_callback(evt->wt_udata);
	}

	return ;
}


static struct sockaddr_in _tcp_dev_addr = { 0 };
extern "C" void tcp_set_device_address(struct tcpip_info *info)
{
	_tcp_dev_addr.sin_family = AF_INET;
	_tcp_dev_addr.sin_port   = (info->port);
	_tcp_dev_addr.sin_addr.s_addr   = (info->address);
	return;
}

static void module_init(void)
{
	int error;

	memcpy(&_addr_in, &_tcp_dev_addr, sizeof(_addr_in));
	_addr_in.sin_family = AF_INET;

	waitcb_init(&_event, listen_callback, NULL);
	waitcb_init(&_stop, listen_statecb, (void *)0);
	waitcb_init(&_start, listen_statecb, (void *)1);
	waitcb_init(&_dev_idle, dev_idle_callback, NULL);

	_file = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	assert(_file != -1);

	error = bind(_file, (struct sockaddr *)&_addr_in, sizeof(_addr_in));
	assert(error == 0);

	if (_addr_in.sin_port == 0) {
		socklen_t addr_len = sizeof(_tcp_dev_addr);
		getsockname(_file, (struct sockaddr *)&_tcp_dev_addr, &addr_len);
		fprintf(stderr, "bind@address# %s:%u\n",
				inet_ntoa(_tcp_dev_addr.sin_addr), htons(_tcp_dev_addr.sin_port));
	}

	_sockcbp = sock_attach(_file);
	slotwait_atstart(&_start);
	slotwait_atstop(&_stop);
	stun_client_init(_file);

#ifndef WIN32
	int l = fcntl(_file, F_GETFL);
	fcntl(_file, F_SETFL, l & ~O_NONBLOCK);
#else
    int bufsize = 1024 * 1024;
    setsockopt(_file, SOL_SOCKET, SO_SNDBUF, (char *)&bufsize, sizeof(bufsize));
    setsockopt(_file, SOL_SOCKET, SO_RCVBUF, (char *)&bufsize, sizeof(bufsize));
#endif
}

static void listen_statecb(void *context)
{
	int state;
	socklen_t addr_len;
	struct sockaddr_in addr_in;

	state = (int)(long)context;
	switch (state) {
		case 1:
			addr_len = sizeof(addr_in);
			getsockname(_file, (struct sockaddr *)&addr_in, &addr_len);
			fprintf(stderr, "bind!address# %s:%u\n",
				   	inet_ntoa(addr_in.sin_addr), htons(addr_in.sin_port));
			waitcb_switch(&_event);
			break;

		case 0:
			waitcb_cancel(&_event);
			break;

		default:
			break;
	}

	return;
}

int ticks = 0;
static short _udp_len[1024];
static char _udp_buf[1024 * 1024 * 8];

static void listen_callback(void *context)
{
	int len;
	socklen_t addr_len;
	struct sockaddr_in addr_in;
	struct {
		struct ip u0;
		struct icmphdr u1;
	} icmphdr0;

	TCP_DEBUG_TRACE(sizeof(icmphdr0) != 36, "Hello World %d\n", sizeof(icmphdr0));

	if (waitcb_completed(&_event)) {
		int ct = 0;
		int filling = 0;
		struct tcpup_addr ta0;
		char *c_buf = _udp_buf;
		ticks = tx_getticks();

		while (ct < 1024) {
		   	addr_len = sizeof(addr_in);
		   	len = recvfrom(_file, c_buf, 1500,
				   	MSG_DONTWAIT, (struct sockaddr *)&addr_in, &addr_len);
			if (len == -1)
				break;

#if 0
			if (len > 0) {
				stun_client_input(c_buf, len, &addr_in);
				TCP_DEBUG_TRACE(len <  20, "small packet drop: %s:%d\n", inet_ntoa(addr_in.sin_addr), htons(addr_in.sin_port));
			}
#endif
			memcpy(&icmphdr0, c_buf, sizeof(icmphdr0));
			if (icmphdr0.u1.code == ICMPCODE_MAGIC) {
				unsigned int valecr, seqno, win, index, test;
				if (_icmp_mode == ICMP_MODE_SERVER &&
					icmphdr0.u1.type == 0x08 && icmphdr0.u1.magic == ICMP_MAGIC_CLIENT) {
					int reset = 0;
					if (_icmp_last_id != icmphdr0.u1.u0.ident) {
						reset += (_icmp_last_idup > 10);
						_icmp_last_idup = 0;
					}

					if (_icmp_last_seq != icmphdr0.u1.u0.seqno) {
						reset += (_icmp_last_sdup > 10);
						_icmp_last_sdup = 0;
					}

					_icmp_last_id = icmphdr0.u1.u0.ident;
					_icmp_last_idup++;

					_icmp_last_seq = icmphdr0.u1.u0.seqno;
					_icmp_last_sdup++;

					if ((int)(ticks - _icmp_last_rcv) > 1000 || reset > 0) {
						_icmp_last_rcv = 0;
						_icmp_cached = 0;
						_icmp_left = 0;
					}

					if (_icmp_cached < ICMP_SIZE_WHEEL) {
						index  = (_icmp_left + _icmp_cached) % ICMP_SIZE_WHEEL;
						_icmp_cached++;
					} else {
						index  = (_icmp_left + _icmp_cached) % ICMP_SIZE_WHEEL;
						_icmp_left++;
					}

					valecr = htonl(icmphdr0.u1.valecr);
					_icmp_ticks[index] = ticks;
					_icmp_pair[index]  = icmphdr0.u1.u0.pair;
					if ((_icmp_valecr - valecr) & 0x800000 ||
						(int)(ticks - _icmp_last_rcv) < 1000 || _icmp_last_rcv == 0) {
						_icmp_last_rcv = ticks;
						_icmp_valecr = valecr;
					}
				} else if (_icmp_mode == ICMP_MODE_CLIENT &&
						icmphdr0.u1.type == 0x00 && icmphdr0.u1.magic == ICMP_MAGIC_SERVER) {
					valecr = htonl(icmphdr0.u1.valecr);
					win    = (valecr >> 24) & 0xff;
					seqno  = (valecr & 0xffffff);

					memcpy(ta0.name, &addr_in, addr_len);
					ta0.namlen = addr_len;

					test = (_icmp_left - seqno) & 0xffffff;
					TCP_DEBUG_TRACE((test & 0x800000), "seq is bad");
					if (test + win < 76) {
						filling = 1;
					}
				} else {
					TCP_DEBUG_TRACE(1, "incorrect icmp mode\n");
					continue;
				}

				if (len >= 20 + sizeof(icmphdr0)) {
					_udp_len[ct++] = len;
					c_buf += len;
				}
			}
		}

		c_buf = _udp_buf;
		for (int i = 0; i < ct; i++) {
			TCP_DEBUG_TRACE(_udp_len[i] < sizeof(icmphdr0), "BAD length %d", _udp_len[i]);
			int handled = tcpup_do_packet(_file, c_buf + sizeof(icmphdr0), _udp_len[i] - sizeof(icmphdr0), &addr_in, addr_len);
			TCP_DEBUG_TRACE(handled == 0, "error packet drop: %s:%d\n", inet_ntoa(addr_in.sin_addr), htons(addr_in.sin_port));
			c_buf += _udp_len[i];
			handled = handled;
		}

		utxpl_output(_file, NULL, 0, &ta0);
		if (filling == 1)
			utxpl_output(_file, NULL, 0, &ta0);

		waitcb_clear(&_event);
	}

	sock_read_wait(_sockcbp, &_event);
	return;
}

static void module_clean(void)
{
	fprintf(stderr, "udp_listen: exiting\n");
	waitcb_clean(&_dev_idle);
	waitcb_clean(&_event);
	waitcb_clean(&_start);
	waitcb_clean(&_stop);
	sock_detach(_sockcbp);
	closesocket(_file);
}

extern "C" void tcp_backwork(struct tcpip_info *info)
{
#if 0
	struct sockaddr_in addr_in1;
	addr_in1.sin_family = AF_INET;
	addr_in1.sin_port   = info->port;
	addr_in1.sin_addr.s_addr   = info->address;

	sendto(_file, "HELO", 4, 0,
			(struct sockaddr *)&addr_in1, sizeof(addr_in1));
#endif

	return;
}

void __utxpl_assert(const char *expr, const char *path, size_t line)
{
	fprintf(stderr, "ASSERT FAILURE: %s:%ld %s\n", path, line, expr);
	*(char *)0 = 0;
	exit(-1);
	return;
}

static void icmp_update_checksum(unsigned char *st, struct iovec *vecs, size_t count)
{
	int index = 0;
	unsigned short *digit;
	unsigned long cksum = 0;
	unsigned short cksum1 = 0;

	if (st != NULL) memset(st, 0, 2);

	for (int i = 0; i < count; i++) {
		size_t len = vecs[i].iov_len;
		unsigned char *adj = (unsigned char *)vecs[i].iov_base;

		for (int j = 0; j < len; j++) {
			cksum += (((int)adj[j]) << ((index & 0x01) << 3));
			index++;
		}
	}

	cksum1 = (cksum >> 16);
	while (cksum1 > 0) {
		cksum  = cksum1 + (cksum & 0xffff); 
		cksum1 = (cksum >> 16);
	}

	cksum = (~cksum);
	if (st != NULL) memcpy(st, &cksum, 2);

	return;
}

int utxpl_output(int fd, rgn_iovec *iov, size_t count, struct tcpup_addr const *name)
{
	int error;
	struct icmphdr icmphdr0;

#ifndef WIN32
	struct msghdr msg0;
	struct iovec  iovecs[10];
	iovecs[0].iov_len = sizeof(icmphdr0);
	iovecs[0].iov_base = &icmphdr0;
	memcpy(iovecs + 1, iov, count * sizeof(iovecs[0]));

	if (_icmp_mode == ICMP_MODE_CLIENT) {
		_icmp_left++;
		icmphdr0.type = 0x08;
		icmphdr0.code = ICMPCODE_MAGIC;
		icmphdr0.u0.ident = 0;
		icmphdr0.u0.seqno = htons(_icmp_left);
		icmphdr0.valecr = htonl(_icmp_left & 0xffffff);
		icmphdr0.magic  = ICMP_MAGIC_CLIENT;
		icmp_update_checksum((unsigned char *)&icmphdr0.checksum, iovecs, count + 1);
	} else if (_icmp_mode == ICMP_MODE_SERVER) {
		icmphdr0.type = 0x00;
		icmphdr0.code = ICMPCODE_MAGIC;
		TCP_DEBUG_TRACE(_icmp_cached <= 0, "no usable icmp response");

		if (_icmp_cached > 1) {
			icmphdr0.u0.pair = _icmp_pair[_icmp_left++ % ICMP_SIZE_WHEEL];
			_icmp_cached--;
		} else {
			icmphdr0.u0.pair = _icmp_pair[_icmp_left % ICMP_SIZE_WHEEL];
		}
		icmphdr0.valecr = htonl((_icmp_valecr & 0xffffff) | (_icmp_cached << 24));
		icmphdr0.magic  = ICMP_MAGIC_SERVER;
		icmp_update_checksum((unsigned char *)&icmphdr0.checksum, iovecs, count + 1);
	}

	TCP_DEBUG_TRACE(_icmp_mode != ICMP_MODE_SERVER && _icmp_mode != ICMP_MODE_CLIENT, "_icmp_mode not correctly");

	msg0.msg_name = (void *)name->name;
	msg0.msg_namelen = name->namlen;
	msg0.msg_iov  = iovecs;
	msg0.msg_iovlen = count + 1;

	msg0.msg_control = NULL;
	msg0.msg_controllen = 0;
	msg0.msg_flags = 0;
	error = sendmsg(fd, &msg0, 0);
#else
	DWORD transfer = 0;
	error = WSASendTo(fd, (LPWSABUF)iov, count, &transfer, 0,
			(const sockaddr *)name->name, name->namlen, NULL, NULL);
	error = (error == 0? transfer: -1);
#endif
	return error;
}

int utxpl_error()
{
    return WSAGetLastError();
}

struct module_stub  tcp_device_mod = {
	module_init, module_clean
};

