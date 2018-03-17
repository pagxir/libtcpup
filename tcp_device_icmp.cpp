#include <time.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <assert.h>
#include <stdarg.h>
#include <stdlib.h>

#include <txall.h>

#define TCPUP_LAYER 1
#include <utx/utxpl.h>
#include <utx/socket.h>

#include <tcpup/tcp.h>
#include <tcpup/tcp_subr.h>
#include <tcpup/tcp_debug.h>
#include <tcpup/tcp_crypt.h>

#include "tcp_channel.h"

#define ICMP_NATYPE_CODE 0
#define ICMP_CLIENT_FILL 0xEC
#define ICMP_SERVER_FILL 0xCE
#define ICMP_SEQNO_FIXED 0xfab5

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
	/* just reserved for expend, not part of icmp protocol. */
	unsigned int   reserved[2];
};

static FILTER_HOOK *_filter_hook;
int set_filter_hook(FILTER_HOOK *hook)
{
	_filter_hook = hook;
	return 0;
}

int get_device_mtu()
{
	int mtu = 1500;
	char *mtup = getenv("MTU");
	if (mtup != NULL) {
		int tmp_mtu = atoi(mtup);
		if (tmp_mtu > 512 && tmp_mtu < 1500) mtu = tmp_mtu;
	}
	return mtu - 20 - 16;
}

struct tcpup_device {
	struct tx_aiocb _sockcbp;

	struct tx_task_t _event;
	struct tx_task_t _dev_idle;
	struct sockaddr_in _addr_in;

public:
	int _file;
	int _offset;
	int _dobind;
	time_t _t_sndtime;
	time_t _t_rcvtime;

public:
	void init(int dobind);
	void fini();
	void incoming();
};

int _tcp_out_fd = -1;
int _tcp_dev_busy = 0;
int _icmp_is_reply = 0;
static tx_task_q _dev_busy;

static struct tx_task_t _stop;
static struct tx_task_t _start;

static struct tcpup_device *_paging_devices[32] = {0};

static void listen_statecb(void *context);
static void listen_callback(void *context);

int tcp_busying(void)
{
	return _tcp_dev_busy;
}

void set_ping_reply(int mode)
{
	_icmp_is_reply = mode;
	return;
}

sockcb_t socreate(so_conv_t conv)
{
#ifndef _DNS_CLIENT_
	int offset = 0;
#else
	int offset = (rand() % 0xF) << 1;
#endif
	tcpup_device *this_device = _paging_devices[offset];

#ifndef _DNS_CLIENT_
	if (this_device != NULL && this_device->_dobind == 0) {
		int idle, idleout;
		time_t now = time(NULL);

		idle = (now - this_device->_t_rcvtime) > 6; // last recv if 15s ago
		idleout = (now - this_device->_t_sndtime) > 2; // last out is 2s ago;

		if (idleout && idle && this_device->_t_rcvtime < this_device->_t_sndtime) {
			if (_paging_devices[offset + 1] != NULL) {
				_paging_devices[offset + 1]->fini();
				delete _paging_devices[offset + 1];
				_paging_devices[offset + 1] = NULL;
			}

			_paging_devices[offset + 1] = _paging_devices[offset];
			_paging_devices[offset + 1]->_offset = offset + 1;
			_paging_devices[offset] = NULL;
			this_device = NULL;
		}
	}

	if (this_device == NULL) {
		this_device = new tcpup_device;
		this_device->init(0);
		this_device->_offset = offset;
		tx_task_active(&this_device->_event, "d-r");

		_paging_devices[offset] = this_device;
	}
#endif

	return socreate(offset, conv);
}

static void dev_idle_callback(void *uup)
{
	tx_task_wakeup(&_dev_busy, "idle");
	TCP_DEBUG(0x1, "dev_idle_callback\n");

	return ;
}

void tcp_devbusy(struct tcpcb *tp)
{
#if 0
	if ((tp->t_flags & TF_DEVBUSY) == 0) {
		tx_task_record(&_dev_busy, &tp->t_event_devbusy);
		tp->t_flags |= TF_DEVBUSY;
		if (_tcp_dev_busy == 0) {
			/* TODO: fixme: device busy */
			sock_write_wait(_sockcbp, &_dev_idle);
			_tcp_dev_busy = 1;
		}
	}
#endif
}

static struct sockaddr_in _tcp_out_addr = { 0 };
extern "C" void tcp_set_outter_address(struct tcpip_info *info)
{
	int error;
	struct sockaddr *out_addr;

	_tcp_out_addr.sin_family = AF_INET;
	_tcp_out_addr.sin_port   = (info->port);
	_tcp_out_addr.sin_addr.s_addr   = (info->address);
	out_addr = (struct sockaddr *)&_tcp_out_addr;

#ifdef _DNS_CLIENT_
	_tcp_out_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
	assert(_tcp_out_fd != -1);
#else
	_tcp_out_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	assert(_tcp_out_fd != -1);
#endif

	error = bind(_tcp_out_fd, out_addr, sizeof(_tcp_out_addr));
	assert(error != -1);

	return;
}

static struct sockaddr_in _tcp_dev_addr = { 0 };
extern "C" void tcp_set_device_address(struct tcpip_info *info)
{
	_tcp_dev_addr.sin_family = AF_INET;
	_tcp_dev_addr.sin_port   = (info->port);
	_tcp_dev_addr.sin_addr.s_addr   = (info->address);
	return;
}

static struct sockaddr_in _tcp_keep_addr = { 0 };
extern "C" void tcp_set_keepalive_address(struct tcpip_info *info)
{
	_tcp_keep_addr.sin_family = AF_INET;
	_tcp_keep_addr.sin_port   = (info->port);
	_tcp_keep_addr.sin_addr.s_addr   = (info->address);
}

struct icmphdr icmp_hdr_fill[1] = {{0}};

void tcpup_device::init(int dobind)
{
	int error;
	socklen_t alen;
	struct sockaddr_in saddr;

	memcpy(&_addr_in, &_tcp_dev_addr, sizeof(_addr_in));
	_addr_in.sin_family = AF_INET;

	tx_loop_t *loop = tx_loop_default();
	tx_task_init(&_event, loop, listen_callback, this);
	tx_task_init(&_dev_idle, loop, dev_idle_callback, this);

#ifdef _DNS_CLIENT_
	_file = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
	assert(_file != -1);
#else
	_file = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	assert(_file != -1);
#endif

	if (dobind) {
		error = bind(_file, (struct sockaddr *)&_addr_in, sizeof(_addr_in));
		assert(error == 0);
		_dobind = 1;
	} else {
		_addr_in.sin_port = 0;
		error = bind(_file, (struct sockaddr *)&_addr_in, sizeof(_addr_in));
		assert(error == 0);
	}

	alen = sizeof(saddr);
	getsockname(_file, (struct sockaddr *)&saddr, &alen);
	fprintf(stderr, "bind@address# %s:%u\n",
			inet_ntoa(saddr.sin_addr), htons(saddr.sin_port));

	_addr_in.sin_port = saddr.sin_port;
	if (saddr.sin_addr.s_addr != 0)
		_addr_in.sin_addr = saddr.sin_addr;

#if defined(WIN32) || defined(__APPLE__)
	int bufsize = 1024 * 1024;
	//setsockopt(_file, SOL_SOCKET, SO_SNDBUF, (char *)&bufsize, sizeof(bufsize));
	setsockopt(_file, SOL_SOCKET, SO_RCVBUF, (char *)&bufsize, sizeof(bufsize));
	tx_setblockopt(_file, 0);
#endif

	tx_aiocb_init(&_sockcbp, loop, _file);
#if 0
	stun_client_init(_file);
#endif
}

static void module_init(void)
{
	tx_loop_t *loop = tx_loop_default();
	tx_taskq_init(&_dev_busy);
	tx_task_init(&_stop, loop, listen_statecb, (void *)0);
	tx_task_init(&_start, loop, listen_statecb, (void *)1);

	tx_task_active(&_start, "start");
	// TODO: fixme how to do when stop loop
	/* slotwait_atstop(&_stop); */
}

static void listen_statecb(void *context)
{
	int state;
	int offset = 0;
	tcpup_device *this_device = _paging_devices[offset];

	state = (int)(long)context;
	switch (state) {
		case 1:
			if (this_device == NULL) {
				this_device = new tcpup_device;
				this_device->init(1);
				this_device->_offset = offset;
				tx_task_active(&this_device->_event, "listen");

				_paging_devices[offset] = this_device;
			}
			break;

		case 0:
			break;

		default:
			break;
	}

	return;
}

int ticks = 0;

#ifndef WIN32
#define IOVEC struct iovec
#define LPIOVEC struct iovec *
#define IOV_LEN(var) var.iov_len
#define IOV_BASE(var) var.iov_base
#else
#define IOVEC WSABUF
#define LPIOVEC LPWSABUF
#define IOV_LEN(var) var.len
#define IOV_BASE(var) var.buf
#endif

#define RCVPKT_MAXCNT 256
#define RCVPKT_MAXSIZ 1500

static u_short _rcvpkt_len[RCVPKT_MAXCNT];
static tcpup_addr _rcvpkt_addr[RCVPKT_MAXCNT];
static char  _rcvpkt_buf[RCVPKT_MAXSIZ * RCVPKT_MAXCNT];
static void icmp_update_checksum(unsigned char *st, LPIOVEC vecs, size_t count);

static void listen_callback(void *context)
{
	struct tcpup_device *up;

	up = (struct tcpup_device *)context;
	up->incoming();
	return;
}

#ifndef _DNS_CLIENT_
#define IPHDR_SKIP_LEN 20
#else
#define IPHDR_SKIP_LEN 0
#endif

void tcpup_device::incoming(void)
{
	int len;
	int pktcnt;
	socklen_t salen;
	struct sockaddr saaddr;
	struct icmphdr *icmphdr;
	char packet[RCVPKT_MAXSIZ];

	if (tx_readable(&_sockcbp)) {
		char *p;
		unsigned short key;
		ticks = tx_getticks();

		pktcnt = 0;
		p = _rcvpkt_buf;
		for (int i = 0; i < RCVPKT_MAXCNT; i++) {
			salen = sizeof(saaddr);
			len = recvfrom(_file, packet, RCVPKT_MAXSIZ, MSG_DONTWAIT, &saaddr, &salen);
			tx_aincb_update(&_sockcbp, len);
			if (len == -1) break;

			int offset = IPHDR_SKIP_LEN + sizeof(icmp_hdr_fill);
			icmphdr = (struct icmphdr *)(packet + IPHDR_SKIP_LEN);

			if (len >= offset + TCPUP_HDRLEN) {
				struct tcpup_addr from;
				TCP_DEBUG(salen > sizeof(_rcvpkt_addr[0].name), "buffer is overflow\n");
				memcpy(&key, packet + 14 + IPHDR_SKIP_LEN, sizeof(key));
				packet_decrypt(htons(key), p, packet + offset, len - offset);

				if (_filter_hook != NULL) {
					memcpy(from.name, &saaddr, salen);
					from.namlen = salen;
					from.xdat   = icmphdr->u0.pair;
					if (_filter_hook(_file, p, len - offset, &from)) {
						//TCP_DEBUG(0x1, "this packet is filter out by %p\n", _filter_hook);
						continue;
					}
				}

				struct tcphdr *tphdr = (struct tcphdr *)p;
				/* 0x08, _icmp_is_reply == 0, 0xec, reversed */
				if ((icmphdr->type == 0x08 && icmphdr->reserved[0] == 0xecececec && _icmp_is_reply) ||
						(_icmp_is_reply == 0 && icmphdr->type == 0x00 && icmphdr->reserved[0] == 0xcececece)) {
					if (tphdr->th_magic == MAGIC_UDP_TCP) {
						this->_t_rcvtime = time(NULL);
						(*(struct sockaddr_in *)&saaddr).sin_port = icmphdr->u0.seqno;
						memcpy(_rcvpkt_addr[pktcnt].name, &saaddr, salen);
						_rcvpkt_addr[pktcnt].xdat = icmphdr->u0.pair;
						_rcvpkt_addr[pktcnt].namlen = salen;
						_rcvpkt_len[pktcnt++] = (len - offset);
						p += (len - offset);
						continue;
					}
				}
			}

#if 1
			if (icmphdr->type == 0x08) {
				IOVEC iov0;
				icmphdr->type = 0;

				IOV_LEN(iov0) = len - IPHDR_SKIP_LEN;
				IOV_BASE(iov0) = packet + IPHDR_SKIP_LEN;
				icmp_update_checksum((unsigned char *)&icmphdr->checksum, &iov0, 1);
				sendto(_file, (char *)icmphdr, len - IPHDR_SKIP_LEN, 0, &saaddr, salen);
			}
#endif
		}

		int handled;
		p = _rcvpkt_buf;
		for (int i = 0; i < pktcnt; i++) {
			handled = tcpup_do_packet(_offset, p, _rcvpkt_len[i], &_rcvpkt_addr[i]);
			TCP_DEBUG(handled == 0, "error packet drop: %s\n", inet_ntoa(((struct sockaddr_in *)(&saaddr))->sin_addr));
			p += _rcvpkt_len[i];
		}
	}

	tx_aincb_active(&_sockcbp, &_event);
	return;
}

static void module_clean(void)
{
	tx_task_drop(&_start);
	tx_task_drop(&_stop);
}

void tcpup_device::fini()
{
	fprintf(stderr, "udp_listen: exiting\n");
	tx_task_drop(&_dev_idle);
	tx_task_drop(&_event);
	tx_aiocb_fini(&_sockcbp);
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
	fprintf(stderr, "ASSERT FAILURE: %s:%d %s\n", path, (int)line, expr);
	abort();
	return;
}

static void icmp_update_checksum(unsigned char *st, LPIOVEC vecs, size_t count)
{
	int index = 0;
	unsigned long cksum = 0;
	unsigned short cksum1 = 0;

	if (st != NULL) memset(st, 0, 2);

	for (int i = 0; i < count; i++) {
		size_t len = IOV_LEN(vecs[i]);
		unsigned char *adj = (unsigned char *)IOV_BASE(vecs[i]);

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

static u_short get_addr_port(struct tcpup_addr const *name)
{
	struct sockaddr_in *saip;
	saip = (struct sockaddr_in *)name->name;
	return saip->sin_port;
}

int utxpl_output(int offset, rgn_iovec *iov, size_t count, struct tcpup_addr const *name)
{
	int fd;
	int error;

	if (offset >= 32 || _paging_devices[offset] == NULL) {
		fprintf(stderr, "offset: %d\n", offset);
		if ((offset & 01) && offset < 32 && _paging_devices[offset - 1]) {
			offset --;
		} else {
			return -1;
		}
	}
	
	fd = _paging_devices[offset]->_file;
	_paging_devices[offset]->_t_sndtime = time(NULL);

#ifdef _FEATRUE_INOUT_TWO_INTERFACE_
	if (_tcp_out_fd >= 0) {
		struct sockaddr_in _addr_in;
		_addr_in = _paging_devices[offset]->_addr_in;
		memcpy(icmp_hdr_fill, &_addr_in.sin_addr, sizeof(_addr_in.sin_addr));
		memcpy((char *)icmp_hdr_fill + 6, &_addr_in.sin_port, sizeof(_addr_in.sin_port));
		fd = _tcp_out_fd;
	}
#endif

	if (_icmp_is_reply == 0) {
		icmp_hdr_fill[0].type = 0x08; // icmp echo request
		icmp_hdr_fill[0].code = ICMP_NATYPE_CODE;
		icmp_hdr_fill[0].u0.ident = getpid();
		memset(icmp_hdr_fill[0].reserved, ICMP_CLIENT_FILL, sizeof(icmp_hdr_fill[0].reserved));
	} else {
		icmp_hdr_fill[0].type = 0x00; // icmp echo reply
		icmp_hdr_fill[0].code = ICMP_NATYPE_CODE;
		icmp_hdr_fill[0].u0.ident = get_addr_port(name);
		memset(icmp_hdr_fill[0].reserved, ICMP_SERVER_FILL, sizeof(icmp_hdr_fill[0].reserved));
	}

#ifndef WIN32
	struct iovec  iovecs[10];
	iovecs[0].iov_len = sizeof(icmp_hdr_fill);
	iovecs[0].iov_base = icmp_hdr_fill;
	memcpy(iovecs + 1, iov, count * sizeof(iovecs[0]));

	struct msghdr msg0;
	msg0.msg_name = (void *)name->name;
	msg0.msg_namelen = name->namlen;
	msg0.msg_iov  = (struct iovec*)iovecs;
	msg0.msg_iovlen = count + 1;

#ifndef DISABLE_ENCRYPT
	int datlen = 0;
	unsigned short key = rand();
	unsigned char _plain_stream[RCVPKT_MAXSIZ];
	unsigned char *bp, _crypt_stream[RCVPKT_MAXSIZ];

	bp = _plain_stream;
	for (int i = 0; i < count; i++) {
		memcpy(bp, iov[i].iov_base, iov[i].iov_len);
		bp += iov[i].iov_len;
	}

	datlen = (bp - _plain_stream);
	memcpy((char *)(icmp_hdr_fill) + 14, &key, 2);
	packet_encrypt(htons(key), _crypt_stream, _plain_stream, datlen);
	iovecs[1].iov_base = _crypt_stream;
	iovecs[1].iov_len  = datlen;
	msg0.msg_iov  = (struct iovec*)iovecs;
	msg0.msg_iovlen = 2;
#endif

	msg0.msg_control = NULL;
	msg0.msg_controllen = 0;
	msg0.msg_flags = 0;

	icmp_hdr_fill[0].u0.pair = name->xdat;
	icmp_update_checksum((unsigned char *)&icmp_hdr_fill[0].checksum, iovecs, msg0.msg_iovlen);
	error = sendmsg(fd, &msg0, 0);
#else
	DWORD transfer = 0;
	WSABUF  iovecs[10];
	iovecs[0].len = sizeof(icmp_hdr_fill);
	iovecs[0].buf = (char *)icmp_hdr_fill;
	memcpy(iovecs + 1, iov, count * sizeof(iovecs[0]));

#ifndef DISABLE_ENCRYPT
	int datlen = 0;
	unsigned short key = rand();
	unsigned char _plain_stream[RCVPKT_MAXSIZ];
	unsigned char *bp, _crypt_stream[RCVPKT_MAXSIZ];

	bp = _plain_stream;
	for (int i = 0; i < count; i++) {
		memcpy(bp, iov[i].iov_base, iov[i].iov_len);
		bp += iov[i].iov_len;
	}

	datlen = (bp - _plain_stream);
	memcpy((char *)(icmp_hdr_fill) + 14, &key, 2);
	packet_encrypt(htons(key), _crypt_stream, _plain_stream, datlen);
	iovecs[1].buf = (char *)_crypt_stream;
	iovecs[1].len = datlen;
	count = 1;
#endif

	icmp_hdr_fill[0].u0.pair = name->xdat;
	icmp_update_checksum((unsigned char *)&icmp_hdr_fill[0].checksum, iovecs, count + 1);
	error = WSASendTo(fd, (LPWSABUF)iovecs, count + 1, &transfer, 0,
			(const sockaddr *)name->name, name->namlen, NULL, NULL);
	error = (error == 0? transfer: -1);
#endif

	TCP_DEBUG(error == -1, "utxpl_output send failure: %d\n", errno);
	return error;
}

int utxpl_error()
{
#ifdef WIN32
	return WSAGetLastError();
#else
	return errno;
#endif
}

struct module_stub  tcp_device_mod = {
	module_init, module_clean
};

