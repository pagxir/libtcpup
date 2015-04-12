#include <time.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <assert.h>
#include <stdarg.h>
#include <stdlib.h>

#include <txall.h>

#include <utx/utxpl.h>
#include <utx/socket.h>

#include <tcpup/tcp.h>
#include <tcpup/tcp_subr.h>
#include <tcpup/tcp_debug.h>

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

struct tcpcb;
struct tcpcb *tcp_create(uint32_t conv)
{
#ifndef _DNS_CLIENT_
	int offset = 0;
#else
	int offset = (rand() % 0xF) << 1;
#endif
	tcpup_device *this_device = _paging_devices[offset];

	if (this_device != NULL && this_device->_dobind == 0) {
		int idle, idleout;
		time_t now = time(NULL);

		idle = (now - this_device->_t_rcvtime) > 6; // last recv if 15s ago
		idleout = (now - this_device->_t_sndtime) > 2; // last out is 2s ago;

		if (idleout && idle && this_device->_t_rcvtime < this_device->_t_sndtime) {
			if (_paging_devices[offset + 1] != NULL) {
				_paging_devices[offset + 1]->fini();
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
		tx_task_active(&this_device->_event);

		_paging_devices[offset] = this_device;
	}

	return tcp_create(offset, conv);
}

static void dev_idle_callback(void *uup)
{
	tx_task_wakeup(&_dev_busy);
	TCP_DEBUG_TRACE(1, "dev_idle_callback\n");

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

#ifdef WIN32
    int bufsize = 1024 * 1024;
    setsockopt(_file, SOL_SOCKET, SO_SNDBUF, (char *)&bufsize, sizeof(bufsize));
    setsockopt(_file, SOL_SOCKET, SO_RCVBUF, (char *)&bufsize, sizeof(bufsize));
#endif

	tx_setblockopt(_file, 0);
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

	tx_task_active(&_start);
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
				tx_task_active(&this_device->_event);

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
static short _udp_len[1024];
static char _udp_buf[1024 * 1024 * 8];

static void listen_callback(void *context)
{
	struct tcpup_device *up;

	up = (struct tcpup_device *)context;
	up->incoming();
	return;
}

void tcpup_device::incoming(void)
{
	int len;
	socklen_t addr_len;
	struct sockaddr_in addr_in;

	if (tx_readable(&_sockcbp)) {
		int ct = 0;
		int count = 0;
		char *c_buf = _udp_buf;
		ticks = tx_getticks();

#ifndef _DNS_CLIENT_
#define IPHDR_SKIP_LEN 20
#else
#define IPHDR_SKIP_LEN 0
#endif

		for (ct = 0; ct < 1024; ct++) {
		   	addr_len = sizeof(addr_in);
		   	len = recvfrom(_file, c_buf, 1500,
				   	MSG_DONTWAIT, (struct sockaddr *)&addr_in, &addr_len);
			tx_aincb_update(&_sockcbp, len);
			if (len == -1)
				break;

#if 0
			if (len > 0) {
				stun_client_input(c_buf, len, &addr_in);
				TCP_DEBUG_TRACE(len <  20, "small packet drop: %s:%d\n", inet_ntoa(addr_in.sin_addr), htons(addr_in.sin_port));
			}
#endif

			if (len >= TCPUP_HDRLEN + IPHDR_SKIP_LEN + sizeof(icmp_hdr_fill)) {
#ifndef DISABLE_ENCRYPT
				unsigned short key;
				memcpy(&key, c_buf + 14 + IPHDR_SKIP_LEN, 2);
				unsigned int d0 = key;

				for (int i = sizeof(icmp_hdr_fill) + IPHDR_SKIP_LEN; i < len; i++) {
					c_buf[i] ^= d0;
					d0 = (d0 * 123 + 59) & 0xffff;
				}
#endif
				_udp_len[count++] = len;
				c_buf += len;
			}

			this->_t_rcvtime = time(NULL);
		}

		int handled;
		c_buf = _udp_buf;
		for (int i = 0; i < count; i++) {

#ifdef _FEATRUE_INOUT_TWO_INTERFACE_
			if (_dobind > 0 && (c_buf[7] || c_buf[6])) {
				struct sockaddr_in newa;
				memcpy(&newa.sin_addr, c_buf, 4);
				memcpy(&newa.sin_port, c_buf + 6, 2);
				addr_in.sin_addr = newa.sin_addr;
				addr_in.sin_port = newa.sin_port;
			}
#endif
			memcpy(&addr_in.sin_port, c_buf + IPHDR_SKIP_LEN + 4, 2);
			handled = tcpup_do_packet(_offset, c_buf + sizeof(icmp_hdr_fill) + IPHDR_SKIP_LEN,
					_udp_len[i] - sizeof(icmp_hdr_fill) - IPHDR_SKIP_LEN, &addr_in, addr_len);
			TCP_DEBUG_TRACE(handled == 0, "error packet drop: %s:%d\n", inet_ntoa(addr_in.sin_addr), htons(addr_in.sin_port));
			c_buf += _udp_len[i];
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
	fprintf(stderr, "ASSERT FAILURE: %s:%ld %s\n", path, line, expr);
	exit(-1);
	return;
}

#ifndef WIN32
#define LPIOVEC struct iovec *
#define IOV_LEN(var) var.iov_len
#define IOV_BASE(var) var.iov_base
#else
#define LPIOVEC LPWSABUF
#define IOV_LEN(var) var.len
#define IOV_BASE(var) var.buf
#endif

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
		icmp_hdr_fill[0].u0.seqno = ICMP_SEQNO_FIXED;
		memset(icmp_hdr_fill[0].reserved, ICMP_CLIENT_FILL, sizeof(icmp_hdr_fill[0].reserved));
	} else {
		icmp_hdr_fill[0].type = 0x00; // icmp echo reply
		icmp_hdr_fill[0].code = ICMP_NATYPE_CODE;
		icmp_hdr_fill[0].u0.ident = get_addr_port(name);
		icmp_hdr_fill[0].u0.seqno = ICMP_SEQNO_FIXED;
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
	unsigned char *bp;
	unsigned int d0 = (rand() & 0xffff);
	unsigned char _crypt_stream[2048];

	bp = _crypt_stream;
	for (int i = 0; i < count; i++) {
		memcpy(bp, iov[i].iov_base, iov[i].iov_len);
		bp += iov[i].iov_len;
	}

	unsigned short key = d0;
	memcpy((char *)(icmp_hdr_fill) + 14, &key, 2);
	for (int i = 0; i < (bp - _crypt_stream); i++) {
		_crypt_stream[i] ^= (d0 & 0xff);
		d0 = (d0 * 123 + 59) & 0xffff;
	}

	iovecs[1].iov_base = _crypt_stream;
	iovecs[1].iov_len  = (bp - _crypt_stream);
	msg0.msg_iov  = (struct iovec*)iovecs;
	msg0.msg_iovlen = 2;
#endif

	msg0.msg_control = NULL;
	msg0.msg_controllen = 0;
	msg0.msg_flags = 0;

	icmp_update_checksum((unsigned char *)&icmp_hdr_fill[0].checksum, iovecs, msg0.msg_iovlen);
	error = sendmsg(fd, &msg0, 0);
#else
	DWORD transfer = 0;
	WSABUF  iovecs[10];
	iovecs[0].len = sizeof(icmp_hdr_fill);
	iovecs[0].buf = (char *)icmp_hdr_fill;
	memcpy(iovecs + 1, iov, count * sizeof(iovecs[0]));

#ifndef DISABLE_ENCRYPT
	unsigned char *bp;
	unsigned int d0 = (rand() & 0xffff);
	unsigned char _crypt_stream[2048];

	bp = _crypt_stream;
	for (int i = 0; i < count; i++) {
		memcpy(bp, iov[i].iov_base, iov[i].iov_len);
		bp += iov[i].iov_len;
	}

	unsigned short key = d0;
	memcpy((char *)(icmp_hdr_fill) + 14, &key, 2);
	for (int i = 0; i < (bp - _crypt_stream); i++) {
		_crypt_stream[i] ^= d0;
		d0 = (d0 * 123 + 59) & 0xffff;
	}

	iovecs[1].buf = (char *)_crypt_stream;
	iovecs[1].len  = (bp - _crypt_stream);
	count = 1;
#endif

	icmp_update_checksum((unsigned char *)&icmp_hdr_fill[0].checksum, iovecs, count + 1);
	error = WSASendTo(fd, (LPWSABUF)iovecs, count + 1, &transfer, 0,
			(const sockaddr *)name->name, name->namlen, NULL, NULL);
	error = (error == 0? transfer: -1);
#endif

	TCP_DEBUG_TRACE(error == -1, "utxpl_output send failure\n");
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

