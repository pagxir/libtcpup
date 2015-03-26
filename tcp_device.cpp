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

#include <tcpup/tcp_subr.h>
#include <tcpup/tcp_debug.h>

#include "tcp_channel.h"

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
	int offset = (rand() % 0xF) << 1;
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

	_tcp_out_fd = socket(AF_INET, SOCK_DGRAM, 0);
	assert(_tcp_out_fd != -1);

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

#ifdef _DNS_CLIENT_

static unsigned char dns_filling_byte[] = {
	0x20, 0x88, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x04, 0x77, 0x77, 0x77,
	0x77, 0x00, 0x00, 0x01, 0x00, 0x01 
};

#else

static unsigned char dns_filling_byte[] = {
	0x20, 0x88, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x04, 0x77, 0x77, 0x77,
	0x77, 0x00, 0x00, 0x01, 0x00, 0x01 
};

#endif

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

	_file = socket(AF_INET, SOCK_DGRAM, 0);
	assert(_file != -1);

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

			if (len >= 20 + sizeof(dns_filling_byte)) {
#ifndef DISABLE_ENCRYPT
				unsigned short key;
				memcpy(&key, c_buf + 14, 2);
				unsigned int d0 = key;

				for (int i = sizeof(dns_filling_byte); i < len; i++) {
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

			handled = tcpup_do_packet(_offset, c_buf + sizeof(dns_filling_byte), _udp_len[i] - sizeof(dns_filling_byte), &addr_in, addr_len);
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
		memcpy(dns_filling_byte, &_addr_in.sin_addr, sizeof(_addr_in.sin_addr));
		memcpy(dns_filling_byte + 6, &_addr_in.sin_port, sizeof(_addr_in.sin_port));
		fd = _tcp_out_fd;
	}
#endif

#ifndef WIN32
	struct iovec  iovecs[10];
	iovecs[0].iov_len = sizeof(dns_filling_byte);
	iovecs[0].iov_base = dns_filling_byte;
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
	memcpy(dns_filling_byte + 14, &key, 2);
	for (int i = 0; i < (bp - _crypt_stream); i++) {
		_crypt_stream[i] ^= d0;
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
	error = sendmsg(fd, &msg0, 0);
#else
	DWORD transfer = 0;
	WSABUF  iovecs[10];
	iovecs[0].len = sizeof(dns_filling_byte);
	iovecs[0].buf = (char *)dns_filling_byte;
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
	memcpy(dns_filling_byte + 14, &key, 2);
	for (int i = 0; i < (bp - _crypt_stream); i++) {
		_crypt_stream[i] ^= d0;
		d0 = (d0 * 123 + 59) & 0xffff;
	}

	iovecs[1].buf = (char *)_crypt_stream;
	iovecs[1].len  = (bp - _crypt_stream);
	count = 1;
#endif

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

