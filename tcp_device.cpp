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
#include <tcpup/tcp_var.h>
#include <tcpup/tcp_subr.h>
#include <tcpup/tcp_debug.h>
#include <tcpup/tcp_crypt.h>

#define IF_DEV 1
#include <tcpup/tcp_device.h>

#include "tcp_channel.h"

extern "C" void tcp_channel_forward(struct sockaddr *dest, socklen_t destlen) __attribute__ ((weak));

void tcp_channel_forward(struct sockaddr *dest, socklen_t destlen)
{
	printf ("emptycall\n");
}

static struct tx_poll_t _dev_idle_poll;
static FILTER_HOOK *_filter_hook;
static int _set_filter_hook(FILTER_HOOK *hook)
{
	_filter_hook = hook;
	return 0;
}

struct tcpup_device {
	struct tx_aiocb _sockcbp;

	struct tx_task_t _event;
	struct tx_task_t _dev_idle;
	struct sockaddr_in6 _addr_in;

	struct tx_task_t _nat_hold;
	struct tx_timer_t _nat_hold_timer;

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
	void holdon();
	void reset_nat();
};

static int _tcp_out_fd = -1;
static int _tcp_dev_busy = 0;
static tx_task_q _dev_busy;

static struct tx_task_t _stop;
static struct tx_task_t _start;

#define MAX_DEV_CNT 8
static struct tcpup_device *_paging_devices[MAX_DEV_CNT] = {0};

static void dev_nat_holdon(void *ctx);
static void listen_statecb(void *context);
static void listen_callback(void *context);

static int tcp_busying(void)
{
	return _tcp_dev_busy;
}

static void _set_ping_reply(int mode)
{
	return;
}

static sockcb_t _socreate(so_conv_t conv)
{
	int offset = (rand() % MAX_DEV_CNT) & ~1;
	if (getenv("RELAYSERVER") != NULL) offset = 0;
	tcpup_device *this_device = _paging_devices[offset];

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
		tx_task_active(&this_device->_event, "d-read");

		_paging_devices[offset] = this_device;
	}

	return socreate(offset, conv);
}

static void _tcp_devbusy(struct tcpcb *tp, tx_task_t *task)
{
	if ((tp->t_flags & TF_DEVBUSY) == 0) {
		tx_task_record(&_dev_busy, &tp->t_event_devbusy);
		tp->t_flags |= TF_DEVBUSY;
		if (_tcp_dev_busy == 0) {
			/* TODO: fixme: device busy */
			// sock_write_wait(_sockcbp, &_dev_idle);
			tx_poll_active(&_dev_idle_poll);
			_tcp_dev_busy = 1;
		}
	}
}

static struct sockaddr_in6 _tcp_out_addr = { 0 };
static void _tcp_set_outter_address(struct tcpip_info *info)
{
	int error;
	struct sockaddr *out_addr;

	_tcp_out_addr.sin6_family = AF_INET6;
	_tcp_out_addr.sin6_port   = (info->port);
	memcpy(&_tcp_out_addr.sin6_addr, info->ipv6, sizeof(info->ipv6));
	out_addr = (struct sockaddr *)&_tcp_out_addr;

	_tcp_out_fd = socket(AF_INET6, SOCK_DGRAM, 0);
	assert(_tcp_out_fd != -1);
	disable_ipv6_only(_tcp_out_fd);

	error = bind(_tcp_out_fd, out_addr, sizeof(_tcp_out_addr));
	assert(error != -1);

	return;
}

static struct sockaddr_in6 _tcp_dev_addr = { 0 };
static void _tcp_set_device_address(struct tcpip_info *info)
{
	_tcp_dev_addr.sin6_family = AF_INET6;
	_tcp_dev_addr.sin6_port   = (info->port);
	memcpy(&_tcp_dev_addr.sin6_addr, info->ipv6, sizeof(info->ipv6));
	return;
}

static struct sockaddr_in6 _tcp_keep_addr = { 0 };
static void _tcp_set_keepalive_address(struct tcpip_info *info)
{
	_tcp_keep_addr.sin6_family = AF_INET6;
	_tcp_keep_addr.sin6_port   = (info->port);
	memcpy(&_tcp_keep_addr.sin6_addr, info->ipv6, sizeof(info->ipv6));
}

#define _DNS_CLIENT_
#ifdef _DNS_CLIENT_

static unsigned char dns_filling_byte[] = {
	0x20, 0x88, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x02,  'c',  'n', 0x00,
	0x00, 0x01, 0x00, 0x01,
};

#else

static unsigned char dns_filling_byte[] = {
	0x20, 0x88, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x02,  'c',  'n', 0x00,
	0x00, 0x01, 0x00, 0x01,
};

#endif

static void dev_idle_callback(void *uup)
{
	int error;

	tx_task_wakeup(&_dev_busy, "idle");
	// TCP_DEBUG(1, "dev_idle_callback\n");
	_tcp_dev_busy = 0;

	return ;
}

void tcpup_device::init(int dobind)
{
	int error;
	socklen_t alen;
	struct sockaddr_in6 saddr;

	memcpy(&_addr_in, &_tcp_dev_addr, sizeof(_addr_in));
	_addr_in.sin6_family = AF_INET6;

	tx_loop_t *loop = tx_loop_default();
	tx_task_init(&_event, loop, listen_callback, this);
	tx_task_init(&_dev_idle, loop, dev_idle_callback, this);

	tx_task_init(&_nat_hold, loop, dev_nat_holdon, this);
	tx_timer_init(&_nat_hold_timer, loop, &_nat_hold);

	tx_poll_active(&_dev_idle_poll);

	_file = socket(AF_INET6, SOCK_DGRAM, 0);
	assert(_file != -1);
	disable_ipv6_only(_file);

	if (dobind) {
		error = bind(_file, (struct sockaddr *)&_addr_in, sizeof(_addr_in));
		assert(error == 0);
		tx_timer_reset(&_nat_hold_timer, 15000);
		_dobind = 1;
	} else {
		_addr_in.sin6_port = 0;
		error = bind(_file, (struct sockaddr *)&_addr_in, sizeof(_addr_in));
		assert(error == 0);
	}

	alen = sizeof(saddr);
	getsockname(_file, (struct sockaddr *)&saddr, &alen);
	LOG_INFO("bind@address# %s:%u\n",
			ntop6(saddr.sin6_addr), htons(saddr.sin6_port));

	_addr_in.sin6_port = saddr.sin6_port;
	if (!IN6_IS_ADDR_UNSPECIFIED(&saddr.sin6_addr))
		_addr_in.sin6_addr = saddr.sin6_addr;

#if defined(WIN32) || defined(__APPLE__)
	int bufsize = 1024 * 1024;
	setsockopt(_file, SOL_SOCKET, SO_SNDBUF, (char *)&bufsize, sizeof(bufsize));
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
	tx_poll_init(&_dev_idle_poll, loop, dev_idle_callback, NULL);

	tx_task_active(&_start, "start");

	// TODO: fixme how to do when stop loop
	/* slotwait_atstop(&_stop); */
}

static void listen_statecb(void *context)
{
	int state;
	int offset = 0;
	tcpup_device *this_device = _paging_devices[offset];

	state = (int)(uint64_t)context;
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

#define RCVPKT_MAXCNT 256
#define RCVPKT_MAXSIZ 1500

static u_short _rcvpkt_len[RCVPKT_MAXCNT];
static u_short _rcvpkt_link[RCVPKT_MAXCNT];
static tcpup_addr _rcvpkt_addr[RCVPKT_MAXCNT];
static char  _rcvpkt_buf[RCVPKT_MAXSIZ * RCVPKT_MAXCNT];

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
	int pktcnt;
	socklen_t salen;
	u_short psuedo_header[2];
	struct sockaddr_in6 saaddr;
	char packet[RCVPKT_MAXSIZ + 1];

	if (tx_readable(&_sockcbp)) {
		char *p;
		unsigned short key = 0;
		ticks = tx_getticks();

		p = _rcvpkt_buf;
		pktcnt = 0;
		packet[RCVPKT_MAXSIZ] = 0;
		for (int i = 0; i < RCVPKT_MAXCNT; i++) {
			salen = sizeof(saaddr);
			len = recvfrom(_file, packet, RCVPKT_MAXSIZ, MSG_DONTWAIT, (struct sockaddr *)&saaddr, &salen);
			tx_aincb_update(&_sockcbp, len);
			if (len == -1) break;

			int offset = sizeof(dns_filling_byte);
			if (len >= offset + TCPUP_HDRLEN + sizeof(psuedo_header)) {
				struct tcpup_addr from;
				TCP_DEBUG(salen > sizeof(_rcvpkt_addr[0].name), "buffer is overflow\n");
				memcpy(&key, packet + 14, 2);
				packet_decrypt(htons(key), p, packet + offset + sizeof(psuedo_header), len - offset - sizeof(psuedo_header));

				if (_filter_hook != NULL) {
					memcpy(from.name, &saaddr, salen);
					from.namlen = salen;
					if (_filter_hook(_file, p, len - offset, &from)) {
						//TCP_DEBUG(0x1, "this packet is filter out by %p\n", _filter_hook);
						continue;
					}
				}

#ifdef _FEATRUE_INOUT_TWO_INTERFACE_
				if (_dobind > 0 && (packet[7] || packet[6])) {
					struct sockaddr_in *inp = (struct sockaddr_in *)&saaddr;
					memcpy(&inp->sin_addr, packet, 4);
					memcpy(&inp->sin_port, packet + 6, 2);
				}
#endif
				memcpy(psuedo_header, packet + offset, sizeof(psuedo_header));
				if (psuedo_header[0] == htons(0xfe80)) {
					memcpy(_rcvpkt_addr[pktcnt].name, &saaddr, salen);
					_rcvpkt_addr[pktcnt].namlen = salen;
					_rcvpkt_link[pktcnt]  = psuedo_header[1];
					_rcvpkt_len[pktcnt++] = (len - offset - sizeof(psuedo_header));
					p += (len - offset - sizeof(psuedo_header));
				}
			}

			this->_t_rcvtime = time(NULL);
		}

		int handled;
		p = _rcvpkt_buf;
		for (int i = 0; i < pktcnt; i++) {
			handled = tcpup_do_packet(_offset, p, _rcvpkt_len[i], &_rcvpkt_addr[i], _rcvpkt_link[i]);

			TCP_DEBUG(handled == 0, "error packet drop: %s\n",
					inet_ntoa(((struct sockaddr_in *)(&saaddr))->sin_addr));
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
	LOG_INFO("udp_listen: exiting\n");
	tx_timer_stop(&_nat_hold_timer);
	tx_task_drop(&_nat_hold);

	tx_task_drop(&_dev_idle);
	tx_task_drop(&_event);
	tx_aiocb_fini(&_sockcbp);
	closesocket(_file);
}

static char _reg_net[] = "HELO 172.0.0.0/16 via feedf00d";

static void dev_nat_holdon(void *ctx)
{
	struct tcpup_device *up;

	up = (struct tcpup_device *)ctx;
	up->holdon();
	return;
}

void tcpup_device::reset_nat(void)
{
	struct sockaddr_in6 addr_in1;
	addr_in1.sin6_family = AF_INET6;
	addr_in1.sin6_port   = _tcp_keep_addr.sin6_port;
	addr_in1.sin6_addr   = _tcp_keep_addr.sin6_addr;

	if (_dobind == 1 && !IN6_IS_ADDR_UNSPECIFIED(&addr_in1.sin6_addr)) {
		tx_timer_reset(&_nat_hold_timer, 15000);
	}

	return;
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

static int _utxpl_output(int offset, rgn_iovec *iov, size_t count, struct tcpup_addr const *name, u_short link)
{
	int fd;
	int error;
	char hold_buffer[2049];

	if (offset >= MAX_DEV_CNT || _paging_devices[offset] == NULL) {
		LOG_INFO("offset: %d\n", offset);
		if ((offset & 01) && offset < MAX_DEV_CNT && _paging_devices[offset - 1]) {
			offset --;
		} else {
			return -1;
		}
	}
	
	fd = _paging_devices[offset]->_file;
	_paging_devices[offset]->_t_sndtime = time(NULL);
	_paging_devices[offset]->reset_nat();

#ifdef _FEATRUE_INOUT_TWO_INTERFACE_
	if (_tcp_out_fd >= 0) {
		struct sockaddr_in _addr_in;
		_addr_in = _paging_devices[offset]->_addr_in;
		memcpy(dns_filling_byte, &_addr_in.sin_addr, sizeof(_addr_in.sin_addr));
		memcpy(dns_filling_byte + 6, &_addr_in.sin_port, sizeof(_addr_in.sin_port));
		fd = _tcp_out_fd;
	}
#endif
	u_short psuedo_header[2];
	psuedo_header[0] = htons(0xfe80);
	psuedo_header[1] = link;

#ifndef WIN32
	struct iovec  iovecs[10];
	iovecs[0].iov_len = sizeof(dns_filling_byte);
	iovecs[0].iov_base = dns_filling_byte;
	iovecs[1].iov_len  = sizeof(psuedo_header);
	iovecs[1].iov_base = psuedo_header;
	memcpy(iovecs + 2, iov, count * sizeof(iovecs[0]));
	packet_encrypt_iovec(iovecs + 2, count, hold_buffer);

	struct msghdr msg0;
	msg0.msg_name = (void *)name->name;
	msg0.msg_namelen = name->namlen;
	msg0.msg_iov  = (struct iovec*)iovecs;
	msg0.msg_iovlen = count + 2;

	msg0.msg_control = NULL;
	msg0.msg_controllen = 0;
	msg0.msg_flags = 0;
	error = sendmsg(fd, &msg0, 0);
#else
	DWORD transfer = 0;
	WSABUF  iovecs[10];
	iovecs[0].len = sizeof(dns_filling_byte);
	iovecs[0].buf = (char *)dns_filling_byte;
	iovecs[1].len = sizeof(psuedo_header);
	iovecs[1].buf = psuedo_header;
	memcpy(iovecs + 2, iov, count * sizeof(iovecs[0]));
	packet_encrypt_iovec(iovecs + 2, count, hold_buffer);

	transfer = 1;
	error = WSASendTo(fd, (LPWSABUF)iovecs, count + 2, &transfer, 0,
			(const sockaddr *)name->name, name->namlen, NULL, NULL);
	error = ((error == 0 || WSAGetLastError() == WSA_IO_PENDING)? transfer: -1);
	{
		char abuf[56];
		struct sockaddr_in6 *inp6 = (struct sockaddr_in6 *) name->name;
		TCP_DEBUG(error == -1, "utxpl_output send failure: %s\n", inet_ntop(AF_INET6, &inp6->sin6_addr, abuf, sizeof(abuf)));
	}
	TCP_DEBUG(error == -1, "utxpl_output send failure: %d\n", WSAGetLastError());
#endif

	TCP_DEBUG(error == -1, "utxpl_output send failure\n");
	return error;
}

void tcpup_device::holdon(void)
{
	struct sockaddr_in6 addr_in1;
	addr_in1.sin6_family = AF_INET6;
	addr_in1.sin6_port   = _tcp_keep_addr.sin6_port;
	addr_in1.sin6_addr   = _tcp_keep_addr.sin6_addr;
    uint16_t v4any[] = {0, 0, 0, 0, 0, 0xffff, 0, 0};

	if (!IN6_IS_ADDR_UNSPECIFIED(&addr_in1.sin6_addr) && memcmp(&addr_in1.sin6_addr, &v4any, sizeof(v4any))) {
		tx_timer_reset(&_nat_hold_timer, 15000);

		rgn_iovec iov;
		struct tcpup_addr name;

		memcpy(name.name, &_tcp_keep_addr, sizeof(_tcp_keep_addr));
		name.namlen = sizeof(_tcp_keep_addr);

		iov.iov_len = sizeof(_reg_net);
		iov.iov_base = _reg_net;
		_utxpl_output(0, &iov, 1, &name, 0);
	}

	return;
}

struct module_stub  tcp_device_udp_mod = {
	module_init, module_clean
};

struct if_dev_cb _udp_if_dev_cb = {
	head_size: 20 + 8 + 22,
	output: _utxpl_output,
	set_filter: _set_filter_hook,
	socreate: _socreate,
	dev_busy: _tcp_devbusy,
	reply_mode: _set_ping_reply,
	device_address: _tcp_set_device_address,
	outter_address: _tcp_set_outter_address,
	keepalive_address: _tcp_set_keepalive_address
};

#if 0
{
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

int disable_ipv6_only(int fd)
{
	int error = 0;
#if defined(WIN32)
	BOOL optval = 0;
	error = setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&optval, sizeof(optval));
	if (error == SOCKET_ERROR) printf("disable_ipv6_only failure: %d\n", WSAGetLastError());
#endif

	return error;
}
