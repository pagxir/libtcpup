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
#define MAX_DEV_CNT 8

#define AFTYP_INET   1
#define AFTYP_INET6  4
static uint8_t builtin_target[] = {AFTYP_INET, 0, 0, 22, 127, 0, 0, 1};
static uint8_t builtin_target6[] = {AFTYP_INET6, 0, 0, 22, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
void set_tcp_destination(uint8_t *buf, size_t len);

static FILTER_HOOK *_filter_hook;
static int _set_filter_hook(FILTER_HOOK *hook)
{
	_filter_hook = hook;
	return 0;
}

struct tcpup_device_ipv6 {
	struct tx_aiocb _sockcbp;

	struct tx_task_t _event;
	struct tx_task_t _dev_idle;
	struct sockaddr_in6 _addr_in;

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

static int _tcp_out_fd = -1;
static int _tcp_dev_busy = 0;
static tx_task_q _dev_busy;

static struct tx_task_t _stop;
static struct tx_task_t _start;

static struct tcpup_device_ipv6 *_paging_devices[MAX_DEV_CNT] = {0};

static void listen_statecb(void *context);
static void listen_callback(void *context);

static int _tcp_busying(void)
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
	tcpup_device_ipv6 *this_device = _paging_devices[offset];

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
		this_device = new tcpup_device_ipv6;
		this_device->init(0);
		this_device->_offset = offset;
		tx_task_active(&this_device->_event, "d-r");

		_paging_devices[offset] = this_device;
	}

	return socreate(offset, conv);
}

static void dev_idle_callback(void *uup)
{
	tx_task_wakeup(&_dev_busy, "idle");
	TCP_DEBUG(0x1, "dev_idle_callback\n");

	return ;
}

static void _tcp_devbusy(struct tcpcb *tp, tx_task_t *task)
{
	if ((tp->t_flags & TF_DEVBUSY) == 0) {
		tx_task_record(&_dev_busy, &tp->t_event_devbusy);
		tp->t_flags |= TF_DEVBUSY;
		if (_tcp_dev_busy == 0) {
			/* TODO: fixme: device busy */
			// sock_write_wait(_sockcbp, &_dev_idle);
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
	// _tcp_out_addr.sin_addr.s_addr   = (info->address);
	out_addr = (struct sockaddr *)&_tcp_out_addr;

	_tcp_out_fd = socket(AF_INET6, SOCK_DGRAM, 0);
	assert(_tcp_out_fd != -1);
	disable_ipv6_only(_tcp_out_fd);

	error = bind(_tcp_out_fd, out_addr, sizeof(_tcp_out_addr));
	assert(error != -1);

	return;
}

static char ipv6_zero[16] = {0};
static struct sockaddr_in6 _tcp_dev_addr = { 0 };
static void _tcp_set_device_address(struct tcpip_info *info)
{
	_tcp_dev_addr.sin6_family = AF_INET6;
	_tcp_dev_addr.sin6_port   = (info->port);
	// _tcp_dev_addr.sin_addr.s_addr   = (info->address);
       if (memcmp(ipv6_zero, info->ipv6, sizeof(info->ipv6)))
               memcpy(&_tcp_dev_addr.sin6_addr, info->ipv6, sizeof(info->ipv6));
	return;
}


static struct sockaddr_in6 _tcp_keep_addr = { 0 };
static void _tcp_set_keepalive_address(struct tcpip_info *info)
{
	_tcp_keep_addr.sin6_family = AF_INET6;
	_tcp_keep_addr.sin6_port   = (info->port);
	// _tcp_keep_addr.sin_addr.s_addr   = (info->address);
}

struct link_header {
	uint16_t ident, flags;
	uint16_t qn, an, xn, yn;
	uint32_t content;
};

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

static uint8_t dns_filling_ipv4[] = {
	0xf1, 0xb0, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00,
	0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00
};

static uint8_t dns_filling_ipv6[] = {
	0xf1, 0xb0, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x1c, 0x00,
	0x01, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};


void tcpup_device_ipv6::init(int dobind)
{
	int error;
	socklen_t alen;
	struct sockaddr_in6 saddr;

	memcpy(&_addr_in, &_tcp_dev_addr, sizeof(_addr_in));
	_addr_in.sin6_family = AF_INET6;

	tx_loop_t *loop = tx_loop_default();
	tx_task_init(&_event, loop, listen_callback, this);
	tx_task_init(&_dev_idle, loop, dev_idle_callback, this);

	_file = socket(AF_INET6, SOCK_DGRAM, 0);
	assert(_file != -1);
	disable_ipv6_only(_file);

	if (dobind) {
		error = bind(_file, (struct sockaddr *)&_addr_in, sizeof(_addr_in));
		assert(error == 0);
		_dobind = 1;
	} else {
		_addr_in.sin6_port = 0;
		error = bind(_file, (struct sockaddr *)&_addr_in, sizeof(_addr_in));
		assert(error == 0);
	}

	char inetbuf[128];
	alen = sizeof(saddr);
	getsockname(_file, (struct sockaddr *)&saddr, &alen);
	fprintf(stderr, "bind@address# %s:%u\n",
			inet_ntop(AF_INET6, &saddr.sin6_addr, inetbuf, sizeof(inetbuf)), htons(saddr.sin6_port));

	_addr_in.sin6_port = saddr.sin6_port;
	if (IN6_IS_ADDR_UNSPECIFIED(&saddr.sin6_addr))
		_addr_in.sin6_addr = saddr.sin6_addr;

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
	tcpup_device_ipv6 *this_device = _paging_devices[offset];

	state = (int)(uint64_t)context;
	switch (state) {
		case 1:
			if (this_device == NULL) {
				this_device = new tcpup_device_ipv6;
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
#define RCVPKT_MAXSIZ 1492

static u_short _rcvpkt_len[RCVPKT_MAXCNT];
static u_short _rcvpkt_link[RCVPKT_MAXCNT];
static tcpup_addr _rcvpkt_addr[RCVPKT_MAXCNT];
static char  _rcvpkt_buf[RCVPKT_MAXSIZ * RCVPKT_MAXCNT];

static void listen_callback(void *context)
{
	struct tcpup_device_ipv6 *up;

	up = (struct tcpup_device_ipv6 *)context;
	up->incoming();
	return;
}

void set_tcp_destination(uint8_t *buf, size_t len);
void tcpup_device_ipv6::incoming(void)
{
	int len;
	int pktcnt;
	socklen_t salen;
	struct sockaddr_in6 saaddr;
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
			len = recvfrom(_file, packet, RCVPKT_MAXSIZ, MSG_DONTWAIT, (struct sockaddr *)&saaddr, &salen);
			tx_aincb_update(&_sockcbp, len);
			if (len == -1) break;

			int offset = sizeof(dns_filling_byte);

			if (len >= offset + TCPUP_HDRLEN) {
				struct tcpup_addr from;
				struct link_header *link = (struct link_header *)packet;
				TCP_DEBUG(salen > sizeof(_rcvpkt_addr[0].name), "buffer is ipv6 overflow %d\n", salen);
				// memcpy(&key, packet + 14, sizeof(key));

				if (_filter_hook != NULL) {
					memcpy(from.name, &saaddr, salen);
					from.namlen = salen;
					if (_filter_hook(_file, p, len - offset, &from)) {
						//TCP_DEBUG(0x1, "this packet is filter out by %p\n", _filter_hook);
						continue;
					}
				}

				uint32_t link_magic = 0x2636e00;
				if (link->yn == htons(1)) {
					switch(packet[14]) {
						case 0x1c:
							offset = sizeof(dns_filling_ipv6);
							memcpy(builtin_target6 + 2, packet + 0x18, 2);
							memcpy(builtin_target6 + 4, packet + 0x1c, 16);
							set_tcp_destination(builtin_target6, sizeof(builtin_target6));
							TCP_DEBUG(1, "receive tcp ipv6");
							link_magic = 0x1c00;
							break;

						case 0x1:
							offset = sizeof(dns_filling_ipv4);
							memcpy(builtin_target + 2, packet + 0x18, 2);
							memcpy(builtin_target + 4, packet + 0x1c, 4);
							set_tcp_destination(builtin_target, sizeof(builtin_target));
							TCP_DEBUG(1, "receive tcp ipv4");
							link_magic = 0x0100;
							break;
					}
				}

				memcpy(&key, packet + 14, 2);
				packet_decrypt(htons(key), p, packet + offset, len - offset);

				if (link->content == htonl(0x1c00)) {
					static tcpup_addr addr[0];
					memcpy(addr[0].name, &saaddr, salen);
					addr[0].namlen = salen;
					tcpup_do_packet(_offset, p, len - offset, addr, link->ident);
				} else if (link->content == htonl(0x0100)) {
					static tcpup_addr addr[0];
					memcpy(addr[0].name, &saaddr, salen);
					addr[0].namlen = salen;
					tcpup_do_packet(_offset, p, len - offset, addr, link->ident);
				} else if (link->content == htonl(link_magic)) {
					memcpy(_rcvpkt_addr[pktcnt].name, &saaddr, salen);
					_rcvpkt_addr[pktcnt].namlen = salen;
					_rcvpkt_link[pktcnt]  = link->ident;
					_rcvpkt_len[pktcnt++] = (len - offset);
					p += (len - offset);
				}
			}

			this->_t_rcvtime = time(NULL);
		}

		int handled;
		p = _rcvpkt_buf;
		for (int i = 0; i < pktcnt; i++) {
			char inbuf[128];
			handled = tcpup_do_packet(_offset, p, _rcvpkt_len[i], &_rcvpkt_addr[i], _rcvpkt_link[i]);

			TCP_DEBUG(handled == 0, "error packet drop: %s\n", inet_ntop(AF_INET6, &saaddr.sin6_addr, inbuf, sizeof(inbuf)));
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

void tcpup_device_ipv6::fini()
{
	fprintf(stderr, "udp_listen: exiting\n");
	tx_task_drop(&_dev_idle);
	tx_task_drop(&_event);
	tx_aiocb_fini(&_sockcbp);
	closesocket(_file);
}

static void _tcp_backwork(struct tcpip_info *info)
{
#if 0
	struct sockaddr_in6 addr_in1;
	addr_in1.sin6_family = AF_INET6;
	addr_in1.sin6_port   = info->port;
	addr_in1.sin_addr.s_addr   = info->address;

	sendto(_file, "HELO", 4, 0,
			(struct sockaddr *)&addr_in1, sizeof(addr_in1));
#endif
	return;
}

static u_short get_addr_port(struct tcpup_addr const *name)
{
	struct sockaddr_in6 *saip;
	saip = (struct sockaddr_in6 *)name->name;
	return saip->sin6_port;
}

static int _utxpl_output(int offset, rgn_iovec *iov, size_t count, struct tcpup_addr const *name, uint32_t link)
{
	int fd;
	int error;
	char hold_buffer[2049];

	if (offset >= MAX_DEV_CNT || _paging_devices[offset] == NULL) {
		fprintf(stderr, "offset: %d\n", offset);
		if ((offset & 01) && offset < MAX_DEV_CNT 
				&& _paging_devices[offset - 1]) {
			offset --;
		} else {
			return -1;
		}
	}
	
	fd = _paging_devices[offset]->_file;
	_paging_devices[offset]->_t_sndtime = time(NULL);

	size_t dns_filling_len = sizeof(dns_filling_byte);
	uint8_t *dns_filling_buf = dns_filling_byte;

	uint8_t link_optval[64];
	uint32_t link_magic = 0x2636e00;
	size_t link_optlen = get_tcp_link_target(link_optval, sizeof(link_optval));

	if (link_optlen == 20) {
		dns_filling_len = sizeof(dns_filling_ipv6);
		dns_filling_buf = dns_filling_ipv6;

		memcpy(dns_filling_ipv6 + 0x18, link_optval + 2, 2);
		memcpy(dns_filling_ipv6 + 0x1c, link_optval + 4, 16);
		TCP_DEBUG(1, "utxpl_output ipv6 tcp\n");
		link_magic = 0x1c00;
	} else if (link_optlen == 8) {
		dns_filling_len = sizeof(dns_filling_ipv4);
		dns_filling_buf = dns_filling_ipv4;

		memcpy(dns_filling_ipv4 + 0x18, link_optval + 2, 2);
		memcpy(dns_filling_ipv4 + 0x1c, link_optval + 4, 4);
		TCP_DEBUG(1, "utxpl_output ipv4 tcp\n");
		link_magic = 0x100;
	}

	struct link_header *plink = (struct link_header *)dns_filling_buf;
	plink->ident = csum_fold(link);
	plink->content = htonl(link_magic);

#ifndef WIN32
	struct iovec  iovecs[10];
	iovecs[0].iov_len = dns_filling_len;
	iovecs[0].iov_base = dns_filling_buf;

	memcpy(iovecs + 1, iov, count * sizeof(iovecs[0]));
	packet_encrypt_iovec(iovecs + 1, count, hold_buffer);

	struct msghdr msg0;
	msg0.msg_name = (void *)name->name;
	msg0.msg_namelen = name->namlen;
	msg0.msg_iov  = (struct iovec*)iovecs;
	msg0.msg_iovlen = count + 1;

	msg0.msg_control = NULL;
	msg0.msg_controllen = 0;
	msg0.msg_flags = 0;

	error = sendmsg(fd, &msg0, 0);
#else
	DWORD transfer = 0;
	WSABUF  iovecs[10];
	iovecs[0].len = dns_filling_len;
	iovecs[0].buf = dns_filling_buf;

	memcpy(iovecs + 1, iov, count * sizeof(iovecs[0]));
	packet_encrypt_iovec(iovecs + 1, count, hold_buffer);

	error = WSASendTo(fd, (LPWSABUF)iovecs, count + 1, &transfer, 0,
			(const sockaddr *)name->name, name->namlen, NULL, NULL);
	error = (error == 0? transfer: -1);
	{
		char abuf[56];
		struct sockaddr_in6 *inp6 = (struct sockaddr_in6 *) name->name;
		TCP_DEBUG(error == -1, "utxpl_output send failure: %s\n", inet_ntop(AF_INET6, &inp6->sin6_addr, abuf, sizeof(abuf)));
	}
	TCP_DEBUG(error == -1, "utxpl_output send failure: %d\n", WSAGetLastError());
#endif

	TCP_DEBUG(error == -1, "utxpl_output send failure v6: %s\n", strerror(errno));
	return error;
}

struct module_stub  tcp_device_ipv6_mod = {
	module_init, module_clean
};

struct if_dev_cb _ipv6_if_dev_cb = {
	head_size: 40 + 8 + 22,
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
