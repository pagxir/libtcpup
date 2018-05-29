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

#define IF_DEV 1
#include <tcpup/tcp_device.h>

#include "tcp_channel.h"

static FILTER_HOOK *_filter_hook;
static int _set_filter_hook(FILTER_HOOK *hook)
{
	_filter_hook = hook;
	return 0;
}

struct ifdev_stdio_device {
	struct tx_aiocb _outcb;
	struct tx_aiocb _sockcbp;

	struct tx_task_t _event;
	struct tx_task_t _wevent;
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

static int _tcp_dev_busy = 0;
static tx_task_q _dev_busy;

static struct tx_task_t _stop;
static struct tx_task_t _start;

static void listen_statecb(void *context);
static void listen_callback(void *context);
static void output_callback(void *context);

static int tcp_busying(void)
{
	return _tcp_dev_busy;
}

static void _set_ping_reply(int mode)
{
	return;
}

static struct ifdev_stdio_device _dummy;

static sockcb_t _socreate(so_conv_t conv)
{
	int offset = 0;
	return socreate(offset, conv);
}

static void dev_idle_callback(void *uup)
{
	tx_task_wakeup(&_dev_busy, "idle");
	TCP_DEBUG(1, "dev_idle_callback\n");

	return ;
}

static void _tcp_devbusy(struct tcpcb *tp)
{
}

static void _tcp_set_dummy(struct tcpip_info *info)
{
	return;
}

void ifdev_stdio_device::init(int dobind)
{
	tx_loop_t *loop = tx_loop_default();
	tx_task_init(&_event, loop, listen_callback, this);
	tx_task_init(&_wevent, loop, output_callback, this);
	tx_task_init(&_dev_idle, loop, dev_idle_callback, this);

	_file = 0;
	assert(_file != -1);

	tx_aiocb_init(&_outcb, loop, 1);
	tx_aiocb_init(&_sockcbp, loop, _file);
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

	state = (int)(long)context;
	switch (state) {
		case 1:
			_dummy.init(1);
			tx_task_active(&_dummy._event, "listen");
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
static tcpup_addr _rcvpkt_addr[RCVPKT_MAXCNT];
static char  _rcvpkt_buf[RCVPKT_MAXSIZ * RCVPKT_MAXCNT];

static void listen_callback(void *context)
{
	struct ifdev_stdio_device *up;

	up = (struct ifdev_stdio_device *)context;
	up->incoming();
	return;
}

static int file_can_read(int fd)
{
	int n;
	fd_set fds;
	struct timeval timo = {0};

	FD_ZERO(&fds);
	FD_SET(fd, &fds);
	n = select(fd + 1, &fds, 0, 0, &timo);
	return  n > 0 && FD_ISSET(fd, &fds);
}

#define END (char)0xC0
#define ESC (char)0xDB
#define ESC_END (char)0xDC
#define ESC_ESC (char)0xDD

static int _stdin_off = 0;
static int _stdin_len = 0;
static char _stdin_buf[8192];

void ifdev_stdio_device::incoming(void)
{
	int len;
	int pktcnt;
	socklen_t salen;
	struct sockaddr saaddr;
	char packet[RCVPKT_MAXSIZ];

	if (tx_readable(&_sockcbp)) {
		char *p;
		unsigned short key;
		ticks = tx_getticks();

		p = _rcvpkt_buf;
		pktcnt = 0;

		if (!file_can_read(0)) {
			errno = EAGAIN;
			tx_aincb_update(&_sockcbp, -1);
		}

		while (file_can_read(0)) {
			if (_stdin_len == sizeof(_stdin_buf) || _stdin_off > sizeof(_stdin_buf) / 2) {
				assert (_stdin_off > 0);
				memmove(_stdin_buf, _stdin_buf + _stdin_off, _stdin_len - _stdin_off);
				_stdin_len -= _stdin_off;
				_stdin_off = 0;
			}

			int error = read(0, _stdin_buf + _stdin_len, sizeof(_stdin_buf) - _stdin_len);
			if (error <= 0) {
				tx_aincb_update(&_sockcbp, -1);
				fprintf(stderr, "error: %d\n", error);
				break;
			}

			int len = 0, esc = 0, aborted = 0;
			_stdin_len += error;
			for (char *ptr = _stdin_buf + _stdin_off; ptr < _stdin_buf + _stdin_len; ptr++) {
				if (esc == 1) {
					if (*ptr  == ESC_END) {
						p[len++] = END;
					} else if (*ptr  == ESC_ESC) {
						p[len++] = ESC;
					} else if ((*ptr & 0xe0) == 0x80) {
						p[len++] = (*ptr & 0x7f);
					} else {
						fprintf(stderr, "failure decode: %x\n", *ptr);
						aborted = 1;
					}
					esc = 0;
				} else if (*ptr == END) {
					_stdin_off = (ptr + 1 - _stdin_buf);
					if (len > 0 && aborted == 0) {
						_rcvpkt_len[pktcnt++] = len;
						if (*p == '!') exit(9);
						p += len;
					}
					aborted = 0;
					len = 0;
				} else if (*ptr == ESC) {
					esc = 1;
				} else {
					p[len++] = *ptr;
				}

				if (aborted || len > 1500) {
					aborted = 1;
					len = 0;
				}
			}
		}

		int handled;
		p = _rcvpkt_buf;
		for (int i = 0; i < pktcnt; i++) {
			handled = tcpup_do_packet(_offset, p, _rcvpkt_len[i], &_rcvpkt_addr[i]);
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

void ifdev_stdio_device::fini()
{
	LOG_INFO("stdio_listen: exiting\n");

	tx_task_drop(&_dev_idle);
	tx_task_drop(&_wevent);
	tx_task_drop(&_event);
	tx_aiocb_fini(&_sockcbp);
	tx_aiocb_fini(&_outcb);
}

static int _stdout_off = 0;
static int _stdout_len = 0;
static char _stdout_buf[8192];

static int file_can_write(int fd)
{
	int n;
	fd_set fds;
	struct timeval timo = {0};

	FD_ZERO(&fds);
	FD_SET(fd, &fds);
	n = select(fd + 1, 0, &fds, 0, &timo);
	return  n > 0 && FD_ISSET(fd, &fds);
}

static void output_callback(void *context)
{
	int error;

	if (_stdout_len > 0 && file_can_write(1)) {
		error = write(1, _stdout_buf + _stdout_off, _stdout_len);
		if (error > 0) {
			assert (error <= _stdout_len);
			_stdout_off += error;
			_stdout_len -= error;
			assert(_stdout_len >= 0);
		}
	}

	if (_stdout_len > 0) {
        tx_outcb_prepare(&_dummy._outcb, &_dummy._wevent, 0);
	}

	return ;
}


static int _utxpl_output(int offset, rgn_iovec *iov, size_t count, struct tcpup_addr const *name)
{
    int error = -1;

	if (file_can_write(1)) {
		if (_stdout_len > 0) {
			error = write(1, _stdout_buf + _stdout_off, _stdout_len);
			if (error > 0) {
				assert (error <= _stdout_len);
				_stdout_off += error;
				_stdout_len -= error;
				assert(_stdout_len >= 0);
			}
		}

		if (_stdout_len == 0) {
			int n = 0;
			_stdout_buf[n++] = END;

			for (int i = 0; i < count; i++) {
				char *ptr = (char *)iov[i].iov_base;
				for (int j = 0; j < iov[i].iov_len; j++) {
					if (*ptr == END) {
						_stdout_buf[n++] = ESC;
						_stdout_buf[n++] = ESC_END;
					} else if (*ptr == ESC) {
						_stdout_buf[n++] = ESC;
						_stdout_buf[n++] = ESC_ESC;
					} else if ((*ptr & 0xe0) == 0x0
						&& *ptr != '\r' && *ptr != '\n' && *ptr != '\t') {
						_stdout_buf[n++] = ESC;
						_stdout_buf[n++] = (*ptr)|0x80;
					} else {
						_stdout_buf[n++] = *ptr;
					}
					ptr++;
				}
			}

			_stdout_buf[n++] = END;
			_stdout_off = 0;
			_stdout_len = n;
			assert ( n > 0);
		} else {
			fprintf(stderr, "write failure: %d %d\n", _stdout_off, _stdout_len);
			tx_outcb_prepare(&_dummy._outcb, &_dummy._wevent, 0);
			assert(_stdout_len >= 0);
			error = -1;
			return error;
		}

		if (_stdout_len > 0 && file_can_write(1)) {
			error = write(1, _stdout_buf + _stdout_off, _stdout_len);
			if (error > 0) {
				assert (error <= _stdout_len);
				_stdout_off += error;
				_stdout_len -= error;
				assert(_stdout_len >= 0);
			}
		}
	}
	
	return error;
}

struct module_stub  tcp_device_stdio_mod = {
	module_init, module_clean
};

struct if_dev_cb _stdio_if_dev_cb = {
	head_size: 0,
	output: _utxpl_output,
	set_filter: _set_filter_hook,
	socreate: _socreate,
	dev_busy: _tcp_devbusy,
	reply_mode: _set_ping_reply,
	device_address: _tcp_set_dummy,
	outter_address: _tcp_set_dummy,
	keepalive_address: _tcp_set_dummy
};
