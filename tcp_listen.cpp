#include <stdio.h>
#include <errno.h>
#include <assert.h>

#include <txall.h>

#include "tcp_channel.h"

#ifndef WIN32
#include <unistd.h>
#define closesocket(s) close(s)
#endif

static int _lenfile = -1;
static struct tx_aiocb _sockcbp;
static struct sockaddr_in _lenaddr;
static struct tx_task_t _event, _runstart, _runstop;

static void listen_statecb(void *ignore);
static void listen_callback(void *context);

extern "C" void set_tcp_listen_address(struct tcpip_info *info)
{
	_lenaddr.sin_port   = info->port;
	_lenaddr.sin_addr.s_addr = info->address;
	return;
}

static void module_init(void)
{
	int error;

	_lenaddr.sin_family = AF_INET;
	if (_lenaddr.sin_port == 0) {
		_lenaddr.sin_port   = htons(4430);
		_lenaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	}

	tx_loop_t *loop = tx_loop_default();
	tx_task_init(&_event, loop, listen_callback, NULL);
	tx_task_init(&_runstop, loop, listen_statecb, (void *)0);
	tx_task_init(&_runstart, loop, listen_statecb, (void *)1);

	_lenfile = socket(AF_INET, SOCK_STREAM, 0);
	assert(_lenfile != -1);

	{
		int v = 1;
		setsockopt(_lenfile, SOL_SOCKET, SO_REUSEADDR, (const char *)&v, sizeof(v));
	}

	error = bind(_lenfile, (struct sockaddr *)&_lenaddr, sizeof(_lenaddr));
	fprintf(stderr, "ipv4 address: %x %d\n", _lenaddr.sin_addr.s_addr, errno);
	assert(error == 0);

	error = listen(_lenfile, 5);
	assert(error == 0);

	tx_aiocb_init(&_sockcbp, loop, _lenfile);
	tx_task_active(&_runstart);
/*
	slotwait_atstop(&_runstop);
*/
}

static void module_clean(void)
{
	tx_aiocb_fini(&_sockcbp);
	closesocket(_lenfile);
	tx_task_drop(&_event);
	tx_task_drop(&_runstop);
	tx_task_drop(&_runstart);

	fprintf(stderr, "tcp_listen: exiting\n");
}

void listen_statecb(void *ignore)
{
	int state;
	int error = -1;

	state = (int)(long)ignore;
	if (state == 0) {
		fprintf(stderr, "listen_stop\n");
		tx_task_drop(&_event);
		return;
	}

	if (state == 1) {
		fprintf(stderr, "listen_start\n");
		tx_aincb_active(&_sockcbp, &_event);
	}
}

void listen_callback(void *context)
{
	int newfd;
	int error;
	struct sockaddr_in newaddr;
	socklen_t newlen = sizeof(newaddr);

	newfd = accept(_lenfile, (struct sockaddr *)&newaddr, &newlen);
	if (newfd != -1) {
		fprintf(stderr, "new client: %s:%u\n",
				inet_ntoa(newaddr.sin_addr), ntohs(newaddr.sin_port));
		new_tcp_channel(newfd);
	}

	tx_aincb_active(&_sockcbp, &_event);
}

struct module_stub tcp_listen_mod = {
	module_init, module_clean
};

