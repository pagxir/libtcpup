#include <stdio.h>
#include <errno.h>
#include <assert.h>

#include <txall.h>

#include <utx/utxpl.h>
#include "tcp_channel.h"

static int _lenfile = -1;
static struct tx_aiocb _sockcbp;
static struct sockaddr_in6 _lenaddr;
static struct tx_task_t _event, _runstart, _runstop;

static void listen_statecb(void *ignore);
static void listen_callback(void *context);

extern "C" void set_tcp_listen_address(struct tcpip_info *info)
{
	_lenaddr.sin6_port = info->port;
	inet_4to6(&_lenaddr.sin6_addr, &info->address);
	return;
}

static void module_init(void)
{
	int v = 1;
	int error;

	_lenaddr.sin6_family = AF_INET6;
	if (_lenaddr.sin6_port == 0) {
		_lenaddr.sin6_port = htons(4430);
		_lenaddr.sin6_addr = in6addr_loopback;
	}

	tx_loop_t *loop = tx_loop_default();
	tx_task_init(&_event, loop, listen_callback, NULL);
	tx_task_init(&_runstop, loop, listen_statecb, (void *)0);
	tx_task_init(&_runstart, loop, listen_statecb, (void *)1);

	_lenfile = socket(AF_INET6, SOCK_STREAM, 0);
	assert(_lenfile != -1);

	tx_setblockopt(_lenfile, 0);
	setsockopt(_lenfile, SOL_SOCKET, SO_REUSEADDR, (const char *)&v, sizeof(v));

	error = bind(_lenfile, (struct sockaddr *)&_lenaddr, sizeof(_lenaddr));
	LOG_DEBUG("ipv4 address: %s %d\n", ntop6(_lenaddr.sin6_addr), errno);
	assert(error == 0);

	error = listen(_lenfile, 5);
	assert(error == 0);

	tx_listen_init(&_sockcbp, loop, _lenfile);
	tx_task_active(&_runstart, "start");
/*
	slotwait_atstop(&_runstop);
*/
}

static void module_clean(void)
{
	tx_listen_fini(&_sockcbp);
	closesocket(_lenfile);
	tx_task_drop(&_event);

	tx_task_drop(&_runstop);
	tx_task_drop(&_runstart);

	LOG_DEBUG("tcp_listen: exiting\n");
}

void listen_statecb(void *ignore)
{
	int state;

	state = (int)(uint64_t)ignore;
	if (state == 0) {
		LOG_DEBUG("listen_stop\n");
		tx_task_drop(&_event);
		return;
	}

	if (state == 1) {
		LOG_DEBUG("listen_start\n");
		tx_listen_active(&_sockcbp, &_event);
	}
}

void listen_callback(void *context)
{
	int newfd;
	struct sockaddr_in newaddr;
	size_t newlen = sizeof(newaddr);

	newfd = tx_listen_accept(&_sockcbp, (struct sockaddr *)&newaddr, &newlen);
	tx_listen_active(&_sockcbp, &_event);

	if (newfd != -1) {
		LOG_DEBUG("new client: %s:%u\n",
				inet_ntoa(newaddr.sin_addr), ntohs(newaddr.sin_port));
		tx_setblockopt(newfd, 0);
		new_tcp_channel(newfd);
	}
}

struct module_stub tcp_listen_mod = {
	module_init, module_clean
};

