#include <stdio.h>
#include <assert.h>

#include <wait/module.h>
#include <wait/platform.h>
#include <wait/slotwait.h>

#include <utx/socket.h>
#include "pstcp_socks.h"
#include "pstcp_channel.h"

static struct waitcb _event;
static struct waitcb _runstop;
static struct waitcb _runstart;

static void accept_statecb(void *ignore);
static void accept_callback(void *context);

static void module_init(void)
{
	waitcb_init(&_event, accept_callback, NULL);
	waitcb_init(&_runstop, accept_statecb, (void *)0);
	waitcb_init(&_runstart, accept_statecb, (void *)1);

	slotwait_atstart(&_runstart);
	slotwait_atstop(&_runstop);
}

static void module_clean(void)
{
	waitcb_clean(&_event);
	waitcb_clean(&_runstop);
	waitcb_clean(&_runstart);

	fprintf(stderr, "tcp_listen: exiting\n");
}

static void accept_statecb(void *ignore)
{
	int state;
	/* int error = -1; */

	state = (int)(long)ignore;
	if (state == 0) {
		fprintf(stderr, "listen_stop\n");
		waitcb_cancel(&_event);
		return;
	}

	if (state == 1) {
		fprintf(stderr, "listen_start\n");
		tcp_poll(NULL, TCP_ACCEPT, &_event);
	}
}

static void accept_callback(void *context)
{
	struct tcpcb *newtp;
	struct sockaddr_in newaddr;
	size_t newlen = sizeof(newaddr);

	newtp = tcp_accept(&newaddr, &newlen);
	if (newtp != NULL) {
		fprintf(stderr, "new client: %s:%u\n",
				inet_ntoa(newaddr.sin_addr), ntohs(newaddr.sin_port));
		new_pstcp_channel(newtp);
	}

	tcp_poll(NULL, TCP_ACCEPT, &_event);
}

struct module_stub pstcp_listen_mod = {
	module_init, module_clean
};

