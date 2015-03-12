#include <stdio.h>
#include <assert.h>

#include <txall.h>

#include <utx/socket.h>
#include "pstcp_socks.h"
#include "pstcp_channel.h"

static struct tx_task_t _event;
static struct tx_task_t _runstop;
static struct tx_task_t _runstart;

static void accept_statecb(void *ignore);
static void accept_callback(void *context);

static void module_init(void)
{
	tx_loop_t *loop = tx_loop_default();
	tx_task_init(&_event, loop, accept_callback, NULL);
	tx_task_init(&_runstop, loop, accept_statecb, (void *)0);
	tx_task_init(&_runstart, loop, accept_statecb, (void *)1);

	tx_task_active(&_runstart);
#if 0
	slotwait_atstop(&_runstop);
#endif
}

static void module_clean(void)
{
	tx_task_drop(&_event);
	tx_task_drop(&_runstop);
	tx_task_drop(&_runstart);

	fprintf(stderr, "tcp_listen: exiting\n");
}

static void accept_statecb(void *ignore)
{
	int state;
	/* int error = -1; */

	state = (int)(long)ignore;
	if (state == 0) {
		fprintf(stderr, "listen_stop\n");
		tx_task_drop(&_event);
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

