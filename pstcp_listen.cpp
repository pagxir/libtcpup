#include <stdio.h>
#include <assert.h>

#include <txall.h>

#include <utx/utxpl.h>
#include <utx/socket.h>
#include "pstcp_socks.h"
#include "pstcp_channel.h"

static struct tx_task_t _event;
static struct tx_task_t _runstop;
static struct tx_task_t _runstart;
static struct tx_task_t _syn_keeper;

static int _syn_count = 0;
static tx_timer_t _reset_timer = {0};
static void reset_counter(void *ignore);

static void reset_counter(void *count);
static void accept_statecb(void *ignore);
static void accept_callback(void *context);

static void module_init(void)
{
	tx_loop_t *loop = tx_loop_default();
	tx_task_init(&_event, loop, accept_callback, NULL);
	tx_task_init(&_runstop, loop, accept_statecb, (void *)0);
	tx_task_init(&_runstart, loop, accept_statecb, (void *)1);
	tx_task_init(&_syn_keeper, loop, reset_counter, &_reset_timer);

	tx_task_active(&_runstart, "run-start");

	tx_timer_ring *provider = tx_timer_ring_get(loop);
	tx_timer_init(&_reset_timer, provider, &_syn_keeper);
	tx_timer_reset(&_reset_timer, 1000);
#if 0
	slotwait_atstop(&_runstop);
#endif
}

static void module_clean(void)
{
	tx_timer_stop(&_reset_timer);
	tx_task_drop(&_event);
	tx_task_drop(&_runstop);
	tx_task_drop(&_runstart);
	tx_task_drop(&_syn_keeper);

	fprintf(stderr, "tcp_listen: exiting\n");
}

static void reset_counter(void *t)
{
	tx_timer_t *timer = (tx_timer_t *)t;
	tx_timer_reset(timer, 10000);
	_syn_count = 0;
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
		sopoll(NULL, SO_ACCEPT, &_event);
	}
}

static void accept_callback(void *context)
{
	sockcb_t newtp;
	struct sockaddr_in newaddr;
	size_t newlen = sizeof(newaddr);

	newtp = soaccept(NULL, (struct sockaddr *)&newaddr, &newlen);
	if (newtp != NULL) {
		fprintf(stderr, "new client: %s:%u\n",
				inet_ntoa(newaddr.sin_addr), ntohs(newaddr.sin_port));
		if (_syn_count++ < 2 * 640)
			new_pstcp_channel(newtp);
		else
			soclose(newtp);
	}

	sopoll(NULL, SO_ACCEPT, &_event);
}

struct module_stub pstcp_listen_mod = {
	module_init, module_clean
};

