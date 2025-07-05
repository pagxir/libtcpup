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

static void module_init(void)
{
#if 0
	tx_loop_t *loop = tx_loop_default();
	tx_taskq_init(&_dev_busy);
	tx_task_init(&_stop, loop, listen_statecb, (void *)0);
	tx_task_init(&_start, loop, listen_statecb, (void *)1);
	tx_poll_init(&_dev_idle_poll, loop, dev_idle_callback, NULL);

	tx_task_active(&_start, "start");

	// TODO: fixme how to do when stop loop
	/* slotwait_atstop(&_stop); */
#endif
}

static void module_clean(void)
{

}

struct module_stub  tcp_device_stdio_mod = {
	module_init, module_clean
};

struct if_dev_cb _stdio_if_dev_cb = {
	head_size: 0,
	output: NULL,
	set_filter: NULL,
	socreate: NULL,
	dev_busy: NULL,
	reply_mode: NULL,
	device_address: NULL,
	outter_address: NULL,
	keepalive_address: NULL
};
