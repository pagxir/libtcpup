#include <time.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <assert.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/uio.h>

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

struct context {
	int sockfd;
	tx_task_t task;
	tx_aiocb netin;
};

extern struct if_dev_cb _stdio_if_dev_cb;
static struct context netif;

static int _netif_xmit(int offset, rgn_iovec *iov, size_t count, struct tcpup_addr const *name, u_short link)
{
	int sockfd1 = STDOUT_FILENO;
	struct iovec iovecs[10];

	assert(count < 10);
	iovecs[0].iov_len = sizeof(link);
	iovecs[0].iov_base = &link;
	memmove(iovecs + 1, iov, count * sizeof(iov[0]));

	return writev(sockfd1, iovecs, count + 1);
}

static void netif_receive(void *upp)
{
	struct context *up = (struct context *)upp;
	struct tcpup_addr from = {};
	char buf[8192];

	while (tx_readable(&up->netin)) {
		int count = read(up->sockfd, buf, sizeof(buf));
		tx_aincb_update(&up->netin, count);

		if (count > 2) {
			u_short *link = (u_short *)buf;
			tcpup_do_packet(0, buf + 2, count - 2, &from, *link);
		}
	}
	
	tx_aincb_active(&up->netin, &up->task);
}

static void module_init(void)
{
	int bufsize = 1024 * 1024;
	tx_loop_t *loop = tx_loop_default();

	int sockfd0 = STDIN_FILENO;
	setsockopt(sockfd0, SOL_SOCKET, SO_RCVBUF, (char *)&bufsize, sizeof(bufsize));
	tx_setblockopt(sockfd0, 0);

#if 0
	int sockfd1 = STDOUT_FILENO;
	setsockopt(sockfd1, SOL_SOCKET, SO_SNDBUF, (char *)&bufsize, sizeof(bufsize));
	tx_setblockopt(sockfd1, 0);
#endif

	netif.sockfd = sockfd0;
	tx_aiocb_init(&netif.netin, loop, sockfd0);
	tx_task_init(&netif.task, loop, netif_receive, &netif);
	tx_aincb_active(&netif.netin, &netif.task);
}

static void module_clean(void)
{
	tx_aincb_stop(&netif.netin, &netif.task);
	tx_aiocb_fini(&netif.netin);
	tx_task_drop(&netif.task);
}

struct module_stub  tcp_device_stdio_mod = {
	module_init, module_clean
};

struct if_dev_cb _stdio_if_dev_cb = {
	head_size: 0,
	output: _netif_xmit,
	set_filter: NULL,
	socreate: ifdev_phony_socreate,
	dev_busy: ifdev_phony_dev_busy,
	reply_mode: ifdev_phony_reply_mode,
	device_address: ifdev_phony_address,
	outter_address: ifdev_phony_address,
	keepalive_address: ifdev_phony_address
};
