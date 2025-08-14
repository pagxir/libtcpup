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

	int tcp_dev_busy;
	tx_task_q dev_busy;
	struct tx_poll_t idle_poll;
};

#define AFTYP_INET   1
#define AFTYP_INET6  4
static uint8_t builtin_target[] = {AFTYP_INET, 0, 0, 22, 127, 0, 0, 1};
static uint8_t builtin_target6[] = {AFTYP_INET6, 0, 0, 22, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
void set_tcp_destination(uint8_t *buf, size_t len);

extern struct if_dev_cb _stdio_if_dev_cb;
static struct context netif;

static uint16_t csum_fold(uint32_t val)
{
	while (val >> 16)
		val = (val >> 16) + (val & 0xffff);

	return val;
}

struct ip_hdr {
	uint16_t verflag;
	uint16_t plen;
	uint16_t ident;
	uint16_t offset;
	uint8_t ttl;
	uint8_t proto;
	uint16_t check;
	uint32_t src;
	uint32_t dst;
};

static int _netif_xmit(int offset, rgn_iovec *iov, size_t count, struct tcpup_addr const *name, uint32_t link)
{
	int sockfd1 = STDOUT_FILENO;
	struct iovec iovecs[10];
	struct ip_hdr iphdr = {};

	assert(count < 10);
	iovecs[0].iov_len = sizeof(iphdr);
	iovecs[0].iov_base = &iphdr;
	memmove(iovecs + 1, iov, count * sizeof(iov[0]));

	uint16_t *dst = (uint16_t*)&iphdr.dst;
	dst[0] = htons(0x0a00);
	dst[1] = (link & 0xffff);

	return writev(sockfd1, iovecs, count + 1);
}

u_short update_checksum(const void *buf, size_t count, uint32_t link);

static void netif_receive(void *upp)
{
	struct context *up = (struct context *)upp;
	struct tcpup_addr from = {};
	char buf[8192];

	while (tx_readable(&up->netin)) {
		int count = read(up->sockfd, buf, sizeof(buf));
		tx_aincb_update(&up->netin, count);

		if (count >= 40) {
			u_short *link, port;
			uint32_t check = 0, verify = 0;
			int offset = 0, modidx = 0;

			switch (buf[0] >> 4) {
				case 0x4:
					link = (u_short *)(buf + 12);
					check = link[0] + link[2] + link[3];
					verify = csum_fold(link[0] + link[1] + link[2] + link[3]);

					memcpy(builtin_target + 2, buf + 22, 2);
					memcpy(builtin_target + 4, buf + 16, 4);
					set_tcp_destination(builtin_target, 8);

					check = csum_fold(check);

					port = link[4];
					link[4] = link[5];
					link[5] = port;
					offset = 20;
					modidx = 1;
					break;

				case 0x6:
					check = 0;
					link = (u_short *)(buf + 8);
					for (int i = 0; i < 16; i++) check += link[i];
					verify = csum_fold(check);
					check -= link[7];

					memcpy(builtin_target6 + 2, buf + 42, 2);
					memcpy(builtin_target6 + 4, buf + 24, 16);
					set_tcp_destination(builtin_target6, sizeof(builtin_target6));

					check = csum_fold(check);

					port = link[16];
					link[16] = link[17];
					link[17] = port;
					offset = 40;
					modidx = 7;
					break;

				default:
					fprintf(stderr, "ip version: %d %d\n", buf[0], buf[0] >> 4);
					continue;
			}

#if 0
			if (0 == update_checksum(buf + offset, count - offset, verify))
#endif
				tcpup_do_packet(0, buf + offset, count - offset, &from, (check << 16) + link[modidx]);
		}
	}
	
	tx_aincb_active(&up->netin, &up->task);
}

static void dev_idle_callback(void *uup)
{
	int error;

	tx_task_wakeup(&netif.dev_busy, "idle");
	netif.tcp_dev_busy = 0;

	return ;
}

static void module_init(void)
{
	int bufsize = 1024 * 1024;
	tx_loop_t *loop = tx_loop_default();

	int sockfd0 = STDIN_FILENO;
	setsockopt(sockfd0, SOL_SOCKET, SO_RCVBUF, (char *)&bufsize, sizeof(bufsize));
	tx_setblockopt(sockfd0, 0);

#if 1
	int sockfd1 = STDOUT_FILENO;
	setsockopt(sockfd1, SOL_SOCKET, SO_SNDBUF, (char *)&bufsize, sizeof(bufsize));
	tx_setblockopt(sockfd1, 0);
#endif

	netif.sockfd = sockfd0;
	tx_aiocb_init(&netif.netin, loop, sockfd0);
	tx_task_init(&netif.task, loop, netif_receive, &netif);
	tx_aincb_active(&netif.netin, &netif.task);

	tx_poll_init(&netif.idle_poll, loop, dev_idle_callback, NULL);
}

static void module_clean(void)
{
	tx_aincb_stop(&netif.netin, &netif.task);
	tx_aiocb_fini(&netif.netin);
	tx_task_drop(&netif.task);
}

static void stdio_device_devbusy(struct tcpcb *tp, tx_task_t *task)
{
	if ((tp->t_flags & TF_DEVBUSY) == 0) {
		tx_task_record(&netif.dev_busy, &tp->t_event_devbusy);
		tp->t_flags |= TF_DEVBUSY;
		if (netif.tcp_dev_busy == 0) {
			tx_poll_active(&netif.idle_poll);
			netif.tcp_dev_busy = 1;
		}
	}
}

struct module_stub  tcp_device_stdio_mod = {
	module_init, module_clean
};

struct if_dev_cb _stdio_if_dev_cb = {
	head_size: 0,
	output: _netif_xmit,
	set_filter: NULL,
	socreate: ifdev_phony_socreate,
	dev_busy: stdio_device_devbusy,
	reply_mode: ifdev_phony_reply_mode,
	device_address: ifdev_phony_address,
	outter_address: ifdev_phony_address,
	keepalive_address: ifdev_phony_address
};
