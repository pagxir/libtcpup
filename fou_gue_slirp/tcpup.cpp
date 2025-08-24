#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/uio.h>

#include <ctype.h>
#include <signal.h>

#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <txall.h>

#include <utx/utxpl.h>
#include <utx/dns_fwd.h>
#include <utx/socket.h>
#include <utx/router.h>

#define IF_DEV 1
#include <tcpup/tcp_device.h>
#include <tcpup/tcp_subr.h>

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#ifndef WIN32
#include <termios.h>
#endif

#include "tcp_channel.h"
#include "pstcp_channel.h"

typedef void f_tcp_packet_receive(void *frame, size_t len, void *buf);
static f_tcp_packet_receive *tcp_packet_receive;

typedef int f_tcp_write(void *head, size_t hlen, void *payload, size_t len);
void set_tcp_send_handler(f_tcp_write *handler);

#define AFTYP_INET   1
#define AFTYP_INET6  4
static uint8_t builtin_target[] = {AFTYP_INET, 0, 0, 22, 127, 0, 0, 1};
static uint8_t builtin_target6[] = {AFTYP_INET6, 0, 0, 22, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
void set_tcp_destination(uint8_t *buf, size_t len);

extern struct if_dev_cb _stdio_if_dev_cb;

static uint16_t csum_fold(uint32_t val)
{
    while (val >> 16)
        val = (val >> 16) + (val & 0xffff);

    return val;
}

static void swap_uint16(void *p1, void *p2)
{
	uint16_t *d1 = (uint16_t *)p1;
	uint16_t *d2 = (uint16_t *)p2;
	uint16_t d = *d1;

	*d1 = *d2;
	*d2 = d;

	return;
}

int tcpup_write(void *head, size_t hlen, void *payload, size_t len)
{
	u_short *link;
	struct tcpup_addr from = {};
	uint32_t check = 0, verify = 0;

	int modidx = 0;
	uint8_t *l2 = (uint8_t *)head;
	uint8_t *l3 = (uint8_t *)payload;

	assert(hlen + len >= 40);
	switch (*l2 >> 4) {
		case 0x4:
			link = (u_short *)(l2 + 12);
			check = link[0] + link[1] + link[2] + link[3];
			// verify = csum_fold(link[0] + link[1] + link[2] + link[3]);

			memcpy(builtin_target + 2, l3 + 2, 2);
			memcpy(builtin_target + 4, l2 + 16, 4);
			set_tcp_destination(builtin_target, 8);

			check = csum_fold(check);
			swap_uint16(l3, l3 + 2);

			// modidx = 1;
			break;

		case 0x6:
			check = 0;
			link = (u_short *)(l2 + 8);
			for (int i = 0; i < 16; i++) check += link[i];
			// verify = csum_fold(check);
			// check -= link[7];

			memcpy(builtin_target6 + 2, l3 + 2, 2);
			memcpy(builtin_target6 + 4, l2 + 24, 16);
			set_tcp_destination(builtin_target6, sizeof(builtin_target6));

			check = csum_fold(check);
			swap_uint16(l3, l3 + 2);
			// modidx = 7;
			break;

		default:
			(void)verify;
			(void)modidx;
			assert(0);
			break;
	}

	tcpup_do_packet(0, (const char *)payload, len, &from, check);
	return len + hlen;
}

extern int tcp_packet_receive_by_stream(int id, void *frame, size_t len, void *buf);

static int tcpup_netif_xmit(int subdev, rgn_iovec *iov, size_t count, struct tcpup_addr const *name, uint32_t link)
{
	char buf[8192];
	char *frame = buf + 80;

	char * ptr = frame;

	for (int i = 0; i < count; i++) {
		memmove(ptr, iov[i].iov_base, iov[i].iov_len);
		ptr += iov[i].iov_len;
	}

    uint16_t *port = (uint16_t*)(frame);
	size_t total = (ptr - frame);
	LOG_VERBOSE("stream id = %x\n", port[1]);

	return tcp_packet_receive_by_stream(port[1], frame, total, buf);
	// return total;
}

void set_ping_reply(int);
void set_cc_algo(const char *name);
extern struct module_stub tcp_timer_mod;
extern struct module_stub tcp_device_mod;
extern struct module_stub pstcp_listen_mod;

struct module_stub *modules_list[] = {
	&tcp_timer_mod, &tcp_device_mod,
   	&pstcp_listen_mod, NULL
};

void set_link_protocol(const char *link);

int ipv6_npt_add(const char *src_pfx, const char *dst_pfx, size_t pfx_len);

void tcpup_init(tx_loop_t *loop, f_tcp_packet_receive *func)
{
#ifndef WIN32
	signal(SIGPIPE, SIG_IGN);
#endif

	set_link_protocol("STDIO");
	initialize_modules(modules_list);
	// set_filter_hook(filter_hook_dns_forward);

	set_tcp_send_handler(tcpup_write);
	tcp_packet_receive = func;
	_stdio_if_dev_cb.output = tcpup_netif_xmit;
	_stdio_if_dev_cb.head_size = 40 + 8 + 24;

	return;
}

