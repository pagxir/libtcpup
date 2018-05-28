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

int ticks = 0;


extern struct module_stub  tcp_device_udp_mod;
extern struct module_stub  tcp_device_icmp_mod;
extern struct module_stub  tcp_device_icmp_user_mod;

extern struct if_dev_cb _udp_if_dev_cb;
extern struct if_dev_cb _icmp_if_dev_cb;
extern struct if_dev_cb _icmp_user_if_dev_cb;

static struct if_dev_cb * _if_dev_db = &_udp_if_dev_cb;
static struct module_stub  * _tcp_device_mod = &tcp_device_udp_mod;

void __utxpl_assert(const char *expr, const char *path, size_t line)
{
	LOG_FATAL("ASSERT FAILURE: %s:%d %s\n", path, line, expr);
	abort();
	return;
}

int utxpl_output(int offset, rgn_iovec *iov, size_t count, struct tcpup_addr const *name)
{
	return (*_if_dev_db->output)(offset, iov, count, name);
}

int get_device_mtu()
{
	int mtu = 1500;
	char *mtup = getenv("MTU");
	if (mtup != NULL) {
		int tmp_mtu = atoi(mtup);
		if (tmp_mtu >= 512 && tmp_mtu < 1500) mtu = tmp_mtu;
	}
	return mtu - _if_dev_db->head_size;
}

int set_filter_hook(FILTER_HOOK *hook)
{
	(*_if_dev_db->set_filter)(hook);
	return 0;
}

void tcp_devbusy(struct tcpcb *tp)
{
	(*_if_dev_db->dev_busy)(tp);
	return;
}

int utxpl_error()
{
#ifdef WIN32
	return WSAGetLastError();
#else
	return errno;
#endif
}


void set_ping_reply(int mode)
{
	(*_if_dev_db->reply_mode)(mode);
	return ;
}

void tcp_set_outter_address(struct tcpip_info *info)
{
	(*_if_dev_db->outter_address)(info);
	return ;
}

void tcp_set_device_address(struct tcpip_info *info)
{
	(*_if_dev_db->device_address)(info);
	return;
}

void tcp_set_keepalive_address(struct tcpip_info *info)
{
	(*_if_dev_db->keepalive_address)(info);
	return;
}

sockcb_t socreate(so_conv_t conv)
{
	return (*_if_dev_db->socreate)(conv);
}

void set_link_protocol(const char *link)
{
	if (strcmp(link, "udp") == 0
			|| strcmp(link, "UDP") == 0) {
		_tcp_device_mod = &tcp_device_udp_mod;
		_if_dev_db = &_udp_if_dev_cb;
		return;
	}

	if (strcmp(link, "icmp") == 0
			|| strcmp(link, "ICMP") == 0) {
		_tcp_device_mod = &tcp_device_icmp_mod;
		_if_dev_db = &_icmp_if_dev_cb;
		return;
	}

	if (strcmp(link, "icmp-user") == 0
			|| strcmp(link, "ICMP-USER") == 0) {
		_tcp_device_mod = &tcp_device_icmp_user_mod;
		_if_dev_db = &_icmp_user_if_dev_cb;
		return;
	}
}

static void module_init(void)
{
	_tcp_device_mod->init();
}

static void module_clean(void)
{
	_tcp_device_mod->clean();
}

struct module_stub  tcp_device_mod = {
	module_init, module_clean
};
