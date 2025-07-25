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

void ifdev_phony_reply_mode(int mode) {}
void ifdev_phony_address(struct tcpip_info *info) {}
void ifdev_phony_dev_busy(struct tcpcb *tp, tx_task_t *task) {}
int ifdev_phony_output(int offset, rgn_iovec *iov, size_t count, struct tcpup_addr const *name, uint32_t link) {}
int ifdev_phony_set_filter(FILTER_HOOK *hook) {}
sockcb_t ifdev_phony_socreate(so_conv_t conv) {}

extern struct module_stub  tcp_device_udp_mod;
extern struct module_stub  tcp_device_icmp_mod;
extern struct module_stub  tcp_device_icmp_user_mod;
extern struct module_stub  tcp_device_stdio_mod;
extern struct module_stub  tcp_device_ipv6_mod;

extern struct if_dev_cb _udp_if_dev_cb;
extern struct if_dev_cb _icmp_if_dev_cb;
extern struct if_dev_cb _icmp_user_if_dev_cb;
extern struct if_dev_cb _stdio_if_dev_cb;
extern struct if_dev_cb _ipv6_if_dev_cb;

static struct if_dev_cb * _if_dev_db = &_udp_if_dev_cb;
static struct module_stub  * _tcp_device_mod = &tcp_device_udp_mod;

void __utxpl_assert(const char *expr, const char *path, size_t line)
{
	LOG_FATAL("ASSERT FAILURE: %s:%d %s\n", path, line, expr);
	abort();
	return;
}

int utxpl_output(int offset, rgn_iovec *iov, size_t count, struct tcpup_addr const *name, uint32_t link)
{
	return (*_if_dev_db->output)(offset, iov, count, name, link);
}

int get_device_mtu()
{
	int mtu = 1500 - 8;
	char *mtup = getenv("MTU");
	if (mtup != NULL) {
		int tmp_mtu = atoi(mtup);
		if (tmp_mtu >= 512 && tmp_mtu < 1500) mtu = tmp_mtu;
	}
	return mtu - _if_dev_db->head_size;
}

int set_filter_hook(FILTER_HOOK *hook)
{
	if (_if_dev_db->set_filter)
		(*_if_dev_db->set_filter)(hook);
	return 0;
}

void tcp_devbusy(struct tcpcb *tp, tx_task_t *task)
{
	(*_if_dev_db->dev_busy)(tp, task);
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

	if (strcmp(link, "udp6") == 0
			|| strcmp(link, "UDP6") == 0) {
		_tcp_device_mod = &tcp_device_ipv6_mod;
		_if_dev_db = &_ipv6_if_dev_cb;
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

	if (strcmp(link, "stdio") == 0
			|| strcmp(link, "STDIO") == 0) {
		_tcp_device_mod = &tcp_device_stdio_mod;
		_if_dev_db = &_stdio_if_dev_cb;
		return;
	}
}

socklen_t get_link_target(struct sockaddr *dest, socklen_t *destlen, const char *target)
{
    int nmatch, rc = 0;
    char domain[128], portstr[64] = "0";
    struct sockaddr_in6 *in6p = (struct sockaddr_in6 *)dest;

    nmatch = sscanf(target, "[%[0-9:.a-fA-F]]:%s", domain, portstr);
    if ((nmatch == 1 || nmatch == 2) && *destlen >= sizeof(*in6p)) {
	in6p->sin6_family = AF_INET6;
	in6p->sin6_port   = htons(atoi(portstr));
	rc = inet_pton(AF_INET6, domain, &in6p->sin6_addr);
	fprintf(stderr, "ipv6: %s, port: %s\n", domain, portstr);
	*destlen = sizeof(*in6p);
	goto check_acceptable;
    }

    if (*target == ':' || !strchr(target, '.')) {
	const char *strp = *target == ':'? target +1: target;
	if (_tcp_device_mod == &tcp_device_ipv6_mod && *destlen >= sizeof(*in6p)) {
	    in6p->sin6_family = AF_INET6;
	    in6p->sin6_port   = htons(atoi(strp));
	    in6p->sin6_addr   = in6addr_any;
	} else {
#if 0
	    inp->sin_family = AF_INET;
	    inp->sin_port   = htons(atoi(strp));
	    inp->sin_addr.s_addr   = INADDR_ANY;
#endif
        assert(0);
	}
    }

    nmatch = sscanf(target, "%[0-9.]:%s", domain, portstr);
	if ((nmatch == 1 || nmatch == 2) && *destlen >= sizeof(*in6p)) {
		in6p->sin6_family = AF_INET6;
		in6p->sin6_port   = htons(atoi(portstr));

        struct in_addr one;
		rc = inet_pton(AF_INET, domain, &one);
        inet_4to6(&in6p->sin6_addr, &one);
		fprintf(stderr, "ipv4: %s, port: %s\n", domain, portstr);
		*destlen = sizeof(*in6p);
		goto check_acceptable;
	}

    nmatch = sscanf(target, "%[^:]:%s", domain, portstr);
    if (nmatch < 1) {
	fprintf(stderr, "invalid format %s\n", target);
	return -1;
    }

    struct addrinfo hints;
    struct addrinfo *result, *rp;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE;
    hints.ai_protocol = 0;
    hints.ai_canonname = NULL;
    hints.ai_addr = NULL;
    hints.ai_next = NULL;

    if (_tcp_device_mod == &tcp_device_ipv6_mod) {
	hints.ai_family = AF_INET6;
    }

    rc = getaddrinfo(NULL, domain, &hints, &result);
    if (rc != 0) {
	fprintf(stderr, "domain: %s, port: %s\n", domain, portstr);
	return rc;
    }

    for (rp = result; rp != NULL; rp = rp->ai_next) {
	if (*destlen >= rp->ai_addrlen) {
	    memcpy(dest, rp->ai_addr, rp->ai_addrlen);
	    *destlen = rp->ai_addrlen;
	    break;
	}
    }

    freeaddrinfo(result);

check_acceptable:
    if (_tcp_device_mod == &tcp_device_ipv6_mod && in6p->sin6_family != AF_INET6) {
	fprintf(stderr, "address unacceptable v6: %s\n", target);
	return -1;
    }

    return rc;
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
