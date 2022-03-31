#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>

#include <txall.h>

#include <utx/utxpl.h>
#include <tcpup/tcp_device.h>
#include "tcp_channel.h"

#ifdef WIN32
int setenv(const char *k, const char *v, int f)
{
	char buf[4096];
	snprintf(buf, sizeof(buf), "%s=%s", k, v);
	return putenv(buf);
}
#endif

void set_cc_algo(const char *name);
extern struct module_stub tcp_timer_mod;
extern struct module_stub tcp_device_mod;
extern struct module_stub tcp_listen_mod;
struct module_stub *modules_list[] = {
	&tcp_device_mod, &tcp_timer_mod, &tcp_listen_mod, NULL
};

void set_link_protocol(const char *link);
socklen_t get_link_target(struct sockaddr *dest, socklen_t *destlen, const char *target);

int filter_hook_keepalive_receive(int netif, void *buf, size_t len, const struct tcpup_addr *from)
{
	int err = -1;
	int magic = -1;
	union {
		uint8_t arr[4];
		uint32_t addr;
	} na;
	int a, b, c, d, prefix;

	struct udpuphdr *udphdr = NULL;

	char *payload = (char *)buf;
	char *payload_limit = (payload + len);

	/* HELO 192.168.1.0/24 is here */
	if (memcmp(buf, "HELO", 4) == 0 &&
			sscanf(payload, "HELO %d.%d.%d.%d/%d is here", &a, &b, &c, &d, &prefix) == 5) {
		struct sockaddr_in *inp = (struct sockaddr_in *)&from->name;
		struct sockaddr_in6 *in6p = (struct sockaddr_in6 *)&from->name;

		char _nb[128], mem[256];
	       	const void *dest = (inp->sin_family == AF_INET? (void*)&inp->sin_addr: (void*)&in6p->sin6_addr);
		na.arr[0] = a; na.arr[1] = b; na.arr[2] = c; na.arr[3] = d;

		fprintf(stderr, "register_network: %s/%d via %s:%d\n",
				inet_ntop(AF_INET, &na, _nb, sizeof(_nb)), prefix,
				inet_ntop(inp->sin_family, dest, mem, sizeof(mem)), htons(inp->sin_port));
		tcp_channel_forward((struct sockaddr *)from->name, from->namlen);
		return 1;
	}

	return 0;
}

int main(int argc, char *argv[])
{
    const char *proxy = NULL;
    struct tcpip_info outter_address = {0};
    struct tcpip_info listen_address = {0};
    struct tcpip_info interface_address = {0};

    union {
        struct sockaddr_in v4;
        struct sockaddr_in6 v6;
    } proxy_mem;

    socklen_t proxy_length = sizeof(proxy_mem);
    struct sockaddr *proxy_address = (struct sockaddr *)&proxy_mem;

#ifdef WIN32
    WSADATA data;
    WSAStartup(0x101, &data);
#else
    signal(SIGPIPE, SIG_IGN);
#endif
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0) {
            fprintf(stderr, "%s [options] <PROXY-ADDRESS>!\n", argv[0]);
            fprintf(stderr, "-h print this help!\n");
#ifdef _FEATRUE_INOUT_TWO_INTERFACE_
            fprintf(stderr, "-o <OUTTER-ADDRESS> out going address, local address use for outgoing packet!\n");
#endif
            fprintf(stderr, "-i <INTERFACE-ADDRESS> interface address, local address use for outgoing/incoming packet!\n");
            fprintf(stderr, "-l <LISTEN-ADDRESS> listening tcp address!\n");
            fprintf(stderr, "-link lower link <UDP/ICMP/ICMP-USER>!\n");
            fprintf(stderr, "-cc.algo <CC-ALGO> algo to control send/recv data!\n");
            fprintf(stderr, "all ADDRESS should use this format <HOST:PORT> OR <PORT>\n");
            fprintf(stderr, "\n");
            return 0;
        } else if (strcmp(argv[i], "-cc.algo") == 0 && i + 1 < argc) {
            i++;
        } else if (strcmp(argv[i], "-mtu") == 0 && i + 1 < argc) {
            i++;
        } else if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            i++;
        } else if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
            i++;
        } else if (strcmp(argv[i], "-link") == 0 && i + 1 < argc) {
            set_link_protocol(argv[i + 1]);
            i++;
        } else if (strcmp(argv[i], "-l") == 0 && i + 1 < argc) {
            i++;
        } else {
            continue;
        }
    }

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0) {
            fprintf(stderr, "%s [options] <PROXY-ADDRESS>!\n", argv[0]);
            fprintf(stderr, "-h print this help!\n");
#ifdef _FEATRUE_INOUT_TWO_INTERFACE_
            fprintf(stderr, "-o <OUTTER-ADDRESS> out going address, local address use for outgoing packet!\n");
#endif
            fprintf(stderr, "-i <INTERFACE-ADDRESS> interface address, local address use for outgoing/incoming packet!\n");
            fprintf(stderr, "-l <LISTEN-ADDRESS> listening tcp address!\n");
            fprintf(stderr, "-cc.algo <CC-ALGO> algo to control send/recv data!\n");
            fprintf(stderr, "-link lower link <UDP/ICMP/ICMP-USER>!\n");
            fprintf(stderr, "all ADDRESS should use this format <HOST:PORT> OR <PORT>\n");
            fprintf(stderr, "\n");
            return 0;
        } else if (strcmp(argv[i], "-cc.algo") == 0 && i + 1 < argc) {
            set_cc_algo(argv[i + 1]);
            i++;
        } else if (strcmp(argv[i], "-mtu") == 0 && i + 1 < argc) {
            setenv("MTU", argv[i+1], 1);
            i++;
        } else if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            get_target_address(&outter_address, argv[i + 1]);
            tcp_set_outter_address(&outter_address);
            i++;
        } else if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
            get_target_address(&interface_address, argv[i + 1]);
            i++;
        } else if (strcmp(argv[i], "-link") == 0 && i + 1 < argc) {
            i++;
        } else if (strcmp(argv[i], "-l") == 0 && i + 1 < argc) {
            get_target_address(&listen_address, argv[i + 1]);
            i++;
        } else {
            proxy = argv[i];
            continue;
        }
    }

    tcp_set_device_address(&interface_address);
    set_tcp_listen_address(&listen_address);

    tx_loop_t *loop = tx_loop_default();
    tx_epoll_init(loop);
    tx_kqueue_init(loop);
    tx_completion_port_init(loop);
    tx_timer_ring_get(loop);

    initialize_modules(modules_list);
    if (proxy == 0 || get_link_target(proxy_address, &proxy_length, proxy) <= 0) {
        fprintf(stderr, "could not parse proxy address info\n");
        return -1;
    }

    tcp_channel_forward(proxy_address, proxy_length);

    set_filter_hook(filter_hook_keepalive_receive);
    tx_loop_main(loop);

    cleanup_modules(modules_list);
#ifdef WIN32
    WSACleanup();
#endif
    return 0;
}
