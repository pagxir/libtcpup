#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>

#include <txall.h>

#include <tcpup/tcp_device.h>
#include "tcp_channel.h"

extern struct module_stub tcp_timer_mod;
extern struct module_stub tcp_device_mod;
extern struct module_stub tcp_listen_mod;
struct module_stub *modules_list[] = {
	&tcp_device_mod, &tcp_timer_mod, &tcp_listen_mod, NULL
};

int main(int argc, char *argv[])
{
	struct tcpip_info out_address = {0};
	struct tcpip_info proxy_address = {0};
	struct tcpip_info listen_address = {0};

#ifdef WIN32
	WSADATA data;
	WSAStartup(0x101, &data);
#else
	signal(SIGPIPE, SIG_IGN);
#endif

	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-h") == 0 && i + 1 < argc) {
			fprintf(stderr, "%s [options] <PROXY-ADDRESS>!\n", argv[0]);
			fprintf(stderr, "-h print this help!\n");
			fprintf(stderr, "-o <OUTGOING-ADDRESS> out going address, local address use for send packet!\n");
			fprintf(stderr, "-l <LISTEN-ADDRESS> listening tcp address!\n");
			fprintf(stderr, "all ADDRESS should use this format <HOST:PORT> OR <PORT>\n");
			fprintf(stderr, "\n");
			return 0;
		} else if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
			get_target_address(&out_address, argv[i + 1]);
			i++;
		} else if (strcmp(argv[i], "-l") == 0 && i + 1 < argc) {
			get_target_address(&listen_address, argv[i + 1]);
			i++;
		} else {
			get_target_address(&proxy_address, argv[i]);
			continue;
		}
	}

	tcp_set_device_address(&out_address);
	set_tcp_listen_address(&listen_address);

	tx_loop_t *loop = tx_loop_default();
    tx_epoll_init(loop);
    tx_kqueue_init(loop);
    tx_completion_port_init(loop);
    tx_timer_ring_get(loop);

	initialize_modules(modules_list);
	if (proxy_address.address == 0 || proxy_address.port == 0) {
		fprintf(stderr, "could not parse proxy address info\n");
		return -1;
	}

	tcp_channel_forward(&proxy_address);

	tx_loop_main(loop);

	cleanup_modules(modules_list);
#ifdef WIN32
	WSACleanup();
#endif
	return 0;
}

