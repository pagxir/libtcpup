#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>

#include <txall.h>

#include <utx/utxpl.h>
#include <tcpup/tcp_device.h>
#include "tcp_channel.h"

void set_cc_algo(const char *name);
extern struct module_stub tcp_timer_mod;
extern struct module_stub tcp_device_mod;
extern struct module_stub tcp_listen_mod;
struct module_stub *modules_list[] = {
	&tcp_device_mod, &tcp_timer_mod, &tcp_listen_mod, NULL
};

int main(int argc, char *argv[])
{
	struct tcpip_info proxy_address = {0};
	struct tcpip_info outter_address = {0};
	struct tcpip_info listen_address = {0};
	struct tcpip_info interface_address = {0};

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
			fprintf(stderr, "-cc.algo <CC-ALGO> algo to control send/recv data!\n");
			fprintf(stderr, "all ADDRESS should use this format <HOST:PORT> OR <PORT>\n");
			fprintf(stderr, "\n");
			return 0;
		} else if (strcmp(argv[i], "-cc.algo") == 0 && i + 1 < argc) {
			set_cc_algo(argv[i + 1]);
			i++;
		} else if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
			get_target_address(&outter_address, argv[i + 1]);
			tcp_set_outter_address(&outter_address);
			i++;
		} else if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
			get_target_address(&interface_address, argv[i + 1]);
			i++;
		} else if (strcmp(argv[i], "-l") == 0 && i + 1 < argc) {
			get_target_address(&listen_address, argv[i + 1]);
			i++;
		} else {
			get_target_address(&proxy_address, argv[i]);
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

