#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include <txall.h>

#include <tcpup/tcp_device.h>
#include "tcp_channel.h"
#include "pstcp_channel.h"

extern struct module_stub timer_mod;
extern struct module_stub slotsock_mod;
extern struct module_stub tcp_timer_mod;
extern struct module_stub tcp_device_mod;
extern struct module_stub pstcp_listen_mod;

struct module_stub *modules_list[] = {
	&slotsock_mod, &tcp_timer_mod, &tcp_device_mod,
   	&timer_mod, &pstcp_listen_mod, NULL
};

int main(int argc, char *argv[])
{
	struct tcpip_info listen_address = {0};
	struct tcpip_info forward_address = {0};


#ifdef _WIN32_
	WSADATA data;
	struct waitcb event;
	WSAStartup(0x101, &data);
#endif

	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-h") == 0 && i + 1 < argc) {
			fprintf(stderr, "%s [options] <FORWARD-ADDRESS>!\n", argv[0]);
			fprintf(stderr, "-h print this help!\n");
			fprintf(stderr, "-l <LISTEN-ADDRESS> listening tcp address!\n");
			fprintf(stderr, "all ADDRESS should use this format <HOST:PORT> OR <PORT>\n");
			fprintf(stderr, "\n");
			return 0;
		} else if (strcmp(argv[i], "-l") == 0 && i + 1 < argc) {
			get_target_address(&listen_address, argv[i + 1]);
			i++;
		} else {
			get_target_address(&forward_address, argv[i]);
			continue;
		}
	}

	pstcp_channel_forward(&forward_address);

	tcp_set_device_address(&listen_address);
	initialize_modules(modules_list);

	tx_loop_t *loop = tx_loop_default();
	tx_loop_main(loop);

	cleanup_modules(modules_list);
#ifdef _WIN32_
	WSACleanup();
#endif
	return 0;
}

