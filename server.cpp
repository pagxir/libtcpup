#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
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

#include <tcpup/tcp_device.h>

#include "tcp_channel.h"
#include "pstcp_channel.h"

void set_ping_reply(int);
void set_cc_algo(const char *name);
extern struct module_stub dns_async_mod;
extern struct module_stub tcp_timer_mod;
extern struct module_stub tcp_device_mod;
extern struct module_stub dns_forward_mod;
extern struct module_stub pstcp_listen_mod;

struct module_stub *modules_list[] = {
	&tcp_timer_mod, &tcp_device_mod, &dns_forward_mod,
   	&pstcp_listen_mod, &dns_async_mod, NULL
};

#ifdef _WINSRV_
void _winsrv_stop()
{
	tx_loop_t *loop = tx_loop_default();
	tx_loop_stop(loop);
	return;
}

int _winsrv(int argc, char *argv[])
#else
int main(int argc, char *argv[])
#endif
{
	struct tcpip_info listen_address = {0};
	struct tcpip_info outter_address = {0};
	struct tcpip_info forward_address = {0};
	struct tcpip_info interface_address = {0};

#ifdef _WIN32_
	WSADATA data;
	struct waitcb event;
	WSAStartup(0x101, &data);
#endif

	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-h") == 0) {
			fprintf(stderr, "%s [options] <FORWARD-ADDRESS>!\n", argv[0]);
			fprintf(stderr, "-h print this help!\n");
			fprintf(stderr, "-l <LISTEN-ADDRESS> listening tcp address!\n");
			fprintf(stderr, "-i <INTERFACE-ADDRESS> interface to send/recv data!\n");
#ifdef _FEATRUE_INOUT_TWO_INTERFACE_
			fprintf(stderr, "-o <OUTTER-ADDRESS> out going address, local address use for outgoing packet!\n");
#endif
			fprintf(stderr, "-cc.algo <CC-ALGO> algo to control send/recv data!\n");
			fprintf(stderr, "all ADDRESS should use this format <HOST:PORT> OR <PORT>\n");
			return 0;
		} else if (strcmp(argv[i], "-cc.algo") == 0 && i + 1 < argc) {
			set_cc_algo(argv[i + 1]);
			i++;
#ifndef WIN32
		} else if (strcmp(argv[i], "-d") == 0) {
			close(1); close(2);
			dup(open("server-stdout.txt", O_WRONLY|O_CREAT));
			if (fork()) exit(0);
			setsid();
			if (fork()) exit(0);
#endif
		} else if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
			get_target_address(&outter_address, argv[i + 1]);
			tcp_set_outter_address(&outter_address);
			i++;
		} else if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
			get_target_address(&interface_address, argv[i + 1]);
			i++;
		} else if (strcmp(argv[i], "-R") == 0 && i + 1 < argc) {
			route_cmd(argv[i + 1]);
			i++;
		} else if (strcmp(argv[i], "-l") == 0 && i + 1 < argc) {
			get_target_address(&listen_address, argv[i + 1]);
			i++;
		} else {
			get_target_address(&forward_address, argv[i]);
			continue;
		}
	}

	{
	struct in_addr si;
	si.s_addr = inet_addr("114.215.3.1");
	printf("%p via x\n", route_get(si));
	}

	set_ping_reply(1);
	tcp_set_device_address(&interface_address);
	pstcp_channel_forward(&forward_address);

	tcp_set_device_address(&listen_address);

	tx_loop_t *loop = tx_loop_default();
	tx_epoll_init(loop);
	tx_kqueue_init(loop);
	tx_completion_port_init(loop);
	tx_timer_ring_get(loop);

	initialize_modules(modules_list);
#ifndef WIN32
	signal(SIGPIPE, SIG_IGN);
#endif

	set_filter_hook(filter_hook_dns_forward);
	tx_loop_main(loop);

	cleanup_modules(modules_list);
#ifdef _WIN32_
	WSACleanup();
#endif
	return 0;
}

