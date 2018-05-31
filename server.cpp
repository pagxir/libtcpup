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

void set_link_protocol(const char *link);

#ifndef WIN32
struct termios orig_termios;

void disable_raw_mode()
{
	tcsetattr(STDIN_FILENO, TCSAFLUSH, &orig_termios);
	exit(-1);
}

static void enable_raw_mode()
{
	if (tcgetattr(STDIN_FILENO, &orig_termios) == -1) abort();
	atexit(disable_raw_mode);

	struct termios raw = orig_termios;
    cfmakeraw(&raw);
    raw.c_cflag |= (CLOCAL | CREAD | CSTOPB);
    raw.c_iflag &= ~(IXON);
	raw.c_cc[VTIME] = 0;
	raw.c_cc[VMIN] = 1;
	
    tcflush(STDIN_FILENO, TCIOFLUSH);

	if (tcsetattr(STDIN_FILENO, TCSANOW, &raw) == -1) abort();
}
#endif


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
	int istty = 0;
	struct tcpip_info listen_address = {0};
	struct tcpip_info outter_address = {0};
	struct tcpip_info forward_address = {0};
	struct tcpip_info interface_address = {0};
	struct tcpip_info keepalive_address = {0};

#ifdef WIN32
	WSADATA data;
	WSAStartup(0x101, &data);
#endif
	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-h") == 0) {
			fprintf(stderr, "%s [options] <FORWARD-ADDRESS>!\n", argv[0]);
			fprintf(stderr, "-h print this help!\n");
			fprintf(stderr, "-l <LISTEN-ADDRESS> listening tcp address!\n");
			fprintf(stderr, "-link lower link <UDP/ICMP/ICMP-USER>!\n");
			fprintf(stderr, "-i <INTERFACE-ADDRESS> interface to send/recv data!\n");
#ifdef _FEATRUE_INOUT_TWO_INTERFACE_
			fprintf(stderr, "-o <OUTTER-ADDRESS> out going address, local address use for outgoing packet!\n");
#endif
			fprintf(stderr, "-cc.algo <CC-ALGO> algo to control send/recv data!\n");
			fprintf(stderr, "all ADDRESS should use this format <HOST:PORT> OR <PORT>\n");
			return 0;
		} else if (strcmp(argv[i], "-cc.algo") == 0 && i + 1 < argc) {
			i++;
		} else if (strcmp(argv[i], "-d") == 0) {
		} else if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
			i++;
		} else if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
			i++;
		} else if (strcmp(argv[i], "-R") == 0 && i + 1 < argc) {
			i++;
		} else if (strcmp(argv[i], "-link") == 0 && i + 1 < argc) {
			istty = !strcmp(argv[i + 1], "STDIO");
			set_link_protocol(argv[i + 1]);
			i++;
		} else if (strcmp(argv[i], "-K") == 0 && i + 1 < argc) {
			i++;
		} else if (strcmp(argv[i], "-l") == 0 && i + 1 < argc) {
			i++;
		} else {
			continue;
		}
	}

	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-h") == 0) {
			fprintf(stderr, "%s [options] <FORWARD-ADDRESS>!\n", argv[0]);
			fprintf(stderr, "-h print this help!\n");
			fprintf(stderr, "-l <LISTEN-ADDRESS> listening tcp address!\n");
			fprintf(stderr, "-link lower link <UDP/ICMP/ICMP-USER>!\n");
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
		} else if (strcmp(argv[i], "-K") == 0 && i + 1 < argc) {
			get_target_address(&keepalive_address, argv[i + 1]);
			i++;
		} else if (strcmp(argv[i], "-link") == 0 && i + 1 < argc) {
			i++;
		} else if (strcmp(argv[i], "-l") == 0 && i + 1 < argc) {
			get_target_address(&listen_address, argv[i + 1]);
			i++;
		} else {
			get_target_address(&forward_address, argv[i]);
			continue;
		}
	}

	set_ping_reply(1);
	tcp_set_device_address(&interface_address);
	tcp_set_keepalive_address(&keepalive_address);
	pstcp_channel_forward(&forward_address);

	tcp_set_device_address(&listen_address);

	tx_loop_t *loop = tx_loop_default();
	tx_epoll_init(loop);
	tx_kqueue_init(loop);
	tx_completion_port_init(loop);
	tx_timer_ring_get(loop);

#ifndef WIN32
	if (istty) {
		enable_raw_mode();
		static tx_timer_t timeout;
		static tx_task_t idle_exit;
		tx_task_init(&idle_exit, loop, (void (*)(void *))exit, NULL);
		tx_timer_init(&timeout, loop, &idle_exit);
		tx_timer_reset(&timeout, 3000 * 1000);
	}
#endif

	initialize_modules(modules_list);
#ifndef WIN32
	signal(SIGPIPE, SIG_IGN);
#endif

	set_filter_hook(filter_hook_dns_forward);
	tx_loop_main(loop);

	cleanup_modules(modules_list);
#ifdef WIN32
	WSACleanup();
#endif
	return 0;
}

