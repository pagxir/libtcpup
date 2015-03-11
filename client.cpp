#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>

#include <wait/module.h>
#include <wait/platform.h>
#include <wait/slotwait.h>

#include <tcpup/tcp_device.h>
#include "tcp_channel.h"

extern struct module_stub timer_mod;
extern struct module_stub slotsock_mod;
extern struct module_stub tcp_timer_mod;
extern struct module_stub tcp_device_mod;
extern struct module_stub tcp_listen_mod;
struct module_stub *modules_list[] = {
	&timer_mod, &slotsock_mod, &tcp_device_mod, 
	&tcp_timer_mod, &tcp_listen_mod, NULL
};

static int get_target_address(struct tcpip_info *info, const char *address)
{
	const char *last;

#define FLAG_HAVE_DOT    1
#define FLAG_HAVE_ALPHA  2
#define FLAG_HAVE_NUMBER 4
#define FLAG_HAVE_SPLIT  8

	int flags = 0;
	char host[128] = {};

	for (last = address; *last; last++) {
		if (isdigit(*last)) flags |= FLAG_HAVE_NUMBER;
		else if (*last == ':') flags |= FLAG_HAVE_SPLIT;
		else if (*last == '.') flags |= FLAG_HAVE_DOT;
		else if (isalpha(*last)) flags |= FLAG_HAVE_ALPHA;
		else { fprintf(stderr, "get target address failure!\n"); return -1;}
	}

	if (flags == FLAG_HAVE_NUMBER) {
		info->port = htons(atoi(address));
		return 0;
	}

	if (flags == (FLAG_HAVE_NUMBER| FLAG_HAVE_DOT)) {
		info->address = inet_addr(address);
		return 0;
	}

	struct hostent *host0 = NULL;
	if ((flags & ~FLAG_HAVE_NUMBER) == (FLAG_HAVE_ALPHA | FLAG_HAVE_DOT)) {
		host0 = gethostbyname(address);
		if (host0 != NULL)
			memcpy(&info->address, host0->h_addr, 4);
		return 0;
	}

	if (flags & FLAG_HAVE_SPLIT) {
		const char *split = strchr(address, ':');
		info->port = htons(atoi(split + 1));

		if (strlen(address) < sizeof(host)) {
			strncpy(host, address, sizeof(host));
			host[split - address] = 0;

			if (flags & FLAG_HAVE_ALPHA) {
				 host0 = gethostbyname(host);
				 if (host0 != NULL)
					 memcpy(&info->address, host0->h_addr, 4);
				 return 0;
			}

			info->address = inet_addr(host);
		}
	}

	return 0;
}

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

	slotwait_held(0);
	initialize_modules(modules_list);
	if (proxy_address.address == 0 || proxy_address.port == 0) {
		fprintf(stderr, "could not parse proxy address info\n");
		return -1;
	}

	tcp_channel_forward(&proxy_address);

	slotwait_start();
	while (slotwait_step());

	cleanup_modules(modules_list);
#ifdef WIN32
	WSACleanup();
#endif
	return 0;
}

