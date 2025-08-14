#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <assert.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <stdint.h>

#define ARRAY_SIZE(array) (sizeof(array)/sizeof(*array))
#define LOG_VERBOSE(expr, ...) printf(expr, ##__VA_ARGS__)

#define MAX_INT(a, b) ((a) < (b)? (b): (a))
static char buffer[65536];
const int XORVAL = 0x5a;
const int g_trace_enable = 0;

typedef struct inner_ident_s {
	struct in6_addr src;
	struct in6_addr dst;
	uint16_t port_src;
	uint16_t port_dst;
} inner_ident_t;

struct session_worker {
	int sockfd;
	time_t last_active;
	inner_ident_t ident;
};

struct session_worker *_worker_list[1000];
static void invert(void *buf, size_t len, uint8_t key)
{
    uint8_t *data = (uint8_t *)buf;
    uint8_t *last = data + len;

	if (getenv("DISABLE_INVERT")) {
		int skip = 4;
		data[skip + 6] ^= XORVAL;
		data[skip + 7] = 0xff;
		return;
	}

	last--;
	while (last > data) {
		uint8_t t = *data;
		*data = *last;
		*last = t;
		data++;
		last--;
	}
}

static int worker_update(struct session_worker *worker, fd_set *readfds, int maxfd)
{
	if (worker && worker->sockfd >= 0) {
		maxfd = MAX_INT(worker->sockfd, maxfd);
		FD_SET(worker->sockfd, readfds);
	}

	return maxfd;
}

static int worker_receive(struct session_worker *worker, fd_set *readfds, int tunnelfd)
{
	int err;
	int receive = 0;
	struct sockaddr_in target;
	socklen_t fromlen = sizeof(target);

	if (worker && worker->sockfd >= 0
			&& FD_ISSET(worker->sockfd, readfds)) {
		const int skip = 4;
		int sockfd = worker->sockfd;
		struct sockaddr *to = (struct sockaddr *)&target;
		target.sin_family = AF_INET;
		receive = recvfrom(sockfd, buffer, sizeof(buffer), MSG_DONTWAIT, (struct sockaddr *)&target, &fromlen);

		while (receive > skip) {
			invert(buffer, receive, XORVAL);
			memcpy(&target.sin_addr, &buffer[skip + 40 - 4], 4);
			socklen_t tolen = sizeof(target);

			err = sendto(tunnelfd, buffer + skip, receive - skip, 0, to, tolen);
			if (g_trace_enable) LOG_VERBOSE("send data to isatap: err = %d fd = %d\n", err, tunnelfd);
			assert (err > 0);

			fromlen = sizeof(target);
			worker->last_active = time(NULL);
			receive = recvfrom(sockfd, buffer, sizeof(buffer), MSG_DONTWAIT, (struct sockaddr *)&target, &fromlen);
		}
	}

	return tunnelfd;
}

static int worker_dispatch(struct session_worker *worker, void *buf, size_t len, struct sockaddr *target, size_t tolen)
{
	int dispatched = 0;
	const inner_ident_t *data = (const inner_ident_t *)(((uint16_t *)buf) + 2 + 4); // 4 + 40 - 16 / 2

	if (worker && worker->sockfd >= 0) {
		if (IN6_ARE_ADDR_EQUAL(&worker->ident.src, &data->src) && worker->ident.port_src == data->port_src) {
			invert(buf, len, XORVAL);
			
			int err = sendto(worker->sockfd, buf, len, 0, target, tolen);
			if (g_trace_enable) LOG_VERBOSE("send data to peer: err = %d fd = %d\n", err, worker->sockfd);
			worker->last_active = time(NULL);
			dispatched = 1;
		}
	}

	return dispatched;
}

static int update_bufsize(int sockfd)
{
	int ret;
	int bufsize = 0;
	int optlen = sizeof(bufsize);
#define BUFSIZE (655360 * 2)

	ret = getsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &bufsize, &optlen);
	if (ret == 0 && bufsize < BUFSIZE) {
		printf("update send buffer to %d %d\n", bufsize, BUFSIZE);
		bufsize = BUFSIZE;
		setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
	}

	ret = getsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &bufsize, &optlen);
	if (ret == 0 && bufsize < BUFSIZE) {
		printf("update receive buffer to %d %d\n", bufsize, BUFSIZE);
		bufsize = BUFSIZE;
		setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));
	}

	return ret;
}

static int worker_assign(struct session_worker *worker, const void *buf)
{
	const inner_ident_t *data = (const inner_ident_t *)(((uint16_t *)buf) + 2 + 4); // 4 + 40 - 32 / 2

	assert(worker != NULL);
	memcpy(&worker->ident, data, sizeof(worker->ident));
	worker->last_active = time(NULL);

	close(worker->sockfd);
	worker->sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	update_bufsize(worker->sockfd);

	return 0;
}

int main(int argc, char *argv[])
{
	int err = 0;
	int turnon = 0;
	fd_set readfds;
	struct sockaddr_in addr;
	int tunnelfd, udpfd, maxfd, nready;

	// IPPROTO_IPIP IPPROTO_GRE IPPROTO_ESP IPPROTO_AH
	tunnelfd  = socket(AF_INET, SOCK_RAW, IPPROTO_IPV6);
	update_bufsize(tunnelfd);

	maxfd = MAX_INT(tunnelfd, udpfd);

	addr.sin_family = AF_INET;
	addr.sin_port   = 0;
	addr.sin_addr.s_addr = INADDR_ANY;

	err = bind(tunnelfd, (struct sockaddr *)&addr, sizeof(addr));
	assert (err == 0);

	struct sockaddr_in target_udp;
	target_udp.sin_family = AF_INET;
	target_udp.sin_port   = htons(7890);
	inet_pton(AF_INET, "137.175.53.113", &target_udp.sin_addr);

	for (int i = 1; i < argc; i++) {
		char bud[164];
		const char *hostpair = argv[i];
		
		int j = 0;
		while (*hostpair) {
			int ch = bud[j++] = *hostpair++;
			if (ch == ':') {
				j--;
				break;
			}
		}
		bud[j++] = 0;
		if (*hostpair) 
			target_udp.sin_port = htons(atoi(hostpair));
		inet_pton(AF_INET, bud, &target_udp.sin_addr);
	}

	if (argc > 1) {
		char abuf[64];
		inet_ntop(AF_INET, &target_udp.sin_addr, abuf, sizeof(abuf));
		LOG_VERBOSE("target %s:%d\n", abuf, htons(target_udp.sin_port));
	}

	struct sockaddr_in target_tunnel;
	target_tunnel.sin_family = AF_INET;
	target_tunnel.sin_port   = 0;
	target_tunnel.sin_addr.s_addr = INADDR_ANY;

	setsockopt(tunnelfd, IPPROTO_IP, IP_HDRINCL, &turnon, sizeof(turnon));

	do {
		maxfd = tunnelfd;
		FD_ZERO(&readfds);
		FD_SET(tunnelfd, &readfds);
		for (int i = 0; i < ARRAY_SIZE(_worker_list); i++)
			maxfd = worker_update(_worker_list[i], &readfds, maxfd);

		struct timeval timeout = {
			.tv_sec = 10
		};

		nready = select(maxfd + 1, &readfds, NULL, NULL, &timeout);
		if (nready > 0) {
			struct sockaddr *from = (struct sockaddr *)&addr;
			socklen_t fromlen = sizeof(addr);
			int receive = 0;
			char abuf[63];

			struct sockaddr *to;
			socklen_t tolen = 0;
			int tofd = 0;
			int skip = 0;
			int ipwrap = 0;

			for (int i = 0; i < ARRAY_SIZE(_worker_list); i++)
				worker_receive(_worker_list[i], &readfds, tunnelfd);

			if (FD_ISSET(tunnelfd, &readfds)) {
				to = (struct sockaddr *)&target_udp;
				tolen = sizeof(target_udp);
				skip = 16;
				receive = recvfrom(tunnelfd, buffer, sizeof(buffer),
						MSG_DONTWAIT, (struct sockaddr *)&target_tunnel, &fromlen);
				*(uint32_t *)(buffer + skip) = random();

				memcpy(&addr, &target_tunnel, sizeof(addr));
			}

			if (receive > skip) {
				// fprintf(stderr, "recieve=%d from tunnelfd=%d\n", receive, tunnelfd);
				// inet_ntop(AF_INET, &addr.sin_addr, abuf, sizeof(abuf));

				int dispatched = 0;
				for (int i = 0; i < ARRAY_SIZE(_worker_list) && !dispatched; i++)
					dispatched = worker_dispatch(_worker_list[i], buffer + skip, receive - skip, to, tolen);

				if (!dispatched) {
					struct session_worker *worker = NULL;

					for (int i = 0; i < ARRAY_SIZE(_worker_list); i++) {
						worker = _worker_list[i];
						if (worker == NULL) {
							worker = (struct session_worker *)calloc(1, sizeof(*worker));
							_worker_list[i] = worker;
							worker->sockfd = -1;
							worker_assign(worker, buffer + skip);
							dispatched = 1;
							break;
						}
					}

					if (!dispatched) {
						int last_select = -1;
						int last_inactive = time(NULL);

						for (int i = 0; i < ARRAY_SIZE(_worker_list); i++) {
							worker = _worker_list[i];
							assert(worker != NULL);

							if (worker->last_active < last_inactive) {
								last_inactive = worker->last_active;
								last_select = i;
							}
						}

						worker = NULL;
						if (last_select >= 0) {
							worker = _worker_list[last_select];
							worker_assign(worker, buffer + skip);
							dispatched = 1;
						}
					}

					dispatched = worker_dispatch(worker, buffer + skip, receive - skip, to, tolen);
					if (g_trace_enable) LOG_VERBOSE("final dispatched=%d\n", dispatched);
				}
			}
		} else if (nready == 0) {
			int save = -1;
			int *shufflingfd = &save; 
			time_t last_active = 0;
			time_t *last_activep = &last_active;

			for (int i = 0; i < ARRAY_SIZE(_worker_list); i++) {
				struct session_worker * item = _worker_list[i];
				if (item && item->sockfd >= 0) {
					*shufflingfd = item->sockfd;
					shufflingfd = &item->sockfd;
					*last_activep = item->last_active;
					last_activep = &item->last_active;
				}
			}

			*shufflingfd = save;
			*last_activep = last_active;
			printf("select timeout, do shuffling\n");
		} else {
			perror("select");
			break;
		}
	} while (nready >= 0);

	close(tunnelfd);
	close(udpfd);

	return 0;
}
