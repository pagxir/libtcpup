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
static int g_trace_enable = 0;

static unsigned int REQLINK_XOR = 0x52;
static unsigned int RESLINK_XOR = 0xA4;

typedef struct inner_ident_s {
	struct in6_addr src;
	struct in6_addr dst;
	uint16_t port_src;
	uint16_t port_dst;
} inner_ident_t;

struct session_worker {
	int sockfd;
	uint32_t check;
	time_t last_active;
	inner_ident_t ident;
};

struct ip6_hdr {
	uint32_t ip6_ver;
	uint16_t ip6_plen;
	uint8_t ip6_next;
	uint8_t ip6_limit;
	struct in6_addr ip6_src;
	struct in6_addr ip6_dst;
};

struct session_worker *_worker_list[1000];

static int worker_update(struct session_worker *worker, fd_set *readfds, int maxfd)
{
	if (worker && worker->sockfd >= 0) {
		maxfd = MAX_INT(worker->sockfd, maxfd);
		FD_SET(worker->sockfd, readfds);
	}

	return maxfd;
}

static void xor_update(void *buf, size_t plen, uint32_t xorkey)
{
    uint32_t *data = (uint32_t *)buf;

    while (plen >= 4) {
        *data++ ^= xorkey;
        plen -= 4;
    }

    if (plen > 0) {
        *data ^= xorkey;
    }

    return ;
}

static uint32_t checksum(void *buf, size_t plen)
{
    uint32_t *data = (uint32_t *)buf;
    uint64_t sum = 0;

    while (plen >= 4) {
        sum += *data++;
        plen -= 4;
    }

    static uint32_t MAP[4] = {
        0, 0xffu << 24, 0xffffu << 16, 0xffffffu << 8
    };

    if (plen > 0) {
        assert (plen < 4 && plen > 0);
        sum += *data & htonl(MAP[plen]);
    }

    while (sum >> 32) {
        sum = (sum >> 32) + (uint32_t)sum;
    }

    return sum;
}

static int checksum_validate(const void *buf, size_t len, struct in6_addr *src, struct in6_addr *dst, uint8_t proto)
{
    int i;
    uint32_t sum = 0;

    uint16_t *d1 = (uint16_t *)src;
    uint16_t *d2 = (uint16_t *)dst;

    for (i = 0; i < 8; i++) {
        sum += *d1++;
        sum += *d2++;
    }

    uint16_t *d = (uint16_t *)buf;
    for (i = 0; i < (len/2); i++) {
        sum += *d++;
    }

    if (len & 1) {
        sum += *d & htons(0xff00);
    }

    sum += htons(len + proto);

	while (sum >> 16)
		sum = (sum >> 16) + (uint16_t)sum;

    return sum ^ 0xffff;
}

static int worker_receive(struct session_worker *worker, fd_set *readfds, int tunnelfd)
{
	int err;
	int receive = 0;
	struct sockaddr_in target;
	socklen_t fromlen = sizeof(target);

	struct sockaddr *to = (struct sockaddr *)&target;
	socklen_t tolen = sizeof(target);

	if (worker && worker->sockfd >= 0
			&& FD_ISSET(worker->sockfd, readfds)) {
		uint16_t flags[2];
		uint32_t ident;
		const int skip = sizeof(struct ip6_hdr);
		do {
			int sockfd = worker->sockfd;
			receive = recvfrom(sockfd, buffer + skip, sizeof(buffer) - skip,
					MSG_DONTWAIT, (struct sockaddr *)&target, &fromlen);

			if (receive > 24) {
				char * packet = (char *)(buffer + skip);
				char * limited = (char *)(buffer + skip + receive);

				if (RESLINK_XOR != 0)
					for (int i = 0; i < receive; i++)
						buffer[skip + i] ^= RESLINK_XOR;

				target.sin_family = AF_INET;
				memcpy(&target.sin_addr, packet, sizeof(target.sin_addr));
				tolen = sizeof(target);

				memcpy(flags, limited - sizeof(flags), sizeof(flags));
				size_t plen = flags[1];

				struct ip6_hdr *ip6 = (struct ip6_hdr *)(packet + sizeof(ident)); ip6--;
				uint32_t check = (htons(flags[0]) & 0xff) == IPPROTO_ICMPV6? checksum(packet + sizeof(ident), htons(plen)): 0;

				ip6->ip6_ver  = htonl(0x60000000);
				ip6->ip6_plen = plen;
				ip6->ip6_limit = 0xff;
				ip6->ip6_next  = htons(flags[0]);
				memcpy(&ip6->ip6_src, limited - 20, 16);
				ip6->ip6_dst = worker->ident.src;

				if (ip6->ip6_next == IPPROTO_ICMPV6
						&& checksum_validate(ip6 + 1, htons(plen), &ip6->ip6_src, &ip6->ip6_dst, ip6->ip6_next))
					xor_update(ip6 + 1, htons(plen), worker->check);

				err = sendto(tunnelfd, ip6, receive + 40 - 24, 0, to, tolen);
				if (g_trace_enable) LOG_VERBOSE("send data to isatap: err = %d fd = %d\n", err, tunnelfd);
				assert (err > 0);

                if (ip6->ip6_next ==  IPPROTO_ICMPV6) worker->check = check;
				worker->last_active = time(NULL);
			}
		} while (receive > 0);
	}

	return tunnelfd;
}

static struct session_worker *last_worker = NULL;
static int worker_dispatch(struct session_worker *worker, const void *buf, size_t len, struct sockaddr *target, size_t tolen)
{
	int dispatched = 0;
	uint8_t *packet = (uint8_t *)buf;
	const inner_ident_t *data = (const inner_ident_t *)((uint8_t *)buf + 8);

	if (worker && worker->sockfd >= 0) {
		if (IN6_ARE_ADDR_EQUAL(&worker->ident.src, &data->src) && worker->ident.port_src == data->port_src) {
			uint32_t src[4], dst[4];
			struct ip6_hdr *ip6 = (struct ip6_hdr *)buf;

			memcpy(src, &ip6->ip6_src, sizeof(src));
			memcpy(dst, &ip6->ip6_dst, sizeof(dst));

			uint32_t *data = (uint32_t *)(ip6 + 1);
			data--;
			data[0] = src[3];

			uint16_t flags[2];
			flags[1] = ip6->ip6_plen;
			flags[0] = htons(0x6000 | ip6->ip6_next);

			memcpy(packet + len, dst, sizeof(dst));
			memcpy(packet + len + sizeof(dst), flags, sizeof(flags));

			if (REQLINK_XOR != 0) {
				for (int i = 0; i < len - 40 + 24; i++) {
					uint8_t *ptr = (uint8_t *)data;
					ptr[i] ^= REQLINK_XOR;
				}
			}

			int err = sendto(worker->sockfd, data, len - 40 + 24, 0, target, tolen);
			if (g_trace_enable) LOG_VERBOSE("send data to peer: err = %d fd = %d\n", err, worker->sockfd);
			worker->last_active = time(NULL);
			last_worker = worker;
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
#define BUFSIZE (655360)

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
	const inner_ident_t *data = (const inner_ident_t *)((uint8_t *)buf + 8); // 40 - 32

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

	int target_count = 0;
	struct sockaddr_in target_udps[10];

	for (int i = 1; i < argc; i++) {
		char bud[164];
		const char *hostpair = argv[i];

		if (i + 1 < argc && strcmp(hostpair, "-xreq") == 0) {
			REQLINK_XOR = atoi(argv[++i]);
			continue;
		} else if (i + 1 < argc && strcmp(hostpair, "-xres") == 0) {
			RESLINK_XOR = atoi(argv[++i]);
			continue;
		} else if (i + 1 < argc && strcmp(hostpair, "-trace") == 0
				|| strcmp(hostpair, "-trace=1") == 0) {
			g_trace_enable = 1;
			continue;
		} else if (i + 1 < argc && strcmp(hostpair, "-trace=0") == 0) {
			g_trace_enable = 0;
			continue;
		}

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

		if (target_count < ARRAY_SIZE(target_udps)) {
			int index = target_count++;
			target_udps[index] = target_udp;
		}
	}

	if (argc > 1) {
		char abuf[64];
		inet_ntop(AF_INET, &target_udp.sin_addr, abuf, sizeof(abuf));
		LOG_VERBOSE("target %s:%d\n", abuf, htons(target_udp.sin_port));
	}

	int target_next = 0;
	uint8_t map2proto[256];
	memset(map2proto, 0xff, sizeof(map2proto));

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
				skip = 20;
				receive = recvfrom(tunnelfd, buffer, sizeof(buffer), MSG_DONTWAIT, (struct sockaddr *)&target_tunnel, &fromlen);
				if (receive == -1) FD_CLR(tunnelfd, &readfds);
				// *(uint32_t *)(buffer + skip) = random();

				memcpy(&addr, &target_tunnel, sizeof(addr));

				if (receive > skip) {
					// fprintf(stderr, "recieve=%d from tunnelfd=%d\n", receive, tunnelfd);
					// inet_ntop(AF_INET, &addr.sin_addr, abuf, sizeof(abuf));

					int dispatched = 0;
					int proto = buffer[skip + 6] & 0xff;
					int index = map2proto[proto];

					if (0xff == index) {
						target_next = (target_next < target_count? target_next: 0);
						index = target_next++;
						map2proto[proto] = index;
					}

					to = (struct sockaddr *)&target_udps[index];
					if (last_worker && worker_dispatch(last_worker, buffer + skip, receive - skip, to, tolen)) {
						dispatched = 1;
					} else {
						for (int i = 0; i < ARRAY_SIZE(_worker_list) && !dispatched; i++)
							dispatched = worker_dispatch(_worker_list[i], buffer + skip, receive - skip, to, tolen);
					}

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
						if (g_trace_enable || !dispatched) LOG_VERBOSE("final dispatched=%d\n", dispatched);
					}
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
