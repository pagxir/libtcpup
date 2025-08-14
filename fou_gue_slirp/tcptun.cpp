#include <ctype.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <sys/uio.h>
#include <sys/ioctl.h>

#include <netinet/in.h>
#include <netinet/icmp6.h>
#include <arpa/nameser.h>
#include <resolv.h>

#include <linux/if.h>
#include <linux/if_tun.h>

#ifdef WIN32
#include <windows.h>
#else
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <netdb.h>
#define closesocket close
#endif

#include "txall.h"

struct global_context_t {
    int tunfd;
    tx_aiocb file;
    tx_task_t task;

    int lastfd;
    struct sockaddr_in6 from;
};

static struct global_context_t g0;
static struct global_context_t *g = &g0;
typedef void f_tcp_packet_receive(void *frame, size_t len, void *buf);
static f_tcp_packet_receive *tcp_packet_receive;

typedef int f_tcp_write(void *head, size_t hlen, void *payload, size_t len);
void set_tcp_send_handler(f_tcp_write *handler);

static void do_tun_exchange_back(void *upp)
{
	int count;
	char buffer[2048];
	struct global_context_t *up;

	up = (struct global_context_t *)upp;
	assert(up == g);

	if (!tx_readable(&up->file)) return;

	count = read(up->tunfd, buffer + 60, sizeof(buffer) - 60);
	tx_aincb_update(&up->file, count);

	while (count > 0) {
		tcp_packet_receive(buffer + 60, count, buffer);  
		count = read(up->tunfd, buffer + 4, sizeof(buffer) - 4);
		tx_aincb_update(&up->file, count);
	}

	tx_aincb_active(&up->file, &up->task);
	return ;
}

static int tun_alloc(char *name)
{
	int fd, err = -1;
	struct ifreq ifr;

	fd = open("/dev/net/tun", O_RDWR);
	if (fd < 0) {
		perror("open");
		return err;
	}

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TUN| IFF_NO_PI;
	if (name && *name) {
		memset(ifr.ifr_name, 0, IFNAMSIZ);
		strncpy(ifr.ifr_name, name, IFNAMSIZ -1);
	}

	err = ioctl(fd, TUNSETIFF, &ifr);
	if (err < 0) {
		perror("ioctl");
		close(fd);
		return err;
	}

	int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	assert (sockfd != -1);

	err = ioctl(sockfd, SIOCGIFFLAGS, &ifr);
	assert (err == 0);

	ifr.ifr_flags |= IFF_UP;
	err = ioctl(sockfd, SIOCSIFFLAGS, &ifr);
	close(sockfd);

	return fd;
}

int tcptun_write(void *head, size_t hlen, void *payload, size_t len)
{
	struct iovec frags[2];
	frags[0].iov_base = head;
	frags[0].iov_len = hlen;

	frags[1].iov_base = payload;
	frags[1].iov_len = len;
	return writev(g->tunfd, frags, 2);
}

void tcptun_init(tx_loop_t *loop, f_tcp_packet_receive *func)
{
    g->tunfd = tun_alloc(NULL);
    assert(g->tunfd != -1);

    tx_setblockopt(g->tunfd, 0);
    tx_aiocb_init(&g->file, loop, g->tunfd);
    tx_task_init(&g->task, loop, do_tun_exchange_back, g);
    tx_aincb_active(&g->file, &g->task);
	set_tcp_send_handler(tcptun_write);
	tcp_packet_receive = func;
}
