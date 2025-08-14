#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>

#include <txall.h>

#define SLIP_END             0300       /* indicates end of frame       */
#define SLIP_ESC             0333       /* indicates byte stuffing      */
#define SLIP_ESC_END         0334       /* ESC ESC_END means END 'data' */
#define SLIP_ESC_ESC         0335       /* ESC ESC_ESC means ESC 'data' */

struct global_context_t {
	int sockfd;
	tx_aiocb file;
	tx_task_t task;
};

static global_context_t slirp;
typedef void f_tcp_packet_receive(void *frame, size_t len, void *buf);
static f_tcp_packet_receive *tcp_packet_receive;

typedef int f_tcp_write(void *head, size_t hlen, void *payload, size_t len);
void set_tcp_send_handler(f_tcp_write *handler);

const char *xxdump(const void *buf, size_t len)
{
	int buflen = 1;
	static char details[8192];
	static const char MAPS[17] = "0123456789ABCDEF";

	char *p = details;
	const uint8_t *d = (const uint8_t *)buf;

	while (len > 0 && buflen < sizeof(details)) {
		*p++ = MAPS[*d >> 4];
		buflen++;
		*p++ = MAPS[*d & 0xf];
		buflen++;
		len--;
		d++;
		if (((d - (uint8_t*)buf) & 0xf) == 0) {
			*p++ = '\n';
			buflen++;
		} else {
			*p++ = ' ';
			buflen++;
		}
	}

	*p = 0;

	return details;
}

int slip_write(void *head, size_t hlen, void *payload, size_t len)
{
	uint8_t buf[8192];
	uint8_t *ptr = buf, *plain = (uint8_t*)head;

	LOG_VERBOSE("slirp head %s\n", xxdump(head, hlen));
	LOG_VERBOSE("slirp data %s\n", xxdump(payload, len));

	*ptr++ = SLIP_END;
	for (int i = 0; i < hlen; i++) {
		uint8_t ch = plain[i];
		switch(ch) {
			case SLIP_END:
				*ptr ++ = SLIP_ESC;
				*ptr ++ = SLIP_ESC_END;
				break;

			case SLIP_ESC:
				*ptr ++ = SLIP_ESC;
				*ptr ++ = SLIP_ESC_ESC;
				break;

			default:
				*ptr ++ = ch;
				break;
		}
	}

	plain = (uint8_t *)payload;
	for (int i = 0; i < len; i++) {
		uint8_t ch = plain[i];
		switch(ch) {
			case SLIP_END:
				*ptr ++ = SLIP_ESC;
				*ptr ++ = SLIP_ESC_END;
				break;

			case SLIP_ESC:
				*ptr ++ = SLIP_ESC;
				*ptr ++ = SLIP_ESC_ESC;
				break;

			default:
				*ptr ++ = ch;
				break;
		}
	}
	*ptr ++ = SLIP_END;

	int writed = write(slirp.sockfd, buf, ptr - buf);
	LOG_VERBOSE("slirp write data %d writed %d hlen %d len %d\n", ptr - buf, writed, hlen, len);
	return writed;
}

#define FRM_HLEN 100
static int frame_off = 0;
static int frame_esc = 0;
static char frame_mem[1600];
static char *frame_buf = frame_mem + FRM_HLEN;

static void do_slirp_exchange_back(void *upp)
{
	int count;
	char buffer[8192];
	struct global_context_t *up;

	up = (struct global_context_t *)upp;
	assert(up == &slirp);

	do {
		count = read(up->sockfd, buffer, sizeof(buffer));
		tx_aincb_update(&up->file, count);

		if (count > 0) {
			LOG_VERBOSE("read from slirp: %d\n", count);
			for (int i = 0; i < count; i++) {
				int ch = (uint8_t)buffer[i];
				assert(frame_off + 1 + FRM_HLEN < sizeof(frame_mem));
				switch (ch) {
					case SLIP_END:
						frame_esc = 0;
						if (frame_off > 0) {
							LOG_VERBOSE("receive packet from slirp: %s\n", xxdump(frame_buf, frame_off));
							tcp_packet_receive(frame_buf, frame_off, frame_mem);
							frame_off = 0;
						}
						break;

					case SLIP_ESC:
						frame_esc = 1;
						break;

					case SLIP_ESC_ESC:
						if (frame_esc == 1) {
							frame_esc = 0;
							ch = SLIP_ESC;
						}

					case SLIP_ESC_END:
						if (frame_esc == 1) {
							frame_esc = 0;
							ch = SLIP_END;
						}

					default:
						frame_buf[frame_off++] = ch;
						break;
				}
			}
		}

		assert(count != 0);
	} while (count > 0);

	tx_aincb_active(&up->file, &up->task);
	return;
}

void slirp_init(tx_loop_t *loop, f_tcp_packet_receive *func)
{
	int pairfds[2];

	int err = socketpair(AF_UNIX, SOCK_STREAM, 0, pairfds);
	assert (err == 0);

	pid_t pid = fork();
	assert (pid != -1);

	if (pid == 0) {
		dup2(pairfds[0], 0);
		dup2(pairfds[0], 1);
		if (pairfds[0] > 1) close(pairfds[0]);
		if (pairfds[1] > 1) close(pairfds[1]);
		execl(getenv("SLIRP"), "slirp", "tty STDIO", "mtu 1400", NULL);
		exit(0);
	}

	struct global_context_t *g = &slirp;
	g->sockfd = pairfds[1];
	tx_setblockopt(g->sockfd, 0);
	tx_aiocb_init(&g->file, loop, g->sockfd);
	tx_task_init(&g->task, loop, do_slirp_exchange_back, g);
	tx_aincb_active(&g->file, &g->task);
	tcp_packet_receive = func;
	set_tcp_send_handler(slip_write);
	close(pairfds[0]);

	return;
}
