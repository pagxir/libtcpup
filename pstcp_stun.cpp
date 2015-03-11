#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <stdint.h>
#include <string.h>

#include <wait/module.h>
#include <wait/platform.h>
#include <wait/callout.h>
#include <wait/slotwait.h>
#include <wait/slotsock.h>

#include "pstcp_stun.h"
#include "tcp_channel.h"

/*
 * stun.l.google.com:19302
 * stun.ekiga.net:3478
 */

int getaddrbybuf(const char * buf, size_t len,
		int type, in_addr_t * addr, in_port_t * port)
{
	int error = -1;
	size_t ix, nx, cut;
	unsigned short hdr[2];
	unsigned char *bp = (unsigned char *)buf;

	for (ix = 20, nx = 24; nx <= len; ix = nx, nx += 4) {
		memcpy(hdr, bp + ix, sizeof(hdr));
		cut = ntohs(hdr[1]);
		ix  = nx;
		nx += cut;

		if (htons(hdr[0]) != type) {
			continue;
		}

		if (nx > len) {
			continue;
		}

		if (cut != 8 || bp[ix + 1] != 1) {
			break;
		}

		memcpy(port, bp + ix + 2, 2);
		memcpy(addr, bp + ix + 4, 4);
		error = 0;
		break;
	}

	return error;
}

struct mapping_args{
	unsigned short operate, zero;
	unsigned int  tids[4];
};

struct changing_args{
	unsigned short operate, zero;
	unsigned int   tids[4];
	unsigned short sub_operate, len_field;
	unsigned char  data[4];
};

static int _stid3 = 0;
int stun_changing(int fd, int same_addr, struct sockaddr * name, socklen_t namelen)
{
	struct changing_args req;

	req.operate = htons(BindingResponse);
	req.zero    = htons(8);
	memset(req.tids, 0x55, sizeof(req.tids));
	req.tids[3] = htonl(_stid3++);

	req.sub_operate = htons(CHANGE_REQUEST);
	req.len_field = htons(4);
	memset(req.data, 0, sizeof(req.data));
	req.data[3] = same_addr? 4: 6;

	return sendto(fd, (const char*)&req, sizeof(req), 0, name, namelen);
}

int stun_maping(int fd, struct sockaddr* name, socklen_t namelen)
{
	struct mapping_args req;

	req.operate = htons(BindingRequest);
	req.zero    = htons(0);
	memset(req.tids, 0x66, sizeof(req.tids));
	req.tids[3] = htonl(_stid3++);

	return sendto(fd, (const char*)&req, sizeof(req), 0, name, namelen);
}

int stun_get_address(int fd, const char * server, int flags, int l_ident, int r_ident)
{
	struct sockaddr_in so_addr;
	struct mapping_args req;

	req.operate = htons(BindingRequest);
	req.zero    = htons(0);

	switch (flags)
	{
		case STUN_EXTERNAL:
			memset(req.tids, 0x55, sizeof(req.tids));
			req.tids[2] = (l_ident);
			req.tids[3] = (r_ident);
			break;

		case STUN_PRIVATE:
			memset(req.tids, 0xAA, sizeof(req.tids));
			req.tids[2] = (l_ident);
			req.tids[3] = (r_ident);
			break;

		case STUN_PROTOCOL:
			memset(req.tids, 0x5A, sizeof(req.tids));
			req.tids[2] = (l_ident);
			req.tids[3] = (r_ident);
			break;
	}

	if (getaddrbyname(server, &so_addr) != 0)
		return -1;

	return sendto(fd, (const char*)&req, sizeof(req), 0,
			(const struct sockaddr *)&so_addr, sizeof(so_addr));
}

int stun_set_address(int fd, const char * buf, size_t len, const struct sockaddr_in * addr, socklen_t addrlen)
{
	struct sockaddr_in myaddr;

	struct  {
		struct mapping_args head;
		struct {
			uint16_t type;
			uint16_t len;
			uint8_t zero;
			uint8_t family;
			uint16_t port;
			uint32_t address;
		} stun_address[2];
	} resp;

	if (len < sizeof(resp.head)) {
		return 0;
	}

	socklen_t mylen = sizeof(myaddr);
	int error = getsockname(fd, (struct sockaddr *) &myaddr, &mylen);
	assert(error == 0);

	memcpy(&resp.head, buf, sizeof(resp.head));
	resp.head.operate = htons(BindingResponse);
	resp.head.zero    = sizeof(resp.stun_address);

	resp.stun_address[0].type = htons(MAPPED_ADDRESS);
	resp.stun_address[0].len  = htons(8);
	resp.stun_address[0].zero = 0;
	resp.stun_address[0].family  = 0x01;
	resp.stun_address[0].port = addr->sin_port;
	resp.stun_address[0].address = addr->sin_addr.s_addr;

	resp.stun_address[1].type = htons(SOURCE_ADDRESS);
	resp.stun_address[1].len  = htons(8);
	resp.stun_address[1].zero = 0;
	resp.stun_address[1].family  = 0x01;
	resp.stun_address[1].port = myaddr.sin_port;
	resp.stun_address[1].address = myaddr.sin_addr.s_addr;

	return sendto(fd, (const char *)&resp, sizeof(resp), 0, (const struct sockaddr *)addr, addrlen);
}

static int _fd_stun = 0;
static int _last_port = 0;
static in_addr _last_addr = {0};
static struct waitcb * _evt_stun_header = 0;

static unsigned int _last_recv = 0;
static unsigned int _last_send = 0;

typedef struct _stun_ident_s {
	struct _stun_ident_s * next;
	struct _stun_ident_s ** prev;

	int type;
	int tick;
	int touch;
	int ident;
	int validate;
	u_short port;
	in_addr addr;
	struct waitcb * wait;
	struct waitcb * liveup;
} stun_ident_t;

static int _ident_gen = 0x19821130;
static stun_ident_t * _ident_header = 0;

int stun_liveup(int ident, struct waitcb * evt)
{
	stun_ident_t * sip;

	for (sip = _ident_header; sip; sip = sip->next) {
		if (sip->ident == ident) {
			slot_record(&sip->liveup, evt);
			break;
		}
	}

	return 0;
}

int stun_lookup(int ident, struct sockaddr_in * so_addr, struct waitcb * evt)
{
	int error = -1;
	stun_ident_t * sip;

	for (sip = _ident_header; sip; sip = sip->next) {
		if (sip->ident == ident) {
			if (sip->validate == 1 && 
				(sip->type == STUN_PRIVATE ||
				sip->tick + 30000 > (int)tx_getticks())) {
				so_addr->sin_family = AF_INET;
				so_addr->sin_port = sip->port;
				so_addr->sin_addr = sip->addr;
				error = 0;
			} else if (evt != NULL) {
				slot_record(&sip->wait, evt);
				slot_wakeup(&sip->liveup);
				error = 1;
			}
			break;
		}
	}

	return error;
}

void stun_last_seen(u_long ident, struct sockaddr_in * so_addr, int type)
{
	stun_ident_t * sip;

	for (sip = _ident_header; sip; sip = sip->next) {
		if (sip->ident == (int)ident) {
			if (sip->addr.s_addr == so_addr->sin_addr.s_addr) {
				/* if address no change, we say this type nochange. */
				type = (type == STUN_NOCHANGE? sip->type: type);
			}

			if (sip->type == type ||
				int(sip->tick + 600000 - tx_getticks()) < 0) {
				sip->type = type;
				sip->validate = 1;
				sip->tick = tx_getticks();
				sip->port = so_addr->sin_port;
				sip->addr = so_addr->sin_addr;
				slot_wakeup(&sip->wait);
			} else if (sip->type != STUN_PRIVATE) {
				sip->type = type;
				sip->validate = 1;
				sip->tick = tx_getticks();
				sip->port = so_addr->sin_port;
				sip->addr = so_addr->sin_addr;
				slot_wakeup(&sip->wait);
			}
		}
	}
}

int stun_alloc_ident()
{
	stun_ident_t * sip;
	sip = new _stun_ident_s();

	sip->type = STUN_EXTERNAL;
	sip->port = 0;
	sip->tick = 0;
	sip->wait = 0;
	sip->validate = 0;
	sip->addr.s_addr = 0;
	sip->touch = tx_getticks();
	sip->ident = ++_ident_gen;
	sip->liveup = 0;

	sip->next = _ident_header;
	if (sip->next != NULL)
		sip->next->prev = &sip->next;
	sip->prev = &_ident_header;
	_ident_header = sip;

	return sip->ident;
}

void stun_client_input(const char *buf, int count, struct sockaddr_in *addr)
{
	int error;
	u_long * stun_ident;
	in_addr_t x_addr = 0;
	in_port_t x_port = 0;

#if 0
	struct tcphdr * ti;

	if (count >= 28 && MAGIC_UDP_TCP == (0xFF & buf[0])) {
		ti = (struct tcphdr *)buf;
		stun_last_seen((ti->ti_srcc), addr, STUN_NOCHANGE);
		return;
	}
#endif

	if (count < 20) {
		fprintf(stderr, "udp packet len: %d\n", count);
		return;
	}

	int private_count = 0;
	int protocol_count = 0;
	int external_count = 0;

	stun_ident = (u_long *)buf;
	for (int i = 1; i < 3; i++) {
		switch (stun_ident[i])
		{
			case 0x55555555:
				external_count++;
				break;

			case 0xAAAAAAAA:
				private_count++;
				break;

			case 0x5A5A5A5A:
				protocol_count++;
				break;
		}
	}

	if (* (short *)buf == htons(BindingRequest)) {
		int external;
		if (external_count == 2 || private_count == 2) {
			external = external_count;
			stun_last_seen((stun_ident[4]), addr, external? STUN_PRIVATE: STUN_EXTERNAL);
		}
		stun_set_address(_fd_stun, buf, count, addr, sizeof(*addr));
		return;
	}

	if (* (short *)buf == htons(BindingResponse)) {
		error = getmappedbybuf(buf, count, &x_addr, &x_port);
		if (error != 0) {
			return;
		}

		memcpy(&_last_addr, &x_addr, sizeof(x_addr));
		_last_recv = tx_getticks();
		_last_port = x_port;

		if (external_count == 2 || protocol_count == 2) {
			slot_wakeup(&_evt_stun_header);
		}


		if (external_count == 3 || private_count == 3) {
			stun_last_seen((stun_ident[3]), addr, STUN_PRIVATE);
			return;
		}
	}
}

void update_stun_address(void * ctx)
{
	int l, r;
	struct waitcb * t_evtp;

	t_evtp = (struct waitcb *)ctx;
	if (int(_last_recv + 30 * 1000 - tx_getticks()) > 0) {
		waitcb_clean(t_evtp);
		delete t_evtp;
		return;
	}

	if (int(_last_send + 1000 - tx_getticks()) < 0) {
		l = _stid3++;
		r = _stid3++;
		stun_get_address(_fd_stun, "stun.l.google.com:19302", STUN_PROTOCOL, l, r);
		_last_send = tx_getticks();
		return;
	}

	return;
}

int get_stun_address(in_addr * addr, int * port, struct waitcb * evt)
{
	int l, r;
	int valid = 0;

	if (int(_last_recv + 60 * 1000 - tx_getticks()) > 0) {
		*addr = _last_addr;
		*port = _last_port;
		valid = 1;
	}

	if (int(_last_recv + 30 * 1000 - tx_getticks()) > 0) {
		/* this address is flush. */
		return 0;
	}

	if (int(_last_send + 1000 - tx_getticks()) < 0) {
		struct waitcb * t_event_p = new struct waitcb;
		waitcb_init(t_event_p, update_stun_address, t_event_p);
		l = _stid3++, r = _stid3++;
		stun_get_address(_fd_stun, "stun.l.google.com:19302", STUN_PROTOCOL, l, r);
		callout_reset(t_event_p, 1000);
		_last_send = tx_getticks();
	}

	slot_record(&_evt_stun_header, evt);
	return valid? 1: 2;
}

struct stun_ping_pong {
	int n_time;
	int t_tick;
	int f_flags;
	int l_ident;
	int r_ident;
	struct waitcb p_timeo;
	struct waitcb n_event;
	char s_server[256];
};

void stun_ping_pong_poll(void * upp)
{
	stun_ident_t * sip;
	stun_ping_pong * spp = (stun_ping_pong *)upp;

	for (sip = _ident_header; sip; sip = sip->next) {
		if (sip->ident == spp->l_ident) {
			if (spp->n_time >= 3)
				goto release;

			if (sip->validate == 1) {
				if (sip->type == spp->f_flags &&
					(unsigned)(sip->tick + 15000) > tx_getticks())
					goto release;

				if (sip->type != STUN_PRIVATE) 
					goto release;
			}

			spp->n_time++;
			waitcb_cancel(&spp->p_timeo);
			callout_reset(&spp->p_timeo, 1000);

			waitcb_cancel(&spp->n_event);;
			slot_record(&sip->wait, &spp->n_event);
			stun_get_address(_fd_stun, spp->s_server, spp->f_flags, spp->l_ident, spp->r_ident);
			return;
		}
	}

release:
	waitcb_cancel(&spp->n_event);
	waitcb_cancel(&spp->p_timeo);
	delete spp;
}

int stun_out_address(const char * server, int flags, int l_ident, int r_ident)
{
	stun_ident_t * sip;
	stun_ping_pong * spp;

	for (sip = _ident_header; sip; sip = sip->next) {
		if (sip->ident == l_ident) {
			spp = new stun_ping_pong;
			spp->n_time = 1;
			spp->l_ident = l_ident;
			spp->r_ident = r_ident;
			spp->f_flags = flags;
			spp->t_tick = tx_getticks();
			strncpy(spp->s_server, server, sizeof(spp->s_server));

			waitcb_init(&spp->n_event, stun_ping_pong_poll, spp);
			waitcb_init(&spp->p_timeo, stun_ping_pong_poll, spp);

			stun_get_address(_fd_stun, server, flags, l_ident, r_ident);
			callout_reset(&spp->p_timeo, 1000);

			slot_record(&sip->wait, &spp->n_event);
			sip->touch = tx_getticks();
		}
	}

	return 0;
}

extern "C" void stun_client_send(const char *server, int type)
{
	stun_get_address(_fd_stun, server, type, 0x5a5a5a5a, 0xa5a5a5a5);
	return;
}

extern "C" int stun_get_name(char *buf, size_t len)
{
	int count;
	count = snprintf(buf, len, "%s:%d",
			inet_ntoa(_last_addr), htons(_last_port));
	UNUSED_VAR(count);
	return 0;
}

int get_stun_port(void)
{
	int error;
	socklen_t namlen;
	struct sockaddr_in addr;

	namlen = sizeof(addr);;
	error = getsockname(_fd_stun, (struct sockaddr *)&addr, &namlen);
	assert(error == 0);

	return (addr.sin_port);
}

int stun_client_init(int sockfd)
{
	srand(time(NULL));
	_fd_stun = sockfd;
	_ident_gen = rand()| (rand() << 16);
	return 0;
}
