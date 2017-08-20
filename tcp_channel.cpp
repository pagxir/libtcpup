#include <stdio.h>
#include <time.h>
#include <assert.h>
#include <stdlib.h>

#include <txall.h>

#include <utx/utxpl.h>
#include <utx/socket.h>
#include "tcp_channel.h"
#include "buf_checker.h"

#ifndef WIN32
#include <unistd.h>
#define closesocket(s) close(s)
#define SD_BOTH SHUT_RDWR
#endif

enum {
    NONE_PROTO = 0,
    UNKOWN_PROTO = (1 << 0),
    SOCKV4_PROTO = (1 << 1),
    SOCKV5_PROTO = (1 << 2),
    DIRECT_PROTO = (1 << 6),
    DOCONNECTING = (1 << 7),

    TF_PROXY_HELLO  = (1 << 8),
    TF_CONNECT      = (1 << 9),
    TF_CONNECTING   = (1 << 10),
};

struct relay_data {
    int off;
    int len;
#define RDF_EOF 0x01
#define RDF_FIN 0x02
    int flag;
    char buf[4096];
};

class tcp_channel {
   	public:
		tcp_channel(int fd);
		~tcp_channel();

	public:
		int run(void);
        void check_proxy_proto(void);
        void sockv4_proto_input(void);
        void sockv5_proto_input(void);

        int do_fake_proxy_hello(void);
        int fill_connect_buffer(struct relay_data *up);
		static void tc_callback(void *context);

	private:
		int m_file;
		int m_flags;
		int proto_flags;

	private:
		tx_task_t m_task;
		sockcb_t  m_peer;
		struct tx_aiocb  m_sockcbp;

	private:
        struct relay_data c2r;
        struct relay_data r2c;
};

static u_short _forward_port = 0; // 1080
static u_long  _forward_addr = INADDR_ANY;

static u_short _relay_port = 5030;
static u_long  _relay_server = INADDR_ANY;
static void set_relay_info(sockcb_t tp, int type, char *host, u_short port);

tcp_channel::tcp_channel(int file)
	:m_file(file), m_flags(0)
{
	static u_long conv = time(NULL);
	m_peer = socreate(conv++);
	assert(m_peer != NULL);

    m_flags = TF_PROXY_HELLO;
    proto_flags = 0;

    c2r.flag = 0;
    c2r.off = c2r.len = 0;

    r2c.flag = 0;
    r2c.off = r2c.len = 0;

	tx_loop_t *loop = tx_loop_default();
	tx_aiocb_init(&m_sockcbp, loop, file);
	tx_task_init(&m_task, loop, tc_callback, this);

	if (_relay_server != INADDR_ANY) {
		m_flags |= DIRECT_PROTO;
		m_flags &= ~TF_PROXY_HELLO;
		unsigned int addr = _relay_server;
		set_relay_info(m_peer, 0x01, (char *)&addr, _relay_port);
	}
}

tcp_channel::~tcp_channel()
{
	fprintf(stderr, "tcp_channel::~tcp_channel\n");
	tx_aiocb_fini(&m_sockcbp);
	closesocket(m_file);
	soclose(m_peer);
	tx_task_drop(&m_task);
}

static const int SUPPORTED_PROTO = UNKOWN_PROTO| SOCKV4_PROTO| SOCKV5_PROTO| DIRECT_PROTO ;

void tcp_channel::check_proxy_proto(void)
{
    struct buf_match m;
    tcp_channel *up = this;

    buf_init(&m, up->c2r.buf, up->c2r.len);
    if (buf_equal(&m, 0, 0x04) && buf_find(&m, 8, 0)) {
        up->m_flags |= SOCKV4_PROTO;
        return;
    }

    if (buf_equal(&m, 0, 0x05) && buf_valid(&m, 1)) {
        int len = (m.base[1] & 0xFF);
        if (memchr(&m.base[2], 0x0, len)) {
            up->m_flags |= SOCKV5_PROTO;
            return;
        }

        if (memchr(&m.base[2], 0x2, len)) {
            up->m_flags |= SOCKV5_PROTO;
            return;
        }
    }

    if (!buf_overflow(&m)) {
        up->m_flags |= UNKOWN_PROTO;
        return;
    }

    if (up->c2r.len == sizeof(up->c2r.buf)) {
        up->m_flags |= UNKOWN_PROTO;
        return;
    }

    if (up->c2r.flag & RDF_EOF) {
        up->m_flags |= UNKOWN_PROTO;
        return;
    }
}

int tcp_channel::fill_connect_buffer(struct relay_data *p)
{
    int len;
    int count;
    char *buf;


    if (!tx_readable(&m_sockcbp)) {
        tx_aincb_active(&m_sockcbp, &m_task);
        return 0;
    }

    if (p->len < (int)sizeof(p->buf)) {
        buf = p->buf + p->len;
        len = sizeof(p->buf) - p->len;
  
		count = recv(m_file, buf, len, 0);
		tx_aincb_update(&m_sockcbp, count);
        switch (count) {
            case -1:
            case 0:
                if (tx_readable(&m_sockcbp)) {
                    fprintf(stderr, "stream is closed: %d %d\n", count, tx_readable(&m_sockcbp));
                    p->flag |= RDF_EOF;
                }
                break;

            default:
                p->len += count;
                break;
        }

        return 0;
    }

    if (p->len == (int)sizeof(p->buf)) {
        fprintf(stderr, "buffer is full\n");
        return -1;
    }

    if (!tx_readable(&m_sockcbp)) {
        tx_aincb_active(&m_sockcbp, &m_task);
        return 0;
    }

    return 0;
}

enum socksv5_proto_flags {
    AUTHED_0 = (1 << 0),
    AUTHED_1 = (1 << 1),
    AUTHED_Z = (1 << 2)
};

static void set_relay_info(sockcb_t tp, int type, char *host, u_short port)
{
	int len;
	char *p, buf[60];
	static unsigned int type_len_map[8] = {0x0, 0x04, 0x0, 0x0, 0x10};

	p = buf;
	*p++ = (type & 0xff);
	*p++ = 0;

	memcpy(p, &port, 2);
	p += 2;

	len = type_len_map[type & 0x7];
	if (type == 0x03) {
		fprintf(stderr, "domain: %s:%d\n", host, htons(port));
		len = strlen(host);
		if (len > 46) return;
	}

	memcpy(p, host, len);
	p += len;

	sooptset_target(tp, buf, p - buf);
	return;
}

void tcp_channel::sockv4_proto_input(void)
{
	char *limit;
	struct buf_match m;
	static u_char resp_v4[] = {
		0x00, 0x5A, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00
	};

	tcp_channel *up = this;
	buf_init(&m, up->c2r.buf, up->c2r.len);

	up->proto_flags |= AUTHED_Z;
	if ((up->proto_flags & AUTHED_Z)) {
		if (buf_equal(&m, 0, 0x04) &&
				buf_equal(&m, 1, 0x01) && buf_valid(&m, 8)) {
			int type;
			char *addrp;
			char *end = 0;
			u_short in_port1;
			limit = up->c2r.buf + up->c2r.len;

			end = (up->c2r.buf + 2);
			memcpy(&in_port1, end, sizeof(in_port1));
			end += sizeof(in_port1);

			addrp = end;
			end += sizeof(int);

			end = (char *)memchr(end, 0, limit - end);
			if (end != NULL) {
				type = 0x01;
				if (!memcmp(addrp, "\000\000\000", 3)) {
					addrp = ++end;
					type = 0x03;
					end = (char *)memchr(end, 0, limit - end);
				}

				if (end != NULL) {
					set_relay_info(m_peer, type, addrp, in_port1);

					end++;
					memmove(up->c2r.buf, end, limit - end);
					up->c2r.len = limit - end;

					memcpy(up->r2c.buf, resp_v4, sizeof(resp_v4));
					tx_outcb_write(&m_sockcbp, up->r2c.buf, sizeof(resp_v4));

					up->m_flags &= ~SOCKV4_PROTO;
					up->m_flags |= DIRECT_PROTO;
					return;
				} else {
					goto more_to_come;
				}
			} else {
				goto more_to_come;
			}
		}
	}

	if (!buf_overflow(&m)) {
		fprintf(stderr, "socks4 no overflow\n");
		goto failure_closed;
	}

more_to_come:
	if (up->c2r.len == sizeof(up->c2r.buf)) {
		fprintf(stderr, "socks4 buffer full\n");
		goto failure_closed;
	} else if (up->c2r.flag & RDF_EOF) {
		fprintf(stderr, "socks4 stream closed\n");
		goto failure_closed;
	}

	tx_aincb_active(&m_sockcbp, &m_task);
	return;

failure_closed:
	up->m_flags |= UNKOWN_PROTO;
	return;
}

void tcp_channel::sockv5_proto_input(void)
{
    int line = 0;
    int len, pat;
    char buf[256];
    char *p, *limit;
    struct buf_match m;
    static u_char resp_v5[] = {
        0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    tcp_channel *up = this;
    buf_init(&m, up->c2r.buf, up->c2r.len);

    if ((up->proto_flags & AUTHED_0) != AUTHED_0) {
        if (buf_equal(&m, 0, 0x05) && buf_valid(&m, 1)) {
            int nmethod = (up->c2r.buf[1] & 0xFF);

            if (buf_valid(&m, nmethod + 1)) {
                buf[0] = 0x05;
                buf[1] = 0x00;

                len = tx_outcb_write(&m_sockcbp, buf, 2);
		if (len != 2) {
			line = __LINE__;
			goto failure_closed;
		}

                up->proto_flags |= AUTHED_Z;
                limit = up->c2r.buf + up->c2r.len;

                p = up->c2r.buf + nmethod + 2;
                memmove(up->c2r.buf, p, limit - p);

                up->c2r.len = (limit - p);
                up->proto_flags |= AUTHED_0;
                buf_init(&m, up->c2r.buf, up->c2r.len);
            }
        }
    }

    if ((up->proto_flags & AUTHED_Z)) {
        if (buf_equal(&m, 0, 0x05) &&
                buf_equal(&m, 2, 0x00) && buf_valid(&m, 9)) {
			int type;
            char *end = 0;
            u_short in_port1;
            char *addrp, domain[256];
            limit = up->c2r.buf + up->c2r.len;

            switch (type = up->c2r.buf[3]) {
                case 0x01:
                    end = (up->c2r.buf + 4);
					addrp = end;
                    end += sizeof(int);
                    memcpy(&in_port1, end, sizeof(in_port1));
                    set_relay_info(m_peer, type, addrp, in_port1);
                    end += sizeof(u_short);
                    break;

                case 0x04:
                    end = (up->c2r.buf + 4);
					addrp = end;
                    end += 16;
                    memcpy(&in_port1, end, sizeof(in_port1));
                    set_relay_info(m_peer, type, addrp, in_port1);
                    end += sizeof(u_short);
                    break;

                case 0x03:
                    pat = (up->c2r.buf[4] & 0xFF);
                    if (buf_valid(&m, 4 + pat + 2)) {
                        memcpy(domain, up->c2r.buf + 5, pat);
                        domain[pat] = 0;
						addrp = domain;

                        end = up->c2r.buf + 5 + pat;
                        memcpy(&in_port1, end, sizeof(in_port1));
                        set_relay_info(m_peer, type, addrp, in_port1);
                        end += sizeof(u_short);
                        break;
                    }
                    goto check_protocol;

                default:
                    fprintf(stderr, "socksv5 bad host type!\n");
                    memcpy(up->r2c.buf, resp_v5, sizeof(resp_v5));
                    up->r2c.buf[1] = 0x08;
                    tx_outcb_write(&m_sockcbp, up->r2c.buf, sizeof(resp_v5));
		    line = __LINE__;
                    goto failure_closed;
            }

            if (up->c2r.buf[1] != 0x01) {
                fprintf(stderr, "socksv5 command udp ass not supported yet!\n");
                memcpy(up->r2c.buf, resp_v5, sizeof(resp_v5));
                up->r2c.buf[1] = 0x07;
                tx_outcb_write(&m_sockcbp, up->r2c.buf, sizeof(resp_v5));
		line = __LINE__;
                goto failure_closed;
            }

            memmove(up->c2r.buf, end, limit - end);
            up->c2r.len = limit - end;

            memcpy(up->r2c.buf, resp_v5, sizeof(resp_v5));
            len = tx_outcb_write(&m_sockcbp, up->r2c.buf, sizeof(resp_v5));
	    if (len != sizeof(resp_v5)) {
		    line = __LINE__;
		    goto failure_closed;
	    }

            up->m_flags &= ~SOCKV5_PROTO;
            up->m_flags |= DIRECT_PROTO;
            return;
        }
    }

check_protocol:
    if (!buf_overflow(&m)) {
        fprintf(stderr, "socks5 no overflow\n");
        fprintf(stderr, "socks5 stream closed\n");
		line = __LINE__;
		goto failure_closed;
    } else if (up->c2r.len == sizeof(up->c2r.buf)) {
        fprintf(stderr, "socks5 buffer full\n");
        fprintf(stderr, "socks5 stream closed\n");
		line = __LINE__;
		goto failure_closed;
    } else if (up->c2r.flag & RDF_EOF) {
        fprintf(stderr, "socks5 stream closed\n");
		line = __LINE__;
		goto failure_closed;
    }

    tx_aincb_active(&m_sockcbp, &m_task);
    return;

failure_closed:
    fprintf(stderr, "socks5 handshake failure, %d\n", line);
    up->m_flags |= UNKOWN_PROTO;
    return;
}

int tcp_channel::do_fake_proxy_hello(void)
{
    tcp_channel *up = this;

    if ((up->m_flags & SUPPORTED_PROTO) == NONE_PROTO) {
        fill_connect_buffer(&up->c2r);
        check_proxy_proto();
    }

    if (up->m_flags & SOCKV4_PROTO) {
        fill_connect_buffer(&up->c2r);
        sockv4_proto_input();
    }

    if (up->m_flags & SOCKV5_PROTO) {
        fill_connect_buffer(&up->c2r);
        sockv5_proto_input();
    }

    if (up->m_flags & UNKOWN_PROTO) {
        fprintf(stderr, "UNKOWN_PROTO\n");
        return 0;
    }

    if (up->m_flags & DIRECT_PROTO) {
        up->m_flags &= ~TF_PROXY_HELLO;
    }

    return 1;
}

int tcp_channel::run(void)
{
	int len = 0;
	int error = 0;
	int change = 0;
	struct sockaddr_in name;

    if (m_flags & TF_PROXY_HELLO) {
        error = do_fake_proxy_hello();
        if (m_flags & TF_PROXY_HELLO) {
            /* XXX: handle shake continue */
            return error;
        }
    }

	if ((m_flags & TF_CONNECT) == 0) {
		name.sin_family = AF_INET;
		name.sin_port   = (_forward_port);
		name.sin_addr.s_addr = (_forward_addr);

	   	error = soconnect(m_peer, (struct sockaddr *)&name, sizeof(name));
		m_flags |= TF_CONNECT;
		if (error == 1) {
			sopoll(m_peer, SO_SEND, &m_task);
			m_flags |= TF_CONNECTING;
			return 1;
		}

		if (error != 0) {
			fprintf(stderr, "udp connect error\n");
			return 0;
		}
	}

	if ((m_flags & TF_CONNECTING)
			&& soconnected(m_peer)) {
		m_flags &= ~TF_CONNECTING;
	}

#if 0
	if (m_flags & TF_CONNECTING) {
		sopoll(m_peer, SO_CONNECT, &w_evt_peer);
		return 1;
	}
#endif

	do {
		change = 0;
		if (c2r.off >= c2r.len) c2r.off = c2r.len = 0;

		if (tx_readable(&m_sockcbp) && c2r.len < (int)sizeof(c2r.buf) && !c2r.flag) {
			len = recv(m_file, c2r.buf + c2r.len, sizeof(c2r.buf) - c2r.len, 0);
			tx_aincb_update(&m_sockcbp, len);

			change |= (len > 0);
			if (len > 0)
				c2r.len += len;
			else if (len == 0)
				c2r.flag |= RDF_EOF;
			else if (tx_readable(&m_sockcbp)) // socket meet error condiction
				return 0;
		}

		if (sowritable(m_peer) && c2r.off < c2r.len) {
			len = sowrite(m_peer, c2r.buf + c2r.off, c2r.len - c2r.off);
			if (len == -1) return 0;
			change |= (len > 0);
			c2r.off += len;
		}
	} while (change);

	do {
		change = 0;
		if (r2c.off >= r2c.len)  r2c.off = r2c.len = 0;
		if (soreadable(m_peer) && r2c.len < (int)sizeof(r2c.buf) && !r2c.flag) {
			len = soread(m_peer, r2c.buf + r2c.len, sizeof(r2c.buf) - r2c.len);
			if (len == -1 || len == 0) {
				r2c.flag |= RDF_EOF;
				len = 0;
			}

			change |= (len > 0);
			r2c.len += len;
		}

		if (tx_writable(&m_sockcbp) && r2c.off < r2c.len) {
			do {
				len = tx_outcb_write(&m_sockcbp, r2c.buf + r2c.off, r2c.len - r2c.off);
				if (len > 0) {
					r2c.off += len;
					change |= (len > 0);
				} else if (tx_writable(&m_sockcbp)) {
					return 0;
				}
			} while (len > 0 && r2c.off < r2c.len);
		}

	} while (change);


	error = 0;

	if (c2r.off >= c2r.len) {
        c2r.off = c2r.len = 0;

		if (c2r.flag == RDF_EOF) {
			soshutdown(m_peer);
            c2r.flag |= RDF_FIN;
        }
	}

	if (r2c.off >= r2c.len) {
        r2c.off = r2c.len = 0;

		if (r2c.flag == RDF_EOF && tx_writable(&m_sockcbp)) {
			assert(tx_writable(&m_sockcbp));
			shutdown(m_file, SD_BOTH);
            r2c.flag |= RDF_FIN;
		}
	}

    if (c2r.off < c2r.len && !sowritable(m_peer)) {
		sopoll(m_peer, SO_SEND, &m_task);
		error = 1;
	}

	if ((r2c.off < r2c.len || r2c.flag == RDF_EOF) && !tx_writable(&m_sockcbp)) {
		tx_outcb_prepare(&m_sockcbp, &m_task, 0);
		error = 1;
	}

    if ((c2r.flag == 0) && !tx_readable(&m_sockcbp) &&
            c2r.len < (int)sizeof(c2r.buf)) {
        tx_aincb_active(&m_sockcbp, &m_task);
        error = 1;
    }

    if ((r2c.flag == 0) && !soreadable(m_peer) &&
            r2c.len < (int)sizeof(r2c.buf)) {
        sopoll(m_peer, SO_RECEIVE, &m_task);
        error = 1;
    }

	return error;
}

void tcp_channel::tc_callback(void *context)
{
	tcp_channel *chan;
	chan = (tcp_channel *)context;

	if (chan->run() == 0) {
		delete chan;
		return;
	}
   
	return;
}

void new_tcp_channel(int fd)
{
	tcp_channel *chan;
   	chan = new tcp_channel(fd);

	if (chan == NULL) {
		closesocket(fd);
		return;
	}

	tcp_channel::tc_callback(chan);
	return;
}

extern "C" void tcp_channel_forward(struct tcpip_info *info)
{
	char *env, *p;
	char  server[128];

	_forward_addr = info->address;
	_forward_port = info->port;

	env = getenv("RELAYSERVER");

	if (env != NULL) {
		strcpy(server, env);
		p = strrchr(server, ':');
		if (p != NULL) {
			*p++ = 0;
			_relay_port = htons(atoi(p));
		}

		_relay_server = inet_addr(server);
	}

	return;
}

