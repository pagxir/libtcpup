#ifndef __STUNCLIENT_H__
#define __STUNCLIENT_H__

#define getmappedbybuf(buf, len, addr, port) \
	getaddrbybuf(buf, len, MAPPED_ADDRESS, addr, port)

#define getchangedbybuf(buf, len, addr, port) \
	getaddrbybuf(buf, len, CHANGED_ADDRESS, addr, port)

typedef unsigned short in_port_t;

int get_stun_port(void);
int stun_alloc_ident(void);
int stun_liveup(int ident, struct waitcb * evt);
int stun_lookup(int ident, struct sockaddr_in * so_addr, struct waitcb * evt);
int stun_out_address(const char * server, int flags, int l_ident, int r_ident);
int stun_get_address(int fd, const char * server, int flags, int l_ident, int r_ident);
int stun_set_address(int fd, const char * buf, size_t len, const struct sockaddr_in * addr, socklen_t addrlen);

int stun_maping(int fd, struct sockaddr * name, socklen_t namelen);
int getaddrbybuf(void * buf, size_t len, int type, in_addr_t * addr, in_port_t * port);

int stun_client_init(int fd);
extern "C" void stun_client_send(const char *server, int type);
void stun_client_input(const char *buf, int count, struct sockaddr_in *addr);

enum {
	BindingRequest  = 0x0001,
	BindingError    = 0x0111,
	BindingResponse = 0x0101,
	SharedSecretRequest  = 0x0002,
	SharedSecretError    = 0x0112,
	SharedSecretResponse = 0x0102
};

enum {
	MAPPED_ADDRESS  = 0x0001,
	RESPONSE_ADDRESS = 0x0002,
	CHANGE_REQUEST = 0x0003,
	SOURCE_ADDRESS = 0x0004,
	CHANGED_ADDRESS = 0x0005,
	USERNAME = 0x0006,
	PASSWORD = 0x0007,
	MESSAGE_INTEGRITY = 0x0008,
	ERROR_CODE = 0x0009,
	UNKNOWN_ATTRIBUTES = 0x000a,
	REFLECTED_FROM = 0x000b
};

#define STUN_PRIVATE  0
#define STUN_EXTERNAL 1
#define STUN_NOCHANGE 2
#define STUN_PROTOCOL 3

#endif

