#ifndef _PORTLAYER_H_
#define _PORTLAYER_H_

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>

#define PACING_SHIFT 16

#if defined(WIN32) && !defined(SOCK_STREAM)
typedef unsigned short u_short;
typedef unsigned long  u_long;
typedef unsigned int   u_int;
typedef unsigned char  u_char;

typedef unsigned char  u_int8_t;
typedef unsigned short u_int16_t;
typedef unsigned int   u_int32_t;
typedef unsigned long long u_int64_t;
#endif

#ifdef WIN32
#include <winsock2.h>
#include <ws2ipdef.h>
#include <ws2tcpip.h>
#define MSG_DONTWAIT 0
#else
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>

#define closesocket(s) close(s)
#endif

void __utxpl_assert(const char *expr, const char *path, size_t line);
#define UTXPL_ASSERT(conf) if (! (conf)) __utxpl_assert(#conf, __FILE__, __LINE__)
#define bcopy(s, d, l) memcpy(d, s, l)

#if !defined(min) && !defined(max)
#define min(a, b) ((a) < (b)? (a): (b))
#define max(a, b) ((a) < (b)? (b): (a))
#endif

inline unsigned umin(unsigned a, unsigned b)
{
	return (a < b? a: b);
}

inline unsigned umax(unsigned a, unsigned b)
{
	return (a < b? b: a);
}

inline long lmin(long a, long b)
{
	return (a < b? a: b);
}

inline long lmax(long a, long b)
{
	return (a < b? b: a);
}

inline u_long ulmin(u_long a, u_long b)
{
	return (a < b? a: b);
}

inline u_long ulmax(u_long a, u_long b)
{
	return (a < b? b: a);
}

//#define KASSERT(conf, msg) 
#define VAR_UNUSED(var) var = var

#define VNET(var) V_##var
#define VNET_DEFINE(type, var) type V_##var
#define VNET_DECLARE(type, var) extern type V_##var

#ifndef ECONNRESET

#if 0
#define ntohl(v) utx_ntohl(v)
#define ntohs(v) utx_ntohs(v)
#define htonl(v) utx_ntohl(v)
#define htons(v) utx_ntohs(v)
#endif

u_long utx_ntohl(u_long v);
u_short utx_ntohs(u_short v);

extern int ticks;
extern u_int tx_getticks(void);

#endif

enum {
    UTXECONNRESET = 100,
#define UTXECONNRESET UTXECONNRESET
    UTXECONNREFUSED,
#define UTXECONNREFUSED UTXECONNREFUSED
    UTXEWOULDBLOCK,
#define UTXEWOULDBLOCK UTXEWOULDBLOCK
    UTXEINVAL,
#define UTXEINVAL UTXEINVAL
    UTXENOMEM,
#define UTXENOMEM UTXENOMEM
	UTXTIMEDOUT
#define UTXTIMEDOUT UTXTIMEDOUT
};

struct tcpup_addr {
    size_t namlen;
    u_long xdat;
    char name[28];
};

#if defined(WIN32)
typedef struct rgn_iovec {
    unsigned long iov_len; 
    void *iov_base;
} rgn_iovec;
#else
typedef struct rgn_iovec {
	void  *iov_base;    /* Starting address */
	size_t iov_len;     /* Number of bytes to transfer */
} rgn_iovec;
#endif

typedef int FILTER_HOOK(int netif, void *buf, size_t len, const struct tcpup_addr *from);
int set_filter_hook(FILTER_HOOK *hook);

int utxpl_output(int fd, rgn_iovec *buf, size_t count, const struct tcpup_addr *target);
int utxpl_error(void);

#define ntop6(a) _ntop6(&a)
inline const char *_ntop6(const void *v6addr) {
	static char addrbuf[128];
	return inet_ntop(AF_INET6, v6addr, addrbuf, sizeof(addrbuf));
}

inline const char *inet_4to6(void *v6ptr, const void *v4ptr)
{
    uint32_t *v4 = (uint32_t *)v4ptr;
    uint32_t *v6 = (uint32_t *)v6ptr;

    v6[2] = ~0u;
    v6[3] = v4[0];
    memset(v6, 0, 10);
    return "";
}

#endif
