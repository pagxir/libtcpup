#ifndef _PORTLAYER_H_
#define _PORTLAYER_H_

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>

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
#define MSG_DONTWAIT 0
#else
#include <unistd.h>
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
};

#endif

struct tcpup_addr {
    size_t namlen;
    char name[16];
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

int utxpl_output(int fd, rgn_iovec *buf, size_t count, const struct tcpup_addr *target);
int utxpl_error(void);

#endif
