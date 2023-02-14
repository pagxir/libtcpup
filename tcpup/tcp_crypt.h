#ifndef _TCP_CRYPT_H_
#define _TCP_CRYPT_H_

int packet_decrypt(unsigned short key, void *dst, const void *src, size_t len);
int packet_encrypt(unsigned short key, void *dst, const void *src, size_t len);

#if WIN32
typedef WSABUF TCPUP_IOVEC;
#else
typedef struct iovec TCPUP_IOVEC;
#endif

int packet_encrypt_iovec(TCPUP_IOVEC *vecs, size_t count, char *buf);

#endif
