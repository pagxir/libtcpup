#include <stdio.h>
#include <string.h>
#include <utx/utxpl.h>
#include <tcpup/tcp_crypt.h>

int packet_decrypt(unsigned short key, void *dst, const void *src, size_t len)
{
	int i;
	unsigned int d0 = key;
	unsigned char *fdst = (unsigned char *)dst;
	const unsigned char *fsrc = (const unsigned char *)src;

	for (i = 0; i < len; i++) fdst[i] = fsrc[i] ^ 0x0f;
	// memmove(dst, src, len);
	return len;
}

int packet_encrypt(unsigned short key, void *dst, const void *src, size_t len)
{
	int i;
	unsigned int d0 = key;
	unsigned char *fdst = (unsigned char *)dst;
	const unsigned char *fsrc = (const unsigned char *)src;

	for (i = 0; i < len; i++) fdst[i] = fsrc[i] ^ 0x0f;
	// memmove(dst, src, len);
	return len;
}

int packet_encrypt_iovec(TCPUP_IOVEC *vecs, size_t count, char *buf)
{
	int i;

	for (i = 0; i < count; i++) {
#if WIN32
		packet_encrypt(0, buf, vecs[i].buf, vecs[i].len);
		vecs[i].buf = buf;
		buf += vecs[i].len;
#else
		packet_encrypt(0, buf, vecs[i].iov_base, vecs[i].iov_len);
		vecs[i].iov_base = buf;
		buf += vecs[i].iov_len;
#endif
	}

	return 0;
}
