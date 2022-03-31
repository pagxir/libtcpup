#include <stdio.h>
#include <string.h>
#include <tcpup/tcp_crypt.h>

int packet_decrypt(unsigned short key, void *dst, const void *src, size_t len)
{
	unsigned int d0 = key;
	unsigned char *fdst = (unsigned char *)dst;
	const unsigned char *fsrc = (const unsigned char *)src;

	memmove(dst, src, len);
	return len;
}

int packet_encrypt(unsigned short key, void *dst, const void *src, size_t len)
{
	unsigned int d0 = key;
	unsigned char *fdst = (unsigned char *)dst;
	const unsigned char *fsrc = (const unsigned char *)src;

	memmove(dst, src, len);
	return len;
}
