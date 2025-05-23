#include <stdlib.h>
#if defined(WIN32)
#include <winsock2.h>
#endif

#include <utx/utxpl.h>
#include <utx/sobuf.h>

#define IS_ODD(n)  ((n & 1) != 0)
#define IS_EVEN(n) ((n & 1) == 0)
#define RGN_ASSERT(exp) UTXPL_ASSERT(exp)

int rgn_round(int size)
{
	size--;
	size |= (size >> 1);
	size |= (size >> 2);
	size |= (size >> 4);
	size |= (size >> 8);
	size |= (size >> 16);
	return (size + 1);
}

struct rgnbuf *rgn_create(int size)
{
	int frgcnt;
	int frgbufsize;

	char *base;
	struct rgnbuf *rgn;

	size = rgn_round(size);
	frgcnt = (size / 1024);

	frgbufsize = frgcnt * 2 * sizeof(int);
	base = (char *)malloc(sizeof(*rgn) + frgbufsize + size);
	RGN_ASSERT(base != NULL);

	rgn = (struct rgnbuf *)base;
	rgn->rb_off = 0;
	rgn->rb_len = 0;
	rgn->rb_size = size;
	rgn->rb_mask = (size - 1);
	rgn->rb_data = (char *)(base + sizeof(*rgn));

	rgn->rb_frgcnt = 0;
	rgn->rb_flags = 0;
	rgn->rb_frgsize = (frgcnt * 2);
	rgn->rb_fragments = (int *)(rgn->rb_data + size);
	return rgn;
}

struct rgnbuf *rgn_trim(struct rgnbuf* old)
{
	int cp, off, cplen;
	int newsize = old->rb_len;

	if (rgn_round(newsize) == old->rb_size) {
		return old;
	}

	struct rgnbuf *newbuf = rgn_create(newsize);
	if (newbuf == NULL) {
		/* no memory to alloc, just keep the origin buf */
		return old;
	}

	newbuf->rb_off = 0;
	newbuf->rb_len = old->rb_len;
	newbuf->rb_flags = old->rb_flags;

	char *pdata = (char *)old->rb_data;
	off = (old->rb_off & old->rb_mask);

	if (old->rb_size - off >= newsize) {
		memcpy(newbuf->rb_data, pdata + off, newsize);
	} else {
		memcpy(newbuf->rb_data, pdata + off, old->rb_size - off);
		cplen = newsize + off - old->rb_size;
		memcpy(newbuf->rb_data + old->rb_size - off, pdata, cplen);
	}

	newbuf->rb_frgcnt = old->rb_frgcnt;
	if (newbuf->rb_frgcnt > newbuf->rb_frgsize)
		newbuf->rb_frgcnt = newbuf->rb_frgsize;

	for (cp = 0; cp < newbuf->rb_frgcnt; cp++)
		newbuf->rb_fragments[cp] = old->rb_fragments[cp] - old->rb_off;
	free(old);

	return newbuf;
}

struct rgnbuf *rgn_resize(struct rgnbuf* old, int newsize)
{
	int cp, off;
	struct rgnbuf *newbuf = rgn_create(newsize);
	if (newbuf == NULL) {
		/* no memory to alloc, just keep the origin buf */
		return old;
	}

	newbuf->rb_off = 0;
	newbuf->rb_len = old->rb_len;
	newbuf->rb_flags = old->rb_flags;

	char *pdata = (char *)old->rb_data;
	off = (old->rb_off & old->rb_mask);
	memcpy(newbuf->rb_data, pdata + off, old->rb_size - off);
	memcpy(newbuf->rb_data + old->rb_size - off, pdata, off);

	newbuf->rb_frgcnt = old->rb_frgcnt;
	for (cp = 0; cp < newbuf->rb_frgcnt; cp++)
		newbuf->rb_fragments[cp] = old->rb_fragments[cp] - old->rb_off;
	free(old);

	return newbuf;
}

int rgn_frgcnt(struct rgnbuf *rb)
{
	return rb->rb_frgcnt;
}

void rgn_clear(struct rgnbuf *rb)
{
	rb->rb_len = 0;
	rb->rb_off = 0;
	rb->rb_frgcnt = 0;
}

void rgn_destroy(struct rgnbuf *rb)
{
	void *base = (void *)rb;
	free(base);
}

int rgn_rest(struct rgnbuf *rb)
{
	return (rb->rb_size - rb->rb_len);
}

int rgn_len(struct rgnbuf *rb)
{
	return (rb->rb_len);
}

int rgn_size(struct rgnbuf *rb)
{
	return (rb->rb_size);
}

int rgn_get(struct rgnbuf *rb, void *buf, size_t count)
{
	int part1, off;
	char *pdata = (char *)buf;

	RGN_ASSERT((int)count <= rb->rb_len);
	off = (rb->rb_off & rb->rb_mask);
	part1 = umin(count, (rb->rb_size - off));
	memcpy(buf, rb->rb_data + off, part1);
	memcpy(pdata + part1, rb->rb_data, count - part1);

	rb->rb_len -= count;
	rb->rb_off += count;
	return 0;
}

int rgn_put(struct rgnbuf *rb, const void *buf, size_t count)
{
	int part1, off;
	const char *pdat = (const char *)buf;
	RGN_ASSERT(count >= 0);
	RGN_ASSERT(count + rb->rb_len <= (rb->rb_size));
	off = (rb->rb_off + rb->rb_len) & (rb->rb_mask);
	part1 = umin(count, (rb->rb_size) - off);
	memcpy(rb->rb_data + off, buf, part1);
	memcpy(rb->rb_data, pdat + part1, count - part1);
	rb->rb_len += count;

	return count;
}

int rgn_reass(struct rgnbuf *rb)
{
	int count = 0;
	int i, left = 0;
	int *fragments = rb->rb_fragments;
	int end = (rb->rb_len + rb->rb_off);

	for (i = 0; i < rb->rb_frgcnt; i++) {
		if (rb->rb_fragments[i] > end) {
			left = i;
			break;
		}
	}

	if (i == rb->rb_frgcnt) {
		left = rb->rb_frgcnt;
		count = 0;
	} else if (IS_ODD(left)) {
		count = (rb->rb_fragments[left] - end);
		left++;
	}

	rb->rb_len += count;
	rb->rb_frgcnt -= left;
	RGN_ASSERT(rb->rb_len >= 0);
	memmove(fragments, fragments + left, rb->rb_frgcnt * sizeof(int));
	return count;
}

int rgn_fragment(struct rgnbuf *rb, const void *buf, size_t count, size_t off)
{
	int off1, part1;
	char *pdata = (char *)buf;

	int i, left, right;
	int adjstart, adjfinish;
	int *fragments = rb->rb_fragments;

	adjstart = (rb->rb_off + rb->rb_len + off);
	adjfinish = (rb->rb_off + rb->rb_len + off + count);

	RGN_ASSERT(int(count + off) <= rgn_rest(rb));
	off1 = (rb->rb_off + rb->rb_len + off) & rb->rb_mask;
	part1 = umin(count, rb->rb_size - off1);

	memcpy(rb->rb_data + off1, buf, part1);
	memcpy(rb->rb_data, pdata + part1, count - part1);

	left = 0;
	right = rb->rb_frgcnt;
	for (i = 0;  i < rb->rb_frgcnt; i++) {
		if (fragments[i] < adjstart) {
			left = (i + 1);
			continue;
		}

		if (fragments[i] > adjfinish) {
			right = i;
			break;
		}
	}

	i = left;
	rb->rb_frgcnt -= (right - left);

	if (i < rb->rb_frgsize &&
			IS_EVEN(left)) {
		rb->rb_frgcnt++;
		i++;
	}

	if (i < rb->rb_frgsize &&
			IS_EVEN(right)) {
		rb->rb_frgcnt++;
		i++;
	}

	RGN_ASSERT(i <= rb->rb_frgcnt);
	RGN_ASSERT(rb->rb_frgcnt <= rb->rb_frgsize);

	memmove(fragments + i, fragments + right, (rb->rb_frgcnt - i) * sizeof(int));
	RGN_ASSERT(IS_EVEN(rb->rb_frgcnt));

	i = left;
	if (i < rb->rb_frgsize &&
			IS_EVEN(left)) {
		fragments[i] = adjstart;
		i++;
	}

	if (i < rb->rb_frgsize &&
			IS_EVEN(right)) {
		fragments[i] = adjfinish;
		i++;
	}

	return 0;
}

int rgn_rlock(struct rgnbuf *rb, rgn_iovec buf[2])
{
	int part1, off, count;

	count = rb->rb_len;
	off   = (rb->rb_off & rb->rb_mask);
	part1 = umin(count, (rb->rb_size - off));

	buf[0].iov_len = part1;
	buf[0].iov_base = rb->rb_data + off;

	buf[1].iov_len = count - part1;
	buf[1].iov_base = rb->rb_data;

	return count;
}

int rgn_runlock(struct rgnbuf *rb, size_t len)
{
	RGN_ASSERT(rb->rb_len >= len);
	rb->rb_len -= len;
	rb->rb_off += len;
	return 0;
}

int rgn_wlock(struct rgnbuf *rb, rgn_iovec buf[2])
{
	int space, part1, off;

	space = (rb->rb_size - rb->rb_len);
	off   = (rb->rb_off + rb->rb_len) & (rb->rb_mask);
	part1 = umin(space, (rb->rb_size) - off);

	buf[0].iov_len = part1;
	buf[0].iov_base = rb->rb_data + off;

	buf[1].iov_len = space - part1;
	buf[1].iov_base = rb->rb_data;

	return space;
}

int rgn_wunlock(struct rgnbuf *rb, size_t len)
{
	RGN_ASSERT(rb->rb_len + len < rb->rb_size);
	rb->rb_len += len;
	return 0;
}

int rgn_peek(struct rgnbuf *rb, rgn_iovec buf[2], size_t count, size_t off)
{
	int off1, part1;

	RGN_ASSERT(int(count + off) <= rb->rb_len);
	off1 = (rb->rb_off + off) & rb->rb_mask;
	part1 = umin(count, (rb->rb_size - off1));

	buf[0].iov_len = part1;
	buf[0].iov_base = rb->rb_data + off1;

	buf[1].iov_len = (count - part1);
	buf[1].iov_base = rb->rb_data;

	return 0;
}

int rgn_drop(struct rgnbuf *rb, size_t len)
{
	RGN_ASSERT(rb->rb_len >= len);
	rb->rb_len -= len;
	rb->rb_off += len;
	return 0;
}

