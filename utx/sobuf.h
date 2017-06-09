#ifndef _RGN_H_
#define _RGN_H_

#define SBS_CANTRCVMORE  0x01
#define SBS_CANTSENDMORE 0x02
#define iscantrcvmore(r) ((r)->rb_flags & SBS_CANTRCVMORE)
#define socantrcvmore(r) do { (r)->rb_flags |= SBS_CANTRCVMORE; } while ( 0 )

struct rgnbuf {
	int rb_flags;
	int rb_off;
	int rb_len;
	int rb_size;
	int rb_mask;
	char *rb_data;

	int rb_frgcnt;
	int rb_frgsize;
	int *rb_fragments;
};

int rgn_wlock(struct rgnbuf *rb, rgn_iovec buf[2]);
int rgn_wunlock(struct rgnbuf *rb, size_t len);

int rgn_rlock(struct rgnbuf *rb, rgn_iovec buf[2]);
int rgn_runlock(struct rgnbuf *rb, size_t len);

int rgn_drop(struct rgnbuf *rb, size_t len);
int rgn_peek(struct rgnbuf *rb, rgn_iovec buf[2], size_t count, size_t off);
int rgn_fragment(struct rgnbuf *rb, const void *buf, size_t count, size_t off);

int rgn_reass(struct rgnbuf *rb);
int rgn_get(struct rgnbuf *rb, void *buf, size_t count);
int rgn_put(struct rgnbuf *rb, const void *buf, size_t count);

int rgn_len(struct rgnbuf *rb);
int rgn_rest(struct rgnbuf *rb);
int rgn_size(struct rgnbuf *rb);
int rgn_frgcnt(struct rgnbuf *rb);

void rgn_clear(struct rgnbuf *rb);
void rgn_destroy(struct rgnbuf *rb);

struct rgnbuf *rgn_create(int size);
struct rgnbuf *rgn_trim(struct rgnbuf *rb);
struct rgnbuf *rgn_resize(struct rgnbuf *rb, int newsize);

#endif

