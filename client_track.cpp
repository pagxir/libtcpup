#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <assert.h>

#include <txall.h>

#define TCPUP_LAYER 1
#include <utx/queue.h>
#include <utx/utxpl.h>
#include <utx/socket.h>

#include "client_track.h"

typedef struct client_track_s {
	uint16_t client;
	time_t tsval;
	struct tcpup_addr peer;

	uint32_t tsecr;
	uint32_t owner;
	LIST_ENTRY(client_track_s) entry;
} client_track_t;

static int _client_count = 0;
static LIST_HEAD(client_track_q, client_track_s) _track_header = LIST_HEAD_INITIALIZER(_track_header);

static client_track_t *lookup(uint16_t conv)
{
	time_t now = time(NULL);
	client_track_t *next, *item = NULL;

	LIST_FOREACH_SAFE(item, &_track_header, entry, next) {
		if (item->client == conv) {
			return item;
		}

		if (item->tsval > now || item->tsval + 300 < now) {
			LIST_REMOVE(item, entry);
			_client_count--;
			free(item);
		}
	}

	return NULL;
}

static client_track_t *client_track_alloc(uint16_t client, uint32_t now)
{
	client_track_t *item;
	item = (client_track_t *)calloc(1, sizeof(*item));
	assert(item != NULL);

	item->client = client;
	item->tsecr = now -1;
	LIST_INSERT_HEAD(&_track_header, item, entry);
	_client_count++;

	return item;
}

int client_track_update(uint32_t conv, const void *target, size_t len, uint32_t now)
{
	uint16_t client = htonl(conv) & 0xffff;
	client_track_t *item = lookup(client);

	if (item == NULL) {
		item = client_track_alloc(client, now);
		LOG_VERBOSE("client count: %d %x %x\n", _client_count, client, htonl(conv));
		assert(item != NULL);
#if 0
	} else {
		if (((int)(item->tsecr - now) >= 0) ||
				(item->tsval + 1 > time(NULL))) {
			return 0;
		}
#endif
	}

	item->owner = conv;
	item->tsecr = now;
	item->tsval = time(NULL);
	assert(len == sizeof(item->peer));
	memcpy(&item->peer, target, sizeof(item->peer));

	return 0;
}

int client_track_fetch(uint32_t conv, void *target, size_t len, uint32_t live)
{
	int stat = 0;
	uint16_t client = htonl(conv) & 0xffff;
	client_track_t *item = lookup(client);

	LOG_INFO("client_track_fetch: %x %x %x\n", client, conv, live);
	if (item != NULL && (int)(item->tsecr - live) > 0) {
		assert(len == sizeof(item->peer));
		stat = memcmp(&item->peer, target, sizeof(item->peer));
		memcpy(target, &item->peer, sizeof(item->peer));
		struct sockaddr_in *in = (struct sockaddr_in *)item->peer.name;
		LOG_INFO("client_track_fetch return: %x %x %d %s\n", item->owner, item->tsval, htons(in->sin_port), inet_ntoa(in->sin_addr));
	}

	return stat;
}
