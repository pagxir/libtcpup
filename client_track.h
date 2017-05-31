#ifndef _CLIENT_TRACK_H_
#define _CLIENT_TRACK_H_

int client_track_update(uint32_t conv, const void *target, size_t len, uint32_t now);
int client_track_fetch(uint32_t conv, void *target, size_t len, uint32_t live);

#endif

