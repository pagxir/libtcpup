#include <ctype.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

#ifdef WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#define ENTER_DNS_LOCK EnterCriticalSection(&_dns_async.mutex)
#define EXIT_DNS_LOCK  LeaveCriticalSection(&_dns_async.mutex)

#else
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <netdb.h>
#include <pthread.h>

#define ENTER_DNS_LOCK pthread_mutex_lock(&_dns_async.mutex)
#define EXIT_DNS_LOCK  pthread_mutex_unlock(&_dns_async.mutex)
#endif

#include "txall.h"
#include "dns_txasync.h"
#include <utx/utxpl.h>

struct dns_async_context {
	int thread_handle;
	int default_handle;

	struct tx_aiocb aiocb;
	struct tx_task_t task_back;

#ifndef WIN32
	pthread_t thread;
	pthread_mutex_t mutex;
#else
	HANDLE thread;
	CRITICAL_SECTION mutex;
#endif
};

static struct dns_async_context _dns_async = {0};

struct dns_query_item {
	int flags;
	int refcnt;
	char serv[10];
	char name[64];
	tx_task_t *task;
	struct addrinfo info;
	struct addrinfo *result;
};

static struct dns_query_item *_dns_items[256] = {0};

int dns_query_open(const char *name, const char *service, struct addrinfo *info, tx_task_t *task)
{
	int i;
	int error;
	struct dns_query_item *item;
	struct dns_async_context *upp;

	upp = (struct dns_async_context *)&_dns_async;

	for (i = 0; i < 256; i ++) {
		if (_dns_items[i] == 0) {
			break;
		}
	}

	if (i == 256) {
		TX_PANIC(0, "dns asnyc query is full");
		return -1;
	}

	item = new dns_query_item;

	strncpy(item->name, name, sizeof(item->name));
	item->name[sizeof(item->name) - 1] = 0;

	strncpy(item->serv, service, sizeof(item->serv));
	item->serv[sizeof(item->serv) - 1] = 0;

	item->info = *info;
	item->task = task;
	item->flags = 0;
	item->refcnt = 1;

	char b = (char)i;
	_dns_items[i] = item;
	error = send(upp->default_handle, &b, 1, 0);
	TX_PANIC(error == 1, "send dns query to thread failure");
	TX_PRINT(TXL_DEBUG, "index: %d dns query\n", b);
	return i;
}

int dns_query_result(int dns_handle, struct addrinfo **result)
{
	struct dns_query_item *item;
	item = _dns_items[dns_handle];
	*result = item->result;
	return item->flags;
}

int dns_query_close(int dns_handle)
{
	struct dns_query_item *item;

	ENTER_DNS_LOCK;
	item = _dns_items[dns_handle];
	if (item != NULL) {
		_dns_items[dns_handle] = NULL;
		/* automatic decreate */
		item->task = NULL;
		if (--item->refcnt == 0) {
			if (item->result) freeaddrinfo(item->result);
			_dns_items[dns_handle] = NULL;
			delete item;
		}
	}
	EXIT_DNS_LOCK;

	return 0;
}

static int do_dns_query(int index)
{
	int freed = 1;
	struct dns_query_item *item;

	ENTER_DNS_LOCK;

	item = _dns_items[index];
	if (item != NULL) {
		item->refcnt++;
		EXIT_DNS_LOCK;
		item->flags = getaddrinfo(item->name, item->serv, &item->info, &item->result);
		TX_PRINT(TXL_DEBUG, "start query %s\n", item->name);
		ENTER_DNS_LOCK;
		if (--item->refcnt == 0) {
			_dns_items[index] = NULL;
			if (item->result) freeaddrinfo(item->result);
			delete item;
			freed = 0;
		}
	}

	EXIT_DNS_LOCK;
	return freed;
}

static void dns_query_back(void *up)
{
	int ind;
	char indexs[256];
	struct dns_query_item *item;
	struct dns_async_context *upp;

	upp = (struct dns_async_context *)up;
	while (tx_readable(&upp->aiocb)) {
		int count = recv(upp->default_handle, indexs, sizeof(indexs), 0);
		tx_aincb_update(&upp->aiocb, count);
		if (count == -1) {
			TX_PRINT(TXL_DEBUG, "reach end of file %d\n", count);
			break;
		}

		for (int i = 0; i < count; i++) {
			ind = (indexs[i] & 0xff);
			item = _dns_items[ind];
			
			TX_PRINT(TXL_DEBUG, "dns is back %d\n", count);
			if (item != NULL &&
					item->task != NULL) {
				tx_task_active(item->task);
				item->task = NULL;
			}
		}
	}

	tx_aincb_active(&upp->aiocb, &upp->task_back);
	return;
}

static void *do_sync_dns_query(void *up)
{
	int error;
	char indexs[256];
	struct dns_async_context *upp;

	upp = (struct dns_async_context *)up;
	for ( ; ; ) {
		int count = recv(upp->thread_handle, indexs, sizeof(indexs), 0);
		if (count == 0) {
			TX_PRINT(TXL_DEBUG, "reach end of file %d\n", count);
			break;
		}

		if (count == -1 && errno != EINTR) {
			TX_PRINT(TXL_DEBUG, "recv error = %d\n", errno);
			break;
		}

		for (int i = 0; i < count; i++) {
			if (do_dns_query(indexs[i] & 0xff)) {
				error = send(upp->thread_handle, &indexs[i], 1, 0);
				TX_PRINT(error == 1, "send back dns query failure\n");
			}
		}
	}

	return NULL;
}

#ifdef WIN32
static DWORD CALLBACK wrap_sync_dns_query(LPVOID lpArg)
{
	void *p = do_sync_dns_query(lpArg);
	return DWORD(p);
}
#endif

static void module_init(void)
{
	int err;
	int family = AF_INET;
	int fildes[2];
	tx_loop_t *loop = tx_loop_default();
	struct dns_async_context *dnsp = &_dns_async;

#ifndef WIN32
	family = PF_LOCAL;
#endif
	err = socketpair(family, SOCK_STREAM, 0, fildes);
	TX_PANIC(err == 0, "socketpair create for async failure!\n");

	dnsp->thread_handle = fildes[1];
	dnsp->default_handle = fildes[0];

	tx_setblockopt(dnsp->default_handle, 0);
	tx_task_init(&dnsp->task_back, loop, dns_query_back, dnsp);

	tx_aiocb_init(&dnsp->aiocb, loop, dnsp->default_handle);
	tx_aincb_active(&dnsp->aiocb, &dnsp->task_back);

#ifndef WIN32
	pthread_mutex_init(&dnsp->mutex, NULL);
	err = pthread_create(&dnsp->thread, NULL, do_sync_dns_query, dnsp);
	TX_PANIC(err == 0, "pthread_create for async dns failure!\n");
#else
	DWORD dropid = 0;
	InitializeCriticalSection(&dnsp->mutex);
	dnsp->thread = CreateThread(NULL, 0, wrap_sync_dns_query, dnsp, 0, &dropid);
	TX_PANIC(dnsp->thread != NULL, "CreateThread for async dns failure\n");
#endif
}

static void module_clean(void)
{
	void *ignore = 0;
	int thread_handle, default_handle;
	struct dns_async_context *dnsp = &_dns_async;

	tx_aiocb_fini(&dnsp->aiocb);

	default_handle = dnsp->default_handle;
	closesocket(default_handle);

	tx_task_drop(&dnsp->task_back);

#ifndef WIN32
	pthread_join(dnsp->thread, &ignore);
	pthread_mutex_destroy(&dnsp->mutex);
#else
	WaitForSingleObject(dnsp->thread, INFINITE);
	DeleteCriticalSection(&dnsp->mutex);
	CloseHandle(dnsp->thread);
#endif

	thread_handle = dnsp->thread_handle;
	closesocket(thread_handle);

	VAR_UNUSED(ignore);
	return;
}

struct module_stub dns_async_mod = {
	module_init, module_clean
};

