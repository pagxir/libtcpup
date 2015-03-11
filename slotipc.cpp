#include <stdio.h>
#include <assert.h>

#include <wait/module.h>
#include <wait/platform.h>
#include <wait/slotwait.h>

#include "slotipc.h"

#ifdef _WIN32_
static slotcb _ipc_slot;
static struct waitcb _ipc_selscan;
static CRITICAL_SECTION _ipc_lock;

void ipccb_init(ipccb_t *ipccbp, wait_call *call, void *upp)
{
	waitcb_init(ipccbp, call, upp);
	return;
}

void ipccb_clean(ipccb_t *ipccbp)
{
	waitcb_clean(ipccbp);
	return;
}

int ipccb_switch(ipccb_t *ipccbp)
{
	int error = -1;

	EnterCriticalSection(&_ipc_lock);
	if (!waitcb_active(ipccbp)) {
	   	slot_record(&_ipc_slot, ipccbp);
	   	SetEvent(slotwait_handle());
		error = 0;
	}
	LeaveCriticalSection(&_ipc_lock);

	return error;
}

static void ipc_selscan(void *upp)
{
	BOOL locked;
	ipccb_t *ipccbp;

	locked = TryEnterCriticalSection(&_ipc_lock);
	if (locked) {
		while (_ipc_slot != NULL) {
			ipccbp = _ipc_slot;
			waitcb_cancel(ipccbp);
			ipccbp->wt_callback(ipccbp->wt_udata);
		}
	   	LeaveCriticalSection(&_ipc_lock);
	}

	return;
}
#endif

static void module_init(void)
{
#ifdef _WIN32_
	InitializeCriticalSection(&_ipc_lock);
	waitcb_init(&_ipc_selscan, ipc_selscan, 0);
	_ipc_selscan.wt_flags &= ~WT_EXTERNAL;
	_ipc_selscan.wt_flags |= WT_WAITSCAN;
	waitcb_switch(&_ipc_selscan);
#endif
}

static void module_clean(void)
{
#ifdef _WIN32_
	waitcb_clean(&_ipc_selscan);
	DeleteCriticalSection(&_ipc_lock);
#endif
}

struct module_stub slotipc_mod = {
	module_init, module_clean
};

