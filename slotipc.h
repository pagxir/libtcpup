#ifndef _SLOTIPC_H_
#define _SLOTIPC_H_

typedef struct waitcb ipccb_t;
void ipccb_init(ipccb_t *ipccbp, wait_call *call, void *upp);
void ipccb_cancel(ipccb_t *ipccbp);
void ipccb_clean(ipccb_t *ipccbp);

int ipccb_switch(ipccb_t *ipccbp);
#endif

