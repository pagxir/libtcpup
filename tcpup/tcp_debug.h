#ifndef _TCPUP_TCP_DEBUG_H_
#define _TCPUP_TCP_DEBUG_H_

void tcp_trace_print(const void *tp, const char *fmt, ...);
void tcp_trace_start(const void *tp, const char *fmt, ...);
void tcp_trace_end(const void *tp, const char *fmt, ...);

#include <tx_debug.h>

#define TCP_TRACE_CHECK(tp, cond, msg, args...)   if (cond) tcp_trace_print(tp, msg, ##args)
#define TCP_TRACE_AWAYS(tp, msg, args...)   tcp_trace_print(tp, msg, ##args)

#define TCP_TRACE_START(tp, msg, args...) tcp_trace_start(tp, msg, ##args)
#define TCP_TRACE_END(tp, msg, args...) tcp_trace_end(tp, msg, ##args)
#define TCP_DEBUG(cond, fmt, args...) if (cond) log_tag_putlog("D", fmt, ##args)

#endif

