#ifndef _TCPUP_TCP_DEBUG_H_
#define _TCPUP_TCP_DEBUG_H_

void tcp_debug_trace(const char *fmt, ...);

#define TCP_DEBUG_TRACE(cond, msg, args...)   if (cond) tcp_debug_trace(msg, ##args)

#endif

