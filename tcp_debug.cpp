#include <stdio.h>
#include <stdarg.h>

#include <utx/utxpl.h>
#include <tcpup/tcp_debug.h>

void tcp_debug_trace(char const *fmt, ...)
{
    int n;
    va_list ap;
    va_start(ap, fmt);
    n = vfprintf(stderr, fmt, ap);
	VAR_UNUSED(n);
    va_end(ap);
    return;
}

