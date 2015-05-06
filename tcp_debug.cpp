#include <stdio.h>
#include <stdarg.h>

#include <utx/utxpl.h>
#include <tcpup/tcp_debug.h>

static const void *_trac_link = 0;

void tcp_trace_print(const void *tp, const char *fmt, ...)
{
    int n;
    va_list ap;
    va_start(ap, fmt);

	if (_trac_link == tp || _trac_link == 0) {
		n = vfprintf(stderr, fmt, ap);
		VAR_UNUSED(n);
	}

    va_end(ap);
    return;
}

void tcp_trace_start(const void *tp, const char *fmt, ...)
{
    int n;
    va_list ap;
    va_start(ap, fmt);

	if (NULL == _trac_link || _trac_link == tp) {
		n = vfprintf(stderr, fmt, ap);
		_trac_link = tp;
		VAR_UNUSED(n);
	}

    va_end(ap);
    return;

}

void tcp_trace_end(const void *tp, const char *fmt, ...)
{
    int n;
    va_list ap;
    va_start(ap, fmt);

	if (tp == _trac_link) {
		n = vfprintf(stderr, fmt, ap);
		_trac_link = NULL;
		VAR_UNUSED(n);
	}

    va_end(ap);
    return;
}

void tcp_debug(const char *fmt, ...)
{
    int n;
    va_list ap;
    va_start(ap, fmt);
    n = vfprintf(stderr, fmt, ap);
	VAR_UNUSED(n);
    va_end(ap);
    return;
}
