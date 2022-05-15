#include <stdlib.h>
#include <assert.h>

#include <utx/utxpl.h>
#include <utx/queue.h>

#include <tcpup/cc.h>
#include <tcpup/tcp_debug.h>

struct cc_algo *default_cc_ptr = &newreno_cc_algo;

void set_cc_algo(const char *name)
{
	if (name == NULL) {
		TCP_DEBUG(1, "use htcp cc algo\n");
		default_cc_ptr = &htcp_cc_algo;
	} else if (strcmp(name, "newreno") == 0) {
		TCP_DEBUG(1, "use newreno cc algo\n");
		default_cc_ptr = &newreno_cc_algo;
	} else if (strcmp(name, "htcp") == 0) {
		TCP_DEBUG(1, "use htcp cc algo\n");
		default_cc_ptr = &htcp_cc_algo;
	} else if (strcmp(name, "cubic") == 0) {
		TCP_DEBUG(1, "use cubic cc algo\n");
		default_cc_ptr = &cubic_cc_algo;
	} else if (strcmp(name, "hybla") == 0) {
		TCP_DEBUG(1, "use hybla cc algo\n");
		default_cc_ptr = &hybla_cc_algo;
	}

	if (default_cc_ptr->mod_init) {
		default_cc_ptr->mod_init();
	}

	return;
}

struct cc_algo * get_cc_ptr(struct tcpcb *tp)
{
	assert(default_cc_ptr != NULL);
	return default_cc_ptr;
}
