#include <stdlib.h>

#include <utx/utxpl.h>
#include <utx/queue.h>

#include <tcpup/cc.h>
#include <tcpup/tcp_debug.h>

struct cc_algo *default_cc_ptr = &cubic_cc_algo;

int update_vegas_alpha_beta(int alpha, int beta);

static void set_vegas_alpha_beta(const char *algo)
{
	int beta = 7;
	int alpha = 3;

	/* "vegas:a-b" */
	if (algo[5] == ':') {
		char *dot, buf[68];
		strncpy(buf, algo + 6, sizeof(buf));

		dot = strchr(buf, '-');
		if (dot != NULL) {
			*dot++ = 0;
			beta = *dot? atoi(dot): beta;
		}

		if (buf[0] != 0) {
			alpha = atoi(buf);
			alpha = alpha < beta? alpha: beta;
		}

		update_vegas_alpha_beta(alpha, beta);
		TCP_DEBUG(1, "alpha = %d, beta = %d\n", alpha, beta);
	}

	return;
}

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
	} else if (strncmp(name, "vegas", 5) == 0) {
		TCP_DEBUG(1, "use vegas cc algo\n");
		default_cc_ptr = &vegas_cc_algo;
		set_vegas_alpha_beta(name);
	} else if (strcmp(name, "vegasab") == 0) {
		TCP_DEBUG(1, "use vegasab cc algo\n");
		default_cc_ptr = &vegasab_cc_algo;
	} else if (strcmp(name, "cubic") == 0) {
		TCP_DEBUG(1, "use cubic cc algo\n");
		default_cc_ptr = &cubic_cc_algo;
	}

	if (default_cc_ptr->mod_init) {
		default_cc_ptr->mod_init();
	}

	return;
}
