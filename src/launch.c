/*
 *	CC Network Filesystem (ccgfs)
 *
 *	Copyright © CC Computer Consultants GmbH, 2007
 *	Contact: Jan Engelhardt <jengelh [at] computergmbh de>
 *
 *	This file is part of CCGFS. CCGFS is free software; you can
 *	redistribute it and/or modify it under the terms of the GNU
 *	General Public License as published by the Free Software
 *	Foundation; either version 2 or 3 of the License.
 */
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include "launch.h"

static void sigchld_handler(int signal_number)
{
	exit(EXIT_SUCCESS);
}

void sigchld_install(void)
{
	struct sigaction sigchld = {};

	sigchld.sa_handler = sigchld_handler;
	sigemptyset(&sigchld.sa_mask);

	if (sigaction(SIGCHLD, &sigchld, NULL) < 0) {
		perror("sigaction()");
		abort();
	}
}
