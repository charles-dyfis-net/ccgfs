/*
 *	CC Network Filesystem (ccgfs)
 *	SSH PUSH mode connector daemon
 *
 *	© Jan Engelhardt <jengelh@computergmbh.de>, 2007
 *
 *	This file is part of CCGFS. CCGFS is free software; you can
 *	redistribute it and/or modify it under the terms of the GNU
 *	General Public License as published by the Free Software
 *	Foundation; either version 2 or 3 of the License.
 */
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "launch.h"

int main(int argc, const char **argv)
{
	int p_storage[2], p_ssh[2];
	pid_t pid;

	if (argc < 3) {
		fprintf(stderr, "Usage: %s SRCPATH HOST DESTPATH\n", *argv);
		exit(EXIT_FAILURE);
	}

	sigchld_install();

	if (pipe(p_storage) < 0 || pipe(p_ssh) < 0) {
		perror("pipe()");
		abort();
	}

	if ((pid = fork()) < 0) {
		perror("fork()");
		abort();
	} else if (pid == 0) {
		if (dup2(p_storage[0], STDIN_FILENO) < 0 ||
		    dup2(p_ssh[1], STDOUT_FILENO) < 0) {
			perror("dup2()");
			abort();
		}
		close(p_storage[0]);
		close(p_storage[1]);
		close(p_ssh[0]);
		close(p_ssh[1]);
		execlp("ssh", "ssh", "-Tenone", argv[2], "ccgfs-mount",
		       argv[3], NULL);
	} else {
		if (dup2(p_storage[1], STDOUT_FILENO) < 0 ||
		    dup2(p_ssh[0], STDIN_FILENO) < 0) {
			perror("dup2()");
			abort();
		}
		close(p_storage[0]);
		close(p_storage[1]);
		close(p_ssh[0]);
		close(p_ssh[1]);
		execlp("ccgfs-storage", "ccgfs-storage", argv[1], NULL);
	}

	return EXIT_FAILURE;
}
