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
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <libHX.h>
#include "launch.h"

int main(int argc, const char **argv)
{
	char *src_path = NULL, *dst_host = NULL, *dst_path;
	unsigned int single_threaded = false;
	int p_storage[2], p_ssh[2];
	pid_t pid;
	struct HXoption options_table[] = {
		{.sh = '1', .type = HXTYPE_NONE, .ptr = &single_threaded,
		 .help = "Run mount daemon in single-threaded mode"},
		{.sh = 'm', .type = HXTYPE_STRING, .ptr = &dst_host,
		 .help = "Remote mountpoint in the form of [user@]host:dir",
		 .htyp = "SPEC"},
		{.sh = 's', .type = HXTYPE_STRING, .ptr = &src_path,
		 .help = "Local source path", .htyp = "DIR"},
		HXOPT_AUTOHELP,
		HXOPT_TABLEEND,
	};

	if (HX_getopt(options_table, &argc, &argv, HXOPT_USAGEONERR) <= 0)
		return EXIT_FAILURE;
	if (src_path == NULL || dst_host == NULL) {
		fprintf(stderr, "%s: You need to specify -m and -s\n"
		        "Try \"%s -?\" for more information.\n",
		        *argv, *argv);
		return EXIT_FAILURE;
	}

	dst_path = strchr(dst_host, ':');
	if (dst_path == NULL) {
		fprintf(stderr, "%s: Illegal value for -m\n"
		        "Try \"%s -?\" for more information.\n",
		        *argv, *argv);
		return EXIT_FAILURE;
	}

	*dst_path++ = '\0';
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
		if (single_threaded)
			execlp("ssh", "ssh", "-Tenone", dst_host,
			       "ccgfs-mount", "-s", dst_path, NULL);
		else
			execlp("ssh", "ssh", "-Tenone", dst_host,
			       "ccgfs-mount", dst_path, NULL);
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
		execlp("ccgfs-storage", "ccgfs-storage", src_path, NULL);
	}

	return EXIT_FAILURE;
}
