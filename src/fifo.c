/*
 *	CC Network Filesystem (ccgfs)
 *	Local FIFO connector daemon
 *
 *	© Jan Engelhardt <jengelh@computergmbh.de>, 2007
 *
 *	This file is part of CCGFS. CCGFS is free software; you can
 *	redistribute it and/or modify it under the terms of the GNU
 *	General Public License as published by the Free Software
 *	Foundation; either version 2 or 3 of the License.
 */
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libHX.h>
#include "launch.h"

static void start_proc(const char *fifo_mount, unsigned int mt_flags,
    int mt_fd, const char *fifo_storage, unsigned int st_flags, int st_fd,
    const char *program, const char *destpath)
{
	int fd;

	fd = open(fifo_mount, mt_flags);
	if (fd < 0) {
		fprintf(stderr, "Could not open %s: %s\n",
		        fifo_mount, strerror(errno));
		abort();
	}
	if (dup2(fd, mt_fd) < 0) {
		perror("dup2()");
		abort();
	}
	close(fd);
	fd = open(fifo_storage, st_flags);
	if (fd < 0) {
		fprintf(stderr, "Could not open %s: %s\n",
		        fifo_storage, strerror(errno));
		abort();
	}
	if (dup2(fd, st_fd) < 0) {
		perror("dup2()");
		abort();
	}
	close(fd);
	execlp(program, program, destpath, NULL);
	perror("execlp()");
	return;
}

int main(int argc, const char **argv)
{
	const char *fifo_mount = NULL, *fifo_storage = NULL;
	const char *src_path = NULL, *dst_path = NULL;
	pid_t pid;
	struct HXoption option_table[] = {
		{.sh = 'M', .type = HXTYPE_STRING, .ptr = &fifo_mount,
		 .help = "Path to the mount daemon fifo", .htyp = "FILE"},
		{.sh = 'S', .type = HXTYPE_STRING, .ptr = &fifo_storage,
		 .help = "Path to the storage daemon fifo", .htyp = "FILE"},
		{.sh = 'm', .type = HXTYPE_STRING, .ptr = &dst_path,
		 .help = "Mountpoint", .htyp = "DIR"},
		{.sh = 's', .type = HXTYPE_STRING, .ptr = &src_path,
		 .help = "Source path", .htyp = "DIR"},
		HXOPT_AUTOHELP,
	};

	if (HX_getopt(option_table, &argc, &argv, HXOPT_USAGEONERR) <= 0)
		return EXIT_FAILURE;
	if (fifo_mount == NULL || fifo_storage == NULL ||
	    src_path == NULL || dst_path == NULL) {
		fprintf(stderr, "%s: You need to specify the -M, -S, -m and -s options\n"
		        "Try \"%s -?\" for more information.\n",
		        *argv, *argv);
		return EXIT_FAILURE;
	}

	sigchld_install();

	if ((pid = fork()) < 0) {
		perror("fork()");
		abort();
	} else if (pid == 0) {
		start_proc(fifo_mount,   O_RDONLY, STDIN_FILENO,
		           fifo_storage, O_WRONLY, STDOUT_FILENO,
		           "ccgfs-mount", dst_path);
	} else {
		start_proc(fifo_mount,   O_WRONLY, STDOUT_FILENO,
		           fifo_storage, O_RDONLY, STDIN_FILENO,
		           "ccgfs-storage", src_path);
	}

	return EXIT_FAILURE;
}
