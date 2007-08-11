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
#include "launch.h"

static void usage(const char *p0)
{
	fprintf(stderr, "Usage: %s SRCPATH STORAGEFIFO:MOUNTFIFO "
	        "DESTPATH\n", p0);
	exit(EXIT_FAILURE);
}

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
	abort();
}

int main(int argc, char **argv)
{
	char *fifo_storage, *fifo_mount;
	pid_t pid;

	if (argc < 4)
		usage(*argv);

	fifo_storage = argv[2];
	fifo_mount   = strchr(fifo_storage, ':');
	if (fifo_mount == NULL)
		usage(*argv);

	*fifo_mount++ = '\0';

	sigchld_install();

	if ((pid = fork()) < 0) {
		perror("fork()");
		abort();
	} else if (pid == 0) {
		start_proc(fifo_mount,   O_RDONLY, STDIN_FILENO,
		           fifo_storage, O_WRONLY, STDOUT_FILENO,
		           "ccgfs-mount", argv[3]);
	} else {
		start_proc(fifo_mount,   O_WRONLY, STDOUT_FILENO,
		           fifo_storage, O_RDONLY, STDIN_FILENO,
		           "ccgfs-storage", argv[1]);
	}

	return EXIT_FAILURE;
}
