#define _GNU_SOURCE 1
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include "xl.h"
#include "xl_errno.c"
#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))

enum {
	OO_READ      = 1 << 0,
	OO_WRITE     = 1 << 1,
	OO_RDWR      = (OO_READ | OO_WRITE),
	OO_ACCMODE   = OO_RDWR,
	OO_CREAT     = 1 << 2,
	OO_EXCL      = 1 << 3,
	OO_NOCTTY    = 1 << 4,
	OO_TRUNC     = 1 << 5,
	OO_APPEND    = 1 << 6,
	OO_NONBLOCK  = 1 << 7,
	OO_SYNC      = 1 << 8,
	OO_ASYNC     = 1 << 9,
	OO_DIRECT    = 1 << 10,
	OO_DIRECTORY = 1 << 11,
	OO_NOFOLLOW  = 1 << 12,
	OO_NOATIME   = 1 << 13,
};

/* x is always negative or zero */
int generic_errno(int x)
{
	if (x > 0)
		abort();
	if (x < -ARRAY_SIZE(arch_to_generic_table))
		return x;
	else
		return arch_to_generic_table[-x];
}

/* x is always negative or zero */
int arch_errno(int x)
{
	if (x > 0)
		abort();
	if (x < -ARRAY_SIZE(generic_to_arch_table))
		return x;
	else
		return generic_to_arch_table[-x];
}

unsigned int generic_openflags(unsigned int x)
{
	unsigned int fl = 0;
	switch (x & O_ACCMODE) {
		case O_RDONLY:
			fl = OO_READ;
			break;
		case O_WRONLY:
			fl = OO_WRITE;
			break;
		case O_RDWR:
			fl = OO_RDWR;
			break;
	}
	if (x & O_CREAT)     fl |= OO_CREAT;
	if (x & O_EXCL)      fl |= OO_EXCL;
	if (x & O_NOCTTY)    fl |= OO_NOCTTY;
	if (x & O_TRUNC)     fl |= OO_TRUNC;
	if (x & O_APPEND)    fl |= OO_APPEND;
	if (x & O_SYNC)      fl |= OO_SYNC;
	if (x & O_ASYNC)     fl |= OO_ASYNC;
	if (x & O_DIRECT)    fl |= OO_DIRECT;
	if (x & O_DIRECTORY) fl |= OO_DIRECTORY;
	if (x & O_NOATIME)   fl |= OO_NOATIME;
	if (x & O_NOFOLLOW)  fl |= OO_NOFOLLOW;
	if (x & O_NONBLOCK)  fl |= OO_NONBLOCK;
	/* No encoding of O_LARGEFILE, will always enable */
	return fl;
}

unsigned int arch_openflags(unsigned int x)
{
	unsigned int fl = 0;
	switch (x & OO_ACCMODE) {
		case OO_READ:
			fl = O_RDONLY;
			break;
		case OO_WRITE:
			fl = O_WRONLY;
			break;
		case OO_RDWR:
			fl = O_RDWR;
			break;
	}
	fl |= O_LARGEFILE;
	if (x & OO_CREAT)     fl |= O_CREAT;
	if (x & OO_EXCL)      fl |= O_EXCL;
	if (x & OO_NOCTTY)    fl |= O_NOCTTY;
	if (x & OO_TRUNC)     fl |= O_TRUNC;
	if (x & OO_APPEND)    fl |= O_APPEND;
	if (x & OO_NONBLOCK)  fl |= O_NONBLOCK;
	if (x & OO_SYNC)      fl |= O_SYNC;
	if (x & OO_ASYNC)     fl |= O_ASYNC;
	if (x & OO_DIRECT)    fl |= O_DIRECT;
	if (x & OO_DIRECTORY) fl |= O_DIRECTORY;
	if (x & OO_NOFOLLOW)  fl |= O_NOFOLLOW;
	if (x & OO_NOATIME)   fl |= O_NOATIME;
	return fl;
}
