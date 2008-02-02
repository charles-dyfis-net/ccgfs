/*
 *	CC Network Filesystem (ccgfs)
 *	Storage Engine
 *
 *	© Jan Engelhardt <jengelh@computergmbh.de>, 2007
 *
 *	This file is part of CCGFS. CCGFS is free software; you can
 *	redistribute it and/or modify it under the terms of the GNU
 *	General Public License as published by the Free Software
 *	Foundation; either version 2 or 3 of the License.
 */
#include <sys/fsuid.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/time.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <attr/xattr.h>
#include "ccgfs.h"
#include "packet.h"

#define b_path(dest, src) /* build path */ \
	(snprintf(dest, sizeof(dest), "%s%s", root_dir, (src)) >= \
	          sizeof(dest)) \

enum {
	LOCALFS_SUCCESS = 0,
	LOCALFS_STOP,
};

typedef int (*localfs_func_t)(int, struct lo_packet *);

static char root_dir[PATH_MAX];
static unsigned int i_am_root;
static unsigned int pagesize;

static int localfs_chmod(int fd, struct lo_packet *rq)
{
	const char *rq_path = pkt_shift_s(rq);
	mode_t rq_mode      = pkt_shift_32(rq);
	char path[PATH_MAX];

	if (b_path(path, rq_path))
		return -ENAMETOOLONG;
	if (chmod(path, rq_mode) < 0)
		return -errno;

	return LOCALFS_SUCCESS;
}

static int localfs_chown(int fd, struct lo_packet *rq)
{
	const char *rq_path = pkt_shift_s(rq);
	uid_t rq_uid        = pkt_shift_32(rq);
	gid_t rq_gid        = pkt_shift_32(rq);
	char path[PATH_MAX];

	if (b_path(path, rq_path))
		return -ENAMETOOLONG;
	if (chown(path, rq_uid, rq_gid) < 0)
		return -errno;

	return LOCALFS_SUCCESS;
}

static int localfs_create(int fd, struct lo_packet *rq)
{
	const char *rq_path   = pkt_shift_s(rq);
	mode_t rq_mode        = pkt_shift_32(rq);
	dev_t rq_dev          = pkt_shift_32(rq);
	unsigned int rq_flags = pkt_shift_32(rq);

	struct lo_packet *rp;
	char path[PATH_MAX];
	int ret;

	if (b_path(path, rq_path))
		return -ENAMETOOLONG;
	if (mknod(path, rq_mode, rq_dev) < 0)
		return -errno;
	if (S_ISREG(rq_mode))
		if ((ret = open(path, rq_flags)) < 0)
			return -errno;

	rp = pkt_init(CCGFS_CREATE_RESPONSE, PV_32);
	pkt_push_32(rp, ret);
	pkt_send(fd, rp);
	return LOCALFS_STOP;
}

static struct lo_packet *getattr_copy_stor(const struct stat *sb)
{
	struct lo_packet *rp;

	rp = pkt_init(CCGFS_GETATTR_RESPONSE, 7 * PV_64 + 5 * PV_32);
	if (rp == NULL)
		return NULL;

	pkt_push_64(rp, sb->st_ino);
	pkt_push_32(rp, sb->st_mode);
	pkt_push_32(rp, sb->st_nlink);
	pkt_push_32(rp, sb->st_uid);
	pkt_push_32(rp, sb->st_gid);
	pkt_push_32(rp, sb->st_rdev);
	pkt_push_64(rp, sb->st_size);
	pkt_push_64(rp, sb->st_blksize);
	pkt_push_64(rp, sb->st_blocks);
	pkt_push_64(rp, sb->st_atime);
	pkt_push_64(rp, sb->st_mtime);
	pkt_push_64(rp, sb->st_ctime);
	return rp;
}

static int localfs_fgetattr(int fd, struct lo_packet *rq)
{
	int rq_fd = pkt_shift_32(rq);
	struct stat sb;

	if (fstat(rq_fd, &sb) < 0)
		return -errno;

	pkt_send(fd, getattr_copy_stor(&sb));
	return LOCALFS_STOP;
}

static int localfs_ftruncate(int fd, struct lo_packet *rq)
{
	int rq_fd    = pkt_shift_32(rq);
	off_t rq_off = pkt_shift_64(rq);

	if (ftruncate(rq_fd, rq_off) < 0)
		return -errno;

	return LOCALFS_SUCCESS;
}

static int localfs_getattr(int fd, struct lo_packet *rq)
{
	const char *rq_path = pkt_shift_s(rq);
	char path[PATH_MAX];
	struct stat sb;

	if (b_path(path, rq_path))
		return -ENAMETOOLONG;
	if (lstat(path, &sb) < 0)
		return -errno;

	pkt_send(fd, getattr_copy_stor(&sb));
	return LOCALFS_STOP;
}

static int localfs_listxattr(int fd, struct lo_packet *rq)
{
	const char *rq_path = pkt_shift_s(rq);

	struct lo_packet *rp;
	char path[PATH_MAX], *list;
	ssize_t ret;

	if (b_path(path, rq_path))
		return -ENAMETOOLONG;
	ret = llistxattr(path, NULL, 0);
	if (ret < 0)
		return -errno;
	if (ret == 0)
		return 0;
	list = malloc(ret);
	if (list == NULL)
		return -ENOMEM;
	ret = llistxattr(path, list, ret);
	if (ret < 0)
		return -errno;
	if (ret == 0)
		return 0;
	rp = pkt_init(CCGFS_LISTXATTR_RESPONSE, PT_32);
	pkt_push_32(rp, ret);
	pkt_push(rp, list, ret, PT_DATA);
	pkt_send(fd, rp);
	free(list);
	return LOCALFS_STOP;
}

static int localfs_mkdir(int fd, struct lo_packet *rq)
{
	const char *rq_path = pkt_shift_s(rq);
	mode_t rq_mode      = pkt_shift_32(rq);
	char path[PATH_MAX];

	if (b_path(path, rq_path))
		return -ENAMETOOLONG;
	if (mkdir(path, rq_mode) < 0)
		return -errno;

	return LOCALFS_SUCCESS;
}

static int localfs_open(int fd, struct lo_packet *rq)
{
	const char *rq_path   = pkt_shift_s(rq);
	unsigned int rq_flags = pkt_shift_32(rq);

	struct lo_packet *rp;
	char path[PATH_MAX];
	int ret;

	if (b_path(path, rq_path))
		return -ENAMETOOLONG;
	if ((ret = open(path, rq_flags)) < 0)
		return -errno;

	rp = pkt_init(CCGFS_OPEN_RESPONSE, PV_32);
	pkt_push_32(rp, ret);
	pkt_send(fd, rp);
	return LOCALFS_STOP;
}

static int localfs_opendir_access(int fd, struct lo_packet *rq)
{
	const char *rq_path = pkt_shift_s(rq);
	char path[PATH_MAX];
	struct stat sb;

	if (b_path(path, rq_path))
		return -ENAMETOOLONG;
	if (stat(path, &sb) < 0)
		return -errno;
	if (!S_ISDIR(sb.st_mode))
		return -ENOTDIR;
	//setreuid(fsuid, -1);
	if (access(path, X_OK) < 0)
		return -errno;
	return LOCALFS_SUCCESS;
}

static int localfs_read(int fd, struct lo_packet *rq)
{
	int rq_fd       = pkt_shift_32(rq);
	size_t rq_size  = pkt_shift_32(rq);
	off_t rq_offset = pkt_shift_64(rq);

	struct lo_packet *rp;
	char buf[8192];
	ssize_t ret;

	ret = lseek(rq_fd, rq_offset, SEEK_SET);
	if (ret < 0 && errno != ESPIPE)
		return -errno;
	ret = read(rq_fd, buf, rq_size);
	if (ret < 0)
		return -errno;

	rp = pkt_init(CCGFS_READ_RESPONSE, 2 * PV_STRING);
	pkt_push_32(rp, ret);
	pkt_push(rp, buf, ret, PT_DATA);
	pkt_send(fd, rp);
	return LOCALFS_STOP;
}

static int localfs_readdir(int fd, struct lo_packet *rq)
{
	const char *rq_path = pkt_shift_s(rq);
	struct dirent *dentry;
	struct lo_packet *rp;
	char path[PATH_MAX];
	DIR *ptr;

	if (b_path(path, rq_path))
		return -ENAMETOOLONG;
	if ((ptr = opendir(path)) == NULL)
		return -errno;

	while ((dentry = readdir(ptr)) != NULL) {
		rp = pkt_init(CCGFS_READDIR_RESPONSE,
		              PV_64 + PV_32 + PV_STRING);
		pkt_push_64(rp, dentry->d_ino);
		pkt_push_32(rp, dentry->d_type);
		pkt_push_s(rp, dentry->d_name);
		pkt_send(fd, rp);
	}

	closedir(ptr);
	return LOCALFS_SUCCESS;
}

static int localfs_readlink(int fd, struct lo_packet *rq)
{
	const char *rq_path = pkt_shift_s(rq);
	char path[PATH_MAX], d_linkbuf[PATH_MAX];
	struct lo_packet *rp;

	if (b_path(path, rq_path))
		return -ENAMETOOLONG;

	memset(d_linkbuf, 0, sizeof(d_linkbuf));
	if (readlink(path, d_linkbuf, sizeof(d_linkbuf) - 1) < 0)
		return -errno;

	rp = pkt_init(CCGFS_READLINK_RESPONSE, PV_STRING);
	pkt_push_s(rp, d_linkbuf);
	pkt_send(fd, rp);
	return LOCALFS_STOP;
}

static int localfs_release(int fd, struct lo_packet *rq)
{
	if (close(pkt_shift_32(rq)) < 0)
		return -errno;
	return LOCALFS_SUCCESS;
}

static int localfs_rename(int fd, struct lo_packet *rq)
{
	const char *rq_oldpath = pkt_shift_s(rq);
	const char *rq_newpath = pkt_shift_s(rq);
	char oldpath[PATH_MAX], newpath[PATH_MAX];

	if (b_path(oldpath, rq_oldpath) || b_path(newpath, rq_newpath))
		return -ENAMETOOLONG;
	if (rename(oldpath, newpath) < 0)
		return -errno;

	return LOCALFS_SUCCESS;
}

static int localfs_rmdir(int fd, struct lo_packet *rq)
{
	const char *rq_path = pkt_shift_s(rq);
	char path[PATH_MAX];

	if (b_path(path, rq_path))
		return -ENAMETOOLONG;
	if (rmdir(path) < 0)
		return -errno;

	return LOCALFS_SUCCESS;
}

static int localfs_symlink(int fd, struct lo_packet *rq)
{
	const char *rq_oldpath = pkt_shift_s(rq);
	const char *rq_newpath = pkt_shift_s(rq);
	char newpath[PATH_MAX];

	if (b_path(newpath, rq_newpath))
		return -ENAMETOOLONG;
	if (symlink(rq_oldpath, newpath) < 0)
		return -errno;

	return LOCALFS_SUCCESS;
}

static int localfs_statfs(int fd, struct lo_packet *rq)
{
	const char *rq_path = pkt_shift_s(rq);
	struct lo_packet *rp;
	struct statvfs st;
	char path[PATH_MAX];

	if (b_path(path, rq_path))
		return -ENAMETOOLONG;
	if (statvfs(path, &st) < 0)
		return -errno;

	rp = pkt_init(CCGFS_STATFS_RESPONSE, 11 * PV_64);
	pkt_push_64(rp, st.f_bsize);
	pkt_push_64(rp, st.f_frsize);
	pkt_push_64(rp, st.f_blocks);
	pkt_push_64(rp, st.f_bfree);
	pkt_push_64(rp, st.f_bavail);
	pkt_push_64(rp, st.f_files);
	pkt_push_64(rp, st.f_ffree);
	pkt_push_64(rp, st.f_favail);
	pkt_push_64(rp, st.f_fsid);
	pkt_push_64(rp, st.f_flag);
	pkt_push_64(rp, st.f_namemax);
	pkt_send(fd, rp);
	return LOCALFS_STOP;
}

static int localfs_truncate(int fd, struct lo_packet *rq)
{
	const char *rq_path = pkt_shift_s(rq);
	off_t rq_off        = pkt_shift_64(rq);
	char path[PATH_MAX];

	if (b_path(path, rq_path))
		return -ENAMETOOLONG;
	if (truncate(path, rq_off) < 0)
		return -errno;

	return LOCALFS_SUCCESS;
}

static int localfs_unlink(int fd, struct lo_packet *rq)
{
	const char *rq_path = pkt_shift_s(rq);
	char path[PATH_MAX];

	if (b_path(path, rq_path))
		return -ENAMETOOLONG;
	if (unlink(path) < 0)
		return -errno;

	return LOCALFS_SUCCESS;
}

static int localfs_utimens(int fd, struct lo_packet *rq)
{
	const char *rq_path = pkt_shift_s(rq);
	struct timeval val[2];
	char path[PATH_MAX];

	if (b_path(path, rq_path))
		return -ENAMETOOLONG;
	val[0].tv_sec  = pkt_shift_64(rq);
	val[0].tv_usec = pkt_shift_64(rq) / 1000;
	val[1].tv_sec  = pkt_shift_64(rq);
	val[1].tv_usec = pkt_shift_64(rq) / 1000;
	if (utimes(path, val) < 0)
		return -errno;

	return LOCALFS_SUCCESS;
}

static int localfs_write(int fd, struct lo_packet *rq)
{
	int rq_fd        = pkt_shift_32(rq);
	size_t size      = pkt_shift_32(rq);
	off_t offset     = pkt_shift_64(rq);
	const char *data = pkt_shift_s(rq);

	struct lo_packet *rp;
	ssize_t ret;

	ret = lseek(rq_fd, offset, SEEK_SET);
	if (ret < 0 && errno != -ESPIPE)
		return -errno;
	if ((ret = write(rq_fd, data, size)) < 0)
		return -errno;

	rp = pkt_init(CCGFS_ERRNO_RESPONSE, PV_32);
	pkt_push_32(rp, ret);
	pkt_send(fd, rp);
	return LOCALFS_STOP;
}

static const localfs_func_t localfs_func_array[] = {
	[CCGFS_CHMOD_REQUEST]     = localfs_chmod,
	[CCGFS_CHOWN_REQUEST]     = localfs_chown,
	[CCGFS_CREATE_REQUEST]    = localfs_create,
	[CCGFS_FGETATTR_REQUEST]  = localfs_fgetattr,
	[CCGFS_FTRUNCATE_REQUEST] = localfs_ftruncate,
	[CCGFS_GETATTR_REQUEST]   = localfs_getattr,
	[CCGFS_LISTXATTR_REQUEST] = localfs_listxattr,
	[CCGFS_MKDIR_REQUEST]     = localfs_mkdir,
	[CCGFS_OPEN_REQUEST]      = localfs_open,
	[CCGFS_OPENDIR_REQUEST]   = localfs_opendir_access,
	[CCGFS_READ_REQUEST]      = localfs_read,
	[CCGFS_READDIR_REQUEST]   = localfs_readdir,
	[CCGFS_READLINK_REQUEST]  = localfs_readlink,
	[CCGFS_RELEASE_REQUEST]   = localfs_release,
	[CCGFS_RENAME_REQUEST]    = localfs_rename,
	[CCGFS_RMDIR_REQUEST]     = localfs_rmdir,
	[CCGFS_STATFS_REQUEST]    = localfs_statfs,
	[CCGFS_SYMLINK_REQUEST]   = localfs_symlink,
	[CCGFS_TRUNCATE_REQUEST]  = localfs_truncate,
	[CCGFS_UNLINK_REQUEST]    = localfs_unlink,
	[CCGFS_UTIMENS_REQUEST]   = localfs_utimens,
	[CCGFS_WRITE_REQUEST]     = localfs_write,
};

static int localfs_setfsid(struct lo_packet *rq)
{
	uid_t uid = pkt_shift_32(rq);
	gid_t gid = pkt_shift_32(rq);
	if (!i_am_root)
		return 0;
	if (setfsuid(uid) < 0 || setfsgid(gid) < 0) {
		perror("setfsid");
		abort();
	}
	return 0;
}

static void handle_packet(int fd, struct lo_packet *rq)
{
	struct ccgfs_pkt_header *hdr;
	struct lo_packet *rp;
	localfs_func_t lf;
	int ret;

	if (localfs_setfsid(rq) < 0) {
		rp = pkt_init(CCGFS_ERRNO_RESPONSE, PV_32);
		pkt_push_32(rp, -EPERM);
		pkt_send(fd, rp);
		return;
	}

	ret = -EIO;
	hdr = rq->data;
	lf  = localfs_func_array[hdr->opcode];
	if (lf != NULL)
		ret = (*lf)(fd, rq);

	if (ret <= 0) {
		rp = pkt_init(CCGFS_ERRNO_RESPONSE, PV_32);
		pkt_push_32(rp, ret);
		pkt_send(fd, rp);
	}

	return;
}

static void send_fsinfo(int fd)
{
	struct lo_packet *rp;
	char host[NAME_MAX], buf[NAME_MAX];

	if (gethostname(host, sizeof(host)) < 0) {
		perror("gethostname");
		exit(EXIT_FAILURE);
	}

	snprintf(buf, sizeof(buf), "%s:%s", host, root_dir);
	rp = pkt_init(CCGFS_FSINFO, PV_STRING);
	pkt_push_s(rp, buf);
	pkt_send(fd, rp);
	return;
}

int main(int argc, const char **argv)
{
	struct lo_packet *rq;

	if (argc < 2) {
		fprintf(stderr, "Usage: %s DIRECTORY\n", *argv);
		exit(EXIT_FAILURE);
	}

	if (chdir(argv[1]) < 0) {
		perror("chdir");
		exit(EXIT_FAILURE);
	}
	if (getcwd(root_dir, sizeof(root_dir)) == NULL) {
		perror("getcwd");
		exit(EXIT_FAILURE);
	}

	umask(0);
	i_am_root = getuid() == 0;
	pagesize  = sysconf(_SC_PAGESIZE);
	send_fsinfo(STDOUT_FILENO);

	while (1) {
		rq = pkt_recv(STDIN_FILENO);
		if (rq == NULL)
			break;
		handle_packet(STDOUT_FILENO, rq);
		pkt_destroy(rq);
	}

	return EXIT_SUCCESS;
}
