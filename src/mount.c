/*
 *	CC Network Filesystem (ccgfs)
 *	Mount Daemon
 *
 *	Copyright © CC Computer Consultants GmbH, 2007
 *	Contact: Jan Engelhardt <jengelh [at] computergmbh de>
 *
 *	This file is part of CCGFS. CCGFS is free software; you can
 *	redistribute it and/or modify it under the terms of the GNU
 *	General Public License as published by the Free Software
 *	Foundation; either version 2 or 3 of the License.
 */
#define FUSE_USE_VERSION 26
#include <sys/fsuid.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <errno.h>
#include <fuse.h>
#include <fuse_opt.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <utime.h>
#include <attr/xattr.h>
#include "ccgfs.h"
#include "config.h"
#include "packet.h"
#include "xl.h"

static pthread_t main_thread_id, monitor_id;
static pthread_mutex_t net_lock = PTHREAD_MUTEX_INITIALIZER;
static const int in_fd = STDIN_FILENO, out_fd = STDOUT_FILENO;

static inline struct lo_packet *mpkt_init(unsigned int type,
    unsigned int length)
{
	const struct fuse_context *ctx = fuse_get_context();
	struct lo_packet *pkt;

	pkt = pkt_init(type, length + 2 * PV_32);
	pkt_push_32(pkt, ctx->uid);
	pkt_push_32(pkt, ctx->gid);
	return pkt;
}

static int __mpkt_recv(unsigned int type, struct lo_packet **putback,
    bool list_retrieval)
{
	const struct ccgfs_pkt_header *hdr;
	struct lo_packet *pkt;

	pkt = pkt_recv(in_fd);
	if (!list_retrieval)
		pthread_mutex_unlock(&net_lock);

	if (pkt == NULL) {
		fprintf(stderr, "%s: %s\n",
		        __func__, strerror(errno));
		pthread_kill(main_thread_id, SIGTERM);
		return -ENOTCONN;
	}

	hdr = pkt->data;
	if (hdr->opcode == CCGFS_ERRNO_RESPONSE) {
		int32_t ret = pkt_shift_32(pkt);
		pkt_destroy(pkt);
		return arch_errno(ret);
	}

	if (hdr->opcode != type) {
		pkt_destroy(pkt);
		*putback = NULL;
		return -EIO;
	}

	*putback = pkt;
	return list_retrieval;
}

#define mpkt_recv(type, putback)      __mpkt_recv((type), (putback), false)
#define mpkt_recv_list(type, putback) __mpkt_recv((type), (putback), true)
#define mpkt_send(fd, packet) \
	do { \
		pthread_mutex_lock(&net_lock); \
		pkt_send((fd), (packet)); \
	} while (false);

static int ccgfs_chmod(const char *path, mode_t mode)
{
	struct lo_packet *rq;

	rq = mpkt_init(CCGFS_CHMOD_REQUEST, PV_STRING + PV_32);
	pkt_push_s(rq, path);
	pkt_push_32(rq, mode);
	mpkt_send(out_fd, rq);

	return mpkt_recv(CCGFS_ERRNO_RESPONSE, NULL);
}

static int ccgfs_chown(const char *path, uid_t uid, gid_t gid)
{
	struct lo_packet *rq;

	rq = mpkt_init(CCGFS_CHOWN_REQUEST, PV_STRING + 2 * PV_32);
	pkt_push_s(rq, path);
	pkt_push_32(rq, uid);
	pkt_push_32(rq, gid);
	mpkt_send(out_fd, rq);

	return mpkt_recv(CCGFS_ERRNO_RESPONSE, NULL);
}

static int ccgfs_create(const char *path, mode_t mode,
    struct fuse_file_info *filp)
{
	struct lo_packet *rq, *rp;
	int ret;

	rq = mpkt_init(CCGFS_CREATE_REQUEST, PV_STRING + 2 * PV_32);
	pkt_push_s(rq, path);
	pkt_push_32(rq, generic_openflags(filp->flags));
	pkt_push_32(rq, mode);
	mpkt_send(out_fd, rq);

	ret = mpkt_recv(CCGFS_CREATE_RESPONSE, &rp);
	if (ret < 0)
		return ret;

	filp->fh = pkt_shift_32(rp);
	pkt_destroy(rp);
	return 0;
}

static void getattr_copy_mount(struct stat *sb, struct lo_packet *rp)
{
	/* No sb->st_dev! */
	sb->st_ino     = pkt_shift_64(rp);
	sb->st_mode    = pkt_shift_32(rp);
	sb->st_nlink   = pkt_shift_32(rp);
	sb->st_uid     = pkt_shift_32(rp);
	sb->st_gid     = pkt_shift_32(rp);
	sb->st_rdev    = pkt_shift_32(rp);
	sb->st_size    = pkt_shift_64(rp);
	sb->st_blksize = pkt_shift_64(rp);
	sb->st_blocks  = pkt_shift_64(rp);
	sb->st_atime   = pkt_shift_64(rp);
	sb->st_mtime   = pkt_shift_64(rp);
	sb->st_ctime   = pkt_shift_64(rp);
	return;
}

static int ccgfs_fgetattr(const char *path, struct stat *sb,
    struct fuse_file_info *filp)
{
	struct lo_packet *rq, *rp;
	int ret;

	rq = mpkt_init(CCGFS_FGETATTR_REQUEST, PV_32);
	pkt_push_32(rq, filp->fh);
	mpkt_send(out_fd, rq);

	ret = mpkt_recv(CCGFS_GETATTR_RESPONSE, &rp);
	if (ret < 0)
		return ret;

	getattr_copy_mount(sb, rp);
	pkt_destroy(rp);
	return 0;
}

static int ccgfs_fsync(const char *path, int meta_only,
    struct fuse_file_info *filp)
{
	struct lo_packet *rq;

	rq = mpkt_init(CCGFS_FSYNC_REQUEST, 2 * PV_32);
	pkt_push_32(rq, filp->fh);
	pkt_push_32(rq, meta_only);
	mpkt_send(out_fd, rq);

	return mpkt_recv(CCGFS_ERRNO_RESPONSE, NULL);
}

static int ccgfs_ftruncate(const char *path, off_t off,
    struct fuse_file_info *filp)
{
	struct lo_packet *rq;

	rq = mpkt_init(CCGFS_FTRUNCATE_REQUEST, PV_32 + PV_64);
	pkt_push_32(rq, filp->fh);
	pkt_push_64(rq, off);
	mpkt_send(out_fd, rq);

	return mpkt_recv(CCGFS_ERRNO_RESPONSE, NULL);
}

static int ccgfs_getattr(const char *path, struct stat *sb)
{
	struct lo_packet *rq, *rp;
	int ret;

	rq = mpkt_init(CCGFS_GETATTR_REQUEST, PV_STRING);
	pkt_push_s(rq, path);
	mpkt_send(out_fd, rq);

	ret = mpkt_recv(CCGFS_GETATTR_RESPONSE, &rp);
	if (ret < 0)
		return ret;

	getattr_copy_mount(sb, rp);
	pkt_destroy(rp);
	return 0;
}

static int ccgfs_getxattr(const char *path, const char *name,
    char *value, size_t size)
{
	struct lo_packet *rq, *rp;
	int ret;

	rq = mpkt_init(CCGFS_GETXATTR_REQUEST, PV_STRING);
	pkt_push_s(rq, path);
	pkt_push_s(rq, name);
	pkt_push_64(rq, size);
	mpkt_send(out_fd, rq);

	ret = mpkt_recv(CCGFS_GETXATTR_RESPONSE, &rp);
	if (ret < 0)
		return ret;

	ret = pkt_shift_64(rp);
	if (size > 0)
		memcpy(value, pkt_shift_s(rp), ret);
	else
		pkt_shift_s(rp); /* DBG */
	pkt_destroy(rp);
	return ret;
}

static void *ccgfs_monitor(void *unused)
{
	struct pollfd poll_rq = {
		.fd     = in_fd,
		.events = POLLHUP,
	};

	while (true)
		if (poll(&poll_rq, 1, -1) > 0)
			break;

	pthread_kill(main_thread_id, SIGTERM);
	return NULL;
}

static void *ccgfs_init(struct fuse_conn_info *conn)
{
	struct sigaction sa = {};
	sa.sa_handler = SIG_IGN;
	sa.sa_flags   = SA_RESTART;
	sigemptyset(&sa.sa_mask);
	if (sigaction(SIGPIPE, &sa, NULL) < 0) {
		perror("sigaction");
		abort();
	}
	if (pthread_create(&monitor_id, NULL, ccgfs_monitor, NULL) < 0) {
		perror("pthread_create");
		abort();
	}
	pthread_detach(monitor_id);
	return NULL;
}

static int ccgfs_link(const char *oldpath, const char *newpath)
{
	struct lo_packet *rq;

	rq = mpkt_init(CCGFS_LINK_REQUEST, 2 * PV_STRING);
	pkt_push_s(rq, oldpath);
	pkt_push_s(rq, newpath);
	mpkt_send(out_fd, rq);

	return mpkt_recv(CCGFS_ERRNO_RESPONSE, NULL);
}

static int ccgfs_listxattr(const char *path, char *buffer, size_t size)
{
	struct lo_packet *rq, *rp;
	int ret;

	rq = mpkt_init(CCGFS_LISTXATTR_REQUEST, PV_STRING);
	pkt_push_s(rq, path);
	pkt_push_64(rq, size);
	mpkt_send(out_fd, rq);

	ret = mpkt_recv(CCGFS_LISTXATTR_RESPONSE, &rp);
	if (ret < 0)
		return ret;

	ret = pkt_shift_64(rp);
	if (size > 0)
		memcpy(buffer, pkt_shift_s(rp), ret);
	else
		pkt_shift_s(rp); /* DBG */
	pkt_destroy(rp);
	return ret;
}

static int ccgfs_mkdir(const char *path, mode_t mode)
{
	struct lo_packet *rq;

	rq = mpkt_init(CCGFS_MKDIR_REQUEST, PV_STRING + PV_32);
	pkt_push_s(rq, path);
	pkt_push_32(rq, mode);
	mpkt_send(out_fd, rq);

	return mpkt_recv(CCGFS_ERRNO_RESPONSE, NULL);
}

static int ccgfs_mknod(const char *path, mode_t mode, dev_t rdev)
{
	struct lo_packet *rq;

	rq = mpkt_init(CCGFS_MKNOD_REQUEST, PV_STRING + 2 * PV_32);
	pkt_push_s(rq, path);
	pkt_push_32(rq, mode);
	pkt_push_32(rq, rdev);
	mpkt_send(out_fd, rq);

	return mpkt_recv(CCGFS_ERRNO_RESPONSE, NULL);
}

static int ccgfs_open(const char *path, struct fuse_file_info *filp)
{
	struct lo_packet *rq, *rp;
	int ret;

	rq = mpkt_init(CCGFS_OPEN_REQUEST, PV_STRING + PV_32);
	pkt_push_s(rq, path);
	pkt_push_32(rq, generic_openflags(filp->flags));
	mpkt_send(out_fd, rq);

	ret = mpkt_recv(CCGFS_OPEN_RESPONSE, &rp);
	if (ret < 0)
		return ret;

	filp->fh = pkt_shift_32(rp);
	pkt_destroy(rp);
	return 0;
}

static int ccgfs_opendir(const char *path, struct fuse_file_info *filp)
{
	struct lo_packet *rq;

	rq = mpkt_init(CCGFS_OPENDIR_REQUEST, PV_STRING);
	pkt_push_s(rq, path);
	mpkt_send(out_fd, rq);

	return mpkt_recv(CCGFS_ERRNO_RESPONSE, NULL);
}

static int ccgfs_read(const char *path, char *buffer, size_t size,
    off_t offset, struct fuse_file_info *filp)
{
	struct lo_packet *rq, *rp;
	const char *data;
	int ret;

	/*
	 * ccgfs operates (at its core) in synchronous mode, so cap the maximum
	 * transfer size at 8192 so that big writes do not clog up the pipe.
	 * (Feel free to change)
	 *
	 * Incidentally, this cap makes the biggest packet have a size of
	 * about 8244 - giving a nice fit for 9000-byte MTU Gigabit Ethernet
	 * jumbo frames.
	 */
	if (size > 8192)
		size = 8192;

	rq = mpkt_init(CCGFS_READ_REQUEST, 2 * PV_32 + PV_64);
	pkt_push_32(rq, filp->fh);
	pkt_push_64(rq, size);
	pkt_push_64(rq, offset);
	mpkt_send(out_fd, rq);

	ret = mpkt_recv(CCGFS_READ_RESPONSE, &rp);
	if (ret < 0)
		return ret;

	ret  = pkt_shift_64(rp); /* return value/size */
	data = pkt_shift_s(rp);
	memcpy(buffer, data, ret);
	pkt_destroy(rp);
	return ret;
}

static int ccgfs_readdir(const char *path, void *what, fuse_fill_dir_t filldir,
    off_t offset, struct fuse_file_info *f)
{
	struct lo_packet *rq, *rp;
	struct stat sb;
	int ret;

	rq = mpkt_init(CCGFS_READDIR_REQUEST, PV_STRING);
	pkt_push_s(rq, path);
	mpkt_send(out_fd, rq);

	memset(&sb, 0, sizeof(sb));
	while ((ret = mpkt_recv_list(CCGFS_READDIR_RESPONSE, &rp)) > 0) {
		sb.st_ino  = pkt_shift_64(rp);
		sb.st_mode = pkt_shift_32(rp) << 12;
		ret = (*filldir)(what, pkt_shift_s(rp), &sb, 0);
		pkt_destroy(rp);
		if (ret > 0)
			break;
	}

	if (ret > 0)
		/*
		 * Means, we exited above loop through the break;
		 * Need to slurp all the remaining packets, though.
		 */
		while ((ret = mpkt_recv_list(CCGFS_READDIR_RESPONSE, &rp)) > 0)
			pkt_destroy(rp);

	pthread_mutex_unlock(&net_lock);

	if (ret < 0)
		return ret;
	
	return 0;
}

static int ccgfs_readlink(const char *path, char *linkbuf, size_t size)
{
	struct lo_packet *rq, *rp;
	const char *d_linkbuf;
	int ret;

	rq = mpkt_init(CCGFS_READLINK_REQUEST, PV_STRING);
	pkt_push_s(rq, path);
	mpkt_send(out_fd, rq);

	ret = mpkt_recv(CCGFS_READLINK_RESPONSE, &rp);
	if (ret < 0)
		return ret;

	d_linkbuf = pkt_shift_s(rp);
	memset(linkbuf, 0, size);
	strncpy(linkbuf, d_linkbuf, size);
	pkt_destroy(rp);
	return 0;
}

static int ccgfs_release(const char *path, struct fuse_file_info *filp)
{
	struct lo_packet *rq;

	rq = mpkt_init(CCGFS_RELEASE_REQUEST, PV_32);
	pkt_push_32(rq, filp->fh);
	mpkt_send(out_fd, rq);

	return mpkt_recv(CCGFS_ERRNO_RESPONSE, NULL);
}

static int ccgfs_removexattr(const char *path, const char *name)
{
	struct lo_packet *rq;

	rq = mpkt_init(CCGFS_REMOVEXATTR_REQUEST, PV_STRING + PV_32);
	pkt_push_s(rq, path);
	pkt_push_s(rq, name);
	mpkt_send(out_fd, rq);

	return mpkt_recv(CCGFS_ERRNO_RESPONSE, NULL);
}

static int ccgfs_rename(const char *oldpath, const char *newpath)
{
	struct lo_packet *rq;

	rq = mpkt_init(CCGFS_RENAME_REQUEST, 2 * PV_STRING);
	pkt_push_s(rq, oldpath);
	pkt_push_s(rq, newpath);
	mpkt_send(out_fd, rq);

	return mpkt_recv(CCGFS_ERRNO_RESPONSE, NULL);
}

static int ccgfs_rmdir(const char *path)
{
	struct lo_packet *rq;

	rq = mpkt_init(CCGFS_RMDIR_REQUEST, PV_STRING);
	pkt_push_s(rq, path);
	mpkt_send(out_fd, rq);

	return mpkt_recv(CCGFS_ERRNO_RESPONSE, NULL);
}

static int ccgfs_statfs(const char *path, struct statvfs *buf)
{
	struct lo_packet *rq, *rp;
	int ret;

	rq = mpkt_init(CCGFS_STATFS_REQUEST, PV_STRING);
	mpkt_send(out_fd, rq);

	ret = mpkt_recv(CCGFS_STATFS_RESPONSE, &rp);
	if (ret == -ENOTCONN) {
		memset(buf, 0, sizeof(*buf));
		return 0;
	}
	if (ret < 0)
		return ret;

	buf->f_bsize   = pkt_shift_64(rp);
	buf->f_frsize  = pkt_shift_64(rp);
	buf->f_blocks  = pkt_shift_64(rp);
	buf->f_bfree   = pkt_shift_64(rp);
	buf->f_bavail  = pkt_shift_64(rp);
	buf->f_files   = pkt_shift_64(rp);
	buf->f_ffree   = pkt_shift_64(rp);
	buf->f_favail  = pkt_shift_64(rp);
	buf->f_fsid    = pkt_shift_64(rp);
	buf->f_flag    = pkt_shift_64(rp);
	buf->f_namemax = pkt_shift_64(rp);
	pkt_destroy(rp);
	return 0;
}

static int ccgfs_setxattr(const char *path, const char *name,
    const char *value, size_t size, int flags)
{
	struct lo_packet *rq;

	rq = mpkt_init(CCGFS_SETXATTR_REQUEST, 3 * PV_STRING + PV_64 + PV_32);
	pkt_push_s(rq, path);
	pkt_push_s(rq, name);
	pkt_push_s(rq, value);
	pkt_push_64(rq, size);
	pkt_push_32(rq, flags);
	mpkt_send(out_fd, rq);

	return mpkt_recv(CCGFS_ERRNO_RESPONSE, NULL);
}

static int ccgfs_symlink(const char *oldpath, const char *newpath)
{
	struct lo_packet *rq;

	rq = mpkt_init(CCGFS_SYMLINK_REQUEST, 2 * PV_STRING);
	pkt_push_s(rq, oldpath);
	pkt_push_s(rq, newpath);
	mpkt_send(out_fd, rq);

	return mpkt_recv(CCGFS_ERRNO_RESPONSE, NULL);
}

static int ccgfs_truncate(const char *path, off_t off)
{
	struct lo_packet *rq;

	rq = mpkt_init(CCGFS_TRUNCATE_REQUEST, PV_STRING + PV_64);
	pkt_push_s(rq, path);
	pkt_push_64(rq, off);
	mpkt_send(out_fd, rq);

	return mpkt_recv(CCGFS_ERRNO_RESPONSE, NULL);
}

static int ccgfs_unlink(const char *path)
{
	struct lo_packet *rq;

	rq = mpkt_init(CCGFS_UNLINK_REQUEST, PV_STRING);
	pkt_push_s(rq, path);
	mpkt_send(out_fd, rq);

	return mpkt_recv(CCGFS_ERRNO_RESPONSE, NULL);
}

static int ccgfs_utimens(const char *path, const struct timespec *val)
{
	struct lo_packet *rq;

	rq = mpkt_init(CCGFS_UTIMENS_REQUEST, PV_STRING + 4 * PV_64);
	pkt_push_s(rq, path);
	pkt_push_64(rq, val[0].tv_sec);
	pkt_push_64(rq, val[0].tv_nsec);
	pkt_push_64(rq, val[1].tv_sec);
	pkt_push_64(rq, val[1].tv_nsec);
	mpkt_send(out_fd, rq);

	return mpkt_recv(CCGFS_ERRNO_RESPONSE, NULL);
}

static int ccgfs_write(const char *path, const char *buffer, size_t size,
    off_t offset, struct fuse_file_info *filp)
{
	struct lo_packet *rq;

	if (size > 8192)
		return -EIO;

	rq = mpkt_init(CCGFS_WRITE_REQUEST, PV_STRING + 2 * PV_32 + PV_64);
	pkt_push_32(rq, filp->fh);
	pkt_push_64(rq, size);
	pkt_push_64(rq, offset);
	pkt_push(rq, buffer, size, PT_DATA);
	mpkt_send(out_fd, rq);

	return mpkt_recv(CCGFS_ERRNO_RESPONSE, NULL);
}

static bool user_allow_other(void)
{
	bool ret = false;
	char buf[64];
	FILE *fp;

	if ((fp = fopen("/etc/fuse.conf", "r")) == NULL)
		return false;
	while (fgets(buf, sizeof(buf), fp) != NULL)
		/* no fancy line ending checks or anything */
		if (strncmp(buf, "user_allow_other",
		    sizeof("user_allow_other") - 1) == 0) {
			ret = true;
			break;
		}

	fclose(fp);
	return ret;
}

static const struct fuse_operations ccgfs_ops = {
	.chmod       = ccgfs_chmod,
	.chown       = ccgfs_chown,
	.create      = ccgfs_create,
	.fgetattr    = ccgfs_fgetattr,
	.fsync       = ccgfs_fsync,
	.ftruncate   = ccgfs_ftruncate,
	.getattr     = ccgfs_getattr,
	.getxattr    = ccgfs_getxattr,
	.init        = ccgfs_init,
	.link        = ccgfs_link,
	.listxattr   = ccgfs_listxattr,
	.mkdir       = ccgfs_mkdir,
	.mknod       = ccgfs_mknod,
	.open        = ccgfs_open,
	.opendir     = ccgfs_opendir,
	.read        = ccgfs_read,
	.readdir     = ccgfs_readdir,
	.readlink    = ccgfs_readlink,
	.release     = ccgfs_release,
	.removexattr = ccgfs_removexattr,
	.rename      = ccgfs_rename,
	.rmdir       = ccgfs_rmdir,
	.symlink     = ccgfs_symlink,
	.setxattr    = ccgfs_setxattr,
	.statfs      = ccgfs_statfs,
	.truncate    = ccgfs_truncate,
	.unlink      = ccgfs_unlink,
	.utimens     = ccgfs_utimens,
	.write       = ccgfs_write,
};

int main(int argc, char **argv)
{
	int new_argc = 0, i, ret;
	struct lo_packet *rp;
	char **new_argv;
	char buf[NAME_MAX];

	/*
	 * The mutex is unlocked. Hence we may not unlock it again.
	 * Hence __mpkt_recv(,,true).
	 */
	if ((ret = __mpkt_recv(CCGFS_FSINFO, &rp, true)) <= 0) {
		perror("mpkt_recv");
		exit(EXIT_FAILURE);
	}

	new_argv = malloc(sizeof(char *) * (argc + 5));
	new_argv[new_argc++] = argv[0];
	new_argv[new_argc++] = "-f";
	new_argv[new_argc++] = "-ouse_ino";

	if (user_allow_other())
		new_argv[new_argc++] = "-oallow_other";

#ifdef HAVE_JUST_FUSE_2_6_5
	snprintf(buf, sizeof(buf), "-ofsname=ccgfs#%s",
	         static_cast(const char *, pkt_shift_s(rp)));
#else
	snprintf(buf, sizeof(buf), "-osubtype=ccgfs,fsname=%s",
	         static_cast(const char *, pkt_shift_s(rp)));
#endif
	new_argv[new_argc++] = buf;
	pkt_destroy(rp);

	for (i = 1; i < argc; ++i)
		new_argv[new_argc++] = argv[i];
	new_argv[new_argc] = NULL;

	main_thread_id = pthread_self();
	return fuse_main(new_argc, new_argv, &ccgfs_ops, NULL);
}
