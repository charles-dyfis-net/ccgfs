/*
 * Wrapper for older kernels where some *at() calls do not work
 */
#ifndef CCGFS_XAT_H
#define CCGFS_XAT_H 1

#define faccessat(fd, path, mode, flags)     access((path), (mode))
#define fchmodat(fd, path, mode, flags)      chmod((path), (mode))
#define fchownat(fd, path, uid, gid, flags)  lchown((path), (uid), (gid))
#define fstatat(fd, path, sb, flags)         lstat((path), (sb))
#define futimesat(fd, path, val)             utimes((path), (val))
#define linkat(ofd, oldpath, nfd, newpath, flags) \
	link((oldpath), (newpath))
#define mkdirat(fd, path, mode)              mkdir((path), (mode))
#define mknodat(fd, path, mode, rdev)        mknod((path), (mode), (rdev))
#define openat(fd, path, flags, mode...)     open((path), (flags), ## mode)
#define readlinkat(fd, path, buf, size)      readlink((path), (buf), (size))
#define renameat(ofd, oldpath, nfd, newpath) rename((oldpath), (newpath))
#define symlinkat(oldpath, fd, newpath)      symlink((oldpath), (newpath))
#define unlinkat(fd, path, flags)            my_unlinkat((fd), (path), (flags))

static inline int my_unlinkat(int fd, const char *pathname, int flags)
{
	if (flags & AT_REMOVEDIR)
		return rmdir(pathname);
	else
		return unlink(pathname);
}

#endif /* CCGFS_XAT_H */
