AM_CFLAGS              = $(AC_CFLAGS)

bin_PROGRAMS           = fifo-unblock test01
sbin_PROGRAMS          = ccgfs-fifo ccgfs-mount ccgfs-ssh-pull ccgfs-ssh-push \
                         ccgfs-storage ccgfs-super

ccgfs_fifo_SOURCES     = fifo.c launch.c
ccgfs_mount_SOURCES    = mount.c packet.c
ccgfs_mount_CFLAGS     = $(AC_CFLAGS) $(LIBFUSE_CFLAGS)
ccgfs_mount_LDFLAGS    = $(LIBFUSE_LDFLAGS)
ccgfs_ssh_pull_SOURCES = ssh-pull.c launch.c
ccgfs_ssh_push_SOURCES = ssh-push.c launch.c
ccgfs_storage_SOURCES  = storage.c packet.c
ccgfs_super_SOURCES    = super.c
ccgfs_super_CFLAGS     = $(LIBXML_CFLAGS) $(LIBSSL_CFLAGS)
ccgfs_super_LDFLAGS    = -lHX $(LIBXML_LDFLAGS) $(LIBSSL_LDFLAGS)
