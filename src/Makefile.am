# -*- Makefile -*-

AM_CFLAGS              = $(AC_CFLAGS)

EXTRA_PROGRAMS         = fifo-unblock test01
sbin_PROGRAMS          = ccgfs-fifo ccgfs-mount ccgfs-ssh-pull ccgfs-ssh-push \
                         ccgfs-storage ccgfs-super \
                         ccgfs-stunnel-pull ccgfs-stunnel-push

ccgfs_fifo_SOURCES     = fifo.c launch.c
ccgfs_fifo_LDADD       = -lHX
ccgfs_mount_SOURCES    = mount.c packet.c
ccgfs_mount_CFLAGS     = $(AC_CFLAGS) $(LIBFUSE_CFLAGS)
ccgfs_mount_LDFLAGS    = $(LIBFUSE_LDFLAGS)
ccgfs_ssh_pull_SOURCES = ssh-pull.c launch.c
ccgfs_ssh_pull_LDADD   = -lHX
ccgfs_ssh_push_SOURCES = ssh-push.c launch.c
ccgfs_ssh_push_LDADD   = -lHX
ccgfs_storage_SOURCES  = storage.c packet.c
ccgfs_super_SOURCES    = super.c
ccgfs_super_CFLAGS     = $(LIBXML_CFLAGS) $(LIBSSL_CFLAGS)
ccgfs_super_LDADD      = -lHX
ccgfs_super_LDFLAGS    = $(LIBXML_LDFLAGS) $(LIBSSL_LDFLAGS)

ccgfs_stunnel_pull_SOURCES = stunnel-pull.c launch.c
ccgfs_stunnel_pull_LDADD   = -lHX
ccgfs_stunnel_push_SOURCES = stunnel-push.c launch.c
ccgfs_stunnel_push_LDADD   = -lHX
