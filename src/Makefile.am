# -*- Makefile -*-

AM_CFLAGS              = ${regular_CFLAGS} ${libHX_CFLAGS}

EXTRA_PROGRAMS         = fifo-unblock test01
sbin_PROGRAMS          = ccgfs-fifo ccgfs-mount ccgfs-ssh-pull ccgfs-ssh-push \
                         ccgfs-storage ccgfs-super \
                         ccgfs-stunnel-pull ccgfs-stunnel-push

ccgfs_fifo_SOURCES     = fifo.c launch.c
ccgfs_fifo_LDADD       = ${libHX_LIBS}
ccgfs_mount_SOURCES    = mount.c packet.c xl.c
ccgfs_mount_CFLAGS     = ${AM_CFLAGS} ${libfuse_CFLAGS}
ccgfs_mount_LDADD      = ${libfuse_LIBS}
ccgfs_ssh_pull_SOURCES = ssh-pull.c launch.c
ccgfs_ssh_pull_LDADD   = ${libHX_LIBS}
ccgfs_ssh_push_SOURCES = ssh-push.c launch.c
ccgfs_ssh_push_LDADD   = ${libHX_LIBS}
ccgfs_storage_SOURCES  = storage.c packet.c xl.c
ccgfs_storage_LDADD    = ${libHX_LIBS}
ccgfs_super_SOURCES    = super.c
ccgfs_super_CFLAGS     = ${AM_CFLAGS} ${libxml_CFLAGS} ${libssl_CFLAGS}
ccgfs_super_LDADD      = ${libHX_LIBS} ${libxml_LIBS} ${libssl_LIBS}

ccgfs_stunnel_pull_SOURCES = stunnel-pull.c launch.c
ccgfs_stunnel_pull_LDADD   = ${libHX_LIBS}
ccgfs_stunnel_push_SOURCES = stunnel-push.c launch.c
ccgfs_stunnel_push_LDADD   = ${libHX_LIBS}
