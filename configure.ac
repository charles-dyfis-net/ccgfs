
AC_INIT([ccgfs], [0.74])
AC_CONFIG_HEADERS([config.h])
AC_PROG_INSTALL
AM_INIT_AUTOMAKE([-Wall])
AC_PROG_CC
AM_PROG_CC_C_O

regular_CFLAGS="-D_LARGEFILE_SOURCE=1 -D_LARGE_FILES -D_FILE_OFFSET_BITS=64 \
	-D_REENTRANT -Wall -Waggregate-return -Wmissing-declarations \
	-Wmissing-prototypes -Wredundant-decls -Wshadow -Wstrict-prototypes \
	-pipe"

AC_ARG_ENABLE([workarounds],
	AS_HELP_STRING([--enable-workarounds],
	[Enable some workaround for Linux kernels < 2.6.16]),
	[AC_DEFINE([ENABLE_WORKAROUNDS], [1], 
	[Define if you do not run Linux 2.6.16 or newer])]
)

AC_C_BIGENDIAN([be=1], [le=1], AC_MSG_ERROR([Could not determine endianess.]))
AC_ARG_WITH([encoding], AS_HELP_STRING([--with-encoding=[[LE|BE]]], [Encoding]),
	[encoding="$withval"], [encoding="LE"])

if [[ "$encoding" == "LE" ]]; then
	echo "Selecting LE encoding";
	if [[ -n "$be" ]]; then
		regular_CFLAGS="$regular_CFLAGS -DPKTSWAP";
	fi;
else
	echo "Selecting BE encoding";
	if [[ -n "$le" ]]; then
		regular_CFLAGS="$regular_CFLAGS -DPKTSWAP";
	fi;
fi;

AC_CHECK_HEADERS([attr/xattr.h], [], [echo -e "\t""You probably need libattr-devel"])
AC_CHECK_HEADERS([sys/fsuid.h sys/mman.h sys/statvfs.h])

# FUSE >= 2.7.0 got subtype name support.
# 2.6.5 does not, but has a similar thing.
PKG_CHECK_MODULES([libfuse], [fuse >= 2.7.0], [], [
	PKG_CHECK_MODULES([libfuse], [fuse >= 2.6.5], [
		AC_DEFINE([HAVE_JUST_FUSE_2_6_5], [1],
			[Define if you have a FUSE version >= 2.6.5 but < 2.7.0])
	])
])

PKG_CHECK_MODULES([libHX], [libHX >= 1.25])
PKG_CHECK_MODULES([libssl], [libssl])
PKG_CHECK_MODULES([libxml], [libxml-2.0])

AC_SUBST([regular_CFLAGS])
AC_CONFIG_FILES([Makefile etc/Makefile etc/ccgfs-super src/Makefile])
AC_OUTPUT
