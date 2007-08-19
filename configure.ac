
AC_INIT(ccgfs, 0.33)
AC_CONFIG_HEADERS(config.h)
AM_INIT_AUTOMAKE
AC_PROG_CC
AM_PROG_CC_C_O

AC_CFLAGS="-D_LARGEFILE_SOURCE=1 -D_LARGE_FILES -D_FILE_OFFSET_BITS=64 \
	-D_REENTRANT -Wall -Waggregate-return -Wmissing-declarations \
	-Wmissing-prototypes -Wredundant-decls -Wshadow -Wstrict-prototypes \
	-Winline -pipe"

AC_C_BIGENDIAN([be=1], [le=1], AC_MSG_ERROR([Could not determine endianess.]))
AC_ARG_WITH([encoding], AS_HELP_STRING([--with-encoding=[[LE|BE]]], [Encoding]),
	[encoding="$withval"], [encoding="LE"])

if [[ "$encoding" == "LE" ]]; then
	echo "Selecting LE encoding";
	if [[ -n "$be" ]]; then
		AC_CFLAGS="$AC_CFLAGS -DPKTSWAP";
	fi;
else
	echo "Selecting BE encoding";
	if [[ -n "$le" ]]; then
		AC_CFLAGS="$AC_CFLAGS -DPKTSWAP";
	fi;
fi;

AC_CHECK_HEADER(attr/xattr.h, [], AC_MSG_ERROR([libattr-devel not installed]))
PKG_CHECK_MODULES([libfuse], [fuse >= 2.6.0])
PKG_CHECK_MODULES([libssl], [libssl])
PKG_CHECK_MODULES([libxml], [libxml-2.0])

AC_SUBST(AC_CFLAGS)
AC_OUTPUT([Makefile src/Makefile])
