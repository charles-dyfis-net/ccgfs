
AC_INIT(ccgfs, 0.33)
AC_CONFIG_HEADERS(config.h)
AM_INIT_AUTOMAKE
AC_PROG_CC

AC_CFLAGS="-D_LARGEFILE_SOURCE=1 -D_LARGE_FILES -D_FILE_OFFSET_BITS=64 \
	-D_REENTRANT -Wall -Waggregate-return -Wmissing-declarations \
	-Wmissing-prototypes -Wredundant-decls -Wshadow -Wstrict-prototypes \
	-Winline -pipe"
LIBFUSE_CFLAGS=`pkg-config fuse --cflags`
LIBFUSE_LDFLAGS=`pkg-config fuse --libs`
LIBSSL_CFLAGS=`pkg-config libssl --cflags`
LIBSSL_LDFLAGS=`pkg-config libssl --libs`
LIBXML_CFLAGS=`pkg-config libxml-2.0 --cflags`
LIBXML_LDFLAGS=`pkg-config libxml-2.0 --libs`

saved_CFLAGS="$CFLAGS"
saved_CPPFLAGS="$CPPFLAGS"
CFLAGS="$CFLAGS $AC_CFLAGS $LIBFUSE_CFLAGS $LIBSSL_CFLAGS $LIBXML_CFLAGS"
CPPFLAGS="$CFLAGS $AC_CFLAGS $LIBFUSE_CFLAGS $LIBSSL_CFLAGS $LIBXML_CFLAGS"
AC_CHECK_HEADER(attr/xattr.h, [],
		AC_MSG_ERROR([libattr-devel not installed]))
AC_CHECK_HEADER(fuse.h, [],
		AC_MSG_ERROR([fuse-devel not installed]))
AC_CHECK_HEADER(libxml/parser.h, [],
                AC_MSG_ERROR([libxml2-devel not installed]))
AC_CHECK_HEADER(openssl/sha.h, [],
                AC_MSG_ERROR([openssl-devel not installed]))
CFLAGS="$saved_CFLAGS"
CPPFLAGS="$saved_CPPFLAGS"

AC_SUBST(AC_CFLAGS)
AC_SUBST(LIBFUSE_CFLAGS)
AC_SUBST(LIBSSL_CFLAGS)
AC_SUBST(LIBSSL_LDFLAGS)
AC_SUBST(LIBFUSE_LDFLAGS)
AC_SUBST(LIBXML_CFLAGS)
AC_SUBST(LIBXML_LDFLAGS)
AC_OUTPUT([Makefile src/Makefile])
