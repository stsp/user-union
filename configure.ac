#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.63])
AC_INIT([user-union], [0.15], [dwheeler@dwheeler.com],
        [user-union], [http://www.dwheeler.com/user-union])
AC_CONFIG_SRCDIR([user-union.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])

# Turn on extensions since we need to muck about in them.
AC_USE_SYSTEM_EXTENSIONS

# Bring in automake.
AM_INIT_AUTOMAKE([1.11 -Wall -Werror])
# The following invokes AM_PROG_AR, but only if it's defined.
# On some systems, failing to invoke AM_PROG_AR triggers an
# automake warning that, because of -Werror, leads to build failure.
# However, other (older) automakes don't have this macro at all.
# This approach handles all cases, and reports when the macro isn't defined.
m4_ifdef([AM_PROG_AR], [AM_PROG_AR],
 # Space out AM_PROG_AR so the suspicious pattern detector doesn't complain.
 [AC_MSG_CHECKING([["Detecting automake macro AM _ PROG _ AR"]])
 AC_MSG_RESULT(["no"])])

# Bring in libtool.
LT_PREREQ([2.2.6])
# Disable static, since they're pointless in our case, and try to make
# relocatable so that it can override anything
LT_INIT([disable-static pic-only dlopen])

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MKDIR_P

# Set PROG_REALPATH_DEFAULT
AC_MSG_CHECKING([[for realpath (all but last component must exist)]])
if test "$(realpath /bin/NoSuchFile 2>/dev/null)" = /bin/NoSuchFile
then
  PROG_REALPATH_DEFAULT=realpath
  AC_MSG_RESULT([$PROG_REALPATH_DEFAULT])
elif test "$(readlink -f /bin/NoSuchFile 2>/dev/null)" = /bin/NoSuchFile
then
  PROG_REALPATH_DEFAULT="readlink -f"
  AC_MSG_RESULT([$PROG_REALPATH_DEFAULT])
else
  AC_MSG_RESULT([FAILURE])
  echo 'No useful realpath or readlink available' >&2
  exit 1
fi
AC_SUBST([PROG_REALPATH_DEFAULT])


# Checks for libraries.
# FIXME: Replace `main' with a function in `-ldl':
# AC_CHECK_LIB([dl], [main])

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h stdlib.h string.h sys/time.h unistd.h utime.h])

# Use libc's dlsym instead of libtool's ones when available, per
# http://mailman.verplant.org/pipermail/collectd/2011-July/004639.html
AC_CHECK_HEADERS(dlfcn.h, [have_dlfcn_h="yes"], [have_dlfcn_h="no"])
AM_CONDITIONAL(BUILD_WITH_LIBDL, test "x$have_dlfcn_h" = "xyes")

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_TYPE_UID_T
AC_C_INLINE
AC_TYPE_MODE_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T

# Checks for library functions.
AC_FUNC_LSTAT_FOLLOWS_SLASHED_SYMLINK
AC_FUNC_MALLOC
AC_CHECK_FUNCS([euidaccess getcwd strchr strcspn strdup strstr])

# See if we have "struct statvfs64" (Cygwin does not)
AC_CHECK_TYPES([struct statvfs64],,,
[AC_INCLUDES_DEFAULT
#include <sys/statvfs.h>])

# Enable gcc warning flags, but only if they seem to work
# C warning flags (if any) are stored in Makefile variable CWARNINGFLAGS.
CWARNINGFLAGS=''
TRY_CWARNINGFLAGS='-Wall -Wextra'
ORIGINAL_CFLAGS="$CFLAGS"
CFLAGS="$CFLAGS $TRY_CWARNINGFLAGS"
AC_MSG_CHECKING([[for gcc warning flags]])
AC_LINK_IFELSE(
[AC_LANG_PROGRAM([[
#include <stdio.h>
int f() {
  return 0;
}
]])],
  [AC_MSG_RESULT([yes])
   CWARNINGFLAGS="$TRY_CWARNINGFLAGS"],
  [AC_MSG_RESULT([no])])
CFLAGS="$ORIGINAL_CFLAGS"
AC_SUBST([CWARNINGFLAGS])

AC_ARG_ENABLE(debug,
  AC_HELP_STRING([--enable-debug], [compile with debug support]),
  CFLAGS="$CFLAGS -ggdb3")

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
