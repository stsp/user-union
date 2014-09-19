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

# Bring in specific .m4 macros, now that automake and libtool are enabled:
m4_include([m4/ax_check_progs_test.m4])

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MKDIR_P

# Set PROG_REALPATH, normally "realpath"
AC_MSG_CHECKING([[for realpath (all but last component must exist)]])
AX_CHECK_PROGS_TEST([PROG_REALPATH],
  ['realpath --' 'readlink -f --'],
  [$try /bin/NoSuchFile >/dev/null 2>&1])
AC_ARG_VAR([PROG_REALPATH], [Command to canonicalize filename (except last component, e.g., 'realpath')])

# Set PROG_REALPATH_E, normally "realpath -e"
# If neither realpath or readlink support "-e" (e.g., Busybox),
# we'll back off to using realpath or readlink. This isn't ideal (it omits
# the existence check for the last component), but should be adequate
# in many use cases.
AC_MSG_CHECKING([[for realpath -e (all components must exist)]])
AX_CHECK_PROGS_TEST([PROG_REALPATH_E],
  ['realpath -e --' 'readlink -e --' 'realpath --' 'readlink --' 'realpath' 'readlink'],
  [$try /bin/sh >/dev/null 2>&1])
case "$PROG_REALPATH_E" in
  *\ -e*) ;; # Normal case, good
  *) AC_MSG_WARN([Do not have 'realpath -e' nor 'readlink -e', using $PROG_REALPATH_E instead.])
esac
AC_ARG_VAR([PROG_REALPATH_E], [Command to canonicalize filename (all components exist, e.g., 'realpath -e')])

# Set PROG_REALPATH_M, normally "realpath -m"
AC_MSG_CHECKING([[for realpath -m (no components need exist)]])
AX_CHECK_PROGS_TEST([PROG_REALPATH_M],
  ['realpath -m --' 'readlink -m --'],
  [$try /No/Such/Filename >/dev/null 2>&1])
AC_ARG_VAR([PROG_REALPATH_M], [Command to canonicalize filename (no components need exist, e.g., 'realpath -m')])

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



AC_MSG_CHECKING([[to determine if private libc namespace should be enabled]])
AC_ARG_ENABLE([private-libc-namespace],
  [AC_HELP_STRING([--enable-private-libc-namespace],
                  [use private libc namespace wrapper (to address the unsafe env where only signal-safe functions are guaranteed to work)])],
  [AS_IF([test "x$private_libc_namespace" != "xyes"],
     [enable_private_libc_namespace="no"])],
  [AC_COMPILE_IFELSE(
    [AC_LANG_PROGRAM([[#include <dlfcn.h>]],
[
void *dl_handle = dlmopen(LM_ID_NEWLM,
 "libc.so.6",
       RTLD_NOW | RTLD_LOCAL | RTLD_DEEPBIND);
])],
    [enable_private_libc_namespace="yes"],
    [enable_private_libc_namespace="no"])])
AC_MSG_RESULT([$enable_private_libc_namespace])
AS_IF([test "x$enable_private_libc_namespace" = "xyes"],
  [AC_DEFINE([PRIVATE_LIBC_NAMESPACE], 1, [Wrap C runtime functions that are not necessarily safe from signals (per POSIX) and that are used internally by this library.])

  AC_MSG_CHECKING([[for name of private libc wrapped library]])
  AC_ARG_VAR([PRIVATE_LIBC_NAMESPACE_LIBNAME],
    [Name of library to invoke by private libc namespace wrapper])
  AS_IF([test "x$PRIVATE_LIBC_NAMESPACE_LIBNAME" = "x"],
        [PRIVATE_LIBC_NAMESPACE_LIBNAME="libc.so.6"])
  AC_DEFINE_UNQUOTED([PRIVATE_LIBC_NAMESPACE_LIBNAME],
    ["$PRIVATE_LIBC_NAMESPACE_LIBNAME"],
    [Name of library to invoke by private libc namespace wrapper])
  AC_MSG_RESULT([$PRIVATE_LIBC_NAMESPACE_LIBNAME])])

AC_ARG_ENABLE(debug,
  AC_HELP_STRING([--enable-debug], [compile with debug support]),
  CFLAGS="$CFLAGS -ggdb3")

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
