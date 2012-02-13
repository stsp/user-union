#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.68])
AC_INIT([user-union], [0.12], [dwheeler@dwheeler.com],
        [user-union], [http://www.dwheeler.com/user-union])
AC_CONFIG_SRCDIR([user-union.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])

# Bring in automake and libtool.
AM_INIT_AUTOMAKE([-Wall -Werror])
# Disable static, since they're pointless in our case, and try to make
# relocatable so that it can override anything:
LT_INIT([disable-static pic-only])

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MKDIR_P

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

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
