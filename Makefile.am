# Makefile.am for user-union

ACLOCAL_AMFLAGS = -I m4 

dist_bin_SCRIPTS = run-redir-union user-union

lib_LTLIBRARIES = libuser-union-0.12.la

libuser_union_0_12_la_SOURCES = user-union.c

# Only include if using library "dl".
# We're using new automake, so use _LIBADD, not _LDADD.
if BUILD_WITH_LIBDL
libuser_union_0_12_la_LIBADD = -ldl
endif

dist_check_SCRIPTS = runtest testscript quicktest

dist_check_DATA = expected_results

# Can't set TESTS= because "runtest" needs an argument.

CLEANFILES = overlay_results overlay/

# Remember: In commands, prefix source files with "$(srcdir)" for VPATH builds
check: all
	"$(srcdir)/runtest" "$(srcdir)"

accept:
	test -f overlay_results || exit 1
	@echo "Test results accepted"
	cp -p overlay_results $(srcdir)/expected_results

dist_man_MANS = run-redir-union.1  user-union.1

# TODO:
# - script needs to load library (.so) - currently quicktest hacks this in.
# - "make check" works by itself, but not in "make distcheck".
# - Fix pdf generation (for the man pages).
# - Switch to AM_MAINTAINER_MODE and explain why, implications.
# - Do something other than am__tar override (might fail in future automakes)

# Don't need to install header files, we're overriding existing functions.

# For now, no version numbers like this:
# libsomething_1_0_la_LDFLAGS = -version-info $(EXAMPLE_LIBRARY_VERSION)
# because it's not clear what would really mean in this context.

# No .pc.in file.
