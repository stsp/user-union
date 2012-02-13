
dist_bin_SCRIPTS = run-redir-union user-union


lib_LTLIBRARIES = libuser-union-0.12.la

libuser_union_0_12_la_SOURCES = user-union.c

ACLOCAL_AMFLAGS = -I m4 

# Only include if using library "dl".
# We're using new automake, so use _LIBADD, not _LDADD.
if BUILD_WITH_LIBDL
libuser_union_0_12_la_LIBADD = -ldl
endif

dist_check_SCRIPTS = runtest testscript quicktest

dist_check_DATA = expected

TESTS = $(check_SCRIPTS)

CLEANFILES = .overlay_results .expected_results

# $(srcdir)/runtest
check: all
	$(srcdir)/runtest "$(srcdir)"

accept:
	@echo "Test results accepted"
	"$(srcdir)/runtest" -a

dist_man_MANS = run-redir-union.1  user-union.1

# Override automake's setting for am__tar, so that symlinks in the
# "expected" directory will be captured.  Do this by removing "-h" from:
# am__tar = ${AMTAR} chof - "$$tardir"
am__tar = ${AMTAR} cof - "$$tardir"


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
