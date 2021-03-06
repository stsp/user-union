# Makefile.am for user-union

ACLOCAL_AMFLAGS = -I m4 --install

AM_CFLAGS = $(CWARNINGFLAGS)

my_library_la_name = libuser-union-0.12.la
lib_LTLIBRARIES = $(my_library_la_name)
libuser_union_0_12_la_SOURCES = user-union.c init.c
# Cygwin and others require this option to build shared libraries:
libuser_union_0_12_la_LDFLAGS = -no-undefined

# Only include if using library "dl".
# We're using new automake, so use _LIBADD, not _LDADD.
if BUILD_WITH_LIBDL
libuser_union_0_12_la_LIBADD = -ldl
endif

dist_bin_SCRIPTS = run-redir-union user-union
CLEANFILES = user-union
EXTRA_DIST = user-union.txt fso_stat m4/NOTES m4/ax_check_progs_test.m4

# We build user-union in the makefile, instead of having a "user-union.in"
# read by configure, so that "make build" can override prefix, libdir, etc.
# We reuse the @varname@ replacement convention for consistency.
user-union: user-union.txt $(my_library_la_name)
	rm -f user-union
	$(SED) -e 's!# YOU MAY EDIT.*!# DO NOT EDIT - GENERATED FILE!' \
          -e 's!@my_library_la_name[@]!$(my_library_la_name)!g' \
          -e 's!@libdir[@]!$(libdir)!g' \
          -e 's!@PROG_REALPATH[@]!$(PROG_REALPATH)!g' \
          -e 's!@PROG_REALPATH_E[@]!$(PROG_REALPATH_E)!g' \
          -e 's!@PROG_REALPATH_M[@]!$(PROG_REALPATH_M)!g' \
          < $(srcdir)/user-union.txt > user-union
	chmod a+rx user-union

# Ensure that libtool is rebuilt if it needs to be
libtool: $(LIBTOOL_DEPS)
	$(SHELL) ./config.status libtool

dist_check_SCRIPTS = runtest testscript quicktest
dist_check_DATA = expected_results
CLEANFILES += overlay_results user-union
# "CLEANFILES" can't rm directories, so use this hack to work around it:
clean-local: clean-local-check
.PHONY: clean-local-check
clean-local-check:
	-rm -rf overlay/
# Can't set TESTS= because "runtest" needs an argument.

# Remember: In commands, prefix source files with "$(srcdir)" for VPATH builds
check: all
	"$(srcdir)/runtest" "$(srcdir)"

# Convenience function
test: check

accept:
	test -f overlay_results || exit 1
	@echo "Test results accepted"
	cp -p overlay_results $(srcdir)/expected_results

dist_man_MANS = run-redir-union.1  user-union.1

# Convenience target.  We don't require this for distribution,
# so these tools aren't required to create a distribution.
# FIXME: use .s1.s2 and .SUFFIXES
my-pdf: user-union.pdf run-redir-union.pdf

user-union.pdf: ./user-union.1
	man -t ./user-union.1 | ps2pdf - user-union.pdf

run-redir-union.pdf: ./run-redir-union.1
	man -t ./run-redir-union.1 | ps2pdf - run-redir-union.pdf

# TODO:
# - script needs to load library (.so) - currently quicktest hacks this in.
# - Do something other than am__tar override (might fail in future automakes)
# - Support values other than LD_PRELOAD, e.g., DYLD_INSERT_LIBRARIES
#    http://www.fortran-2000.com/ArnaudRecipes/sharedlib.html

# Don't need to install header files, we're overriding existing functions.

# For now, no version numbers like this:
# libsomething_1_0_la_LDFLAGS = -version-info $(EXAMPLE_LIBRARY_VERSION)
# because it's not clear what would really mean in this context.

# No .pc.in file.


# Cygwin LD_PRELOAD not working, and docs say it WILL work
#   (though may require : as separator)
# http://cygwin.com/cygwin-ug-net/dll.html
# Suggests:
# gcc -shared -o cyg${module}.dll \
#     -Wl,--out-implib=lib${module}.dll.a \
#     -Wl,--export-all-symbols \
#     -Wl,--enable-auto-import \
#     -Wl,--whole-archive ${old_libs} \
#     -Wl,--no-whole-archive ${dependency_libs}
# The name of your library is ${module}, prefixed with cyg for the DLL and lib for the import library. Cygwin DLLs use the cyg prefix to differentiate them from native-Windows MinGW DLLs, see the MinGW website for more details. ${old_libs} are all your object files, bundled together in static libs or single object files and the ${dependency_libs} are import libs you need to link against, e.g '-lpng -lz -L/usr/local/special -lmyspeciallib'.


