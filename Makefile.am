# Makefile.am for user-union

ACLOCAL_AMFLAGS = -I m4 --install

my_library_la_name = libuser-union-0.12.la
lib_LTLIBRARIES = $(my_library_la_name)
libuser_union_0_12_la_SOURCES = user-union.c
# Cygwin and others require this option to build shared libraries:
libuser_union_0_12_la_LDFLAGS = -no-undefined

# Only include if using library "dl".
# We're using new automake, so use _LIBADD, not _LDADD.
if BUILD_WITH_LIBDL
libuser_union_0_12_la_LIBADD = -ldl
endif

dist_bin_SCRIPTS = run-redir-union user-union
CLEANFILES = user-union
EXTRA_DIST = user-union.txt m4/NOTES fso_stat

# We build user-union in the makefile, instead of having a "user-union.in"
# read by configure, so that "make build" can override prefix, libdir, etc.
user-union: user-union.txt $(my_library_la_name)
	rm -f user-union
	$(SED) -e 's!# YOU MAY EDIT.*!# DO NOT EDIT - GENERATED FILE!' \
          -e 's!^\(my_library_la_name\)=\(.*\)!\1="$(my_library_la_name)"!' \
          -e 's!^\(libdir\)=.*!\1="$(libdir)"!' \
          < $(srcdir)/user-union.txt > user-union
	chmod a-w user-union
	chmod a+rx user-union

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


