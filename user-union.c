// user-union: union mount (writeable overlay) that unprivileged users can use
// Unlike many implementations, this allows *ordinary users* to
// create union mounts.  It does this by using LD_PRELOAD.
//
// Copyright (C) 2011 David A. Wheeler
// Released under the "MIT license" / X11 license
// (as posted at http://www.opensource.org/licenses/mit-license.php):
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
//
// If you have root privileges there are WAY better ways to do union mounts
// than this library.  This includes
// FUSE-based approaches and kernel-implemented union mounts.
// Implementations of such things include unionfs and aufs.
// An LD_PRELOAD mechanism *always* has serious weaknesses, e.g., it can't
// redirect setuid root programs, and there will always be calls that it
// doesn't redirect.  Also, the GNU C library normally make it
// impossible to redirect "internal" calls inside the GNU C library,
// making the "union mount" abstraction especially leaky.
// You can recompile the GNU C library to enable redirection (using
// "--disable-hidden-plt" option), but for most users, recompiling their
// C library is not a practical solution.
// Even if you had "--disable-hidden-plt", this kind of tool will always be
// a leaky abstraction. At best it's a set of heuristics that try
// to "usually work".  There will always be cases where a request
// to access something will end up being set to the underlay (or rarely,
// the overlay) when it should have been redirected, typically leading to
// failure to create or read the right file.
//
// However, if you need union mounts without privileges, this is a useful tool.
// My goal was to simplify automating DESTDIR, see:
//   http://www.dwheeler.com/essays/automating-destdir.html
//   http://www.dwheeler.com/auto-destdir/
// but many other uses are possible.
//
// Terminology and notions:
// - A union mount allows you to define a set of branch commands.
//   Each branch command can specify either a "non-union" directory
//   (which will NOT be unioned), or a a read-write ("overlay") filesystem
//   that will be over "underlay" filesystems.  The underlays are
//   treated as if they are read-only, though they might not be.
//   For now, overlays and underlays come in pairs, and there's only 1 pair.
// - It will *appear* that underlays can be written to, but
//   any changes will actually occur in the overlay(s).
// - Anything in "overlay" overrides the contents of the underlays.
//   Note: there is a "whitelist" area in the overlay, which records which
//   contents in the underlay that are "removed".
// - A "unioned region" is NOT inside any "non-union directory"
//   *and* is inside an "overlay" or an "underlay".
//   Where this definition conflicts, the longest match wins, so
//   if "/tmp/f" is an overlay of "/", and "/tmp" is non-union, then
//   /tmp/f/bin is a union region (it's the overlay name for underlay /bin).
// - A filesystem object in a unioned region has two names:
//   its "underlay name" is its original undirected name,
//   and its "overlay name" is its redirected name inside the overlay.
//   We redirect names inside EITHER the
//   overlay directory *or* an underlay directory; if both would match,
//   use the longer match.   Thus, if the underlay "/" is overlaid with
//   "/tmp/f/", and the current directory is "/tmp/f", an attempt to open
//   for reading "bin/sh" or "/bin/sh" would see if there is
//   a "/tmp/f/bin/sh" in the underlying system; if not, it will try
//   "/bin/sh" in the underlying system.
//   If you have more than a pair (future), then the
//   overlay name is converted to the LAST underlay name; that leaks some
//   info, so more than a pair doesn't work as gracefully.
//   We have to permit the current directory to be in an overlay;
//   that way, the user can "mkdir()" a new directory without changing
//   the underlay.  My expectation is that the
//   "current directory" is normally in an underlay directory, but
//   that might change from experience.
//
// - This implementation allows a single overlay + underlay pair.
//   Future versions should allow multiple pairs.
//
// USER_UNION="{branch_command}+"
// branch_command ::= overlay ['\t' underlay]
// branch commands are separated by newlines.
// When overlay is given WITHOUT an underlay, it's a "nonunion_directory",
// i.e., a directory that is NOT redirected.
// Note that overlay, underlay, and nonunion_directory must be
// absolute pathnames to directories.
//
// Simple test using program "trivial":
//   LD_PRELOAD="$(pwd)/user-union.so" USER_UNION=$'/tmp/testy\t/' ./trivial
//
// For debugging, put some test program like above in a file Q, +x, and do:
//   strace -f -e trace=file ./Q
// or for gdb, e.g., "gdb /bin/cp" (just "set environment" will fail):
//   set exec-wrapper env 'LD_PRELOAD=/YOUR/DIRECTORY/HERE/user-union.so'
//   set args /bin/echo /dev/null
//   run
//
// TODO: A lot :-).
// TODO: Optionally simulate exacting permission checking.
//       Currently we just claim that we're root.
// TODO: Test to make it work with fakeroot.

// Need this for Apple MacOS X, to deal with weirdness in its "stat":
#define _DARWIN_NO_64_BIT_INODE

// For GNU "AT" functions like linkat(), openat():
// #define _XOPEN_SOURCE 700 || _POSIX_C_SOURCE >= 200809L
#define _XOPEN_SOURCE 700
#define _POSIX_C_SOURCE 200809L
#define _ATFILE_SOURCE 1


#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>
#include <stdarg.h>
#include <assert.h>
#include <utime.h>
#include <sys/time.h>
#include <sys/statvfs.h>
#include <sys/inotify.h>
// For opendir():
#include <dirent.h>
#include <assert.h>
#include <libgen.h>

// For dlsym
#if HAVE_DLFCN_H
#include <dlfcn.h>
#else
#include <ltdl.h>
#endif

#include "init.h"
#include "user-union.h"

#ifdef __CYGWIN__
/* https://cygwin.com/ml/cygwin/2011-01/msg00258.html
 * RTLD_NEXT appears to be semi-unimplemented in Cygwin
 * (a grep through the sources shows code for RTLD_NEXT in newlib but not
 * in winsup).
 *
 * We define it by hands and use only for the functions defined in newlib,
 * so it works for us pretty well. */
#ifndef RTLD_NEXT
#define RTLD_NEXT ((void *) -1L)
#endif
#endif

enum RedirRet { REDIR, NOREDIR, FAILREDIR };

struct redir_ret {
  enum RedirRet ret;
  char *new_name;
};

// Coding style for C used here, to make it easier to read (in my opinion):
// - Bracing is K&R (One True Brace Style), *even* for function headings.
// - 2-space indents.
// - Comments use "//"; everyone important supports it now.

// A lot of stuff here is marked "static" to make it more private.
// We're doing a lot of subterfugue, so symbol visibility needs to be
// reduced to *only* the symbols we are intentionally overriding.

int debug_level = 0;

#if defined(__linux__)
#include <sys/sendfile.h>
#define USE_SENDFILE 1
// Special stuff to handle GNU C library.
// Technically, that's not the same as __linux__.

// GNU C library doesn't normally let us redirect its internal
// calls to open(), etc., so we have to wrap functions like fopen() ourselves:
#define WRAP_USERS 1
#endif

#ifdef PRIVATE_LIBC_NAMESPACE
static void *dl_handle;

static void __attribute__((constructor)) initialize(void)
{
  // PRIVATE_LIBC_NAMESPACE_LIBNAME is typically "libc.so.6"
  dl_handle = dlmopen(LM_ID_NEWLM, PRIVATE_LIBC_NAMESPACE_LIBNAME,
      RTLD_NOW | RTLD_LOCAL | RTLD_DEEPBIND);
}

static void __attribute__((destructor)) finalize(void)
{
  if (dl_handle) {
    dlclose(dl_handle);
    dl_handle = NULL;
  }
}

/* below we wrap the functions that are not specified by POSIX to be
 * signal-safe. This allows us to use them even if we hooked some
 * call that goes from inside the C library. This is necessary to
 * avoid the recursion inside calls that use mutex, and even without
 * any recursion, calling such functions is unsafe because this can
 * happen after fork() (inside system() or popen() calls), and after
 * fork() all the thread-shared resources inside libc are in an
 * inconsistent state (most importantly, the mutexes itself).
 * This is most prominent on uClibc that does not care to use the
 * private, unhookable definitions in the critical places the way
 * glibc does. Unfortunately, these wrappers do not work on uClibc
 * yet, so for uClibc we also disable the exec* wrappers. */

#define __C_WRP(RTYPE, SYM, DEF_ARGS, ORIG_CODE, NEW_CODE) \
static RTYPE wrp_##SYM DEF_ARGS \
{ \
  static RTYPE (*orig_##SYM) DEF_ARGS; \
  static RTYPE (*new_##SYM) DEF_ARGS; \
  if (!orig_##SYM) \
    orig_##SYM = dlsym(RTLD_NEXT, __STRING(SYM)); \
  if (!orig_##SYM) { \
    fprintf(stderr, "FAIL, cannot resolve symbol " __STRING(SYM) "\n"); \
    _exit(1); \
  } \
  if (dl_handle && !new_##SYM) \
    new_##SYM = dlsym(dl_handle, __STRING(SYM)); \
  if (!new_##SYM || !dl_handle) \
    ORIG_CODE; \
  NEW_CODE; \
}

#define C_WRP(RTYPE, SYM, DEF_ARGS, CALL_ARGS) \
__C_WRP(RTYPE, SYM, DEF_ARGS, return orig_##SYM CALL_ARGS, \
    return new_##SYM CALL_ARGS) \
inline __attribute__((visibility("hidden"))) RTYPE SYM DEF_ARGS \
{ \
  return wrp_##SYM CALL_ARGS; \
}

/* malloc() and free() are protected with mutex. They are first-class
 * offenders. */
C_WRP(void *, malloc, (size_t size), (size))
C_WRP(void, free, (void *ptr), (ptr))
/* strdup() uses malloc() */
#undef strdup
C_WRP(char *, strdup, (const char *s), (s))

/* exit() can call atexit() callbacks */
#define exit _exit

/* the following are using the static buffer */
C_WRP(char *, dirname, (char *path), (path))
C_WRP(char *, strerror, (int num), (num))

/* the following are not making problems, but are not listed as
 * signal-safe by posix, either. So better wrap them too. */
C_WRP(char *, getcwd, (char *buf, size_t size), (buf, size))
C_WRP(void *, memcpy, (void *dest, const void *src, size_t n), (dest, src, n))
C_WRP(void *, memmove, (void *dest, const void *src, size_t n), (dest, src, n))
#undef strchr
C_WRP(char *, strchr, (const char *s, int c), (s, c))
#undef strcmp
C_WRP(int, strcmp, (const char *s1, const char *s2), (s1, s2))
#undef strcpy
C_WRP(char *, strcpy, (char *s1, const char *s2), (s1, s2))
C_WRP(size_t, strlen, (const char *s), (s))
#undef strncmp
C_WRP(int, strncmp, (const char *s1, const char *s2, size_t n), (s1, s2, n))
C_WRP(char *, strncpy, (char *s1, const char *s2, size_t n), (s1, s2, n))
C_WRP(char *, strrchr, (const char *s, int c), (s, c))

/* fprintf() and other stdio functions are protected with mutex too, and
 * so they are the first-class offenders. But we use it only for debug
 * output, so wrap only stderr for now. */
C_WRP(size_t, fwrite, (const void *ptr, size_t size, size_t nmemb,
                     FILE *stream), (ptr, size, nmemb, stream))

static FILE **my_stderr;
static int (*orig_fprintf)(FILE *stream, const char *format, ...);
__C_WRP(int, vfprintf, (FILE *stream, const char *format, va_list ap),
    return orig_vfprintf(stream, format, ap), do {
  if (stream != stderr) {
    orig_fprintf(stderr, "FAIL, unsupported fprintf, please report bug\n");
    exit(1);
  }
  if (!my_stderr)
    my_stderr = dlsym(dl_handle, "stderr");
  if (!my_stderr) {
    orig_fprintf(stderr, "FAIL, stderr does not resolve\n");
    exit(1);
  }
  return new_vfprintf(*my_stderr, format, ap);
} while (0))

inline __attribute__((visibility("hidden")))
	int fprintf(FILE *stream, const char *format, ...)
{
  int ret;
  va_list ap;
  if (!orig_fprintf)
    orig_fprintf = dlsym(RTLD_NEXT, "fprintf");
  if (!orig_fprintf)
    abort();
  va_start(ap, format);
  ret = wrp_vfprintf(stream, format, ap);
  va_end(ap);
  return ret;
}
#endif

// Use this to mark intentionally-unused variables.
#define unused_okay(VAR) (void) VAR

// Sometimes it's easier to just create a big char buffer and use it.
// When we do, here's the size we use.
// TODO: Examine all uses, eliminate them or at least check for overflow.
#define BIGBUF (64*1024)

// Misc. utility definitions:
#define streq(s1,s2)    (strcmp(s1,s2) == 0)
#define strneq(s1,s2,n) (strncmp(s1,s2,n) == 0)

// Return a heap-allocated string s1+s2.  Doesn't change s1 or s2.
// Watch out for "s1=concat(s1,s2)" if s1 is allocated; if there's not
// another pointer to s1, you won't be able to free s1 later.
static char *concat(const char *s1, const char *s2) {
  size_t strlen_s1 = strlen(s1);
  char *new = malloc(strlen_s1+strlen(s2)+1);
  strcpy(new,s1);
  strcpy(new+strlen_s1,s2);
  return new;
}

// Concatenate a filename, s1+s2, and return a newly-allocated string of it.
// Watch out for "s1=concat(s1,s2)" if s1 is allocated; if there's not
// another pointer to s1, you won't be able to free s1 later.
static char *concat_dir(const char *s1, const char *s2) {
  size_t strlen_s1 = strlen(s1);
  char *new = malloc(strlen_s1+strlen(s2)+1);
  debug("concat_dir(%s,%s)", s1, s2);
  strcpy(new,s1);
  if ((strlen_s1 > 0) && (s1[strlen_s1-1] ==  '/') && (s2[0] == '/'))
    s2++;
  strcpy(new+strlen_s1,s2);
  debug("->%s\n", new);
  return new;
}


// Returns true if s begins with "prefix", else returns false.
// If "s" is a directory, you should probably use "within" instead.
inline static bool begins_with(const char *s, const char *prefix) {
  return strncmp(s, prefix, strlen(prefix)) == 0;
}

// Returns true if path is within directory dir, else false.
// E.G., "/usr/bin" is within "/" and "/usr" and "/usr/bin".
// Presumes "path" and "dir" are absolute (not relative).
// This is *not* the same as begins_with!
inline static bool within(const char *path, const char *dir) {
  int dir_len = strlen(dir);
  if (!path || !dir) return false;
  if ((dir_len == 1) && (dir[0] == '/') && (path[0] == '/'))
    return true;
  // Strip away trailing "/" in dir, but not the first '/':
  while ((dir_len > 1) && (dir[dir_len-1] == '/'))
    dir_len--;
  if ((strneq(path, dir, dir_len)) &&
      ((path[dir_len] == '\0') || (path[dir_len] == '/')))
    return true;
  return false;
}

static bool within_max(const char *path, const char *dir, int depth)
{
  const char *p;
  int cnt;
  if (!within(path, dir))
    return false;
  if (depth == -1)
    return true;
  p = path + strlen(dir);
  while (*p == '/')
    p++;
  cnt = 0;
  while (p && *p) {
    p = strchr(p, '/');
    cnt++;
    if (p) {
      while (*p == '/')
        p++;
    }
  }
  return (cnt <= depth);
}

inline static int skip(const char *path) {
  int len = strlen(path);
  if (path && (path[0] == '/') && (path[1] == '\0'))
    len--;
  return len;
}

// The type usage_t indicates how the filesystem object is being used.
typedef enum usage {
  READ,  // Filesystem object will *only* be read
  PREFER_UNDERLAY,  // Prefer the underlay name. For chdir.
  WRITE,  // Filesystem object may be changed (might be read, too)
  EXCLUSIVE,  // O_EXCL creation
  READLINK,  // readlink() emulation
  OPENDIR, // Got the parameter for opendir().
  EXIST, // Like WRITE, but if file exists in underlay, touch overlay
         // ("WRITE" would copy a whole file, which is pointless if we're
         // about to delete it)
  SKIP_UNSLASHED, // Don't redirect if contains "/", else READ
                  // Needed for exec, dlopen, etc.
  UNWHITELIST, // Remove a whitelist entry for the (maybe overlay) pathname
  WHITELIST, // Create a whitelist entry for this (overlay) pathname
  // NOTE: WHITELIST must be last one so we can check enum length.
} usage_t;

#ifdef WRAP_USERS
// Convert fopen() flags to usage flags
static usage_t use_fopen(const char *mode) {
  if (strstr(mode, "x")) // Support new 'x' flag; means O_EXCL.
    return EXCLUSIVE;
  else if (begins_with(mode, "r+") || begins_with(mode, "rb+"))
    return WRITE;
  else if (begins_with(mode, "r") || begins_with(mode, "rb"))
    return READ;
  else
    return WRITE;
}
#endif

// Standards don't define how to take open() flags and determine if it's
// read-only.  The following probably works everywhere, though:
#define FLAG_READONLY(flag) (((flag) & (O_RDONLY|O_WRONLY|O_RDWR)) == O_RDONLY)

// Convert open() flags to usage flags
static usage_t use_open(int flags) {
  if (flags & O_CREAT) {
    if (flags & O_EXCL)
      return EXCLUSIVE;
    return WRITE;
  }
  if (FLAG_READONLY(flags))
    return READ;
  return WRITE;
}

// The redir_name "use" parameter is an "or" of usage_t and possibly
// information about the "at" file descriptor; this lets us handle
// that *at() functions more accurately.

#define USAGE_T_BITS 4
#if (1 << (USAGE_T_BITS - 1)) <= WHITELIST
#error "enum_t does not have enough bits.  Increase USAGE_T_BITS"
#endif
#define USAGE_T_MASK  ((1 << (USAGE_T_BITS)) - 1)
#define GET_AT_FD ((1 << (USAGE_T_BITS)) - 1)

// We need a separate flag to tell us if the "AT" values have been set,
// because a file descriptor can be 0.
#define IS_AT_FLAG (1 << USAGE_T_BITS)
#define AT_FD_SHIFT ((USAGE_T_BITS) + 1)
#define GET_FD(x)  (( (x) & ~USAGE_T_MASK) >> AT_FD_SHIFT)
#define AT(fd)  ((IS_AT_FLAG) |  ((fd) << (AT_FD_SHIFT)))

// Implement the "override_prefix" (the prefix to filenames that says
// "we've already intercepted this once, don't change it any more").
//
// Rationale:
// We intercept many functions and then call down to the C library.
// It's possible that when the C library implements those functions,
// it could call other functions that we *also* intercept.
// For example, we may override fopen(), but when we call down to the
// C library fopen(), it will invoke open() which might end up
// intercepting as well.  Whether or not this happens depends on a
// wide variety of factors.
//
// In many cases this won't matter, because in many cases it'll produce
// the same results.  But in some cases this matters; opendir() might
// get very confused, for example.  What's worse, it could produce
// hard-to-debug results that vary between systems depending on
// very low-level implementation details.
//
// A solution is an "override_prefix" that is prepended to redirected
// filenames in most cases.  A filename within the override_prefix
// is NOT redirected again.
// You DON'T want this if some other LD_PRELOAD program is ALSO
// prefixing filenames.

// The prefix - it must be *unlikely* to be used in real programs,
// but when prepended will refer to the same location:
static char override_prefix[] = "/./.././.";

static bool use_override_prefix = true;

// Add prefix, if needed.
// This may free s and return a newly-allocated s if required.
static inline char *prepend_override_prefix(char *s) {
  char *new_result;
  if (!s || (s[0] != '/')) {
    fprintf(stderr, "prepend_prefix - %s doesn't start with /\n", s);
    exit(1);
  }
  if (use_override_prefix && !within(s, override_prefix)) {
     new_result = concat_dir(override_prefix, s);
     free(s);
    return new_result;
  } else
    return s;
}


static struct branch *branchlist;
static int num_branches;

static char whitelist_prefix[BIGBUF];

static void __attribute__((constructor)) initialize_branchlist(void)
{
  branchlist = create_branchlist(whitelist_prefix, sizeof(whitelist_prefix),
    &num_branches);
  if (!branchlist)
    exit(1);
}

// We will need to use internally some redirected functions, so that
// we can directly manipulate the filesystem.  We declare them here,
// so that the compiler will complain if we have it wrong, but will
// define them later once we have the other functions defined that they need.

static int my_open64(const char *path, int flags, mode_t mode);
static int my_mkdir(const char *pathname, mode_t mode);
static int my_unlink(const char *path);
static int my_lstat(const char *path, struct stat *buf);
static ssize_t my_readlink(const char *path, char *buf, size_t bufsiz);
static int my_symlink(const char *oldpath, const char *newpath);
static int my_rename(const char *oldpath, const char *newpath);
#if 0
static DIR *my_opendir(const char *name);
#endif
// static int my_stat(const char *path, struct stat *buf);



// TODO: Error handling.
static int my_file_copy(const char *old, const char *new, mode_t mode) {
#ifdef USE_SENDFILE
  struct stat s;
#else
  char buffer[1024*512];
  int bytes_read, bytes_written;
#endif
  char *tmpname;
  const char *suff = ".$#@";
  int oldfd, newfd, err = 0;
  int bytes_total;
  oldfd = my_open64(old, O_RDONLY, 0);
  if (oldfd == -1) {
    fprintf(stderr, "FAIL. unable to open %s\n", old);
    return -1;
  }
  // TODO: POSSIBLE SECURITY ISSUE: This creates a predictable filename.
  // If an attacker can manipulate the directory, an attacker could
  // cause this file creation effort to fail.  We'll use O_EXCL
  // to at least prevent an attacker from pre-creating the file and thus
  // controlling its contents.
  tmpname = malloc(strlen(new) + strlen(suff) + 1);
  strcpy(tmpname, new);
  strcat(tmpname, suff);
  my_unlink(tmpname);
  newfd = my_open64(tmpname, O_WRONLY|O_CREAT|O_EXCL|O_TRUNC, mode);
  if (newfd == -1) {
    fprintf(stderr, "FAIL. unable to open %s\n", tmpname);
    err = -1;
    goto done2;
  }
  bytes_total = 0;
#ifdef USE_SENDFILE
  err = fstat(oldfd, &s);
  if (!err) {
    bytes_total = sendfile(newfd, oldfd, NULL, s.st_size);
    if (bytes_total != s.st_size) {
      fprintf(stderr, "FAIL. cannot copy %s to %s\n", old, new);
      err = -1;
    }
  }
#else
  while ( (bytes_read = read(oldfd, buffer, sizeof(buffer))) > 0) {
    bytes_written = write(newfd, buffer, bytes_read);
    if (bytes_read != bytes_written) {
      fprintf(stderr, "FAIL. cannot copy %s to %s\n", old, new);
      err = -1;
      break;
    }
    bytes_total += bytes_written;
  }
#endif
  close(newfd);
  my_rename(tmpname, new);
done2:
  free(tmpname);
  close(oldfd);
  return err;
}

static bool my_file_exists(const char *pathname) {
  struct stat mystats;
  bool result = my_lstat(pathname, &mystats) != -1;
  debug("my_file_exists(\"%s\")=%d\n", pathname, result);
  // If we can lstat it at all, it exists.  Note that this really only
  // checks if the *symlink* exists, not what it points to.
  return result;
}

static bool my_is_directory(const char *pathname) {
  struct stat mystats;
  int result = my_lstat(pathname, &mystats);
  if (result == -1)
    return false;
  return S_ISDIR(mystats.st_mode);
}

static void make_parents_of(const char *pathname) {
  if(!pathname || !pathname[0]) return;
  int saved_errno = errno;
  char buf[strlen(pathname)+1];
  char *p = buf;
  int done = 0;

  buf[0] = '\0';

  while(!done) {
    do {
      *(p++) = *(pathname++);
      done = done || !*pathname;
    } while(!done && *pathname != '/');

    if (!done) {
      *p = '\0';
      int ret = my_mkdir(buf, 0755) != 0;
      if (ret == -1) {
        debug("can't create parent directory %s\n", buf);
      } else {
        debug("created parent directory %s\n", buf);
      }
    }
  }
  errno = saved_errno;
}


// Make the parents of overlay, but only if the equivalent directories
// exist in underlay
static void make_parents(const char *overlay, const char *underlay, const char *overlay_prefix, const char *underlay_prefix) {
  char *p; // Pointer to inside overlay_buffer
  char *q; // Pointer to inside underlay_buffer
  int saved_errno = errno;
  bool done = false;
  size_t overlay_prefix_len = strlen(overlay_prefix);
  size_t underlay_prefix_len = strlen(underlay_prefix);
  char overlay_buffer[strlen(overlay)+1];
  char underlay_buffer[strlen(underlay)+1];

  if (!overlay || !overlay[0]) return;

  assert(strlen(overlay_prefix) <= strlen(overlay));
  assert(strlen(underlay_prefix) <= strlen(underlay));

  strcpy(overlay_buffer, overlay);
  strcpy(underlay_buffer, underlay);

  p = overlay_buffer + overlay_prefix_len;
  q = underlay_buffer + underlay_prefix_len;
  overlay += overlay_prefix_len;
  underlay += underlay_prefix_len;

  while(!done) {
    do {
      *(p++) = *(overlay++);
      *(q++) = *(underlay++);
      done = done || !*overlay || !*underlay;
    } while(!done && *overlay != '/');

    if (!done) {
      int ret;
      *p = '\0';
      *q = '\0';
      if (!my_is_directory(underlay_buffer)) {
        return;
      }
      ret = my_mkdir(overlay_buffer, 0755);
      if (ret == -1) {
        debug("can't create parent directory %s\n", overlay_buffer);
      } else {
        debug("created parent directory %s\n", overlay_buffer);
      }
    }
  }
  errno = saved_errno;
}

static int subpath_len(const char *path)
{
  char *p = strdup(path);
  char *end;
  int len = 0;
  while (*p) {
    if (my_file_exists(p)) {
      len = strlen(p);
      if (len == 1) {	// skip single /
        assert(p[0] == '/');
        len = 0;
      }
      break;
    }
    end = strrchr(p, '/');
    if (!end)
      break;
    *end = 0;
  }
  free(p);
  return len;
}

/* Retrieve st_mode of given file.  You can then use
 * S_ISREG(m) (is regular file), S_ISDIR(m) (is directory), etc.
 */
static mode_t my_file_lstat_mode(char *pathname) {
  struct stat mystats;
  my_lstat(pathname, &mystats);
  return mystats.st_mode;
}


// Whitelist storage.  We put all the whitelist entries in one place
// so they don't pollute the namespace.
// One interesting problem is that someone can do
//   rm DIRNAME ; touch DIRNAME
// so we add a highly-unlikely suffix so we can differentiate between
// "this is deleted" and "this is a subdirectory containing deleted things".
static char whitelist_suffix[] = ".*9%$7";

// Generate whitelist name, return it malloc'ed (caller must free)
// Name must be absolute without the overlay prefix.
static char *gen_whitelist_name(const char *name) {
  char *final = concat_dir(whitelist_prefix, name);
  debug("gen_whitelist_name(\"%s\")->%s\n", name, final);
  return final;
}


// Take pathname and return a pointer to a redirected pathname.
// The returned pointer (if not null) must be free()d by caller.
// If it's not to be redirected, return NULL.

static struct redir_ret __redir_name(const char *pathname, int use)
{
  struct redir_ret ret = { .ret = REDIR, .new_name = NULL };
  char *canonicalized_pathname;
  int  len, best_match_len, best_depth_len;
  int  i, j;
  int exist_creat;
  char *overlay_prefix, *underlay_prefix, *mount_point;
  char *overlay_name;   // Will be allocated.
  char *underlay_name;  // Will be allocated.
  struct branch *branch;
  bool is_whitelisted;
  char *whitelist_name;
  char *whitelist_name_full;
#if 0
  bool is_at = false;
  int  at_fd;
#endif

  debug("redir_name begin: path=%s usage=%d\n", pathname, use);

  // Extract the primary use.  The "use" parameter is int,
  // not type "usage_t", because "use" is an OR'ed value that
  // combines both usage_t and the file descriptor to be used
  // in an "at" function.  We'll change "use" so it's just the primary use,
  // and set "is_at" and "at_fd" as appropriate.
  if (use & IS_AT_FLAG) {
#if 0
    is_at = true;
    at_fd = GET_FD(use);
#endif
    use &= USAGE_T_MASK;
  }
  // If use is "SKIP_UNSLASHED", and there's no slash in the pathname,
  // don't bother to do lots of calculations.  We'll just use what we got.
  if (use == SKIP_UNSLASHED) {
    if (!strchr(pathname, '/'))
      return ret;
    else
      use = READ;
  }

  // Canonicalize pathname - force it to absolute (not relative) name.
  // TODO: If we're given relative name, *AND* we have an *at function,
  // we should use the *at function's file descriptor as the starting point.
  // Use "is_at" and "at_fd".
  i = 0;
  while (pathname[i] == '/')
    i++;
  if (i > 0) {
    canonicalized_pathname = strdup(pathname + i - 1);
  } else {
    char current_directory[BIGBUF];
    int len;
    // FIXME - if error or overflow!:
    getcwd(current_directory, sizeof(current_directory));
    len = strlen(current_directory);
    if (len > 1)
      strcat(current_directory, "/");
    canonicalized_pathname = concat_dir(current_directory, pathname);
    debug("redir_name, relative pathname became %s\n", canonicalized_pathname);
  }

  // TODO: Remove unnecessary ".." and ".", e.g., "/.." becomes "/".
  // Sortof like "realpath", but it's probably best if we do NOT
  // try to handle symbolic links (since that requires a lot of queries
  // to the underlying system that might cause their own problems).

  // Now examine branch information to find best match.
  // Track best match using best_match_len (longest one wins),
  // setting overlay_prefix as needed.
  overlay_prefix = underlay_prefix = mount_point = NULL;
  best_match_len = -1;
  best_depth_len = -1;
  branch = NULL;
  // debug("Looking for best match to %s\n", canonicalized_pathname);
  for (i = 0; i < num_branches; i++) {
    struct branch *br = &branchlist[i];
    int depth_cmp = (br->match_depth != -1 || best_depth_len != -1);
    debug("Comparing with branch %s\n", br->mount_point);
    if (!within_max(canonicalized_pathname, br->mount_point, br->match_depth))
      continue;
    len = strlen(br->mount_point);
    debug(" len=%d, best_match_len=%d best_depth_len=%d\n",
        len, best_match_len, best_depth_len);
    if ((depth_cmp && best_depth_len != -1 && br->match_depth >= best_depth_len) ||
        (!depth_cmp && len <= best_match_len))
      continue;
    // This is better than any previous match, accept it.
    overlay_prefix = br->overlay;
    mount_point = br->mount_point;
    best_match_len = len;
    best_depth_len = br->match_depth;
    branch = br;
    // debug(" Best so far.  overlay_prefix=%s, underlay_prefix=%s\n", overlay_prefix, underlay_prefix);
  }
  if (!branch)
    return ret;

  if (branch->underlay) {
      int best_match_len_undl = -1;
      // debug(" Examining union beginning %s\n", branch->list->val);
      for (j = 0; j < branch->num_underlays; j++) {
        char *tmp_name;
        int len_undl, len_pref;
        len_pref = strlen(branch->underlay[j]);
        // debug("  Examining branch %s\n", mystringlist->val);
        tmp_name = concat_dir(branch->underlay[j],
                     canonicalized_pathname + skip(mount_point));
        len_undl = subpath_len(tmp_name);
        if (len_undl >= len_pref)
          len_undl -= len_pref;
        else
          len_undl = 0;
        free(tmp_name);
        if (len_undl >= best_match_len_undl) {
          underlay_prefix = branch->underlay[j];
          best_match_len_undl = len_undl;
          break;
        }
      }
      if (!underlay_prefix)
        underlay_prefix = branch->underlay[0];
      // debug(" Setting underlay_prefix=%s\n", underlay_prefix);
  } else if (branch->overlay) { // Non-union
      // debug(" Examining non-union %s\n", branch->list->val);
      underlay_prefix = overlay_prefix;
  } else { // exclude branch
      return ret;
  }
  debug("redir_name: For canonicalized_pathname=%s, overlay_prefix=%s, underlay_prefix=%s\n", canonicalized_pathname, overlay_prefix, underlay_prefix);

  // TODO: Don't allocate canonicalized_pathname if we don't have to;
  // then, free it only if it got allocated.
  // That way we can speed absolute filenames that aren't redirected.

  if (best_match_len == -1) {
    free(canonicalized_pathname);
    debug("redir_name returning NULL undirected %s\n", pathname);
    return ret; // Don't redirect.
  }

  // Whitelist handling.
  whitelist_name = gen_whitelist_name(
                     canonicalized_pathname + skip(mount_point));
  whitelist_name_full = malloc(strlen(whitelist_name) + strlen(whitelist_suffix) + 1);
  whitelist_name_full = concat(whitelist_name, whitelist_suffix);
  // Determine if the file is whitelisted (marked as "deleted from underlay").
  // Invariant: If the file is whitelisted, it is *NOT* present in the
  // overlay. Thus, whitelisted files should be redirected to
  // the *overlay*, so that the wrapped functions will correctly report that
  // they don't exist.
  is_whitelisted = my_file_exists(whitelist_name_full);

  underlay_name = concat_dir(underlay_prefix,
                     canonicalized_pathname + skip(mount_point));
  exist_creat = 0;
  if (overlay_prefix && use == EXIST) {
    overlay_name = concat_dir(overlay_prefix,
                     canonicalized_pathname + skip(mount_point));
    if (!my_file_exists(overlay_name))
      exist_creat = 1;		// will create file
    free(overlay_name);
  }
  if (overlay_prefix && !exist_creat) {
    overlay_name = concat_dir(overlay_prefix,
                     canonicalized_pathname + skip(mount_point));
  } else if (is_whitelisted || exist_creat) {
    overlay_prefix = whitelist_prefix;
    overlay_name = strdup(whitelist_name);
  } else {
    overlay_name = NULL;
  }
  free(canonicalized_pathname);

  // If we are supposed to whitelist the pathname, let's do so.
  if (use == WHITELIST ) {
    // Create a whitelist entry for the overlay pathname
    int result;
    if (overlay_name && my_file_exists(overlay_name)) {
      fprintf(stderr, "FAIL. Whitelisting %s but file %s exists!\n", whitelist_name, overlay_name);
    }
    // Only create a whitelist entry if it exists in the underlay.
    if (my_file_exists(underlay_name)) {
      make_parents_of(whitelist_name_full);
      result = my_open64(whitelist_name_full, O_RDWR | O_CREAT, 0777);
      if (result >= 0) close(result);
    }
    free(whitelist_name);
    free(whitelist_name_full);
    free(overlay_name);
    free(underlay_name);
    return ret;
  } else if (use == UNWHITELIST ) {
    if (my_file_exists(whitelist_name_full)) {
      my_unlink(whitelist_name_full);
    }
    free(whitelist_name);
    free(whitelist_name_full);
    free(overlay_name);
    free(underlay_name);
    return ret;
  }
  free(whitelist_name);
  free(whitelist_name_full);

  debug("redir_name.  Overlay=%s  Underlay=%s\n", overlay_name, underlay_name);

  if (use == READ) { // Read-only filesystem object (simple override)
    if (overlay_name && (is_whitelisted || my_file_exists(overlay_name))) {
      free(underlay_name);
      debug("redir_name 11 returning overlay name %s\n", overlay_name);
      ret.new_name = prepend_override_prefix(overlay_name);
      return ret;
    } else {
      free(overlay_name);
      debug("redir_name 12 returning underlay name %s\n", underlay_name);
      ret.new_name = prepend_override_prefix(underlay_name);
      return ret;
    }
  } else if (use == PREFER_UNDERLAY) { // Like READ but use underlay if exists.
    if (!overlay_name || (!is_whitelisted && my_file_exists(underlay_name))) {
      free(overlay_name);
      debug("redir_name 12 returning underlay name %s\n", underlay_name);
      ret.new_name = prepend_override_prefix(underlay_name);
      return ret;
    } else {
      free(underlay_name);
      debug("redir_name 11 returning overlay name %s\n", overlay_name);
      ret.new_name = prepend_override_prefix(overlay_name);
      return ret;
    }
  } else if (use == EXCLUSIVE) { // Exclusively-create filesystem object:
    debug("O_EXCL!\n");
    if (overlay_name && my_file_exists(overlay_name)) {
      // It exists in overlay. Return the overlay name, it'll fail.
      debug("Overlay already exists!\n");
      free(underlay_name);
      debug("redir_name 21 returning underlay name %s\n", overlay_name);
      ret.new_name = prepend_override_prefix(overlay_name);
      return ret;
    } else if (!overlay_name) {
      free(underlay_name);
      ret.ret = FAILREDIR;
      return ret;
    } else if (!is_whitelisted && my_file_exists(underlay_name)) {
      // It exists in underlay. Return the underlay name, it'll fail.
      debug("Underlay already exists!\n");
      free(overlay_name);
      debug("redir_name 22 returning underlay name %s\n", underlay_name);
      ret.new_name = prepend_override_prefix(underlay_name);
      return ret;
    } else {
      // Return the overlay name, because we can only create things there.
      debug("Doesn't exist in underlay or overlay (and that's good)!\n");
      make_parents(overlay_name, underlay_name, overlay_prefix, underlay_prefix);
      free(underlay_name);
      debug("redir_name 23 returning overlay name %s\n", overlay_name);
      ret.new_name = prepend_override_prefix(overlay_name);
      return ret;
    }
  } else if (use == OPENDIR) {
    // Create a new directory that mirrors
    // whether it exists or not.  This is different from PREFER_UNDERLAY,
    // which only returns the underlay name if it exists.
    debug("OPENDIR!\n");
    // char *new_directory;
    //
    // new_directory = mkdir_new(???);
    // create_files(new_directory, underlay_name);
    //
    // TODO: Create a new temporary directory in overlay/.user-union/opendir
    // and populate it with the set of filenames in underlay+overlay.
    // (Don't include ".user-union" if it's at the top).
    // Then return that temporary directory.
    // #include <dirent.h>
    // ...
    // DIR *dir;
    // struct dirent *dp;
    // ...
    // if ((dir = opendir (".")) == NULL) {
    // perror ("Cannot open .");
    // exit (1);
    // }
    // while ((dp = readdir (dir)) != NULL) {
    // }
    /* HACK, for now */
    if (my_file_exists(overlay_name)) {
      free(underlay_name);
      debug("redir_name 160 returning overlay name %s\n", overlay_name);
      ret.new_name = prepend_override_prefix(overlay_name);
      return ret;
    }
    if (my_file_exists(underlay_name)) {
      free(overlay_name);
      debug("redir_name 161 returning overlay name %s\n", underlay_name);
      ret.new_name = prepend_override_prefix(underlay_name);
      return ret;
    }
    free(overlay_name);
    free(underlay_name);
    debug("redir_name 70 returning NULL for opendir\n");
    return ret;
  } else if (use == WRITE) { // Write (and maybe read) filesystem object
    debug("read-write!\n");
    if (!overlay_name) {
      ret.ret = FAILREDIR;
      return ret;
    }
    if (!is_whitelisted && !my_file_exists(overlay_name) &&
        my_file_exists(underlay_name)) {
      mode_t underlay_mode = my_file_lstat_mode(underlay_name);
      // It only exists in the underlay; we can't write new files there.
      // Is it a regular file, or something else?
      debug("Exists in underlay, not in overlay!\n");
      if (S_ISREG(underlay_mode)) {
       // Regular file.  We'll make a copy to modify (copy-on-write)
       debug("copying file, lstat_mode=%d.\n", my_file_lstat_mode(underlay_name));
       make_parents(overlay_name, underlay_name, overlay_prefix, underlay_prefix);
       my_file_copy(underlay_name, overlay_name, underlay_mode & 0777);
      } else if (S_ISDIR(underlay_mode)) {
       debug("Recreating directory, lstat_mode=%d.\n", my_file_lstat_mode(underlay_name));
       make_parents(overlay_name, underlay_name, overlay_prefix, underlay_prefix);
      } else {
        // Special case!  If it doesn't exist in the overlay, and
        // it's not a normal file in the underlay,
        // return the underlay.  That way we continue
        // to directly use devices like "/dev/null", FIFOs, etc. as-is.
        // Copying them won't actually do what we want!
        // If they are *created* later while union'ed, then they'll
        // exist in the overlay and we won't reach this case at all.
        // FIXME: What about directories?
        debug("Returning underlay name.\n");
        free(overlay_name);
        debug("redir_name 15 returning underlay name %s\n", underlay_name);
        ret.new_name = prepend_override_prefix(underlay_name);
        return ret;
      }
    } else {
       debug("Just making parents, if necessary.\n");
       make_parents(overlay_name, underlay_name, overlay_prefix, underlay_prefix);
    }
    free(underlay_name);
    debug("redir_name 16 returning overlay name %s\n", overlay_name);
    ret.new_name = prepend_override_prefix(overlay_name);
    return ret;
  } else if (use == EXIST ) {
    // If file exists in underlay, simply cause it to exist in the overlay.
    // This is like WRITE, but WRITE would copy a whole file in this case,
    // which is pointless if we're about to delete it.
    // Then return overlay name.
    debug("EXIST!\n");
    if (!is_whitelisted && !my_file_exists(overlay_name) &&
        my_file_exists(underlay_name)) {
      int result;
      make_parents(overlay_name, underlay_name, overlay_prefix, underlay_prefix);
      // FIXME: Mode (and owner) should match original file.
      result = my_open64(overlay_name, O_RDWR | O_CREAT, 0777);
      // Technically close() can return an error code, but there's nothing
      // we can practically do about close errors so we'll ignore them.
      if (result >= 0) close(result);
    }
    free(underlay_name);
    debug("redir_name 89 returning overlay name %s\n", overlay_name);
    ret.new_name = prepend_override_prefix(overlay_name);
    return ret;
  } else {
    fprintf(stderr, "FAIL, unknown use value %d\n", use);
    exit(1);
  }
}

static char *redir_symlink(const char *pathname)
{
  char buf[BIGBUF];
  ssize_t n;
  int rc;
  char *whitelist_name = gen_whitelist_name(pathname);
  n = my_readlink(whitelist_name, buf, BIGBUF);
  if (n > 0 && n < BIGBUF) {
    buf[n] = 0;
    /* symlink exists */
    if (strcmp(pathname, buf) == 0)
      return whitelist_name;
  }
  /* remove old symlink, if exists */
  my_unlink(whitelist_name);
  make_parents_of(whitelist_name);
  rc = my_symlink(pathname, whitelist_name);
  if (rc == -1) {
    fprintf(stderr, "FAIL: symlink creation failed at %s\n", whitelist_name);
    free(whitelist_name);
    return NULL;
  }
  return whitelist_name;
}

static struct redir_ret redir_name(const char *pathname, int use)
{
  struct redir_ret ret = { .ret = REDIR, .new_name = NULL };
  struct redir_ret ret1 = ret;
  char *r_path;
  const char *f_path;
  struct stat mystats;
  int result;
  int is_readlink = ((use & USAGE_T_MASK) == READLINK);

  // Check if initialized already
  if (!branchlist) {
    debug("not yet initialized\n");
    return ret;
  }

  if (!pathname) return ret; // Shouldn't happen.

  // If the special "override_prefix" is present, and we're using it,
  // return immediately.  This helps us guard against intercepting the
  // same pathname multiple times (in most cases it doesn't matter,
  // but this seems safer).
  if (use_override_prefix && within(pathname, override_prefix))
    return ret;

  // we allow readlink() to see the original symlink.
  // all other calls see the replacement symlink.
  if (is_readlink)
    use = READ | (use & ~USAGE_T_MASK);
  ret = __redir_name(pathname, use);
  r_path = ret.new_name;
  f_path = r_path ?: pathname;
  result = my_lstat(f_path, &mystats);
  if (result == -1)
    return ret;
  if (S_ISLNK(mystats.st_mode)) {
    char buf[BIGBUF];
    char *r_path1;
    ssize_t n;
    n = my_readlink(f_path, buf, BIGBUF);
    if (n <= 0 || n >= BIGBUF)
      return ret;
    buf[n] = 0;
    if (buf[0] == '/' && my_file_exists(buf)) {
      if (is_readlink) {
        /* we don't yet support readlink for symlinks that were created
         * without user-union, and are containing the absolute, real path.
         * The (partial) solution may be to create a replacement symlink
         * in which the dirname() from "buf" is replaced with dirname()
         * from "pathname" */
        debug("FAIL: unsupported readlink redirection %s\n", buf);
      }
      return ret;
    }
    if (is_readlink)
      return ret;
    if (buf[0] != '/' && pathname[0] == '/') {
      /* handle relative symlinks */
      char *f_path1 = strdup(pathname);
      char *d_name = dirname(f_path1);
      char *f_path2;
      memmove(buf + 1, buf, strlen(buf) + 1);
      buf[0] = '/';
      f_path2 = concat_dir(d_name, buf);
      free(f_path1);
      strcpy(buf, f_path2);
      free(f_path2);
    }
    ret1 = __redir_name(buf, use);
    r_path1 = ret1.new_name;
    if (!r_path1)
      return ret;
    free(r_path);
    r_path = redir_symlink(r_path1 + skip(override_prefix));
    free(r_path1);
    ret.new_name = prepend_override_prefix(r_path);
  }
  return ret;
}

// Quickly calculate euidaccess as if we're root.
// If the file exists somewhere, we'll return 0; else return -1.
static int my_overlay_euidaccess(const char *path, int mode) {
  struct redir_ret ret = redir_name(path, READ);
  char *new_path = ret.new_name;
  bool exists;
  unused_okay(mode);  // Remove excess -Wunused-parameter warning
  if (!new_path)
    return -1;
  exists = my_file_exists(new_path);
  free(new_path);
  return exists ? 0 : -1;
}

// We will now create the macros, etc., we need to wrap functions,
// and use them to create the wrappers.

// This macro creates a real_NAME function that chains to the "real"
// functions. It memoizes what it chains to, for efficiency.
// In most cases, "NAME" and "TOSYMBOL" are the same.
#define SPECIAL_CHAIN(RETURNTYPE, NAME, CALL_PARAMETER_TYPES,               \
        CHAIN_PARAMETER_TYPES, ARGUMENTS, TOSYMBOL)                         \
typedef RETURNTYPE NAME##_t CHAIN_PARAMETER_TYPES;                          \
static RETURNTYPE real_##NAME CALL_PARAMETER_TYPES {                        \
  static NAME##_t* p_real_##NAME = NULL;                                    \
  if (p_real_##NAME == NULL) {                                              \
    p_real_##NAME = (NAME##_t*) dlsym(RTLD_NEXT, #TOSYMBOL);                \
    if (!p_real_##NAME) {                                                   \
      fprintf(stderr, "FAIL: real_" #NAME " can't chain " #TOSYMBOL "\n");  \
      exit(1);                                                              \
    }                                                                       \
  }                                                                         \
  debug("Chaining real_" #NAME " to " #TOSYMBOL " using path=%s\n", path);  \
  return (*p_real_##NAME) ARGUMENTS;                                        \
}

#define CHAIN(RETURNTYPE, NAME, PARAMETER_TYPES, ARGUMENTS, TOSYMBOL)       \
SPECIAL_CHAIN(RETURNTYPE, NAME, PARAMETER_TYPES,                            \
PARAMETER_TYPES, ARGUMENTS, TOSYMBOL)

#define SOCKET_CHAIN(RETURNTYPE, NAME, CALL_PARAMETER_TYPES,                \
        ARGUMENTS, TOSYMBOL)                                                \
typedef RETURNTYPE NAME##_t CALL_PARAMETER_TYPES;                           \
static RETURNTYPE real_##NAME CALL_PARAMETER_TYPES {                        \
  static NAME##_t* p_real_##NAME = NULL;                                    \
  if (p_real_##NAME == NULL) {                                              \
    p_real_##NAME = (NAME##_t*) dlsym(RTLD_NEXT, #TOSYMBOL);                \
    if (!p_real_##NAME) {                                                   \
      fprintf(stderr, "FAIL: real_" #NAME " can't chain " #TOSYMBOL "\n");  \
      exit(1);                                                              \
    }                                                                       \
  }                                                                         \
  debug("Chaining real_" #NAME " to " #TOSYMBOL "\n");                      \
  return (*p_real_##NAME) ARGUMENTS;                                        \
}

#define ALIAS(RETURNTYPE, NAME, PARAMETER_TYPES, TOSYMBOL)                  \
RETURNTYPE NAME PARAMETER_TYPES __attribute__((alias(#TOSYMBOL)));

// Create a simple function that returns a value, WITHOUT chaining
// down to lower-level functions.  Useful for geteuid(), etc.
#define BASIC_RETURNS(RETURNTYPE, NAME, PARAMETER_TYPES, RESULT)            \
RETURNTYPE NAME PARAMETER_TYPES {                                           \
  return RESULT;                                                            \
}
#define RETURNS(RETURNTYPE, NAME, PARAMETER_TYPES, RESULT)                  \
BASIC_RETURNS(RETURNTYPE, NAME, PARAMETER_TYPES, RESULT)                    \
ALIAS(RETURNTYPE, _##NAME, PARAMETER_TYPES, NAME)                           \
ALIAS(RETURNTYPE, __##NAME, PARAMETER_TYPES, NAME)

// Create a "wrapper", that is, a function with the given NAME that
// intercepts a request, changes the filenames (etc.), and then calls
// the chaining function to perform the rest of the action.
// One parameter must be named "path"; that's the filename to be
// redirected.  The "USAGE" says if it's READ, WRITE, etc.
#define NORMAL_WRAPPER(RETURNTYPE, NAME, PARAMETER_TYPES, ARGUMENTS, USAGE, AFTER) \
RETURNTYPE NAME PARAMETER_TYPES {                                           \
  struct redir_ret ret;                                                     \
  RETURNTYPE result = 0;                                                    \
  int saved_errno;                                                          \
  const char *old_pathname = NULL;                                          \
  debug("Intercepted " #NAME "\n");                                         \
  ret = redir_name(path, USAGE);                                            \
  switch (ret.ret) {                                                        \
  case REDIR:                                                               \
    if (ret.new_name) {                                                     \
      old_pathname = path;                                                  \
      path = ret.new_name;                                                  \
    }                                                                       \
    result = real_##NAME ARGUMENTS;                                         \
    break;                                                                  \
  case NOREDIR:                                                             \
    assert(!ret.new_name);                                                  \
    result = 0;                                                             \
    break;                                                                  \
  case FAILREDIR:                                                           \
    assert(!ret.new_name);                                                  \
    result = -1;                                                            \
    break;                                                                  \
  }                                                                         \
  saved_errno = errno;                                                      \
  AFTER ;                                                                   \
  if (ret.new_name) free(ret.new_name);                                     \
  debug("Finished wrapped version of " #NAME "\n");                         \
  errno = saved_errno;                                                      \
  unused_okay(old_pathname);                                                \
  return result;                                                            \
}

// Create a 2-parameter "wrapper" for name NAME.
// The parameters to be changed *must* be "path" and "path2".
// We use "path" (not "path1") so that the chain function can easily
// output it for debugging purposes.
#define TWO_NORMAL_WRAPPER(RETURNTYPE, NAME, PARAMETER_TYPES, ARGUMENTS,    \
                    USAGE1, USAGE2, AFTER)                                  \
RETURNTYPE NAME PARAMETER_TYPES {                                           \
  struct redir_ret ret1, ret2;                                              \
  RETURNTYPE result;                                                        \
  int saved_errno;                                                          \
  const char *old_pathname = NULL;                                          \
  const char *old_pathname2 = NULL;                                         \
  debug("Intercepted " #NAME "\n");                                         \
  ret1 = redir_name(path, USAGE1);                                          \
  ret2 = redir_name(path2, USAGE2);                                         \
  assert(ret1.ret == REDIR && ret2.ret == REDIR);                           \
  if (ret1.new_name) {                                                      \
    old_pathname = path;                                                    \
    path = ret1.new_name;                                                   \
  }                                                                         \
  if (ret2.new_name) {                                                      \
    old_pathname2 = path2;                                                  \
    path2 = ret2.new_name;                                                  \
  }                                                                         \
  result = real_##NAME ARGUMENTS;                                           \
  saved_errno = errno;                                                      \
  AFTER ;                                                                   \
  if (ret1.new_name) free(ret1.new_name);                                   \
  if (ret2.new_name) free(ret2.new_name);                                   \
  debug("Finished wrapped version of " #NAME "\n");                         \
  errno = saved_errno;                                                      \
  unused_okay(old_pathname);                                                \
  unused_okay(old_pathname2);                                               \
  return result;                                                            \
}

#define PTR_WRAPPER(RETURNTYPE, NAME, PARAMETER_TYPES, ARGUMENTS, USAGE, AFTER) \
RETURNTYPE NAME PARAMETER_TYPES {                                           \
  struct redir_ret ret;                                                     \
  RETURNTYPE result = NULL;                                                 \
  int saved_errno;                                                          \
  const char *old_pathname = NULL;                                          \
  debug("Intercepted " #NAME "\n");                                         \
  ret = redir_name(path, USAGE);                                            \
  switch (ret.ret) {                                                        \
  case REDIR:                                                               \
    if (ret.new_name) {                                                     \
      old_pathname = path;                                                  \
      path = ret.new_name;                                                  \
    }                                                                       \
    result = real_##NAME ARGUMENTS;                                         \
    break;                                                                  \
  case NOREDIR:                                                             \
    abort();                                                                \
    break;                                                                  \
  case FAILREDIR:                                                           \
    assert(!ret.new_name);                                                  \
    result = NULL;                                                          \
    break;                                                                  \
  }                                                                         \
  saved_errno = errno;                                                      \
  AFTER ;                                                                   \
  if (ret.new_name) free(ret.new_name);                                     \
  debug("Finished wrapped version of " #NAME "\n");                         \
  errno = saved_errno;                                                      \
  unused_okay(old_pathname);                                                \
  return result;                                                            \
}

// Wrap "open".  This is special; open takes either 2 *OR* 3 parameters;
// so declaring external functions with 3 arguments will
// cause warnings/errors.  Instead, we accept 2, but
// always pass on 3 (it's simpler, that way the real_open style
// functions don't need to use va_start and friends).
#define OPEN_WRAPPER(NAME, PARAMETER_TYPES, ARGUMENTS, USAGE) \
int NAME PARAMETER_TYPES {                                                  \
  struct redir_ret ret;                                                     \
  int result;                                                               \
  int saved_errno;                                                          \
  mode_t mode;                                                              \
  va_list ap;                                                               \
  const char *old_pathname = NULL;                                          \
                                                                            \
  if (flags & O_CREAT) {                                                    \
    va_start(ap, flags);                                                    \
    mode = va_arg(ap, int);                                                 \
    va_end(ap);                                                             \
  } else {                                                                  \
    mode = 0;                                                               \
  }                                                                         \
  debug("Intercepted open(\"%s\",0%o,0%o)\n", path, flags, mode);           \
  ret = redir_name(path, USAGE);                                            \
  assert(ret.ret == REDIR);                                                 \
  if (ret.new_name) {                                                       \
    old_pathname = path;                                                    \
    path = ret.new_name;                                                    \
  }                                                                         \
  result = real_##NAME ARGUMENTS ;                                          \
  saved_errno = errno;                                                      \
  unwhitelist_if_error_free(result >= 0, old_pathname);                     \
  if (ret.new_name) free(ret.new_name);                                     \
  debug("Finished wrapped version of " #NAME "\n");                         \
  errno = saved_errno;                                                      \
  unused_okay(old_pathname);                                                \
  return result;                                                            \
}

#define SOCKET_WRAPPER(NAME, PARAMETER_TYPES, ARGUMENTS, USAGE, AFTER)      \
int NAME PARAMETER_TYPES {                                                  \
  struct redir_ret ret;                                                     \
  struct sockaddr_un new_addr;                                              \
  struct sockaddr_un *my_addr;                                              \
  struct sockaddr_un *old_addr;                                             \
  char *old_pathname;                                                       \
  char *path;                                                               \
  int result;                                                               \
  int saved_errno;                                                          \
  if (addr->sa_family != AF_UNIX)                                           \
    return real_##NAME ARGUMENTS ;                                          \
  my_addr = &new_addr;                                                      \
  old_addr = (struct sockaddr_un *)addr;                                    \
  *my_addr = *old_addr;                                                     \
  path = my_addr->sun_path;                                                 \
  old_pathname = old_addr->sun_path;                                        \
  debug("Intercepted " #NAME "(\"%s\")\n", path);                           \
  ret = redir_name(path, USAGE);                                            \
  assert(ret.ret == REDIR);                                                 \
  if (ret.new_name) {                                                       \
    strncpy(new_addr.sun_path, ret.new_name, sizeof(new_addr.sun_path) - 1);\
    new_addr.sun_path[sizeof(new_addr.sun_path) - 1] = 0;                   \
    addr = (struct sockaddr *)my_addr;                                      \
    addrlen = offsetof(struct sockaddr_un, sun_path) + strlen(new_addr.sun_path) + 1; \
    debug("Chaining " #NAME " with %s len=%i\n", my_addr->sun_path, addrlen);\
  }                                                                         \
  result = real_##NAME ARGUMENTS ;                                          \
  saved_errno = errno;                                                      \
  if (result == -1) debug(#NAME " failed, %i %s\n", saved_errno, strerror(saved_errno)); \
  AFTER ;                                                                   \
  if (ret.new_name) free(ret.new_name);                                     \
  debug("Finished wrapped version of " #NAME "\n");                         \
  errno = saved_errno;                                                      \
  unused_okay(old_pathname);                                                \
  return result;                                                            \
}

// TODO: Should I wrap _NAME and __NAME also?

// Basic wrap: create wrapper function NAME and real_NAME chain.
#define BASIC_WRAP(RETURNTYPE, NAME, SYMBOL, PARAMETER_TYPES, ARGUMENTS, USAGE, AFTER) \
CHAIN(RETURNTYPE, NAME, PARAMETER_TYPES, ARGUMENTS, SYMBOL) \
NORMAL_WRAPPER(RETURNTYPE, NAME, PARAMETER_TYPES, ARGUMENTS, USAGE, AFTER)

// Basic 2-parameter wrap: create wrapper function NAME and real_NAME chain.
#define TWO_BASIC_WRAP(RETURNTYPE, NAME, SYMBOL, PARAMETER_TYPES, ARGUMENTS, USAGE1, USAGE2, AFTER) \
CHAIN(RETURNTYPE, NAME, PARAMETER_TYPES, ARGUMENTS, SYMBOL) \
TWO_NORMAL_WRAPPER(RETURNTYPE, NAME, PARAMETER_TYPES, ARGUMENTS, USAGE1, USAGE2, AFTER)

#define PTR_WRAP(RETURNTYPE, NAME, SYMBOL, PARAMETER_TYPES, ARGUMENTS, USAGE, AFTER) \
CHAIN(RETURNTYPE, NAME, PARAMETER_TYPES, ARGUMENTS, SYMBOL) \
PTR_WRAPPER(RETURNTYPE, NAME, PARAMETER_TYPES, ARGUMENTS, USAGE, AFTER)

// Normal wrap - wrap up NAME, _NAME, and __NAME.
#define WRAP(RETURNTYPE, NAME, SYMBOL, PARAMETER_TYPES, ARGUMENTS, USAGE, AFTER) \
BASIC_WRAP(RETURNTYPE, NAME, SYMBOL, PARAMETER_TYPES, ARGUMENTS, USAGE, AFTER) \
ALIAS(RETURNTYPE, _##NAME, PARAMETER_TYPES, NAME) \
ALIAS(RETURNTYPE, __##NAME, PARAMETER_TYPES, NAME)

// Two-parameter wrap
#define TWO_WRAP(RETURNTYPE, NAME, SYMBOL, PARAMETER_TYPES, ARGUMENTS, USAGE1, USAGE2, AFTER) \
TWO_BASIC_WRAP(RETURNTYPE, NAME, SYMBOL, PARAMETER_TYPES, ARGUMENTS, USAGE1, USAGE2, AFTER) \
ALIAS(RETURNTYPE, _##NAME, PARAMETER_TYPES, NAME) \
ALIAS(RETURNTYPE, __##NAME, PARAMETER_TYPES, NAME)

#define PWRAP(RETURNTYPE, NAME, SYMBOL, PARAMETER_TYPES, ARGUMENTS, USAGE, AFTER) \
PTR_WRAP(RETURNTYPE, NAME, SYMBOL, PARAMETER_TYPES, ARGUMENTS, USAGE, AFTER) \
ALIAS(RETURNTYPE, _##NAME, PARAMETER_TYPES, NAME) \
ALIAS(RETURNTYPE, __##NAME, PARAMETER_TYPES, NAME)

// Wrap 64-bit version; like WRAP, but also do it for NAME ## 64.
#define WRAP64(RETURNTYPE, NAME, SYMBOL, PARAMETER_TYPES, ARGUMENTS, USAGE, AFTER) \
WRAP(RETURNTYPE, NAME, SYMBOL, PARAMETER_TYPES, ARGUMENTS, USAGE, AFTER) \
WRAP(RETURNTYPE, NAME##64, SYMBOL##64, PARAMETER_TYPES, ARGUMENTS, USAGE, AFTER)

#define PWRAP64(RETURNTYPE, NAME, SYMBOL, PARAMETER_TYPES, ARGUMENTS, USAGE, AFTER) \
PWRAP(RETURNTYPE, NAME, SYMBOL, PARAMETER_TYPES, ARGUMENTS, USAGE, AFTER) \
PWRAP(RETURNTYPE, NAME##64, SYMBOL##64, PARAMETER_TYPES, ARGUMENTS, USAGE, AFTER)

// Like BASIC_WRAP, but for open() which takes a varying # of parameters.
#define BASIC_OPEN_WRAP(NAME, PARAMETER_TYPES, PARAMETER_TYPES_ALL, ARGUMENTS, USAGE) \
CHAIN(int, NAME, PARAMETER_TYPES_ALL, ARGUMENTS, NAME) \
OPEN_WRAPPER(NAME, PARAMETER_TYPES, ARGUMENTS, USAGE)

#define OPEN_WRAP(NAME, PARAMETER_TYPES, PARAMETER_TYPES_ALL, ARGUMENTS, USAGE) \
BASIC_OPEN_WRAP(NAME, PARAMETER_TYPES, PARAMETER_TYPES_ALL, ARGUMENTS, USAGE) \
ALIAS(int, _##NAME, PARAMETER_TYPES, NAME) \
ALIAS(int, __##NAME, PARAMETER_TYPES, NAME)

#define OPEN_WRAP64(NAME, PARAMETER_TYPES, PARAMETER_TYPES_ALL, ARGUMENTS, USAGE) \
OPEN_WRAP(NAME, PARAMETER_TYPES, PARAMETER_TYPES_ALL, ARGUMENTS, USAGE) \
OPEN_WRAP(NAME##64, PARAMETER_TYPES, PARAMETER_TYPES_ALL, ARGUMENTS, USAGE)

#define BASIC_SOCKET_WRAP(NAME, PARAMETER_TYPES, ARGUMENTS, USAGE, AFTER) \
SOCKET_CHAIN(int, NAME, PARAMETER_TYPES, ARGUMENTS, NAME) \
SOCKET_WRAPPER(NAME, PARAMETER_TYPES, ARGUMENTS, USAGE, AFTER)

#define SOCKET_WRAP(NAME, PARAMETER_TYPES, ARGUMENTS, USAGE, AFTER) \
BASIC_SOCKET_WRAP(NAME, PARAMETER_TYPES, ARGUMENTS, USAGE, AFTER) \
ALIAS(int, _##NAME, PARAMETER_TYPES, NAME) \
ALIAS(int, __##NAME, PARAMETER_TYPES, NAME)

// Helper functions for the wrappers
static void whitelist_if_error_free(int result, const char *path) {
  if (result && path) {
    struct redir_ret ret = redir_name(path, WHITELIST);
    char *s = ret.new_name;
    if (s) free(s);
  }
}

static void unwhitelist_if_error_free(int result, const char *path) {
  if (result && path) {
    struct redir_ret ret = redir_name(path, UNWHITELIST);
    char *s = ret.new_name;
    if (s) free(s);
  }
}


// Wrap the functions!
// FIXME: The "at" functions (openat, faccess, linkat, etc.) need to
// be handled specially, so that relative filenames are handled correctly.
// More information is here:
// https://lwn.net/Articles/164887/
// Not yet intercepted at all:
//  int mknodat(int dfd, const char *pathname, mode_t mode, dev_t dev);
//  int utimesat(int dfd, const char *filename, struct timeval *tvp);
//  int chownat(int dfd, const char *path, uid_t owner, gid_t group);

// We must use a special wrapper for open().
OPEN_WRAP64(open, (const char *path, int flags, ...), (const char *path, int flags, mode_t mode), (path, flags, mode), use_open(flags))
OPEN_WRAP64(openat, (int dirfd, const char *path, int flags, ...), (int dirfd, const char *path, int flags, mode_t mode), (dirfd, path, flags, mode), use_open(flags)|AT(dirfd))

SOCKET_WRAP(bind, (int sockfd, const struct sockaddr *addr, \
                socklen_t addrlen), (sockfd, addr, addrlen), WRITE, \
                unwhitelist_if_error_free(result >= 0, old_pathname))
SOCKET_WRAP(connect, (int sockfd, const struct sockaddr *addr, \
                socklen_t addrlen), (sockfd, addr, addrlen), READ,)


WRAP(int, access, access, (const char *path, int mode), (path, mode), READ,)

WRAP64(int, faccessat, faccessat, \
     (int dirfd, const char *path, int mode, int flags), \
     (dirfd, path, mode, flags), READ|AT(dirfd),)
WRAP64(int, newfstatat, newfstatat,
      (int dirfd, char *path, struct stat *buf, int flag),
      (dirfd, path, buf, flag), READ|AT(dirfd),)

WRAP(int, mkdir, mkdir, (const char *path, mode_t mode), \
                 (path, mode), EXCLUSIVE, \
                 unwhitelist_if_error_free(result>=0, old_pathname))
WRAP(int, mkdirat, mkdirat, (int dirfd, const char *path, mode_t mode), \
                 (dirfd, path, mode), EXCLUSIVE|AT(dirfd), \
                 unwhitelist_if_error_free(result>=0, old_pathname))

WRAP(int, rmdir, rmdir, (const char *path), \
                 (path), WRITE, whitelist_if_error_free(result>=0, old_pathname))

// Pretend that we have an effective UID of root.
// That way, tools that first check to see if we have permission to do
// something (like rm) will quickly decide that we do have permission.

RETURNS(uid_t, geteuid, (void), 0)
RETURNS(int, euidaccess, (const char *path, int mode), \
        my_overlay_euidaccess(path, mode))
RETURNS(int, eaccess, (const char *path, int mode), \
        my_overlay_euidaccess(path, mode))



// We'll make chdir prefer to return the *underlay* name.
// That way, whenever the abstraction leaks, the current directory (etc.)
// will be the "expected" directory in the underlay.
// Note that this is merely *preferred* - if a user creates new directories,
// we may still need to set the current directory to be a value inside
// the overlay.
WRAP(int, chdir, chdir, (const char *path), (path), PREFER_UNDERLAY,)


WRAP(ssize_t, readlink, readlink, (const char *path, char *buf, size_t bufsiz), (path, buf, bufsiz), READLINK,)
WRAP(ssize_t, readlinkat, readlinkat, (int dirfd, const char *path, char *buf, size_t bufsiz), (dirfd, path, buf, bufsiz), READLINK|AT(dirfd),)

WRAP(int, inotify_add_watch, inotify_add_watch, \
       (int fd, const char *path, uint32_t mask), (fd, path, mask), WRITE,)

WRAP(int, symlink, symlink, (const char *oldpath, const char *path), \
       (oldpath, path), EXCLUSIVE, \
       unwhitelist_if_error_free(result>=0, old_pathname))
WRAP(int, symlinkat, symlinkat, (const char *oldpath, int newdfd, const char *path), \
       (oldpath, newdfd, path), EXCLUSIVE|AT(newdfd), \
       unwhitelist_if_error_free(result>=0, old_pathname))

// We can't link across filesystems, so on some environments this will fail:
TWO_WRAP(int, link, link, (const char *path, const char *path2), \
       (path, path2), READ, EXCLUSIVE, \
       unwhitelist_if_error_free(result>=0, old_pathname2))
TWO_WRAP(int, linkat, linkat,
 (int olddirfd, const char *path, int newdirfd, const char *path2, int flags), \
 (olddirfd, path, newdirfd, path2, flags), READ|AT(olddirfd), EXCLUSIVE|AT(newdirfd), \
       unwhitelist_if_error_free(result>=0, old_pathname2))

TWO_WRAP(int, rename, rename, (const char *path, const char *path2), \
       (path, path2), WRITE, EXCLUSIVE, whitelist_if_error_free(result>=0, old_pathname); \
       unwhitelist_if_error_free(result>=0, old_pathname2))

TWO_WRAP(int, renameat, renameat, (int olddirfd, const char *path, int newdirfd, \
       const char *path2), (olddirfd, path, newdirfd, path2), WRITE|AT(olddirfd), \
       EXCLUSIVE|AT(newdirfd), whitelist_if_error_free(result>=0, old_pathname) ; \
       unwhitelist_if_error_free(result>=0, old_pathname2))

WRAP(int, mount, mount, (const char *source, const char *path, \
       const char *filesystemtype, unsigned long mountflags, const void *data), \
       (source, path, filesystemtype, mountflags, data), WRITE,)

WRAP(int, umount, umount, (const char *path), (path), WRITE,)
WRAP(int, umount2, umount2, (const char *path, int flags), (path, flags), WRITE,)


WRAP(int, utime, utime, (const char *path, const struct utimbuf *times),
     (path, times), WRITE,)
WRAP(int, utimes, utimes, (const char *path, const struct timeval times[2]),
     (path, times), WRITE,)

WRAP(int, chmod, chmod, (const char* path, mode_t mode), \
     (path, mode), WRITE,)

PWRAP(DIR *, opendir, opendir, (const char* path), (path), OPENDIR,)
// It's not clear how to handle fdopendir().

// TODO: Should we handle chown, lchown, fchown differently?
// E.G., perhaps ignore errors?  For now, they're passed through as-is.
// fchown isn't wrapped, because it has no path.

WRAP(int, chown, chown, (const char* path, uid_t owner, gid_t group), \
     (path, owner, group), WRITE,)
WRAP(int, lchown, lchown, (const char* path, uid_t owner, gid_t group), \
     (path, owner, group), WRITE,)

WRAP(int, statvfs, statvfs, (const char* path, struct statvfs *buf), \
     (path, buf), READ,)

WRAP64(int, unlink, unlink, (const char* path), (path), EXIST, whitelist_if_error_free(result>=0, old_pathname))
WRAP64(int, unlinkat, unlinkat, (int dirfd, const char* path, int flags), (dirfd, path, flags), EXIST|AT(dirfd),
     whitelist_if_error_free(result>=0,old_pathname))
#ifdef HAVE_STRUCT_STATVFS64
WRAP(int, statvfs64, statvfs64, (const char* path, struct statvfs64 *buf), \
     (path, buf), READ,)
#endif


// We can only create SOME kinds of nodes, but we can try.
WRAP(int, mknod, mknod, (const char* path, mode_t mode, dev_t dev), \
     (path, mode, dev), WRITE, \
       unwhitelist_if_error_free(result>=0, old_pathname))
// This is probably implemented with mknod, but we'll specially wrap it
// no matter what.
WRAP(int, mkfifo, mkfifo, (const char* path, mode_t mode), \
     (path, mode), WRITE, \
       unwhitelist_if_error_free(result>=0, old_pathname))

WRAP(ssize_t, getxattr, getxattr, (const char *path, const char *name, \
     void *value, size_t size), (path, name, value, size), READ,)
WRAP(ssize_t, lgetxattr, lgetxattr, (const char *path, const char *name, \
     void *value, size_t size), (path, name, value, size), READ,)

// TODO: Need to wrap many more, including:
// opendir::void *:const char *pathname
// readlink::ssize_t:const char *pathname, char *buf, int size
// execve::int:const char *pathname, void *foo1, void *foo2
//
// getcwd, etc. (if we're in overlay, show underlay values)
//
//  int euidaccess(const char *pathname, int mode);
//  int eaccess(const char *pathname, int mode);
//
// TODO: fstatat.


//     ssize_t xstat(int dfd, const char *filename, unsigned atflag,
// 	          struct xstat *buffer, size_t buflen);
//
//     ssize_t fxstat(int fd, struct xstat *buffer, size_t buflen);

// WRAP(ssize_t, xstat, xstat, (int dfd, const char *path, unsigned atflag,
//        void *buffer, size_t buflen),
//        (dfd, path, atflag, buffer, buflen), READ,)
// WRAP64(ssize_t, fxstat, fxstat, (int fd, struct xstat *buffer, size_t buflen),
//        (fd, buffer, buflen), READ,)


#if defined(__linux__) && !defined(__UCLIBC__)
// Wrap stat*, lstat*, etc.  This is more complicated
// due to the GNU C implementation of stat*, lstat*, etc.
// *USERS* see the standard definitions:
//       int stat(const char *path, struct stat *buf);
//       int fstat(int fd, struct stat *buf);
//       int lstat(const char *path, struct stat *buf);
// However, the GNU C compiler inlines these functions, and generates a
// *different* function name with a *different* number of parameters.
// To wrap "stat", we need to wrap "__xstat", to wrap "lstat", we
// must wrap "__lxstat", and so on.  Note that the parameter list is
// different than the standard; a "version" is added to the front.
// See /usr/include/sys/stat.h for details.
// We don't need to map fstat at all, because it has no filename parameter.

BASIC_WRAP(int, __xstat, __xstat, (int ver, const char* path, struct stat* sb), (ver, path, sb), READ,)
BASIC_WRAP(int, __lxstat, __lxstat, (int ver, const char* path, struct stat* sb), (ver, path, sb), READ,)
BASIC_WRAP(int, __xstat64, __xstat64, (int ver, const char* path, struct stat64* sb), (ver, path, sb), READ,)
BASIC_WRAP(int, __lxstat64, __lxstat64, (int ver, const char* path, struct stat64* sb), (ver, path, sb), READ,)


BASIC_WRAP(int, __fxstatat, __fxstatat, (int ver, int dirfd, const char* path, struct stat* sb, int flag), (ver, dirfd, path, sb, flag), READ|AT(dirfd),)
BASIC_WRAP(int, __fxstatat64, __fxstatat, (int ver, int dirfd, const char* path, struct stat64 *sb, int flag), (ver, dirfd, path, sb, flag), READ|AT(dirfd),)


// *We* need to have a useful "real_lstat" and friends.
// So we need to wrap them specially so we can call them as well.
// The following creates real_lstat and friends, using
// SPECIAL_CHAIN(RETURNTYPE, NAME, CALL_PARAMETER_TYPES,
//               CHAIN_PARAMETER_TYPES, ARGUMENTS, TOSYMBOL)
#ifndef _STAT_VER
#define _STAT_VER 0
#endif
SPECIAL_CHAIN(int, lstat, (const char *path, struct stat *statbuf), \
                  (int ver, const char *path, struct stat *statbuf), \
                  (_STAT_VER, path, statbuf), __lxstat)
/* We don't use these, so don't mention them.
 * Otherwise, the compiler will (correctly) complain about unused
 * static functions.  NOTE: Using multi-line commends because we're
 * commenting out macro uses with backslashes.
SPECIAL_CHAIN(int, stat,  (const char *path, struct stat *statbuf), \
                  (int ver, const char *path, struct stat *statbuf), \
                  (_STAT_VER, path, statbuf), __xstat)
SPECIAL_CHAIN(int, stat64,  (const char *path, struct stat64 *statbuf), \
                  (int ver, const char *path, struct stat64 *statbuf), \
                  (_STAT_VER, path, statbuf), __xstat64)
SPECIAL_CHAIN(int, lstat64, (const char *path, struct stat64 *statbuf), \
                  (int ver, const char *path, struct stat64 *statbuf), \
                  (_STAT_VER, path, statbuf), __lxstat64)
*/


#elif __APPLE__

// For Apple we also have to wrap fopen() and friends:
#define WRAP_USERS 1

WRAP(int, stat, stat, (const char* path, struct stat* sb), (path, sb), READ,)
WRAP(int, lstat, lstat, (const char* path, struct stat* sb), (path, sb), READ,)

// TODO: OSX stuff from ekam

// OSX defines an alternate version of stat with 64-bit inodes.

WRAP(int, stat64, stat64, (const char* path, struct stat64* sb), (path, sb), READ,)

// ekam notes the following:
// In some crazy attempt to transition the regular "stat" call to use
// 64-bit inodes, Apple resorted to some sort of linker magic in which
// calls to stat() in newly-compiled code actually go to _stat$INODE64(),
// which appears to be identical to stat64().  We disabled this by defining
// _DARWIN_NO_64_BIT_INODE, above, but we need to intercept all versions
// of stat, including the $INODE64 version.  Let's avoid any dependency
// on stat64, though, since it is "deprecated".  So, we just make the stat
// buf pointer opaque.

// typedef int stat_inode64_t(const char* path, void* sb);
// int stat_inode64(const char* path, void* sb) __asm("_stat$INODE64");
// int stat_inode64(const char* path, void* sb) {
//   static stat_inode64_t* real_stat_inode64 = NULL;
//   char buffer[PATH_MAX];
//
//   if (real_stat_inode64 == NULL) {
//     real_stat_inode64 = (stat_inode64_t*) dlsym(RTLD_NEXT, "stat$INODE64");
//     assert(real_stat_inode64 != NULL);
//   }
//
//   path = remap_file("_stat$INODE64", path, buffer, READ);
//   if (path == NULL) return -1;
//   return real_stat_inode64(path, sb);
// }

WRAP(int, stat64, _stat$INODE64, (const char* path, struct stat64* sb), (path, sb), READ,)


#else

WRAP(int, stat, stat, (const char* path, struct stat* sb), (path, sb), READ,)
WRAP(int, lstat, lstat, (const char* path, struct stat* sb), (path, sb), READ,)

#if defined (__UCLIBC__)
WRAP(int, stat64, stat64, (const char* path, struct stat64* sb), (path, sb), READ,)
WRAP(int, lstat64, lstat64, (const char* path, struct stat64* sb), (path, sb), READ,)
#endif

#endif


#ifdef WRAP_USERS

// Many platforms require us to wrap other C library routines that
// depend on lower-level routines, so we must wrap fopen(), etc.

// For example, the default GNU C library install will
// not normally let us override the open() inside fopen, so we must
// do it ourselves.

PWRAP64(FILE *, fopen,   fopen,   (const char *path, const char *mode), \
                    (path, mode), use_fopen(mode), unwhitelist_if_error_free(result!=NULL, old_pathname))

PWRAP64(FILE *, freopen, freopen, \
       (const char *path, const char *mode, FILE *stream), \
                     (path, mode, stream), use_fopen(mode),unwhitelist_if_error_free(result!=NULL, old_pathname))

WRAP64(int, creat, creat, \
      (const char *path, mode_t mode), (path, mode), WRITE, \
       unwhitelist_if_error_free(result>=0, old_pathname))


// FIXME: "SKIP_UNSLASHED" should work *most* of the time, but
// it doesn't *exactly* capture the right semantics.  Should define
// special modes for each type of use (dl*, exec*) and do the path-like
// searching specially.

PWRAP(void *, dlopen, dlopen, (const char *path, int flag), (path, flag), \
  SKIP_UNSLASHED,)

/* Under uClibc it is unsafe to wrap these functions.
 * They can be intercepted from within the system() call, which is
 * after fork(). Unfortunately uclibc doesn't sanitize its mutexes
 * on fork(), so calling most library funtions, like malloc() or strdup(),
 * may deadlock. */
#ifndef __UCLIBC__
WRAP(int, execve, execve, \
     (const char* path, char* const argv[], char* const envp[]), \
     (path, argv, envp), SKIP_UNSLASHED,)
WRAP(int, execv, execv, (const char *path, char *const argv[]), \
       (path, argv), SKIP_UNSLASHED,)
WRAP(int, execvp, execvp, (const char *path, char *const argv[]), \
       (path, argv), SKIP_UNSLASHED,)
#endif

// TODO: Add these exec* functions.  These have a variable number of
// arguments, making them more work, so I haven't handled them yet:
// int execl(const char *path, const char *arg, ...);
// int execlp(const char *file, const char *arg, ...);
// int execle(const char *path, const char *arg,
//            ..., char * const envp[]);
// Unfortunately, there really isn't a standard way to to use stdarg.h to
// call a variable-argument
// function from a variable-argument function when the underlying function
// doesn't have a variant that accepts a va_list.
// If this were printf, I could just use vprintf, but this isn't printf.
// One alternative would be to switch from stdarg.h (the "newer" way) to
// the older "varargs.h" - which isn't in ANSI C but is an older standard,
// and is widely supported.  I believe that WILL work.
// More info:
// http://stackoverflow.com/questions/205529/c-c-passing-variable-number-of-arguments-around
// http://www.gnu.org/s/libc/manual/html_node/Old-Varargs.html

#endif




// Here we define the functions that the user-union shared library uses
// to access the underlying file system.
// These functions call to the real_NAME functions,
// just like the wrappers do, to invoke the underlying system.


// Template for creating a "my_NAME" function.  This is a function invoked by
// user-union to the underlying C library to implement unions
// (as opposed to an intercepted function call).
// The my_NAME functions insert the override_prefix, to reduce the
// risks from recursive loops, and then call the real_NAME function
// to actually do the operation.
// There *must* be a parameter named "path".
#define MAKE_MY_FUNCTION(RETURNTYPE, NAME, PARAMETER_TYPES, ARGUMENTS)      \
static RETURNTYPE my_ ## NAME PARAMETER_TYPES {                             \
  RETURNTYPE result;                                                        \
  if (use_override_prefix && !within(path, override_prefix)) {              \
    char *new_path;                                                         \
    new_path = concat_dir(override_prefix, path);                           \
    result = real_ ## NAME ARGUMENTS ;                                      \
    free(new_path);                                                         \
    return result;                                                          \
  } else {                                                                  \
    result = real_ ## NAME ARGUMENTS ;                                      \
    return result;                                                          \
  }                                                                         \
}

MAKE_MY_FUNCTION(int, open64, (const char *path, int flags, mode_t mode), \
                              (path, flags, mode))
MAKE_MY_FUNCTION(int, mkdir,  (const char *path, mode_t mode), \
                              (path, mode))
MAKE_MY_FUNCTION(int, lstat,  (const char *path, struct stat *buf), \
                              (path, buf))
MAKE_MY_FUNCTION(int, unlink, (const char *path), (path))
MAKE_MY_FUNCTION(ssize_t, readlink, (const char *path, char *buf, \
                              size_t bufsiz), (path, buf, bufsiz))
MAKE_MY_FUNCTION(int, symlink, (const char *oldpath, const char *path), \
                              (oldpath, path))
MAKE_MY_FUNCTION(int, rename, (const char *oldpath, const char *path), \
                              (oldpath, path))
#if 0
MAKE_MY_FUNCTION(DIR *, opendir, (const char *path), (path))
#endif

/*
    27: 00000000     0 FUNC    GLOBAL DEFAULT  UND __lxstat64@GLIBC_2.2 (6)
    31: 00000000     0 FUNC    GLOBAL DEFAULT  UND openat64@GLIBC_2.4 (7)

    39: 00000000     0 FUNC    GLOBAL DEFAULT  UND readdir64@GLIBC_2.2 (6)

    45: 00000000     0 FUNC    GLOBAL DEFAULT  UND euidaccess@GLIBC_2.0 (2)
    46: 00000000     0 FUNC    GLOBAL DEFAULT  UND getegid@GLIBC_2.0 (2)
    48: 00000000     0 FUNC    GLOBAL DEFAULT  UND rpmatch@GLIBC_2.0 (2)

    52: 00000000     0 FUNC    GLOBAL DEFAULT  UND rewinddir@GLIBC_2.0 (2)
    56: 00000000     0 FUNC    GLOBAL DEFAULT  UND __fpending@GLIBC_2.2 (6)

    60: 00000000     0 FUNC    GLOBAL DEFAULT  UND fstatfs64@GLIBC_2.1 (4)

    64: 00000000     0 FUNC    GLOBAL DEFAULT  UND textdomain@GLIBC_2.0 (2)

    65: 00000000     0 FUNC    GLOBAL DEFAULT  UND __fxstat64@GLIBC_2.2 (6)
    66: 00000000     0 FUNC    GLOBAL DEFAULT  UND fcntl@GLIBC_2.0 (2)

    69: 00000000     0 FUNC    GLOBAL DEFAULT  UND unlinkat@GLIBC_2.4 (7)

    72: 00000000     0 FUNC    GLOBAL DEFAULT  UND lseek64@GLIBC_2.1 (4)

    74: 00000000     0 FUNC    GLOBAL DEFAULT  UND __fxstatat64@GLIBC_2.4 (7)
*/

