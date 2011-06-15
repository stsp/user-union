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
// If you have root privileges, DON'T use this tool, because with root
// privileges there are WAY better ways to do union mounts.  This includes
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

// Need this so GNU C library will support dlsym's RTLD_NEXT flag:
#define _GNU_SOURCE 
// Need this for Apple MacOS X, to deal with weirdness in its "stat":
#define _DARWIN_NO_64_BIT_INODE

// For GNU "AT" functions like linkat(), openat():
// #define _XOPEN_SOURCE 700 || _POSIX_C_SOURCE >= 200809L
#define _XOPEN_SOURCE 700
#define _POSIX_C_SOURCE 200809L
#define _ATFILE_SOURCE 1


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdarg.h>
#include <dlfcn.h>
#include <assert.h>
#include <utime.h>
#include <sys/time.h>
// For opendir():
#include <dirent.h>
#include <assert.h>

// We use pthread.h for a simple mutex lock (we don't create threads).
// This lock (see below) is used to ensure we initialize correctly.
#include <pthread.h>

// The following is for Cygwin:
#ifndef RTLD_NEXT
#define RTLD_NEXT ((void *) -1L)
#endif
// If your system doesn't support RTLD_NEXT, one workaround is to do a
// compile-time definition of RTLD_NEXT to refer to the underlying C library.
// Or, get a real operating system :-).

// Coding style for C used here, to make it easier to read (in my opinion):
// - Bracing is K&R (One True Brace Style), *even* for function headings.
// - 2-space indents.
// - Comments use "//"; everyone important supports it now.

// A lot of stuff here is marked "static" to make it more private.
// We're doing a lot of subterfugue, so symbol visibility needs to be
// reduced to *only* the symbols we are intentionally overriding.


#define DEBUG 1
#ifdef DEBUG
#define debug(...) fprintf(stderr, "user-union: " __VA_ARGS__)
#else
#define debug(format, args...) do { } while (0)
#endif


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
  SWITCH_UNDERLAY,  // If given an overlay name, switch to underlay
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

// Standards don't define how to take open() flags and determine if it's
// read-only.  The following probably works everywhere, though:
#define FLAG_READONLY(flag) (((flag) & (O_RDONLY|O_WRONLY|O_RDWR)) == O_RDONLY)

// Convert open() flags to usage flags
static usage_t use_open(int flags) {
  if (FLAG_READONLY(flags))
    return READ;
  else if (flags & O_EXCL)
    return EXCLUSIVE;
  else
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
// It's possible that when the the C library implements those functions,
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


// Branch handling - we need to know how to handle directories.
// This data comes from environment variable USER_UNION.
// This structure is actually more than we strictly need; I have hopes
// to eventually expand the code to support multiple overlays, and
// this structure supports that.

struct stringlist;
struct stringlist {
  char *val;
  struct stringlist *next;
};

struct branch {
  struct stringlist *list;
  struct branch *next;
};

static struct branch *branchlist;

// Set up branches by reading in the environment variable.
static void initialize_branchlist(void) {
  char *spec;
  int len;
  struct branch *current_branch;
  struct branch *previous_branch = NULL;
  struct stringlist *current_stringlist;
  struct stringlist *previous_stringlist = NULL;
  char *current_string;
  spec = getenv("USER_UNION");
  if (!spec || (spec[0] == '\0')) {
    fprintf(stderr,
         "user-union: Warning. Environment variable USER_UNION not set.\n");
    // This is intended to only be used when debugging (to simplify things):
    spec="/tmp\n/var/tmp\n/home\n/Users\n/tmp/redir\t/";
  }
  while (*spec) {
    if ((*spec == ' ') | (*spec == '\n')) {
      spec++;
      continue;
    }
    if (*spec == '\t') {
      fprintf(stderr,
         "user-union: FATAL.  A USER_UNION branch began with tab.\n");
      exit(1);
    }

    current_branch = malloc(sizeof(struct branch));
    current_branch->next = NULL;
    if (!branchlist) {
      branchlist = current_branch;
    } else {
      previous_branch->next = current_branch;
    }
    previous_branch = current_branch;

    current_stringlist = previous_stringlist = NULL;
    while (*spec && *spec != '\n') {
      if (*spec == '\t') spec++;
      len = strcspn(spec, "\t\n");
      if (len <= 0) {
        fprintf(stderr,
         "user-union: FATAL.  USER_UNION misformatted.\n");
        exit(1);
      } else if (*spec != '/') {
        fprintf(stderr,
         "user-union: FATAL.  Directory %s fails to start with '/'.\n", spec);
        exit(1);
      } else if (len > 2 && spec[len-1]=='/') {
        fprintf(stderr,
         "user-union: FATAL.  Directory %s ends with '/'.\n", spec);
        exit(1);
      }
      current_stringlist = malloc(sizeof(struct stringlist));
      current_stringlist->next = NULL;
      current_string = malloc(len + 1);
      strncpy(current_string, spec, len);
      current_string[len] = '\0';
      current_stringlist->val = current_string;
      if (!previous_stringlist) {
        current_branch->list = current_stringlist; // First list in branch.
      } else {
        previous_stringlist->next = current_stringlist;
      }
      previous_stringlist = current_stringlist;
      spec += len;
    }
    if (current_branch->list && current_branch->list->next &&
        current_branch->list->next->next) {
        fprintf(stderr, "user-union: FATAL.  Cannot have >1 underlay.\n");
        exit(1);
    }
  }
  // Complete.
#ifdef DEBUG
  debug("Completed setting branchlist.  Results:\n");
  for (current_branch = branchlist; current_branch;
       current_branch = current_branch->next) {
    debug("Branch:\n");
    for (current_stringlist = current_branch->list; current_stringlist;
         current_stringlist = current_stringlist->next) {
      debug("  Directory: %s\n", current_stringlist->val);
    }
  }
#endif
}


// The following ensures that we initialize *exactly once* before
// doing anything else, and that initialization *completes*
// before *any* other operations occur.
// Otherwise, if an application has multiple threads,
// it might start initializing the library, and while that happens
// another thread might start up and try to initialize the library
// simultaneously.  Resulting in Bad Things.
//
// This may look inefficient, but the mutex lock/lock is extremely
// efficient on most systems.. especially since in most cases it'll just
// fall through (and if it doesn't, then we're using the lock!).
// The guarded section merely checks if a single pointer is null,
// and in most cases it's non-null (so nothing happens).
// By inlining it, initialize_if_needed becomes really fast.
// In any case, it's better to be a little slower but right, than
// fast but occasionally failing in Mysterious Ways.
//
// I had originally tried to do this using GNU C's constructors, like this:
// static void initialize_library(void) __attribute__ ((constructor(65535)));
// That would have been a little more efficient.
// However, they didn't work reliably for this purpose
// (they would occasionally segfault).  They aren't portable anyway.
// In contrast, this approach is really portable.

static pthread_mutex_t are_currently_initializing = PTHREAD_MUTEX_INITIALIZER;

static inline void initialize_if_needed(void) {
  pthread_mutex_lock(&are_currently_initializing);
  if (!branchlist) initialize_branchlist();
  pthread_mutex_unlock(&are_currently_initializing);
}



// We will need to use internally some redirected functions, so that
// we can directly manipulate the filesystem.  We declare them here,
// so that the compiler will complain if we have it wrong, but will
// define them later once we have the other functions defined that they need.

static int my_open64(const char *path, int flags, mode_t mode);
static int my_mkdir(const char *pathname, mode_t mode);
static int my_unlink(const char *path);
static int my_lstat(const char *path, struct stat *buf);
static DIR *my_opendir(const char *name);

// static int my_stat(const char *path, struct stat *buf);



// TODO: Error handling.
static void my_file_copy(const char *old, const char *new, mode_t mode) {
  int oldfd = my_open64(old, O_RDONLY, 0);
  int newfd = my_open64(new, O_WRONLY|O_CREAT, mode);
  char buffer[1024*512];
  int bytes_read;
  while ( (bytes_read = read(oldfd, buffer, sizeof(buffer))) > 0) {
    write(newfd, buffer, bytes_read);
  }
  close(oldfd);
  close(newfd);
}


static bool my_file_exists(const char *pathname) {
  struct stat mystats;
  bool result = my_lstat(pathname, &mystats) != -1;
  debug("my_file_exists(\"%s\")=%d\n", pathname, result);
  // If we can lstat it at all, it exists.  Note that this really only
  // checks if the *symlink* exists, not what it points to.
  return my_lstat(pathname, &mystats) != -1;
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
#define WHITELIST_PREFIX "/.user-union/.whitelist"
static char whitelist_suffix[] = ".*9%$7";

// Generate whitelist name, return it malloc'ed (caller must free)
// Name must be absolute without the overlay prefix.
static char *gen_whitelist_name(const char *overlay_prefix,
                   const char *name) {
  char *intermediate = concat_dir(WHITELIST_PREFIX, name);
  char *final = concat_dir(overlay_prefix, intermediate);
  free(intermediate);
  debug("gen_whitelist_name(\"%s\",\"%s\")->%s\n", overlay_prefix, name, final);
  return final;
}


// Take pathname and return a pointer to a redirected pathname.
// The returned pointer (if not null) must be free()d by caller.
// If it's not to be redirected, return NULL.

static char *redir_name(const char *pathname, int use) {
  char *canonicalized_pathname;
  bool overlay_region = false;
  bool is_overlay = false;
  char *best_match;
  int  len, best_match_len;
  char *overlay_prefix, *underlay_prefix;
  char *overlay_name;   // Will be allocated.
  char *underlay_name;  // Will be allocated.
  struct branch *branch;
  struct stringlist *mystringlist;
  bool is_whitelisted;
  char *whitelist_name;
  char *whitelist_name_full;
  bool is_at = false;
  int  at_fd;

  debug("redir_name begin: path=%s usage=%d\n", pathname, use);

  if (!pathname) return NULL; // Shouldn't happen.

  // If the special "override_prefix" is present, and we're using it,
  // return immediately.  This helps us guard against intercepting the
  // same pathname multiple times (in most cases it doesn't matter,
  // but this seems safer).
  if (use_override_prefix && within(pathname, override_prefix))
    return NULL;

  // Extract the primary use.  The "use" parameter is int,
  // not type "usage_t", because "use" is an OR'ed value that
  // combines both usage_t and the file descriptor to be used
  // in an "at" function.  We'll change "use" so it's just the primary use,
  // and set "is_at" and "at_fd" as appropriate.
  if (use & IS_AT_FLAG) {
    is_at = true;
    at_fd = GET_FD(use);
    use &= USAGE_T_MASK;
  }

  // If use is "SKIP_UNSLASHED", and there's no slash in the pathname,
  // don't bother to do lots of calculations.  We'll just use what we got.
  if (use == SKIP_UNSLASHED) {
    if (!strchr(pathname, '/'))
      return NULL;
    else 
      use = READ;
  }

  // Initialize, in case we haven't already:
  // if (!branchlist) initialize_branchlist();
  initialize_if_needed();

  // Canonicalize pathname - force it to absolute (not relative) name.
  // TODO: If we're given relative name, *AND* we have an *at function,
  // we should use the *at function's file descriptor as the starting point.
  // Use "is_at" and "at_fd".
  if (pathname[0] == '/') {
    canonicalized_pathname = strdup(pathname);
  } else {
    char current_directory[BIGBUF];
    int len;
    // FIXME - if error or overflow!:
    getcwd(current_directory, sizeof(current_directory));
    len = strlen(current_directory);
    current_directory[len + 1] = '\0'; /* FIXME: Buffer overflow */
    current_directory[len] = '/';
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
  // If overlay_prefix is true, set is_overlay and overlay_prefix.
  overlay_region = false;
  overlay_prefix = underlay_prefix = NULL;
  best_match = NULL;
  best_match_len = -1;
  // debug("Looking for best match to %s\n", canonicalized_pathname); 
  for (branch = branchlist; branch; branch = branch->next) {
    // debug("Comparing with branch %s\n", branch->list->val); 
    if (!(branch->list)) continue;
    if (branch->list->next) { // > 1 string, we have a union.
      // debug(" Examining union beginning %s\n", branch->list->val);
      for (mystringlist = branch->list; mystringlist;
           mystringlist = mystringlist->next) {
        // debug("  Examining branch %s\n", mystringlist->val);
        if (within(canonicalized_pathname, mystringlist->val)) {
          len = strlen(mystringlist->val);
          // debug(" len=%d, best_match_len=%d\n", len, best_match_len);
          if (len > best_match_len) {
            // This is better than any previous match, accept it.
            overlay_region = true;
            overlay_prefix = branch->list->val;
            underlay_prefix = branch->list->next->val;
            // debug(" Setting underlay_prefix=%s\n", underlay_prefix);
            best_match_len = len;
            if (mystringlist == branch->list)
              is_overlay = true;
            else {
              is_overlay = false;
            }
            // debug(" Best so far.  overlay_region=%d, is_overlay=%d, overlay_prefix=%s, underlay_prefix=%s\n", overlay_region, is_overlay, overlay_prefix, underlay_prefix);
          }
        }
      }
    } else { // Non-union
      // debug(" Examining non-union %s\n", branch->list->val);
      if (within(canonicalized_pathname, branch->list->val)) {
        len = strlen(branch->list->val);
        if (len > best_match_len) {
          // This is better than any previous match, accept it.
          overlay_region = false;
          best_match_len = len;
          // debug(" Best so far.  overlay_region=%d\n", overlay_region);
        }
      }
    }
  }
  debug("redir_name: For canonicalized_pathname=%s, overlay_region=%d, is_overlay=%d, overlay_prefix=%s, underlay_prefix=%s\n", canonicalized_pathname, overlay_region, is_overlay, overlay_prefix, underlay_prefix);

  // TODO: Don't allocate canonicalized_pathname if we don't have to;
  // then, free it only if it got allocated.
  // That way we can speed absolute filenames that aren't redirected.

  if (!overlay_region) {
    free(canonicalized_pathname);
    debug("redir_name returning NULL undirected %s\n", pathname);
    return NULL; // Don't redirect.
  }

  if (is_overlay) {
    overlay_name = canonicalized_pathname;
    // Here we have to guess the intended underlay name if >1 underlay
    debug("Hmm. underlay_prefix=%s, canon pathname-overlay prefix=%s\n",
      underlay_prefix, canonicalized_pathname + strlen(overlay_prefix));
    underlay_name = concat_dir(underlay_prefix,
                     canonicalized_pathname + skip(overlay_prefix));
    whitelist_name = gen_whitelist_name(overlay_prefix,
                     canonicalized_pathname + skip(overlay_prefix));
  } else {
    underlay_name = canonicalized_pathname;
    overlay_name = concat_dir(overlay_prefix,
                     canonicalized_pathname + skip(underlay_prefix));
    whitelist_name = gen_whitelist_name(overlay_prefix,
                     canonicalized_pathname + skip(underlay_prefix));
  }

  // Whitelist handling.
  whitelist_name_full = malloc(strlen(whitelist_name) + strlen(whitelist_suffix) + 1);
  whitelist_name_full = concat(whitelist_name, whitelist_suffix);
  // If we are supposed to whitelist the pathname, let's do so.
  if (use == WHITELIST ) {
    // Create a whitelist entry for the overlay pathname
    int result;
    if (my_file_exists(overlay_name)) {
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
    return NULL;
  } else if (use == UNWHITELIST ) {
    if (my_file_exists(whitelist_name_full)) {
      my_unlink(whitelist_name_full);
    }
    free(whitelist_name);
    free(whitelist_name_full);
    free(overlay_name);
    free(underlay_name);
    return NULL;
  }
  // Determine if the file is whitelisted (marked as "deleted from underlay").
  // Invariant: If the file is whitelisted, it is *NOT* present in the
  // overlay. Thus, whitelisted files should be redirected to
  // the *overlay*, so that the wrapped functions will correctly report that
  // they don't exist.
  is_whitelisted = my_file_exists(whitelist_name_full);
  free(whitelist_name);
  free(whitelist_name_full);

  debug("redir_name.  Overlay=%s  Underlay=%s\n", overlay_name, underlay_name);

  if (use == READ) { // Read-only filesystem object (simple override)
    if (is_whitelisted || my_file_exists(overlay_name)) {
      free(underlay_name);
      debug("redir_name 11 returning overlay name %s\n", overlay_name);
      return prepend_override_prefix(overlay_name);
    } else {
      free(overlay_name);
      debug("redir_name 12 returning underlay name %s\n", underlay_name);
      return prepend_override_prefix(underlay_name);
    }
  } else if (use == PREFER_UNDERLAY) { // Like READ but use underlay if exists.
    if (!is_whitelisted && my_file_exists(underlay_name)) {
      free(overlay_name);
      debug("redir_name 12 returning underlay name %s\n", underlay_name);
      return prepend_override_prefix(underlay_name);
    } else {
      free(underlay_name);
      debug("redir_name 11 returning overlay name %s\n", overlay_name);
      return prepend_override_prefix(overlay_name);
    }
  } else if (use == EXCLUSIVE) { // Exclusively-create filesystem object:
    debug("O_EXCL!\n");
    if (my_file_exists(overlay_name)) {
      // It exists in overlay. Return the overlay name, it'll fail.
      debug("Overlay already exists!\n");
      free(underlay_name);
      debug("redir_name 21 returning underlay name %s\n", overlay_name);
      return prepend_override_prefix(overlay_name);
    } else if (!is_whitelisted && my_file_exists(underlay_name)) {
      // It exists in underlay. Return the underlay name, it'll fail.
      debug("Underlay already exists!\n");
      free(overlay_name);
      debug("redir_name 22 returning underlay name %s\n", underlay_name);
      return prepend_override_prefix(underlay_name);
    } else {
      // Return the overlay name, because we can only create things there.
      debug("Doesn't exist in underlay or overlay (and that's good)!\n");
      make_parents(overlay_name, underlay_name, overlay_prefix, underlay_prefix);
      free(underlay_name);
      debug("redir_name 23 returning overlay name %s\n", overlay_name);
      return prepend_override_prefix(overlay_name);
    }
  } else if (use == SWITCH_UNDERLAY) {
    // If given overlay name, forceably switch to underlay
    // whether it exists or not.  This is different from PREFER_UNDERLAY,
    // which only returns the underlay name if it exists.
    // Do *NOT* prepend the override prefix, we need the original name.
    debug("SWITCH_UNDERLAY!\n");
    if (is_overlay) {
      free(overlay_name);
      debug("redir_name 55 returning underlay name %s\n", underlay_name);
      return underlay_name;
    }
    else {
      free(overlay_name);
      free(underlay_name);
      debug("redir_name 56 returning NULL, interp as %s\n", pathname);
      return NULL;
    }
  } else if (use == OPENDIR) {
    // Create a new directory that mirrors
    // whether it exists or not.  This is different from PREFER_UNDERLAY,
    // which only returns the underlay name if it exists.
    debug("OPENDIR!\n");
    char *new_directory;
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
    free(overlay_name);
    free(underlay_name);
    debug("redir_name 70 returning underlay name %s\n", underlay_name);
    return NULL;
  } else if (use == WRITE) { // Write (and maybe read) filesystem object
    debug("read-write!\n");
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
       my_mkdir(overlay_name, underlay_mode & 0777);
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
        return prepend_override_prefix(underlay_name);
      }
    } else {
       debug("Just making parents, if necessary.\n");
       make_parents(overlay_name, underlay_name, overlay_prefix, underlay_prefix);
    }
    free(underlay_name);
    debug("redir_name 16 returning overlay name %s\n", overlay_name);
    return prepend_override_prefix(overlay_name);
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
    return prepend_override_prefix(overlay_name);
  } else {
    fprintf(stderr, "FAIL, unknown use value %d\n", use);
    exit(1);
  }
}


// Quickly calculate euidaccess as if we're root.
// If the file exists somewhere, we'll return 0; else return -1.
static int my_overlay_euidaccess(const char *path) {
  char *new_path = redir_name(path, READ);
  bool exists;
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

// Create a simple function that returns a value, WITHOUT chaining
// down to lower-level functions.  Useful for geteuid(), etc.
#define BASIC_RETURNS(RETURNTYPE, NAME, PARAMETER_TYPES, RESULT)            \
RETURNTYPE NAME PARAMETER_TYPES {                                           \
  return RESULT;                                                            \
}
#define RETURNS(RETURNTYPE, NAME, PARAMETER_TYPES, RESULT)                  \
BASIC_RETURNS(RETURNTYPE, NAME, PARAMETER_TYPES, RESULT)                    \
BASIC_RETURNS(RETURNTYPE, _##NAME, PARAMETER_TYPES, RESULT)                 \
BASIC_RETURNS(RETURNTYPE, __##NAME, PARAMETER_TYPES, RESULT)

// Create a "wrapper", that is, a function with the given NAME that
// intercepts a request, changes the filenames (etc.), and then calls
// the chaining function to perform the rest of the action.
// One parameter must be named "path"; that's the filename to be
// redirected.  The "USAGE" says if it's READ, WRITE, etc.
#define NORMAL_WRAPPER(RETURNTYPE, NAME, PARAMETER_TYPES, ARGUMENTS, USAGE, AFTER) \
RETURNTYPE NAME PARAMETER_TYPES {                                           \
  RETURNTYPE result;                                                        \
  char *new_pathname;                                                       \
  debug("Intercepted " #NAME "\n");                                         \
  new_pathname = redir_name(path, USAGE);                                   \
  if (new_pathname) path = new_pathname;                                    \
  result = real_##NAME ARGUMENTS;                                           \
  AFTER ;                                                                   \
  if (new_pathname) free(new_pathname);                                     \
  debug("Finished wrapped version of " #NAME "\n");                         \
  return result;                                                            \
}

// Create a 2-parameter "wrapper" for name NAME.
// The parameters to be changed *must* be "path" and "path2".
// We use "path" (not "path1") so that the chain function can easily
// output it for debugging purposes.
#define TWO_NORMAL_WRAPPER(RETURNTYPE, NAME, PARAMETER_TYPES, ARGUMENTS,    \
                    USAGE1, USAGE2, AFTER)                                  \
RETURNTYPE NAME PARAMETER_TYPES {                                           \
  RETURNTYPE result;                                                        \
  char *new_pathname;                                                       \
  char *new_pathname2;                                                      \
  debug("Intercepted " #NAME "\n");                                         \
  new_pathname = redir_name(path, USAGE1);                                  \
  new_pathname2 = redir_name(path2, USAGE2);                                \
  if (new_pathname) path = new_pathname;                                    \
  if (new_pathname2) path2 = new_pathname2;                                 \
  result = real_##NAME ARGUMENTS;                                           \
  AFTER ;                                                                   \
  if (new_pathname) free(new_pathname);                                     \
  if (new_pathname2) free(new_pathname2);                                   \
  debug("Finished wrapped version of " #NAME "\n");                         \
  return result;                                                            \
}


// Wrap "open".  This is special; open takes either 2 *OR* 3 parameters;
// so declaring external functions with 3 arguments will
// cause warnings/errors.  Instead, we accept 2, but
// always pass on 3 (it's simpler, that way the real_open style
// functions don't need to use va_start and friends).
#define OPEN_WRAPPER(NAME, PARAMETER_TYPES, ARGUMENTS, USAGE) \
int NAME PARAMETER_TYPES {                                                  \
  int result;                                                               \
  mode_t mode;                                                              \
  va_list ap;                                                               \
  char *new_pathname;                                                       \
                                                                            \
  if (flags & O_CREAT) {                                                    \
    va_start(ap, flags);                                                    \
    mode = va_arg(ap, int);                                                 \
    va_end(ap);                                                             \
  } else {                                                                  \
    mode = 0;                                                               \
  }                                                                         \
  debug("Intercepted open(\"%s\",0%o,0%o)\n", path, flags, mode);           \
  new_pathname = redir_name(path, USAGE);                                   \
  if (new_pathname) path = new_pathname;                                    \
  result = real_##NAME ARGUMENTS ;                                          \
  unwhitelist_if_error_free(result >= 0, path);                             \
  if (new_pathname) free(new_pathname);                                     \
  debug("Finished wrapped version of " #NAME "\n");                         \
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

// Normal wrap - wrap up NAME, _NAME, and __NAME.
#define WRAP(RETURNTYPE, NAME, SYMBOL, PARAMETER_TYPES, ARGUMENTS, USAGE, AFTER) \
BASIC_WRAP(RETURNTYPE, NAME, SYMBOL, PARAMETER_TYPES, ARGUMENTS, USAGE, AFTER) \
BASIC_WRAP(RETURNTYPE, _##NAME, _##SYMBOL, PARAMETER_TYPES, ARGUMENTS, USAGE, AFTER) \
BASIC_WRAP(RETURNTYPE, __##NAME, __##SYMBOL, PARAMETER_TYPES, ARGUMENTS, USAGE, AFTER)

// Two-parameter wrap
#define TWO_WRAP(RETURNTYPE, NAME, SYMBOL, PARAMETER_TYPES, ARGUMENTS, USAGE1, USAGE2, AFTER) \
TWO_BASIC_WRAP(RETURNTYPE, NAME, SYMBOL, PARAMETER_TYPES, ARGUMENTS, USAGE1, USAGE2, AFTER) \
TWO_BASIC_WRAP(RETURNTYPE, _##NAME, _##SYMBOL, PARAMETER_TYPES, ARGUMENTS, USAGE1, USAGE2, AFTER) \
TWO_BASIC_WRAP(RETURNTYPE, __##NAME, __##SYMBOL, PARAMETER_TYPES, ARGUMENTS, USAGE1, USAGE2, AFTER)

// Wrap 64-bit version; like WRAP, but also do it for NAME ## 64.
#define WRAP64(RETURNTYPE, NAME, SYMBOL, PARAMETER_TYPES, ARGUMENTS, USAGE, AFTER) \
WRAP(RETURNTYPE, NAME, SYMBOL, PARAMETER_TYPES, ARGUMENTS, USAGE, AFTER) \
WRAP(RETURNTYPE, NAME##64, SYMBOL##64, PARAMETER_TYPES, ARGUMENTS, USAGE, AFTER)

// Like BASIC_WRAP, but for open() which takes a varying # of parameters.
#define BASIC_OPEN_WRAP(NAME, PARAMETER_TYPES, PARAMETER_TYPES_ALL, ARGUMENTS, USAGE) \
CHAIN(int, NAME, PARAMETER_TYPES_ALL, ARGUMENTS, NAME) \
OPEN_WRAPPER(NAME, PARAMETER_TYPES, ARGUMENTS, USAGE)

#define OPEN_WRAP(NAME, PARAMETER_TYPES, PARAMETER_TYPES_ALL, ARGUMENTS, USAGE) \
BASIC_OPEN_WRAP(NAME, PARAMETER_TYPES, PARAMETER_TYPES_ALL, ARGUMENTS, USAGE) \
BASIC_OPEN_WRAP(_##NAME, PARAMETER_TYPES, PARAMETER_TYPES_ALL, ARGUMENTS, USAGE) \
BASIC_OPEN_WRAP(__##NAME, PARAMETER_TYPES, PARAMETER_TYPES_ALL, ARGUMENTS, USAGE)

#define OPEN_WRAP64(NAME, PARAMETER_TYPES, PARAMETER_TYPES_ALL, ARGUMENTS, USAGE) \
OPEN_WRAP(NAME, PARAMETER_TYPES, PARAMETER_TYPES_ALL, ARGUMENTS, USAGE) \
OPEN_WRAP(NAME##64, PARAMETER_TYPES, PARAMETER_TYPES_ALL, ARGUMENTS, USAGE)


// Helper functions for the wrappers
static void whitelist_if_error_free(int result, const char *path) {
  if (result == 0) {
    char *s = redir_name(path, WHITELIST);
    if (s) free(s);
  }
}

static void unwhitelist_if_error_free(int result, const char *path) {
  if (result == 0) {
    char *s = redir_name(path, UNWHITELIST);
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


WRAP(int, access, access, (const char *path, int mode), (path, mode), READ,)

WRAP64(int, faccessat, faccessat, \
     (int dirfd, const char *path, int mode, int flags), \
     (dirfd, path, mode, flags), READ|AT(dirfd),)
WRAP64(int, newfstatat, newfstatat,
      (int dirfd, char *path, struct stat *buf, int flag),
      (dirfd, path, buf, flag), READ|AT(dirfd),)

WRAP(int, mkdir, mkdir, (const char *path, mode_t mode), \
                 (path, mode), EXCLUSIVE, \
                 unwhitelist_if_error_free(result, path))
WRAP(int, mkdirat, mkdirat, (int dirfd, const char *path, mode_t mode), \
                 (dirfd, path, mode), EXCLUSIVE|AT(dirfd), \
                 unwhitelist_if_error_free(result, path))

WRAP(int, rmdir, rmdir, (const char *path), \
                 (path), WRITE, whitelist_if_error_free(result, path))

// Pretend that we have an effective UID of root.
// That way, tools that first check to see if we have permission to do
// something (like rm) will quickly decide that we do have permission.

RETURNS(uid_t, geteuid, (void), 0)
RETURNS(int, euidaccess, (const char *path, int mode), \
        my_overlay_euidaccess(path))
RETURNS(int, eaccess, (const char *path, int mode), \
        my_overlay_euidaccess(path))



// We'll make chdir prefer to return the *underlay* name.
// That way, whenever the abstraction leaks, the current directory (etc.)
// will be the "expected" directory in the underlay.
// Note that this is merely *preferred* - if a user creates new directories,
// we may still need to set the current directory to be a value inside
// the overlay.
WRAP(int, chdir, chdir, (const char *path), (path), PREFER_UNDERLAY,)


WRAP(ssize_t, readlink, readlink, (const char *path, char *buf, size_t bufsiz), (path, buf, bufsiz), READ,)
WRAP(ssize_t, readlinkat, readlinkat, (int dirfd, const char *path, char *buf, size_t bufsiz), (dirfd, path, buf, bufsiz), READ|AT(dirfd),)

// "symlink" gets wrapped specially.
// If old path is an absolute pathname inside the overlay, we'll
// change it to be an absolute value in the underlay; otherwise,
// we leave it unchanged.  That way, if a routine learns of
// the underlay's location, and uses it to calculate a symlink,
// the symlink will still be correct.
TWO_WRAP(int, symlink, symlink, (const char *path, const char *path2), \
       (path, path2), SWITCH_UNDERLAY, EXCLUSIVE, \
       unwhitelist_if_error_free(result, path2))
TWO_WRAP(int, symlinkat, symlinkat, (const char *path, int newdfd, const char *path2), \
       (path, newdfd, path2), SWITCH_UNDERLAY, EXCLUSIVE|AT(newdfd), \
       unwhitelist_if_error_free(result, path2))

// We can't link across filesystems, so on some environments this will fail:
TWO_WRAP(int, link, link, (const char *path, const char *path2), \
       (path, path2), READ, EXCLUSIVE, \
       unwhitelist_if_error_free(result, path2))
TWO_WRAP(int, linkat, linkat,
 (int olddirfd, const char *path, int newdirfd, const char *path2, int flags), \
 (olddirfd, path, newdirfd, path2, flags), READ|AT(olddirfd), EXCLUSIVE|AT(newdirfd), \
       unwhitelist_if_error_free(result, path2))

TWO_WRAP(int, rename, rename, (const char *path, const char *path2), \
       (path, path2), WRITE, EXCLUSIVE, whitelist_if_error_free(result, path); \
       unwhitelist_if_error_free(result, path2))

TWO_WRAP(int, renameat, renameat, (int olddirfd, const char *path, int newdirfd, const char *path2), (olddirfd, path, newdirfd, path2), WRITE|AT(olddirfd), EXCLUSIVE|AT(newdirfd), whitelist_if_error_free(result, path) ; \
       unwhitelist_if_error_free(result, path2))


WRAP(int, utime, utime, (const char *path, const struct utimbuf *times),
     (path, times), WRITE,)
WRAP(int, utimes, utimes, (const char *path, const struct timeval times[2]),
     (path, times), WRITE,)

WRAP(int, chmod, chmod, (const char* path, mode_t mode), \
     (path, mode), WRITE,)

WRAP(DIR *, opendir, opendir, (const char* path), (path), OPENDIR,)
// It's not clear how to handle fdopendir().

// TODO: Should we handle chown, lchown, fchown differently?
// E.G., perhaps ignore errors?  For now, they're passed through as-is.
// fchown isn't wrapped, because it has no path.

WRAP(int, chown, chown, (const char* path, uid_t owner, gid_t group), \
     (path, owner, group), WRITE,)
WRAP(int, lchown, lchown, (const char* path, uid_t owner, gid_t group), \
     (path, owner, group), WRITE,)

WRAP64(int, unlink, unlink, (const char* path), (path), EXIST, whitelist_if_error_free(result>=0, path))
WRAP64(int, unlinkat, unlinkat, (int dirfd, const char* path, int flags), (dirfd, path, flags), EXIST|AT(dirfd), whitelist_if_error_free(result>=0,path))


// We can only create SOME kinds of nodes, but we can try.
WRAP(int, mknod, mknod, (const char* path, mode_t mode, dev_t dev), \
     (path, mode, dev), WRITE, \
       unwhitelist_if_error_free(result>=0, path))
// This is probably implemented with mknod, but we'll specially wrap it
// no matter what.
WRAP(int, mkfifo, mkfifo, (const char* path, mode_t mode), \
     (path, mode), WRITE, \
       unwhitelist_if_error_free(result>=0, path))



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


#if defined(__linux__)

// Special stuff to handle GNU C library.
// Technically, that's not the same as __linux__.

// GNU C library doesn't normally let us redirect its internal
// calls to open(), etc., so we have to wrap functions like fopen() ourselves:
#define WRAP_USERS 1

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


#endif


#ifdef WRAP_USERS

// Many platforms require us to wrap other C library routines that
// depend on lower-level routines, so we must wrap fopen(), etc.

// For example, the default GNU C library install will
// not normally let us override the open() inside fopen, so we must
// do it ourselves.

WRAP(FILE *, fopen,   fopen,   (const char *path, const char *mode), \
                    (path, mode), use_fopen(mode), unwhitelist_if_error_free(result!=NULL, path))

WRAP(FILE *, freopen, freopen, \
       (const char *path, const char *mode, FILE *stream), \
                     (path, mode, stream), use_fopen(mode),unwhitelist_if_error_free(result!=NULL, path))

WRAP64(int, creat, creat, \
      (const char *path, mode_t mode), (path, mode), WRITE, \
       unwhitelist_if_error_free(result>=0, path))


// FIXME: "SKIP_UNSLASHED" should work *most* of the time, but
// it doesn't *exactly* capture the right semantics.  Should define
// special modes for each type of use (dl*, exec*) and do the path-like
// searching specially.

WRAP(void *, dlopen, dlopen, (const char *path, int flag), (path, flag), \
  SKIP_UNSLASHED,)

WRAP(int, execve, execve, \
     (const char* path, char* const argv[], char* const envp[]), \
     (path, argv, envp), SKIP_UNSLASHED,)
WRAP(int, execv, execv, (const char *path, char *const argv[]), \
       (path, argv), SKIP_UNSLASHED,)
WRAP(int, execvp, execvp, (const char *path, char *const argv[]), \
       (path, argv), SKIP_UNSLASHED,)

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

MAKE_MY_FUNCTION(DIR *, opendir, (const char *path), (path))


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

