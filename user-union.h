#ifndef USER_UNION_H
#define USER_UNION_H

// Branch handling - we need to know how to handle directories.
// This data comes from environment variable USER_UNION.
// This structure is actually more than we strictly need; I have hopes
// to eventually expand the code to support multiple overlays, and
// this structure supports that.

struct branch {
  char *overlay;
  char **underlay;
  int num_underlays;
  char *mount_point;
  int match_depth;
};

extern int debug_level;
#define debug(...) do if (debug_level) fprintf(stderr, "user-union: " __VA_ARGS__); \
    while (0)

#endif
