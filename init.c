#include <stdio.h>
#include <stdlib.h>
#include "user-union.h"
#include "init.h"

// Set up branches by reading in the environment variable.
struct branch *create_branchlist(char *whitelist_prefix, int wp_len,
    int *r_num_br)
{
  char *endp;
  int i, j, cnt, num_branches;
  struct branch *current_branch, *branchlist;
  char var_name[128];
  char *str;

  str = getenv("USER_UNION_PRIV_DIR");
  if (!str || (str[0] == '\0')) {
    fprintf(stderr,
         "user-union: Warning. Environment variable USER_UNION_PRIV_DIR not set.\n");
    return NULL;
  }
  snprintf(whitelist_prefix, wp_len, "%s/whitelist", str);

  str = getenv("USER_UNION_DEBUG");
  if (str && str[0]) {
    cnt = strtol(str, &endp, 10);
    if (*endp) {
      fprintf(stderr,
         "user-union: Warning. Environment variable USER_UNION_DEBUG=%s wrong.\n",
         str);
    } else {
      debug_level = cnt;
    }
  }

  str = getenv("USER_UNION_CNT");
  if (!str || (str[0] == '\0')) {
    fprintf(stderr,
         "user-union: Warning. Environment variable USER_UNION_CNT not set.\n");
    return NULL;
  }
  cnt = strtol(str, &endp, 10);
  if (*endp) {
    fprintf(stderr,
         "user-union: Warning. Environment variable USER_UNION_CNT=%s wrong.\n",
         str);
    return NULL;
  }

  branchlist = malloc(sizeof(struct branch) * cnt);
  num_branches = cnt;
  for (i = 0; i < cnt; i++) {
    int undl_cnt;
    current_branch = branchlist + i;
    snprintf(var_name, sizeof(var_name), "USER_UNION_%i_OVERLAY", i);
    str = getenv(var_name);
    if (!str || !str[0])
      current_branch->overlay = NULL;
    else
      current_branch->overlay = str;

    snprintf(var_name, sizeof(var_name), "USER_UNION_%i_MOUNT_POINT", i);
    str = getenv(var_name);
    if (!str || !str[0]) {
      fprintf(stderr,
         "user-union: FATAL. Environment variable %s not set.\n", var_name);
      exit(1);
    }
    current_branch->mount_point = str;

    snprintf(var_name, sizeof(var_name), "USER_UNION_%i_MATCH_DEPTH", i);
    str = getenv(var_name);
    if (!str || !str[0]) {
      current_branch->match_depth = -1;
    } else {
      cnt = strtol(str, &endp, 10);
      if (*endp) {
        fprintf(stderr,
           "user-union: FATAL. Environment variable %s=%s wrong.\n",
           var_name, str);
        exit(1);
      }
      current_branch->match_depth = cnt;
    }

    snprintf(var_name, sizeof(var_name), "USER_UNION_%i_UNDERLAY_CNT", i);
    str = getenv(var_name);
    if (!str || !str[0]) {
      current_branch->num_underlays = 0;
      current_branch->underlay = NULL;
      continue;
    }
    undl_cnt = strtol(str, &endp, 10);
    if (*endp) {
      fprintf(stderr,
         "user-union: FATAL. Environment variable %s=%s wrong.\n",
         var_name, str);
      exit(1);
    }

    current_branch->underlay = malloc(sizeof(char*) * undl_cnt);
    current_branch->num_underlays = undl_cnt;
    for (j = 0; j < undl_cnt; j++) {
      snprintf(var_name, sizeof(var_name), "USER_UNION_%i_UNDERLAY_%i", i, j);
      str = getenv(var_name);
      if (!str || !str[0]) {
        fprintf(stderr,
           "user-union: FATAL. Environment variable %s not set.\n", var_name);
        exit(1);
      }
      current_branch->underlay[j] = str;
    }
  }
  // Complete.
#ifdef DEBUG
  debug("Completed setting branchlist.  Results:\n");
  for (i = 0; i < num_branches; i++) {
    current_branch = branchlist + i;
    debug("Branch:\n");
    debug("  Overlay: %s\n", current_branch->overlay);
    debug("  Mount point: %s\n", current_branch->mount_point);
    for (j = 0; j < current_branch->num_underlays; j++) {
      debug("  Underlay: %s\n", current_branch->underlay[j]);
    }
  }
#endif
  *r_num_br = num_branches;
  return branchlist;
}
