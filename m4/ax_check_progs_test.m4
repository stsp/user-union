# Define helper macro:
#   AC_CHECK_PROGS_TEST(variable_set,list_of_alternative_commands,command_test)
# This is provided a list of alternative commands (with arguments);
# each is tested in turn, and the result is stored in variable_set.

m4_define([AX_CHECK_PROGS_TEST],[
if test -z "${$1}" ; then
  result=''
  for try in $2 ; do
    if $3 ; then
      result="$try"
      AC_MSG_RESULT([$result])
      break
    fi
  done
  if test "$result" = '' ; then
    AC_MSG_RESULT([FAILURE])
    echo 'No useful command available' >&2
    exit 1
  fi
  $1="$result"
fi
AC_SUBST([$1])
])
