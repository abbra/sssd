#!/bin/sh

. $CWRAP_TEST_SRCDIR/cwrap_test_setup.sh

exec ./become_user-tests "$@"
