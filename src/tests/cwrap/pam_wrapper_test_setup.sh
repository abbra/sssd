#!/bin/bash

pam_wrapper_libs=$(pkg-config --libs pam_wrapper)

export LD_PRELOAD="$LD_PRELOAD $pam_wrapper_libs"
if [ -z $pam_wrapper_libs ]; then
    echo "Cannot locate cwrap libraries"
    exit 2
fi

export PAM_WRAPPER=1
export PAM_WRAPPER_CONFDIR=$(pwd)/pam_services
