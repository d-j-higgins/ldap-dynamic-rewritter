#!/bin/bash

(
SCRIPTDIR=`readlink -f \`dirname $0\``
cd $SCRIPTDIR

log=/var/log/ldap-rewrite.log
while true; do ./bin/ldap-rewrite.pl  | tee -a $log; done
)&

echo $! > /tmp/ldap-rewriter.pid
