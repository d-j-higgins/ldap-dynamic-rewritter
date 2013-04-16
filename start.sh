#!/bin/bash

FILE="/tmp/ldap-rewriter.pid";

        (
         SCRIPTDIR=`readlink -f \`dirname $0\``
         cd $SCRIPTDIR

         log=./main-ldap-rewrite.log
         while true; do ./bin/ldap-rewrite.pl  | tee -a $log; done
        )&

# store pid and programgroup pid (as negative)
spid=$!
pgid=$(ps -p $spid  -o pgid="" | awk '{print $1}')
echo $spid -$pgid > $FILE
cat $FILE
