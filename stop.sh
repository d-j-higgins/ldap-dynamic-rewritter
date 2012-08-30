#!/bin/bash
FILE=/tmp/ldap-rewriter.pid

PGID=$(ps -o 'pgid'  -p`cat $FILE`| tail -1)

kill -15 -$PGID
