#!/bin/bash
FILE=/tmp/ldap-rewriter.pid

kill -15 `cat $FILE`
