#!/bin/sh

dir="/srv/virtual-ldap"
pid="/tmp/ldap-rewrite.pid"

case "$1" in
	start)
		su -c "cd $dir && ./bin/ldap-rewrite.pl" dpavlin &
		echo $! > $pid
		;;
	stop)
		kill `cat $pid`
	;;
	*)
		exit 3
	;;
esac

