#!/bin/sh

dir="/opt/LDAP-rewriter"
pid="/tmp/ldap-rewrite.pid"

case "$1" in
	start)
		su -c "cd $dir && ./start.sh"  nobody
		;;
	stop)
		su -c "cd $dir && ./stop.sh"  nobody
	;;
	*)
		exit 3
	;;
esac

