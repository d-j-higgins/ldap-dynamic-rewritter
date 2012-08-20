cd /srv/virtual-ldap/
log=log/safeq-ldap-koha.log 
test -f $log && mv $log $log.`date +%Y-%m-%dT%H%M%S`
( MAX_RESULTS=10 ./bin/ldap-koha.pl 10.60.0.13:2389 2>&1 ) | tee -a $log
