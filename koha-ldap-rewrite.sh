cd /srv/virtual-ldap/
log=log/koha-ldap-rewrite.log 
test -f $log && mv $log $log.`date +%Y-%m-%dT%H%M%S`
( ./bin/ldap-rewrite.pl 2>&1 ) | tee -a $log
