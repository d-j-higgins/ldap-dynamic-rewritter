select
	concat('cn=',c.categorycode,',ou=',c.categorycode,',dc=ffzg,dc=hr')	as dn,
	'group'				as objectClass,
	c.categorycode			as ou,
	c.categorycode			as cn,
	description			as description,

	concat('uid=',replace(userid,'@ffzg.hr',''),',ou=',c.categorycode,',dc=ffzg,dc=hr') as members
from categories c
join borrowers b on b.categorycode = c.categorycode
where length(userid) > 0
