
select
	concat('ou=',c.categorycode,',dc=ffzg,dc=hr')	as dn,
	'organizationalunit'		as objectClass,
	c.categorycode			as ou,
	c.description			as description,
	-- fake for SafeQ, we don't have numeric primary key
	crc32(categorycode) % 1000	as objectGUID
from categories c

