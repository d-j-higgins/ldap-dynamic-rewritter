
select
	concat('uid=',trim(userid),',ou=',categorycode,',dc=ffzg,dc=hr')	as dn,
	'person
	organizationalPerson
	inetOrgPerson
	hrEduPerson'					as objectClass,

	trim(userid)					as uid,
	firstname					as givenName,
	surname						as sn,
	concat(firstname,' ',surname)			as cn,

	-- SAFEQ specific mappings from UMgr-LDAP.conf
	b.borrowernumber					as objectGUID,
	surname						as displayName,
	a.attribute					as pager,
	email						as mail,
	categorycode					as memberOf,
	categorycode					as ou,
	categorycode					as department,
	concat('/home/',b.borrowernumber)			as homeDirectory
from borrowers b
left join borrower_attributes a on b.borrowernumber = a.borrowernumber and code='RFID_SID'



