use inc::Module::Install;

name        'LDAP-Virtual';
version     '0.00';
license     'GPL';

requires	'IO::Socket::INET';
requires	'Data::Dump';
requires	'YAML';

features(
	'virtual-server.pl (Net::LDAP::Server based)' => [
		-default => 0,
		'Net::LDAP::Server',
		'URI::Escape',
		'File::Slurp',
	],
	'ldap-rewrite.pl' => [
		-default => 1,
		'IO::Select',
		'IO::Socket::SSL',
		'Convert::ASN1',
		'Net::LDAP::ASN',
	],
	't/koha integration tests' => [
		-default => 0,
		'Test::WWW::Mechanize',
	],
);

auto_install;
	
WriteAll;
