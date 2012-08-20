#!/usr/bin/perl

use warnings;
use strict;

use Test::More tests => 76;
use Data::Dump qw(dump);

BEGIN {
	use_ok 'Net::LDAP';
}

our $config;
ok( require( ( shift @ARGV || 't/config.pl' ) ), 'config.pl' );

diag "config ",dump($config);

sub ldap_check_error {
	my $o = shift;
	ok( ! $o->code, 'no errror' );
	diag $o->error if $o->code;
}

ok( my $ldap = Net::LDAP->new( $ENV{LISTEN} || 'localhost:2389' ), 'new Net::LDAP' );

ok( my $bind = $ldap->bind, 'bind' );
ldap_check_error $bind;

sub check_search_attributes {
	my $search = shift;

	foreach my $entry ( $search->entries ) {
		diag dump $entry;
		map { ok( $_, "attribute $_" ) } grep { /^\Q$_\E$/i } $entry->attributes;
	}
}

sub search {
	my ($ldap,$search) = @_;
	ok( my $result = $ldap->search( filter => $search ), "search $search" );
	ldap_check_error $result;
	ok( $result->entries, 'have results' );
	return $result;
}

foreach my $search ( qw/
uid=dpavlin@ffzg.hr
pager=E00401001F77E218
/ ) {
	my $entries = search $ldap => $search;
	check_search_attributes $entries => 'uid', 'mail', 'pager', 'memberOf';

	$entries = search $ldap => "(&(objectclass=HrEduPerson)($search))";
	check_search_attributes $entries => 'uid', 'mail', 'pager', 'memberOf';
}

search $ldap => $_ foreach ( qw/
objectclass=organizationalUnit
objectclass=group
/ );

ok( $ldap->unbind, 'unbind' );
