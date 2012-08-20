#!/usr/bin/perl

use warnings;
use strict;

use Test::More tests => 9;
use Data::Dump qw(dump);

BEGIN {
	use_ok 'Net::LDAP';
}

our $config;
ok( require( ( shift @ARGV || 't/config.pl' ) ), 'config.pl' );

sub ldap_check_error {
	my $o = shift;
	ok( ! $o->code, 'no errror' );
	diag $o->error if $o->code;
}

ok( my $ldap = Net::LDAP->new( $config->{server} ), 'new Net::LDAP ' . dump( $config->{server} ) );

ok( my $bind = $ldap->bind( $config->{bind_as}, password => $config->{password} ), 'bind ' . $config->{bind_as} );
ldap_check_error $bind;

ok( my $search = $ldap->search( %{ $config->{search} } ), 'search ' . dump( $config->{search} ) );
ldap_check_error $search;

foreach my $entry ( $search->entries ) {

#	diag dump $entry;
	$entry->dump;

	my $missing = 0;
	my @required = @{ $config->{attributes_required} };
	foreach my $attr ( @required ) {
		next if grep { /^\Q$attr\E$/i } $entry->attributes;
		$missing++;
		diag "$missing missing $attr\n";
	}

	ok( ! $missing, "attributes " . dump( @required ) );
}

ok( $ldap->unbind, 'unbind' );
