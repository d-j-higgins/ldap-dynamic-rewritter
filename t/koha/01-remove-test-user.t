#!/usr/bin/perl

use warnings;
use strict;

use Test::More tests => 7;
use Test::WWW::Mechanize;
use XML::Simple;
use Data::Dump qw(dump);

my $url =       $ENV{INTRANET}  || 'http://ffzg.koha-dev.rot13.org:8080';
my $koha_conf = $ENV{KOHA_CONF} || '/etc/koha/sites/ffzg/koha-conf.xml';

my $xml = XMLin( $koha_conf );
diag 'Koha config = ',dump $xml->{config};

ok( $xml->{config}->{useldapserver}, 'useldapserver' );

our $config;
require 't/config.pl';
diag 'test config = ',dump $config;

my $mech = Test::WWW::Mechanize->new;

$mech->get_ok( $url, "intranet $url" );

$mech->submit_form_ok({
	fields => {
		userid   => $xml->{config}->{user},
		password => $xml->{config}->{pass},
	},
}, "login $xml->{config}->{user}");

$mech->submit_form_ok({
	form_number => 2,
	fields => {
		member => $config->{bind_as},
	},
}, 'find patron' );

#diag $mech->content;

$mech->follow_link_ok({ url_regex => qr/moremember/ }, 'details' );

my $html = $mech->content();

if ( $html =~ m{(/cgi-bin/koha/members/deletemem\.pl\?member=\d+)}s ) {
	ok( $1, 'found deletemem' );
	$mech->get_ok( $url . $1 );
}
