#!/usr/bin/perl

use warnings;
use strict;

use Test::More tests => 4;
use Test::WWW::Mechanize;

our $config;
require 't/config.pl';

use WWW::Mechanize;

my $mech = Test::WWW::Mechanize->new;

my $save_count = 1;
sub save {
	my $path = '/tmp/login-' . $save_count++ . '.html';
	open(my $fh, '>', $path);
	print $fh @_;
	warn "# save $path ", -s $path, " bytes\n";
}

my $opac_url = $ENV{OPAC_URL} || 'http://ffzg.koha-dev.rot13.org';

$mech->get_ok( $opac_url, "opac $opac_url" );
save $mech->content;

$mech->follow_link_ok({ url_regex => qr/opac-user/i }, 'login form' );
save $mech->content;

$mech->submit_form_ok({
	form_number => 2,
	fields => {
		userid => $config->{bind_as},
		password => $config->{password},
	},
}, 'login');
save $mech->content;

$mech->follow_link_ok({ url_regex => qr/logout/ }, 'logout' );
