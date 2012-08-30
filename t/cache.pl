#!/usr/bin/perl

use Test::More no_plan;

use lib 'lib/';
use ReqCache;
use Storable qw/freeze/;

use Data::Dumper;

my $c = new ReqCache( expire => 3700 );
$c->{c}->clear();
print Dumper($c);

my $k = { a => { b => [ { c => 1 }, { d => 2 } ] } };    # used as a key structure for the cache db
my $i = { f => { d => [ { e => 1 }, { g => 2 } ] } };    # used as fake data in cache db
print Dumper($k);

my $sha  = $c->genkey($k);
my $sha2 = $c->genkey($sha);
is( $sha, $sha2, "test Genkey for valid returns" );

# key types:
is( $c->get($k),   undef );
is( $c->get($sha), undef );

# scalar data
is( $c->set( $k, "test" ), 1 );
is( $c->get($sha), "test" );

#struct data
is( $c->set( $k, $i ), 1 );
my ( $key, $d ) = $c->get($sha);
$d = $c->genkey($d);
is( $d, "eUEVRx6FSEYtL2PvAA+zlJd0zr4" );

#warn "- $key $d ";
