#!/usr/bin/perl

use warnings;
use strict;

# cvs2dbi.pl
#
# 03/15/2009 05:06:53 PM CET Dobrica Pavlinusic <dpavlin@rot13.org>

use Data::Dump qw/dump/;
use File::Slurp;
use YAML qw/DumpFile/;
use Text::CSV;
use Encode qw/from_to/;

my $debug = 0;

my $path = shift @ARGV || die "usage: $0 file.csv\n";

my $csv = read_file( $path );
from_to($csv, 'utf-16', 'utf-8');

my @columns;

foreach my $line ( split(/\r?\n/, $csv) ) {

	warn "## $line\n";

	my @fields = split(/;/, $line);
	if ( ! @columns ) {
		@columns = @fields;
		warn "# columns = ",dump( @columns ) if $debug;
		next;
	}

	my $hash;

	warn "# fields = ",dump( @fields ) if $debug;

	foreach ( 0 .. $#fields ) {
		my $n = $columns[$_];
		my $v = $fields[$_];

		$v =~ s{\s*#\s*$}{};
		$v =~ s{^\s+}{};
		$v =~ s{\s+$}{};

		# fix tel fields
		$v =~ s{\s+}{#}g if $n =~ m{tel};
		$v =~ s[\xC5\xBD][F]i if $n =~ m{spol};

		if ( $v =~ m{#} ) { # subfields delimiter in CSV data
			my @v = split(/\s*#+\s*/, $v);
			foreach my $pos ( 0 .. $#v ) {
				if ( $n =~ m{tel} ) {
					if ( $v[$pos] =~ m{^09} ) {
						$hash->{ $n . '_mobile' } ||= $v[$pos];
					} else {
						$hash->{ $n . '_fixed' } ||= $v[$pos];
					}
				}
				$hash->{ $n . '_' . $pos } = $v[$pos];
			}

			$hash->{ $n } = [ @v ];
		} else {
			$hash->{ $n } = $v;
		}
	}

	warn dump( $hash ) if $debug;

	my $uuid = $fields[0];

	DumpFile( "yaml/$uuid.yaml", $hash );
}
