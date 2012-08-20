#!/usr/bin/perl

use warnings;
use strict;

# 2010-07-13 Dobrica Pavlinusic <dpavlin@rot13.org>

# http://en.wikipedia.org/wiki/Unique_Master_Citizen_Number

use Data::Dump qw/dump/;
use YAML qw/DumpFile/;
use Text::CSV;

my $debug = 0;
my $dir = 'yaml/hrEduPersonUniqueNumber_JMBG';

mkdir $dir unless -e $dir;

my $path = shift @ARGV || die "usage: $0 file.csv\n";


sub valid_jmbg {
	my $jmbg = shift;
	return 0 unless $jmbg =~ /^\d{13}$/;
	my @c = split(//, $jmbg);
	my $S=0;
	for (my $i=0;$i<6;$i++){
		$S+= (7-$i)*($c[$i]+$c[6+$i]);
	}
	my $checksum = 11-($S%11);
	return $checksum == $c[12];
}

my $csv = Text::CSV->new ( { binary => 1 } )  # should set binary attribute.
	or die "Cannot use CSV: ".Text::CSV->error_diag ();

open my $fh, "<:encoding(utf8)", $path or die "$path: $!";
while ( my $row = $csv->getline( $fh ) ) {

	my ( $ulica, $grad ) = split(/\s*,\s*/, $row->[8]);

	my $info = {
		prezime => $row->[0],
		ime => $row->[1],
		jmbg => $row->[2],
		datum_rodjenja => $row->[3],
		email => $row->[4],
		adresa_ulica => $ulica,
		adresa_grad  => $grad,
		tel_fixed => $row->[9],
		tel_mobile => $row->[10],
		spol => substr($row->[2],9,3) < 500 ? 'M' : 'F',
	};

	my $uuid = $row->[2];
	DumpFile( "$dir/$uuid.yaml", $info );
	warn "$uuid ", valid_jmbg( $row->[2] ) ? 'OK' : 'INVALID', "\n";

}
$csv->eof or $csv->error_diag();
close $fh;

