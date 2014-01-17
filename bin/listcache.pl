use Cache::FileCache;
use Data::Dumper;

use lib 'lib/';
use ReqCache;

$last = new ReqCache;
foreach my $k ($last->{c}->get_keys()) {
	print "$k :\n\t";
	print Dumper($last->{c}->get($k));
}
