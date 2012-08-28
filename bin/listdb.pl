use Cache::FileCache;

use lib 'lib/';
use GidCache;

$last = GidCache::getGroupFromGid("last") . "\n";
print "last: $last ";
chomp($last);
$group = GidCache::getGroupFromGid($last) . "\n";
print "group:$group\n";
