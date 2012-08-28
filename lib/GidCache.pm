package GidCache;
use Fcntl qw(:flock SEEK_END);    # import LOCK_* and SEEK_END constants
use Cache::FileCache;
use Data::Dumper;

my $dbpath = "./db";
my $lock   = "$dbpath/.lock";
our $c = new Cache::FileCache( { default_expires_in => $EXPIRES_NEVER, autopurge_on_set => 0, namespace => "gidNumber", cache_root => "./db" } );

## expects a 24bit unique gid number
# returns a 32bit gid with the second to high bit set to 1. since typical gidnumbers are assigned from 0 growing up we do not expect collisions
# we use second to high because having the 32st set seem to confuse ldap and it returns a negative
sub encodeGidNumber
{
    my $lowgid = shift;
    my $rawgid;
    my $gid;
    vec( $rawgid, 30, 1 ) = 1;
    vec( $rawgid, 0,  8 ) = $lowgid & 0xFF;
    vec( $rawgid, 1,  8 ) = $lowgid >> 8;
    vec( $rawgid, 2,  8 ) = $lowgid >> 16;
    $gid = unpack( "L", $rawgid );

    warn "encoded from $lowgid to $gid ";
    return $gid;
}

sub decodeGidNumber
{
    my $gid = shift;
    $ngid = pack( "L", $gid );
    vec( $ngid, 30, 1 ) = 0;
    $ngid = unpack( "L", $ngid );
    warn "decoded $gid to $ngid";
    return $ngid;
}

# find the last "local" gid number assigned in our database
sub findLastGid
{
    my $lastgid = $c->get("gid: last");
    chomp($lastgid);
    if ( !$lastgid )
    {

        # this will be slow, but should never occur because of the set("gid: last") cache
        my @lastgid = grep ( /^gid:/, $c->get_keys );
        my @lastgid = sort { $a =~ /gid: (.*)/; $An = $1; $b =~ /gid: (.*)/; $An <=> $1 } @lastgid;
        $lastgid = $lastgid[-1];
        $lastgid =~ /^gid: (.*)/;
        $lastgid = $1;

        #       print "calculated lastgid: $lastgid\n";
    }

    #   print "lastgid: $lastgid\n";
    return $lastgid;
}

# get or generate a gid number.
sub getGroupGid
{
    my $groupname = shift;

    chomp($groupname);
    my $gid = $c->get("group: $groupname");
    chomp($gid);
    if ( !$gid )
    {

        # no gid for this group, make a new one
        my $thislock = filelock($lock);
        my $lastgid  = findLastGid;
        $gid = $lastgid + 1;
        $c->set( "gid: last",         $gid );
        $c->set( "gid: $gid",         "$groupname" );
        $c->set( "group: $groupname", "$gid" );
        unlock($thislock);
    }

    return $gid;
}

sub getGroupFromGid
{
    my $gid = shift;

    print "-$gid-";
    return $c->get("gid: $gid");
}

sub filelock
{
    my ($file) = @_;

    #    warn "lock $file";
    open( my $fh, ">>", "$file" ) or die "Can't open $file: $!";
    flock( $fh, LOCK_EX ) or die "Cannot lock- $!\n";

    # and, in case someone appended while we were waiting...
    seek( $fh, 0, SEEK_END ) or die "Cannot seek - $!\n";
    return $fh;
}

sub unlock
{
    my ($fh) = @_;

    #   warn "unlock";
    flock( $fh, LOCK_UN ) or die "Cannot unlock - $!\n";
}

sub listall
{
    while ( $c->get_keys() )
    {
        print Dumper( $c->get($_) );
    }
}

1;
